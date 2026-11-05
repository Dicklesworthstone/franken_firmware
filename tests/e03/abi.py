#!/usr/bin/env python3
"""E03 (ffw-q2p) host-side kernel-ABI capability classifier.

Pure, stdlib-only, offline.  It reads the serial transcript the PID-1 probe binary
(``toolchain/src/ffw-hello-init``) prints in a QEMU guest and says, per capability, what that
transcript does and does not establish.  It never boots anything and never edits the root's
validator (``toolchain/src/run-qemu-verification.py``), which answers a different question: did
this run reproduce the expected all-PASS transcript.

Per-capability status (about the TARGET kernel profile, not about the guest that ran):

  supported          the probe passed, with a self-consistent result, on a guest that matches the
                     profile's kernel release, and the guest's own ENOSYS number agrees with the
                     errno table (so negative return values can be decoded)
  unsupported        the probe failed with -ENOSYS in the profile ABI's numbering (38 on PowerPC,
                     89 on MIPS)
  ambiguous          anything else: failed for another errno, EINTR/EAGAIN, failed with no errno
                     to read, a contradictory PASS, a missing/duplicated/malformed line, or ANY
                     result from a guest whose kernel does not match the profile
  unavailable-guest  no guest kernel was exercised: nothing booted, userspace never started, or the
                     binary ran under user-mode CPU emulation (CPU evidence only)

The bead's rule is mechanical here: a Debian 4.x guest can never make a 2.6.x profile ``supported``,
because "if no matching guest exists, record compatibility as unqualified".

Gate (``verdict``): ``green`` only if every required capability is ``supported`` and the transcript carries
exactly one well-formed, identified, self-consistent ``FFW_BUILD`` line (target triple, rustc, linker
flavor, libc; the bead requires the probe to record them); ``degraded`` if the only gaps are capabilities
with a declared, itself-supported fallback (EPOLL falls back to POLL); ``red`` otherwise.  The build
identity is the compile's own report, not an attestation of the remote compiler, and it never changes what
a capability probe established.  Exit codes of ``classify``: 0 green, 4 degraded, 1 red, 2 usage.

Known limits, not hidden:
* The guest prints a failing POLL as ``rc=0`` and CLOCK_MONOTONIC as a resolution only, so a failure
  there carries no errno; it is ``ambiguous`` by construction, not guessed to be ENOSYS.
* ``UNPROBED`` lists capabilities the contract mentions but no guest probe emits; it is empty now (accept4,
  TLS and threads gained probes).  getrandom, eventfd2, timerfd, futex and accept4 (e03_probes.rs) and
  threads, TLS and memory peak (e03_probes_rt.rs) are probed (the guest prints the raw return of the defining
  syscall) but are optional: each has a declared fallback, or none (absent means no threads, no /proc or no
  accept4, which leaves a single-thread executor, another memory source or no fast accept).  An exact -ENOSYS
  there is a classified capability absence (``unsupported``), never a guest failure; it degrades the verdict
  while the fallback is ``supported`` and turns it red when the fallback is not.  A MISSING line is different:
  once the transcript carries FFW_BUILD the guest has the probes, so a missing line means the probe did not
  run, and that is red, never degraded.  Signal delivery, repeated timer interrupts, EINTR, the allocator,
  rename durability, the atomic width, loopback UDP, reactor wakeup and character-device poll are REQUIRED:
  the executor cannot run without them, so a missing or ambiguous result is red.  No committed real
  transcript carries any of these lines yet, so every case that uses them is SYNTHETIC.
* The errno tables come from the Linux uapi headers (asm-generic for PowerPC, arch/mips for MIPS); only
  ENOSYS/ENOENT/EBADF are also observed in the committed QEMU transcripts.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "ffw.e03.abi-classification.v1"
STATUSES = ("supported", "unsupported", "ambiguous", "unseeded", "unavailable-guest")
MODES = ("full-system", "user-mode", "none")
MAX_RAW = 200
PARTIAL_WRITE_REQUESTED = 8192   # the guest asks a full pipe for 8192 bytes and expects a short write

_COMMON = {"EPERM": 1, "ENOENT": 2, "EINTR": 4, "EIO": 5, "EBADF": 9, "EAGAIN": 11, "ENOMEM": 12,
           "EACCES": 13, "EFAULT": 14, "EINVAL": 22, "EMFILE": 24}
ERRNO: Dict[str, Dict[str, int]] = {
    "powerpc": dict(_COMMON, ENOSYS=38, ENOTSOCK=88, EPROTONOSUPPORT=93, EOPNOTSUPP=95, EAFNOSUPPORT=97),
    "mips": dict(_COMMON, ENOSYS=89, ENOTSOCK=95, EPROTONOSUPPORT=120, EOPNOTSUPP=122, EAFNOSUPPORT=124),
}
ARCH_ALIASES = {"powerpc-be": "powerpc", "powerpc": "powerpc", "mips-be": "mips", "mips": "mips"}

# name -> (line prefix, detail key, detail is a raw syscall return, PASS predicate on the detail value)
PROBES: Dict[str, Tuple[str, str, bool, Any]] = {
    "CLOCK_MONOTONIC": ("FFW_PROBE", "res_ns", False, lambda v: 1 <= v <= 999_999_999),
    "NONBLOCK_PIPE": ("FFW_PROBE", "rc", True, lambda v: v == 0),
    "POLL": ("FFW_PROBE", "rc", False, lambda v: v == 1),
    "EPOLL": ("FFW_PROBE", "fd", True, lambda v: v > 0),
    "SOCKET_UDP": ("FFW_PROBE", "fd", True, lambda v: v > 0),
    "ENTROPY": ("FFW_PROBE", "fd", True, lambda v: v > 0),
    "ATOMICS_32": ("FFW_PROBE", "ok", False, lambda v: v == 1),
    "PARTIAL_WRITE": ("FFW_TEST", "bytes", False, lambda v: 0 < v < PARTIAL_WRITE_REQUESTED),
    # e03_probes.rs: the detail is the RAW return of the defining syscall, so -ENOSYS decodes against the
    # guest's own calibration; PASS prints only when the whole behavior check passed.
    "GETRANDOM": ("FFW_PROBE", "rc", True, lambda v: v == 16),
    "EVENTFD2": ("FFW_PROBE", "fd", True, lambda v: v > 0),
    "TIMERFD": ("FFW_PROBE", "fd", True, lambda v: v > 0),
    "FUTEX": ("FFW_PROBE", "rc", True, lambda v: v == 0),
    # e03_probes_rt.rs, same grammar.  EINTR_READ passes with the NEGATIVE return -EINTR; TLS passes with the
    # thread pointer the child was given (0x12345678); ATOMIC_WIDTH records that neither SoC has native
    # 64-bit atomics.  MEM_PEAK prints FAIL kb=-<errno> when /proc is unavailable.
    "THREADS": ("FFW_PROBE", "tid", True, lambda v: v > 0),
    "TLS": ("FFW_PROBE", "tp", True, lambda v: v == 305419896),
    "SIGNAL": ("FFW_PROBE", "rc", True, lambda v: v == 0),
    "TIMER_SIGNALS": ("FFW_PROBE", "rc", True, lambda v: v == 0),
    "EINTR_READ": ("FFW_PROBE", "rc", True, lambda v: v == -4),
    "ALLOC": ("FFW_PROBE", "rc", True, lambda v: v == 0),
    "MEM_PEAK": ("FFW_PROBE", "kb", False, lambda v: v > 0),
    "ATOMIC_WIDTH": ("FFW_PROBE", "bits", False, lambda v: v == 32),
    "FS_RENAME": ("FFW_PROBE", "rc", True, lambda v: v == 0),
    # e03_probes/net.rs, same grammar.  The detail is the raw return of the syscall that stopped the probe, else
    # the success value.  Everything runs over the loopback interface only: it shows kernel UDP/TCP semantics,
    # not any real network path, and CHARDEV_POLL is generic VFS behavior, not the retained audio driver.
    "LOOPBACK_UP": ("FFW_PROBE", "rc", True, lambda v: v == 0),
    "UDP_LOOPBACK": ("FFW_PROBE", "rc", True, lambda v: v == 24),
    "ACCEPT4": ("FFW_PROBE", "fd", True, lambda v: v > 0),
    "REACTOR_WAKE": ("FFW_PROBE", "rc", True, lambda v: v == 1),
    "CHARDEV_POLL": ("FFW_PROBE", "rc", True, lambda v: v == 2),
}
# Guest self-checks: they do not describe a kernel capability, but a transcript without them is not trusted.
SELFTESTS: Dict[str, Tuple[str, Any]] = {
    "ERR_ENOENT": ("errno", lambda v: v == 2),
    "ERR_EBADF": ("errno", lambda v: v == 9),
    "POS_FD_SHORT_WRITE": ("fd", lambda v: v > 0),
}
REQUIRED = ("CLOCK_MONOTONIC", "NONBLOCK_PIPE", "POLL", "SOCKET_UDP", "ENTROPY", "ATOMICS_32", "PARTIAL_WRITE",
            "SIGNAL", "TIMER_SIGNALS", "EINTR_READ", "ALLOC", "FS_RENAME", "ATOMIC_WIDTH",
            "LOOPBACK_UP", "UDP_LOOPBACK", "REACTOR_WAKE", "CHARDEV_POLL")
# optional capability -> what stands in for it; None means nothing does (the feature is simply unavailable)
FALLBACKS: Dict[str, Optional[str]] = {"EPOLL": "POLL", "GETRANDOM": "ENTROPY", "EVENTFD2": "NONBLOCK_PIPE",
                                       "TIMERFD": "POLL", "FUTEX": None, "THREADS": None, "TLS": None,
                                       "MEM_PEAK": None,
                                       # accept4 absent has NO declared fallback: accept plus fcntl can race
                                       # (bead section 4) and is not probed, so it is never declared supported
                                       "ACCEPT4": None}
UNPROBED: Tuple[str, ...] = ()
PROFILES: Dict[str, Dict[str, str]] = {
    "harness-mips-4.19": {"arch": "mips", "kernel": "4.19.0-21-4kc-malta"},
    "harness-ppc-4.9": {"arch": "powerpc", "kernel": "4.9.0-0.bpo.6-powerpc"},
    "stock-ppc-2.6.14": {"arch": "powerpc", "kernel": "2.6.14"},
    "stock-mips-2.6.35": {"arch": "mips", "kernel": "2.6.35"},
}

_INT = re.compile(r"-?(?:0|[1-9][0-9]{0,9})\Z")
_LINE = re.compile(r"(FFW_PROBE|FFW_TEST):([A-Z0-9_]+) status=(PASS|FAIL|UNSEEDED) ([a-z0-9_]+)=(\S+)\Z")
# Only GETRANDOM may report UNSEEDED, and only with the raw -EAGAIN it saw (11 on both ABIs): the call exists
# (a bad flag gave exactly -EINVAL) but the kernel's entropy pool is not yet seeded when PID 1 runs.
UNSEEDED_PROBES = ("GETRANDOM",)
_KERNEL = re.compile(r"FFW_KERNEL_VERSION: Linux version (\S+)")
_HELLO = re.compile(r"FFW_HELLO arch=(\S+) ")

# The probe's own report of the compile that produced it (build.rs + main.rs in toolchain/src/ffw-hello-init).
# Tokens are [A-Za-z0-9._+-]{1,40}; the probe spells "could not read" as unknown/unspecified.
_TOKEN = r"[A-Za-z0-9._+-]{1,40}"
_BUILD = re.compile(r"FFW_BUILD target=(%s) rustc=(%s) rustc_commit=(%s) linker_flavor=(%s) libc=(%s) runtime=(%s)\Z"
                    % ((_TOKEN,) * 6))
BUILD_FIELDS = ("target", "rustc", "rustc_commit", "linker_flavor", "libc", "runtime")
UNIDENTIFIED = ("unknown", "unspecified")
TRIPLE_ARCH = {"mips": "mips", "powerpc": "powerpc"}       # first component of the target triple -> ABI


# ------------------------------------------------------------------ errno and integers


def errno_name(arch: str, number: int) -> Optional[str]:
    """Name of ``number`` in ``arch``'s errno numbering, or None if the table does not know it."""
    if arch not in ERRNO:
        raise ValueError("unknown ABI %r" % (arch,))
    if not isinstance(number, int) or isinstance(number, bool):
        raise ValueError("errno must be an int")
    for name, value in ERRNO[arch].items():
        if value == number:
            return name
    return None


def errno_number(arch: str, name: str) -> int:
    if arch not in ERRNO:
        raise ValueError("unknown ABI %r" % (arch,))
    if name not in ERRNO[arch]:
        raise ValueError("unknown errno name %r for %s" % (name, arch))
    return ERRNO[arch][name]


def parse_i32(text: str) -> int:
    """Canonical decimal in the 32-bit signed range; anything looser is refused (no '+', no leading
    zeros, no '-0', no non-ASCII digits, no trailing text), so ``errno=890`` can never read as 89."""
    if not isinstance(text, str) or _INT.match(text) is None or text == "-0":
        raise ValueError("not a canonical decimal integer: %r" % (text[:40] if isinstance(text, str) else text,))
    value = int(text)
    if not -(1 << 31) <= value < (1 << 31):
        raise ValueError("outside the 32-bit signed range: %s" % text)
    return value


def classify_io(requested: int, result: int, arch: str) -> Tuple[str, Optional[str]]:
    """What a read/write return value says, as (kind, errno name or None).

    kind: full | short | zero | would_block | interrupted | error | invalid.  A short count is a normal
    result, not an error; EINTR and EAGAIN never mean the call is unsupported."""
    for label, v in (("requested", requested), ("result", result)):
        if not isinstance(v, int) or isinstance(v, bool) or not -(1 << 31) <= v < (1 << 31):
            raise ValueError("%s must be a 32-bit int" % label)
    if requested < 1:
        raise ValueError("requested must be >= 1")
    if result < 0:
        name = errno_name(arch, -result)
        if name == "EAGAIN":
            return "would_block", name
        if name == "EINTR":
            return "interrupted", name
        return "error", name
    if result > requested:
        return "invalid", None            # a kernel cannot transfer more than was asked
    if result == requested:
        return "full", None
    return ("zero", None) if result == 0 else ("short", None)


# ------------------------------------------------------------------ transcript


def _clip(text: str) -> str:
    return text if len(text) <= MAX_RAW else text[: MAX_RAW - 3] + "..."


def parse_transcript(text: str) -> Dict[str, Any]:
    """Structured view of the guest's serial output.  Only lines that START with ``FFW_`` count (a
    shell-echoed or kernel-printed copy of a marker is not guest execution)."""
    records: Dict[str, Dict[str, str]] = {}
    duplicates: List[str] = []
    malformed: List[str] = []
    build_lines: List[str] = []
    started = terminal = False
    kernel = hello_arch = None
    for raw in text.replace("\r", "").split("\n"):
        line = raw.strip()
        if not line.startswith("FFW_"):
            continue
        if line == "FFW_MARKER:USERSPACE_START":
            started = True
        elif line.startswith("FFW_BUILD"):
            build_lines.append(_clip(line))
        elif line == "FFW_MARKER:REBOOT_REQUEST":
            terminal = True
        elif line.startswith("FFW_KERNEL_VERSION: "):
            m = _KERNEL.match(line)
            kernel = kernel or (m.group(1) if m else None)
        elif line.startswith("FFW_HELLO "):
            m = _HELLO.match(line)
            hello_arch = hello_arch or (m.group(1) if m else None)
        elif line.startswith(("FFW_PROBE:", "FFW_TEST:")):
            m = _LINE.match(line)
            if m is None:
                malformed.append(_clip(line))
                continue
            name = m.group(2)
            if name in records:
                duplicates.append(name)
                continue
            records[name] = {"status": m.group(3), "key": m.group(4), "value": m.group(5), "raw": _clip(line)}
    return {"userspace_started": started, "terminal": terminal, "kernel_release": kernel,
            "hello_arch": hello_arch, "records": records, "duplicates": sorted(set(duplicates)),
            "malformed": malformed, "build_lines": build_lines}


def classify_build(lines: List[str], arch: str) -> Dict[str, Any]:
    """Whether the transcript carries exactly one well-formed, identified, self-consistent FFW_BUILD line.

    This is provenance the bead requires the probe to record (target triple, compiler, linker, libc).  It is
    the compile's own report, bound to the booted bytes only by the receipt's binary hash; it does not attest
    the remote compiler, and it never changes what a capability probe established.  ``ok`` gates the verdict."""
    if not lines:
        return {"recorded": False, "ok": False, "fields": None, "problems": ["unrecorded: no FFW_BUILD line"]}
    if len(lines) > 1:
        return {"recorded": False, "ok": False, "fields": None,
                "problems": ["duplicate: %d FFW_BUILD lines" % len(lines)]}
    m = _BUILD.match(lines[0])
    if m is None:
        return {"recorded": False, "ok": False, "fields": None,
                "problems": ["malformed: the FFW_BUILD line did not parse"]}
    fields = dict(zip(BUILD_FIELDS, m.groups()))
    problems = ["unidentified: %s=%s" % (n, fields[n]) for n in ("rustc", "rustc_commit", "linker_flavor")
                if fields[n] in UNIDENTIFIED]
    if fields["libc"] != "none":
        problems.append("libc: reported %s, but the probe is no_std and must report none" % fields["libc"])
    if fields["runtime"] != "no_std":
        problems.append("runtime: reported %s, expected no_std" % fields["runtime"])
    if TRIPLE_ARCH.get(fields["target"].split("-")[0]) != arch:
        problems.append("target_arch: %s is not a %s triple" % (fields["target"], arch))
    return {"recorded": True, "ok": not problems, "fields": fields, "problems": problems}


def kernel_matches(release: Optional[str], wanted: str) -> bool:
    if not release:
        return False
    return release == wanted or (release.startswith(wanted) and release[len(wanted)] in ".-+_")


# ------------------------------------------------------------------ classification


def _classify_probe(name: str, rec: Optional[Dict[str, str]], arch: str, calibrated: bool,
                    duplicated: bool, malformed: bool) -> Tuple[str, str, Optional[int]]:
    """(status, reason, parsed value) from one probe line, BEFORE the evidence class is applied."""
    prefix, key, errno_bearing, pass_ok = PROBES[name]
    if duplicated:
        return "ambiguous", "duplicate_line: the probe reported more than once", None
    if rec is None:
        return ("ambiguous", "malformed_line: the probe line did not parse", None) if malformed else \
               ("ambiguous", "no_evidence: the probe line is missing", None)
    if rec["key"] != key:
        return "ambiguous", "wrong_detail_key: %s, expected %s" % (rec["key"], key), None
    try:
        value = parse_i32(rec["value"])
    except ValueError:
        return "ambiguous", "bad_integer: %s=%s" % (rec["key"], _clip(rec["value"])[:40]), None
    if rec["status"] == "UNSEEDED":
        if name in UNSEEDED_PROBES and value == -ERRNO[arch]["EAGAIN"]:
            return "unseeded", "unseeded: the call exists but the entropy pool is not seeded at PID-1 boot", value
        return "ambiguous", "bad_unseeded: only %s with the raw -EAGAIN may report UNSEEDED, got %s %s=%d" % (
            "/".join(UNSEEDED_PROBES), name, key, value), value
    if rec["status"] == "PASS":
        if pass_ok(value):
            return "supported", "pass", value
        return "ambiguous", "contradictory_pass: PASS with %s=%d" % (key, value), value
    if errno_bearing and value < 0:
        if not calibrated:
            return "ambiguous", "errno_calibration_failed: cannot decode %d without the guest's ENOSYS" % value, value
        ename = errno_name(arch, -value)
        if ename == "ENOSYS":
            return "unsupported", "ENOSYS", value
        if ename in ("EINTR", "EAGAIN"):
            return "ambiguous", "transient:%s: retry is required, absence is not shown" % ename, value
        if ename:
            return "ambiguous", "errno:%s: the call exists but failed" % ename, value
        return "ambiguous", "unknown_errno:%d for %s" % (-value, arch), value
    return "ambiguous", "failed_without_errno: %s=%d carries nothing to decode" % (key, value), value


def classify_run(text: str, profile: str, mode: str = "full-system") -> Dict[str, Any]:
    if profile not in PROFILES:
        raise ValueError("unknown profile %r" % (profile,))
    if mode not in MODES:
        raise ValueError("mode must be one of %s" % ", ".join(MODES))
    prof = PROFILES[profile]
    arch = prof["arch"]
    parsed = parse_transcript(text)
    recs = parsed["records"]
    guest_arch = ARCH_ALIASES.get(parsed["hello_arch"] or "")

    # evidence class: what kind of run produced this transcript
    if mode == "user-mode":
        evidence, why = "cpu-emulation", "user-mode emulation runs the host kernel's syscalls: CPU evidence only"
    elif mode == "none" or not parsed["userspace_started"] or not parsed["kernel_release"]:
        evidence, why = "unavailable-guest", "no guest kernel identity or userspace start in the transcript"
    elif guest_arch != arch:
        evidence, why = "non-matching-guest", "guest architecture %s is not %s" % (parsed["hello_arch"], arch)
    elif not kernel_matches(parsed["kernel_release"], prof["kernel"]):
        evidence, why = "non-matching-guest", "guest kernel %s is not %s" % (parsed["kernel_release"], prof["kernel"])
    else:
        evidence, why = "matching-guest", "guest kernel %s matches the profile" % parsed["kernel_release"]

    # the guest's own ENOSYS number must equal the table before any negative return can be decoded
    cal = recs.get("ERR_ENOSYS")
    expected_enosys = ERRNO[arch]["ENOSYS"]
    calibration = {"ok": False, "reason": "ERR_ENOSYS line is missing"}
    if cal is not None:
        try:
            seen = parse_i32(cal["value"]) if cal["key"] == "errno" else None
        except ValueError:
            seen = None
        if cal["status"] == "PASS" and seen == expected_enosys:
            calibration = {"ok": True, "reason": "guest ENOSYS %d equals the %s table" % (seen, arch)}
        else:
            calibration = {"ok": False, "reason": "guest reported %s, the %s table says %d" % (cal["raw"], arch, expected_enosys)}
    selftests_ok = True
    for name, (key, ok) in SELFTESTS.items():
        rec = recs.get(name)
        try:
            good = rec is not None and rec["status"] == "PASS" and rec["key"] == key and ok(parse_i32(rec["value"]))
        except ValueError:
            good = False
        selftests_ok = selftests_ok and good
    calibration["selftests_ok"] = selftests_ok
    enosys_ok = calibration["ok"]          # decoding negative returns needs only the ENOSYS agreement

    bad_names = {m.split(":")[1].split(" ")[0] for m in parsed["malformed"] if ":" in m}
    probes: Dict[str, Dict[str, Any]] = {}
    for name in PROBES:
        status, reason, value = _classify_probe(
            name, recs.get(name), arch, enosys_ok, name in parsed["duplicates"], name in bad_names)
        guest_status = status
        if evidence == "non-matching-guest":
            status, reason = "ambiguous", "no_matching_guest: %s" % why
        elif evidence in ("cpu-emulation", "unavailable-guest"):
            status, reason = "unavailable-guest", why
        probes[name] = {"status": status, "reason": reason, "guest_status": guest_status,
                        "observed": recs[name]["raw"] if name in recs else None}

    counts = {s: sum(1 for p in probes.values() if p["status"] == s) for s in STATUSES}
    reasons = ["%s is %s" % (n, probes[n]["status"]) for n in REQUIRED if probes[n]["status"] != "supported"]
    degraded = []
    build = classify_build(parsed["build_lines"], arch)
    for name, fallback in FALLBACKS.items():
        if probes[name]["status"] != "supported":
            if build["recorded"] and probes[name]["reason"].startswith("no_evidence"):
                # The guest carries the probes (it printed FFW_BUILD), so a missing line means the probe did not
                # run. That is not a capability statement, so it must never be filed with an exact -ENOSYS.
                reasons.append("%s did not run: its line is missing from a transcript whose guest carries the "
                               "probes" % name)
            elif probes[name]["status"] == "unseeded":
                # Present, but no entropy was obtained. The declared fallback does not rescue it: ENTROPY reads
                # /dev/urandom, which on this guest is the same pool (the committed log reports an "uninitialized
                # urandom read"), so its PASS does not establish secure entropy either.
                degraded.append("%s is unseeded: the call exists but the pool has no entropy at PID-1 boot, so "
                                "firmware must not block on it; the %s probe reads the same unseeded pool and "
                                "does not establish secure entropy" % (name, fallback))
            elif fallback is None:
                degraded.append("%s is %s (no fallback: the feature is unavailable, e.g. no threads)"
                                % (name, probes[name]["status"]))
            elif probes[fallback]["status"] == "supported":
                degraded.append("%s is %s (fallback %s is supported)" % (name, probes[name]["status"], fallback))
            else:
                reasons.append("%s is %s and its fallback %s is not supported" % (name, probes[name]["status"], fallback))
    if not enosys_ok:
        reasons.append("calibration failed: %s" % calibration["reason"])
    if not selftests_ok:
        reasons.append("guest self-tests failed or are missing (ERR_ENOENT, ERR_EBADF, POS_FD_SHORT_WRITE)")
    if evidence != "matching-guest":
        reasons.append("evidence is %s: %s" % (evidence, why))
    if not build["ok"]:
        reasons.append("build identity: " + "; ".join(build["problems"]))
    verdict = "red" if reasons else ("degraded" if degraded else "green")
    return {"schema": SCHEMA, "profile": profile, "mode": mode, "evidence": evidence, "evidence_reason": why,
            "guest": {"kernel_release": parsed["kernel_release"], "arch": parsed["hello_arch"],
                      "reached_end": parsed["terminal"]},
            "calibration": calibration, "build": build, "probes": probes, "counts": counts,
            "unprobed": list(UNPROBED),
            "verdict": verdict, "reasons": reasons, "degraded": degraded,
            "transcript_problems": {"duplicates": parsed["duplicates"], "malformed": parsed["malformed"]}}


EXIT = {"green": 0, "red": 1, "degraded": 4}


def render(result: Dict[str, Any]) -> str:
    out = ["E03 %s  profile=%s mode=%s evidence=%s" % (result["verdict"].upper(), result["profile"],
                                                          result["mode"], result["evidence"]),
           "guest: kernel=%s arch=%s; calibration: %s" % (result["guest"]["kernel_release"], result["guest"]["arch"],
                                                          result["calibration"]["reason"]),
           "probes: " + " ".join("%s=%d" % (s, n) for s, n in result["counts"].items()),
           "build: " + ("target=%s rustc=%s linker_flavor=%s libc=%s%s" % (
               result["build"]["fields"]["target"], result["build"]["fields"]["rustc"],
               result["build"]["fields"]["linker_flavor"], result["build"]["fields"]["libc"],
               "" if result["build"]["ok"] else " (REJECTED: " + "; ".join(result["build"]["problems"]) + ")")
               if result["build"]["fields"] else "UNRECORDED (" + "; ".join(result["build"]["problems"]) + ")")]
    for name, p in result["probes"].items():
        out.append("  %-16s %-17s %s" % (name, p["status"], p["reason"]))
    out.append("unprobed (contract names them, no guest probe emits them): " + ", ".join(result["unprobed"]))
    out += ["why not green: " + r for r in result["reasons"]] + ["degraded: " + d for d in result["degraded"]]
    return "\n".join(out) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Classify an E03 probe transcript against a kernel profile")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("classify")
    c.add_argument("transcript")
    c.add_argument("--profile", required=True, choices=sorted(PROFILES))
    c.add_argument("--mode", default="full-system", choices=MODES)
    c.add_argument("--json", action="store_true", help="print the JSON result instead of the summary")
    sub.add_parser("profiles")
    args = ap.parse_args(argv)
    if args.cmd == "profiles":
        print(json.dumps(PROFILES, indent=1, sort_keys=True))
        return 0
    try:
        with open(args.transcript, "rb") as fh:
            text = fh.read(8 << 20).decode("utf-8", errors="replace")
    except OSError as exc:
        print("abi.py: cannot read transcript: %s" % exc.__class__.__name__, file=sys.stderr)
        text = ""          # an unreadable transcript is "no guest evidence", never a pass
        args.mode = "none"
    result = classify_run(text, args.profile, args.mode)
    sys.stdout.write(json.dumps(result, indent=1, sort_keys=True) + "\n" if args.json else render(result))
    return EXIT[result["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
