#!/usr/bin/env python3
"""Build, boot, and verify BE-MIPS and BE-PowerPC initramfs images under QEMU.

Covers:
- E07 (ffw-ll1): Repair and qualify reusable BE bootstrap and initramfs test harness
- E03 (ffw-q2p): Legacy kernel ABI capability matrix probes inside full-system guests
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import selectors
import signal
import subprocess
import sys
import time
import uuid
from typing import Any

try:  # Python >= 3.11; without it the configured-linker record says so instead of guessing.
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
sys.path.insert(0, str(SCRIPT_DIR))
import mkinitramfs  # noqa: E402
import speaker_expect  # noqa: E402


FORBIDDEN_SUBSTRINGS: tuple[str, ...] = (
    "Warning: unable to open an initial console.",
    "FFW_PANIC",
    "FFW_MARKER:TEST_FAILURE",
    "Kernel panic - not syncing",
)


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cmd_version(cmd: list[str]) -> str:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=10)
        return (res.stdout or res.stderr).strip().splitlines()[0]
    except Exception as exc:
        return f"unavailable ({exc})"


# ---- E03 build identity (bead ffw-q2p: target triple, compiler, linker, libc) --------------------------
#
# The probe prints one `FFW_BUILD` line (toolchain/src/ffw-hello-init/build.rs + main.rs). It is the
# compile's own report. It describes the booted bytes because the runner checks that the archive's init entry
# hashes to the binary it names (`initramfs_init_differs_from_binary`); it is NOT an attestation of the
# remote compiler (`build_provenance` below stays "not_attested_by_this_boot_runner"). The runner
# cross-checks what it can: the triple against the one it built for, the libc claim against the ELF it
# booted, and the linker flavor against the committed cargo config.

BUILD_TOKEN = r"[A-Za-z0-9._+-]{1,40}"          # build.rs emits only this alphabet, capped at 40
UNIDENTIFIED = ("unknown", "unspecified")        # build.rs spells "could not read" this way
ELF_MACHINE = {"mips": 8, "ppc": 20}             # EM_MIPS, EM_PPC
PT_DYNAMIC, PT_INTERP = 2, 3
_BUILD_FIELDS = re.compile(
    r"FFW_BUILD target=(\S+) rustc=(\S+) rustc_commit=(\S+) linker_flavor=(\S+) libc=(\S+) runtime=(\S+)"
)


def build_identity_pattern(expected_triple: str) -> str:
    """Exact grammar of the probe's FFW_BUILD line for the triple this runner built."""
    return (
        r"FFW_BUILD target=" + re.escape(expected_triple)
        + rf" rustc={BUILD_TOKEN} rustc_commit={BUILD_TOKEN} linker_flavor={BUILD_TOKEN}"
        + r" libc=none runtime=no_std"
    )


def parse_build_identity(line: str) -> dict[str, str] | None:
    m = _BUILD_FIELDS.fullmatch(line)
    if m is None:
        return None
    return dict(zip(("target", "rustc", "rustc_commit", "linker_flavor", "libc", "runtime"), m.groups()))


# ---- E03 capability probes with an explicit "absent" answer (bead ffw-q2p: getrandom, eventfd2, timerfd, futex)
#
# Each prints `FFW_PROBE:<NAME> status=PASS|FAIL <key>=<raw return of the defining syscall>`
# (ffw-hello-init/src/e03_probes.rs; verdicts in e03_judge.rs). `-ENOSYS` is the kernel saying the call does
# not exist: the explicit capability failure the bead asks for, not a guest malfunction, so the transcript is
# still well formed and the guest may still report success. Anything else that is not a pass (another errno,
# a FAIL with a non-error return, short data) means the call exists and misbehaves; the guest then prints
# TEST_FAILURE and this verifier refuses the line. "Probe ran and found nothing" is therefore distinct from
# "probe did not run" (missing marker) and from "probe misbehaved" (invalid line).

OPTIONAL_PROBES: dict[str, tuple[str, str]] = {   # name -> (detail key, regex of the success value)
    "GETRANDOM": ("rc", "16"),
    "EVENTFD2": ("fd", "[1-9][0-9]*"),
    "TIMERFD": ("fd", "[1-9][0-9]*"),
    "FUTEX": ("rc", "0"),
    "ACCEPT4": ("fd", "[1-9][0-9]*"),        # e03_probes/net.rs
    "THREADS": ("tid", "[1-9][0-9]*"),       # e03_probes_rt.rs
    "TLS": ("tp", "305419896"),              # 0x12345678, the thread pointer the child was given
}
OPTIONAL_PROBE_KEYS = frozenset(f"FFW_PROBE:{name}" for name in OPTIONAL_PROBES)

# Runtime BEHAVIORS rather than syscalls an old kernel may lack. On the 4.9/4.19 harness kernels none of them can
# legitimately be -ENOSYS, so the transcript must carry the exact PASS line: an ENOSYS line, any other FAIL, or a
# missing line fails the guest. (Whether a capability is usable on a given profile is the classifier's question.)
REQUIRED_PROBES: dict[str, tuple[str, str]] = {
    "LOOPBACK_UP": ("rc", "0"),              # e03_probes/net.rs
    "UDP_LOOPBACK": ("rc", "24"),
    "REACTOR_WAKE": ("rc", "1"),
    "CHARDEV_POLL": ("rc", "2"),
    "ATOMIC_WIDTH": ("bits", "32"),          # e03_probes_rt.rs
    "ALLOC": ("rc", "0"),
    "MEM_PEAK": ("kb", "[1-9][0-9]*"),
    "FS_RENAME": ("rc", "0"),
    "SIGNAL": ("rc", "0"),
    "TIMER_SIGNALS": ("rc", "0"),
    "EINTR_READ": ("rc", "-4"),              # the NEGATIVE return -EINTR is the pass
}


def required_probe_pattern(name: str) -> str:
    key, success = REQUIRED_PROBES[name]
    return rf"FFW_PROBE:{name} status=PASS {key}={success}"


# Guest setup that is not a kernel capability, so it is not an E03 probe and never reaches the capability matrix. The guest's
# first action is klogctl(SYSLOG_ACTION_CONSOLE_LEVEL, NULL, 1): only KERN_EMERG then reaches the serial console, so a kernel
# printk cannot land inside a marker (it split FFW_MARKER:TEST_SUCCESS on the first PowerPC smoke). The exact PASS line is
# required; a refused call is named (`console_level_refused:`); and the parser stays strict about partial lines on purpose:
# a lenient one could pass a marker the guest never wrote whole.
GUEST_SETUP: dict[str, tuple[str, str]] = {"CONSOLE_LEVEL": ("rc", "0")}
CONSOLE_LEVEL_FAILURE = re.compile(r"FFW_GUEST:CONSOLE_LEVEL status=FAIL rc=-?[0-9]+")


def guest_setup_pattern(name: str) -> str:
    key, success = GUEST_SETUP[name]
    return rf"FFW_GUEST:{name} status=PASS {key}={success}"


# `rustc -vV` as seen by the compiler that built the booted bytes (build.rs), printed once by the probe. E07 asks
# the receipt to pin the compiler; this records it as observed provenance, not enforcement (no toolchain pin).
RUSTC_TOKEN = r"[A-Za-z0-9._+-]{1,40}"
RUSTC_PATTERN = (
    rf"FFW_RUSTC release={RUSTC_TOKEN} commit=[0-9a-f]{{40}} date=[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}} "
    rf"host={RUSTC_TOKEN} llvm={RUSTC_TOKEN}"
)
_RUSTC_FIELDS = re.compile(r"FFW_RUSTC release=(\S+) commit=(\S+) date=(\S+) host=(\S+) llvm=(\S+)")


def parse_rustc_identity(line: str) -> dict[str, str] | None:
    m = _RUSTC_FIELDS.fullmatch(line)
    return None if m is None else dict(zip(("release", "commit_hash", "commit_date", "host", "llvm"), m.groups()))


def enosys_errno_of(expected_enosys: str) -> str:
    """The guest ABI's ENOSYS number, read from the same expected line that calibrates the errno self-test
    (38 on PowerPC, 89 on MIPS), so one ABI's number can never be accepted for the other."""
    m = re.fullmatch(r"FFW_TEST:ERR_ENOSYS status=PASS errno=([1-9][0-9]*)", expected_enosys)
    if m is None:
        raise ValueError(f"cannot read the guest ENOSYS number from {expected_enosys!r}")
    return m.group(1)


# A third outcome only GETRANDOM can have. On the real guest the kernel's entropy pool is not yet seeded when PID 1
# runs (the committed MIPS log reads `random: init: uninitialized urandom read`; no RNG device is attached), so
# `getrandom` keeps answering -EAGAIN. The probe then proves the call exists without needing entropy (a bad flag
# must give exactly -EINVAL) and reports `UNSEEDED rc=-11` (EAGAIN is 11 on both ABIs). That is neither a pass nor
# an absence nor a misbehaving call, so it is recorded as its own token and never as PASS, FAIL or supported.
UNSEEDED_PROBES: dict[str, str] = {"GETRANDOM": "-11"}


def optional_probe_pattern(name: str, enosys_errno: str) -> str:
    key, success = OPTIONAL_PROBES[name]
    unseeded = rf"|UNSEEDED {key}={UNSEEDED_PROBES[name]}" if name in UNSEEDED_PROBES else ""
    return rf"FFW_PROBE:{name} status=(?:PASS {key}={success}|FAIL {key}=-{enosys_errno}{unseeded})"


def inspect_static_elf(path: pathlib.Path, arch: str) -> dict[str, Any]:
    """Facts about the exact binary that was booted that back the probe's `libc=none` claim: a 32-bit
    big-endian ELF for the right machine with neither PT_INTERP nor PT_DYNAMIC (no loader, no shared libc)."""
    with path.open("rb") as handle:
        data = handle.read(1 << 16)
    out: dict[str, Any] = {"is_elf": False, "problems": []}
    if len(data) < 52 or data[:4] != b"\x7fELF":
        out["problems"].append("not_elf")
        return out
    out["is_elf"] = True
    if data[4] != 1 or data[5] != 2:
        out["problems"].append("not_elf32_big_endian")
        return out
    machine = int.from_bytes(data[18:20], "big")
    phoff = int.from_bytes(data[28:32], "big")
    phentsize = int.from_bytes(data[42:44], "big")
    phnum = int.from_bytes(data[44:46], "big")
    out.update({"machine": machine, "machine_matches_arch": machine == ELF_MACHINE.get(arch)})
    if not out["machine_matches_arch"]:
        out["problems"].append("machine_does_not_match_arch")
    if phentsize != 32 or phnum == 0 or phoff + phnum * phentsize > len(data):
        out["problems"].append("program_headers_unreadable")
        return out
    types = {int.from_bytes(data[phoff + i * 32: phoff + i * 32 + 4], "big") for i in range(phnum)}
    out.update({"has_interp": PT_INTERP in types, "has_dynamic": PT_DYNAMIC in types})
    out["static"] = not (out["has_interp"] or out["has_dynamic"])
    if not out["static"]:
        out["problems"].append("dynamic_or_interpreted")
    return out


def configured_linker(crate_dir: pathlib.Path, triple: str) -> dict[str, Any]:
    """The linker the committed cargo config names for `triple`. A configuration claim, never an
    attestation of the linker that actually ran on the remote worker."""
    record: dict[str, Any] = {"source": ".cargo/config.toml", "attested": False, "linker": None, "flavor": None}
    if tomllib is None:
        return {**record, "error": "tomllib_unavailable"}
    try:
        target = tomllib.loads((crate_dir / ".cargo" / "config.toml").read_text())["target"][triple]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        return {**record, "error": type(exc).__name__}
    flags = target.get("rustflags", [])
    flavor = next((f.split("=", 1)[1] for f in flags if isinstance(f, str) and f.startswith("linker-flavor=")), None)
    return {**record, "linker": target.get("linker"), "flavor": flavor}


# ---- E07 build manifest (bead ffw-ll1: "pins rustc/toolchain/nightly, target JSON/CPU features, linker,
# source/lockfile, kernel/initramfs/binary digests and exact command") ---------------------------------------
#
# Digests of the kernel, initramfs and booted binary are recorded per guest below. This adds what produced the
# binary: the exact command, and a digest of every file that decides what the crate compiles to. The runner
# still does not attest the remote compiler: rustc and the linker flavor are the probe's own FFW_BUILD report
# and the linker name is the committed config's claim (see `build_provenance`).

MANIFEST_FILES = ("Cargo.toml", "Cargo.lock", ".cargo/config.toml", "build.rs")
OUTSIDE_REPO = "<outside-repo>"


def _raise_walk_error(error: OSError) -> None:
    """`os.walk` swallows the errors it meets (an unreadable directory, a missing top) unless told otherwise.
    Swallowing one here would drop part of the tree from the digest set without a word."""
    raise error


def source_tree(crate_dir: pathlib.Path) -> list[str]:
    """Every regular file under ``<crate>/src``, at any depth, as sorted crate-relative POSIX paths.

    All files, not only ``*.rs``: a module can ``include_str!`` or ``include_bytes!`` anything, and a file that
    decides what the crate compiles to must be in the digest set. Nothing in an existing tree is skipped
    silently: a symlinked directory is refused rather than walked or skipped, and so is a directory that cannot
    be read. Either would leave part of the tree out of a receipt that says the sources are bound to the binary,
    which is the gap an earlier shallow ``src/*.rs`` listing left for ``src/e03_probes/net.rs`` and
    ``src/e03_judge/net.rs``. The receipt records no exclusions because there are none. A crate with no ``src``
    directory at all has no source files to digest, so its listing is empty (it could not have been built)."""
    src = crate_dir / "src"
    if not src.is_dir():
        return []
    found: list[str] = []
    for root, dirs, files in os.walk(src, onerror=_raise_walk_error):
        for name in dirs:
            if (pathlib.Path(root) / name).is_symlink():
                raise ValueError(f"symlinked directory under src is not digested: {pathlib.Path(root) / name}")
        found.extend((pathlib.Path(root) / name).relative_to(crate_dir).as_posix() for name in files)
    return sorted(found)


def source_digests(crate_dir: pathlib.Path) -> dict[str, str | None]:
    """sha256 of the manifest, lockfile, cargo config, build script and every file under `src/` (recursively;
    see `source_tree`) of the bootstrap crate, keyed by crate-relative path. A manifest file that is absent is
    recorded as None, never omitted."""
    names = [*MANIFEST_FILES, *source_tree(crate_dir)]
    return {n: sha256_file(crate_dir / n) if (crate_dir / n).is_file() else None for n in names}


def repo_relative(path: pathlib.Path) -> str:
    """A path as it may appear in a committed receipt: repo-relative, or a marker, never an absolute path."""
    try:
        return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return OUTSIDE_REPO


def build_manifest(
    crate_dir: pathlib.Path,
    triple: str,
    command: list[str] | None,
    sources: dict[str, str | None],
    target_dir: pathlib.Path,
    features: list[str] | None = None,
) -> dict[str, Any]:
    """What this receipt pins about the build. `command` is the exact argv handed to rch, or None when the
    runner was told to reuse existing artifacts (`--skip-build`); in that case the source digests describe the
    tree at verification time and are explicitly NOT bound to the binary that booted."""
    flags: list[str] = []
    if tomllib is not None:
        try:
            raw = tomllib.loads((crate_dir / ".cargo" / "config.toml").read_text())["target"][triple]["rustflags"]
            flags = [f for f in raw if isinstance(f, str)]
        except (OSError, KeyError, tomllib.TOMLDecodeError):
            flags = []
    built = command is not None
    manifest = {
        "command": command,
        "environment": {"RCH_REQUIRE_REMOTE": "1", "CARGO_TARGET_DIR": repo_relative(target_dir)} if built else None,
        "sources_sha256": sources,
        "sources_bound_to_binary": built,
        "toolchain": {
            "selector": "+nightly",
            "pinned": False,
            "note": "cargo +nightly selects the worker's nightly; the release and commit that built the binary are "
                    "the probe's FFW_BUILD report in build_identity",
        },
        "target": {
            "triple": triple,
            "target_json": None,
            "builtin_target": True,
            "rustflags": flags,
            "cpu_features_overridden": any(re.search(r"target-(cpu|feature)", f) for f in flags),
            "build_std": "core,panic_abort" if built and "build-std=core,panic_abort" in command else None,
        },
    }
    if features:
        # Only when there are some: a default run's manifest keeps exactly the shape it has always had.
        manifest["features"] = list(features)
    return manifest


def capture_guest(command: list[str], env: dict[str, str], timeout: float,
                  max_bytes: int = 8 * 1024 * 1024) -> dict[str, Any]:
    """Bound both runtime and retained bytes; kill only our process group.

    Timeout/output-limit prefixes remain diagnostic evidence, never a pass.
    Separate byte streams preserve CRLF and invalid UTF-8 without pretending
    their concatenation establishes ordering between stdout and stderr.
    """
    if timeout <= 0 or max_bytes <= 0:
        raise ValueError("positive capture limits required")
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    reason = None
    proc = subprocess.Popen(command, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True)
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
        selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = "timeout"
                    break
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    available = max_bytes - sum(map(len, streams.values()))
                    streams[key.data].extend(chunk[:available])
                    if len(chunk) > available:
                        reason = "output_limit"
                        break
                if reason:
                    break
            if reason is None:
                try:
                    proc.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    reason = "timeout"
        finally:
            # On timeout, overflow or interruption terminate the isolated
            # group before reaping its leader. Never signal a reaped PID,
            # which the OS could already have reused for an unrelated job.
            if proc.returncode is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            proc.wait()
            proc.stdout.close()
            proc.stderr.close()
    return {"stdout": bytes(streams["stdout"]), "stderr": bytes(streams["stderr"]),
            "returncode": proc.returncode, "stop_reason": reason}


# ---- franken-speaker smoke (E07 runner change; BeigeMaple mail 3794) ---------------------------------------------
#
# With `--speaker-mips/--speaker-ppc` the initramfs also carries `/franken-speaker` and the guest is built with the
# `speaker-smoke` feature: after every probe, PID 1 runs `/franken-speaker --catalog` as a child process and prints
#
#     FFW_SPEAKER_BEGIN path=/franken-speaker argv=--catalog
#     <the child's stdout, forwarded verbatim: the pretty-printed board catalog>
#     FFW_SPEAKER_EXIT status=0 stdout_bytes=<N> stdout_fnv1a64=<16 hex>
#
# before the usual summary markers. The expected markers are fixed here, before any run:
#   * the BEGIN line, exactly once, before the EXIT line;
#   * the EXIT line in its single success form (status 0, at least one byte of stdout); every other form is a
#     named failure (`speaker_failed:<what the guest said>`), never a pass;
#   * the console transcript between BEGIN and EXIT must be byte-for-byte what the guest measured (count and
#     FNV-1a-64), so a corrupted or interleaved transcript does not verify;
#   * that transcript must be the catalog the Rust source defines (`speaker_expect.judge_catalog`): the same
#     nine rows, in order, with the fields the source literals state and digests that recompute.
# The existing probe markers and their order are unchanged, and without the speaker flags any FFW_SPEAKER_* line
# is an unknown marker and fails the guest.

SPEAKER_FEATURE = "speaker-smoke"
SPEAKER_CPIO_NAME = "franken-speaker"          # `/franken-speaker` in the guest
SPEAKER_MODE = 0o100755
SPEAKER_ARCHES = ("mips", "ppc")

# Planted faults, one boot each. The real run is the "remove the plant" baseline: a control is only credited when
# the unplanted run of the same guest passed, and it must fail for exactly the planted reason and no other.
SPEAKER_CONTROLS: dict[str, dict[str, Any]] = {
    "missing": {
        "errno": 2,                             # ENOENT, the same number on both ABIs
        "plant": "no /franken-speaker entry in the archive",
    },
    "non_executable": {
        "errno": 13,                            # EACCES
        "plant": "/franken-speaker present with mode 0644",
    },
    "wrong_isa": {
        "errno": 8,                             # ENOEXEC: a valid static ELF32 BE for the other ISA
        "plant": "the other ISA's franken-speaker, mode 0755",
    },
}


def judge_speaker(raw_log: str, lines: list[str], positions: dict[str, int], errors: list[str],
                  speaker: dict[str, Any]) -> dict[str, Any]:
    """The speaker half of a transcript: grammar, console-versus-guest measurement, and the catalog itself.
    Appends named errors to `errors`; returns the record that goes into the receipt."""
    record: dict[str, Any] = {
        "argv": [speaker_expect.SPEAKER_PATH, speaker_expect.SPEAKER_ARG],
        "outcome": "not_run",
        "exit_line": None,
    }
    begin, exit_at = positions.get("FFW_SPEAKER_BEGIN"), positions.get("FFW_SPEAKER_EXIT")
    if exit_at is None:
        return record
    exit_line = lines[exit_at]
    record["exit_line"] = exit_line
    if begin is not None and begin > exit_at:
        errors.append("speaker_order:exit_before_begin")
    ok = speaker_expect.EXIT_OK.fullmatch(exit_line)
    if ok is None:
        record["outcome"] = "failed" if speaker_expect.EXIT_FAILURE.fullmatch(exit_line) else "invalid"
        return record
    record["outcome"] = "exited_0"
    reported = {"stdout_bytes": int(ok.group(1)), "stdout_fnv1a64": ok.group(2)}
    record["reported"] = reported
    host = speaker.get("host")
    if host is not None:
        record["host_catalog"] = host
        if (reported["stdout_bytes"], reported["stdout_fnv1a64"]) != (host["stdout_bytes"], host["stdout_fnv1a64"]):
            errors.append("speaker_stdout_differs_from_host")
    region, reason = speaker_expect.stdout_region(raw_log)
    if region is None:
        errors.append(f"speaker_region:{reason}")
        return record
    measured = {"stdout_bytes": len(region), "stdout_fnv1a64": f"{speaker_expect.fnv1a64(region):016x}"}
    record["console_region"] = measured
    if measured["stdout_bytes"] != reported["stdout_bytes"]:
        errors.append("speaker_stdout_mismatch:bytes")
    if measured["stdout_fnv1a64"] != reported["stdout_fnv1a64"]:
        errors.append("speaker_stdout_mismatch:fnv1a64")
    problems = speaker_expect.judge_catalog(region, speaker["expected"])
    record["catalog"] = {"rows_expected": len(speaker["expected"]["rows"]), "problems": problems}
    errors.extend(f"speaker_catalog:{problem}" for problem in problems)
    return record


def judge_speaker_control(verification: dict[str, Any], expected_errno: int,
                          stop_reason: str | None, returncode: int | None) -> dict[str, Any]:
    """Was a planted fault caught, and for the right reason? Every check must hold: the guest failed; the only
    validation errors are the planted exec failure with its errno and the guest's own TEST_FAILURE line (which
    this verifier has always reported as an unknown marker, so a failing guest always carries it); the only
    missing marker is the success marker (every probe line was still valid); the only forbidden marker is that
    same TEST_FAILURE; and the capture ended cleanly (QEMU exit 0, no timeout)."""
    checks = {
        "guest_failed": verification["status"] == "FAIL",
        "only_the_planted_error": verification["validation_errors"] == [
            f"speaker_failed:spawn=exec errno={expected_errno}", "invalid:FFW_MARKER:TEST_FAILURE"],
        "only_the_success_marker_missing": verification["missing_markers"] == ["FFW_MARKER:TEST_SUCCESS"],
        "only_the_guest_failure_marker": verification["forbidden_hits"] == ["FFW_MARKER:TEST_FAILURE"],
        "clean_capture": stop_reason is None and returncode == 0,
    }
    return {"checks": checks, "caught": all(checks.values())}


def speaker_binary_facts(arch: str, path: pathlib.Path, data: bytes,
                         archive_receipt: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Facts about the speaker binary that was packed, and the errors they imply: it must be a static ELF32
    big-endian executable for the guest's ISA, and the archive entry must be those exact bytes."""
    elf = inspect_static_elf(path, arch)
    entry = archive_receipt.get("extra_files", {}).get(SPEAKER_CPIO_NAME)
    sha256 = hashlib.sha256(data).hexdigest()
    errors = []
    if elf["problems"]:
        errors.append("speaker_elf:" + ",".join(elf["problems"]))
    if entry is None or entry["sha256"] != sha256:
        errors.append("speaker_entry_differs_from_binary")
    return {"path": repo_relative(path), "sha256": sha256, "bytes": len(data), "static_elf": elf,
            "archive_entry": entry}, errors


SPEAKER_BOUNDARY = (
    "Generic full-system QEMU guests (Debian Linux 4.19 Malta / 4.9 g3beige), not Sonos silicon or kernels. Shows "
    "the linked franken-speaker starts as a userspace process under a retained-kernel-class guest, runs std, "
    "allocation, serde_json and SHA-256 on a big-endian CPU, and prints the catalog the Rust source defines. "
    "The catalog has no floating point and the run uses no network, audio or threads beyond startup, so it says "
    "nothing about the float ABI, drivers, timing or memory pressure on a real unit."
)


def run_speaker_controls(arch: str, cfg: dict[str, Any], bin_path: pathlib.Path,
                         speaker_bins: dict[str, pathlib.Path], results_dir: pathlib.Path,
                         build_dir: pathlib.Path, timeout: float, speaker_ctx: dict[str, Any]) -> dict[str, Any]:
    """Boot this guest once per planted fault and judge each with the same verifier that judged the real run.

    Each control uses the SAME hello-init binary as the real run; only the archive differs. The record keeps the
    raw logs, so a reader can see the guest's own EXIT line, not just the verdict."""
    own = speaker_bins[arch].read_bytes()
    other_arch = next(name for name in SPEAKER_ARCHES if name != arch)
    other = speaker_bins[other_arch].read_bytes()
    plants: dict[str, list[tuple[str, int, bytes]]] = {
        "missing": [],
        "non_executable": [(SPEAKER_CPIO_NAME, 0o100644, own)],
        "wrong_isa": [(SPEAKER_CPIO_NAME, SPEAKER_MODE, other)],
    }
    controls: dict[str, Any] = {}
    for name, spec in SPEAKER_CONTROLS.items():
        initrd_path = results_dir / f"initramfs-{arch}-control-{name}.cpio.gz"
        archive = mkinitramfs.build(bin_path, initrd_path, extra_files=plants[name])
        entry = archive.get("extra_files", {}).get(SPEAKER_CPIO_NAME)
        env = os.environ.copy()
        env["FFW_BUILD_DIR"] = str(build_dir)
        env["FFW_INITRAMFS"] = str(initrd_path.resolve())
        capture = capture_guest([str(cfg["boot_script"])], env, timeout)
        raw = capture["stdout"] + capture["stderr"]
        prefix = f"boot-{arch}-control-{name}"
        for stream in ("stdout", "stderr"):
            with (results_dir / f"{prefix}-{stream}.bin").open("xb") as output:
                output.write(capture[stream])
        with (results_dir / f"{prefix}-serial.log").open("xb") as output:
            output.write(raw)
        verification = verify_serial_output(arch, cfg["hello"], cfg["enosys"], raw.decode("utf-8", errors="replace"),
                                            cfg["triple"], speaker=speaker_ctx)
        judged = judge_speaker_control(verification, spec["errno"], capture["stop_reason"], capture["returncode"])
        # The plant must be what it claims to be, read back from the archive that was booted.
        planted = {
            "missing": entry is None,
            "non_executable": entry is not None and entry["mode"] == oct(0o100644)
            and entry["sha256"] == hashlib.sha256(own).hexdigest(),
            "wrong_isa": entry is not None and entry["mode"] == oct(SPEAKER_MODE)
            and entry["sha256"] == hashlib.sha256(other).hexdigest(),
        }[name]
        judged["checks"]["plant_is_what_it_claims"] = planted
        judged["caught"] = all(judged["checks"].values())
        controls[name] = {
            "plant": spec["plant"],
            "expected_errno": spec["errno"],
            "archive_sha256": archive["archive_sha256"],
            "archive_entry": entry,
            "serial_log_path": f"{prefix}-serial.log",
            "serial_log_sha256": hashlib.sha256(raw).hexdigest(),
            "capture_stop_reason": capture["stop_reason"],
            "qemu_exit_code": capture["returncode"],
            "status": verification["status"],
            "validation_errors": verification["validation_errors"],
            "missing_markers": verification["missing_markers"],
            "forbidden_hits": verification["forbidden_hits"],
            "speaker_exit_line": verification["speaker"]["exit_line"],
            **judged,
        }
    return controls


def verify_serial_output(
    arch: str, expected_hello: str, expected_enosys: str, raw_log: str, expected_triple: str,
    speaker: dict[str, Any] | None = None,
) -> dict[str, Any]:
    lines = [line.strip() for line in raw_log.splitlines()]
    forbidden_hits = [bad for bad in FORBIDDEN_SUBSTRINGS if bad in raw_log]
    # Parse the exact v1 transcript. Substring matching accepts errno=890 as
    # errno=89, failures=01 as zero, and even shell-echoed markers as execution.
    patterns = {
        "FFW_MARKER:USERSPACE_START": r"FFW_MARKER:USERSPACE_START",
        "FFW_HELLO": re.escape(expected_hello),
        "FFW_BUILD": build_identity_pattern(expected_triple),
        "FFW_RUSTC": RUSTC_PATTERN,
        "FFW_KERNEL_VERSION:": r"FFW_KERNEL_VERSION: Linux version \S.*",
        "FFW_TEST:ERR_ENOENT": r"FFW_TEST:ERR_ENOENT status=PASS errno=2",
        "FFW_TEST:ERR_EBADF": r"FFW_TEST:ERR_EBADF status=PASS errno=9",
        "FFW_TEST:ERR_ENOSYS": re.escape(expected_enosys),
        "FFW_TEST:POS_FD_SHORT_WRITE": r"FFW_TEST:POS_FD_SHORT_WRITE status=PASS fd=[0-9]+",
        "FFW_TEST:PARTIAL_WRITE": r"FFW_TEST:PARTIAL_WRITE status=PASS bytes=[1-9][0-9]*",
        "FFW_PROBE:CLOCK_MONOTONIC": r"FFW_PROBE:CLOCK_MONOTONIC status=PASS res_ns=[1-9][0-9]*",
        "FFW_PROBE:NONBLOCK_PIPE": r"FFW_PROBE:NONBLOCK_PIPE status=PASS rc=0",
        "FFW_PROBE:POLL": r"FFW_PROBE:POLL status=PASS rc=1",
        "FFW_PROBE:EPOLL": r"FFW_PROBE:EPOLL status=PASS fd=[0-9]+",
        "FFW_PROBE:SOCKET_UDP": r"FFW_PROBE:SOCKET_UDP status=PASS fd=[0-9]+",
        "FFW_PROBE:ENTROPY": r"FFW_PROBE:ENTROPY status=PASS fd=[0-9]+",
        "FFW_PROBE:ATOMICS_32": r"FFW_PROBE:ATOMICS_32 status=PASS ok=1",
        **{
            f"FFW_PROBE:{name}": optional_probe_pattern(name, enosys_errno_of(expected_enosys))
            for name in OPTIONAL_PROBES
        },
        **{f"FFW_PROBE:{name}": required_probe_pattern(name) for name in REQUIRED_PROBES},
        **{f"FFW_GUEST:{name}": guest_setup_pattern(name) for name in GUEST_SETUP},
        "FFW_MARKER:TEST_SUCCESS": r"FFW_MARKER:TEST_SUCCESS failures=0",
        "FFW_MARKER:REBOOT_REQUEST": r"FFW_MARKER:REBOOT_REQUEST",
    }
    if speaker is not None:
        patterns["FFW_SPEAKER_BEGIN"] = re.escape(speaker_expect.BEGIN_LINE)
        patterns["FFW_SPEAKER_EXIT"] = speaker_expect.EXIT_OK.pattern
    positions: dict[str, int] = {}
    errors = []
    probes = {}
    for idx, line in enumerate(lines):
        if not line.startswith("FFW_"):
            continue
        key = line.split()[0]
        if key in positions:
            errors.append(f"duplicate:{key}")
        else:
            positions[key] = idx
        pattern = patterns.get(key)
        if pattern is None or re.fullmatch(pattern, line) is None:
            if speaker is not None and key == "FFW_SPEAKER_EXIT" and speaker_expect.EXIT_FAILURE.fullmatch(line):
                # The guest said exactly how the speaker failed; name that, do not call it a malformed line.
                errors.append("speaker_failed:" + line[len("FFW_SPEAKER_EXIT "):])
            elif key == "FFW_GUEST:CONSOLE_LEVEL" and CONSOLE_LEVEL_FAILURE.fullmatch(line):
                # The guest said exactly what the kernel answered; name that.
                errors.append("console_level_refused:" + line[len("FFW_GUEST:CONSOLE_LEVEL "):])
            else:
                errors.append(f"invalid:{key}")
        elif key == "FFW_TEST:PARTIAL_WRITE" and int(line.rsplit("=", 1)[1]) >= 8192:
            errors.append("invalid:partial_write_count_is_not_partial")
        if line.startswith("FFW_TEST:") or line.startswith("FFW_PROBE:"):
            well_formed = pattern is not None and re.fullmatch(pattern, line) is not None
            token = re.search(r" status=(PASS|FAIL|UNSEEDED)(?: |$)", line)
            guest_status = token.group(1) if token is not None else "FAIL"
            # The recorded status is the guest's own token: a well-formed explicit -ENOSYS is a FAIL here, never
            # PASS, and UNSEEDED is neither. A line that did not parse is FAIL whatever it claims.
            record: dict[str, Any] = {"raw": line, "status": guest_status if well_formed else "FAIL"}
            if well_formed and key in OPTIONAL_PROBE_KEYS:
                record["capability"] = {"PASS": "supported", "FAIL": "unsupported", "UNSEEDED": "unseeded"}[guest_status]
            probes[key] = record

    missing = [key for key in patterns if key not in positions]
    idx_start = positions.get("FFW_MARKER:USERSPACE_START", -1)
    idx_success = positions.get("FFW_MARKER:TEST_SUCCESS", -1)
    idx_reboot = positions.get("FFW_MARKER:REBOOT_REQUEST", -1)
    control_markers = {
        "FFW_MARKER:USERSPACE_START", "FFW_MARKER:TEST_SUCCESS", "FFW_MARKER:REBOOT_REQUEST"
    }
    order_ok = 0 <= idx_start < idx_success < idx_reboot and all(
        idx_start < idx < idx_success
        for key, idx in positions.items() if key not in control_markers
    )

    kernel_version = None
    for line in lines:
        if line.startswith("FFW_KERNEL_VERSION: "):
            kernel_version = line[len("FFW_KERNEL_VERSION: ") :]
            break

    # A compiler or linker flavor the build could not read is not a recorded identity.
    build_identity = next((parse_build_identity(l) for l in lines if l.startswith("FFW_BUILD ")), None)
    if build_identity is not None:
        for name in ("rustc", "rustc_commit", "linker_flavor"):
            if build_identity[name] in UNIDENTIFIED:
                errors.append(f"unidentified:FFW_BUILD.{name}")

    # The two compiler reports must describe the same compiler: FFW_BUILD carries the release and the short commit.
    rustc_identity = next((parse_rustc_identity(l) for l in lines if l.startswith("FFW_RUSTC ")), None)
    if rustc_identity is not None:
        for name in ("release", "host", "llvm"):
            if rustc_identity[name] in UNIDENTIFIED:
                errors.append(f"unidentified:FFW_RUSTC.{name}")
        if build_identity is not None and (
            build_identity["rustc"] != rustc_identity["release"]
            or rustc_identity["commit_hash"][:9] != build_identity["rustc_commit"]
        ):
            errors.append("inconsistent:FFW_BUILD_vs_FFW_RUSTC")

    speaker_record = judge_speaker(raw_log, lines, positions, errors, speaker) if speaker is not None else None

    passed = (not forbidden_hits) and (not missing) and (not errors) and order_ok
    result = {
        "arch": arch,
        "status": "PASS" if passed else "FAIL",
        "build_identity": build_identity,
        "rustc_identity": rustc_identity,
        "kernel_version": kernel_version,
        "forbidden_hits": forbidden_hits,
        "missing_markers": missing,
        "validation_errors": errors,
        "marker_order_ok": order_ok,
        "probes": probes,
        # Probes that ran and got an explicit -ENOSYS. Kept apart from `missing_markers` (did not run).
        "unsupported_capabilities": sorted(
            key.split(":", 1)[1] for key, rec in probes.items() if rec.get("capability") == "unsupported"
        ),
        # Probes that ran, found the call present, and got no entropy because the pool is not yet seeded. Never
        # merged with `unsupported_capabilities`: the call exists, and this says nothing about secure entropy.
        "unseeded_capabilities": sorted(
            key.split(":", 1)[1] for key, rec in probes.items() if rec.get("capability") == "unseeded"
        ),
    }
    if speaker_record is not None:
        result["speaker"] = speaker_record
    return result


def run_verification(args: argparse.Namespace, results_dir: pathlib.Path) -> int:
    build_dir = mkinitramfs.resolve_default_build_dir(REPO_ROOT)

    self_test_receipt = mkinitramfs.self_test()

    hello_crate = SCRIPT_DIR / "ffw-hello-init"
    # Speaker mode builds a different binary from the same crate (feature `speaker-smoke`), so it gets its own
    # default target directory: the default E07 build products are never overwritten by it.
    speaker_bins: dict[str, pathlib.Path] | None = getattr(args, "speaker_binaries", None)
    speaker_ctx: dict[str, Any] | None = None
    if speaker_bins is not None:
        speaker_ctx = {"expected": speaker_expect.load_expected(REPO_ROOT)}
        if getattr(args, "speaker_host", None) is not None:
            speaker_ctx["host"] = args.speaker_host           # already checked in main(), before anything ran
    target_dir = args.target_dir or build_dir / (
        "hello-init-speaker-target" if speaker_bins is not None else "hello-init-target")

    targets = {
        "mips": {
            "triple": "mips-unknown-linux-musl",
            "hello": "FFW_HELLO arch=mips-be endian=0x01020304 pid=1 ptr_bits=32",
            "enosys": "FFW_TEST:ERR_ENOSYS status=PASS errno=89",
            "boot_script": SCRIPT_DIR / "boot-mips.sh",
            "kernel_path": build_dir / "kernels" / "xm" / "boot" / "vmlinux-4.19.0-21-4kc-malta",
            "qemu_bin": "qemu-system-mips",
        },
        "ppc": {
            "triple": "powerpc-unknown-linux-musl",
            "hello": "FFW_HELLO arch=powerpc-be endian=0x01020304 pid=1 ptr_bits=32",
            "enosys": "FFW_TEST:ERR_ENOSYS status=PASS errno=38",
            "boot_script": SCRIPT_DIR / "boot-ppc.sh",
            "kernel_path": build_dir / "kernels" / "x" / "boot" / "vmlinux-4.9.0-0.bpo.6-powerpc",
            "qemu_bin": "qemu-system-ppc",
        },
    }

    # Hashed before the build so the digests describe what was handed to rch, not what the tree became after.
    sources = source_digests(hello_crate)
    build_commands: dict[str, list[str]] = {}
    if not args.skip_build:
        for arch, cfg in targets.items():
            cmd = [
                "rch",
                "exec",
                "--source-content-receipt",
                "--",
                "cargo",
                "+nightly",
                "build",
                "--release",
                "--target",
                cfg["triple"],
                "-Z",
                "build-std=core,panic_abort",
            ]
            if speaker_bins is not None:
                cmd += ["--features", SPEAKER_FEATURE]
            # RCH admits a build against a worker's slot count using ITS OWN core estimate, which ignores
            # CARGO_BUILD_JOBS, so the job count has to be in the command itself ("-j 3 (or fewer)" on a
            # 3-slot worker). Recorded verbatim in build_manifest.command like every other argument.
            jobs = getattr(args, "jobs", None)
            if jobs is not None:
                cmd += ["-j", str(jobs)]
            build_commands[arch] = list(cmd)
            env = os.environ.copy()
            env["CARGO_TARGET_DIR"] = str(target_dir)
            env["RCH_REQUIRE_REMOTE"] = "1"
            subprocess.run(cmd, cwd=str(hello_crate), env=env, check=True, timeout=3600)

    archive_receipts = {}
    guest_results = {}
    args.receipt["guests"] = guest_results
    overall_pass = True

    for arch, cfg in targets.items():
        bin_path = target_dir / cfg["triple"] / "release" / "ffw-hello-init"
        initrd_path = results_dir / f"initramfs-{arch}.cpio.gz"
        speaker_bytes = speaker_bins[arch].read_bytes() if speaker_bins is not None else None
        if speaker_bytes is not None:
            archive_receipts[arch] = mkinitramfs.build(
                bin_path, initrd_path, extra_files=[(SPEAKER_CPIO_NAME, SPEAKER_MODE, speaker_bytes)])
        else:
            archive_receipts[arch] = mkinitramfs.build(bin_path, initrd_path)

        t0 = time.monotonic()
        env = os.environ.copy()
        env["FFW_BUILD_DIR"] = str(build_dir)
        env["FFW_INITRAMFS"] = str(initrd_path.resolve())
        capture = capture_guest([str(cfg["boot_script"])], env, args.timeout)
        stdout, stderr, returncode = capture["stdout"], capture["stderr"], capture["returncode"]
        timed_out = capture["stop_reason"] == "timeout"
        elapsed_s = round(time.monotonic() - t0, 3)
        # Preserve exact bytes, including invalid UTF-8 and CRLF, separately.
        # Concatenation below is a parser view, not a cross-stream ordering claim.
        for stream, data in (("stdout", stdout), ("stderr", stderr)):
            with (results_dir / f"boot-{arch}-{stream}.bin").open("xb") as output:
                output.write(data)
        raw_combined = stdout + stderr
        combined = raw_combined.decode("utf-8", errors="replace")
        log_path = results_dir / f"boot-{arch}-serial.log"
        with log_path.open("xb") as output:
            output.write(raw_combined)

        verification = verify_serial_output(arch, cfg["hello"], cfg["enosys"], combined, cfg["triple"],
                                            speaker=speaker_ctx)
        elf = inspect_static_elf(bin_path, arch)
        linker = configured_linker(hello_crate, cfg["triple"])
        identity = verification["build_identity"]
        identity_errors = []
        speaker_facts = None
        if speaker_bytes is not None:
            speaker_facts, speaker_errors = speaker_binary_facts(
                arch, speaker_bins[arch], speaker_bytes, archive_receipts[arch])
            identity_errors.extend(speaker_errors)
        binary_sha256 = sha256_file(bin_path)
        # The archive's init entry is what QEMU executed; it must be the binary this receipt names and inspects.
        if archive_receipts[arch].get("init_sha256") != binary_sha256:
            identity_errors.append("initramfs_init_differs_from_binary")
        if elf["problems"]:
            identity_errors.append("libc_claim_unsupported_by_elf:" + ",".join(elf["problems"]))
        if identity is not None and linker["flavor"] is not None and identity["linker_flavor"] != linker["flavor"]:
            identity_errors.append("linker_flavor_differs_from_committed_config")
        if identity_errors:
            verification["validation_errors"].extend(identity_errors)
            verification["status"] = "FAIL"
        verification.update(
            {
                # What the runner built and booted, and what the probe reported about its own compile.
                "target_triple": cfg["triple"],
                "libc": {
                    # What the ELF check PROVES is a static executable with no interpreter or dynamic section. It
                    # cannot tell "no libc" from "statically linked musl"; `libc=none` is the build's own claim.
                    "conclusion": "static_no_loader" if identity is not None and identity["libc"] == "none"
                    and not elf["problems"] else "unverified",
                    "reported_by_probe": identity["libc"] if identity is not None else None,
                    "static_elf": elf,
                },
                "booted_init_sha256": archive_receipts[arch].get("init_sha256"),
                "linker_configured": linker,
                "build_manifest": build_manifest(
                    hello_crate, cfg["triple"], build_commands.get(arch), sources, target_dir,
                    [SPEAKER_FEATURE] if speaker_bins is not None else None),
                "qemu_exit_code": returncode,
                "timed_out": timed_out,
                "capture_stop_reason": capture["stop_reason"],
                "capture_byte_limit": 8 * 1024 * 1024,
                "elapsed_seconds": elapsed_s,
                "binary_sha256": sha256_file(bin_path),
                "binary_bytes": bin_path.stat().st_size,
                "initramfs_sha256": archive_receipts[arch]["archive_sha256"],
                "kernel_sha256": sha256_file(cfg["kernel_path"]),
                "serial_log_path": log_path.name,
                "serial_log_sha256": hashlib.sha256(raw_combined).hexdigest(),
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                "capture_layout": "stdout-then-stderr; separate raw streams retained",
                "qualification_boundary": (
                    "Full-system Debian QEMU guest (Linux 4.19 Malta / Linux 4.9 g3beige); "
                    "proves ISA, endianness, static ELF startup, initramfs device nodes, and "
                    "syscall ABI probes; does not substitute for stock Sonos 2.4/2.6 kernel or "
                    "proprietary audio driver qualification."
                ),
            }
        )
        if speaker_bins is not None and speaker_facts is not None:
            verification["speaker"]["binary"] = speaker_facts
            verification["speaker"]["qualification_boundary"] = SPEAKER_BOUNDARY
            if getattr(args, "speaker_controls", False):
                # Credited only against a green baseline: a planted fault proves nothing if the unplanted run of
                # the same guest did not pass.
                baseline_ok = not capture["stop_reason"] and returncode == 0 and verification["status"] == "PASS"
                if baseline_ok:
                    controls = run_speaker_controls(arch, cfg, bin_path, speaker_bins, results_dir, build_dir,
                                                    args.timeout, speaker_ctx)
                else:
                    controls = {name: {"skipped": "baseline_failed"} for name in SPEAKER_CONTROLS}
                verification["speaker"]["controls"] = controls
                for name, record in controls.items():
                    if "skipped" in record:
                        verification["validation_errors"].append(f"speaker_control_not_run:{name}")
                        verification["status"] = "FAIL"
                    elif not record["caught"]:
                        verification["validation_errors"].append(f"speaker_control_not_caught:{name}")
                        verification["status"] = "FAIL"
        if capture["stop_reason"] or returncode != 0 or verification["status"] != "PASS":
            verification["status"] = "FAIL"
            overall_pass = False
        guest_results[arch] = verification
        # Persist completed guests before starting the next one. A later
        # exception must retain both successful and failed earlier evidence.
        (results_dir / "e07-e03-verification-receipt.json").write_text(
            json.dumps(args.receipt, indent=2, sort_keys=True) + "\n"
        )

    receipt = {
        "schema_version": "ffw.e07_e03.receipt.v1",
        "run_id": args.run_id,
        "status": "PASS" if overall_pass else "FAIL",
        "build_provenance": {
            "status": "not_attested_by_this_boot_runner",
            "note": (
                "Binary hashes bind this boot. Each guest's build_identity is the probe's own FFW_BUILD report "
                "(target, rustc release and commit, linker flavor, libc) plus the FFW_RUSTC `rustc -vV` fields; it "
                "describes the booted bytes (the archive's init entry is checked against binary_sha256) but is not "
                "an attestation of the remote compiler or linker, which requires the separate build receipt. "
                "Each guest's build_manifest records the exact build command and the digests of the sources, "
                "lockfile and cargo config handed to rch; those digests are bound to the binary only when the "
                "runner built it itself (sources_bound_to_binary), never under --skip-build. "
                "Local rustc is not the remote compiler."
            ),
        },
        "local_inspection_tools": {
            "host_rustc_nightly": cmd_version(["rustc", "+nightly", "--version"]),
            "host_lld": cmd_version(["ld.lld", "--version"]),
            "qemu_mips": cmd_version(["qemu-system-mips", "--version"]),
            "qemu_ppc": cmd_version(["qemu-system-ppc", "--version"]),
            "bootstrap_policy_note": (
                "Nightly -Z build-std=core,panic_abort and asm_experimental_arch are scoped "
                "strictly to the freestanding PID-1 bootstrap probe; production application, "
                "protocol, and DSP crates target stable Rust with #![forbid(unsafe_code)]."
            ),
        },
        "mkinitramfs_self_test": self_test_receipt,
        "guests": guest_results,
    }
    if speaker_ctx is not None:
        expected = speaker_ctx["expected"]
        receipt["speaker_smoke"] = {
            "feature": SPEAKER_FEATURE,
            "argv": [speaker_expect.SPEAKER_PATH, speaker_expect.SPEAKER_ARG],
            "controls_requested": bool(getattr(args, "speaker_controls", False)),
            "expected_source": {"path": expected["source"], "sha256": expected["source_sha256"],
                                "schema_version": expected["schema_version"], "rows": len(expected["rows"])},
            "host_catalog": speaker_ctx.get("host"),
        }

    receipt_path = results_dir / "e07-e03-verification-receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if overall_pass else 1


def check_catalog_file(path: pathlib.Path, parser: argparse.ArgumentParser) -> int:
    """`--check-catalog`: judge a `franken-speaker --catalog` stdout file and print the verdict. Run it on the HOST
    build's output first: it must pass there (that validates this checker, including its SHA-256 replication)
    before a guest's output is held to it. The printed byte count and FNV-1a-64 are what a guest's EXIT line must
    equal if the catalog is byte-identical across ISAs, which JSON text should be."""
    if not path.is_file():
        parser.error(f"--check-catalog: not a file: {path.name}")
    data = path.read_bytes()
    expected = speaker_expect.load_expected(REPO_ROOT)
    problems = speaker_expect.judge_catalog(data, expected)
    print(json.dumps({
        "checked": path.name,
        "status": "PASS" if not problems else "FAIL",
        "problems": problems,
        "stdout_bytes": len(data),
        "stdout_fnv1a64": f"{speaker_expect.fnv1a64(data):016x}",
        "sha256": hashlib.sha256(data).hexdigest(),
        "rows_expected": len(expected["rows"]),
        "expected_source": {"path": expected["source"], "sha256": expected["source_sha256"]},
    }, indent=2, sort_keys=True))
    return 0 if not problems else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-build", action="store_true", help="Use existing artifacts; do not compile")
    parser.add_argument("--timeout", type=float, default=30.0, help="Per-guest QEMU timeout in seconds")
    parser.add_argument("--target-dir", type=pathlib.Path, help="Directory containing target-triple/release artifacts")
    parser.add_argument("--results-dir", type=pathlib.Path, help="New output directory; existing directories are refused")
    parser.add_argument("--jobs", type=int, default=None, metavar="N",
                        help="append -j N to each cargo build command (RCH admits against a worker's slot count)")
    speaker = parser.add_argument_group(
        "franken-speaker smoke",
        "Run the linked franken-speaker as a userspace process in each guest (see the franken-speaker smoke "
        "section above verify_serial_output). The guests are then built with the `speaker-smoke` feature.")
    speaker.add_argument("--speaker-mips", type=pathlib.Path, metavar="PATH",
                         help="static ELF32 big-endian MIPS franken-speaker to pack as /franken-speaker")
    speaker.add_argument("--speaker-ppc", type=pathlib.Path, metavar="PATH",
                         help="static ELF32 big-endian PowerPC franken-speaker to pack as /franken-speaker")
    speaker.add_argument("--speaker-controls", action="store_true",
                         help="also boot each guest with planted faults (missing, non-executable, wrong-ISA "
                              "binary); each must fail for exactly the planted reason or the run fails")
    speaker.add_argument("--speaker-host-catalog", type=pathlib.Path, metavar="FILE",
                         help="stdout of the HOST build's `franken-speaker --catalog`; it must pass the catalog "
                              "check itself (positive control) and each guest's stdout must equal it exactly")
    parser.add_argument("--check-catalog", type=pathlib.Path, metavar="FILE",
                        help="only judge FILE (a `franken-speaker --catalog` stdout) against the catalog the Rust "
                             "source defines, print the verdict and exit; runs no guest")
    args = parser.parse_args(argv)
    if not 0 < args.timeout <= 3600:
        parser.error("timeout must be positive, finite and no greater than 3600 seconds")
    if args.jobs is not None and not 1 <= args.jobs <= 256:
        parser.error("--jobs must be between 1 and 256")
    if args.jobs is not None and args.skip_build:
        parser.error("--jobs has no effect with --skip-build (no build runs, so no command would record it)")

    args.speaker_binaries = None
    args.speaker_host = None
    if args.check_catalog is not None:
        if (args.speaker_mips is not None or args.speaker_ppc is not None
                or args.speaker_host_catalog is not None or args.speaker_controls):
            parser.error("--check-catalog stands alone; it runs no guest")
        return check_catalog_file(args.check_catalog, parser)
    if args.speaker_mips is not None or args.speaker_ppc is not None:
        if args.speaker_mips is None or args.speaker_ppc is None:
            parser.error("--speaker-mips and --speaker-ppc go together: both guests run the same build")
        args.speaker_binaries = {"mips": args.speaker_mips, "ppc": args.speaker_ppc}
        for arch, path in args.speaker_binaries.items():
            if not path.is_file():
                parser.error(f"--speaker-{arch}: not a file: {path.name}")
            problems = inspect_static_elf(path, arch)["problems"]
            if problems:
                parser.error(f"--speaker-{arch}: not a static ELF32 big-endian {arch} executable: {','.join(problems)}")
        if args.speaker_host_catalog is not None:
            if not args.speaker_host_catalog.is_file():
                parser.error(f"--speaker-host-catalog: not a file: {args.speaker_host_catalog.name}")
            host_bytes = args.speaker_host_catalog.read_bytes()
            host_problems = speaker_expect.judge_catalog(host_bytes, speaker_expect.load_expected(REPO_ROOT))
            if host_problems:
                # The positive control: the HOST build's own output must satisfy the checker before any guest is
                # blamed. A failure here belongs to the checker or the source, not to a guest.
                parser.error("--speaker-host-catalog does not satisfy the catalog check: " + "; ".join(host_problems[:5]))
            args.speaker_host = {"stdout_bytes": len(host_bytes),
                                 "stdout_fnv1a64": f"{speaker_expect.fnv1a64(host_bytes):016x}",
                                 "sha256": hashlib.sha256(host_bytes).hexdigest()}
    elif args.speaker_controls or args.speaker_host_catalog is not None:
        parser.error("--speaker-controls and --speaker-host-catalog need --speaker-mips and --speaker-ppc")
    run_id = args.run_id = uuid.uuid4().hex
    results_dir = args.results_dir or REPO_ROOT / "toolchain" / "results" / "runs" / run_id
    results_dir.mkdir(parents=True, exist_ok=False)
    receipt_path = results_dir / "e07-e03-verification-receipt.json"
    receipt = {"schema_version": "ffw.e07_e03.receipt.v1", "run_id": run_id, "status": "INCOMPLETE"}
    args.receipt = receipt
    receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n")
    try:
        return run_verification(args, results_dir)
    except (Exception, KeyboardInterrupt) as exc:
        receipt.update(status="FAIL", error_type=type(exc).__name__)
        receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n")
        print(json.dumps(receipt), file=sys.stderr)
        return 130 if isinstance(exc, KeyboardInterrupt) else 1


if __name__ == "__main__":
    sys.exit(main())
