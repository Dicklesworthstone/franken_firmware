#!/usr/bin/env python3
"""Generate crates/franken-speaker/src/guest_evidence.rs from the committed E03 harness-guest transcripts (P02 / ffw-jub).

The device speaker admits its platform layer against a `KernelCapabilityMatrix`. The only kernels that have evidence are the two
Debian harness kernels E03 booted in full-system QEMU (central run 1412ac47...). This script derives their matrices from the
committed serial transcripts through the E03 oracle (tests/e03/abi.py), so no capability status is typed by hand, and it REFUSES
to emit anything for evidence the oracle does not call matching-guest, self-consistent and (apart from GETRANDOM, which may be
`unseeded`) fully `supported`.

    scripts/p02/gen_guest_evidence.py            check: exit 1 if the committed file differs from what the transcripts give
    scripts/p02/gen_guest_evidence.py --write    rewrite the committed file

Stdlib only, offline, deterministic, no absolute paths in the output.
"""
import argparse
import hashlib
import importlib.util
import os
import re
import sys

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
ORACLE = os.path.join(ROOT, "tests", "e03", "abi.py")
RUN_ID = "1412ac47120d4e5b865f9de6e05f50fe"
RUN_REL = "toolchain/results/runs/" + RUN_ID
OUTPUT = os.path.join(ROOT, "crates", "franken-speaker", "src", "guest_evidence.rs")

# (static name, Abi variant, oracle profile, transcript file)
GUESTS = [
    ("HARNESS_PPC", "PowerPc32", "harness-ppc-4.9", "boot-ppc-serial.log"),
    ("HARNESS_MIPS", "Mips32", "harness-mips-4.19", "boot-mips-serial.log"),
]
# (matrix field, oracle probe). `clock_monotonic` also carries the resolution; `static_elf_startup` has no probe of its own.
FIELDS = [
    ("clock_monotonic", "CLOCK_MONOTONIC"),
    ("nonblocking_pipe_io", "NONBLOCK_PIPE"),
    ("poll_syscall", "POLL"),
    ("epoll_syscall", "EPOLL"),
    ("udp_socket_io", "SOCKET_UDP"),
    ("urandom_entropy", "ENTROPY"),
    ("getrandom_syscall", "GETRANDOM"),
    ("atomics_32bit", "ATOMICS_32"),
    ("atomics_64bit_fallback", "ATOMIC_WIDTH"),
    ("eventfd_syscall", "EVENTFD2"),
]
VARIANT = {"supported": "Supported", "unseeded": "ObservedUnseeded"}


class EvidenceError(Exception):
    """The transcript does not establish what a matrix needs; nothing is emitted."""


def load_oracle():
    spec = importlib.util.spec_from_file_location("ffw_p02_gen_abi", ORACLE)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ffw_p02_gen_abi"] = module
    spec.loader.exec_module(module)
    return module


def derive(oracle, profile, text):
    """The facts one transcript gives, or EvidenceError."""
    result = oracle.classify_run(text, profile, "full-system")
    if result["evidence"] != "matching-guest":
        raise EvidenceError("%s: evidence is %r, not matching-guest (%s)" % (profile, result["evidence"], result["evidence_reason"]))
    if result["verdict"] not in ("green", "degraded"):
        raise EvidenceError("%s: verdict is %r" % (profile, result["verdict"]))
    problems = result["transcript_problems"]
    if any(problems.values()) if isinstance(problems, dict) else problems:
        raise EvidenceError("%s: transcript problems: %s" % (profile, problems))
    if not (result["build"]["ok"] and result["calibration"]["ok"] and result["guest"]["reached_end"]):
        raise EvidenceError("%s: the build identity, the ENOSYS calibration or the end marker is not established" % profile)
    statuses = {}
    for field, probe in FIELDS:
        status = result["probes"][probe]["status"]
        allowed = ("supported", "unseeded") if probe == "GETRANDOM" else ("supported",)
        if status not in allowed:
            raise EvidenceError("%s: probe %s is %r; this generator emits only %s for it" % (profile, probe, status, "/".join(allowed)))
        statuses[field] = VARIANT[status]
    match = re.search(r"^FFW_PROBE:CLOCK_MONOTONIC status=PASS res_ns=(\d+)\r?$", text, re.M)       # serial lines end in CRLF
    if not match:
        raise EvidenceError("%s: no CLOCK_MONOTONIC PASS line with res_ns" % profile)
    resolution = int(match.group(1))
    if not 1 <= resolution <= 10_000_000:
        raise EvidenceError("%s: clock resolution %d ns is outside 1..=10 ms" % (profile, resolution))
    return {
        "kernel_release": result["guest"]["kernel_release"],
        "target_triple": result["build"]["fields"]["target"],
        "resolution_ns": resolution,
        "statuses": statuses,
        "verdict": result["verdict"],
    }


HEADER = '''//! Kernel capability evidence for the guests E03 observed (`P02` / `ffw-jub`). GENERATED: do not edit.
//!
//! Regenerate with `scripts/p02/gen_guest_evidence.py --write`; `scripts/p02/gen_guest_evidence.py` (no flag) and
//! `tests/p02/test_guest_evidence.py` fail when this file differs from what the committed transcripts give. Every status below
//! comes from the E03 oracle (`tests/e03/abi.py`) classifying a committed full-system QEMU serial transcript of central run
//! `{run}`; nothing is typed by hand. The generator refuses to emit evidence the oracle does not call matching-guest.
//!
//! These are the **only** kernels with evidence: two Debian harness kernels, one run each. They are not the stock kernels the
//! boards run (every stock cell in E03 stays unqualified), and a real board's kernel is the vendor's. A status here is what E03
//! observed on the guest whose release is `kernel_release`; it says nothing about another kernel. The speaker picks the matrix by
//! the backend's ABI, which the target fixes at compile time, and does **not** compare the running kernel's release to it:
//! `platform_start` records the release and lets the probes (each syscall's typed answer) decide.

use franken_platform::abi::Abi;
use franken_platform::{{CapabilityStatus, KernelCapabilityMatrix}};

/// What E03 observed on one full-system harness guest, and the identity of the transcript it was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestEvidence {{
    /// The oracle's profile name for the guest.
    pub profile_id: &'static str,
    pub abi: Abi,
    pub target_triple: &'static str,
    /// The kernel release the guest reported: what the observations were made on. Evidence about that guest, not a check on the running kernel.
    pub kernel_release: &'static str,
    /// The central run the transcript is committed under (`{run_rel}`).
    pub run_id: &'static str,
    /// SHA-256 of the committed serial transcript.
    pub transcript_sha256: &'static str,
    clock_monotonic_res_ns: u64,
    static_elf_startup: CapabilityStatus,
{struct_fields}}}

impl GuestEvidence {{
    /// The capability matrix this evidence supports: the profile is the guest's own kernel, and the guest observed is the same
    /// release, so `check_admission` accepts it. It is what the layer is admitted against; it is not compared to the running kernel.
    #[must_use]
    pub fn matrix(&self) -> KernelCapabilityMatrix {{
        KernelCapabilityMatrix {{
            profile_id: self.profile_id.to_string(),
            target_triple: self.target_triple.to_string(),
            nominal_kernel_version: self.kernel_release.to_string(),
            guest_kernel_observed: Some(self.kernel_release.to_string()),
            static_elf_startup: self.static_elf_startup,
            clock_monotonic: self.clock_monotonic,
            clock_monotonic_res_ns: self.clock_monotonic_res_ns,
            nonblocking_pipe_io: self.nonblocking_pipe_io,
            poll_syscall: self.poll_syscall,
            epoll_syscall: self.epoll_syscall,
            udp_socket_io: self.udp_socket_io,
            urandom_entropy: self.urandom_entropy,
            getrandom_syscall: self.getrandom_syscall,
            atomics_32bit: self.atomics_32bit,
            atomics_64bit_fallback: self.atomics_64bit_fallback,
            eventfd_syscall: self.eventfd_syscall,
        }}
    }}
}}

/// The evidence for the guest of `abi`.
#[must_use]
pub fn for_abi(abi: Abi) -> &'static GuestEvidence {{
    match abi {{
{arms}    }}
}}

/// Every guest with evidence.
pub static ALL: [&GuestEvidence; 2] = [&HARNESS_PPC, &HARNESS_MIPS];
'''


def render(facts_by_guest, digests):
    field_lines = "".join("    %s: CapabilityStatus,\n" % name for name, _ in FIELDS if name != "clock_monotonic")
    # clock_monotonic is declared next to its resolution above; keep the struct in matrix order
    field_lines = "    clock_monotonic: CapabilityStatus,\n" + field_lines
    arms = "".join("        Abi::%s => &%s,\n" % (variant, name) for name, variant, _, _ in GUESTS)
    out = HEADER.format(run=RUN_ID, run_rel=RUN_REL, struct_fields=field_lines, arms=arms)
    for (name, variant, profile, log), facts, digest in zip(GUESTS, facts_by_guest, digests):
        out += "\n/// `%s`: kernel `%s`, E03 verdict `%s`.\n" % (profile, facts["kernel_release"], facts["verdict"])
        out += "pub static %s: GuestEvidence = GuestEvidence {\n" % name
        out += '    profile_id: "%s",\n' % profile
        out += "    abi: Abi::%s,\n" % variant
        out += '    target_triple: "%s",\n' % facts["target_triple"]
        out += '    kernel_release: "%s",\n' % facts["kernel_release"]
        out += '    run_id: "%s",\n' % RUN_ID
        out += '    transcript_sha256: "%s",\n' % digest
        out += "    clock_monotonic_res_ns: %d,\n" % facts["resolution_ns"]
        out += "    static_elf_startup: CapabilityStatus::Supported,\n"
        for field, _ in FIELDS:
            out += "    %s: CapabilityStatus::%s,\n" % (field, facts["statuses"][field])
        out += "};\n"
    return out


def generate():
    oracle = load_oracle()
    facts, digests = [], []
    for _, _, profile, log in GUESTS:
        with open(os.path.join(ROOT, *RUN_REL.split("/"), log), "rb") as fh:
            raw = fh.read()
        digests.append(hashlib.sha256(raw).hexdigest())
        facts.append(derive(oracle, profile, raw.decode("utf-8", errors="replace")))
    return render(facts, digests)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true", help="rewrite the committed file instead of checking it")
    args = parser.parse_args(argv)
    try:
        text = generate()
    except EvidenceError as error:
        print("gen_guest_evidence: refusing to emit: %s" % error, file=sys.stderr)
        return 1
    if args.write:
        with open(OUTPUT, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("wrote", os.path.relpath(OUTPUT, ROOT))
        return 0
    try:
        with open(OUTPUT, encoding="utf-8") as fh:
            current = fh.read()
    except OSError:
        print("gen_guest_evidence: %s is missing" % os.path.relpath(OUTPUT, ROOT), file=sys.stderr)
        return 1
    if current != text:
        print("gen_guest_evidence: %s differs from the transcripts; run with --write" % os.path.relpath(OUTPUT, ROOT), file=sys.stderr)
        return 1
    print("gen_guest_evidence: up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
