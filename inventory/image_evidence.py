#!/usr/bin/env python3
"""Build one E01 image-evidence registry record from an extracted image (bead ffw-xdi).  Offline.

    python3 inventory/image_evidence.py --image PATH --internal-model-id 16 --build 57.23-74170 \\
        --image-name anacapad --provenance-source "..." --provenance-basis "..." \\
        [--join-model S5 --join-basis owner-attested --revision 1.16.4.1-1.0] \\
        [--expect-sha256 HEX] [--expect-isa powerpc] --out .local-real/ev.local.json

What it measures, from the image bytes: the SHA-256, and ISA / endianness / word size (and the ABI
only where the ELF header states it) through ``identity.normalize_elf_header``.  It never infers a
SoC, a float ABI or a PowerPC ABI.

What it will NOT do: decide which product an image belongs to.  The ``modelNumber`` join is an
explicit operator assertion (``--join-model`` with ``--join-basis image-verified|owner-attested`` and
at least one ``--revision``), recorded as such.  Without it the record is written ``unmapped``.  A
record that asserts a join may only be written to a git-ignored location (``.local-real/`` or a
``*.local.*`` name), so an attestation is never published by accident.  The image is only read.

Exit codes: 0 ok, 2 usage/input error, 5 output refused.  Messages never echo image content.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

MAX_IMAGE_BYTES = 512 * 1024 * 1024
CHUNK = 1024 * 1024
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}$")


class ToolError(Exception):
    def __init__(self, code, message, exit_code=2):
        super().__init__(message)
        self.code, self.message, self.exit_code = code, message, exit_code


def _reconcile():
    path = Path(__file__).resolve().with_name("reconcile.py")
    if not path.is_file():
        raise ToolError("shared_module_missing", "reconcile.py is required beside this tool")
    spec = importlib.util.spec_from_file_location("ffw_shared_reconcile", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ffw_shared_reconcile"] = mod
    spec.loader.exec_module(mod)
    return mod


def digest_and_header(path: Path):
    """-> (sha256 hex, first 64 bytes).  Bounded streaming read."""
    h, head, total = hashlib.sha256(), b"", 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_IMAGE_BYTES:
                    raise ToolError("image_too_large", f"image exceeds {MAX_IMAGE_BYTES} bytes")
                if len(head) < 64:
                    head += chunk[: 64 - len(head)]
                h.update(chunk)
    except OSError as e:
        raise ToolError("image_unreadable", f"image cannot be read ({type(e).__name__})")
    return h.hexdigest(), head


def build_record(args, rc):
    idm = rc._sibling("identity")
    digest, header = digest_and_header(Path(args.image))
    if args.expect_sha256 and args.expect_sha256.lower() != digest:
        raise ToolError("digest_mismatch", "the image's SHA-256 differs from --expect-sha256")
    try:
        image = idm.ImageRef(sha256=digest, internal_model_id=args.internal_model_id, software_build=args.build)
        norm = idm.normalize_elf_header(header, image, idm.Source("local:elf-header", "elf_header"))
    except idm.IdentityError as e:
        raise ToolError("elf_header_rejected", f"image header rejected by identity.py ({e.code})")
    claims = {c.field: c.value for c in norm.claims}
    for needed in ("arch.isa", "arch.endianness", "arch.word_bits"):
        if needed not in claims:
            raise ToolError("elf_header_incomplete", f"header does not state {needed}")
    if args.expect_isa and args.expect_isa != claims["arch.isa"]:
        raise ToolError("isa_mismatch", "the header's ISA differs from --expect-isa")
    line = args.firmware_line or ".".join(idm_build_line(idm, args.build))
    if args.join_model:
        join = {"model_number": args.join_model, "join_basis": args.join_basis}
    else:
        join = {"model_number": None, "join_basis": "unmapped"}
    rec = {
        "evidence_id": args.evidence_id or f"ev-local-model{args.internal_model_id}-{args.build}-{args.image_name}".lower(),
        "join": join,
        "firmware_lines": [line],
        "claim": {"machine": claims["arch.isa"], "elf_class": claims["arch.word_bits"], "endianness": claims["arch.endianness"],
                  "abi": claims.get("arch.abi"), "float_abi": None, "atomic_widths": None},
        "image": {"name": args.image_name, "digest": "sha256:" + digest},
        "provenance": {"source": args.provenance_source, "basis": args.provenance_basis},
    }
    if args.revision:
        rec["hardware_revisions"] = list(args.revision)
    try:
        rc._validate_evidence(rec, 0)
    except rc.E01Error as e:
        raise ToolError("record_invalid", f"the record fails registry validation ({e.code})")
    return rec


def idm_build_line(idm, build):
    m = re.match(r"^(\d+)\.(\d+)-\d+$", build or "")
    if not m:
        raise ToolError("usage", "--build must look like <major>.<minor>-<build>")
    return m.group(1), m.group(2)


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # same convention as reconcile.py: usage problems go through error[usage]
        raise ToolError("usage", message)


def _parser():
    p = _Parser(prog="image_evidence.py", allow_abbrev=False, description=__doc__.split("\n\n")[0])
    p.add_argument("--image", required=True, metavar="PATH", help="extracted image to measure (only read)")
    p.add_argument("--internal-model-id", required=True, type=int)
    p.add_argument("--build", required=True, help="<major>.<minor>-<build>, e.g. 57.23-74170")
    p.add_argument("--image-name", required=True)
    p.add_argument("--provenance-source", required=True, help="relative reference, no URL or absolute path")
    p.add_argument("--provenance-basis", required=True, help="what the claim rests on")
    p.add_argument("--out", required=True, metavar="PATH")
    p.add_argument("--evidence-id")
    p.add_argument("--firmware-line", help="default: derived from --build")
    p.add_argument("--expect-sha256", help="refuse unless the image has exactly this SHA-256")
    p.add_argument("--expect-isa", choices=("mips", "powerpc", "arm", "aarch64", "x86", "x86_64", "riscv"), help="refuse unless the header says this")
    p.add_argument("--join-model", help="ASSERT that this image belongs to this modelNumber (explicit operator attestation)")
    p.add_argument("--join-basis", choices=("image-verified", "owner-attested"), help="required with --join-model")
    p.add_argument("--revision", action="append", default=[], help="hardwareVersion(s) the join covers; required with --join-model")
    p.add_argument("--overwrite", action="store_true")
    return p


def main(argv=None, stdout=None, stderr=None) -> int:
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    try:
        try:
            args = _parser().parse_args(argv)
        except SystemExit as e:
            return e.code if isinstance(e.code, int) else 2
        if not _TOKEN.match(args.image_name):
            raise ToolError("usage", "--image-name must be a short token")
        if args.join_model and (not args.join_basis or not args.revision):
            raise ToolError("usage", "--join-model needs --join-basis and at least one --revision (no blanket joins)")
        if (args.join_basis or args.revision) and not args.join_model:
            raise ToolError("usage", "--join-basis/--revision only apply with --join-model")
        rc = _reconcile()
        out = Path(args.out).resolve()
        if out == Path(args.image).resolve():
            raise ToolError("output_collides_with_input", "--out would overwrite the image", 5)
        if args.join_model and not rc._is_private_location(out):
            raise ToolError("private_out_not_ignored", "a record that asserts a join must be written under .local-real/ or to a *.local.* file", 5)
        if not out.parent.is_dir():
            raise ToolError("output_parent_missing", "--out parent directory does not exist", 5)
        if out.exists() and not args.overwrite:
            raise ToolError("output_exists", "output exists; pass --overwrite to replace it", 5)
        rec = build_record(args, rc)
        text = json.dumps({"schema": rc.EVIDENCE_SCHEMA, "records": [rec]}, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        try:
            rc.write_atomic(out, text.encode("ascii"), args.overwrite, 0o600 if args.join_model else 0o644)
        except rc.E01Error as e:
            raise ToolError(e.code, e.message, 5)
        c = rec["claim"]
        stdout.write(f"wrote 1 record: isa={c['machine']} class={c['elf_class']} endianness={c['endianness']} abi={c['abi']} "
                     f"digest=sha256:{rec['image']['digest'][7:23]}... join={rec['join']['model_number'] or 'unmapped'}\n")
        return 0
    except ToolError as e:
        stderr.write(f"error[{e.code}]: {e.message}\n")
        return e.exit_code
    except KeyboardInterrupt:
        stderr.write("error[interrupted]: interrupted; no partial output file was left behind\n")
        return 130
    except Exception as e:  # never echo exception text
        stderr.write(f"error[internal]: unexpected {type(e).__name__}; nothing was written\n")
        return 70


if __name__ == "__main__":
    sys.exit(main())
