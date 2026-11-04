#!/usr/bin/env python3
"""Q00 wrong-newc-alignment canaries and a paired positive, judged by the E07 archive parser.

The verifier is the existing independent parser ``toolchain/src/mkinitramfs.py::parse_cpio_bytes``
(loaded by explicit path).  This module adds no archive-parsing logic of its own.  What it adds:

* an independent newc *encoder* that can plant the alignment defects the parser must reject;
* a mapping from the parser's rejection message to a typed violation kind;
* the run-suite wire contract (``ffw.case-result.v1``, v1.1), so the registry can name each
  defect as a canary with the exact oracle and violation kind it must produce.

    newc_case.py replay --defect align_unpadded_sum|omit_header_padding|omit_data_padding|nonzero_padding|align_to_8
    newc_case.py positive

Verdicts (exit 0 pass, 1 fail, 2 incomplete or usage error):

  replay  fail        the parser rejected EVERY applicable planted archive (the named probe plus all 16
                      name/data alignments, skipping any whose bytes the defect leaves unchanged);
                      ``violation_kinds`` counts how.  For a canary this is the DETECTION, so the
                      registry expects exit 1 and an exact kind among those counted.
          pass        the parser ACCEPTED at least one planted archive: the defect was missed (a blind
                      spot at a single alignment is enough).  Whatever the parser returned for it is
                      irrelevant: a defective archive that parses is not a detection.  The runner
                      reports ``canary_not_detected``.
          incomplete  the parser crashed, could not be loaded, or REJECTED the correct control
                      archive (so its rejection of the planted one proves nothing).  Never a
                      detection.
  positive pass       every correct archive (all 16 name/data alignment residues plus the production
                      default archive) was accepted with exactly the expected contents.
          fail        a correct archive was rejected (``correct_archive_rejected``) or parsed to the
                      wrong contents (``content_mismatch``).
          incomplete  the parser crashed or could not be loaded.

Limits, not hidden: the violation kind is derived from the parser's message text, so rewording a
message makes the canary fail loudly with the wrong kind rather than pass silently.  The canaries
show the parser rejects these three alignment mistakes and accepts correct archives; they say
nothing about archives built any other way, or about a kernel's own unpacker.
"""
from __future__ import annotations

import argparse
import collections
import importlib.util
import json
import os
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

RESULT_SCHEMA = "ffw.case-result.v1"
MAX_RESULT_BYTES = 256 * 1024
ORACLE = "newc.archive_parser"
ORACLE_KIND = "protocol"
CANARY_PREFIX = "q00.newc.canary."
POSITIVE_ID = "q00.newc.positive.alignments"
TRAILER = "TRAILER!!!"

HERE = os.path.dirname(os.path.realpath(__file__))
DEFAULT_VERIFIER = os.path.normpath(os.path.join(HERE, "..", "..", "..", "toolchain", "src", "mkinitramfs.py"))
_REQUIRED_API = ("parse_cpio_bytes", "build_cpio_bytes", "verify_initramfs_bytes")

DefectSpec = collections.namedtuple("DefectSpec", "name scenario oracle kind description")
DEFECTS: Dict[str, DefectSpec] = {
    d.name: d
    for d in (
        DefectSpec("align_unpadded_sum", "newc", ORACLE, "header_padding",
                   "header and data are padded once, to the unpadded sum 110+namesize+filesize (the historical bug)"),
        DefectSpec("omit_header_padding", "newc", ORACLE, "header_padding",
                   "the name is not padded to 4 bytes before the file data"),
        DefectSpec("omit_data_padding", "newc", ORACLE, "data_padding",
                   "the header is padded but the file data is not padded to 4 bytes"),
        DefectSpec("nonzero_padding", "newc", ORACLE, "header_padding",
                   "padding is present at the right places but is filled with 0xFF instead of zeros"),
        DefectSpec("align_to_8", "newc", ORACLE, "misaligned_header",
                   "header and data are aligned to 8 bytes instead of 4"),
    )
}

# Planted-defect probe: ("ab", b"x") is the named counterexample (namesize 3, filesize 1), where aligning
# the unpadded sum differs from padding header and data separately.
PROBE: Tuple[Tuple[str, bytes], ...] = (("ab", b"x"), ("next", b"after"))

# Parser rejection message fragment -> violation kind.  First match wins; anything else is "invalid_archive".
_KINDS: Tuple[Tuple[str, str], ...] = (
    ("non-zero header padding", "header_padding"),
    ("non-zero data padding", "data_padding"),
    ("invalid CPIO magic", "misaligned_header"),
    ("malformed hex header", "malformed_header"),
    ("truncated", "truncated"),
    ("duplicate CPIO entry", "duplicate_entry"),
    ("noncanonical or escaping", "bad_path"),
    ("missing TRAILER", "missing_trailer"),
    ("must not contain data", "trailer_payload"),
    ("non-zero bytes after", "trailing_garbage"),
    ("invalid namesize", "bad_name"),
    ("missing trailing NUL", "bad_name"),
    ("embedded NUL", "bad_name"),
)


def classify(message: str) -> str:
    for needle, kind in _KINDS:
        if needle in message:
            return kind
    return "invalid_archive"


# ----------------------------------------------------------------------------- independent encoder


def encode_entry(name: str, payload: bytes = b"", mode: int = 0o100644, bug: Optional[str] = None) -> bytes:
    """One newc entry, written from the format description and NOT via the production encoder.

    ``bug`` plants one alignment mistake (a key of DEFECTS); None encodes correctly."""
    name_bytes = name.encode("utf-8") + b"\0"
    fields = (1, mode, 0, 0, 1, 0, len(payload), 0, 0, 0, 0, len(name_bytes), 0)
    header = b"070701" + b"".join(format(v, "08x").encode("ascii") for v in fields)
    if bug is None:
        out = header + name_bytes
        out += b"\0" * (-len(out) % 4)
        out += payload
        out += b"\0" * (-len(out) % 4)
    elif bug == "align_unpadded_sum":
        out = header + name_bytes + payload
        out += b"\0" * (-len(out) % 4)
    elif bug == "omit_header_padding":
        out = header + name_bytes + payload
        out += b"\0" * (-len(payload) % 4)
    elif bug == "omit_data_padding":
        out = header + name_bytes
        out += b"\0" * (-len(out) % 4)
        out += payload
    elif bug == "nonzero_padding":
        out = header + name_bytes
        out += b"\xff" * (-len(out) % 4)
        out += payload
        out += b"\xff" * (-len(out) % 4)
    elif bug == "align_to_8":
        out = header + name_bytes
        out += b"\0" * (-len(out) % 8)
        out += payload
        out += b"\0" * (-len(out) % 8)
    else:
        raise ValueError("unknown alignment defect %r" % (bug,))
    return out


def build_archive(entries, bug: Optional[str] = None) -> bytes:
    """Uncompressed newc archive of ``entries`` [(name, payload)] plus a trailer, the bug applied to every entry."""
    raw = b"".join(encode_entry(n, p, bug=bug) for n, p in entries)
    return raw + encode_entry(TRAILER, b"", mode=0, bug=bug)


# ----------------------------------------------------------------------------- verifier access


class VerifierUnavailable(Exception):
    pass


def load_verifier(path: Optional[str] = None) -> Any:
    """Import the archive verifier by explicit path (no sys.path edits, no bytecode written)."""
    path = path or DEFAULT_VERIFIER
    if not os.path.isfile(path):
        raise VerifierUnavailable("verifier not found: %s" % os.path.basename(path))
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("ffw_newc_verifier_%d" % abs(hash(os.path.realpath(path))), path)
    if spec is None or spec.loader is None:
        raise VerifierUnavailable("cannot load %s" % os.path.basename(path))
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:   # a broken verifier is loud, never an empty pass
        raise VerifierUnavailable("%s failed to import: %s" % (os.path.basename(path), type(exc).__name__))
    missing = [n for n in _REQUIRED_API if not callable(getattr(mod, n, None))]
    if missing:
        raise VerifierUnavailable("verifier lacks %s" % ", ".join(missing))
    return mod


# ----------------------------------------------------------------------------- verdicts (pure)


def _base() -> Dict[str, Any]:
    return {"oracle": ORACLE, "oracle_kind": ORACLE_KIND, "independent": True}


def _incomplete(reasons: List[str], checks: int = 0, counters: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    return dict(_base(), verdict="incomplete", finalized=False, incomplete_reasons=reasons, checks=checks,
                mismatches=0, violation_kinds={}, expected=None, observed=None,
                first_causal_event=reasons[0], counters=counters or {"archives_checked": checks})


def _contents(entries) -> List[Tuple[str, bytes]]:
    return [(e["name"], e["data"]) for e in entries]


def sweep() -> List[Tuple[str, List[Tuple[str, bytes]]]]:
    """The named probe plus all 16 (namesize % 4, filesize % 4) combinations, each followed by an aligned entry."""
    return [("probe", list(PROBE))] + positive_cases()


def plan(defect: str) -> List[Tuple[str, List[Tuple[str, bytes]], bytes]]:
    """(label, entries, planted archive) for every sweep archive the defect actually changes."""
    out = []
    for label, entries in sweep():
        planted = build_archive(entries, bug=defect)
        if planted != build_archive(entries):
            out.append((label, entries, planted))
    return out


def canary_result(defect: str, verifier: Any) -> Dict[str, Any]:
    """Plant ``defect`` across the whole sweep and report what the verifier did.

    For each archive the correct control is checked first; the defect is DETECTED only if every
    applicable planted archive is rejected."""
    spec = DEFECTS[defect]
    todo = plan(defect)
    if not todo:
        return _incomplete(["defect_never_manifested: %s changes no archive in the sweep" % defect])
    kinds: Dict[str, int] = {}
    missed: List[str] = []
    first: Optional[str] = None
    checks = 0
    for label, entries, planted in todo:
        try:
            control = verifier.parse_cpio_bytes(build_archive(entries))
        except ValueError as exc:
            return _incomplete(["control_rejected: the verifier rejects a CORRECT archive (%s: %s)"
                                % (label, classify(str(exc)))], checks)
        except Exception as exc:
            return _incomplete(["verifier_crashed:%s" % type(exc).__name__], checks)
        checks += 1
        if _contents(control) != list(entries) + [(TRAILER, b"")]:
            return _incomplete(["control_misparsed: wrong contents for a CORRECT archive (%s)" % label], checks)
        try:
            verifier.parse_cpio_bytes(planted)
        except ValueError as exc:
            kind = classify(str(exc))
            kinds[kind] = kinds.get(kind, 0) + 1
            first = first or "%s[%s]: %s" % (defect, label, exc)
        except Exception as exc:
            return _incomplete(["verifier_crashed:%s" % type(exc).__name__], checks)
        else:
            missed.append(label)
        checks += 1
    counters = {"archives_checked": checks, "applicable": len(todo), "rejected": sum(kinds.values()),
                "missed": len(missed)}
    if missed:
        return dict(_base(), verdict="pass", finalized=True, incomplete_reasons=[], checks=checks, mismatches=0,
                    violation_kinds={}, expected={"planted_archives_accepted": 0},
                    observed={"planted_archives_accepted": len(missed), "of": len(todo), "labels": missed[:5],
                              "defect": defect},
                    first_causal_event="none: the verifier accepted %d of %d planted %s archives (%s)"
                                       % (len(missed), len(todo), defect, spec.description),
                    counters=counters)
    return dict(_base(), verdict="fail", finalized=True, incomplete_reasons=[], checks=checks,
                mismatches=len(todo), violation_kinds=kinds,
                expected={"archive": "valid newc: header and data each padded with zeros to a multiple of 4 bytes"},
                observed={"rejected": len(todo), "kinds": kinds, "defect": defect},
                first_causal_event=first or defect, counters=counters)


def positive_cases() -> List[Tuple[str, List[Tuple[str, bytes]]]]:
    """All 16 (namesize % 4, filesize % 4) combinations, each followed by an aligned entry and a trailer."""
    cases = []
    for name_len in range(1, 5):
        for data_len in range(4):
            name, payload = "x" * name_len, b"z" * data_len
            cases.append(("name%d_data%d" % (name_len, data_len), [(name, payload), ("next", b"after")]))
    return cases


def positive_result(verifier: Any) -> Dict[str, Any]:
    """Every correct archive must be accepted with exactly the expected contents."""
    problems: List[str] = []
    kinds: Dict[str, int] = {}
    checks = 0

    def problem(kind: str, text: str) -> None:
        kinds[kind] = kinds.get(kind, 0) + 1
        problems.append(text)

    try:
        for label, entries in positive_cases():
            checks += 1
            try:
                parsed = verifier.parse_cpio_bytes(build_archive(entries))
            except ValueError as exc:
                problem("correct_archive_rejected", "%s: %s" % (label, exc))
                continue
            if _contents(parsed) != list(entries) + [(TRAILER, b"")]:
                problem("content_mismatch", "%s: parsed contents differ" % label)
        checks += 1
        try:
            raw = verifier.build_cpio_bytes(b"synthetic init")
            result = verifier.verify_initramfs_bytes(raw)
            if result.get("init_size") != 14 or result["devices"]["dev/console"]["rdev"] != [5, 1]:
                problem("content_mismatch", "production default archive: unexpected init size or console device")
        except ValueError as exc:
            problem("correct_archive_rejected", "production default archive: %s" % exc)
    except Exception as exc:
        return _incomplete(["verifier_crashed:%s" % type(exc).__name__], checks)
    counters = {"archives_checked": checks, "problems": len(problems)}
    if problems:
        return dict(_base(), verdict="fail", finalized=True, incomplete_reasons=[], checks=checks,
                    mismatches=len(problems), violation_kinds=kinds,
                    expected={"correct_archives": "all accepted with exact contents"},
                    observed={"problems": problems[:3], "count": len(problems)},
                    first_causal_event=problems[0], counters=counters)
    return dict(_base(), verdict="pass", finalized=True, incomplete_reasons=[], checks=checks, mismatches=0,
                violation_kinds={}, expected={"correct_archives": "all accepted with exact contents"},
                observed={"accepted": checks}, first_causal_event="none: every correct archive was accepted",
                counters=counters)


def _canary_case(defect: str) -> Callable[[], Dict[str, Any]]:
    return lambda: canary_result(defect, load_verifier())


CANARY_CASES: List[Tuple[str, Callable[[], Dict[str, Any]]]] = (
    [(CANARY_PREFIX + name, _canary_case(name)) for name in DEFECTS]
    + [(POSITIVE_ID, lambda: positive_result(load_verifier()))]
)


# ----------------------------------------------------------------------------- wire + CLI


def _write_result(path: str, doc: Dict[str, Any]) -> None:
    data = json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n"
    if len(data.encode("utf-8")) > MAX_RESULT_BYTES:
        raise ValueError("result exceeds the 256 KiB limit")
    tmp = "%s.%d.tmp" % (path, os.getpid())
    try:
        with open(tmp, "x", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)   # our own scratch file only
        except OSError:
            pass
        raise


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Q00 newc alignment canary / positive over the E07 archive parser")
    sub = ap.add_subparsers(dest="cmd", required=True)
    rp = sub.add_parser("replay", help="plant one alignment defect and report whether the parser caught it")
    rp.add_argument("--defect", required=True, choices=sorted(DEFECTS))
    rp.add_argument("--verifier", default=None, help="path to the parser module (test hook; default toolchain/src/mkinitramfs.py)")
    pp = sub.add_parser("positive", help="the parser must accept every correct archive")
    pp.add_argument("--verifier", default=None, help="path to the parser module (test hook)")
    args = ap.parse_args(argv)

    target = None
    if os.environ.get("FFW_RESULT_PATH"):
        ids = {k: os.environ.get(k) for k in ("FFW_RUN_ID", "FFW_CASE_ID", "FFW_RESULT_NONCE")}
        missing = [k for k, v in ids.items() if not v]
        if missing:
            print("newc_case: %s required when FFW_RESULT_PATH is set" % ", ".join(missing), file=sys.stderr)
            return 2
        target = (os.environ["FFW_RESULT_PATH"], ids)

    try:
        verifier = load_verifier(args.verifier)
    except VerifierUnavailable as exc:
        verdict = _incomplete(["verifier_unavailable: %s" % exc])
    else:
        verdict = canary_result(args.defect, verifier) if args.cmd == "replay" else positive_result(verifier)

    label = args.defect if args.cmd == "replay" else "alignments"
    print("NEWC %s: verdict=%s checks=%s violations=%s" % (
        label, verdict["verdict"], verdict["checks"], json.dumps(verdict["violation_kinds"], sort_keys=True)), flush=True)
    if verdict["verdict"] != "pass":
        print("NEWC cause: %s" % verdict["first_causal_event"], flush=True)
    if target is not None:
        path_out, ids = target
        _write_result(path_out, dict(verdict, schema=RESULT_SCHEMA, run_id=ids["FFW_RUN_ID"],
                                     case_id=ids["FFW_CASE_ID"], nonce=ids["FFW_RESULT_NONCE"]))
    return {"pass": 0, "fail": 1}.get(verdict["verdict"], 2)


if __name__ == "__main__":
    sys.exit(main())
