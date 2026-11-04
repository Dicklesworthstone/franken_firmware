#!/usr/bin/env python3
"""Planted-defect canary for newc archive alignment, as a run-suite case (result contract ffw.case-result.v1, v1.1).

    newc_case.py positive           [--parser PATH]
    newc_case.py canary DEFECT      [--parser PATH]
    newc_case.py floor                                  # print the independent floor entries (JSON)

The oracle under test is root's production parser, ``toolchain/src/mkinitramfs.py: parse_cpio_bytes``.  The
archives it is judged on come from a **separate, hand-rolled newc encoder in this file**, which uses no production
encoding helper (the same independence rule as ``toolchain/tests/test_initramfs_archive.py``'s ``fixture``).  Each
defect is a *wrong writer*; a sound parser must reject, or at least not silently mis-decode, what it writes:

  align_total      one pad over header+name+data, i.e. advance by align(110 + namesize + filesize)  (the named bug)
  skip_name_pad    no padding after the name field
  skip_data_pad    no padding after the file data
  nonzero_pad      padding bytes that are not zero

Every defect is run over all 16 alignments (name length 1..4 x data length 0..3) of an archive made of two entries of
that shape plus the trailer.  Only archives whose bytes really differ from the correct archive count: a defect that is
invisible at some alignment (align_total at 7 of 16, skip_data_pad at 4) is not an instance of it there.

  positive   the correct writer over the 16 alignments is accepted with exactly the intended entries
  canary D   pass       => the parser accepted at least one defective archive (the oracle missed it)  -> canary_not_detected
             fail       => every defective archive was rejected or mis-decoded; violation kinds are typed from the
                           parser's own message (bad_magic, bad_header_padding, bad_data_padding, ...)
             incomplete => the defect never manifested at any alignment, so nothing was judged

Exit codes: 0 pass, 1 fail, 2 incomplete or usage error.  Stdlib only, offline.  This judges a host-side parser against
synthetic archives; it says nothing about a stock kernel's own unpacker or a real device.
"""
from __future__ import annotations

import argparse
import collections
import importlib.util
import json
import os
import sys
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
DEFAULT_PARSER = os.path.join(REPO, "toolchain", "src", "mkinitramfs.py")

ORACLE = "newc_alignment"
ORACLE_KIND = "protocol"
PROOF_CLASS = "host-simulation"
POSITIVE_ID = "q00.newc.positive.correct_alignment"
CANARY_PREFIX = "q00.newc.canary."
NAME_LENS = range(1, 5)
DATA_LENS = range(4)
RESULT_SCHEMA = "ffw.case-result.v1"


class Defect(NamedTuple):
    description: str
    violation: str   # the typed kind the parser's rejection is expected to map to


DEFECTS: Dict[str, Defect] = {
    # The pinned violation is the kind the production parser really reports for the defect (measured, then fixed
    # here so the canary identity is exact).  nonzero_pad also yields bad_data_padding at some alignments; the
    # expected kind need only be among the kinds reported.
    "align_total": Defect("one pad over header+name+data: advance by align(110+namesize+filesize)", "bad_header_padding"),
    "skip_name_pad": Defect("no padding after the name field", "bad_header_padding"),
    "skip_data_pad": Defect("no padding after the file data", "bad_data_padding"),
    "nonzero_pad": Defect("padding bytes are not zero", "bad_header_padding"),
}


# --------------------------------------------------------------------------- independent encoder
def _pad(n: int, byte: bytes = b"\0") -> bytes:
    return byte * (-n % 4)


def encode_entry(name: str, payload: bytes, mode: int, defect: Optional[str]) -> bytes:
    fields = (1, mode, 0, 0, 1, 0, len(payload), 0, 0, 0, 0, len(name.encode()) + 1, 0)
    head = b"070701" + b"".join(format(v, "08x").encode() for v in fields) + name.encode() + b"\0"
    if defect is None:
        return head + _pad(len(head)) + payload + _pad(len(payload))
    if defect == "align_total":
        return head + payload + _pad(len(head) + len(payload))
    if defect == "skip_name_pad":
        return head + payload + _pad(len(payload))
    if defect == "skip_data_pad":
        return head + _pad(len(head)) + payload
    if defect == "nonzero_pad":
        return head + _pad(len(head), b"\x01") + payload + _pad(len(payload), b"\x01")
    raise ValueError("unknown defect %r" % defect)


def build(name_len: int, data_len: int, defect: Optional[str]) -> Tuple[bytes, List[Tuple[str, bytes]]]:
    # Two entries of the swept shape, so each defect shows (or does not) at exactly the alignment being swept.
    name, payload = "x" * name_len, b"z" * data_len
    entries = [(name, payload, 0o100644), ("y" * name_len, payload, 0o100644), ("TRAILER!!!", b"", 0)]
    raw = b"".join(encode_entry(n, p, m, defect) for n, p, m in entries)
    return raw, [(n, p) for n, p, _ in entries]


# --------------------------------------------------------------------------- the oracle under test
def load_parser(path: str) -> Any:
    spec = importlib.util.spec_from_file_location("newc_parser_under_test", path)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load %s" % path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["newc_parser_under_test"] = mod
    spec.loader.exec_module(mod)
    if not hasattr(mod, "parse_cpio_bytes"):
        raise ImportError("%s has no parse_cpio_bytes" % path)
    return mod


_KINDS = (("invalid CPIO magic", "bad_magic"), ("non-zero header padding", "bad_header_padding"),
          ("non-zero data padding", "bad_data_padding"), ("truncated", "truncated"),
          ("noncanonical or escaping", "bad_path"), ("duplicate", "duplicate_entry"),
          ("TRAILER", "bad_trailer"), ("malformed hex", "bad_header_field"), ("namesize", "bad_name_field"),
          ("trailing NUL", "bad_name_field"), ("embedded NUL", "bad_name_field"))


def classify(message: str) -> str:
    """Type a rejection from the parser's own message; anything unrecognised is still a rejection, named as such."""
    for needle, kind in _KINDS:
        if needle in message:
            return kind
    return "rejected_other"


def run_parser(parser: Any, raw: bytes, intended: List[Tuple[str, bytes]]) -> Tuple[str, Optional[str], str]:
    """(outcome, kind, detail): accepted | rejected | misparsed."""
    try:
        entries = parser.parse_cpio_bytes(raw)
    except ValueError as exc:
        return "rejected", classify(str(exc)), str(exc)
    got = [(e["name"], bytes(e["data"])) for e in entries]
    if got == intended:
        return "accepted", None, ""
    return "misparsed", "content_mismatch", "decoded %r, intended %r" % (got, intended)


def judge(parser: Any, defect: Optional[str]) -> Dict[str, Any]:
    """The verdict fields of the result file (pure given the parser; unit-tested)."""
    base: Dict[str, Any] = {"oracle": ORACLE, "oracle_kind": ORACLE_KIND, "independent": True}
    kinds: "collections.Counter[str]" = collections.Counter()
    judged = undetected = 0
    first = ""
    for nl in NAME_LENS:
        for dl in DATA_LENS:
            raw, intended = build(nl, dl, defect)
            if defect is not None and raw == build(nl, dl, None)[0]:
                continue   # the defect is invisible at this alignment: not an instance of it
            judged += 1
            outcome, kind, detail = run_parser(parser, raw, intended)
            if defect is None:
                if outcome != "accepted":   # the correct writer must be accepted exactly
                    kinds["valid_archive_rejected" if outcome == "rejected" else "content_mismatch"] += 1
                    first = first or "name_len=%d data_len=%d: %s" % (nl, dl, detail)
            elif outcome == "accepted":
                undetected += 1
                first = first or "name_len=%d data_len=%d: accepted a %s archive" % (nl, dl, defect)
            else:
                kinds[kind or "rejected_other"] += 1
                first = first or "name_len=%d data_len=%d: %s" % (nl, dl, detail)
    counters = {"alignments_judged": judged, "undetected": undetected}
    counters.update({"kind_" + k: v for k, v in kinds.items()})
    if judged == 0:
        return dict(base, verdict="incomplete", finalized=False, incomplete_reasons=["defect_never_manifested"],
                    checks=0, mismatches=0, violation_kinds={}, expected=None, observed=None,
                    first_causal_event="no alignment was affected by the defect", counters=counters)
    if defect is None:
        if kinds:
            return dict(base, verdict="fail", finalized=True, incomplete_reasons=[], checks=judged,
                        mismatches=sum(kinds.values()), violation_kinds=dict(kinds),
                        expected={"correct_archives": "all accepted with the intended entries"},
                        observed={"problems": dict(kinds)}, first_causal_event=first, counters=counters)
        return dict(base, verdict="pass", finalized=True, incomplete_reasons=[], checks=judged, mismatches=0,
                    violation_kinds={}, expected={"correct_archives": "all accepted"},
                    observed={"accepted": judged}, first_causal_event="none: no violation", counters=counters)
    if undetected:   # the oracle missed a defective archive: it found nothing wrong, so it reports a pass
        return dict(base, verdict="pass", finalized=True, incomplete_reasons=[], checks=judged, mismatches=0,
                    violation_kinds={}, expected={"defective_archives": "all rejected"},
                    observed={"accepted_defective": undetected, "judged": judged}, first_causal_event=first,
                    counters=counters)
    return dict(base, verdict="fail", finalized=True, incomplete_reasons=[], checks=judged,
                mismatches=sum(kinds.values()), violation_kinds=dict(kinds),
                expected={"defective_archives": "accepted only if spec-aligned"},
                observed={"rejected": dict(kinds)}, first_causal_event=first, counters=counters)


# --------------------------------------------------------------------------- floor source (code, not a manifest)
def floor_entries() -> Dict[str, Dict[str, Any]]:
    """{case_id: {proof_class, canary[, oracle, violation]}} in exactly floor.py's ``required`` shape."""
    out: Dict[str, Dict[str, Any]] = {POSITIVE_ID: {"proof_class": PROOF_CLASS, "canary": False}}
    for name, d in DEFECTS.items():
        out[CANARY_PREFIX + name] = {"proof_class": PROOF_CLASS, "canary": True, "oracle": ORACLE,
                                     "violation": d.violation}
    return out


# --------------------------------------------------------------------------- CLI
def _write_result(path: str, doc: Dict[str, Any]) -> None:
    data = json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n"
    if len(data.encode("utf-8")) > 256 * 1024:
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
    ap = argparse.ArgumentParser(description="newc alignment canary (run-suite case)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("positive", "canary"):
        sp = sub.add_parser(name)
        if name == "canary":
            sp.add_argument("defect", choices=sorted(DEFECTS))
        sp.add_argument("--parser", default=DEFAULT_PARSER, help="path to the parser module (default: toolchain/src/mkinitramfs.py)")
    sub.add_parser("floor")
    args = ap.parse_args(argv)

    if args.cmd == "floor":
        print(json.dumps(floor_entries(), indent=1, sort_keys=True))
        return 0
    target = None
    if os.environ.get("FFW_RESULT_PATH"):
        ids = {k: os.environ.get(k) for k in ("FFW_RUN_ID", "FFW_CASE_ID", "FFW_RESULT_NONCE")}
        missing = [k for k, v in ids.items() if not v]
        if missing:
            print("newc_case: %s required when FFW_RESULT_PATH is set" % ", ".join(missing), file=sys.stderr)
            return 2
        target = (os.environ["FFW_RESULT_PATH"], ids)
    try:
        parser = load_parser(args.parser)
    except Exception as exc:   # no parser, no judgement: no result file, which can never pass
        print("newc_case: cannot load the parser under test: %s" % exc, file=sys.stderr)
        return 2

    verdict = judge(parser, args.defect if args.cmd == "canary" else None)
    print("NEWC %s: verdict=%s judged=%s %s" % (
        args.defect if args.cmd == "canary" else "positive", verdict["verdict"],
        verdict["counters"]["alignments_judged"],
        " ".join("%s=%s" % (k, v) for k, v in sorted(verdict["counters"].items()) if k != "alignments_judged")), flush=True)
    if target is not None:
        doc = dict(verdict, schema=RESULT_SCHEMA, run_id=target[1]["FFW_RUN_ID"], case_id=target[1]["FFW_CASE_ID"],
                   nonce=target[1]["FFW_RESULT_NONCE"])
        _write_result(target[0], doc)
    return {"pass": 0, "fail": 1}.get(verdict["verdict"], 2)


if __name__ == "__main__":
    sys.exit(main())
