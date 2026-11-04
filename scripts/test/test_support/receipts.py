#!/usr/bin/env python3
"""Versioned test-receipt stream: writer, strict validator, fail-closed aggregator.

Stdlib only. Imports no production crate and touches no network or device.

Stream format (``ffw.receipt-stream/1``): UTF-8 JSONL, one canonical JSON
object per newline-terminated line, in this order::

    run_header            exactly one, first line
    case  ...             one per (case_id, attempt)
    run_footer            exactly one, last line

``run_footer.stream_sha256`` is the SHA-256 of every byte before the footer
line, and the footer also carries the line and case-record counts. This
detects truncation and accidental corruption. It is NOT a signature: someone
who can rewrite the whole stream can rewrite the footer too.

Fail-closed rules enforced by ``aggregate``:

* The caller supplies the expected case set (``{case_id: {"mandatory",
  "proof_class"[, "canary"]}}``) from a registry independent of the runner.
  Its digest is pinned in the header; any mismatch is a problem. The
  denominator is that set, never whatever the stream happens to contain.
* A missing, truncated, duplicated, torn, reordered or unexpected record is a
  recorded problem and the run is not qualified. Absence of error text never
  counts as a pass: a pass needs an independent oracle that made at least one
  check, an intact log, and artifact digests matching the header (plus a zero
  exit, except for canaries, whose subject is expected to fail).
* A canary pass means the oracle caught a planted defect. The registry names
  the oracle and violation kind it expects; the receipt's oracle block must
  be that oracle, ``finalized``, with no ``incomplete_reasons``, status
  ``failed`` and the expected kind among ``violation_kinds``. An oracle that
  is incomplete, was never finalized, or fired a different violation proves
  nothing and is never a pass; a canary the oracle missed is a ``fail``.
  ``oracle_block_from_verdict`` derives the block from an
  ``ffw.oracle_verdict.v1`` so the runner does not map fields by hand.
* The denominator is only as honest as the registry. An independent floor
  (``required=``, CLI ``--require``) names cases the registry must still
  contain as mandatory; a case dropped, demoted or altered there is a
  problem even when the stream agrees with the shrunk registry.
* A case that failed and later passed on retry stays failed (``flaky``); the
  original failure is retained.
* Proof classes are exact (no hierarchy): ``host-simulation`` evidence never
  satisfies a ``guest-execution`` case. Ran ``real-service`` and ``physical``
  evidence must have ``origin: external`` and carry an ``external``
  authorization reference; their blocked/not_run records are local and carry
  none. This module only checks that the reference is well-formed; verifying
  the external authority is the caller's job.

Verdict buckets (they always sum to the denominator): pass, fail, timeout,
crash, cancelled, blocked, not_run, invalid. ``invalid`` means evidence
exists but cannot be trusted. ``executed`` counts every launched case
(pass, fail, timeout, crash, cancelled); ``not_run`` means never launched.

``failure.first_causal_event.log_seq`` indexes the case's original event
sequence, so it must be below ``log.events + log.dropped``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import sys
from collections import namedtuple
from collections.abc import Mapping

SCHEMA = "ffw.receipt-stream/1"
SUMMARY_SCHEMA = "ffw.run-summary/1"

TIERS = ("smoke", "full", "soak")
# Evidence classes, named as in the run-suite wire contract. A receipt must
# carry exactly the class the registry requires; there is no hierarchy, so
# host-simulation evidence can never stand in for guest-execution, and so on.
PROOF_CLASSES = (
    "host-simulation",
    "guest-execution",
    "loopback-integration",
    "real-service",
    "physical",
)
EXTERNAL_CLASSES = ("real-service", "physical")
OUTCOMES = ("pass", "fail", "timeout", "crash", "cancelled", "blocked", "not_run")
VERDICTS = OUTCOMES + ("invalid",)
RAN_OUTCOMES = ("pass", "fail", "timeout", "crash", "cancelled")
FAILURE_OUTCOMES = ("fail", "timeout", "crash")
REASON_OUTCOMES = ("cancelled", "blocked", "not_run")
ORACLE_KINDS = ("sample", "state", "protocol", "timing", "property", "output")
# Mirrors scripts/test/test_support/oracles.py (schema ffw.oracle_verdict.v1); no import.
VERDICT_SCHEMA = "ffw.oracle_verdict.v1"
ORACLE_STATUSES = ("passed", "failed", "incomplete")
FLOOR_FIELDS = ("proof_class", "canary", "oracle", "violation")

MAX_LINE_BYTES = 1 << 20
MAX_STREAM_BYTES = 64 << 20
MAX_PROBLEMS = 200
MAX_FAILURES = 100
U64 = 1 << 64

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_CASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")


class ReceiptError(ValueError):
    """Caller misuse (bad registry, bad writer call), not bad evidence."""


class _StrictJSON(Exception):
    def __init__(self, code, detail):
        super().__init__(code)
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------- primitives


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _is_str(v):
    return isinstance(v, str) and v != ""


def _in(v, choices):
    return isinstance(v, str) and v in choices


def _is_hex64(v):
    return isinstance(v, str) and _HEX64.match(v) is not None


def _clip(text, n):
    text = str(text)
    return text if len(text) <= n else text[: n - 3] + "..."


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj):
    """Deterministic ASCII JSON bytes; NaN/Infinity are rejected."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _loads_strict(text):
    """json.loads that rejects duplicate keys and non-finite numbers.

    Plain json.loads keeps the last duplicate key silently, which would let
    ``{"outcome":"fail","outcome":"pass"}`` launder a failure.
    """

    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise _StrictJSON("duplicate_json_key", k)
            out[k] = v
        return out

    def const(name):
        raise _StrictJSON("non_finite_number", name)

    def flt(text_):
        value = float(text_)
        if value != value or value in (float("inf"), float("-inf")):
            raise _StrictJSON("non_finite_number", text_)
        return value

    return json.loads(
        text, object_pairs_hook=pairs, parse_constant=const, parse_float=flt
    )


Spec = namedtuple("Spec", "mandatory proof_class canary oracle violation")


def normalize_expected(expected):
    """Validate the caller's registry slice.

    ``{case_id: {"mandatory": bool, "proof_class": str[, "canary": bool,
    "oracle": str, "violation": str]}}`` -> ``{case_id: Spec}``.

    A canary is a case whose pass means "the oracle caught a planted defect".
    A canary must say which oracle and which violation kind it expects, because
    without that an oracle that merely failed, or never finished, is
    indistinguishable from one that detected the defect. Non-canaries must not
    carry ``oracle``/``violation``.
    """
    if not isinstance(expected, Mapping) or not expected:
        raise ReceiptError("expected case set must be a non-empty mapping")
    out = {}
    for cid, spec in expected.items():
        if not isinstance(cid, str) or _CASE_ID.match(cid) is None:
            raise ReceiptError(f"bad case id in expected set: {_clip(repr(cid), 60)}")
        if not isinstance(spec, Mapping):
            raise ReceiptError(f"expected spec for {cid} must be a mapping")
        keys = set(spec)
        if not {"mandatory", "proof_class"} <= keys or keys - {"mandatory", "proof_class", "canary", "oracle", "violation"}:
            raise ReceiptError(
                f"expected spec for {cid} must have mandatory, proof_class and optional canary/oracle/violation"
            )
        if not isinstance(spec["mandatory"], bool):
            raise ReceiptError(f"mandatory for {cid} must be a bool")
        if not _in(spec["proof_class"], PROOF_CLASSES):
            raise ReceiptError(f"unknown proof_class for {cid}")
        canary = spec.get("canary", False)
        if not isinstance(canary, bool):
            raise ReceiptError(f"canary for {cid} must be a bool")
        oracle, violation = spec.get("oracle"), spec.get("violation")
        if canary:
            if not (_is_str(oracle) and len(oracle) <= 128 and _is_str(violation) and len(violation) <= 128):
                raise ReceiptError(f"canary {cid} must name the expected oracle and violation kind")
        elif "oracle" in keys or "violation" in keys:
            raise ReceiptError(f"{cid} is not a canary but names an oracle/violation")
        out[cid] = Spec(spec["mandatory"], spec["proof_class"], canary, oracle, violation)
    return out


def registry_digest(expected):
    norm = normalize_expected(expected)
    rows = [[cid, *sp] for cid, sp in sorted(norm.items())]
    return sha256_hex(canonical_json(rows))


def normalize_required(required):
    """Validate an independent floor of case ids the registry must still contain.

    An iterable of case ids, or ``{case_id: {proof_class, canary, oracle,
    violation}}`` where any given constraint must match the registry exactly.
    Returns ``{case_id: constraints}`` or None when no floor was supplied.
    """
    if required is None:
        return None
    if isinstance(required, Mapping):
        items = list(required.items())
    elif isinstance(required, (str, bytes)) or not hasattr(required, "__iter__"):
        raise ReceiptError("required must be an iterable of case ids or a mapping")
    else:
        items = [(cid, {}) for cid in required]
    if not items:
        raise ReceiptError("required floor must not be empty (pass None for no floor)")
    out = {}
    for cid, cons in items:
        if not isinstance(cid, str) or _CASE_ID.match(cid) is None:
            raise ReceiptError(f"bad case id in required floor: {_clip(repr(cid), 60)}")
        cons = {} if cons is None else cons
        if not isinstance(cons, Mapping) or set(cons) - set(FLOOR_FIELDS):
            raise ReceiptError(f"required constraints for {cid} may only use {', '.join(FLOOR_FIELDS)}")
        if "proof_class" in cons and not _in(cons["proof_class"], PROOF_CLASSES):
            raise ReceiptError(f"unknown proof_class in required floor for {cid}")
        if "canary" in cons and not isinstance(cons["canary"], bool):
            raise ReceiptError(f"canary in required floor for {cid} must be a bool")
        for k in ("oracle", "violation"):
            if k in cons and not _is_str(cons[k]):
                raise ReceiptError(f"{k} in required floor for {cid} must be a non-empty string")
        out[cid] = dict(cons)
    return out


def derive_case_seed(run_seed, case_id):
    """Per-case seed, a pure function of the run seed and the case id."""
    if not _is_int(run_seed) or not 0 <= run_seed < U64:
        raise ReceiptError("run seed must be an int in [0, 2**64)")
    if not isinstance(case_id, str):
        raise ReceiptError("case id must be a string")
    digest = hashlib.sha256(
        b"ffw.case-seed/1\0" + str(run_seed).encode("ascii") + b"\0" + case_id.encode("utf-8")
    ).digest()
    return int.from_bytes(digest[:8], "big")


# -------------------------------------------------------------------- writer


class StreamWriter:
    """Append-only writer. Every record is one flushed line; a failed write
    poisons the writer so a stream that hit a full disk can never gain a
    footer and therefore can never qualify."""

    def __init__(self, fp, *, max_line_bytes=MAX_LINE_BYTES, durable=False):
        self._fp = fp
        self._max = max_line_bytes
        self._durable = durable
        self._sha = hashlib.sha256()
        self._lines = 0
        self._cases = 0
        self._state = "new"
        self._run_id = None
        self._broken = False

    def _emit(self, obj, *, hashed=True):
        if self._broken:
            raise ReceiptError("writer failed earlier; stream is incomplete")
        try:
            line = canonical_json(obj) + b"\n"
        except (TypeError, ValueError) as exc:
            raise ReceiptError(f"unserializable record: {exc}") from exc
        if len(line) - 1 > self._max:
            raise ReceiptError(f"record exceeds {self._max} bytes")
        try:
            self._fp.write(line)
            self._fp.flush()
            if self._durable:
                os.fsync(self._fp.fileno())
        except OSError:
            self._broken = True
            raise
        if hashed:
            self._sha.update(line)
        self._lines += 1

    def write_header(self, *, run_id, suite, tier, seed, expected, versions, artifacts):
        if self._state != "new":
            raise ReceiptError("header already written")
        header = {
            "schema": SCHEMA,
            "kind": "run_header",
            "run_id": run_id,
            "suite": suite,
            "tier": tier,
            "seed": seed,
            "timebase": "monotonic_ns",
            "registry_digest": registry_digest(expected),
            "expected_cases": len(expected),
            "versions": versions,
            "artifacts": artifacts,
        }
        bad = validate_header(header)
        if bad:
            raise ReceiptError("invalid header: " + "; ".join(f"{c}: {d}" for c, d in bad[:5]))
        self._emit(header)
        self._run_id = run_id
        self._state = "open"

    def write_case(self, **fields):
        if self._state != "open":
            raise ReceiptError("write_case requires an open stream (header, no footer)")
        if "schema" in fields or "kind" in fields:
            raise ReceiptError("schema/kind are set by the writer")
        fields.setdefault("run_id", self._run_id)
        self._emit({"schema": SCHEMA, "kind": "case", **fields})
        self._cases += 1

    def write_footer(self):
        if self._state != "open":
            raise ReceiptError("write_footer requires an open stream")
        self._emit(
            {
                "schema": SCHEMA,
                "kind": "run_footer",
                "case_records": self._cases,
                "lines": self._lines,
                "stream_sha256": self._sha.hexdigest(),
            },
            hashed=False,
        )
        self._state = "closed"


# ---------------------------------------------------------------- validators


def _key_errors(obj, required, optional, errs, what):
    keys = set(obj)
    for k in sorted(map(str, set(required) - keys)):
        errs.append(("missing_field", f"{what}.{k}"))
    for k in sorted(map(str, keys - set(required) - set(optional))):
        errs.append(("unknown_field", f"{what}.{k}"))


def _artifact_refs(value, keys, what, errs, *, nonempty):
    """Validate a list of artifact dicts; return {name: sha256} of the good ones."""
    names = {}
    if not isinstance(value, list):
        errs.append(("bad_artifacts", f"{what} must be a list"))
        return names
    if nonempty and not value:
        errs.append(("bad_artifacts", f"{what} must not be empty"))
    for i, art in enumerate(value):
        if not isinstance(art, Mapping):
            errs.append(("bad_artifacts", f"{what}[{i}] must be an object"))
            continue
        _key_errors(art, keys, (), errs, f"{what}[{i}]")
        name, digest = art.get("name"), art.get("sha256")
        if not _is_str(name) or len(name) > 256:
            errs.append(("bad_artifacts", f"{what}[{i}].name"))
            continue
        if not _is_hex64(digest):
            errs.append(("bad_artifacts", f"{what}[{i}].sha256 must be 64 lowercase hex"))
            continue
        if "size" in keys and (not _is_int(art.get("size")) or art["size"] < 0):
            errs.append(("bad_artifacts", f"{what}[{i}].size"))
        if name in names:
            errs.append(("bad_artifacts", f"{what} repeats {name}"))
        names[name] = digest
    return names


def validate_header(h):
    errs = []
    if not isinstance(h, Mapping):
        return [("not_object", "header")]
    _key_errors(
        h,
        ("schema", "kind", "run_id", "suite", "tier", "seed", "timebase",
         "registry_digest", "expected_cases", "versions", "artifacts"),
        (),
        errs,
        "header",
    )
    if h.get("schema") != SCHEMA:
        errs.append(("bad_schema", _clip(repr(h.get("schema")), 60)))
    if h.get("kind") != "run_header":
        errs.append(("bad_kind", "header"))
    for k in ("run_id", "suite"):
        if not _is_str(h.get(k)):
            errs.append(("bad_field", f"header.{k}"))
    if not _in(h.get("tier"), TIERS):
        errs.append(("bad_field", "header.tier must be smoke|full|soak"))
    if not _is_int(h.get("seed")) or not 0 <= h["seed"] < U64:
        errs.append(("bad_field", "header.seed must be an int in [0, 2**64)"))
    if h.get("timebase") != "monotonic_ns":
        errs.append(("bad_field", "header.timebase"))
    if not _is_hex64(h.get("registry_digest")):
        errs.append(("bad_field", "header.registry_digest"))
    if not _is_int(h.get("expected_cases")) or h["expected_cases"] < 1:
        errs.append(("bad_field", "header.expected_cases"))
    v = h.get("versions")
    if (
        not isinstance(v, Mapping)
        or not v
        or not all(_is_str(a) and isinstance(b, str) for a, b in v.items())
    ):
        errs.append(("bad_field", "header.versions must be a non-empty str->str map"))
    _artifact_refs(h.get("artifacts"), ("name", "sha256", "size"), "header.artifacts", errs, nonempty=True)
    return errs


def validate_footer(f):
    errs = []
    if not isinstance(f, Mapping):
        return [("not_object", "footer")]
    _key_errors(f, ("schema", "kind", "case_records", "lines", "stream_sha256"), (), errs, "footer")
    if f.get("schema") != SCHEMA:
        errs.append(("bad_schema", _clip(repr(f.get("schema")), 60)))
    if f.get("kind") != "run_footer":
        errs.append(("bad_kind", "footer"))
    for k in ("case_records", "lines"):
        if not _is_int(f.get(k)) or f[k] < 0:
            errs.append(("bad_field", f"footer.{k}"))
    if not _is_hex64(f.get("stream_sha256")):
        errs.append(("bad_field", "footer.stream_sha256"))
    return errs


def log_evidence_lost(rec):
    """True if a structurally valid log block reports truncation or critical loss."""
    log = rec.get("log") if isinstance(rec, Mapping) else None
    return isinstance(log, Mapping) and (log.get("truncated") is True or log.get("critical_lost") is True)


def _argv_names(argv, value):
    return any(a == value or a.endswith("=" + value) for a in argv)


def validate_case_record(rec, header):
    """Return [(code, detail)] for one case record; empty means trustworthy.

    ``header`` must be a validated header mapping (or None, which fails every
    record: nothing can be trusted without a valid header).
    """
    if not isinstance(rec, Mapping):
        return [("not_object", "case record")]
    errs = []
    add = lambda code, detail: errs.append((code, detail))  # noqa: E731
    hdr = header if isinstance(header, Mapping) else None
    if hdr is None:
        add("no_valid_header", "case records cannot be trusted without a valid header")

    outcome = rec.get("outcome")
    out_ok = _in(outcome, OUTCOMES)
    ran = out_ok and outcome in RAN_OUTCOMES
    pclass = rec.get("proof_class")
    canary = rec.get("canary")

    required = {"schema", "kind", "run_id", "case_id", "attempt", "outcome",
                "proof_class", "canary", "origin", "seed", "replay"}
    optional = {"external"}
    if out_ok:
        if ran:
            required |= {"process", "started_mono_ns", "ended_mono_ns", "log", "artifacts"}
        else:
            optional |= {"artifacts", "log"}
        if outcome == "pass":
            required.add("oracle")
        if outcome in FAILURE_OUTCOMES:
            required.add("failure")
        if outcome in REASON_OUTCOMES:
            required.add("reason")
    else:
        add("bad_outcome", _clip(repr(outcome), 60))
    _key_errors(rec, required, optional, errs, "case")

    if rec.get("schema") != SCHEMA:
        add("bad_schema", _clip(repr(rec.get("schema")), 60))
    if rec.get("kind") != "case":
        add("bad_kind", _clip(repr(rec.get("kind")), 60))
    if hdr is not None and rec.get("run_id") != hdr.get("run_id"):
        add("run_id_mismatch", f"record {_clip(repr(rec.get('run_id')), 60)} != header")
    case_id = rec.get("case_id")
    if not isinstance(case_id, str) or _CASE_ID.match(case_id) is None:
        add("bad_field", "case.case_id")
        case_id = None
    if not _is_int(rec.get("attempt")) or rec["attempt"] < 1:
        add("bad_field", "case.attempt must be an int >= 1")
    if not _in(pclass, PROOF_CLASSES):
        add("bad_field", "case.proof_class")
    if not isinstance(canary, bool):
        add("bad_field", "case.canary must be a bool")

    # Proof-class / origin. Evidence of an external class (real-service,
    # physical) that actually ran can only have come from an authorized
    # external receipt, so it must say so and carry the reference. A blocked,
    # not_run or otherwise unlaunched record for such a case is produced
    # locally and cannot carry an authorization (its absence is the reason it
    # is blocked).
    origin = rec.get("origin")
    want_external = ran and _in(pclass, EXTERNAL_CLASSES)
    if origin != ("external" if want_external else "local"):
        add("origin_mismatch", f"{'ran ' if ran else 'unlaunched '}{_clip(repr(pclass), 24)} record requires origin "
            f"{'external' if want_external else 'local'}, got {_clip(repr(origin), 20)}")
    if want_external:
        ext = rec.get("external")
        if not isinstance(ext, Mapping):
            add("missing_external", "ran real-service/physical evidence needs an external reference")
        else:
            _key_errors(ext, ("authorization_id", "receipt_sha256"), (), errs, "case.external")
            if not _is_str(ext.get("authorization_id")) or not _is_hex64(ext.get("receipt_sha256")):
                add("bad_field", "case.external authorization_id/receipt_sha256")
    elif "external" in rec:
        add("unexpected_external", "only ran real-service/physical evidence may carry external")

    # Seed and replay identity.
    seed = rec.get("seed")
    seed_ok = _is_int(seed) and 0 <= seed < U64
    if not seed_ok:
        add("bad_field", "case.seed must be an int in [0, 2**64)")
    run_seed = hdr.get("seed") if hdr is not None else None
    if not (_is_int(run_seed) and 0 <= run_seed < U64):
        run_seed = None
    if seed_ok and case_id is not None and run_seed is not None and seed != derive_case_seed(run_seed, case_id):
        add("seed_not_derived", "seed is not derive_case_seed(header.seed, case_id)")
    replay = rec.get("replay")
    if not isinstance(replay, Mapping):
        add("bad_replay", "replay must be an object")
    else:
        _key_errors(replay, ("argv", "case_id", "run_seed", "case_seed"), (), errs, "case.replay")
        argv = replay.get("argv")
        if (not isinstance(argv, list) or not argv or len(argv) > 256
                or not all(_is_str(a) and len(a) <= 4096 for a in argv)):
            add("bad_replay", "replay.argv must be 1..256 non-empty strings")
            argv = None
        if case_id is not None and replay.get("case_id") != case_id:
            add("bad_replay", "replay.case_id != case_id")
        if run_seed is not None and replay.get("run_seed") != run_seed:
            add("bad_replay", "replay.run_seed != header.seed")
        if seed_ok and replay.get("case_seed") != seed:
            add("bad_replay", "replay.case_seed != seed")
        if argv is not None and case_id is not None and not _argv_names(argv, case_id):
            add("bad_replay", "replay.argv does not name the case id")
        if argv is not None and run_seed is not None and not _argv_names(argv, str(run_seed)):
            add("bad_replay", "replay.argv does not carry the run seed")

    # Artifact identity must match the header exactly.
    if "artifacts" in rec:
        got = _artifact_refs(rec["artifacts"], ("name", "sha256"), "case.artifacts", errs, nonempty=ran)
        want = _artifact_refs(hdr.get("artifacts"), ("name", "sha256", "size"), "header.artifacts", [], nonempty=False) if hdr is not None else {}
        for name, digest in got.items():
            if name not in want:
                add("artifact_mismatch", f"{name} is not a header artifact")
            elif want[name] != digest:
                add("artifact_mismatch", f"{name} digest differs from header")

    log_events = None
    if "log" in rec:
        log = rec["log"]
        if not isinstance(log, Mapping):
            add("bad_log", "log must be an object")
        else:
            _key_errors(log, ("sha256", "events", "dropped", "bytes", "truncated", "critical_lost"), (), errs, "case.log")
            if not _is_hex64(log.get("sha256")):
                add("bad_log", "log.sha256")
            for k in ("events", "dropped", "bytes"):
                if not _is_int(log.get(k)) or log[k] < 0:
                    add("bad_log", f"log.{k}")
            for k in ("truncated", "critical_lost"):
                if not isinstance(log.get(k), bool):
                    add("bad_log", f"log.{k} must be a bool")
            if _is_int(log.get("events")) and _is_int(log.get("dropped")):
                log_events = log["events"] + log["dropped"]
            if outcome == "pass" and log_evidence_lost(rec):
                add("critical_evidence_lost", "a pass cannot rest on a truncated or lossy log")

    if ran:
        proc = rec.get("process")
        timed_out = None
        exit_code = None
        if not isinstance(proc, Mapping):
            add("bad_process", "process must be an object")
        else:
            _key_errors(proc, ("exit_code", "timed_out"), (), errs, "case.process")
            exit_code, timed_out = proc.get("exit_code"), proc.get("timed_out")
            if exit_code is not None and not _is_int(exit_code):
                add("bad_process", "process.exit_code must be an int or null")
            if not isinstance(timed_out, bool):
                add("bad_process", "process.timed_out must be a bool")
        if outcome == "pass" and timed_out is not False:
            add("contradiction", "pass requires timed_out false")
        if outcome == "pass" and canary is False and exit_code != 0:
            add("contradiction", "pass requires exit_code 0 (canary subjects are expected to fail)")
        if outcome == "pass" and canary is True and not _is_int(exit_code):
            add("contradiction", "a canary pass needs the subject's observed exit_code")
        if outcome == "timeout" and timed_out is not True:
            add("contradiction", "timeout requires timed_out true")
        if outcome in ("fail", "crash", "cancelled") and timed_out is True:
            add("contradiction", f"{outcome} cannot have timed_out true")
        if outcome == "crash" and (not _is_int(exit_code) or exit_code == 0):
            add("contradiction", "crash requires a non-zero exit_code (negative = signal)")
        t0, t1 = rec.get("started_mono_ns"), rec.get("ended_mono_ns")
        if not (_is_int(t0) and _is_int(t1) and 0 <= t0 <= t1):
            add("bad_time", "started_mono_ns/ended_mono_ns must be ints with 0 <= start <= end")

    if outcome == "pass":
        orc = rec.get("oracle")
        if not isinstance(orc, Mapping):
            add("bad_oracle", "oracle must be an object")
        else:
            _key_errors(orc, ("name", "kind", "independent", "checks", "mismatches", "status",
                              "finalized", "incomplete_reasons", "violation_kinds"), (), errs, "case.oracle")
            if not _is_str(orc.get("name")):
                add("bad_oracle", "oracle.name")
            kind = orc.get("kind")
            if kind == "log":
                add("log_only_oracle", "a log is not a functional oracle")
            elif not _in(kind, ORACLE_KINDS):
                add("bad_oracle", f"oracle.kind must be one of {','.join(ORACLE_KINDS)}")
            if orc.get("independent") is not True:
                add("bad_oracle", "oracle.independent must be true")
            checks, mism = orc.get("checks"), orc.get("mismatches")
            if not _is_int(checks) or checks < 1:
                add("vacuous_pass", "oracle.checks must be >= 1")
            mism_ok = _is_int(mism) and mism >= 0
            if not mism_ok:
                add("bad_oracle", "oracle.mismatches")
            status, finalized = orc.get("status"), orc.get("finalized")
            reasons, kinds = orc.get("incomplete_reasons"), orc.get("violation_kinds")
            if not _in(status, ORACLE_STATUSES):
                add("bad_oracle", "oracle.status must be passed|failed|incomplete")
            if not isinstance(finalized, bool):
                add("bad_oracle", "oracle.finalized must be a bool")
            reasons_ok = isinstance(reasons, list) and all(_is_str(x) for x in reasons)
            if not reasons_ok:
                add("bad_oracle", "oracle.incomplete_reasons must be a list of non-empty strings")
            kinds_ok = isinstance(kinds, Mapping) and all(_is_str(k) and _is_int(v) and v >= 1 for k, v in kinds.items())
            if not kinds_ok:
                add("bad_oracle", "oracle.violation_kinds must map a kind to a count >= 1")
            if mism_ok and kinds_ok and sum(kinds.values()) != mism:
                add("bad_oracle", "oracle.mismatches != sum(oracle.violation_kinds)")
            # An oracle that did not finish proved nothing, whatever else it reports.
            if status == "incomplete" or finalized is False or (reasons_ok and reasons):
                add("oracle_incomplete",
                    f"status={_clip(repr(status), 20)} finalized={_clip(repr(finalized), 8)} "
                    f"reasons={_clip(repr(reasons), 80)}")
            if canary is True:
                if status != "failed" or not kinds_ok or not kinds or not mism_ok or mism < 1:
                    add("canary_not_detected",
                        "a canary pass needs oracle status failed with at least one violation kind")
            elif canary is False:
                if status == "failed" or (mism_ok and mism != 0) or (kinds_ok and kinds):
                    add("pass_with_mismatches", f"{mism} oracle mismatches on a pass")

    if outcome in FAILURE_OUTCOMES:
        fail = rec.get("failure")
        if not isinstance(fail, Mapping):
            add("bad_failure", "failure must be an object")
        else:
            _key_errors(fail, ("oracle", "expected", "observed", "first_causal_event"), (), errs, "case.failure")
            if not _is_str(fail.get("oracle")):
                add("bad_failure", "failure.oracle")
            if "expected" in fail and "observed" in fail:
                try:
                    same = canonical_json(fail["expected"]) == canonical_json(fail["observed"])
                except (TypeError, ValueError):
                    same = False
                if same:
                    add("bad_failure", "failure.expected equals failure.observed")
            ev = fail.get("first_causal_event")
            if not isinstance(ev, Mapping):
                add("bad_failure", "first_causal_event must be an object")
            else:
                _key_errors(ev, ("log_seq", "kind"), (), errs, "case.failure.first_causal_event")
                if not _is_int(ev.get("log_seq")) or ev["log_seq"] < 0 or not _is_str(ev.get("kind")):
                    add("bad_failure", "first_causal_event.log_seq/kind")
                elif log_events is not None and ev["log_seq"] >= log_events:
                    add("bad_failure", "first_causal_event.log_seq lies outside the log")

    if outcome in REASON_OUTCOMES and (not _is_str(rec.get("reason")) or len(rec["reason"]) > 2000):
        add("bad_field", "case.reason must be 1..2000 chars")
    return errs


def oracle_block_from_verdict(verdict, *, kind, independent=True, checks=None):
    """Build a pass record's ``oracle`` block from an ``ffw.oracle_verdict.v1``.

    The runner should call this instead of mapping fields by hand: a hand
    mapping that turns "incomplete" into ``mismatches >= 1`` is exactly how an
    oracle that never finished gets counted as a canary detection. This copies
    status, finalized, incomplete reasons and violation kinds as reported and
    refuses a verdict whose own fields contradict each other. It does not
    decide pass/fail: an incomplete verdict yields a block that
    ``validate_case_record`` then rejects as a pass.
    """
    if not isinstance(verdict, Mapping) or verdict.get("schema") != VERDICT_SCHEMA:
        raise ReceiptError(f"verdict must be a {VERDICT_SCHEMA} mapping")
    if not _in(kind, ORACLE_KINDS):
        raise ReceiptError(f"kind must be one of {','.join(ORACLE_KINDS)}")
    if not isinstance(independent, bool):
        raise ReceiptError("independent must be a bool")
    name, status = verdict.get("oracle"), verdict.get("status")
    finalized, reasons = verdict.get("finalized"), verdict.get("incomplete_reasons")
    count, kinds = verdict.get("violation_count"), verdict.get("violation_kinds")
    if not _is_str(name) or not _in(status, ORACLE_STATUSES) or not isinstance(finalized, bool):
        raise ReceiptError("verdict needs oracle, status and finalized")
    if not (isinstance(reasons, list) and all(_is_str(x) for x in reasons)):
        raise ReceiptError("verdict.incomplete_reasons must be a list of strings")
    if not _is_int(count) or count < 0:
        raise ReceiptError("verdict.violation_count must be an int >= 0")
    if not (isinstance(kinds, Mapping) and all(_is_str(k) and _is_int(v) and v >= 1 for k, v in kinds.items())):
        raise ReceiptError("verdict.violation_kinds must map a kind to a count >= 1")
    if sum(kinds.values()) != count:
        raise ReceiptError("verdict.violation_kinds does not sum to violation_count")
    if (status == "failed") != (count > 0):
        raise ReceiptError("verdict status failed must coincide with violations")
    if status == "passed" and (reasons or not finalized):
        raise ReceiptError("verdict status passed contradicts its incomplete reasons/finalized flag")
    if status == "incomplete" and finalized and not reasons:
        raise ReceiptError("verdict status incomplete without a reason")
    if checks is None:
        checks = verdict.get("events_relevant")
    if not _is_int(checks) or checks < 0:
        raise ReceiptError("checks (default verdict.events_relevant) must be an int >= 0")
    return {
        "name": name, "kind": kind, "independent": independent, "checks": checks, "mismatches": count,
        "status": status, "finalized": finalized, "incomplete_reasons": list(reasons),
        "violation_kinds": dict(kinds),
    }


# ---------------------------------------------------------------- aggregator


class _Problems:
    def __init__(self, cap):
        self.cap = cap
        self.items = []
        self.total = 0
        self.incomplete = False
        self.codes_by_case = {}

    def add(self, code, detail, *, case_id=None, line=None, incomplete=False):
        self.total += 1
        self.incomplete = self.incomplete or incomplete
        if case_id is not None:
            self.codes_by_case.setdefault(case_id, set()).add(code)
        if len(self.items) < self.cap:
            item = {"code": code, "detail": _clip(detail, 300)}
            if case_id is not None:
                item["case_id"] = case_id
            if line is not None:
                item["line"] = line
            self.items.append(item)


def _parse_lines(data, max_line_bytes, probs):
    """-> [(lineno, raw_bytes, obj_or_None)]; every defect becomes a problem."""
    out = []
    if not data:
        probs.add("stream_empty", "no bytes", incomplete=True)
        return out
    parts = data.split(b"\n")
    if data.endswith(b"\n"):
        parts.pop()
    else:
        probs.add("stream_truncated", "final record has no newline terminator", incomplete=True)
    for no, raw in enumerate(parts, 1):
        obj = None
        if len(raw) > max_line_bytes:
            probs.add("line_too_long", f"{len(raw)} bytes > {max_line_bytes}", line=no, incomplete=True)
        elif not raw.strip():
            probs.add("blank_line", "empty record", line=no, incomplete=True)
        else:
            try:
                parsed = _loads_strict(raw.decode("utf-8"))
            except UnicodeDecodeError:
                probs.add("bad_encoding", "not valid UTF-8", line=no, incomplete=True)
            except _StrictJSON as exc:
                probs.add(exc.code, _clip(exc.detail, 80), line=no, incomplete=True)
            except (ValueError, RecursionError) as exc:
                probs.add("bad_json", _clip(exc, 120), line=no, incomplete=True)
            else:
                if isinstance(parsed, dict):
                    obj = parsed
                else:
                    probs.add("not_object", "record is not a JSON object", line=no, incomplete=True)
        out.append((no, raw, obj))
    return out


def _judge_case(cid, entries, max_attempts, probs):
    """entries: [(lineno, record, errs)] -> verdict dict for one expected case."""
    if not entries:
        return {"verdict": "not_run", "attempts": [], "flaky": False, "reason": "no_receipt", "first": None}
    bad = False
    for no, rec, errs in entries:
        for code, detail in errs:
            probs.add(code, detail, case_id=cid, line=no, incomplete=(code == "critical_evidence_lost"))
            bad = True
        if log_evidence_lost(rec) and rec.get("outcome") != "pass":
            probs.add("critical_evidence_lost", "log truncated or lossy", case_id=cid, line=no, incomplete=True)
    seen = {}
    for no, rec, _ in entries:
        n = rec.get("attempt")
        if _is_int(n):
            seen.setdefault(n, []).append((no, rec))
    for n, group in sorted(seen.items()):
        if len(group) > 1:
            same = len({canonical_json(r) for _, r in group}) == 1
            probs.add(
                "duplicate_case_evidence",
                f"attempt {n} appears {len(group)} times ({'identical' if same else 'conflicting'})",
                case_id=cid, line=group[1][0],
            )
            bad = True
    if seen:
        top = max(seen)
        if set(seen) != set(range(1, top + 1)):
            probs.add("attempt_gap", f"attempts present: {sorted(seen)}", case_id=cid)
            bad = True
        if top > max_attempts:
            probs.add("attempts_exceeded", f"{top} attempts > max_attempts {max_attempts}", case_id=cid)
            bad = True
    ordered = [
        t[2]
        for t in sorted(
            ((r.get("attempt") if _is_int(r.get("attempt")) else 0, k, r) for k, (_, r, _) in enumerate(entries)),
            key=lambda t: (t[0], t[1]),
        )
    ]
    outcomes = [r.get("outcome") if _in(r.get("outcome"), OUTCOMES) else "invalid" for r in ordered]
    if bad:
        return {"verdict": "invalid", "attempts": outcomes, "flaky": False, "reason": None, "first": None}
    first_bad = next((r for r in ordered if r["outcome"] != "pass"), None)
    if first_bad is None:
        return {"verdict": "pass", "attempts": outcomes, "flaky": False, "reason": None, "first": None}
    flaky = any(o == "pass" for o in outcomes)
    return {"verdict": first_bad["outcome"], "attempts": outcomes, "flaky": flaky, "reason": None, "first": first_bad}


def _aggregate(data, expected, *, max_attempts, max_line_bytes, max_problems, max_failures, pre, required=None):
    exp = normalize_expected(expected)
    floor = normalize_required(required)
    if not _is_int(max_attempts) or max_attempts < 1:
        raise ReceiptError("max_attempts must be an int >= 1")
    probs = _Problems(max_problems)
    for code, detail in pre:
        probs.add(code, detail, incomplete=True)

    lines = _parse_lines(data, max_line_bytes, probs)
    n = len(lines)

    header = footer = None
    footer_idx = None
    case_lines = []
    for idx, (no, _raw, obj) in enumerate(lines):
        if obj is None:
            continue
        kind = obj.get("kind")
        if kind == "run_header":
            if idx == 0:
                header = obj
            else:
                probs.add("header_misplaced", "run_header is not the first line", line=no, incomplete=True)
        elif kind == "run_footer":
            if idx == n - 1 and footer is None:
                footer, footer_idx = obj, idx
            else:
                probs.add("footer_misplaced", "run_footer is not the last line (or repeated)", line=no, incomplete=True)
        elif kind == "case":
            case_lines.append((no, obj))
        else:
            probs.add("unknown_kind", _clip(repr(kind), 60), line=no, incomplete=True)

    header_ok = False
    if lines and header is None:
        probs.add("header_missing", "first line is not a run_header", incomplete=True)
    elif header is not None:
        herrs = validate_header(header)
        for code, detail in herrs:
            probs.add(code, detail, line=1, incomplete=True)
        header_ok = not herrs
        if header_ok:
            if header["registry_digest"] != registry_digest(expected):
                probs.add("registry_mismatch", "header registry_digest differs from the supplied expected set")
            if header["expected_cases"] != len(exp):
                probs.add("registry_mismatch", f"header expected_cases {header['expected_cases']} != {len(exp)}")

    if lines and footer is None:
        probs.add("footer_missing", "stream ends without a run_footer", incomplete=True)
    elif footer is not None:
        ferrs = validate_footer(footer)
        for code, detail in ferrs:
            probs.add(code, detail, line=n, incomplete=True)
        if not ferrs:
            h = hashlib.sha256()
            for _no, raw, _obj in lines[:footer_idx]:
                h.update(raw + b"\n")
            if h.hexdigest() != footer["stream_sha256"]:
                probs.add("footer_digest_mismatch", "bytes before the footer do not match stream_sha256", line=n, incomplete=True)
            if footer["lines"] != footer_idx:
                probs.add("footer_count_mismatch", f"footer lines {footer['lines']} != {footer_idx}", line=n, incomplete=True)
            if footer["case_records"] != len(case_lines):
                probs.add("footer_count_mismatch", f"footer case_records {footer['case_records']} != {len(case_lines)}", line=n, incomplete=True)

    by_case = {cid: [] for cid in exp}
    unexpected = 0
    for no, rec in case_lines:
        cid = rec.get("case_id")
        if not isinstance(cid, str) or cid not in exp:
            unexpected += 1
            probs.add("unexpected_case", _clip(repr(cid), 80), line=no)
            continue
        errs = validate_case_record(rec, header if header_ok else None)
        spec = exp[cid]
        if rec.get("proof_class") != spec.proof_class:
            errs.append(("proof_class_mismatch", f"registry requires {spec.proof_class}, receipt says {_clip(repr(rec.get('proof_class')), 20)}"))
        if rec.get("canary") is not spec.canary:
            errs.append(("canary_mismatch", f"registry says canary={spec.canary}, receipt says {_clip(repr(rec.get('canary')), 20)}"))
        if spec.canary and rec.get("outcome") == "pass" and isinstance(rec.get("oracle"), Mapping):
            orc = rec["oracle"]
            if orc.get("name") != spec.oracle:
                errs.append(("canary_wrong_oracle", f"registry expects oracle {spec.oracle}, receipt says {_clip(repr(orc.get('name')), 40)}"))
            kinds = orc.get("violation_kinds")
            if not (isinstance(kinds, Mapping) and spec.violation in kinds):
                errs.append(("canary_wrong_violation", f"registry expects violation {spec.violation}, receipt has {_clip(repr(kinds), 80)}"))
        by_case[cid].append((no, rec, errs))

    # Independent floor: a registry that was shrunk, demoted or altered by whoever
    # also writes the stream is self-consistent, so only an outside list can catch it.
    req = None
    if floor is not None:
        req = {"count": len(floor), "dropped": 0, "demoted": 0, "altered": 0}
        for cid in sorted(floor):
            sp = exp.get(cid)
            if sp is None:
                req["dropped"] += 1
                probs.add("required_case_dropped", "required case is absent from the registry", case_id=cid)
                continue
            if not sp.mandatory:
                req["demoted"] += 1
                probs.add("required_case_demoted", "required case is optional in the registry", case_id=cid)
            for field, want in floor[cid].items():
                have = getattr(sp, field)
                if have != want:
                    req["altered"] += 1
                    probs.add("required_case_altered", f"{field}: floor {_clip(repr(want), 40)}, registry {_clip(repr(have), 40)}", case_id=cid)

    judged = {cid: _judge_case(cid, by_case[cid], max_attempts, probs) for cid in sorted(exp)}

    counts = {v: 0 for v in VERDICTS}
    by_class = {}
    for cid, j in judged.items():
        counts[j["verdict"]] += 1
        pc = exp[cid].proof_class
        row = by_class.setdefault(pc, {"total": 0, **{v: 0 for v in VERDICTS}})
        row["total"] += 1
        row[j["verdict"]] += 1
    mandatory = sorted(c for c, sp in exp.items() if sp.mandatory)
    denominator = {
        "total": len(exp),
        "mandatory": len(mandatory),
        "optional": len(exp) - len(mandatory),
        "executed": sum(counts[o] for o in RAN_OUTCOMES),
    }
    if sum(counts.values()) != denominator["total"]:
        raise RuntimeError("internal error: verdict buckets do not sum to the denominator")

    mandatory_open = [c for c in mandatory if judged[c]["verdict"] != "pass"]
    reasons = []
    if probs.incomplete:
        reasons.append("stream_incomplete")
    if probs.total:
        reasons.append("evidence_problems")
    if mandatory_open:
        reasons.append(f"mandatory_not_passed:{len(mandatory_open)}")
    if not mandatory:
        reasons.append("no_mandatory_cases")
    if req and req["dropped"] + req["demoted"] + req["altered"]:
        reasons.append(f"required_cases_violated:{req['dropped'] + req['demoted'] + req['altered']}")

    failures = []
    ordered_ids = sorted((c for c in judged if judged[c]["verdict"] != "pass"), key=lambda c: (not exp[c].mandatory, c))
    for cid in ordered_ids[:max_failures]:
        j = judged[cid]
        first = j["first"]
        entry = {
            "case_id": cid,
            "verdict": j["verdict"],
            "mandatory": exp[cid].mandatory,
            "proof_class": exp[cid].proof_class,
            "flaky": j["flaky"],
            "attempt_outcomes": j["attempts"],
            "problem_codes": sorted(probs.codes_by_case.get(cid, ())),
            "replay": None,
            "original": None,
        }
        if j["reason"]:
            entry["original"] = {"reason": j["reason"]}
        if first is not None:
            entry["replay"] = list(first["replay"]["argv"])
            entry["original"] = {"attempt": first["attempt"], "outcome": first["outcome"]}
            if "failure" in first:
                entry["original"]["failure"] = first["failure"]
            if "reason" in first:
                entry["original"]["reason"] = first["reason"]
        failures.append(entry)

    ident = None
    if header_ok:
        ident = {k: header[k] for k in ("run_id", "suite", "tier", "seed", "registry_digest", "versions", "artifacts")}
    return {
        "schema": SUMMARY_SCHEMA,
        "qualified": not reasons,
        "unqualified_reasons": reasons,
        "complete": not probs.incomplete,
        "tier": header["tier"] if header_ok else None,
        "identity": ident,
        "evidence_sha256": sha256_hex(data),
        "denominator": denominator,
        "counts": counts,
        "unexpected_records": unexpected,
        "required": req,
        "by_proof_class": {k: by_class[k] for k in sorted(by_class)},
        "cases": {
            cid: {"verdict": j["verdict"], "mandatory": exp[cid].mandatory, "proof_class": exp[cid].proof_class,
                  "canary": exp[cid].canary, "attempt_outcomes": j["attempts"], "flaky": j["flaky"]}
            for cid, j in judged.items()
        },
        "failures": failures,
        "failures_omitted": max(0, len(ordered_ids) - len(failures)),
        "problems": probs.items,
        "problems_total": probs.total,
        "problems_omitted": probs.total - len(probs.items),
    }


def aggregate(data, expected, *, max_attempts=1, max_line_bytes=MAX_LINE_BYTES,
              max_problems=MAX_PROBLEMS, max_failures=MAX_FAILURES, required=None):
    """Validate a receipt stream (bytes) against the expected case set.

    ``required`` is an optional independent floor (see ``normalize_required``):
    case ids the registry must still contain as mandatory, with the given
    proof class / canary / oracle / violation. Supply it from a source the
    runner does not control, or a runner that drops a case from both its
    registry and its stream is indistinguishable from a complete run."""
    if not isinstance(data, (bytes, bytearray)):
        raise ReceiptError("stream must be bytes")
    return _aggregate(bytes(data), expected, max_attempts=max_attempts, max_line_bytes=max_line_bytes,
                      max_problems=max_problems, max_failures=max_failures, pre=(), required=required)


def aggregate_path(path, expected, *, max_bytes=MAX_STREAM_BYTES, max_attempts=1,
                   max_line_bytes=MAX_LINE_BYTES, max_problems=MAX_PROBLEMS,
                   max_failures=MAX_FAILURES, required=None):
    """Like ``aggregate`` but reads ``path``; an unreadable or oversized stream
    is an unqualified result, not an exception."""
    pre = []
    data = b""
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes + 1)
        if len(data) > max_bytes:
            data = b""
            pre.append(("stream_too_large", f"more than {max_bytes} bytes"))
    except OSError as exc:
        data = b""
        pre.append(("stream_unreadable", _clip(exc, 200)))
    return _aggregate(data, expected, max_attempts=max_attempts, max_line_bytes=max_line_bytes,
                      max_problems=max_problems, max_failures=max_failures, pre=pre, required=required)


def render_summary(s, *, max_lines=60):
    """Concise human summary; counts are exact, detail lists are clipped."""
    d, c = s["denominator"], s["counts"]
    ident = s["identity"] or {}
    out = [
        f"RECEIPTS {'QUALIFIED' if s['qualified'] else 'NOT QUALIFIED'}"
        f"  run={ident.get('run_id', '?')} suite={ident.get('suite', '?')} tier={s['tier'] or '?'}",
        f"denominator: total={d['total']} executed={d['executed']} mandatory={d['mandatory']} optional={d['optional']}"
        f"  complete={'yes' if s['complete'] else 'NO'} unexpected_records={s['unexpected_records']}",
        "verdicts: " + " ".join(f"{v}={c[v]}" for v in VERDICTS),
    ]
    for pc, row in s["by_proof_class"].items():
        out.append(f"  class {pc}: total={row['total']} pass={row['pass']} "
                   f"other={row['total'] - row['pass']}")
    rq = s["required"]
    out.append("required floor: none supplied (the denominator is only the caller's registry)" if rq is None else
               f"required floor: {rq['count']} cases dropped={rq['dropped']} demoted={rq['demoted']} altered={rq['altered']}")
    if s["unqualified_reasons"]:
        out.append("reasons: " + ", ".join(s["unqualified_reasons"]))
    for f in s["failures"]:
        out.append(f"[{f['verdict']}] {f['case_id']} ({'mandatory' if f['mandatory'] else 'optional'}, "
                   f"{f['proof_class']}) attempts={','.join(f['attempt_outcomes']) or '-'}"
                   f"{' FLAKY' if f['flaky'] else ''}")
        if f["replay"]:
            out.append("    replay: " + _clip(shlex.join(f["replay"]), 400))
        orig = f["original"] or {}
        if "failure" in orig:
            fl = orig["failure"]
            ev = fl["first_causal_event"]
            out.append(f"    oracle={fl['oracle']} expected={_clip(json.dumps(fl['expected']), 120)} "
                       f"observed={_clip(json.dumps(fl['observed']), 120)} first_cause=log#{ev['log_seq']}:{ev['kind']}")
        if "reason" in orig:
            out.append(f"    reason: {_clip(orig['reason'], 200)}")
        if f["problem_codes"]:
            out.append("    problems: " + ",".join(f["problem_codes"]))
    if s["failures_omitted"]:
        out.append(f"... {s['failures_omitted']} more non-passing cases omitted (counts above are exact)")
    for p in s["problems"]:
        where = f" {p['case_id']}" if "case_id" in p else ""
        ln = f" line {p['line']}" if "line" in p else ""
        out.append(f"problem {p['code']}{where}{ln}: {p['detail']}")
    if s["problems_omitted"]:
        out.append(f"... {s['problems_omitted']} more problems omitted (total {s['problems_total']})")
    out.append(f"evidence sha256: {s['evidence_sha256']}")
    if len(out) > max_lines:
        dropped = len(out) - max_lines + 1
        out = out[: max_lines - 1] + [f"... {dropped} summary lines clipped"]
    return "\n".join(out) + "\n"


# ----------------------------------------------------------------------- CLI


def main(argv=None):
    ap = argparse.ArgumentParser(prog="receipts", description=__doc__.split("\n", 1)[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="exit 0 only if the stream is fully qualified")
    v.add_argument("stream")
    v.add_argument("--expected", required=True,
                   help="JSON {case_id: {mandatory, proof_class[, canary, oracle, violation]}}")
    # The floor is the only defence against a registry shrunk by whoever also writes the
    # stream, so omitting it must be a decision, not an accident.
    floor = v.add_mutually_exclusive_group(required=True)
    floor.add_argument("--require", help="JSON list of case ids, or {case_id: constraints}, the registry must still "
                                         "contain (independent floor against dropped/demoted cases)")
    floor.add_argument("--no-floor", action="store_true",
                       help="explicitly verify without an independent floor; the denominator is then only "
                            "the --expected registry and a case dropped from both is invisible")
    v.add_argument("--max-attempts", type=int, default=1)
    v.add_argument("--json", action="store_true", help="print the JSON summary instead of text")
    args = ap.parse_args(argv)
    try:
        with open(args.expected, "rb") as fh:
            expected = _loads_strict(fh.read().decode("utf-8"))
        normalize_expected(expected)
    except (OSError, ValueError, RecursionError, _StrictJSON, ReceiptError) as exc:
        print(f"receipts: bad --expected: {_clip(getattr(exc, 'detail', exc), 200)}", file=sys.stderr)
        return 2
    required = None
    if args.require is not None:
        try:
            with open(args.require, "rb") as fh:
                required = _loads_strict(fh.read().decode("utf-8"))
            normalize_required(required)
        except (OSError, ValueError, RecursionError, _StrictJSON, ReceiptError) as exc:
            print(f"receipts: bad --require: {_clip(getattr(exc, 'detail', exc), 200)}", file=sys.stderr)
            return 2
    if args.max_attempts < 1:
        print("receipts: --max-attempts must be >= 1", file=sys.stderr)
        return 2
    summary = aggregate_path(args.stream, expected, max_attempts=args.max_attempts, required=required)
    if args.json:
        sys.stdout.write(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    else:
        sys.stdout.write(render_summary(summary))
    return 0 if summary["qualified"] else 1


if __name__ == "__main__":
    sys.exit(main())
