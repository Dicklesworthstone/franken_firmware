#!/usr/bin/env python3
"""Offline enrichment of a private device capture with published hardware profiles.

Reads a *private* capture (``scan.py`` output, git-ignored ``devices.json``) and a
versioned *published hardware profile* document, and emits a sanitized,
deterministic, model-level inventory. Nothing happens at import time: no file is
read or written and no network or subprocess module is imported. The shared
``identity.py`` (sibling file) is loaded lazily on first use.

Evidence classes kept strictly apart in every record
----------------------------------------------------
``device_reported``   values the unit itself reported in ``device_description.xml``.
                      Bare ``memory``/``flash`` numbers carry *no unit* in that XML, so
                      the unit stays ``null`` (reason ``*_unit_unknown``) unless the
                      operator asserts one with ``--nominal-unit``; the asserted unit is
                      recorded as ``operator_asserted``, never as device evidence.
``published_profile`` model-level claims from public teardowns or vendor pages,
                      matched by exact ``modelNumber``. These are *hints*. This tool never
                      asserts per-unit silicon: ``per_unit_silicon_confirmed`` and
                      ``binary_or_calibration_selection_eligible`` are constants (false)
                      computed here, never read from any input file. Nothing is inferred
                      from product era, software generation or a "nearest" model.

Shared identity engine (``identity.py``) is used, not re-implemented, for: serial
pseudonyms (``Pseudonymizer``), the hardware-revision / software-build / generation /
nominal-size parsing and unit handling (``normalize_record``), the board profile id
(``profile_id_for``, emitted as ``board_profile_id``, a single-observation candidate;
fleet-level resolution belongs to reconcile), and a leak scan
(``find_private_identifiers``). The published-profile id (``published_profile_id``) is a
different object and deliberately named differently.

Statuses
--------
``enriched``             known model, profile attached, every expected field valid.
``enriched_incomplete``  profile attached, but a reported field, a unit or the serial is
                         missing/invalid/unknown (see ``reason_codes``).
``unknown_model``        model number valid but no published profile for it.
``invalid``              entry malformed (not an object, no ``fields``, scan error row,
                         bad ``modelNumber``) or too complex to inspect.
``ambiguous``            two or more entries claim the same serial. Neither is dropped,
                         merged or enriched; reconciliation owns that.

Privacy
-------
Only an allowlist of public fields is ever read for output. Serials, UDNs, MACs, IPs,
URLs, room and zone names, household identifiers and every other key are never copied.
Defence in depth: every identifier-class value harvested from the capture is checked
(a) as an exact value in the serialized artifacts and (b) as a canary, together with
generic identifier patterns, by the shared scanner on the structured output. Either hit
aborts the run (exit 6) without echoing the value. ``device_ref`` is a keyed pseudonym
of the serial (``--salt-file``; stable for one key) or a run-local ordinal that implies
no identity across runs; ``device_ref_scope`` says which.

Exit codes
----------
0 all devices ``enriched``           4 input/profile/salt/shared module rejected, nothing written
2 usage error                        5 output refused or write failed
3 outputs produced, but at least     6 sanitized artifact would leak a private value,
  one device is not ``enriched``       nothing written
130 interrupted (Ctrl-C or SIGTERM): temp files removed; see ``publish_outputs`` for what a
  rerun repairs

Interruption and restart
------------------------
Output is deterministic, so a rerun after any interruption converges on byte-identical files.
Publication stages every output first and renames afterwards (``publish_outputs``): an
interruption or write failure before the rename phase leaves all destinations untouched.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import signal
import stat
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

TOOL = "inventory/enrich.py"
OUTPUT_SCHEMA = "ffw.enriched-inventory/2"
RECORD_SCHEMA = "ffw.enriched-device/2"
PROFILE_SCHEMA = "ffw.published-hardware-profiles"
PROFILE_SCHEMA_VERSION = 1
LEGACY_PROFILE_SCHEMA_VERSION = 0

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_PARTIAL = 3
EXIT_INPUT = 4
EXIT_OUTPUT = 5
EXIT_LEAK = 6
EXIT_INTERRUPT = 130  # Ctrl-C or SIGTERM, same code as reconcile.py

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_PROFILE_BYTES = 256 * 1024
MAX_SALT_BYTES = 4096
MIN_SALT_BYTES = 16
MAX_DEVICES = 512
MAX_PROFILES = 64
MAX_SOURCES = 16
MAX_CLAIM_CHARS = 512
MAX_FIELD_CHARS = 256
MAX_JSON_DEPTH = 32
MAX_ENTRY_NODES = 2000
MAX_ENTRY_DEPTH = 8
MIN_LEAK_CHECK_CHARS = 6
NOMINAL_UNITS = ("MB", "MiB")

DEFAULT_PROFILES = Path(__file__).resolve().parent / "hardware-profiles.json"

STATUSES = ("enriched", "enriched_incomplete", "unknown_model", "invalid", "ambiguous")

# Fields validated here (the shared module does not cover them): (reason prefix, output key, XML key, kind)
_TEXT_SPECS = (
    ("model_name", "model_name", "modelName", "text"),
    ("series_id", "series_id", "seriesid", "token"),
)
# identity field -> enrich reason prefix (software_generation is optional: absence is not a reason)
_IDENTITY_PREFIX = {
    "hardware_revision": "hardware_revision",
    "software_build": "software_build",
    "software_generation": "software_generation",
    "nominal_ram_bytes": "memory",
    "nominal_flash_bytes": "flash",
}

REASON_CODES = frozenset(
    {
        "entry_not_an_object",
        "entry_too_complex",
        "fields_missing",
        "scan_error_row",
        "model_number_missing",
        "model_number_invalid",
        "identity_record_rejected",
        "no_published_profile_for_model",
        "serial_missing",
        "serial_invalid",
        "duplicate_serial_in_input",
        "software_generation_invalid",
        "software_generation_conflict",
    }
    | {f"{prefix}_{problem}" for prefix, *_ in _TEXT_SPECS for problem in ("missing", "invalid", "contains_identifier")}
    | {f"{prefix}_{problem}" for prefix in ("hardware_revision", "software_build") for problem in ("missing", "invalid")}
    | {f"{prefix}_{problem}" for prefix in ("memory", "flash") for problem in ("missing", "invalid", "unit_unknown")}
)

# Keys whose values are read individually and validated; never bulk-harvested.
_PUBLIC_KEYS = frozenset({"modelName", "modelNumber", "hardwareVersion", "softwareVersion", "seriesid", "memory", "flash", "swGen", "SWGen"})
_LABEL_KEYS = frozenset({"roomname", "displayname", "friendlyname", "zonename", "zonedisplayname"})
_ID_KEY_HINTS = ("serial", "udn", "mac", "uuid", "uid", "household", "location", "token", "secret", "addr", "host", "password", "key")

_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}")
_TEXT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._:+/()-]{0,63}")
_PROFILE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{2,63}")
_CLAIM_RE = re.compile(r"[ -~]{1,%d}" % MAX_CLAIM_CHARS)
_SOURCE_RE = re.compile(r"https?://[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~%+/-]*)?")
_URL_HOST_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://(?:[^/@\s]*@)?([^/:?#\s]+)")
# Schema-defined keys in THIS tool's output that carry a sha256 of public data. They are
# handed to the shared scanner, which exempts only an exact 64-lowercase-hex value under
# such a key; the same hex under any other key is still a finding.
_DIGEST_KEYS = frozenset({"input_sha256", "profile_digest", "set_digest"})
# Provenance suffix the shared normalizer appends to a size claim's origin.
_SIZE_ORIGIN_RE = re.compile(r":(src|op)-([A-Za-z]{1,5})$")

_MAC_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}(?P<sep>[:-])[0-9A-Fa-f]{2}(?:(?P=sep)[0-9A-Fa-f]{2}){4}(?![0-9A-Fa-f])")
_UUID_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f])")
_LONG_HEX_RE = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{12,}(?![0-9A-Za-z])")
_IPV4_RE = re.compile(r"(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?![0-9])")
_IPV6_RE = re.compile(r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}(?![0-9A-Za-z:])")
_IDENTIFIER_RES = (_MAC_RE, _UUID_RE, _LONG_HEX_RE, _IPV4_RE, _IPV6_RE)

_CLAIM_KEYS = ("cpu", "ram", "flash", "network", "audio", "qualification")


class EnrichError(Exception):
    """Fatal, value-free failure. ``code`` and ``detail`` never contain device data."""

    def __init__(self, code: str, exit_code: int = EXIT_INPUT, detail: Optional[str] = None):
        super().__init__(code)
        self.code = code
        self.exit_code = exit_code
        self.detail = detail


# ----------------------------------------------------------------------------
# shared identity module (lazy; sibling file)
# ----------------------------------------------------------------------------

_IDENTITY: Any = None


def _identity() -> Any:
    """Load the sibling ``identity.py`` once, reusing an already-imported copy of the same file."""
    global _IDENTITY
    if _IDENTITY is not None:
        return _IDENTITY
    path = Path(__file__).resolve().parent / "identity.py"
    existing = sys.modules.get("identity")
    if existing is not None and getattr(existing, "__file__", None) and Path(existing.__file__).resolve() == path:
        _IDENTITY = existing
        return _IDENTITY
    if not path.is_file():
        raise EnrichError("identity_module_unavailable", EXIT_INPUT, "inventory/identity.py not found next to enrich.py")
    name = "identity" if existing is None else "_ffw_inventory_identity"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise EnrichError("identity_module_unavailable", EXIT_INPUT, "cannot load inventory/identity.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    _IDENTITY = module
    return module


# ----------------------------------------------------------------------------
# bounded input
# ----------------------------------------------------------------------------


def read_bounded(path: Path, limit: int, label: str) -> bytes:
    """Read a regular file of at most ``limit`` bytes; never block on special files."""
    try:
        st = os.stat(path)
    except OSError as exc:
        raise EnrichError(f"{label}_unreadable", EXIT_INPUT, exc.strerror) from None
    if not stat.S_ISREG(st.st_mode):
        raise EnrichError(f"{label}_not_a_regular_file")
    if st.st_size > limit:
        raise EnrichError(f"{label}_too_large", EXIT_INPUT, f"limit {limit} bytes")
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit + 1)
    except OSError as exc:
        raise EnrichError(f"{label}_unreadable", EXIT_INPUT, exc.strerror) from None
    if len(data) > limit:
        raise EnrichError(f"{label}_too_large", EXIT_INPUT, f"limit {limit} bytes")
    return data


def _no_duplicate_keys(pairs):
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate_json_key")
        out[key] = value
    return out


def _reject_constant(_name):
    raise ValueError("non_finite_number")


def _ensure_shallow(obj: Any, label: str) -> None:
    """Iterative depth bound. Newer interpreters parse arbitrarily deep JSON without
    raising, and deepcopy/dumps would then recurse; reject uniformly instead."""
    stack = [(obj, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise EnrichError(f"{label}_nesting_too_deep", EXIT_INPUT, f"limit {MAX_JSON_DEPTH}")
        children = node.values() if isinstance(node, dict) else node if isinstance(node, list) else ()
        stack.extend((child, depth + 1) for child in children if isinstance(child, (dict, list)))


def parse_json_bounded(data: bytes, label: str) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise EnrichError(f"{label}_not_utf8") from None
    try:
        obj = json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant)
    except RecursionError:
        raise EnrichError(f"{label}_nesting_too_deep", EXIT_INPUT, f"limit {MAX_JSON_DEPTH}") from None
    except ValueError as exc:
        if str(exc) in ("duplicate_json_key", "non_finite_number"):
            raise EnrichError(f"{label}_{exc}") from None
        raise EnrichError(f"{label}_malformed_json") from None
    _ensure_shallow(obj, label)
    return obj


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ----------------------------------------------------------------------------
# identifier detection (field gates; the shared scanner gates whole artifacts)
# ----------------------------------------------------------------------------


def identifier_kinds(text: str) -> list:
    """Identifier shapes present in ``text``."""
    kinds = []
    if _MAC_RE.search(text):
        kinds.append("mac")
    if _UUID_RE.search(text):
        kinds.append("uuid")
    if _LONG_HEX_RE.search(text):
        kinds.append("long_hex")
    if _IPV4_RE.search(text):
        kinds.append("ipv4")
    if _IPV6_RE.search(text):
        kinds.append("ipv6")
    return kinds


# ----------------------------------------------------------------------------
# versioned published-profile document
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class ProfileSet:
    schema_version: int
    digest: str
    by_model: dict = field(default_factory=dict)  # model -> normalized profile (+ published_profile_id, profile_digest)


def _profile_error(code: str, where: str) -> EnrichError:
    return EnrichError(code, EXIT_INPUT, where)


def _normalize_profile(model: str, raw: Any, allow_declared_id: bool) -> dict:
    if not isinstance(raw, dict):
        raise _profile_error("profiles_profile_not_an_object", model)
    allowed = set(_CLAIM_KEYS) | {"sources"} | ({"published_profile_id"} if allow_declared_id else set())
    for key in raw:
        if key not in allowed:
            raise _profile_error("profiles_unknown_field", f"{model}.{key}")
    norm: dict = {}
    for key in _CLAIM_KEYS:
        value = raw.get(key)
        if not isinstance(value, str) or not value.strip():
            raise _profile_error("profiles_bad_field", f"{model}.{key}")
        value = value.strip()
        if not _CLAIM_RE.fullmatch(value) or "://" in value or "@" in value:
            raise _profile_error("profiles_bad_field", f"{model}.{key}")
        if identifier_kinds(value):
            raise _profile_error("profiles_contains_identifier", f"{model}.{key}")
        norm[key] = value
    sources = raw.get("sources")
    if not isinstance(sources, list) or not 1 <= len(sources) <= MAX_SOURCES:
        raise _profile_error("profiles_bad_field", f"{model}.sources")
    clean_sources = []
    for item in sources:
        if not isinstance(item, str) or not _SOURCE_RE.fullmatch(item) or len(item) > 300:
            raise _profile_error("profiles_bad_source_url", model)
        if identifier_kinds(item):
            raise _profile_error("profiles_contains_identifier", f"{model}.sources")
        clean_sources.append(item)
    norm["sources"] = clean_sources
    if "published_profile_id" in raw:
        pid = raw["published_profile_id"]
        if not isinstance(pid, str) or not _PROFILE_ID_RE.fullmatch(pid):
            raise _profile_error("profiles_bad_field", f"{model}.published_profile_id")
        norm["_declared_id"] = pid
    return norm


def parse_profiles(doc: Any) -> ProfileSet:
    if not isinstance(doc, dict):
        raise EnrichError("profiles_not_an_object")
    versioned = any(key in doc for key in ("schema", "schema_version", "profiles"))
    if versioned:
        extra = sorted(set(doc) - {"schema", "schema_version", "profiles"})
        if extra:
            raise _profile_error("profiles_unexpected_top_level_key", extra[0])
        if doc.get("schema") != PROFILE_SCHEMA:
            raise EnrichError("profiles_unknown_schema")
        version = doc.get("schema_version")
        if type(version) is not int or version != PROFILE_SCHEMA_VERSION:
            raise EnrichError("profiles_unsupported_schema_version")
        raw_profiles = doc.get("profiles")
    else:
        version = LEGACY_PROFILE_SCHEMA_VERSION
        raw_profiles = doc
    if not isinstance(raw_profiles, dict) or not raw_profiles:
        raise EnrichError("profiles_empty")
    if len(raw_profiles) > MAX_PROFILES:
        raise EnrichError("profiles_too_many")

    by_model: dict = {}
    seen_ids: dict = {}
    for model in sorted(raw_profiles):
        if not isinstance(model, str) or not _TOKEN_RE.fullmatch(model):
            raise _profile_error("profiles_bad_model_key", "key")
        norm = _normalize_profile(model, raw_profiles[model], allow_declared_id=versioned)
        declared = norm.pop("_declared_id", None)
        digest = _sha256(_canon({"model": model, "profile": norm}))
        pid = declared or f"pub-{model.lower()}-{digest[:8]}"
        if pid in seen_ids:
            raise _profile_error("profiles_duplicate_profile_id", model)
        seen_ids[pid] = model
        by_model[model] = dict(norm, published_profile_id=pid, profile_digest=digest)
    set_digest = _sha256(_canon({"schema_version": version, "profiles": {m: {"id": p["published_profile_id"], "digest": p["profile_digest"]} for m, p in by_model.items()}}))
    return ProfileSet(schema_version=version, digest=set_digest, by_model=by_model)


def load_profiles(path: Path) -> ProfileSet:
    return parse_profiles(parse_json_bounded(read_bounded(path, MAX_PROFILE_BYTES, "profiles"), "profiles"))


def load_salt(path: Path) -> bytes:
    salt = read_bounded(path, MAX_SALT_BYTES, "salt").rstrip(b"\r\n")
    if len(salt) < MIN_SALT_BYTES:
        raise EnrichError("salt_too_short", EXIT_INPUT, f"need at least {MIN_SALT_BYTES} bytes")
    return salt


# ----------------------------------------------------------------------------
# per-entry processing
# ----------------------------------------------------------------------------


def _clean_public(value: Any, kind: str, labels_folded: frozenset) -> tuple:
    """Return ``(clean_value, problem)``; ``problem`` is None, missing, invalid or contains_identifier."""
    if value is None:
        return None, "missing"
    if not isinstance(value, str):
        return None, "invalid"
    text = value.strip()
    if not text:
        return None, "missing"
    if len(text) > MAX_FIELD_CHARS:
        return None, "invalid"
    if identifier_kinds(text):
        return None, "contains_identifier"
    if kind == "text" and text.casefold() in labels_folded:
        return None, "contains_identifier"
    pattern = {"text": _TEXT_RE, "token": _TOKEN_RE}[kind]
    if not pattern.fullmatch(text):
        return None, "invalid"
    return text, None


class _TooComplex(Exception):
    pass


def harvest(entry: Any) -> tuple:
    """Collect private values from a capture entry: ``(identifier_values, label_values)``."""
    ids: set = set()
    labels: set = set()
    stack = [(None, entry, 0)]
    nodes = 0
    while stack:
        key, node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_ENTRY_NODES or depth > MAX_ENTRY_DEPTH:
            raise _TooComplex()
        if isinstance(node, dict):
            stack.extend((k, v, depth + 1) for k, v in node.items())
        elif isinstance(node, list):
            stack.extend((key, v, depth + 1) for v in node)
        elif isinstance(node, str):
            if key in _PUBLIC_KEYS:
                continue
            lowered = (key or "").lower()
            text = node.strip()
            if lowered in _LABEL_KEYS:
                if text:
                    labels.add(text)
            elif lowered == "url" or any(hint in lowered for hint in _ID_KEY_HINTS):
                if text:
                    ids.add(text)
                    host = _URL_HOST_RE.match(text)
                    if host:
                        ids.add(host.group(1))
            else:
                # Real status blocks carry dotted-quad version strings (HardwareVersion
                # is shaped like 1.8.3.7-2.1); IPv4 scanning on version-like keys would
                # mark legitimate public output as a leak. Addresses live under keyed
                # buckets above (url, IPAddress, ...), which harvest the whole value.
                for pattern in _IDENTIFIER_RES:
                    if pattern is _IPV4_RE and "ver" in lowered:
                        continue
                    ids.update(m.group(0) for m in pattern.finditer(text))
    return ids, labels


@dataclass
class _Context:
    idn: Any
    pseud: Any
    source: Any
    nominal_unit: Optional[str]


@dataclass
class _Processed:
    index: int
    record: dict
    device_token: Optional[str]  # keyed pseudonym of the canonical serial; None when no usable serial
    ids: set


def _identity_block() -> dict:
    return {
        "basis": "model_number_published_hint_only",
        "board_profile_basis": "single_observation_candidate",
        "per_unit_silicon_confirmed": False,
        "binary_or_calibration_selection_eligible": False,
    }


def _published_block(profile: dict) -> dict:
    return {
        "published_profile_id": profile["published_profile_id"],
        "profile_digest": profile["profile_digest"],
        "matched_by": "model_number_exact",
        "evidence_class": "published_model_level",
        "claims": {key: (list(profile[key]) if key == "sources" else profile[key]) for key in (*_CLAIM_KEYS, "sources")},
    }


def _new_record() -> dict:
    return {
        "schema": RECORD_SCHEMA,
        "status": "invalid",
        "reason_codes": [],
        "identity_findings": [],
        "model_number": None,
        "board_profile_id": None,
        "device_reported": None,
        "published_profile": None,
        "identity": _identity_block(),
    }


def _invalid(index: int, code: str, ids: Optional[set] = None) -> _Processed:
    record = _new_record()
    record["reason_codes"] = [code]
    return _Processed(index, record, None, ids or set())


def _finding_reason(finding: Any) -> str:
    """Map a shared-module finding to this tool's reason suffix."""
    if finding.code == "ABSENT_IN_SOURCE":
        return "missing"
    if finding.code == "UNIT_UNKNOWN":  # the shared normalizer reports this only for an otherwise valid number
        return "unit_unknown"
    return "invalid"


def process_entry(index: int, entry: Any, profiles: ProfileSet, ctx: _Context) -> _Processed:
    if not isinstance(entry, dict):
        return _invalid(index, "entry_not_an_object")
    try:
        ids, labels = harvest(entry)
    except _TooComplex:
        return _invalid(index, "entry_too_complex")
    fields = entry.get("fields")
    if not isinstance(fields, dict):
        return _invalid(index, "scan_error_row" if "error" in entry else "fields_missing", ids)

    raw_model = fields.get("modelNumber")
    if raw_model is None or (isinstance(raw_model, str) and not raw_model.strip()):
        return _invalid(index, "model_number_missing", ids)
    model = raw_model.strip() if isinstance(raw_model, str) else None
    if model is None or not _TOKEN_RE.fullmatch(model) or identifier_kinds(model):
        return _invalid(index, "model_number_invalid", ids)

    idn = ctx.idn
    reasons: set = set()
    raw_serial = fields.get("serialNum")
    token = None
    if not isinstance(raw_serial, str) or not raw_serial.strip():
        reasons.add("serial_missing")
    else:
        try:
            token = ctx.pseud.device(raw_serial)
        except idn.IdentityError:
            reasons.add("serial_invalid")
    status_map = entry.get("status") if isinstance(entry.get("status"), dict) else {}
    # normalize_record cannot key a record without a usable serial; a run-index placeholder
    # keeps every other field normalizable. It is internal only and never emitted.
    rec = {"url": entry.get("url"), "fields": dict(fields, serialNum=raw_serial if token else f"enrich-record-{index}"), "status": status_map}
    try:
        norm = idn.normalize_record(rec, ctx.source, ctx.pseud, memory_unit=ctx.nominal_unit)
    except idn.IdentityError:
        return _invalid(index, "identity_record_rejected", ids)

    claims: dict = defaultdict(list)
    for claim in norm.claims:
        claims[claim.field].append(claim)
    findings: dict = defaultdict(list)
    for finding in norm.findings:
        findings[finding.field].append(finding)
    if not claims["product_model"]:
        return _invalid(index, "model_number_invalid", ids)
    product_model = claims["product_model"][0].value

    labels_folded = frozenset(label.casefold() for label in labels)
    reported: dict = {"product_model": product_model}
    for prefix, out_key, xml_key, kind in _TEXT_SPECS:
        value, problem = _clean_public(fields.get(xml_key), kind, labels_folded)
        reported[out_key] = value
        if problem:
            reasons.add(f"{prefix}_{problem}")

    for field_name in ("hardware_revision", "software_build"):
        values = {c.value for c in claims[field_name]}  # single origin each, so at most one value
        reported[field_name] = next(iter(values), None)
        if not values:
            suffix = _finding_reason(findings[field_name][0]) if findings[field_name] else "missing"
            reasons.add(f"{_IDENTITY_PREFIX[field_name]}_{suffix}")

    generations = {c.value for c in claims["software_generation"]}
    bad_generation = [f for f in findings["software_generation"] if f.code != "ABSENT_IN_SOURCE"]
    generation = None
    if bad_generation:
        reasons.add("software_generation_invalid")
    elif len(generations) > 1:
        reasons.add("software_generation_conflict")
    elif generations:
        generation = next(iter(generations))
    reported["software_generation"] = generation

    for field_name, out_key in (("nominal_ram_bytes", "nominal_ram"), ("nominal_flash_bytes", "nominal_flash")):
        prefix = _IDENTITY_PREFIX[field_name]
        block = {"reported_number": None, "unit": None, "unit_basis": "unknown", "bytes": None}
        if claims[field_name]:
            # The shared normalizer records who supplied the unit: the source text itself
            # ("128 MB" -> :src-MB, the device's own word) or the operator for a bare number (:op-MB).
            claim = claims[field_name][0]
            origin = _SIZE_ORIGIN_RE.search(claim.origin)
            if origin is None or origin.group(2) not in idn.UNIT_FACTORS:
                reasons.add(f"{prefix}_invalid")  # unit provenance cannot be established: fail closed, keep no bytes
            else:
                unit = origin.group(2)
                basis = "device_stated" if origin.group(1) == "src" else "operator_asserted"
                block.update(reported_number=claim.value // idn.UNIT_FACTORS[unit], unit=unit, unit_basis=basis, bytes=claim.value)
        elif findings[field_name]:
            finding = findings[field_name][0]
            reasons.add(f"{prefix}_{_finding_reason(finding)}")
            if _finding_reason(finding) == "unit_unknown":
                block["reported_number"] = finding.detail.get("number")
        else:
            reasons.add(f"{prefix}_missing")
        reported[out_key] = block
    reported["evidence_class"] = "device_self_report"
    reported["note"] = "values as self-reported by the unit; nominal sizes carry no unit in the source XML, so a unit appears only when the operator asserts it; measured availability unverified"

    board_profile_id = None
    if reported["hardware_revision"] is not None:
        try:
            board_profile_id = idn.profile_id_for(product_model, reported["hardware_revision"])
        except idn.IdentityError:
            return _invalid(index, "identity_record_rejected", ids)

    record = _new_record()
    record["model_number"] = model
    record["board_profile_id"] = board_profile_id
    record["device_reported"] = reported
    record["identity_findings"] = sorted(
        ({"field": f.field, "code": f.code, "origin": f.detail.get("origin")} for fs in findings.values() for f in fs),
        key=lambda d: (d["field"], d["code"], d["origin"] or ""),
    )
    profile = profiles.by_model.get(model)
    if profile is None:
        reasons.add("no_published_profile_for_model")
        record["status"] = "unknown_model"
    else:
        record["published_profile"] = _published_block(profile)
        record["status"] = "enriched_incomplete" if reasons else "enriched"
    record["reason_codes"] = sorted(reasons)
    return _Processed(index, record, token, ids)


# ----------------------------------------------------------------------------
# document-level enrichment
# ----------------------------------------------------------------------------


@dataclass
class Enriched:
    output: dict
    ee_records: list
    annotated: dict
    private_ids: set
    counts: dict
    reason_histogram: Counter


def _valid_observed_at(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not 10 <= len(value) <= 64:
        return None
    try:
        datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return None
    return value


def enrich_document(doc: Any, profiles: ProfileSet, salt: Optional[bytes] = None, input_sha256: Optional[str] = None, nominal_unit: Optional[str] = None) -> Enriched:
    if not isinstance(doc, dict):
        raise EnrichError("devices_bad_shape")
    entries = doc.get("devices")
    if not isinstance(entries, list):
        raise EnrichError("devices_bad_shape")
    if not entries:
        raise EnrichError("devices_empty")
    if len(entries) > MAX_DEVICES:
        raise EnrichError("devices_too_many", EXIT_INPUT, f"limit {MAX_DEVICES}")
    if nominal_unit is not None and nominal_unit not in NOMINAL_UNITS:
        raise EnrichError("nominal_unit_invalid", EXIT_USAGE, f"choose one of {', '.join(NOMINAL_UNITS)}")

    idn = _identity()
    try:
        pseud = idn.Pseudonymizer(salt if salt is not None else os.urandom(32))
        ctx = _Context(idn, pseud, idn.Source("enrich-capture", "live_description"), nominal_unit)
    except idn.IdentityError as exc:
        raise EnrichError("identity_setup_rejected", EXIT_INPUT, exc.code) from None
    processed = [process_entry(i, entry, profiles, ctx) for i, entry in enumerate(entries)]

    token_counts = Counter(p.device_token for p in processed if p.device_token)
    for p in processed:
        if p.device_token and token_counts[p.device_token] > 1:
            p.record["status"] = "ambiguous"
            p.record["published_profile"] = None
            p.record["board_profile_id"] = None
            p.record["reason_codes"] = sorted(set(p.record["reason_codes"]) | {"duplicate_serial_in_input"})

    # Deterministic order independent of input order; refs assigned afterwards.
    ordered = sorted(processed, key=lambda p: _canon(p.record))
    local_rank = 0
    ref_seen: Counter = Counter()
    for p in ordered:
        if salt is not None and p.device_token:
            ref, scope = p.device_token, "salted_stable"
        else:
            local_rank += 1
            ref, scope = f"local-{local_rank:04d}", "run_local"
        ref_seen[ref] += 1
        if ref_seen[ref] > 1:
            ref = f"{ref}+dup{ref_seen[ref] - 1}"
        p.record["device_ref"] = ref
        p.record["device_ref_scope"] = scope

    counts = {"devices_in_input": len(processed)}
    counts.update({status: 0 for status in STATUSES})
    reason_histogram: Counter = Counter()
    for p in processed:
        counts[p.record["status"]] += 1
        reason_histogram.update(p.record["reason_codes"])

    records = sorted((p.record for p in ordered), key=lambda r: r["device_ref"])
    notes = []
    observed_at = _valid_observed_at(doc.get("observed_at"))
    if observed_at is None:
        notes.append("observed_at_missing_or_invalid")
    output = {
        "schema": OUTPUT_SCHEMA,
        "tool": TOOL,
        "observed_at": observed_at,
        "notes": notes,
        "input_sha256": input_sha256,
        "nominal_unit": {"value": nominal_unit, "basis": "operator_asserted" if nominal_unit else "unknown"},
        "profile_set": {"schema_version": profiles.schema_version, "set_digest": profiles.digest, "models": sorted(profiles.by_model)},
        "denominator": counts,
        "devices": records,
    }

    source = f"ffw-enrich://input-{(input_sha256 or 'unknown')[:10]}/profiles-{profiles.digest[:10]}"
    ee_records = []
    for record in records:
        if record["status"] not in ("enriched", "enriched_incomplete"):
            continue
        compact = {key: record[key] for key in ("device_ref", "device_ref_scope", "status", "reason_codes", "model_number", "board_profile_id", "device_reported", "published_profile", "identity")}
        ee_records.append(
            {
                "content": "Sonos device, sanitized; published model-level profile, per-unit silicon NOT confirmed: " + json.dumps(compact, sort_keys=True, separators=(",", ":")),
                "level": "semantic",
                "kind": "fact",
                "tags": ["sonos", "hardware-inventory", record["model_number"].lower(), "published-profile"],
                "source": source,
            }
        )

    annotated = copy.deepcopy(doc)
    for p in processed:
        if p.record["published_profile"] is None:
            continue
        block = p.record["published_profile"]
        annotated["devices"][p.index]["published_hardware_profile"] = {
            "published_profile_id": block["published_profile_id"],
            "profile_digest": block["profile_digest"],
            "evidence_class": block["evidence_class"],
            "per_unit_silicon_confirmed": False,
            **block["claims"],
        }
    annotated["enrichment"] = {"tool": TOOL, "profile_set_digest": profiles.digest}
    annotated["contains_private_identifiers"] = True

    private_ids = set().union(*(p.ids for p in processed))
    return Enriched(output, ee_records, annotated, private_ids, counts, reason_histogram)


# ----------------------------------------------------------------------------
# leak gates
# ----------------------------------------------------------------------------


def find_leaks(artifacts: list, private_ids: set) -> int:
    """Count harvested private values present verbatim in any serialized artifact (values are never returned)."""
    texts = []
    for artifact in artifacts:
        texts.append(json.dumps(artifact, sort_keys=True, ensure_ascii=False))
        texts.append(json.dumps(artifact, sort_keys=True, ensure_ascii=True))
    leaks = 0
    for value in private_ids:
        if len(value) < MIN_LEAK_CHECK_CHARS:
            continue
        escaped = json.dumps(value)[1:-1]
        if any(value in text or escaped in text for text in texts):
            leaks += 1
    return leaks


def shared_guard_findings(structured: Any, private_ids: set) -> int:
    """Findings from the shared ``identity.find_private_identifiers`` scan (generic identifier
    patterns plus separator/case-insensitive canaries) over structured output. This tool's
    own digest keys are declared to the scanner, which applies the format check."""
    canaries = sorted(v for v in private_ids if len(v) >= MIN_LEAK_CHECK_CHARS)
    return len(_identity().find_private_identifiers(structured, canaries=canaries, digest_keys=sorted(_DIGEST_KEYS)))


# ----------------------------------------------------------------------------
# outputs
# ----------------------------------------------------------------------------


def looks_private_ignored(path: Path) -> bool:
    """True when ``path`` matches the repo's git-ignore conventions for private captures."""
    name = path.name
    if name == "devices.json" or name.endswith(".local.json"):
        return True
    return ".local-real" in path.resolve().parts


def _discard_staged(staged: list) -> None:
    """Remove the temp files this run created and has not yet renamed into place."""
    for entry in staged:
        if entry[2] is not None:
            try:
                os.unlink(entry[2])
            except OSError:
                pass
            entry[2] = None


def publish_outputs(planned: list, payloads: dict, written: list) -> None:
    """Publish every output in two phases so an interrupted or failed run cannot half-publish.

    Phase 1 stages each payload in a temp file beside its destination and fsyncs it. Any
    failure or interruption here removes every temp file and leaves all destinations exactly
    as they were. Phase 2 renames each staged file into place (each rename is atomic);
    ``written`` receives the labels already renamed, so a failure or interruption in this
    short window can leave a mix of new and old files, which is reported and which a rerun
    repairs because the output is deterministic. A hard kill (SIGKILL, power loss) can leave
    a stale ``.enrich-*.tmp``; it is never read and never replaces an output.
    """
    staged: list = []  # [label, destination, temp-or-None]
    try:
        for label, path, mode in planned:
            fd, tmp = tempfile.mkstemp(prefix=".enrich-", suffix=".tmp", dir=str(path.parent))
            staged.append([label, path, tmp])
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(payloads[label])
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, mode)
        for entry in staged:
            os.replace(entry[2], entry[1])
            entry[2] = None
            written.append(entry[0])
    except BaseException:
        _discard_staged(staged)
        raise


def _raise_interrupt(_signum, _frame):
    raise KeyboardInterrupt


def _install_term_handler():
    """Map SIGTERM to the same cleanup path as Ctrl-C; returns the previous handler, or None if unavailable."""
    try:
        return signal.signal(signal.SIGTERM, _raise_interrupt)
    except (ValueError, OSError, AttributeError):  # not the main thread, or no SIGTERM on this platform
        return None


def _json_text(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _jsonl_text(records: list) -> str:
    return "".join(json.dumps(r, sort_keys=True, ensure_ascii=True) + "\n" for r in records)


def _plan_outputs(args: argparse.Namespace) -> list:
    """Validate every requested output before reading or computing anything."""
    planned = []  # (label, path, mode)
    for label, path, mode in (("out", args.out, 0o644), ("ee_records_out", args.ee_records_out, 0o644), ("private_annotated_out", args.private_annotated_out, 0o600)):
        if path is None:
            continue
        if label == "private_annotated_out" and not looks_private_ignored(path):
            raise EnrichError("private_output_path_not_git_ignored", EXIT_OUTPUT, "name it devices.json, *.local.json or place it under .local-real/")
        if not path.parent.is_dir():
            raise EnrichError("output_directory_missing", EXIT_OUTPUT, label)
        planned.append((label, path, mode))
    real = [os.path.realpath(p) for _, p, _ in planned]
    if len(set(real)) != len(real):
        raise EnrichError("output_paths_collide", EXIT_OUTPUT)
    protected = {os.path.realpath(p) for p in (args.devices, args.profiles, args.salt_file) if p is not None}
    if protected & set(real):
        raise EnrichError("output_would_overwrite_input", EXIT_OUTPUT)
    return planned


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="enrich.py",
        description="Offline: enrich a private device capture with published hardware profiles and emit sanitized, deterministic output.",
        allow_abbrev=False,
    )
    p.add_argument("--devices", type=Path, help="private capture JSON (scan.py output); read-only")
    p.add_argument("--profiles", type=Path, default=DEFAULT_PROFILES, help="published profile document (legacy or versioned); read-only. Default: hardware-profiles.json next to this script")
    p.add_argument("--salt-file", type=Path, help="file with >=16 secret bytes; enables stable keyed device_ref pseudonyms (identity.Pseudonymizer)")
    p.add_argument("--nominal-unit", choices=NOMINAL_UNITS, help="unit to ASSERT for the bare memory/flash numbers; the device XML carries none. Recorded as operator_asserted")
    p.add_argument("--out", type=Path, help="write sanitized enriched inventory JSON here")
    p.add_argument("--ee-records-out", type=Path, help="write sanitized ee memory records (JSONL) here")
    p.add_argument("--private-annotated-out", type=Path, help="write a PRIVATE copy of the capture annotated with profiles; the name must be git-ignored (devices.json, *.local.json, .local-real/)")
    p.add_argument("--check-profiles", action="store_true", help="validate the profile document and print its digest; --devices optional")
    p.add_argument("--dry-run", action="store_true", help="process and summarize but write nothing")
    return p


def _run(args: argparse.Namespace, out, err) -> int:
    profiles = load_profiles(args.profiles)
    print(f"enrich: profiles schema_version={profiles.schema_version} digest={profiles.digest[:12]} models={len(profiles.by_model)}", file=out)
    if args.devices is None:
        return EXIT_OK

    planned = [] if args.dry_run else _plan_outputs(args)
    salt = load_salt(args.salt_file) if args.salt_file else None
    data = read_bounded(args.devices, MAX_INPUT_BYTES, "devices")
    result = enrich_document(parse_json_bounded(data, "devices"), profiles, salt, _sha256(data), args.nominal_unit)

    sanitized_structured = [result.output] + [{k: v for k, v in rec.items() if k != "content"} for rec in result.ee_records]
    exact = find_leaks([result.output, result.ee_records], result.private_ids)
    shared = shared_guard_findings(sanitized_structured, result.private_ids)
    if exact or shared:
        raise EnrichError("sanitized_output_would_leak_private_value", EXIT_LEAK, f"{exact} exact + {shared} scanner finding(s); nothing written")

    c = result.counts
    print("enrich: devices={devices_in_input} ".format(**c) + " ".join(f"{s}={c[s]}" for s in STATUSES), file=out)
    if result.reason_histogram:
        print("enrich: reason_codes " + " ".join(f"{k}={v}" for k, v in sorted(result.reason_histogram.items())), file=out)

    if args.dry_run:
        print("enrich: dry-run, nothing written", file=out)
    else:
        payloads = {"out": _json_text(result.output), "ee_records_out": _jsonl_text(result.ee_records), "private_annotated_out": _json_text(result.annotated)}
        written: list = []
        try:
            publish_outputs(planned, payloads, written)
        except OSError as exc:
            raise EnrichError("output_write_failed", EXIT_OUTPUT, f"{exc.strerror}; already renamed into place: {', '.join(written) or 'none'}") from None
        except KeyboardInterrupt:
            raise EnrichError("interrupted", EXIT_INTERRUPT, f"no temporary file left; already renamed into place: {', '.join(written) or 'none'}; rerun to repair") from None
        for label in written:
            print(f"enrich: wrote {label}", file=out)
    if c["enriched"] != c["devices_in_input"]:
        print("enrich: not every device is fully enriched; see reason_codes in the output", file=err)
        return EXIT_PARTIAL
    return EXIT_OK


def main(argv=None, stdout=None, stderr=None) -> int:
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
        if args.devices is None and not args.check_profiles:
            parser.error("--devices is required (or use --check-profiles)")
        if args.devices is not None and not args.dry_run and not (args.out or args.ee_records_out or args.private_annotated_out):
            parser.error("no output requested: use --out, --ee-records-out, --private-annotated-out or --dry-run")
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    previous_term = _install_term_handler()
    try:
        return _run(args, out, err)
    except EnrichError as exc:
        print(f"enrich: error: {exc.code}" + (f": {exc.detail}" if exc.detail else ""), file=err)
        return exc.exit_code
    except KeyboardInterrupt:  # before the publish phase: nothing had been written
        print("enrich: error: interrupted: nothing was written", file=err)
        return EXIT_INTERRUPT
    finally:
        if previous_term is not None:
            signal.signal(signal.SIGTERM, previous_term)


if __name__ == "__main__":
    sys.exit(main())
