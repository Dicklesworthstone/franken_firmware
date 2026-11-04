#!/usr/bin/env python3
"""E01 offline device/firmware identity reconciliation (bead ffw-xdi).

Explicit, offline, deterministic CLI.  Nothing happens at import time: no file
is read or written and no socket is opened (the module does not import any
network library).  Inputs are named on the command line; they are never
modified, and no device is ever contacted.

    python3 inventory/reconcile.py --input BATCH.json [--input ...] \
        [--evidence image-evidence.json] [--hypotheses hardware-profiles.json] \
        [--nominal-unit MB|MiB] [--format json|md] [--out PATH] \
        [--private-out PATH] [--overwrite] [--allow-incomplete]

What it does
------------
* Parses observation batches (scan.py/enrich.py-shaped JSON, or a raw
  ``device_description.xml``) into observations.
* Merges observations into devices using strong identifiers (serial, MAC, UDN)
  with union-find, so duplicates, renamed devices and address-changed devices
  collapse to one device while identifier collisions stay visible as conflicts.
* Groups devices into board-profile entries keyed on model, hardware revision,
  nominal resources and firmware line.  ISA/ABI/image-digest come ONLY from
  declarative image-evidence records whose join to ``modelNumber`` is attested;
  nothing is ever derived from product era or a published teardown.
* Emits a sanitized public manifest by default.  Per-device identifiers exist
  only in the optional ``--private-out`` report, which must live in a
  git-ignored location.  A leak guard rejects any public document that
  contains a value seen in the private input.

Exit codes: 0 everything resolved, 2 usage/input error, 3 incomplete (anything unresolved,
conflicted or unattributed; the manifest is still written; --allow-incomplete turns this into 0),
4 leak guard tripped, 5 output refused, 70 internal error, 130 interrupted.
Error text never echoes input values.
"""
from __future__ import annotations

import argparse
import collections
import datetime as _dt
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
import traceback
import xml.etree.ElementTree as ET
from pathlib import Path

TOOL_NAME = "inventory/reconcile.py"
TOOL_VERSION = "1"
MANIFEST_SCHEMA = "ffw.e01.profile-manifest.v1"
PRIVATE_SCHEMA = "ffw.e01.private-report.v1"
EVIDENCE_SCHEMA = "ffw.e01.image-evidence.v1"
REASONS_SCHEMA = "ffw.e01.reason-codes.v1"

EXIT_OK, EXIT_USAGE, EXIT_INCOMPLETE, EXIT_LEAK, EXIT_OUTPUT = 0, 2, 3, 4, 5
EXIT_INTERNAL, EXIT_INTERRUPT = 70, 130

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_RECORDS_PER_BATCH = 4096
MAX_BATCHES = 256
MAX_VALUE_LEN = 1024
MAX_KEYS_PER_MAP = 512

# severity: "conflict" (contradiction), "blocking" (insufficient evidence), "info".
REASONS = {
    "identity_ambiguous": ("conflict", "Strong identifiers (serial, MAC, UDN) link observations that disagree on another identifier; the group is not counted as a device."),
    "identity_unidentifiable": ("blocking", "Observation has no usable strong identifier and cannot be attributed to a device."),
    "hardware_field_conflict": ("conflict", "Observations of one device disagree on an immutable hardware field."),
    "firmware_unordered_conflict": ("conflict", "Observations of one device disagree on a firmware field and cannot be ordered by observed_at."),
    "isa_evidence_conflict": ("conflict", "Matched image-evidence records contradict each other on ISA, ABI or atomic widths."),
    "image_digest_conflict": ("conflict", "One image name carries different digests in the matched evidence."),
    "model_absent": ("blocking", "modelNumber is absent."),
    "hardware_revision_absent": ("blocking", "hardwareVersion is absent; a model alone cannot select a board."),
    "hardware_field_malformed": ("blocking", "A public-bound hardware field is not a short plain token."),
    "firmware_line_unknown": ("blocking", "softwareVersion is absent or not <major>.<minor>-<build>."),
    "nominal_size_absent": ("blocking", "Nominal memory or flash is absent."),
    "nominal_size_unit_unknown": ("blocking", "Nominal size has no unit (bare number) or an unrecognised unit; declare one with --nominal-unit only if it is known."),
    "nominal_size_invalid": ("blocking", "Nominal size is not a positive whole number."),
    "isa_evidence_absent": ("blocking", "No image-evidence record exists for this model."),
    "isa_evidence_join_unattested": ("blocking", "Evidence exists for this model but its join to modelNumber is not attested (image-verified or owner-attested)."),
    "isa_evidence_firmware_line_mismatch": ("blocking", "Attested evidence exists for this model but not for this firmware line."),
    "isa_evidence_revision_mismatch": ("blocking", "Attested evidence exists for this model/firmware line but not this hardware revision."),
    "image_digest_absent": ("blocking", "Matched evidence records no image digest."),
    "abi_not_recorded": ("blocking", "Matched evidence does not record an ABI."),
    "float_abi_not_recorded": ("info", "Matched evidence does not record a float ABI."),
    "atomic_widths_not_recorded": ("info", "Matched evidence does not record required atomic widths."),
    "identity_serial_absent": ("info", "Device was identified without a serial number."),
    "identity_mac_malformed": ("info", "A MACAddress value was malformed and ignored for identity."),
    "record_malformed": ("info", "A record was malformed and skipped."),
    "record_error_only": ("info", "A record carried only a scan error and was skipped."),
    "observed_at_invalid": ("info", "observed_at was not an ISO-8601 timestamp with a timezone."),
    "duplicate_batch_ignored": ("info", "An identical batch was supplied more than once; extra copies were ignored."),
    "evidence_unjoined": ("info", "An evidence record has no model join and cannot be matched to any device."),
}
ACCEPTED_JOIN_BASES = ("image-verified", "owner-attested")
ALL_JOIN_BASES = ACCEPTED_JOIN_BASES + ("name-inferred", "unmapped")
MACHINES = ("mips", "powerpc", "arm", "aarch64", "x86", "x86_64", "riscv")

# Logical field -> (device_description key, status/zp key).
TEXT_FIELDS = (
    ("model_number", "modelNumber", None),
    ("model_name", "modelName", None),
    ("series_id", "seriesid", "SeriesID"),
    ("variant", "variant", "Variant"),
    ("hardware_revision", "hardwareVersion", "HardwareVersion"),
)
SIZE_FIELDS = (("memory", "memory", None), ("flash", "flash", None))
DATED_FIELDS = (("software_version", "softwareVersion", "SoftwareVersion"), ("sw_gen", "swGen", "SWGen"))
KEY_ORDER = ("model_number", "model_name", "series_id", "variant", "hardware_revision",
             "memory", "flash", "firmware_line", "sw_gen")
PROVENANCE_ORDER = ("model_number", "model_name", "series_id", "variant", "hardware_revision",
                    "memory", "flash", "software_version", "sw_gen")

KNOWN_FIELD_KEYS = frozenset(
    ["serialNum", "MACAddress", "UDN", "deviceID", "roomName", "friendlyName"]
    + [f for _, f, _ in TEXT_FIELDS + SIZE_FIELDS + DATED_FIELDS])
KNOWN_STATUS_KEYS = frozenset(
    ["SerialNumber", "MACAddress", "IPAddress", "HouseholdControlID", "LocalUID", "ZoneName"]
    + [s for _, _, s in TEXT_FIELDS + SIZE_FIELDS + DATED_FIELDS if s])
# Private-value classification (case-insensitive key names).
_IDENT_KEYS = frozenset(k.lower() for k in (
    "serialNum", "SerialNumber", "MACAddress", "UDN", "deviceID", "IPAddress",
    "HouseholdControlID", "LocalUID", "LocationId", "HouseholdID"))
_NAME_KEYS = frozenset(k.lower() for k in ("roomName", "friendlyName", "ZoneName"))

_BAD = "\x00bad"  # sentinel for a value identity.py rejected (compares unequal to every canonical value)
CANONICAL_FIELDS = {"model_number": "product_model", "hardware_revision": "hardware_revision"}
DATED_CANONICAL = {"software_version": "software_build", "sw_gen": "software_generation"}
_TEXT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:+/()\-]{0,63}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}$")
_FWLINE_RE = re.compile(r"^(\d{1,4})\.(\d{1,4})-(\d{1,9})$")
_FWLINE_ONLY_RE = re.compile(r"^\d{1,4}\.\d{1,4}$")
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(?:[:\-.]?[0-9A-Fa-f]{2}){5}$")
_UDN_RE = re.compile(r"^(?:uuid:)?(RINCON_[0-9A-F]+)(?:_[A-Z]{1,3})?$", re.I)
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVID_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")

# Backstop patterns for the public leak guard.
_LEAK_PATTERNS = (
    ("ipv4", re.compile(r"(?<![\w.\-])(?:\d{1,3}\.){3}\d{1,3}(?![\w\-]|\.\d)")),
    ("mac", re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f])")),
    ("rincon", re.compile(r"RINCON_[0-9A-Fa-f]{6,}", re.I)),
    ("uuid", re.compile(r"\buuid:", re.I)),
    ("url", re.compile(r"\b[a-z][a-z0-9+.\-]*://", re.I)),
    ("abs_path", re.compile(r"(?:^|\s)(?:/Users/|/home/|[A-Za-z]:\\)")),
)


# --------------------------------------------------------------------------- errors
class E01Error(Exception):
    exit_code = EXIT_USAGE

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class InputError(E01Error):
    exit_code = EXIT_USAGE


class LeakError(E01Error):
    exit_code = EXIT_LEAK


class OutputError(E01Error):
    exit_code = EXIT_OUTPUT


class _Malformed(Exception):
    pass


# ---------------------------------------------------------------------- primitives
def canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hexdigest(domain: str, obj) -> str:
    return hashlib.sha256((domain + "\n" + canon(obj)).encode("ascii")).hexdigest()


# ------------------------------------------------ shared engines (thin adapters)
# inventory/identity.py owns value normalisation (model, revision, build, generation, nominal
# sizes and their units) and the profile-id formula; inventory/enrich.py owns published-profile
# loading.  They are loaded lazily by path (no sys.path use, nothing runs at import) and a missing
# or broken module is a hard error: there is deliberately no private fallback.
_SHARED = {}


def _sibling(name):
    if name not in _SHARED:
        path = Path(__file__).resolve().with_name(name + ".py")
        modname = "ffw_shared_" + name
        spec = importlib.util.spec_from_file_location(modname, path) if path.is_file() else None
        if spec is None or spec.loader is None:
            raise InputError("shared_module_missing", f"required sibling module {name}.py is missing")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[modname] = mod
        try:
            spec.loader.exec_module(mod)
        except Exception:
            sys.modules.pop(modname, None)
            raise InputError("shared_module_unusable", f"sibling module {name}.py failed to load")
        _SHARED[name] = mod
    return _SHARED[name]


def _norm(field, raw, unit=None):
    """Strictly normalise one value with identity.make_claim: ('ok', canonical) | ('err', reason_code)."""
    idm = _sibling("identity")
    if "claim_ctx" not in _SHARED:
        _SHARED["claim_ctx"] = (idm.Subject.device("dev-" + "0" * 20), idm.Source("live:e01-reconcile", "live_description"))
    subject, source = _SHARED["claim_ctx"]
    try:
        return "ok", idm.make_claim(subject, field, raw, source, unit=unit).value
    except idm.IdentityError as e:
        return "err", e.code


def profile_id_for(model_number, hardware_revision):
    """bp-<16 hex> from identity.profile_id_for (the single shared formula); None unless both resolve."""
    if not model_number or not hardware_revision:
        return None
    idm = _sibling("identity")
    try:
        return idm.profile_id_for(model_number, hardware_revision)
    except idm.IdentityError:
        return None


def _clean(v):
    """Collapse whitespace; None for empty."""
    s = " ".join(str(v).split())
    return s or None


def _parse_ts(v):
    """(datetime|None, valid).  None input is valid-but-absent."""
    if v is None:
        return None, True
    if not isinstance(v, str):
        return None, False
    s = v.strip()
    if s[-1:] in ("Z", "z"):
        s = s[:-1] + "+00:00"
    try:
        d = _dt.datetime.fromisoformat(s)
    except ValueError:
        return None, False
    if d.tzinfo is None:
        return None, False
    return d.astimezone(_dt.timezone.utc), True


def _fmt_ts(d):
    return None if d is None else d.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def norm_serial(v):
    return v.strip().upper() or None


def norm_mac(v):
    v = v.strip()
    if not _MAC_RE.match(v):
        return None
    h = re.sub(r"[^0-9A-Fa-f]", "", v).lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def norm_udn(v):
    v = v.strip()
    m = _UDN_RE.match(v)
    if m:
        return m.group(1).upper()
    return re.sub(r"^uuid:", "", v, flags=re.I).lower() or None


def _stated_unit(raw, factors):
    m = re.search(r"([A-Za-z]+)\s*$", raw)
    return m.group(1) if m and m.group(1) in factors else None


def size_state(logical, raw, declared_unit):
    """-> (state tuple, basis).  Unit rules are identity's: a bare number has no unit unless declared."""
    idm = _sibling("identity")
    field = "nominal_ram_bytes" if logical == "memory" else "nominal_flash_bytes"
    factors = idm.UNIT_FACTORS
    kind, out = _norm(field, raw)  # the unit, if any, must come from the string itself
    if kind == "ok":
        unit = _stated_unit(raw, factors)
        return ("ok", f"{out // factors[unit]} {unit}"), "device_stated"
    if out == idm.R_UNIT_UNKNOWN:
        if declared_unit:
            kind2, out2 = _norm(field, raw, declared_unit)
            if kind2 == "ok":
                return ("ok", f"{out2 // factors[declared_unit]} {declared_unit}"), "operator_asserted"
            return ("invalid",), None
        digits = re.sub(r"\D", "", raw)
        return ("bare", str(int(digits)) if digits else "0"), "unknown"
    if out == idm.R_UNIT_INVALID:
        return ("unit_unknown",), None
    return ("invalid",), None


# ------------------------------------------------------------------------ file I/O
def _read_bounded(path, label: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_INPUT_BYTES + 1)
    except OSError as e:
        raise InputError("input_unreadable", f"{label}: cannot be read ({type(e).__name__})")
    if len(data) > MAX_INPUT_BYTES:
        raise InputError("input_too_large", f"{label}: exceeds {MAX_INPUT_BYTES} bytes")
    return data


def _loads_strict(data: bytes, label: str):
    def no_dupes(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise InputError("input_duplicate_key", f"{label}: duplicate object key")
            d[k] = v
        return d

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=no_dupes)
    except UnicodeDecodeError:
        raise InputError("input_not_json", f"{label}: not valid UTF-8")
    except json.JSONDecodeError as e:
        raise InputError("input_not_json", f"{label}: not valid JSON (offset {e.pos})")
    except (ValueError, RecursionError):
        raise InputError("input_not_json", f"{label}: not parseable JSON")


UPNP_DEVICE_NS = "urn:schemas-upnp-org:device-1-0"
_UPNP_PREFIX = "{" + UPNP_DEVICE_NS + "}"


def parse_description_xml(data: bytes, label: str = "xml") -> dict:
    """The one rule for turning a UPnP ``device_description.xml`` into flat ``fields``.

    * The device is the first ``<device>`` in document order that is in the UPnP device namespace
      (``urn:schemas-upnp-org:device-1-0``, exact match; a default or a prefixed binding both work
      because the parser resolves them).  A ``<device>`` in another namespace, or in none, is never
      used; if those are the only ones the document is refused with ``xml_namespace``.
    * Only that device's direct leaf children in the same namespace become fields.  Children in a
      foreign namespace (or with ``xmlns=""``) are ignored: they are never a field and never a
      duplicate conflict, so a look-alike ``serialNum`` cannot stand in for the real one.
    * Nested devices (the MediaServer/MediaRenderer sub-devices real speakers embed) repeat tags
      such as ``UDN`` with different text; they must never become the unit's value, which is what a
      whole-tree "last wins" scan does.
    * DOCTYPE/ENTITY declarations are refused (no entity expansion), a repeated field with differing
      text is refused, and the input is size-bounded.

    Evidence for refusing un-namespaced documents: on the owner's 17 real description files the root
    and device are in the UPnP namespace 17/17 and all 599 direct leaf fields are too.  Raises
    ``InputError`` with a code and no document content.
    """
    if len(data) > MAX_INPUT_BYTES:
        raise InputError("input_too_large", f"{label}: exceeds {MAX_INPUT_BYTES} bytes")
    if re.search(rb"<!\s*(DOCTYPE|ENTITY)", data, re.I):
        raise InputError("xml_doctype_forbidden", f"{label}: DOCTYPE/ENTITY declarations are refused")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise InputError("xml_parse", f"{label}: XML parse error at {e.position}")
    dev, other_device = None, False
    for el in root.iter():
        if el.tag == _UPNP_PREFIX + "device":
            dev = el
            break
        if el.tag.split("}")[-1] == "device":
            other_device = True
    if dev is None:
        if other_device:
            raise InputError("xml_namespace", f"{label}: <device> is not in the UPnP device namespace")
        raise InputError("xml_shape", f"{label}: no <device> element")
    fields = {}
    for child in dev:
        if len(child) != 0 or not child.tag.startswith(_UPNP_PREFIX):
            continue
        tag = child.tag[len(_UPNP_PREFIX):]
        text = (child.text or "").strip()
        if tag in fields and fields[tag] != text:
            raise InputError("xml_duplicate_field", f"{label}: repeated device field with differing text")
        fields[tag] = text
    return fields


def _xml_to_batch(data: bytes, label: str) -> dict:
    return {"observed_at": None, "devices": [{"fields": parse_description_xml(data, label)}]}


def load_batch_file(path, label: str):
    data = _read_bounded(path, label)
    if data.lstrip()[:1] == b"<":
        return _xml_to_batch(data, label), "xml"
    return _loads_strict(data, label), "json"


# ----------------------------------------------------------------- batch -> records
def _scalar_map(d, known, where: str):
    if not isinstance(d, dict) or len(d) > MAX_KEYS_PER_MAP:
        raise _Malformed
    out = {}
    for k, v in d.items():
        if not isinstance(k, str):
            raise _Malformed
        if k not in known or v is None:
            continue
        if isinstance(v, bool) or not isinstance(v, (str, int, float)):
            raise _Malformed
        s = _clean(v)
        if s is None:
            continue
        if len(s) > MAX_VALUE_LEN:
            raise _Malformed
        out[k] = s
    return out


def _collect_private(rec, ids: set, names: set):
    """Harvest values that must never reach public output (all keys, not only known)."""
    def take(mapping):
        if not isinstance(mapping, dict):
            return
        for k, v in mapping.items():
            if not isinstance(k, str) or isinstance(v, bool) or not isinstance(v, (str, int, float)):
                continue
            s = _clean(v)
            if not s:
                continue
            lk = k.lower()
            if lk in _IDENT_KEYS:
                ids.add(s)
                ids.add(s.lower())
                mac = norm_mac(s) if lk in ("macaddress",) else None
                if mac:
                    ids.add(mac)
                    ids.add(mac.replace(":", ""))
                m = _UDN_RE.match(s)
                if m:
                    ids.add(m.group(1))
            elif lk in _NAME_KEYS:
                names.add(s.lower())

    if not isinstance(rec, dict):
        return
    take(rec.get("fields"))
    take(rec.get("status"))
    url = rec.get("url")
    if isinstance(url, str) and url.strip():
        u = url.strip()
        ids.add(u)
        host = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", u, flags=re.I).split("/", 1)[0]
        if host:
            ids.add(host)
            ids.add(host.rsplit(":", 1)[0] if host.count(":") == 1 else host)


def parse_batch(obj, label: str, batch_id: str, diag, ids: set, names: set):
    """-> list of observation dicts."""
    if not isinstance(obj, dict) or not isinstance(obj.get("devices"), list):
        raise InputError("batch_shape", f"{label}: expected an object with a 'devices' list")
    devices = obj["devices"]
    if len(devices) > MAX_RECORDS_PER_BATCH:
        raise InputError("batch_too_many_records", f"{label}: more than {MAX_RECORDS_PER_BATCH} records")
    top_ts, top_ok = _parse_ts(obj.get("observed_at"))
    if not top_ok:
        diag["observed_at_invalid"] += 1
    out = []
    for i, rec in enumerate(devices):
        _collect_private(rec, ids, names)
        try:
            if not isinstance(rec, dict):
                raise _Malformed
            if "fields" not in rec:
                if "error" in rec:
                    diag["record_error_only"] += 1
                    continue
                raise _Malformed
            fields = _scalar_map(rec["fields"], KNOWN_FIELD_KEYS, "fields")
            raw_status = rec.get("status")
            status = _scalar_map(raw_status if raw_status is not None else {}, KNOWN_STATUS_KEYS, "status")
            url = rec.get("url")
            if url is not None and not isinstance(url, str):
                raise _Malformed
            if rec.get("observed_at") is None:
                ts = top_ts  # record has no timestamp of its own: inherit the batch's
            else:
                ts, ok = _parse_ts(rec["observed_at"])
                if not ok:
                    diag["observed_at_invalid"] += 1
                    ts = None
            out.append({"batch": batch_id, "index": i, "ts": ts, "fields": fields,
                        "status": status, "url": _clean(url) if url else None})
        except _Malformed:
            diag["record_malformed"] += 1
    return out


def load_inputs(paths):
    """-> (observations, batches_meta, diag, private_ids, private_names)."""
    if len(paths) > MAX_BATCHES:
        raise InputError("usage", f"more than {MAX_BATCHES} --input files")
    diag = collections.Counter()
    ids, names = set(), set()
    seen, metas, obs = set(), [], []
    for n, path in enumerate(paths, 1):
        label = f"--input #{n}"
        raw, kind = load_batch_file(path, label)
        bid = _hexdigest("ffw.e01.batch-id.v1", raw)[:12]
        if bid in seen:
            diag["duplicate_batch_ignored"] += 1
            continue
        seen.add(bid)
        parsed = parse_batch(raw, label, bid, diag, ids, names)
        ts, _ = _parse_ts(raw.get("observed_at")) if isinstance(raw, dict) else (None, True)
        metas.append({"batch_id": bid, "kind": kind, "records": len(raw["devices"]),
                      "observed_at": _fmt_ts(ts)})
        obs.extend(parsed)
    metas.sort(key=lambda m: m["batch_id"])
    return obs, metas, diag, ids, names


# --------------------------------------------------------------- evidence registry
def _validate_evidence(rec, idx: int) -> dict:
    def bad(msg):
        raise InputError("registry_invalid", f"evidence record {idx}: {msg}")

    if not isinstance(rec, dict):
        bad("not an object")
    eid = rec.get("evidence_id")
    if not isinstance(eid, str) or not _EVID_ID_RE.match(eid):
        bad("evidence_id missing or malformed")
    join = rec.get("join")
    if not isinstance(join, dict):
        bad("join missing")
    basis = join.get("join_basis")
    if basis not in ALL_JOIN_BASES:
        bad("join_basis not recognised")
    model = join.get("model_number")
    if model is not None:
        kind, canon_model = _norm("product_model", model) if isinstance(model, str) else ("err", None)
        if kind != "ok":
            bad("join.model_number malformed")
        model = canon_model
    if model is None and basis != "unmapped":
        bad("join.model_number required unless join_basis is 'unmapped'")
    fls = rec.get("firmware_lines")
    if not isinstance(fls, list) or not fls or not all(isinstance(x, str) and _FWLINE_ONLY_RE.match(x) for x in fls):
        bad("firmware_lines must be a non-empty list of '<major>.<minor>'")
    revs = rec.get("hardware_revisions")
    if revs is not None:
        if not isinstance(revs, list) or not revs or not all(isinstance(x, str) for x in revs):
            bad("hardware_revisions must be a non-empty list of revisions when present")
        canon_revs = [_norm("hardware_revision", x) for x in revs]
        if any(k != "ok" for k, _ in canon_revs):
            bad("hardware_revisions contains a malformed revision")
        revs = [v for _, v in canon_revs]
    claim = rec.get("claim")
    if not isinstance(claim, dict):
        bad("claim missing")
    if claim.get("machine") not in MACHINES:
        bad("claim.machine not recognised")
    if claim.get("elf_class") not in (32, 64) or isinstance(claim.get("elf_class"), bool):
        bad("claim.elf_class must be 32 or 64")
    if claim.get("endianness") not in ("big", "little"):
        bad("claim.endianness must be big or little")
    for opt in ("abi", "float_abi"):
        v = claim.get(opt)
        if v is not None and (not isinstance(v, str) or not _TOKEN_RE.match(v)):
            bad(f"claim.{opt} malformed")
    aw = claim.get("atomic_widths")
    if aw is not None:
        if not isinstance(aw, list) or not aw or not all(type(x) is int and x in (8, 16, 32, 64) for x in aw):
            bad("claim.atomic_widths must be a non-empty list drawn from 8,16,32,64")
        aw = sorted(set(aw))
    image = rec.get("image")
    if not isinstance(image, dict) or not isinstance(image.get("name"), str) or not _TOKEN_RE.match(image["name"]):
        bad("image.name missing or malformed")
    digest = image.get("digest")
    if digest is not None and (not isinstance(digest, str) or not _DIGEST_RE.match(digest)):
        bad("image.digest must be null or 'sha256:<64 lowercase hex>'")
    prov = rec.get("provenance")
    if not isinstance(prov, dict) or not isinstance(prov.get("source"), str) or not isinstance(prov.get("basis"), str):
        bad("provenance.source and provenance.basis are required")
    for s in (prov["source"], prov["basis"]):
        if len(s) > 300 or any(p.search(s) for _, p in _LEAK_PATTERNS):
            bad("provenance text is too long or looks like a URL/path/address")
    return {
        "id": eid,
        "join": {"model_number": model, "join_basis": basis},
        "firmware_lines": sorted(set(fls)),
        "hardware_revisions": None if revs is None else sorted(set(revs)),
        "isa": (claim["machine"], claim["elf_class"], claim["endianness"]),
        "abi": claim.get("abi"),
        "float_abi": claim.get("float_abi"),
        "atomic_widths": aw,
        "image": {"name": image["name"], "digest": digest[len("sha256:"):] if digest else None},
        "provenance": {"source": prov["source"], "basis": prov["basis"]},
    }


def load_registry(paths):
    """-> registry dict {records, contradicted:set(ids)}, diag Counter."""
    diag = collections.Counter()
    records, seen = [], set()
    for n, path in enumerate(paths, 1):
        label = f"--evidence #{n}"
        obj = _loads_strict(_read_bounded(path, label), label)
        if not isinstance(obj, dict) or obj.get("schema") != EVIDENCE_SCHEMA or not isinstance(obj.get("records"), list):
            raise InputError("registry_invalid", f"{label}: expected schema {EVIDENCE_SCHEMA} with a 'records' list")
        if len(obj["records"]) > MAX_RECORDS_PER_BATCH:
            raise InputError("registry_invalid", f"{label}: too many records")
        for i, rec in enumerate(obj["records"]):
            r = _validate_evidence(rec, i)
            if r["id"] in seen:
                raise InputError("registry_invalid", f"{label}: duplicate evidence_id across registry")
            seen.add(r["id"])
            records.append(r)
    records.sort(key=lambda r: r["id"])
    by_digest = collections.defaultdict(list)
    for r in records:
        if r["join"]["model_number"] is None:
            diag["evidence_unjoined"] += 1
        if r["image"]["digest"]:
            by_digest[r["image"]["digest"]].append(r)
    contradicted = set()
    for group in by_digest.values():
        if len({g["isa"] for g in group}) > 1:
            contradicted.update(g["id"] for g in group)
            diag["isa_evidence_conflict"] += 1
    return {"records": records, "contradicted": contradicted}, diag


def load_hypotheses(path):
    """Published-hardware notes via enrich.load_profiles (strict, versioned or legacy).  -> {canonical model: note}."""
    if path is None:
        return {}
    enrich = _sibling("enrich")
    try:
        pset = enrich.load_profiles(Path(path))
    except Exception:  # EnrichError carries codes only, but never echo exception text
        raise InputError("hypotheses_invalid", "--hypotheses: rejected by enrich.load_profiles (see enrich.py --check-profiles)")
    out = {}
    for model, prof in pset.by_model.items():
        kind, canon_model = _norm("product_model", model)
        if kind == "ok":
            out[canon_model] = {"qualification": prof.get("qualification", ""), "published_profile_id": prof.get("published_profile_id")}
    return out


def _match_evidence(model, revision, fw_line, registry):
    """-> (result dict, set of (code, field))."""
    reasons = set()
    res = {"isa": None, "abi": None, "float_abi": None, "atomic_widths": None,
           "images": [], "evidence_ids": [], "join_bases": []}
    cands = [r for r in registry["records"] if r["join"]["model_number"] == model]
    if not cands:
        reasons.add(("isa_evidence_absent", None))
        return res, reasons
    accepted = [r for r in cands if r["join"]["join_basis"] in ACCEPTED_JOIN_BASES]
    if not accepted:
        reasons.add(("isa_evidence_join_unattested", None))
        return res, reasons
    matched, fw_miss, rev_miss = [], False, False
    for r in accepted:
        fw_ok = fw_line in r["firmware_lines"]
        rev_ok = r["hardware_revisions"] is None or (revision is not None and revision in r["hardware_revisions"])
        if fw_ok and rev_ok:
            matched.append(r)
        elif not fw_ok:
            fw_miss = True
        else:
            rev_miss = True
    if not matched:
        if fw_miss:
            reasons.add(("isa_evidence_firmware_line_mismatch", None))
        if rev_miss:
            reasons.add(("isa_evidence_revision_mismatch", None))
        return res, reasons
    res["evidence_ids"] = sorted(r["id"] for r in matched)
    res["join_bases"] = sorted({r["join"]["join_basis"] for r in matched})
    isas = {r["isa"] for r in matched}
    abis = {r["abi"] for r in matched if r["abi"] is not None}
    fabis = {r["float_abi"] for r in matched if r["float_abi"] is not None}
    atoms = {tuple(r["atomic_widths"]) for r in matched if r["atomic_widths"] is not None}
    if len(isas) > 1 or len(abis) > 1 or len(fabis) > 1 or len(atoms) > 1 \
            or any(r["id"] in registry["contradicted"] for r in matched):
        reasons.add(("isa_evidence_conflict", None))
        return res, reasons
    machine, elf_class, endian = next(iter(isas))
    res["isa"] = {"machine": machine, "elf_class": elf_class, "endianness": endian}
    res["abi"] = next(iter(abis)) if abis else None
    res["float_abi"] = next(iter(fabis)) if fabis else None
    res["atomic_widths"] = list(next(iter(atoms))) if atoms else None
    by_name = collections.defaultdict(set)
    pairs = set()
    for r in matched:
        pairs.add((r["image"]["name"], r["image"]["digest"]))
        if r["image"]["digest"]:
            by_name[r["image"]["name"]].add(r["image"]["digest"])
    res["images"] = [{"name": n, "digest": d, "digest_algorithm": "sha256" if d else None}
                     for n, d in sorted(pairs, key=lambda p: (p[0], p[1] or ""))]
    if any(len(v) > 1 for v in by_name.values()):
        reasons.add(("image_digest_conflict", None))
    if not any(d for _, d in pairs):
        reasons.add(("image_digest_absent", None))
    if res["abi"] is None:
        reasons.add(("abi_not_recorded", None))
    if res["float_abi"] is None:
        reasons.add(("float_abi_not_recorded", None))
    if res["atomic_widths"] is None:
        reasons.add(("atomic_widths_not_recorded", None))
    return res, reasons


# ------------------------------------------------------------------ device merging
class _UnionFind:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


def _identity_tokens(o, diag):
    toks = set()
    for kind, sources, norm in (
        ("serial", (("fields", "serialNum"), ("status", "SerialNumber")), norm_serial),
        ("mac", (("fields", "MACAddress"), ("status", "MACAddress")), norm_mac),
        ("udn", (("fields", "UDN"),), norm_udn),
    ):
        for part, key in sources:
            v = o[part].get(key)
            if not v:
                continue
            n = norm(v)
            if n is None:
                if kind == "mac":
                    diag["identity_mac_malformed"] += 1
                continue
            toks.add((kind, n))
    return toks


def _values(o, key, skey):
    out = []
    v = o["fields"].get(key)
    if v:
        out.append(("device_description", v))
    if skey:
        v = o["status"].get(skey)
        if v:
            out.append(("status_zp", v))
    return out


def _pick_latest(pairs):
    """pairs: [(ts|None, value)] -> ('ok', value, changed) | ('conflict',)."""
    vals = {v for _, v in pairs}
    if len(vals) == 1:
        return ("ok", next(iter(vals)), False)
    if any(ts is None for ts, _ in pairs):
        return ("conflict",)
    latest = max(ts for ts, _ in pairs)
    top = {v for ts, v in pairs if ts == latest}
    if len(top) > 1:
        return ("conflict",)
    return ("ok", next(iter(top)), True)


def _content_hash(o):
    return _hexdigest("ffw.e01.obs-content.v1",
                      [o["fields"], o["status"], o["url"]])


def _host(url):
    """Host part of a URL without scheme or port (so it compares with a bare IP)."""
    if not url:
        return None
    host = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", url, flags=re.I).split("/", 1)[0]
    return re.sub(r":\d+$", "", host) or None


def _resolve_device(obs, tokens, declared_unit):
    """Merge one identity component into a device dict."""
    ids = collections.defaultdict(set)
    for kind, val in tokens:
        ids[kind].add(val)
    dev = {
        "tokens": sorted(f"{k}:{v}" for k, v in tokens),
        "ids": {k: sorted(v) for k, v in sorted(ids.items())},
        "obs": obs, "conflicts": [], "key": None, "sources": {}, "bases": {},
        "changes": {}, "model_numbers": set(),
    }
    seen, dups = set(), 0
    for o in obs:
        h = _content_hash(o)
        if h in seen:
            dups += 1
        seen.add(h)
    dev["dups"] = dups
    ambiguous = sorted(k for k, v in ids.items() if len(v) > 1)
    for o in obs:
        for _, v in _values(o, "modelNumber", None):
            kind, out = _norm("product_model", v)
            if kind == "ok":
                dev["model_numbers"].add(out)
    if ambiguous:
        dev["conflicts"].append(("identity_ambiguous", ",".join(ambiguous)))
        return dev
    state = {}
    # Immutable text fields.
    for logical, f, s in TEXT_FIELDS:
        vals, srcs = set(), set()
        for o in obs:
            for src, v in _values(o, f, s):
                if logical in CANONICAL_FIELDS:  # model and revision are normalised by identity.py
                    kind, out = _norm(CANONICAL_FIELDS[logical], v)
                    vals.add(out if kind == "ok" else _BAD)
                else:
                    vals.add(v)
                srcs.add(src)
        dev["sources"][logical] = sorted(srcs)
        if len(vals) > 1:
            dev["conflicts"].append(("hardware_field_conflict", logical))
        elif not vals:
            state[logical] = ("absent",)
        else:
            v = next(iter(vals))
            ok = v != _BAD and (logical in CANONICAL_FIELDS or _TEXT_RE.match(v))
            state[logical] = ("ok", v) if ok else ("malformed",)
    # Nominal sizes.
    for logical, f, s in SIZE_FIELDS:
        parsed, bases, srcs = set(), set(), set()
        for o in obs:
            for src, v in _values(o, f, s):
                st, basis = size_state(logical, v, declared_unit)
                parsed.add(st if st[0] != "invalid" else ("invalid", v))
                if basis:
                    bases.add(basis)
                srcs.add(src)
        if len(bases) > 1:
            bases.discard("unknown")  # an explicit basis supersedes "unit unknown" for the same quantity
        dev["sources"][logical] = sorted(srcs)
        dev["bases"][logical] = sorted(bases)
        # A bare number is compatible with an explicit-unit value of the same quantity.
        explicit_numbers = {st[1].split(" ", 1)[0] for st in parsed if st[0] == "ok"}
        parsed = {st for st in parsed if not (st[0] == "bare" and st[1] in explicit_numbers)}
        if len(parsed) > 1:
            dev["conflicts"].append(("hardware_field_conflict", logical))
        elif not parsed:
            state[logical] = ("absent",)
        else:
            st = next(iter(parsed))
            state[logical] = ("invalid",) if st[0] == "invalid" else st
    # Firmware fields ordered by observation time.
    fw_changed = False
    for logical, f, s in DATED_FIELDS:
        pairs, srcs = [], set()
        for o in obs:
            for src, v in _values(o, f, s):
                kind, out = _norm(DATED_CANONICAL[logical], v)  # identity.py: build string / integer generation
                pairs.append((o["ts"], out if kind == "ok" else _BAD))
                srcs.add(src)
        dev["sources"][logical] = sorted(srcs)
        if not pairs:
            state[logical] = ("absent",)
            continue
        pick = _pick_latest(pairs)
        if pick[0] == "conflict":
            dev["conflicts"].append(("firmware_unordered_conflict", logical))
            continue
        fw_changed = fw_changed or pick[2]
        state[logical] = ("malformed",) if pick[1] == _BAD else ("ok", pick[1])
    dev["changes"]["firmware_changed"] = fw_changed
    names = sorted({v for o in obs for v in (o["fields"].get("roomName"), o["fields"].get("friendlyName"), o["status"].get("ZoneName")) if v})
    hosts = sorted({h for h in (_host(o["url"]) for o in obs) if h} | {o["status"]["IPAddress"] for o in obs if o["status"].get("IPAddress")})
    dev["changes"]["names_seen"] = names
    dev["changes"]["hosts_seen"] = hosts
    dev["changes"]["renamed"] = len({v for o in obs for v in [o["fields"].get("roomName") or o["status"].get("ZoneName")] if v}) > 1
    dev["changes"]["address_changed"] = len(hosts) > 1
    if dev["conflicts"]:
        return dev
    # Firmware line from the winning softwareVersion.
    sw = state["software_version"]
    if sw[0] == "ok":
        m = _FWLINE_RE.match(sw[1])
        state["firmware_line"] = ("ok", f"{m.group(1)}.{m.group(2)}") if m else ("unknown",)
    else:
        state["firmware_line"] = ("absent",)
    dev["key"] = tuple(state[k] for k in KEY_ORDER)
    return dev


# ---------------------------------------------------------------- entry building
def _val(st):
    return st[1] if st[0] == "ok" else None


def _size_obj(st, bases):
    if st[0] == "ok":
        value, unit = st[1].split(" ", 1)
        return {"value": int(value), "unit": unit, "unit_basis": "+".join(bases) or "unknown",
                "bytes": int(value) * _sibling("identity").UNIT_FACTORS[unit]}
    if st[0] == "bare":
        return {"value": int(st[1]), "unit": None, "unit_basis": "unknown", "bytes": None}
    return None


def _key_reasons(key):
    """Reason codes that follow from the group key alone."""
    s = dict(zip(KEY_ORDER, key))
    r = set()
    if s["model_number"][0] == "absent":
        r.add(("model_absent", None))
    if s["hardware_revision"][0] == "absent":
        r.add(("hardware_revision_absent", None))
    for name in ("model_number", "model_name", "series_id", "variant", "hardware_revision", "sw_gen"):
        if s[name][0] == "malformed":
            r.add(("hardware_field_malformed", name))
    for name in ("memory", "flash"):
        st = s[name][0]
        if st == "absent":
            r.add(("nominal_size_absent", name))
        elif st in ("bare", "unit_unknown"):
            r.add(("nominal_size_unit_unknown", name))
        elif st == "invalid":
            r.add(("nominal_size_invalid", name))
    if s["firmware_line"][0] in ("absent", "unknown"):
        r.add(("firmware_line_unknown", None))
    return r


def _reason_list(pairs):
    out = [{"code": c, **({"field": f} if f else {})} for c, f in sorted(pairs, key=lambda p: (p[0], p[1] or ""))]
    return out


def _build_entry(key, devices, registry, hypotheses):
    s = dict(zip(KEY_ORDER, key))
    model, revision, fw_line = _val(s["model_number"]), _val(s["hardware_revision"]), _val(s["firmware_line"])
    reasons = set(_key_reasons(key))
    evidence = {"isa": None, "abi": None, "float_abi": None, "atomic_widths": None,
                "images": [], "evidence_ids": [], "join_bases": []}
    if model and fw_line:
        evidence, ev_reasons = _match_evidence(model, revision, fw_line, registry)
        reasons |= ev_reasons
    severities = {REASONS[c][0] for c, _ in reasons}
    resolution = "conflicted" if "conflict" in severities else ("unresolved" if "blocking" in severities else "resolved")
    prov = {}
    for logical in PROVENANCE_ORDER:
        srcs, count = set(), 0
        for d in devices:
            if d["sources"].get(logical):
                srcs.update(d["sources"][logical])
                count += 1
        p = {"sources": sorted(srcs), "devices": count}
        if logical in ("memory", "flash"):
            p["unit_basis"] = sorted({b for d in devices for b in d["bases"].get(logical, [])})
        prov[logical] = p
    prov["target"] = {"source": "image_evidence" if evidence["evidence_ids"] else None,
                      "evidence_ids": evidence["evidence_ids"], "join_bases": evidence["join_bases"]}
    hyp = hypotheses.get(model) if model else None
    entry = {
        "profile_id": profile_id_for(model, revision),
        "resolution": resolution,
        "activation_eligible": resolution == "resolved",
        "admission_scope": "e01-evidence-only; production admission is a separate update-policy decision (U02)",
        "device_count": len(devices),
        "model": {"model_number": model, "model_name": _val(s["model_name"]),
                  "series_id": _val(s["series_id"]), "variant": _val(s["variant"])},
        "hardware_revision": revision,
        "firmware": {"line": fw_line, "sw_gen": _val(s["sw_gen"])},
        "nominal_resources": {
            "measured": False,
            "memory": _size_obj(s["memory"], sorted({b for d in devices for b in d["bases"].get("memory", [])})),
            "flash": _size_obj(s["flash"], sorted({b for d in devices for b in d["bases"].get("flash", [])})),
        },
        "target": {k: evidence[k] for k in ("isa", "abi", "float_abi", "atomic_widths", "images")},
        "evidence_ids": evidence["evidence_ids"],
        "reason_codes": _reason_list(reasons),
        "provenance": prov,
        "published_hypothesis": None if hyp is None else {
            "ref": model, "published_profile_id": hyp.get("published_profile_id"),
            "status": "hypothesis-not-evidence", "used_for_selection": False,
            "qualification": _clean(hyp.get("qualification", ""))[:400] if hyp.get("qualification") else "",
        },
    }
    entry["evidence_digest"] = _hexdigest("ffw.e01.evidence-digest.v1", entry)  # bare 64-hex, a schema-defined digest key
    return entry


# ---------------------------------------------------------------------- pipeline
def reconcile(observations, batches_meta, registry, hypotheses, diag, declared_unit=None):
    """-> (public_doc, private_doc, clean: bool)."""
    n = len(observations)
    uf = _UnionFind(n)
    tok_first, tokens = {}, []
    for i, o in enumerate(observations):
        t = _identity_tokens(o, diag)
        tokens.append(t)
        for tk in t:
            if tk in tok_first:
                uf.union(i, tok_first[tk])
            else:
                tok_first[tk] = i
    comps, unidentifiable = collections.defaultdict(list), []
    for i, o in enumerate(observations):
        if not tokens[i]:
            unidentifiable.append(o)
        else:
            comps[uf.find(i)].append(i)
    devices = []
    for idxs in comps.values():
        toks = set().union(*(tokens[i] for i in idxs))
        devices.append(_resolve_device([observations[i] for i in idxs], toks, declared_unit))
    devices.sort(key=lambda d: d["tokens"])
    for d in devices:
        if "serial" not in d["ids"] and not any(c == "identity_ambiguous" for c, _ in d["conflicts"]):
            diag["identity_serial_absent"] += 1

    groups = collections.defaultdict(list)
    conflict_groups = collections.defaultdict(lambda: {"count": 0})
    for d in devices:
        if d["conflicts"]:
            sig = (tuple(sorted(set(d["conflicts"]), key=lambda p: (p[0], p[1] or ""))), tuple(sorted(d["model_numbers"])))
            conflict_groups[sig]["count"] += 1
        else:
            groups[d["key"]].append(d)

    entries = [_build_entry(k, groups[k], registry, hypotheses) for k in sorted(groups)]
    conflicts = []
    for (codes, models), info in sorted(conflict_groups.items(), key=lambda kv: canon([list(map(list, kv[0][0])), list(kv[0][1])])):
        code_objs = [{"code": c, **({"field": f} if f else {})} for c, f in codes]
        conflicts.append({
            "conflict_id": "cf-" + _hexdigest("ffw.e01.conflict-id.v1", [list(map(list, codes)), list(models)])[:8],
            "codes": code_objs, "model_numbers": list(models),
            "component_count": info["count"], "activation_eligible": False,
        })

    ts_all = sorted(o["ts"] for o in observations if o["ts"] is not None)
    res_counts = collections.Counter(e["resolution"] for e in entries)
    clean = (bool(entries) and not conflicts and not unidentifiable and res_counts["resolved"] == len(entries))
    summary = {
        "observations": n,
        "identity_components": len(devices),
        "devices_in_profiles": sum(e["device_count"] for e in entries),
        "devices_in_conflict": sum(c["component_count"] for c in conflicts),
        "unidentifiable_observations": len(unidentifiable),
        "duplicate_observations": sum(d["dups"] for d in devices),
        "profiles": len(entries),
        "profiles_resolved": res_counts["resolved"],
        "profiles_unresolved": res_counts["unresolved"],
        "profiles_conflicted": res_counts["conflicted"],
        "all_resolved": clean,
    }
    public = {
        "schema": MANIFEST_SCHEMA,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "inputs": {"batches": len(batches_meta), "evidence_records": len(registry["records"]),
                   "hypotheses_supplied": bool(hypotheses), "nominal_unit_declared": declared_unit},
        "observation_window": {"earliest": _fmt_ts(ts_all[0]) if ts_all else None,
                               "latest": _fmt_ts(ts_all[-1]) if ts_all else None},
        "summary": summary,
        "profiles": entries,
        "conflicts": conflicts,
        "unattributed": {"unidentifiable_observations": len(unidentifiable),
                         "reason_codes": [{"code": "identity_unidentifiable"}] if unidentifiable else []},
        "diagnostics": {k: diag[k] for k in sorted(diag) if diag[k]},
        "sanitization": {"policy": "allowlist-v1", "per_device_identifiers": "none", "identifier_hashes": "none"},
    }
    private = {
        "schema": PRIVATE_SCHEMA,
        "warning": "OWNER-LOCAL: contains device identifiers. Never commit, paste or share.",
        "ordinal_scope": "run-local; ordinals are not stable across runs",
        "batches": batches_meta,
        "devices": [{
            "ordinal": i + 1,
            "identifiers": d["ids"],
            "observations": sorted(({"batch": o["batch"], "index": o["index"]} for o in d["obs"]),
                                   key=lambda r: (r["batch"], r["index"])),
            "duplicate_observations": d["dups"],
            "changes": d["changes"],
            "profile_id": None if d["conflicts"] else profile_id_for(
                _val(d["key"][KEY_ORDER.index("model_number")]),
                _val(d["key"][KEY_ORDER.index("hardware_revision")])),
            "conflicts": [{"code": c, **({"field": f} if f else {})} for c, f in sorted(set(d["conflicts"]), key=lambda p: (p[0], p[1] or ""))],
        } for i, d in enumerate(devices)],
        "unidentifiable": sorted(({"batch": o["batch"], "index": o["index"]} for o in unidentifiable),
                                 key=lambda r: (r["batch"], r["index"])),
    }
    return public, private, clean


# -------------------------------------------------------------------- leak guard
def _walk_strings(obj, path=""):
    if isinstance(obj, dict):
        for k in sorted(obj):
            yield from _walk_strings(obj[k], f"{path}.{k}" if path else str(k))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from _walk_strings(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def scan_public(doc, private_ids, private_names):
    """-> list of (kind, path).  Never returns matched values."""
    model_strings = set()
    for e in doc.get("profiles", []):
        for v in list(e.get("model", {}).values()) + [e.get("hardware_revision")]:
            if isinstance(v, str):
                model_strings.add(v.lower())
    ids = sorted(x.lower() for x in private_ids if len(x) >= 6)
    names = sorted(x for x in private_names if len(x) >= 3 and x not in model_strings)
    findings = []
    for path, s in _walk_strings(doc):
        low = s.lower()
        for pid in ids:
            if pid in low:
                findings.append(("identifier", path))
                break
        if low in names:
            findings.append(("name", path))
        for kind, pat in _LEAK_PATTERNS:
            if kind == "ipv4" and path.endswith("hardware_revision"):
                continue
            if pat.search(s):
                findings.append((kind, path))
    return findings


def assert_public_clean(doc, private_ids, private_names):
    findings = scan_public(doc, private_ids, private_names)
    if findings:
        kinds = sorted({k for k, _ in findings})
        first = findings[0][1]
        raise LeakError("leak_guard", f"public output rejected: {len(findings)} finding(s) of kind {','.join(kinds)}; first at {first}; nothing was written")


# ------------------------------------------------------------------------ output
def render_json(doc) -> str:
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _fmt_size(o):
    if not o:
        return "unknown"
    return f"{o['value']} {o['unit']}" if o["unit"] else f"{o['value']} (unit unknown)"


def render_markdown(doc) -> str:
    s = doc["summary"]
    lines = [
        "# Board-profile manifest (sanitized)", "",
        f"Schema `{doc['schema']}`. No per-device identifiers; counts only. Nominal sizes are device-reported, not measured.", "",
        f"- Observations: {s['observations']}; identity components: {s['identity_components']}; "
        f"duplicates: {s['duplicate_observations']}; unidentifiable: {s['unidentifiable_observations']}",
        f"- Profiles: {s['profiles']} ({s['profiles_resolved']} resolved, {s['profiles_unresolved']} unresolved, {s['profiles_conflicted']} conflicted)",
        f"- Device-level conflicts: {s['devices_in_conflict']}", "",
        "| Model | Series | Revision | Firmware line | Devices | Nominal RAM / flash | Resolution | Reasons |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for e in doc["profiles"]:
        reasons = ", ".join(r["code"] + (f":{r['field']}" if "field" in r else "") for r in e["reason_codes"]
                            if REASONS[r["code"]][0] != "info") or "none"
        lines.append("| " + " | ".join([
            str(e["model"]["model_number"] or "?"), str(e["model"]["series_id"] or "?"),
            str(e["hardware_revision"] or "?"), str(e["firmware"]["line"] or "?"), str(e["device_count"]),
            f"{_fmt_size(e['nominal_resources']['memory'])} / {_fmt_size(e['nominal_resources']['flash'])}",
            e["resolution"], reasons]) + " |")
    if doc["conflicts"]:
        lines += ["", "## Conflicts (ineligible for activation)", "", "| Conflict | Codes | Models | Components |", "|---|---|---|---|"]
        for c in doc["conflicts"]:
            codes = ", ".join(x["code"] + (f":{x['field']}" if "field" in x else "") for x in c["codes"])
            lines.append(f"| {c['conflict_id']} | {codes} | {', '.join(c['model_numbers']) or '?'} | {c['component_count']} |")
    return "\n".join(lines) + "\n"


def catalog_doc():
    return {"schema": REASONS_SCHEMA,
            "codes": [{"code": c, "severity": REASONS[c][0], "summary": REASONS[c][1]} for c in sorted(REASONS)]}


def _is_private_location(p: Path) -> bool:
    return ".local-real" in p.parts or ".local." in p.name


def write_atomic(path: Path, data: bytes, overwrite: bool, mode: int):
    """Write via a temp file in the target directory; never leaves a partial file."""
    fd, tmp = tempfile.mkstemp(prefix=".e01-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        if overwrite:
            os.replace(tmp, path)
        else:
            try:
                os.link(tmp, path)
            except FileExistsError:
                raise OutputError("output_exists", "output file already exists; pass --overwrite to replace it")
            os.unlink(tmp)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _plan_outputs(args):
    protected = {Path(p).resolve() for p in list(args.input) + list(args.evidence)}
    if args.hypotheses:
        protected.add(Path(args.hypotheses).resolve())
    out = Path(args.out).resolve() if args.out else None
    priv = Path(args.private_out).resolve() if args.private_out else None
    if out and priv and out == priv:
        raise OutputError("output_collision", "--out and --private-out name the same file")
    for label, p in (("--out", out), ("--private-out", priv)):
        if p is None:
            continue
        if p in protected:
            raise OutputError("output_collides_with_input", f"{label} would overwrite an input file")
        if not p.parent.is_dir():
            raise OutputError("output_parent_missing", f"{label}: parent directory does not exist")
        if p.is_dir():
            raise OutputError("output_is_directory", f"{label} is a directory")
        if p.exists() and not args.overwrite:
            raise OutputError("output_exists", f"{label}: file already exists; pass --overwrite to replace it")
    if priv is not None and not _is_private_location(priv):
        raise OutputError("private_out_not_ignored",
                          "--private-out must be under a '.local-real' directory or have a '.local.' file name (git-ignored locations)")
    return out, priv


# --------------------------------------------------------------------------- CLI
class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError("usage", message)


def _build_parser():
    p = _Parser(prog="reconcile.py", allow_abbrev=False, description=__doc__.split("\n\n")[0])
    p.add_argument("--input", action="append", default=[], metavar="PATH", help="observation batch (JSON) or device_description.xml; repeatable; required")
    p.add_argument("--evidence", action="append", default=[], metavar="PATH", help="image-evidence registry JSON; repeatable")
    p.add_argument("--hypotheses", metavar="PATH", help="published-hardware notes, read with enrich.load_profiles (legacy or versioned); referenced, never used for selection")
    p.add_argument("--nominal-unit", choices=("MB", "MiB"), help="declare the unit of bare memory/flash numbers (default: unknown)")
    p.add_argument("--format", choices=("json", "md"), default="json")
    p.add_argument("--out", metavar="PATH", help="write the sanitized public output here instead of stdout")
    p.add_argument("--private-out", metavar="PATH", help="write the owner-local report (git-ignored location only)")
    p.add_argument("--overwrite", action="store_true", help="replace existing output files (never input files)")
    p.add_argument("--allow-incomplete", action="store_true", help="exit 0 even when profiles are unresolved/conflicted or records unattributed (default: exit 3)")
    p.add_argument("--list-reason-codes", action="store_true", help="print the reason-code catalog and exit")
    return p


def _run(argv, stdout):
    args = _build_parser().parse_args(argv)
    if args.list_reason_codes:
        stdout.write(render_json(catalog_doc()))
        return EXIT_OK
    if not args.input:
        raise InputError("usage", "at least one --input is required (no implicit discovery)")
    out, priv = _plan_outputs(args)
    obs, metas, diag, ids, names = load_inputs(args.input)
    registry, rdiag = load_registry(args.evidence)
    diag.update(rdiag)
    hyp = load_hypotheses(args.hypotheses)
    public, private, clean = reconcile(obs, metas, registry, hyp, diag, args.nominal_unit)
    assert_public_clean(public, ids, names)
    # Identifier-class canaries only: the shared scanner matches by substring, which is right for
    # serials/MACs/addresses but would flag a room named like a word in a model name.  Names stay
    # with the exact-match guard above.
    shared = _sibling("identity").find_private_identifiers(
        public, canaries=sorted(x for x in ids if len(x) >= 6), digest_keys=("digest",))
    if shared:
        kinds = sorted({f.rsplit(": ", 1)[-1] for f in shared})
        raise LeakError("leak_guard", f"public output rejected by the shared identity scanner: {len(shared)} finding(s) of kind {','.join(kinds)}; nothing was written")
    text = render_json(public) if args.format == "json" else render_markdown(public)
    if out:
        write_atomic(out, text.encode("utf-8"), args.overwrite, 0o644)
    else:
        stdout.write(text)
    if priv:
        write_atomic(priv, render_json(private).encode("utf-8"), args.overwrite, 0o600)
    return EXIT_INCOMPLETE if (not clean and not args.allow_incomplete) else EXIT_OK


def main(argv=None, stdout=None, stderr=None) -> int:
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    try:
        return _run(argv, stdout)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else EXIT_USAGE
    except E01Error as e:
        stderr.write(f"error[{e.code}]: {e.message}\n")
        return e.exit_code
    except KeyboardInterrupt:
        stderr.write("error[interrupted]: interrupted; no partial output file was left behind\n")
        return EXIT_INTERRUPT
    except Exception as e:  # never echo exception text: it could carry input values
        frames = traceback.extract_tb(e.__traceback__)[-4:]
        where = "; ".join(f"{os.path.basename(f.filename)}:{f.lineno} {f.name}" for f in frames)
        stderr.write(f"error[internal]: unexpected {type(e).__name__} at {where}; no output was written\n")
        return EXIT_INTERNAL


if __name__ == "__main__":
    sys.exit(main())
