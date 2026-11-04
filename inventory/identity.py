#!/usr/bin/env python3
"""Offline identity/provenance normalization for FrankenFirmware (bead E01, ffw-xdi).

Pure standard library. No file, network, clock or environment access except the
explicit ``Pseudonymizer.from_env``. Deterministic: the same set of claims yields
byte-identical output regardless of batch order or duplication.

What this module is for
-----------------------
E01 must say which board a device is *without guessing*. Four evidence axes are
kept strictly separate, because conflating them is how wrong boards get picked:

* **product model**      ``modelNumber`` (``S1``, ``S12`` ...), never the marketing
                         name, never ``seriesid`` (one series id spans several models).
* **hardware revision**  ``hardwareVersion``. Absent stays absent.
* **software generation**``swGen`` 1 or 2, and the software *build* string. The model
                         token ``S1`` is not software generation 1; the two are distinct
                         fields and a model-like token in the generation field is rejected.
* **architecture**       ISA / endianness / word size / ABI / float ABI / SoC, accepted
                         only from bases that can actually establish them (an ELF header
                         establishes ISA, endianness and word size; it never establishes a
                         SoC). Era, release year, product family and software generation are
                         forbidden bases (``ERA_INFERENCE_FORBIDDEN``).

plus **nominal RAM/flash**: a bare number from ``device_description.xml`` carries no
unit, so it stays ``UNIT_UNKNOWN`` until a unit-bearing source says otherwise. A string
that states its own unit (``"128 MB"``) keeps it (MB and MiB are different byte counts); the
claim origin records whether the unit was stated by the source (``src-MB``) or assumed by the
operator for a bare number (``op-MiB``).

Resolution rules (``resolve_fleet``)
------------------------------------
* ``unknown`` stays ``unknown``. No default, no inference, no "best guess".
* Disagreeing observed/declared claims on an immutable axis => ``conflict`` with
  ``value=None`` and every candidate kept with provenance. Never merged.
* Mutable axes (software build/generation) that disagree are an ordered history when
  every claim is dated, otherwise a ``conflict``.
* Hypothesis-tier evidence (published teardown, community research, peer report)
  never resolves a field alone (``hypothesis_only``) and never overrides observed
  evidence; contradictions are listed under ``contradicted_hypotheses``.
* A board profile id is a function of (product model, hardware revision) only. It is
  ``None`` when either is unresolved. ``evidence_digest`` covers everything else.
* ``activation_eligible`` is a *necessary* precondition only (production admission is a
  separate update-design decision). It is false on any conflict, any unresolved
  required field, any image-digest/binding conflict, and when required evidence is
  synthetic-only.

Privacy
-------
Serials, addresses and room names are reduced to keyed HMAC pseudonyms
(``Pseudonymizer``) at the edge; the raw values are never stored in any claim,
finding, exception message or public document. ``resolve_fleet`` re-scans its own
output with ``find_private_identifiers`` and fails closed on a hit.

Honest limits
-------------
* An ``ImageRef`` digest is caller-asserted: ``normalize_elf_header`` sees only the
  header bytes and cannot verify they belong to that digest.
* An ELF header proves the image's ISA/endianness/word size, not that any specific
  device runs it; that link exists only through an explicit, sourced
  ``bound_product_model`` binding.
* Nothing here proves a physical board identity. Synthetic fixtures are labeled
  (``synthetic:`` source ids) and can never make a profile activation-eligible.
"""
from __future__ import annotations

import copy
import dataclasses
import datetime as _dt
import hashlib
import hmac
import json
import os
import re
import struct
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

SCHEMA = "ffw.identity/v1"
MAX_STR = 128
MAX_CLAIMS = 100_000
MAX_BYTES = 2 ** 50

# --------------------------------------------------------------------------- reason codes
R_ABSENT = "ABSENT_IN_SOURCE"
R_PLACEHOLDER = "PLACEHOLDER_IN_SOURCE"
R_MALFORMED = "MALFORMED_VALUE"
R_UNIT_UNKNOWN = "UNIT_UNKNOWN"
R_UNIT_INVALID = "UNIT_INVALID"
R_NO_EVIDENCE = "NO_EVIDENCE"
R_CONFLICT = "CONFLICTING_EVIDENCE"
R_UNORDERABLE = "UNORDERABLE_UNDATED_CHANGE"
R_CHANGED = "CHANGED_OVER_TIME"
R_HYPOTHESIS_ONLY = "HYPOTHESIS_ONLY"
R_HYPOTHESES_DISAGREE = "HYPOTHESES_DISAGREE"
R_BOUND_VIOLATED = "BOUND_VIOLATED"
R_ERA = "ERA_INFERENCE_FORBIDDEN"
R_BASIS_UNKNOWN = "BASIS_UNKNOWN"
R_BASIS_FIELD = "BASIS_NOT_ALLOWED_FOR_FIELD"
R_SUBJECT = "SUBJECT_NOT_ALLOWED"
R_SUBJECT_INVALID = "SUBJECT_INVALID"
R_QUALIFIER = "QUALIFIER_NOT_ALLOWED"
R_FIELD_UNKNOWN = "FIELD_UNKNOWN"
R_GEN_MODEL = "PRODUCT_MODEL_IN_GENERATION_FIELD"
R_SOC_ISA = "SOC_IS_ISA_NAME"
R_ISA_UNRECOGNIZED = "UNRECOGNIZED_ISA"
R_ARCH_INCONSISTENT = "ISA_FIELDS_INCONSISTENT"
R_IMAGE_INVALID = "IMAGE_INVALID"
R_IMAGE_UNBOUND = "IMAGE_UNBOUND"
R_IMAGE_BINDING_CONFLICT = "IMAGE_BINDING_CONFLICT"
R_IMAGE_DIGEST_CONFLICT = "IMAGE_DIGEST_CONFLICT"
R_IMAGE_META_CONFLICT = "IMAGE_METADATA_CONFLICT"
R_BOUND_MODEL_ABSENT = "BOUND_MODEL_NOT_IN_FLEET"
R_SYNTHETIC_ONLY = "SYNTHETIC_EVIDENCE_ONLY"
R_ELF_MALFORMED = "ELF_MALFORMED"
R_ELF_INCONSISTENT = "ELF_INCONSISTENT"
R_DEVICE_KEY = "DEVICE_KEY_MISSING"
R_RECORD = "RECORD_INVALID"
R_SOURCE = "SOURCE_INVALID"
R_TIME = "OBSERVED_AT_MALFORMED"
R_KEY = "PSEUDONYM_KEY_INVALID"
R_ADDRESS = "ADDRESS_INVALID"
R_LIMIT = "LIMIT_EXCEEDED"
R_LEAK = "PRIVATE_IDENTIFIER_IN_OUTPUT"

REASON_CODES = frozenset(v for k, v in list(globals().items()) if k.startswith("R_") and isinstance(v, str))


class IdentityError(ValueError):
    """Strict-validation failure. The message carries the code and field only,
    never the offending value."""

    def __init__(self, code: str, field: Optional[str] = None, detail: Optional[Mapping[str, Any]] = None):
        self.code = code
        self.field = field
        self.detail = dict(detail or {})
        super().__init__(code if field is None else "%s [%s]" % (code, field))


# --------------------------------------------------------------------------- small helpers
def _cj(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()


_PLACEHOLDERS = frozenset({"unknown", "n/a", "na", "none", "null", "?", "-", "tbd", "unset", "undefined"})


def _shape(text: str, limit: int = 24) -> str:
    """Structure-only fingerprint (digits->d, letters->a) for non-private fields."""
    out = []
    for ch in text[:limit]:
        if ch.isascii() and ch.isdigit():
            out.append("d")
        elif ch.isascii() and ch.isalpha():
            out.append("a")
        elif ch in ".-_:/":
            out.append(ch)
        else:
            out.append("?")
    return "".join(out)


def _text(raw: Any, field: str, maxlen: int = MAX_STR) -> str:
    if not isinstance(raw, str):
        raise IdentityError(R_MALFORMED, field, {"type": type(raw).__name__})
    s = raw.strip()
    if not s:
        raise IdentityError(R_ABSENT, field)
    if s.casefold() in _PLACEHOLDERS:
        raise IdentityError(R_PLACEHOLDER, field)
    if len(s) > maxlen or not s.isascii() or any(ord(c) < 32 or ord(c) == 127 for c in s):
        raise IdentityError(R_MALFORMED, field, {"len": min(len(s), 4096)})
    return s


def _posint(raw: Any, field: str) -> int:
    if isinstance(raw, bool):
        raise IdentityError(R_MALFORMED, field, {"type": "bool"})
    if isinstance(raw, int):
        n = raw
    elif isinstance(raw, str):
        s = _text(raw, field)
        if not s.isdigit() or len(s) > 15:
            raise IdentityError(R_MALFORMED, field, {"shape": _shape(s)})
        n = int(s)
    else:
        raise IdentityError(R_MALFORMED, field, {"type": type(raw).__name__})
    if n <= 0:
        raise IdentityError(R_MALFORMED, field, {"why": "non_positive"})
    return n


def _canon_time(raw: Any) -> str:
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 40:
        raise IdentityError(R_TIME, "observed_at")
    s = raw.strip()
    if s[-1] in "zZ":
        s = s[:-1] + "+00:00"
    try:
        dt = _dt.datetime.fromisoformat(s)
    except ValueError:
        raise IdentityError(R_TIME, "observed_at") from None
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise IdentityError(R_TIME, "observed_at", {"why": "naive"})
    dt = dt.astimezone(_dt.timezone.utc)
    if not 2000 <= dt.year <= 2100:
        raise IdentityError(R_TIME, "observed_at", {"why": "range"})
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- field parsers
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,23}$")
_REV_RE = re.compile(r"^[0-9]{1,5}(?:\.[0-9]{1,5}){0,5}(?:-[0-9]{1,5}(?:\.[0-9]{1,5}){0,3})?$")
_BUILD_RE = re.compile(r"^[0-9]{1,5}(?:\.[0-9]{1,5}){1,3}(?:-[0-9]{1,9})?$")
_ABI_RE = re.compile(r"^[a-z][a-z0-9_-]{1,15}$")
_SOC_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/+-]{1,47}$")
_SOC_ISA_LIKE = re.compile(
    r"^(?:mips(?:32|64)?(?:r\d+)?|ppc(?:32|64)?|powerpc(?:32|64)?|arm(?:32|64)?|armv\d+[a-z]*|aarch64"
    r"|x86(?:_64)?|amd64|i[3-6]86|riscv(?:32|64)?)$"
)
_SERIES_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{1,11}$")
_GEN_MODELISH_RE = re.compile(r"^[A-Za-z]+[0-9]+$")

_ISA_ALIASES = {
    "mips": "mips", "mips32": "mips",
    "ppc": "powerpc", "ppc32": "powerpc", "powerpc": "powerpc", "powerpc32": "powerpc",
    "arm": "arm", "arm32": "arm",
    "aarch64": "aarch64", "arm64": "aarch64",
    "x86": "x86", "i386": "x86", "i686": "x86",
    "x86_64": "x86_64", "amd64": "x86_64",
    "riscv": "riscv",
}
ISAS = frozenset(_ISA_ALIASES.values())
UNIT_FACTORS = {"B": 1, "KiB": 2 ** 10, "MiB": 2 ** 20, "GiB": 2 ** 30, "KB": 10 ** 3, "MB": 10 ** 6, "GB": 10 ** 9}


def _reject_private(s: str, field: str) -> None:
    """A value shaped like a MAC/RINCON/UUID/long hex run is never a legitimate model/ABI/SoC token."""
    if _scan_string(s, allow_ipv4=True):
        raise IdentityError(R_MALFORMED, field, {"why": "looks_private"})


def _dotted_canon(s: str) -> str:
    return re.sub(r"[0-9]+", lambda m: str(int(m.group())), s)


def _parse_model(raw: Any, field: str = "product_model") -> str:
    s = _text(raw, field, 24)
    if not _MODEL_RE.match(s):
        raise IdentityError(R_MALFORMED, field, {"shape": _shape(s)})
    _reject_private(s, field)
    return s.upper()


def _parse_revision(raw: Any, unit: Optional[str] = None) -> str:
    s = _text(raw, "hardware_revision", 32)
    if not _REV_RE.match(s):
        raise IdentityError(R_MALFORMED, "hardware_revision", {"shape": _shape(s)})
    return _dotted_canon(s)


def _parse_build(raw: Any, unit: Optional[str] = None, field: str = "software_build") -> str:
    s = _text(raw, field, 32)
    if not _BUILD_RE.match(s):
        raise IdentityError(R_MALFORMED, field, {"shape": _shape(s)})
    return _dotted_canon(s)


def _parse_generation(raw: Any, unit: Optional[str] = None) -> int:
    f = "software_generation"
    if isinstance(raw, bool):
        raise IdentityError(R_MALFORMED, f, {"type": "bool"})
    if isinstance(raw, int):
        n = raw
    elif isinstance(raw, str):
        s = _text(raw, f, 8)
        if _GEN_MODELISH_RE.match(s):
            raise IdentityError(R_GEN_MODEL, f, {"shape": _shape(s)})
        if not s.isdigit():
            raise IdentityError(R_MALFORMED, f, {"shape": _shape(s)})
        n = int(s)
    else:
        raise IdentityError(R_MALFORMED, f, {"type": type(raw).__name__})
    if n not in (1, 2):
        raise IdentityError(R_MALFORMED, f, {"why": "unsupported_generation"})
    return n


def _parse_isa(raw: Any, unit: Optional[str] = None) -> str:
    s = _text(raw, "arch.isa", 16).casefold()
    if s not in _ISA_ALIASES:
        raise IdentityError(R_ISA_UNRECOGNIZED, "arch.isa", {"shape": _shape(s)})
    return _ISA_ALIASES[s]


def _parse_endianness(raw: Any, unit: Optional[str] = None) -> str:
    s = _text(raw, "arch.endianness", 8).casefold()
    if s in ("big", "be", "msb"):
        return "big"
    if s in ("little", "le", "lsb"):
        return "little"
    raise IdentityError(R_MALFORMED, "arch.endianness", {"shape": _shape(s)})


def _parse_word_bits(raw: Any, unit: Optional[str] = None) -> int:
    n = _posint(raw, "arch.word_bits")
    if n not in (32, 64):
        raise IdentityError(R_MALFORMED, "arch.word_bits", {"why": "unsupported_width"})
    return n


def _parse_abi(raw: Any, unit: Optional[str] = None) -> str:
    s = _text(raw, "arch.abi", 16).casefold()
    if not _ABI_RE.match(s):
        raise IdentityError(R_MALFORMED, "arch.abi", {"shape": _shape(s)})
    _reject_private(s, "arch.abi")
    return s


def _parse_float_abi(raw: Any, unit: Optional[str] = None) -> str:
    s = _text(raw, "arch.float_abi", 8).casefold()
    if s not in ("hard", "soft", "softfp"):
        raise IdentityError(R_MALFORMED, "arch.float_abi", {"shape": _shape(s)})
    return s


def _parse_soc(raw: Any, unit: Optional[str] = None) -> str:
    s = _text(raw, "arch.soc", 48)
    s = re.sub(r"\s+", " ", s)
    if not _SOC_RE.match(s):
        raise IdentityError(R_MALFORMED, "arch.soc", {"shape": _shape(s)})
    _reject_private(s, "arch.soc")
    if _SOC_ISA_LIKE.match(s.casefold().replace(" ", "")):
        # A SoC is a specific part. An ISA name there means someone inferred silicon from ISA.
        raise IdentityError(R_SOC_ISA, "arch.soc", {"shape": _shape(s)})
    return s.upper()


# Grammar for a size string that states its own unit: ASCII digits, at most ONE ASCII space, then an
# alphabetic unit token ("128MB" and "128 MB" are accepted). Leading/trailing whitespace of the whole
# value is trimmed before matching. Tabs, newlines, NBSP and runs of spaces between number and unit are
# NOT part of the grammar and are rejected as malformed rather than silently reinterpreted.
_SIZE_STR_RE = re.compile(r"^([0-9]{1,15}) ?([A-Za-z]{1,5})$")


def _make_bytes_parser(field: str) -> Callable[[Any, Optional[str]], int]:
    def parse(raw: Any, unit: Optional[str] = None) -> int:
        if isinstance(raw, str):
            m = _SIZE_STR_RE.match(raw.strip())
            if m:
                # The source text states its own unit ("128 MB"). It is kept as stated and wins over
                # the operator-supplied default, which applies to bare numbers only. MB != MiB.
                if m.group(2) not in UNIT_FACTORS:
                    raise IdentityError(R_UNIT_INVALID, field)
                n = _posint(m.group(1), field) * UNIT_FACTORS[m.group(2)]
                if n > MAX_BYTES:
                    raise IdentityError(R_MALFORMED, field, {"why": "too_large"})
                return n
        n = _posint(raw, field)  # value problems first: UNIT_UNKNOWN means "a valid number, but no unit"
        if unit is None:
            raise IdentityError(R_UNIT_UNKNOWN, field)
        if not isinstance(unit, str) or unit not in UNIT_FACTORS:
            raise IdentityError(R_UNIT_INVALID, field)
        n *= UNIT_FACTORS[unit]
        if n > MAX_BYTES:
            raise IdentityError(R_MALFORMED, field, {"why": "too_large"})
        return n

    return parse


@dataclasses.dataclass(frozen=True)
class FieldSpec:
    name: str
    axis: str
    mutable: bool
    subjects: frozenset
    parse: Callable[[Any, Optional[str]], Any]


_DEV = frozenset({"device"})
_DEV_IMG_MODEL = frozenset({"device", "image", "model"})
_DEV_MODEL = frozenset({"device", "model"})

FIELDS: Dict[str, FieldSpec] = {
    s.name: s
    for s in (
        FieldSpec("product_model", "product_model", False, _DEV, lambda r, u=None: _parse_model(r)),
        FieldSpec("hardware_revision", "hardware_revision", False, _DEV, _parse_revision),
        FieldSpec("software_generation", "software_generation", True, _DEV, _parse_generation),
        FieldSpec("software_build", "software_build", True, _DEV, _parse_build),
        FieldSpec("arch.isa", "architecture", False, _DEV_IMG_MODEL, _parse_isa),
        FieldSpec("arch.endianness", "architecture", False, _DEV_IMG_MODEL, _parse_endianness),
        FieldSpec("arch.word_bits", "architecture", False, _DEV_IMG_MODEL, _parse_word_bits),
        FieldSpec("arch.abi", "architecture", False, _DEV_IMG_MODEL, _parse_abi),
        FieldSpec("arch.float_abi", "architecture", False, _DEV_IMG_MODEL, _parse_float_abi),
        FieldSpec("arch.soc", "architecture", False, _DEV_IMG_MODEL, _parse_soc),
        FieldSpec("nominal_ram_bytes", "nominal_resources", False, _DEV_MODEL, _make_bytes_parser("nominal_ram_bytes")),
        FieldSpec("nominal_flash_bytes", "nominal_resources", False, _DEV_MODEL, _make_bytes_parser("nominal_flash_bytes")),
    )
}
DEVICE_FIELDS = ("product_model", "hardware_revision", "software_generation", "software_build")
PROFILE_FIELDS = tuple(sorted(f for f in FIELDS if f.startswith("arch.") or f.startswith("nominal_")))
DEFAULT_REQUIRED = (
    "product_model", "hardware_revision",
    "arch.isa", "arch.endianness", "arch.word_bits", "arch.abi", "arch.float_abi",
    "nominal_ram_bytes",
)
QUALIFIERS = ("exact", "upper_bound", "lower_bound")


# --------------------------------------------------------------------------- bases
@dataclasses.dataclass(frozen=True)
class BasisSpec:
    tier: str  # observed | declared | hypothesis
    fields: frozenset
    subjects: frozenset


_ARCH = frozenset(f for f in FIELDS if f.startswith("arch."))
_NOMINAL = frozenset({"nominal_ram_bytes", "nominal_flash_bytes"})
_IDF = frozenset(DEVICE_FIELDS)

BASES: Dict[str, BasisSpec] = {
    "live_description": BasisSpec("observed", _IDF | _NOMINAL, frozenset({"device"})),
    "kernel_cpuinfo": BasisSpec(
        "observed", frozenset({"arch.isa", "arch.endianness", "arch.word_bits", "arch.soc"}), frozenset({"device"})),
    "silicon_marking": BasisSpec("observed", frozenset({"arch.soc"}), frozenset({"device"})),
    "elf_header": BasisSpec(
        "observed",
        frozenset({"arch.isa", "arch.endianness", "arch.word_bits", "arch.abi", "arch.float_abi"}),
        frozenset({"image"})),
    "elf_attributes": BasisSpec("observed", frozenset({"arch.abi", "arch.float_abi"}), frozenset({"image"})),
    "vendor_documentation": BasisSpec("declared", _ARCH | _NOMINAL, _DEV_MODEL),
    "owner_attestation": BasisSpec("declared", _ARCH | _NOMINAL | _IDF, _DEV_MODEL),
    "firmware_package_metadata": BasisSpec("declared", frozenset(), frozenset({"image"})),
    "published_teardown": BasisSpec("hypothesis", _ARCH | _NOMINAL, _DEV_MODEL),
    "community_research": BasisSpec("hypothesis", _ARCH | _NOMINAL, _DEV_MODEL),
    "peer_report": BasisSpec("hypothesis", _ARCH | _NOMINAL | _IDF, _DEV_MODEL),
}
# Inference-from-era style bases. Constructing a Source with one of these is an error.
FORBIDDEN_BASES = frozenset({
    "product_era", "release_year", "model_family", "product_family", "product_name",
    "marketing_name", "software_generation", "generation_inference", "series_id", "seriesid", "era",
})
_BINDING_BASES = frozenset({"firmware_package_metadata", "vendor_documentation", "owner_attestation"})
_RECORD_BASES = frozenset({"live_description", "peer_report"})
_TIER_RANK = {"observed": 0, "declared": 1, "hypothesis": 2}

# --------------------------------------------------------------------------- privacy guard
_IPV4 = re.compile(r"(?<![0-9A-Za-z.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![0-9A-Za-z])")
_MAC = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
_RINCON = re.compile(r"RINCON_[0-9A-Fa-f]{12}", re.I)
_UUID = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![0-9A-Za-z])")
_HEXRUN = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{12,}(?![0-9A-Za-z])")
_PSEUDONYM = re.compile(r"(?<![0-9A-Za-z])(?:dev|adr|lbl|img|bp)-[0-9a-f]{8,64}(?![0-9A-Za-z])")
_VERSION_KEYS = frozenset({"hardware_revision", "hardware_revisions", "software_build"})
DIGEST_KEYS = frozenset({"evidence_digest", "fleet_digest", "aggregate_evidence_digest", "aggregate_digest"})
# ^ this module's own schema-defined digest keys
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")


def _scan_string(s: str, allow_ipv4: bool) -> List[str]:
    kinds = []
    t = _PSEUDONYM.sub(" ", s)
    if not allow_ipv4 and _IPV4.search(t):
        kinds.append("ipv4")
    if _MAC.search(t):
        kinds.append("mac")
    if _RINCON.search(t):
        kinds.append("rincon")
    if _UUID.search(t):
        kinds.append("uuid")
    if _HEXRUN.search(t):
        kinds.append("long_hex")
    return kinds


def _looks_private(s: str) -> bool:
    return bool(_scan_string(s, allow_ipv4=False))


def find_private_identifiers(obj: Any, canaries: Sequence[str] = (), digest_keys: Sequence[str] = ()) -> List[str]:
    """Return ``"<json-path>: <kind>"`` findings (never the matched text).

    Detects IPv4, MAC, RINCON ids, UUIDs, long hex runs, and any caller-supplied
    ``canaries`` (case-insensitive, separator-insensitive for canaries >= 6 chars).

    Two narrow, explicit exemptions (no generic masking):

    * A dotted-decimal revision such as ``1.8.3.1-2`` is IPv4-shaped, so strings under the
      ``hardware_revision``/``software_build`` fields skip the IPv4 check only.
    * A string under a *schema-defined digest key* (``DIGEST_KEYS`` plus the caller's explicit
      ``digest_keys``) skips the hex-run check only when the entire string is exactly 64
      lowercase hex characters. Anything else under a digest key, or the same hex under any
      other key, is still reported, so a secret cannot hide behind a digest-looking key.
    """
    extra = frozenset(digest_keys)
    if not all(isinstance(k, str) and _DIGEST_KEY_RE.match(k) for k in extra):
        raise IdentityError(R_RECORD, "digest_keys")
    allowed_digest_keys = DIGEST_KEYS | extra
    canon = []
    for c in canaries:
        if isinstance(c, str) and len(c.strip()) >= 3:
            cf = c.casefold()
            canon.append((cf, re.sub(r"[\s:._-]", "", cf) if len(cf) >= 6 else None))
    out: List[str] = []

    def check_str(s: str, path: str, allow_ipv4: bool, is_digest: bool) -> None:
        kinds = _scan_string(s, allow_ipv4)
        if is_digest and _DIGEST_RE.match(s):
            kinds = [k for k in kinds if k != "long_hex"]
        for k in kinds:
            out.append("%s: %s" % (path, k))
        cf = s.casefold()
        stripped = re.sub(r"[\s:._-]", "", cf)
        for plain, flat in canon:
            if plain in cf or (flat is not None and flat in stripped):
                out.append("%s: canary" % path)
                break

    def walk(node: Any, path: str, allow_ipv4: bool, is_digest: bool) -> None:
        if isinstance(node, str):
            check_str(node, path, allow_ipv4, is_digest)
        elif isinstance(node, Mapping):
            local = allow_ipv4 or node.get("field") in _VERSION_KEYS
            for k in sorted(node, key=str):
                ks = str(k)
                check_str(ks, path + ".<key>", False, False)
                walk(node[k], path + "." + ks, local or ks in _VERSION_KEYS, ks in allowed_digest_keys)
        elif isinstance(node, (list, tuple)):
            for i, v in enumerate(node):
                walk(v, "%s[%d]" % (path, i), allow_ipv4, is_digest)

    walk(obj, "$", False, False)
    return out


# --------------------------------------------------------------------------- pseudonyms
def _canon_serial(serial: Any) -> str:
    if not isinstance(serial, str):
        raise IdentityError(R_DEVICE_KEY, "serial")
    s = serial.strip()
    if not s or s.casefold() in _PLACEHOLDERS or len(s) > 64 or not s.isascii() or any(ord(c) < 32 or ord(c) == 127 for c in s):
        raise IdentityError(R_DEVICE_KEY, "serial")
    return re.sub(r"[\s:_-]+", "-", s.upper())


def _host_of(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise IdentityError(R_ADDRESS, "address")
    s = value.strip()
    if "//" not in s:
        s = "//" + s
    try:
        host = urlsplit(s).hostname
    except ValueError:
        raise IdentityError(R_ADDRESS, "address") from None
    if not host:
        raise IdentityError(R_ADDRESS, "address")
    return host.lower()


class Pseudonymizer:
    """Keyed (HMAC-SHA256) pseudonyms for serial, address and label values.

    The key is a local secret (never commit it). Low-entropy identifiers such as
    serials must not be hashed without a key, so a short or missing key is an error.
    """

    def __init__(self, key: Any):
        if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
            raise IdentityError(R_KEY, "key")
        self._key = bytes(key)

    @classmethod
    def from_env(cls, name: str = "FFW_IDENTITY_KEY") -> "Pseudonymizer":
        raw = os.environ.get(name)
        if not raw:
            raise IdentityError(R_KEY, "key")
        return cls(raw.encode("utf-8"))

    def __repr__(self) -> str:
        return "Pseudonymizer(<redacted>)"

    def _mac(self, domain: str, text: str, n: int) -> str:
        msg = ("ffw-identity/v1/%s\0%s" % (domain, text)).encode("utf-8")
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()[:n]

    def device(self, serial: Any) -> str:
        return "dev-" + self._mac("device", _canon_serial(serial), 20)

    def address(self, url_or_host: Any) -> str:
        return "adr-" + self._mac("address", _host_of(url_or_host), 12)

    def label(self, text: Any) -> str:
        if not isinstance(text, str) or not text.strip() or len(text) > 128:
            raise IdentityError(R_RECORD, "label")
        return "lbl-" + self._mac("label", re.sub(r"\s+", " ", text.strip()).casefold(), 12)


# --------------------------------------------------------------------------- data model
_SOURCE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$")
_DEV_RE = re.compile(r"^dev-[0-9a-f]{20}$")
_IMG_RE = re.compile(r"^img-[0-9a-f]{16}$")
_ORIGIN_RE = re.compile(r"^[A-Za-z0-9_.:-]{0,32}$")
_FINDING_FIELD_RE = re.compile(r"^[a-z][a-z0-9_.]{0,39}$")


@dataclasses.dataclass(frozen=True)
class Source:
    """Where a claim came from. ``synthetic`` sources must be labeled ``synthetic:...``."""

    source_id: str
    basis: str
    observed_at: Optional[str] = None
    synthetic: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.source_id, str) or not _SOURCE_ID_RE.match(self.source_id) or _looks_private(self.source_id):
            raise IdentityError(R_SOURCE, "source_id")
        if not isinstance(self.basis, str):
            raise IdentityError(R_BASIS_UNKNOWN, "basis")
        if self.basis in FORBIDDEN_BASES:
            raise IdentityError(R_ERA, "basis")
        if self.basis not in BASES:
            raise IdentityError(R_BASIS_UNKNOWN, "basis")
        if not isinstance(self.synthetic, bool) or self.synthetic != self.source_id.startswith("synthetic:"):
            raise IdentityError(R_SOURCE, "source_id", {"why": "synthetic_label_mismatch"})
        if self.observed_at is not None:
            object.__setattr__(self, "observed_at", _canon_time(self.observed_at))

    @property
    def tier(self) -> str:
        return BASES[self.basis].tier

    def to_json(self) -> Dict[str, Any]:
        return {"source_id": self.source_id, "basis": self.basis, "tier": self.tier,
                "observed_at": self.observed_at, "synthetic": self.synthetic}


@dataclasses.dataclass(frozen=True, order=True)
class Subject:
    kind: str
    ref: str

    def __post_init__(self) -> None:
        ok = False
        if isinstance(self.kind, str) and isinstance(self.ref, str):
            if self.kind == "device":
                ok = bool(_DEV_RE.match(self.ref))
            elif self.kind == "image":
                ok = bool(_IMG_RE.match(self.ref))
            elif self.kind == "model":
                ok = bool(_MODEL_RE.match(self.ref)) and self.ref == self.ref.upper()
        if not ok:
            raise IdentityError(R_SUBJECT_INVALID, "subject")

    @staticmethod
    def device(ref: str) -> "Subject":
        return Subject("device", ref)

    @staticmethod
    def image(ref: str) -> "Subject":
        return Subject("image", ref)

    @staticmethod
    def model(raw: Any) -> "Subject":
        return Subject("model", _parse_model(raw, "subject"))


def _check_placement(spec: FieldSpec, subject: Any, source: Any, qualifier: Any) -> None:
    if not isinstance(subject, Subject) or not isinstance(source, Source):
        raise IdentityError(R_RECORD, spec.name)
    basis = BASES[source.basis]
    if spec.name not in basis.fields:
        raise IdentityError(R_BASIS_FIELD, spec.name, {"basis": source.basis})
    if subject.kind not in (spec.subjects & basis.subjects):
        raise IdentityError(R_SUBJECT, spec.name, {"subject": subject.kind, "basis": source.basis})
    if qualifier not in QUALIFIERS or (qualifier != "exact" and spec.axis != "nominal_resources"):
        raise IdentityError(R_QUALIFIER, spec.name)


@dataclasses.dataclass(frozen=True)
class Claim:
    """One validated assertion. Invalid claims cannot be constructed."""

    subject: Subject
    field: str
    value: Any
    source: Source
    qualifier: str = "exact"
    origin: str = ""

    def __post_init__(self) -> None:
        spec = FIELDS.get(self.field) if isinstance(self.field, str) else None
        if spec is None:
            raise IdentityError(R_FIELD_UNKNOWN, "field")
        _check_placement(spec, self.subject, self.source, self.qualifier)
        if not isinstance(self.origin, str) or not _ORIGIN_RE.match(self.origin):
            raise IdentityError(R_RECORD, "origin")
        unit = "B" if spec.axis == "nominal_resources" else None
        try:
            canon = spec.parse(self.value, unit)
        except IdentityError:
            raise IdentityError(R_MALFORMED, spec.name, {"why": "non_canonical_value"}) from None
        if type(canon) is not type(self.value) or canon != self.value:
            raise IdentityError(R_MALFORMED, spec.name, {"why": "non_canonical_value"})

    def key(self) -> Tuple[Any, ...]:
        return (self.subject.kind, self.subject.ref, self.field, _cj(self.value), self.qualifier,
                self.source.source_id, self.source.basis, self.source.observed_at or "", self.origin)

    def to_json(self) -> Dict[str, Any]:
        return {"subject": {"kind": self.subject.kind, "ref": self.subject.ref}, "field": self.field,
                "value": self.value, "qualifier": self.qualifier, "source": self.source.to_json(),
                "origin": self.origin}


def make_claim(subject: Subject, field: str, value: Any, source: Source, *,
               qualifier: str = "exact", unit: Optional[str] = None, origin: str = "") -> Claim:
    """Strictly normalize ``value`` and build a claim, or raise ``IdentityError``."""
    spec = FIELDS.get(field) if isinstance(field, str) else None
    if spec is None:
        raise IdentityError(R_FIELD_UNKNOWN, "field")
    _check_placement(spec, subject, source, qualifier)  # basis errors outrank value errors
    return Claim(subject, field, spec.parse(value, unit), source, qualifier, origin)


@dataclasses.dataclass(frozen=True)
class Finding:
    """A rejected/absent/unusable input, kept so unknown stays visibly unknown."""

    subject: Subject
    field: str
    code: str
    source_id: str
    detail: Mapping[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.code not in REASON_CODES or not isinstance(self.field, str) or not _FINDING_FIELD_RE.match(self.field):
            raise IdentityError(R_RECORD, "finding")
        if not isinstance(self.subject, Subject) or not isinstance(self.source_id, str):
            raise IdentityError(R_RECORD, "finding")
        for k, v in self.detail.items():
            if not isinstance(k, str) or not (v is None or isinstance(v, (bool, int)) or (isinstance(v, str) and len(v) <= 40)):
                raise IdentityError(R_RECORD, "finding_detail")
        if len(_cj(dict(self.detail))) > 512:
            raise IdentityError(R_LIMIT, "finding_detail")

    def key(self) -> Tuple[Any, ...]:
        return (self.subject.kind, self.subject.ref, self.field, self.code, self.source_id, _cj(dict(self.detail)))

    def to_json(self) -> Dict[str, Any]:
        return {"field": self.field, "code": self.code, "source_id": self.source_id, "detail": dict(self.detail)}


@dataclasses.dataclass(frozen=True)
class ImageRef:
    """A firmware image known only by digest + optional metadata (never its bytes).

    ``bound_product_model`` links the image to a product model and requires a sourced
    ``binding_source``. Without it the image's architecture evidence stays unbound.
    """

    sha256: str
    internal_model_id: Optional[int] = None
    software_build: Optional[str] = None
    bound_product_model: Optional[str] = None
    binding_source: Optional[Source] = None

    def __post_init__(self) -> None:
        if not isinstance(self.sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise IdentityError(R_IMAGE_INVALID, "sha256")
        imid = self.internal_model_id
        if imid is not None and (isinstance(imid, bool) or not isinstance(imid, int) or not 0 <= imid <= 65535):
            raise IdentityError(R_IMAGE_INVALID, "internal_model_id")
        if self.software_build is not None:
            try:
                object.__setattr__(self, "software_build", _parse_build(self.software_build))
            except IdentityError:
                raise IdentityError(R_IMAGE_INVALID, "software_build") from None
        if self.bound_product_model is not None:
            try:
                object.__setattr__(self, "bound_product_model", _parse_model(self.bound_product_model, "bound_product_model"))
            except IdentityError:
                raise IdentityError(R_IMAGE_INVALID, "bound_product_model") from None
            if not isinstance(self.binding_source, Source) or self.binding_source.basis not in _BINDING_BASES:
                raise IdentityError(R_IMAGE_INVALID, "binding_source")
        elif self.binding_source is not None:
            raise IdentityError(R_IMAGE_INVALID, "binding_source")

    @property
    def image_id(self) -> str:
        return "img-" + self.sha256[:16]

    def key(self) -> Tuple[Any, ...]:
        bs = self.binding_source
        return (self.sha256, self.internal_model_id if self.internal_model_id is not None else -1,
                self.software_build or "", self.bound_product_model or "",
                bs.source_id if bs else "", bs.basis if bs else "")


@dataclasses.dataclass
class Normalized:
    """Output of one normalization call: claims + findings + non-identifying tokens."""

    device: Optional[str] = None
    claims: List[Claim] = dataclasses.field(default_factory=list)
    findings: List[Finding] = dataclasses.field(default_factory=list)
    images: List[ImageRef] = dataclasses.field(default_factory=list)
    source: Optional[Source] = None
    address_token: Optional[str] = None
    label_tokens: Tuple[str, ...] = ()
    series_hint: Optional[str] = None
    ignored_keys: int = 0


# --------------------------------------------------------------------------- normalizers
_KNOWN_FIELD_KEYS = frozenset({
    "modelNumber", "hardwareVersion", "softwareVersion", "swGen", "memory", "flash", "seriesid",
    "serialNum", "roomName", "modelName", "displayName", "zoneType",
})
_RECORD_MAP = (
    ("fields", "modelNumber", "product_model"),
    ("fields", "hardwareVersion", "hardware_revision"),
    ("fields", "softwareVersion", "software_build"),
    ("fields", "swGen", "software_generation"),
    ("status", "SWGen", "software_generation"),
    ("fields", "memory", "nominal_ram_bytes"),
    ("fields", "flash", "nominal_flash_bytes"),
)


def _finding_from_error(subject: Subject, field: str, source_id: str, err: IdentityError, raw: Any, origin: str) -> Finding:
    detail: Dict[str, Any] = {"origin": origin}
    for k in ("shape", "len", "type", "why"):
        v = err.detail.get(k)
        if v is not None:
            detail[k] = v
    if err.code == R_UNIT_UNKNOWN:
        try:
            detail["number"] = _posint(raw, field)
        except IdentityError:
            pass
    return Finding(subject, field, err.code, source_id, detail)


def normalize_record(rec: Mapping[str, Any], source: Source, pseud: Pseudonymizer, *,
                     memory_unit: Optional[str] = None) -> Normalized:
    """Normalize one ``devices.json``-shaped record.

    ``rec = {"url", "fields": {...}, "status": {...}, "observed_at"}``. Raises
    ``IdentityError`` only when the record cannot be keyed or is structurally invalid;
    individual bad/absent fields become ``Finding``s instead. ``memory_unit`` is the
    unit to apply to the XML's ``memory``/``flash`` numbers; the XML itself carries none,
    so ``None`` keeps them ``UNIT_UNKNOWN`` rather than assuming one.
    """
    if not isinstance(rec, Mapping):
        raise IdentityError(R_RECORD, "record")
    if not isinstance(source, Source) or source.basis not in _RECORD_BASES:
        raise IdentityError(R_RECORD, "source")
    if not isinstance(pseud, Pseudonymizer):
        raise IdentityError(R_RECORD, "pseudonymizer")
    if memory_unit is not None and memory_unit not in UNIT_FACTORS:
        raise IdentityError(R_UNIT_INVALID, "memory_unit")
    fields = rec.get("fields")
    status = rec.get("status")
    if status is None:
        status = {}
    if not isinstance(fields, Mapping) or not isinstance(status, Mapping):
        raise IdentityError(R_RECORD, "record")
    token = pseud.device(fields.get("serialNum"))
    subject = Subject.device(token)
    if source.observed_at is None and rec.get("observed_at") is not None:
        source = dataclasses.replace(source, observed_at=rec["observed_at"])

    claims: List[Claim] = []
    findings: List[Finding] = []
    produced: Dict[str, int] = {}
    reported: Dict[str, int] = {}
    for container, key, field in _RECORD_MAP:
        src = fields if container == "fields" else status
        raw = src.get(key)
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            continue
        origin = "%s.%s" % (container, key)
        is_size = field in ("nominal_ram_bytes", "nominal_flash_bytes")
        if is_size:
            m = _SIZE_STR_RE.match(raw.strip()) if isinstance(raw, str) else None
            if m and m.group(2) in UNIT_FACTORS:
                origin += ":src-" + m.group(2)       # unit stated by the source itself
            elif memory_unit is not None:
                origin += ":op-" + memory_unit       # unit assumed by the operator for a bare number
        try:
            unit = memory_unit if is_size else None
            claims.append(make_claim(subject, field, raw, source, unit=unit, origin=origin))
            produced[field] = produced.get(field, 0) + 1
        except IdentityError as err:
            findings.append(_finding_from_error(subject, field, source.source_id, err, raw, origin))
            reported[field] = reported.get(field, 0) + 1
    for field in sorted({f for _, _, f in _RECORD_MAP}):
        if not produced.get(field) and not reported.get(field):
            findings.append(Finding(subject, field, R_ABSENT, source.source_id, {"origin": "record"}))

    series_hint = None
    raw_series = fields.get("seriesid")
    if isinstance(raw_series, str) and raw_series.strip():
        if _SERIES_RE.match(raw_series.strip()):
            series_hint = raw_series.strip().upper()
        else:
            findings.append(Finding(subject, "series_hint", R_MALFORMED, source.source_id,
                                    {"origin": "fields.seriesid", "shape": _shape(raw_series.strip())}))

    address_token = None
    if rec.get("url") is not None:
        try:
            address_token = pseud.address(rec["url"])
        except IdentityError as err:
            findings.append(Finding(subject, "address", err.code, source.source_id, {"origin": "record.url"}))

    labels = set()
    for raw_label in (fields.get("roomName"), status.get("ZoneName")):
        if isinstance(raw_label, str) and raw_label.strip() and len(raw_label) <= 128:
            labels.add(pseud.label(raw_label))
    ignored = len([k for k in fields if k not in _KNOWN_FIELD_KEYS])
    return Normalized(device=token, claims=claims, findings=findings, images=[], source=source,
                      address_token=address_token, label_tokens=tuple(sorted(labels)),
                      series_hint=series_hint, ignored_keys=ignored)


_EM_ISA = {3: "x86", 8: "mips", 20: "powerpc", 21: "powerpc", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv"}
_EM_REQUIRES_64 = frozenset({21, 62, 183})
_EM_REQUIRES_32 = frozenset({3, 20, 40})


def normalize_elf_header(header: Any, image: ImageRef, source: Source) -> Normalized:
    """Extract ISA / endianness / word size (and ABI where the header states it).

    Never emits ``arch.soc``: an ELF header does not identify silicon. Fields the
    header does not state (e.g. MIPS float ABI, PowerPC ABI) stay unknown.
    """
    if not isinstance(source, Source) or source.basis != "elf_header":
        raise IdentityError(R_BASIS_FIELD, "basis")
    if not isinstance(image, ImageRef):
        raise IdentityError(R_RECORD, "image")
    if not isinstance(header, (bytes, bytearray, memoryview)):
        raise IdentityError(R_ELF_MALFORMED, "header", {"type": type(header).__name__})
    h = bytes(header[:64])
    if len(h) < 52 or h[:4] != b"\x7fELF":
        raise IdentityError(R_ELF_MALFORMED, "header", {"why": "magic_or_short"})
    cls, data, ver = h[4], h[5], h[6]
    if cls not in (1, 2) or data not in (1, 2) or ver != 1:
        raise IdentityError(R_ELF_MALFORMED, "header", {"why": "ident"})
    if cls == 2 and len(h) < 64:
        raise IdentityError(R_ELF_MALFORMED, "header", {"why": "short_elf64"})
    end = "<" if data == 1 else ">"
    e_type, e_machine = struct.unpack_from(end + "HH", h, 16)
    (e_flags,) = struct.unpack_from(end + "I", h, 36 if cls == 1 else 48)
    if e_type not in (1, 2, 3):
        raise IdentityError(R_ELF_MALFORMED, "header", {"why": "e_type"})
    if (e_machine in _EM_REQUIRES_64 and cls != 2) or (e_machine in _EM_REQUIRES_32 and cls != 1):
        raise IdentityError(R_ELF_INCONSISTENT, "header", {"why": "class_vs_machine"})

    subject = Subject.image(image.image_id)
    origin = "elf.header"
    findings: List[Finding] = []
    claims: List[Claim] = []
    bits = 32 if cls == 1 else 64
    claims.append(make_claim(subject, "arch.endianness", "little" if data == 1 else "big", source, origin=origin))
    claims.append(make_claim(subject, "arch.word_bits", bits, source, origin=origin))
    isa = _EM_ISA.get(e_machine)
    if isa is None:
        findings.append(Finding(subject, "arch.isa", R_ISA_UNRECOGNIZED, source.source_id, {"origin": origin}))
    else:
        claims.append(make_claim(subject, "arch.isa", isa, source, origin=origin))
    abi = None
    if e_machine == 8:
        if e_flags & 0x20:
            abi = "n32"
        elif (e_flags & 0xF000) == 0x1000:
            abi = "o32"
        elif (e_flags & 0xF000) == 0x2000:
            abi = "o64"
        elif cls == 2:
            abi = "n64"
    elif e_machine == 40 and (e_flags & 0xFF000000) == 0x05000000:
        abi = "eabi"
    if abi is not None:
        claims.append(make_claim(subject, "arch.abi", abi, source, origin=origin))
    if e_machine == 40 and (e_flags & 0xFF000000) == 0x05000000:
        if e_flags & 0x400:
            claims.append(make_claim(subject, "arch.float_abi", "hard", source, origin=origin))
        elif e_flags & 0x200:
            claims.append(make_claim(subject, "arch.float_abi", "soft", source, origin=origin))
    return Normalized(device=None, claims=claims, findings=findings, images=[image], source=source)


# --------------------------------------------------------------------------- resolution
def _tier(c: Claim) -> str:
    return BASES[c.source.basis].tier


def _is_synth(c: Claim, tainted: frozenset = frozenset()) -> bool:
    return c.source.synthetic or c.key() in tainted


def _prov(c: Claim, tainted: frozenset = frozenset()) -> Dict[str, Any]:
    subj = c.subject.kind if c.subject.kind != "image" else "image:" + c.subject.ref
    return {"source_id": c.source.source_id, "basis": c.source.basis, "tier": _tier(c),
            "observed_at": c.source.observed_at, "synthetic": _is_synth(c, tainted),
            "tainted_by_synthetic_binding": (not c.source.synthetic) and c.key() in tainted,
            "origin": c.origin, "subject": subj}


def _provs(claims: Iterable[Claim], tainted: frozenset = frozenset()) -> List[Dict[str, Any]]:
    seen = {}
    for c in claims:
        p = _prov(c, tainted)
        seen[_cj(p)] = p
    return [seen[k] for k in sorted(seen)]


def _group(claims: Iterable[Claim]) -> List[Tuple[Any, List[Claim]]]:
    g: Dict[str, Tuple[Any, List[Claim]]] = {}
    for c in claims:
        g.setdefault(_cj(c.value), (c.value, []))[1].append(c)
    return [g[k] for k in sorted(g)]


def _violates(value: Any, bound: Claim) -> bool:
    return value > bound.value if bound.qualifier == "upper_bound" else value < bound.value


def _resolve_mutable(bind: List[Claim]) -> Tuple[str, Any, List[Dict[str, Any]], List[str]]:
    if not bind:
        return "unknown", None, [], []
    groups = _group(bind)
    if len(groups) == 1:
        return "resolved", groups[0][0], [], []
    if any(c.source.observed_at is None for c in bind):
        return "conflict", None, [], [R_UNORDERABLE, R_CONFLICT]
    by_time: Dict[str, List[Claim]] = {}
    for c in bind:
        by_time.setdefault(c.source.observed_at, []).append(c)  # type: ignore[arg-type]
    times = sorted(by_time)
    history = [{"observed_at": t, "values": [v for v, _ in _group(by_time[t])]} for t in times]
    latest = _group(by_time[times[-1]])
    if len(latest) > 1:
        return "conflict", None, history, [R_CONFLICT]
    return "resolved", latest[0][0], history, [R_CHANGED]


def _unit_notes(findings: Sequence[Finding], value: Any) -> List[Dict[str, Any]]:
    notes: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        if f.code != R_UNIT_UNKNOWN:
            continue
        n = f.detail.get("number")
        units = sorted(u for u, k in UNIT_FACTORS.items() if value is not None and isinstance(n, int) and n * k == value)
        entry = {"number": n, "source_id": f.source_id, "consistent_with_units": units}
        notes[_cj(entry)] = entry
    return [notes[k] for k in sorted(notes)]


def _resolve_field(spec: FieldSpec, claims: Sequence[Claim], findings: Sequence[Finding],
                   tainted: frozenset = frozenset()) -> Dict[str, Any]:
    exact = [c for c in claims if c.qualifier == "exact"]
    bounds = [c for c in claims if c.qualifier != "exact"]
    bind = [c for c in exact if _tier(c) != "hypothesis"]
    hyp = [c for c in exact if _tier(c) == "hypothesis"]
    bbound = [c for c in bounds if _tier(c) != "hypothesis"]
    hbound = [c for c in bounds if _tier(c) == "hypothesis"]
    reasons: List[str] = []
    history: List[Dict[str, Any]] = []
    value: Any = None

    if spec.mutable:
        status, value, history, reasons = _resolve_mutable(bind)
    else:
        groups = _group(bind)
        if len(groups) == 1:
            status, value = "resolved", groups[0][0]
        elif len(groups) > 1:
            status = "conflict"
            reasons.append(R_CONFLICT)
        else:
            status = "unknown"
    if status == "unknown":
        hgroups = _group(hyp)
        if hgroups:
            status = "hypothesis_only"
            reasons = [R_HYPOTHESIS_ONLY] + ([R_HYPOTHESES_DISAGREE] if len(hgroups) > 1 else [])
        else:
            reasons.append(R_NO_EVIDENCE)

    if status == "resolved" and bbound:
        if any(_violates(value, b) for b in bbound):
            status, value = "conflict", None
            reasons.append(R_BOUND_VIOLATED)
    lowers = [b.value for b in bbound if b.qualifier == "lower_bound"]
    uppers = [b.value for b in bbound if b.qualifier == "upper_bound"]
    if lowers and uppers and max(lowers) > min(uppers) and status != "conflict":
        status, value = "conflict", None
        reasons.append(R_BOUND_VIOLATED)

    contradicted: List[Dict[str, Any]] = []
    if status == "resolved":
        for v, cs in _group(hyp):
            if v != value:
                contradicted.append({"value": v, "qualifier": "exact", "sources": _provs(cs, tainted)})
        for hb in hbound:
            if _violates(value, hb):
                contradicted.append({"value": hb.value, "qualifier": hb.qualifier, "sources": _provs([hb], tainted)})

    supporting = [c for c in bind if status == "resolved" and c.value == value]
    synthetic_only = bool(supporting) and all(_is_synth(c, tainted) for c in supporting)

    cand = []
    for qualifier in QUALIFIERS:
        for v, cs in _group([c for c in claims if c.qualifier == qualifier]):
            tier = min((_tier(c) for c in cs), key=lambda t: _TIER_RANK[t])
            cand.append({"value": v, "qualifier": qualifier, "tier": tier, "sources": _provs(cs, tainted)})
    cand.sort(key=lambda c: (_TIER_RANK[c["tier"]], c["qualifier"], _cj(c["value"])))

    if status == "conflict":
        reasons = [r for r in reasons if r != R_NO_EVIDENCE]  # evidence exists; it just disagrees
    elif status != "resolved":
        reasons.extend(f.code for f in findings)  # unusable inputs explain why nothing resolved
    return {
        "field": spec.name,
        "status": status,
        "value": value if status == "resolved" else None,
        "reason_codes": sorted(set(reasons)),
        "synthetic_only": synthetic_only,
        "candidates": cand,
        "history": history,
        "contradicted_hypotheses": contradicted,
        "input_findings": [f.to_json() for f in sorted(findings, key=lambda f: f.key())],
        "unit_unknown_numbers": _unit_notes(findings, value) if spec.axis == "nominal_resources" else [],
    }


_ARCH_CONSISTENCY = {
    "x86": ({"little"}, {32}),
    "x86_64": ({"little"}, {64}),
    "aarch64": ({"little", "big"}, {64}),
}


def _check_required(required: Sequence[str]) -> Tuple[str, ...]:
    allowed = set(PROFILE_FIELDS) | {"product_model", "hardware_revision"}
    if not isinstance(required, (list, tuple, set, frozenset)) or not all(isinstance(f, str) and f in allowed for f in required):
        raise IdentityError(R_FIELD_UNKNOWN, "required")
    return tuple(sorted(set(required)))


def _image_key_meta(ims: Sequence[ImageRef]) -> Dict[str, Any]:
    models = sorted({i.bound_product_model for i in ims if i.bound_product_model})
    ids = sorted({i.internal_model_id for i in ims if i.internal_model_id is not None})
    builds = sorted({i.software_build for i in ims if i.software_build})
    return {"models": models, "internal_ids": ids, "builds": builds}


def _device_category(claims: Sequence[Claim]) -> str:
    if not claims:
        return "other_unverified"
    if all(c.source.synthetic for c in claims):
        return "synthetic_only"
    real = [c for c in claims if not c.source.synthetic]
    if any(_tier(c) == "observed" for c in real):
        return "independent_observation"
    if any(c.source.basis == "peer_report" for c in real):
        return "peer_reported_only"
    return "other_unverified"


def profile_id_for(product_model: str, hardware_revision: str) -> str:
    """Stable board-profile id: a function of (product model, hardware revision) only.

    The single shared formula for identity, reconcile and enrich. Inputs are validated and
    canonicalised first (``"s5"``/``"01.008.3.1-02"`` give the same id as ``"S5"``/``"1.8.3.1-2"``);
    an absent, placeholder or malformed value raises ``IdentityError`` rather than hashing garbage.
    Callers with an unresolved axis must not call this: no id exists without both.
    """
    return "bp-" + _sha(_cj({"schema": SCHEMA, "kind": "board-profile-id",
                             "product_model": _parse_model(product_model, "product_model"),
                             "hardware_revision": _parse_revision(hardware_revision)}))[:16]


class Fleet:
    """Resolved, sanitized identity document (schema ``ffw.identity/v1``)."""

    def __init__(self, doc: Dict[str, Any]):
        self._doc = doc

    def to_public_json(self) -> Dict[str, Any]:
        return copy.deepcopy(self._doc)

    def to_json(self) -> str:
        return json.dumps(self._doc, sort_keys=True, indent=2, ensure_ascii=True)

    def to_aggregate_json(self) -> Dict[str, Any]:
        """Publishable view: counts and per-profile resolution only.

        No per-device record, device/address/label pseudonym, member list or per-device digest.
        Because nothing keyed survives, this view is independent of the ``Pseudonymizer`` key:
        the same evidence yields byte-identical output under any key, so publishing it reveals
        nothing about identifiers and a later key leak cannot unmask it. Unassigned devices are
        summarised as reason-code counts. Use ``to_public_json`` only for private, local reports.
        """
        d = copy.deepcopy(self._doc)
        counts: Dict[str, int] = {}
        for dev in d.pop("devices"):
            for r in dev["unassigned_reasons"]:
                counts[r] = counts.get(r, 0) + 1
        d.pop("fleet_digest")
        for p in d["profiles"]:
            p.pop("member_devices")
            p.pop("evidence_digest")
            p["aggregate_evidence_digest"] = _sha(_cj(p))
        d["view"] = "aggregate"
        d["unassigned_reason_counts"] = dict(sorted(counts.items()))
        d["aggregate_digest"] = _sha(_cj(d))
        if find_private_identifiers(d):
            raise IdentityError(R_LEAK, "output")
        return d

    @property
    def digest(self) -> str:
        return self._doc["fleet_digest"]

    def profile(self, profile_id: str) -> Optional[Dict[str, Any]]:
        for p in self._doc["profiles"]:
            if p["profile_id"] == profile_id:
                return copy.deepcopy(p)
        return None

    def device(self, token: str) -> Optional[Dict[str, Any]]:
        for d in self._doc["devices"]:
            if d["device"] == token:
                return copy.deepcopy(d)
        return None


def resolve_fleet(batches: Iterable[Normalized], *, required: Sequence[str] = DEFAULT_REQUIRED) -> Fleet:
    req = _check_required(required)
    claim_map: Dict[Tuple[Any, ...], Claim] = {}
    finding_map: Dict[Tuple[Any, ...], Finding] = {}
    image_map: Dict[Tuple[Any, ...], ImageRef] = {}
    dev_meta: Dict[str, Dict[str, set]] = {}

    for b in batches:
        if not isinstance(b, Normalized):
            raise IdentityError(R_RECORD, "batch")
        for c in b.claims:
            if not isinstance(c, Claim):
                raise IdentityError(R_RECORD, "claim")
            claim_map.setdefault(c.key(), c)
        if len(claim_map) > MAX_CLAIMS:
            raise IdentityError(R_LIMIT, "claims")
        for f in b.findings:
            if not isinstance(f, Finding):
                raise IdentityError(R_RECORD, "finding")
            finding_map.setdefault(f.key(), f)
        for im in b.images:
            if not isinstance(im, ImageRef):
                raise IdentityError(R_RECORD, "image")
            image_map.setdefault(im.key(), im)
        if b.device is not None:
            Subject.device(b.device)  # validates shape
            m = dev_meta.setdefault(b.device, {"addr": set(), "labels": set(), "series": set(), "obs": set()})
            if b.address_token:
                m["addr"].add(b.address_token)
            m["labels"].update(b.label_tokens)
            if b.series_hint:
                m["series"].add(b.series_hint)
            if b.source is not None:
                m["obs"].add((b.source.source_id, b.source.observed_at or ""))

    dev_claims: Dict[str, List[Claim]] = {}
    model_claims: Dict[str, List[Claim]] = {}
    image_claims: Dict[str, List[Claim]] = {}
    for c in sorted(claim_map.values(), key=Claim.key):
        target = {"device": dev_claims, "model": model_claims, "image": image_claims}[c.subject.kind]
        target.setdefault(c.subject.ref, []).append(c)
    dev_findings: Dict[str, List[Finding]] = {}
    for f in sorted(finding_map.values(), key=Finding.key):
        if f.subject.kind == "device":
            dev_findings.setdefault(f.subject.ref, []).append(f)
        else:
            dev_findings.setdefault("image:" + f.subject.ref, []).append(f)
    devices = sorted(set(dev_meta) | set(dev_claims) | {k for k in dev_findings if not k.startswith("image:")})

    # ---- images: binding + conflicts
    by_sha: Dict[str, List[ImageRef]] = {}
    for im in sorted(image_map.values(), key=ImageRef.key):
        by_sha.setdefault(im.sha256, []).append(im)
    image_state: Dict[str, Dict[str, Any]] = {}
    image_findings: List[Dict[str, Any]] = []
    for sha, ims in sorted(by_sha.items()):
        iid = "img-" + sha[:16]
        meta = _image_key_meta(ims)
        state = {"image_id": iid, "bound_model": None, "reason": None, "binding_sources": [], "binding_synthetic": False}
        if len(meta["internal_ids"]) > 1 or len(meta["builds"]) > 1:
            image_findings.append({"code": R_IMAGE_META_CONFLICT, "image_ids": [iid], "detail": {}})
        if len(meta["models"]) == 1:
            state["bound_model"] = meta["models"][0]
            state["binding_sources"] = sorted({i.binding_source.source_id for i in ims if i.binding_source})
            state["binding_synthetic"] = all(i.binding_source.synthetic for i in ims if i.binding_source)
        elif len(meta["models"]) > 1:
            state["reason"] = R_IMAGE_BINDING_CONFLICT
            image_findings.append({"code": R_IMAGE_BINDING_CONFLICT, "image_ids": [iid],
                                   "detail": {"models": meta["models"]}})
        else:
            state["reason"] = R_IMAGE_UNBOUND
        state["internal_id"] = meta["internal_ids"][0] if len(meta["internal_ids"]) == 1 else None
        state["build"] = meta["builds"][0] if len(meta["builds"]) == 1 else None
        image_state[iid] = state
    by_meta: Dict[Tuple[int, str], List[str]] = {}
    for iid, st in image_state.items():
        if st["internal_id"] is not None and st["build"] is not None:
            by_meta.setdefault((st["internal_id"], st["build"]), []).append(iid)
    digest_conflict_models = set()
    for (imid, build), iids in sorted(by_meta.items()):
        if len(iids) > 1:
            image_findings.append({"code": R_IMAGE_DIGEST_CONFLICT, "image_ids": sorted(iids),
                                   "detail": {"internal_model_id": imid, "software_build": build}})
            for iid in iids:
                if image_state[iid]["bound_model"]:
                    digest_conflict_models.add(image_state[iid]["bound_model"])
    for f in sorted(finding_map.values(), key=Finding.key):
        if f.subject.kind == "image":
            image_findings.append({"code": f.code, "image_ids": [f.subject.ref], "detail": dict(f.detail, field=f.field)})
    image_findings.sort(key=_cj)

    # ---- device-level resolution (identity axes)
    dev_docs: Dict[str, Dict[str, Any]] = {}
    members: Dict[Tuple[str, str], List[str]] = {}
    for tok in devices:
        cl = dev_claims.get(tok, [])
        fl = dev_findings.get(tok, [])
        res = {f: _resolve_field(FIELDS[f], [c for c in cl if c.field == f], [x for x in fl if x.field == f])
               for f in DEVICE_FIELDS}
        m_res, r_res = res["product_model"], res["hardware_revision"]
        unassigned = []
        for f in ("product_model", "hardware_revision"):
            if res[f]["status"] != "resolved":
                unassigned.extend("%s:%s" % (f, code) for code in res[f]["reason_codes"])
        pid = None
        if not unassigned:
            pid = profile_id_for(m_res["value"], r_res["value"])
            members.setdefault((m_res["value"], r_res["value"]), []).append(tok)
        meta = dev_meta.get(tok, {"addr": set(), "labels": set(), "series": set(), "obs": set()})
        dev_docs[tok] = {
            "device": tok,
            "verification": _device_category(cl),
            "fields": res,
            "profile_id": pid,
            "unassigned_reasons": sorted(set(unassigned)),
            "unattached_claim_fields": sorted({c.field for c in cl if c.field in PROFILE_FIELDS}) if pid is None else [],
            "series_hints": sorted(meta["series"]),
            "address_tokens": sorted(meta["addr"]),
            "label_tokens": sorted(meta["labels"]),
            "observation_count": len(meta["obs"]),
            "findings": [f.to_json() for f in fl],
        }

    # ---- profiles (board-level architecture + nominal resources)
    models_with_profiles = {m for (m, _r) in members}
    bound_by_model: Dict[str, List[str]] = {}
    for iid, st in sorted(image_state.items()):
        if st["bound_model"]:
            bound_by_model.setdefault(st["bound_model"], []).append(iid)
    profiles = []
    for (model, rev), toks in sorted(members.items()):
        pooled: Dict[str, List[Claim]] = {f: [] for f in PROFILE_FIELDS}
        pooled_f: Dict[str, List[Finding]] = {f: [] for f in PROFILE_FIELDS}
        tainted = set()
        for tok in toks:
            for c in dev_claims.get(tok, []):
                if c.field in pooled:
                    pooled[c.field].append(c)
            for x in dev_findings.get(tok, []):
                if x.field in pooled_f:
                    pooled_f[x.field].append(x)
        for iid in bound_by_model.get(model, []):
            bind_synth = image_state[iid]["binding_synthetic"]
            for c in image_claims.get(iid, []):
                pooled[c.field].append(c)
                if bind_synth:
                    tainted.add(c.key())
            for x in dev_findings.get("image:" + iid, []):
                if x.field in pooled_f:
                    pooled_f[x.field].append(x)
        for c in model_claims.get(model, []):
            pooled[c.field].append(c)
        frozen_taint = frozenset(tainted)
        fres = {f: _resolve_field(FIELDS[f], pooled[f], pooled_f[f], frozen_taint) for f in PROFILE_FIELDS}

        blocking: List[str] = []
        for f in sorted(set(req) | set(PROFILE_FIELDS)):
            if f in ("product_model", "hardware_revision"):
                continue
            r = fres[f]
            if f in req:
                if r["status"] != "resolved":
                    blocking.extend("%s:%s" % (f, c) for c in (r["reason_codes"] or [r["status"].upper()]))
                elif r["synthetic_only"]:
                    blocking.append("%s:%s" % (f, R_SYNTHETIC_ONLY))
            elif r["status"] == "conflict":
                blocking.extend("%s:%s" % (f, c) for c in (r["reason_codes"] or [R_CONFLICT]))
        iso, endi, bits = (fres[k]["value"] for k in ("arch.isa", "arch.endianness", "arch.word_bits"))
        rule = _ARCH_CONSISTENCY.get(iso)
        if rule and ((endi is not None and endi not in rule[0]) or (bits is not None and bits not in rule[1])):
            blocking.append("arch:" + R_ARCH_INCONSISTENT)
        if model in digest_conflict_models:
            blocking.append("profile:" + R_IMAGE_DIGEST_CONFLICT)
        blocking = sorted(set(blocking))

        cats: Dict[str, int] = {"independent_observation": 0, "peer_reported_only": 0, "synthetic_only": 0, "other_unverified": 0}
        for tok in toks:
            cats[dev_docs[tok]["verification"]] += 1
        body = {
            "profile_id": profile_id_for(model, rev),
            "product_model": model,
            "hardware_revision": rev,
            "device_count": len(toks),
            "member_devices": sorted(toks),
            "verification": cats,
            "fields": fres,
            "bound_images": sorted(bound_by_model.get(model, [])),
            "activation_eligible": not blocking,
            "blocking_reasons": blocking,
        }
        body["evidence_digest"] = _sha(_cj(body))
        profiles.append(body)

    # ---- model roll-up (family trap guard: keyed by modelNumber, never by marketing name)
    models = []
    for model in sorted({d["fields"]["product_model"]["value"] for d in dev_docs.values()
                         if d["fields"]["product_model"]["status"] == "resolved"}):
        ds = [d for d in dev_docs.values() if d["fields"]["product_model"]["value"] == model]
        models.append({
            "product_model": model,
            "device_count": len(ds),
            "profile_ids": sorted({d["profile_id"] for d in ds if d["profile_id"]}),
            "devices_without_profile": sum(1 for d in ds if d["profile_id"] is None),
            "series_hints": sorted({h for d in ds for h in d["series_hints"]}),
            "hardware_revisions": sorted({d["fields"]["hardware_revision"]["value"] for d in ds
                                          if d["fields"]["hardware_revision"]["status"] == "resolved"}),
        })

    # ---- unbound / orphaned image evidence
    unbound = []
    for iid in sorted(set(image_claims) | set(image_state)):
        st = image_state.get(iid)
        cl = image_claims.get(iid, [])
        if not cl:
            continue
        if st is None:
            reason = R_IMAGE_UNBOUND
        elif st["bound_model"] is None:
            reason = st["reason"]
        elif st["bound_model"] not in models_with_profiles:
            reason = R_BOUND_MODEL_ABSENT
        else:
            continue
        unbound.append({
            "image_id": iid, "reason": reason,
            "claims": [{"field": f, "value": v, "sources": _provs(cs2)}
                       for f in sorted({c.field for c in cl})
                       for v, cs2 in _group([c for c in cl if c.field == f])],
        })

    # ---- denominators + document
    cats = {"independent_observation": 0, "peer_reported_only": 0, "synthetic_only": 0, "other_unverified": 0}
    for d in dev_docs.values():
        cats[d["verification"]] += 1
    counts: Dict[str, int] = {}
    for f in finding_map.values():
        counts[f.code] = counts.get(f.code, 0) + 1
    any_synth = any(c.source.synthetic for c in claim_map.values())
    doc: Dict[str, Any] = {
        "schema": SCHEMA,
        "synthetic": any_synth,
        "required_fields": list(req),
        "denominators": {
            "devices_total": len(dev_docs),
            **cats,
            "devices_without_profile": sum(1 for d in dev_docs.values() if d["profile_id"] is None),
            "profiles_total": len(profiles),
            "profiles_activation_eligible": sum(1 for p in profiles if p["activation_eligible"]),
            "profiles_blocked": sum(1 for p in profiles if not p["activation_eligible"]),
            "claims_total": len(claim_map),
            "findings_total": len(finding_map),
        },
        "models": models,
        "profiles": profiles,
        "devices": [dev_docs[t] for t in sorted(dev_docs)],
        "unbound_evidence": unbound,
        "image_findings": image_findings,
        "finding_counts": dict(sorted(counts.items())),
    }
    doc["fleet_digest"] = _sha(_cj(doc))
    leaks = find_private_identifiers(doc)
    if leaks:
        raise IdentityError(R_LEAK, "output", {"count": len(leaks)})
    return Fleet(doc)
