"""Expected output of `franken-speaker --catalog`, derived from the Rust source, and the judge for a guest's output.

Used by `run-qemu-verification.py` for the franken-speaker smoke (E07 runner change). Nothing here is a guest
measurement: it states what the guest must print and checks what it did print.

Where the expectation comes from
--------------------------------
`--catalog` prints `serde_json::to_string_pretty(&canonical_board_catalog())` (crates/franken-speaker/src/main.rs).
The catalog rows are the `HypothesisSpec` literals in `canonical_board_catalog()` in
`crates/franken-board-profile/src/lib.rs`; this module parses those literals, so the expectation changes when the
source does and is never a copy that can drift. For each row it expects the identity fields the literal states
(`model_number`, `model_name`, `supported_hw_rev`, `legacy_sw_gen_hint`, `cpu_isa`, `facts.isa`), the capacity
the `device_reported_capacity_mib` table gives for that model, and the `profile_id` that `profile_id_for` derives.

Two digests are recomputed here in Python from the guest's own printed row, independent of the guest's SHA-256:

* `profile_id` = `bp-` + first 16 hex of SHA-256 of the compact key-sorted JSON built from the canonical model and
  revision. The replication is validated against the two golden ids committed in `lib.rs` and
  `inventory/test_identity.py` (`test_speaker_smoke.py`).
* `integrity_sha256` = SHA-256 of `serde_json::to_vec(row with integrity_sha256 = "")`: the compact JSON of the
  row in field order. This one has no committed vector. It is validated by running `--check-catalog` on the HOST
  build's `--catalog` output first (a positive control): if that does not pass, the replication is wrong, not the
  guest. On a big-endian guest it is a real computation (the guest hashed each row with its own SHA-256).

What this does not establish: nothing here exercises floating point (the catalog has no floats), networking or
audio, and the guest is a generic QEMU machine, not Sonos silicon.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
from typing import Any

CATALOG_SOURCE = "crates/franken-board-profile/src/lib.rs"

SPEAKER_PATH = "/franken-speaker"
SPEAKER_ARG = "--catalog"
BEGIN_LINE = f"FFW_SPEAKER_BEGIN path={SPEAKER_PATH} argv={SPEAKER_ARG}"

# The wire grammar printed by ffw-hello-init/src/speaker_judge.rs. The example lines in
# toolchain/tests/test_speaker_smoke.py are the same strings the Rust unit tests assert.
EXIT_OK = re.compile(r"FFW_SPEAKER_EXIT status=0 stdout_bytes=([1-9][0-9]*) stdout_fnv1a64=([0-9a-f]{16})")
_PAIR = r"stdout_bytes=[0-9]+ stdout_fnv1a64=[0-9a-f]{16}"
EXIT_FAILURE = re.compile(
    r"FFW_SPEAKER_EXIT (?:"
    r"spawn=(?:pipe|fork|exec) errno=[0-9]+"
    rf"|(?:status=[1-9][0-9]*|signal=[0-9]+|read_error=[0-9]+|wait_error=[0-9]+|wait_status=[0-9]+"
    rf"|exec_probe_error=[0-9]+) {_PAIR}"
    rf"|status=0 stdout_bytes=0 stdout_fnv1a64=[0-9a-f]{{16}}"   # exit 0 with an empty stdout shows nothing
    r")"
)

FNV64_OFFSET = 0xCBF29CE484222325
FNV64_PRIME = 0x100000001B3
_MASK64 = (1 << 64) - 1


def fnv1a64(data: bytes) -> int:
    value = FNV64_OFFSET
    for byte in data:
        value ^= byte
        value = (value * FNV64_PRIME) & _MASK64
    return value


# ---- the Rust helpers this replicates ---------------------------------------------------------------------


def serde_snake_case(variant: str) -> str:
    """serde's `rename_all = "snake_case"` for a variant name: an underscore before every uppercase letter that is
    not first, then lowercase. Digits are not uppercase, so `Mips32R2BigEndian` is `mips32_r2_big_endian`."""
    out = []
    for index, char in enumerate(variant):
        if index > 0 and char.isupper():
            out.append("_")
        out.append(char.lower())
    return "".join(out)


def canonical_model_number(raw: str) -> str:
    """`canonical_model_number`: trimmed, 1-24 ASCII alphanumerics plus `_ . -`, first one alphanumeric, upper-cased."""
    text = raw.strip()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,23}", text) is None:
        raise ValueError(f"not a canonical model number: {raw!r}")
    return text.upper()


def _canonical_dotted(part: str, low: int, high: int) -> str:
    components = part.split(".")
    if not low <= len(components) <= high:
        raise ValueError(f"wrong component count in {part!r}")
    out = []
    for component in components:
        if not component or len(component) > 5 or not component.isascii() or not component.isdigit():
            raise ValueError(f"bad component {component!r} in {part!r}")
        out.append(str(int(component)))
    return ".".join(out)


def canonical_hardware_revision(raw: str) -> str:
    """`canonical_hardware_revision`: 1-6 dotted numbers, optionally `-` and 1-4 dotted numbers, leading zeros removed."""
    text = raw.strip()
    if not text or len(text) > 32:
        raise ValueError(f"not a canonical hardware revision: {raw!r}")
    main, dash, suffix = text.partition("-")
    result = _canonical_dotted(main, 1, 6)
    return f"{result}-{_canonical_dotted(suffix, 1, 4)}" if dash else result


def profile_id_for(model_number: str, hw_rev: str) -> str:
    model = canonical_model_number(model_number)
    revision = canonical_hardware_revision(hw_rev)
    canonical = (
        '{"hardware_revision":"%s","kind":"board-profile-id","product_model":"%s","schema":"ffw.identity/v1"}'
        % (revision, model)
    )
    return "bp-" + hashlib.sha256(canonical.encode("ascii")).hexdigest()[:16]


def integrity_digest(row: dict[str, Any]) -> str:
    """`BoardProfile::compute_digest`: SHA-256 of the compact JSON of the row with `integrity_sha256` cleared."""
    cleared = dict(row)
    cleared["integrity_sha256"] = ""
    compact = json.dumps(cleared, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(compact.encode("utf-8")).hexdigest()


# ---- reading the expectation out of the Rust source --------------------------------------------------------


def _function_body(source: str, signature: str) -> str:
    """Text between the braces of the function whose header starts with `signature`; string literals and `//`
    comments are skipped while matching braces."""
    start = source.find(signature)
    if start < 0:
        raise ValueError(f"function not found in the catalog source: {signature!r}")
    brace = source.index("{", start)
    depth, index = 1, brace + 1
    while depth:
        char = source[index]
        if char == '"':
            index += 1
            while source[index] != '"':
                index += 2 if source[index] == "\\" else 1
        elif char == "/" and source.startswith("//", index):
            index = source.index("\n", index)
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        index += 1
    return source[brace + 1:index - 1]


def _field(chunk: str, pattern: str, name: str) -> str:
    match = re.search(pattern, chunk)
    if match is None:
        raise ValueError(f"catalog literal has no {name}: {chunk[:80]!r}")
    return match.group(1)


def expected_catalog(source: str) -> dict[str, Any]:
    """The rows `--catalog` must print, from the text of `crates/franken-board-profile/src/lib.rs`."""
    schema = _field(source, r'pub const BOARD_PROFILE_SCHEMA_VERSION: &str = "([^"]+)";', "schema version")
    body = _function_body(source, "pub fn canonical_board_catalog() -> Vec<BoardProfile> {")
    capacity_body = _function_body(source, "fn device_reported_capacity_mib(")
    capacities: dict[str, tuple[int, int]] = {}
    for match in re.finditer(r'((?:"[^"]+"\s*\|?\s*)+)=>\s*Some\(\((\d+),\s*(\d+)\)\)', capacity_body):
        for name in re.findall(r'"([^"]+)"', match.group(1)):
            capacities[name] = (int(match.group(2)), int(match.group(3)))

    chunks = re.findall(r"hypothesis_profile\(HypothesisSpec \{(.*?)\}\)", body, re.S)
    if not chunks or len(chunks) != body.count("hypothesis_profile("):
        raise ValueError("catalog rows are not all HypothesisSpec literals; the extractor must be updated")
    rows = []
    for chunk in chunks:
        model = _field(chunk, r'model_number:\s*"([^"]+)"', "model_number")
        revision = _field(chunk, r'hw_rev:\s*"([^"]+)"', "hw_rev")
        capacity = capacities.get(canonical_model_number(model))
        if capacity is None:
            raise ValueError(f"no device-reported capacity for model {model!r}")
        rows.append({
            "schema_version": schema,
            "profile_id": profile_id_for(model, revision),
            "model_number": model,
            "model_name": _field(chunk, r'model_name:\s*"([^"]+)"', "model_name"),
            "supported_hw_rev": revision,
            "legacy_sw_gen_hint": int(_field(chunk, r"sw_gen_hint:\s*(\d+)", "sw_gen_hint")),
            "cpu_isa": serde_snake_case(_field(chunk, r"(?<![A-Za-z_])isa:\s*CpuIsa::(\w+)", "isa")),
            "facts.isa": serde_snake_case(_field(chunk, r"isa_status:\s*FactStatus::(\w+)", "isa_status")),
            "nominal_ram_mib": capacity[0],
            "nominal_flash_mib": capacity[1],
        })
    return {"source": CATALOG_SOURCE, "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            "schema_version": schema, "rows": rows}


def load_expected(repo_root: pathlib.Path) -> dict[str, Any]:
    return expected_catalog((repo_root / CATALOG_SOURCE).read_text(encoding="utf-8"))


# ---- judging output ----------------------------------------------------------------------------------------


def _dig(row: dict[str, Any], dotted: str) -> Any:
    value: Any = row
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def judge_catalog(stdout: bytes, expected: dict[str, Any]) -> list[str]:
    """Problems with a `--catalog` output against the source-derived expectation; empty means it holds.

    Every row is checked field by field and in catalog order, and each row's `integrity_sha256` is recomputed from
    the row as printed."""
    try:
        text = stdout.decode("utf-8")
    except UnicodeDecodeError:
        return ["not_utf8"]
    try:
        rows = json.loads(text)
    except ValueError as error:
        return [f"json_invalid:{error}"]
    if not isinstance(rows, list):
        return ["json_not_a_list"]
    wanted = expected["rows"]
    problems = []
    if len(rows) != len(wanted):
        problems.append(f"row_count:{len(rows)}!={len(wanted)}")
    for index, (got, want) in enumerate(zip(rows, wanted)):
        if not isinstance(got, dict):
            problems.append(f"row{index}:not_an_object")
            continue
        for key, value in want.items():
            actual = _dig(got, key)
            if actual != value:
                problems.append(f"row{index}.{key}:{actual!r}!={value!r}")
        if got.get("integrity_sha256") != integrity_digest(got):
            problems.append(f"row{index}.integrity_sha256")
    return problems


def stdout_region(raw_log: str) -> tuple[bytes | None, str | None]:
    """The bytes the child wrote, reconstructed from the console transcript: every line between the single BEGIN
    and the single EXIT line, with the console's CRLF mapped back to LF. Returns (bytes, None) or (None, reason).

    Lines are not stripped: JSON indentation is part of the bytes the guest measured."""
    lines = [line[:-1] if line.endswith("\r") else line for line in raw_log.split("\n")]
    begins = [i for i, line in enumerate(lines) if line.strip().startswith("FFW_SPEAKER_BEGIN ")]
    exits = [i for i, line in enumerate(lines) if line.strip().startswith("FFW_SPEAKER_EXIT ")]
    if len(begins) != 1 or len(exits) != 1:
        return None, "begin_or_exit_not_exactly_once"
    if begins[0] >= exits[0]:
        return None, "exit_before_begin"
    text = "".join(line + "\n" for line in lines[begins[0] + 1:exits[0]])
    if "�" in text:
        return None, "not_utf8"
    return text.encode("utf-8"), None
