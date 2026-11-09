"""Judge for `franken-speaker --platform-startup` as a QEMU guest's console shows it (P02 / `ffw-jub`).

Used by `run-qemu-verification.py` for the platform step of the franken-speaker smoke. Nothing here is a guest
measurement: it states what the guest must print and checks what it did print.

What is judged
--------------
After the `--catalog` step, PID 1 runs `/franken-speaker --platform-startup` as a second child and prints

    FFW_PLATFORM_STEP_BEGIN path=/franken-speaker argv=--platform-startup
    <the child's stdout, forwarded verbatim: six FFW_PLATFORM:* lines>
    FFW_PLATFORM_STEP_EXIT status=<0|3> stdout_bytes=<N> stdout_fnv1a64=<16 hex>

The wrapper lines have their own names so the catalog step's lines, and its committed digests, are untouched. The six child
lines are `BEGIN`, `KERNEL`, `CLOCK`, `ENTROPY`, `WAKE`, `END`, each exactly once, in that order, newline-terminated, with
nothing after `END` (docs/contracts/p02.md, "Markers"). The guest measures the child's bytes before forwarding them; the
runner recomputes the count and the FNV-1a-64 from the console, so a transcript that was corrupted, truncated or interleaved
with other output does not verify.

Where the grammar comes from
----------------------------
The closed value sets (statuses, provenances, mechanisms, ABIs, evidence names, reason codes per capability) are read from
`crates/franken-speaker/tests/vectors/p02_platform_markers.json`, the file the speaker's own unit test holds the code to. The
structural rules (six lines, the order, which keys each line carries, which combinations are contradictory) and the verdict
policy are restated here from the contract text and do not read the speaker's code. `tests/p02/test_platform_markers.py`
holds a second, independently written judge over the same file; `toolchain/tests/test_platform_smoke.py` requires the two to
agree on every committed example and on every planted fault.

Verdicts
--------
`green`: every capability `PASS` with `provenance=kernel`, `backend=kernel`, the ABI and evidence of the guest, `END
started=1`, exit status 0. `degraded` (E03's own verdict for an unseeded pool: neither green nor red): on MIPS only,
`ENTROPY` `REFUSED` with `provenance=kernel reason=not_seeded`, `END started=0 refused=entropy:not_seeded`, exit status 3,
everything else `PASS`. `red`: everything else, each with a named problem. The table of what is degraded is `DEGRADED`; a
cell is one line to change and the contract's text is the authority for it.

The explicit legacy provider
----------------------------
With a provider selected (`judge_output(..., provider="legacy_dev_random_test_environment")`, the runner's `--entropy-provider`) the
guest step runs `/franken-speaker --platform-startup --entropy-provider=legacy-dev-random-test-environment`, the BEGIN line names both
arguments, and the ENTROPY line, and only it, carries `provider=<name>` between `provenance=` and `reason=` on PASS, REFUSED and NOT_RUN
alike (docs/contracts/p02.md, "The legacy provider"). The default judge still rejects that token, and a provider run rejects a line
without it, so neither kind of run can pass as the other. A started provider run is a harness-guest observation of the real adapter
reading `/dev/random`: never device evidence, never a stock kernel. The two harness kernels do NOT answer that read alike (the sources and the booted
binaries, docs/contracts/p02.md, "The harness kernels do not answer alike"): the PowerPC guest's 4.9 kernel is the old blocking pool, whose
`O_NONBLOCK` read answers `EAGAIN` while the pool has nothing to give, so `not_seeded` is a real answer there and is `degraded` (it shows no
positive); by source reading, the MIPS guest's 4.19.249 kernel ignores `O_NONBLOCK` on `/dev/random`: the read waits until the pool is ready and then returns bytes,
so a MIPS start is a blocking read that succeeded, and a MIPS `not_seeded` is a refusal that kernel cannot give, which is red. No seeded
nonblocking `/dev/random` read has been observed in any guest (PowerPC's reads answered `EAGAIN`; the one MIPS start, run 2a405e88, waited inside
the kernel), so a PowerPC refusal is the information such a run gives, and it shows no positive. `absent` (no device node), `unavailable` and
every other reason are red on both. Those cells, and the per-kernel statement in a provider run's claim, belong to the two pinned harness kernel images
(`JUDGED_KERNEL_SHA256`): a provider run is judged against the sha256 of the kernel it booted, and a run on any other image, or with no usable digest,
is red with a named problem and gets no cell.

What this does not establish
----------------------------
That the real backend runs on a board, what a board's `kernel=` string is, or anything about a stock kernel. A transcript
that passes shows what the harness guest's kernel answered to one start of the device speaker, once.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
from typing import Any

import speaker_expect

VECTORS = "crates/franken-speaker/tests/vectors/p02_platform_markers.json"
SCHEMA = "ffw.p02.platform-markers.v2"

STEP_PATH = "/franken-speaker"
STEP_ARG = "--platform-startup"
STEP_BEGIN_KEY = "FFW_PLATFORM_STEP_BEGIN"
STEP_EXIT_KEY = "FFW_PLATFORM_STEP_EXIT"
# The explicit legacy entropy providers a step may select (docs/contracts/p02.md, "The legacy provider"): the marker value the speaker
# prints, and the command-line spelling the guest passes. `legacy_dev_random` (the evidence-qualified one, refused `unavailable` without a
# kernel call) has no guest step: only the admitted test environment can be tried in a harness guest.
PROVIDERS = {"legacy_dev_random_test_environment": "legacy-dev-random-test-environment"}


def provider_arg(provider: str) -> str:
    """The argument the guest passes for `provider`. Raises ValueError for any name this judge does not know (fail closed)."""
    if provider not in PROVIDERS:
        raise ValueError(f"unknown entropy provider {provider!r}")
    return f"--entropy-provider={PROVIDERS[provider]}"


def step_argv(provider: str | None = None) -> list[str]:
    """The step's argv after the path: `--platform-startup`, and the provider argument when one is selected."""
    return [STEP_ARG] if provider is None else [STEP_ARG, provider_arg(provider)]


def step_begin_line(provider: str | None = None) -> str:
    return f"{STEP_BEGIN_KEY} path={STEP_PATH} argv={' '.join(step_argv(provider))}"


STEP_BEGIN_LINE = step_begin_line()
LINE_PREFIX = "FFW_PLATFORM:"

# The guest accepts these exit statuses as "the step ran"; the judge decides what they mean (0 started, 3 refused).
STEP_RAN_STATUSES = (0, 3)

_PAIR = r"stdout_bytes=[0-9]+ stdout_fnv1a64=[0-9a-f]{16}"
STEP_EXIT_OK = re.compile(
    rf"{STEP_EXIT_KEY} status=(0|3) stdout_bytes=([1-9][0-9]*) stdout_fnv1a64=([0-9a-f]{{16}})")
STEP_EXIT_FAILURE = re.compile(
    rf"{STEP_EXIT_KEY} (?:"
    r"spawn=(?:pipe|fork|exec) errno=[0-9]+"
    rf"|(?:status=(?:[1-24-9]|[1-9][0-9]+)|signal=[0-9]+|read_error=[0-9]+|wait_error=[0-9]+|wait_status=[0-9]+"
    rf"|exec_probe_error=[0-9]+) {_PAIR}"
    rf"|status=[03] stdout_bytes=0 stdout_fnv1a64=[0-9a-f]{{16}}"          # started or refused, and printed nothing
    r")"
)

ORDER = ("BEGIN", "KERNEL", "CLOCK", "ENTROPY", "WAKE", "END")
CAPABILITIES = ("kernel", "clock", "entropy", "wake")
CAPABILITY_LINE = {"kernel": "KERNEL", "clock": "CLOCK", "entropy": "ENTROPY", "wake": "WAKE"}
BACKENDS = ("kernel", "simulated")
KERNEL_RELEASE = re.compile(r"[A-Za-z0-9._+-]{1,64}")

# The ABI and evidence a harness guest's speaker must report. The ABI is fixed by the target at compile time, so a speaker
# that names the other one is the wrong binary in the guest.
GUEST_ABI = {"mips": ("mips32", "harness-mips-4.19"), "ppc": ("powerpc32", "harness-ppc-4.9")}

# (guest, capability, reason) combinations the contract reports as degraded and not red: getrandom was UNSEEDED at PID-1 boot
# on the MIPS guest in the E03 run, and one run per guest does not say the pool stays unseeded. PowerPC's was seeded.
DEGRADED = frozenset({("mips", "entropy", "not_seeded")})

# The same table for a run that selected the legacy provider. Only the PowerPC guest can report `not_seeded` for it: its 4.9.88 kernel answers a
# nonblocking `/dev/random` read with `EAGAIN` while the blocking pool is empty (`_random_read`, drivers/char/random.c at v4.9.88 lines 1702-1735;
# the booted vmlinux has `_random_read`/`blocking_pool`). That is neither green nor red, and no positive. Every other reason is red
# (a missing device node is `absent`, a qualified-but-untried provider is `unavailable`).
DEGRADED_PROVIDER = frozenset({("ppc", "entropy", "not_seeded")})

# A refusal a harness kernel cannot give. The MIPS guest's 4.19.249 kernel has `random_read_iter` call `wait_for_random_bytes()` unconditionally and
# never tests `O_NONBLOCK` (drivers/char/random.c at v4.19.249 lines 1293-1300; the booted vmlinux, sha256 3803357e..., disassembles to exactly
# that), so its `/dev/random` read waits for the pool and then succeeds: it has no `EAGAIN` to turn into `not_seeded`. A transcript that says so
# was not produced by that kernel's read, and is red with this extra named problem beside the usual one. The cell is a property of that kernel
# image, not of MIPS, so it is applied only to a run whose `kernel_sha256` is the pinned image (`JUDGED_KERNEL_SHA256` below). Revisit this cell if the MIPS harness kernel image (`kernel_sha256` `3803357e`) is replaced, or if a
# provider-side wait bound is added (the refusal would then be the provider's own timeout, not an `EAGAIN` from the kernel).
UNREACHABLE_PROVIDER_REFUSAL = frozenset({("mips", "entropy", "not_seeded")})

# The harness kernel images the provider cells above describe: the full sha256 of the vmlinux the runner boots for each guest, as recorded in the
# `kernel_sha256` of run 2a405e88's receipt (the digests docs/contracts/p02.md names by prefix). A provider run is judged by those cells, and says what
# PROVIDER_READ says, only when its `kernel_sha256` is exactly the pinned digest of its guest. Any other image (or no digest) gets no special cell: it
# is red with a named problem, and its claim makes no statement about how its `/dev/random` read behaves.
JUDGED_KERNEL_SHA256 = {
    "mips": "3803357ef7821dbf691c901105fb9b2b00382abf67fce8a4be2a0d592267dc61",
    "ppc": "289f40b63ea9aa82743f568ddeaba669a16a859970497dccf7135596da538f98",
}
_SHA256 = re.compile(r"[0-9a-f]{64}")


def image_problem(arch: str, kernel_sha256: Any) -> str | None:
    """The named problem with the kernel image a provider run claims to have booted, or None when it is the pinned image for `arch`. No digest, a digest
    that is not 64 lowercase hex characters (a prefix is not a digest), and a well formed digest that is not the pinned one are three different problems."""
    if kernel_sha256 is None:
        return "platform_kernel_sha256_missing"
    if not isinstance(kernel_sha256, str) or _SHA256.fullmatch(kernel_sha256) is None:
        return "platform_kernel_sha256_malformed"
    if kernel_sha256 != JUDGED_KERNEL_SHA256.get(arch):
        return "platform_kernel_not_the_judged_image"
    return None


PROVIDER_CLAIM = ("explicit legacy /dev/random provider in an admitted test environment (a harness guest): a started run is an observation "
                  "of the real adapter on that guest's kernel and says nothing about a device or a stock kernel; a refusal shows no positive")

# What a `/dev/random` read does on each harness guest's kernel, appended to the claim so a receipt says which kind of read it observed.
PROVIDER_READ = {
    "mips": ("by source reading, this guest's kernel (Debian 4.19.249) ignores O_NONBLOCK on /dev/random: the read blocks until the pool is ready and then returns "
             "bytes, so a start is a blocking read that succeeded and not an observation of nonblocking semantics; it cannot answer not_seeded"),
    "ppc": ("by source reading, this guest's kernel (Debian 4.9.88) answers a nonblocking /dev/random read with EAGAIN while its blocking pool is empty: a start is a "
            "read that returned bytes, a refusal is that answer"),
}

# What the claim says instead of PROVIDER_READ when the run's kernel is not the pinned image.
PROVIDER_READ_UNJUDGED = ("this run's kernel image is not the one this judge's per-kernel reading of /dev/random covers, so nothing is claimed about whether its "
                          "nonblocking read answers EAGAIN or waits")


class PlatformGrammarError(Exception):
    """The grammar file is missing, unreadable or not the schema this judge understands. Fail closed."""


def load_grammar(repo_root: pathlib.Path) -> dict[str, Any]:
    path = repo_root / VECTORS
    try:
        data = path.read_bytes()
        doc = json.loads(data.decode("utf-8"))
    except (OSError, ValueError) as error:
        raise PlatformGrammarError(f"cannot read {VECTORS}: {error}") from error
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise PlatformGrammarError(f"{VECTORS} is not schema {SCHEMA}")
    grammar, reasons = doc.get("grammar"), doc.get("reason_codes")
    if not isinstance(grammar, dict) or not isinstance(reasons, dict):
        raise PlatformGrammarError(f"{VECTORS} has no grammar or reason_codes")
    for key in ("status", "provenance", "mechanism", "abi", "evidence", "lines"):
        value = grammar.get(key)
        if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
            raise PlatformGrammarError(f"{VECTORS} grammar.{key} is not a non-empty list of strings")
    if tuple(grammar["lines"]) != ORDER:
        raise PlatformGrammarError(f"{VECTORS} grammar.lines is not {list(ORDER)}")
    for capability in CAPABILITIES:
        value = reasons.get(capability)
        if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
            raise PlatformGrammarError(f"{VECTORS} reason_codes.{capability} is not a non-empty list of strings")
    return {
        "source": VECTORS,
        "sha256": hashlib.sha256(data).hexdigest(),
        "schema": SCHEMA,
        "grammar": grammar,
        "reasons": reasons,
        "examples": doc.get("examples", {}),
    }


# ---- the console region ------------------------------------------------------------------------------------


def step_region(raw_log: str) -> tuple[bytes | None, str | None]:
    """The bytes the child wrote, reconstructed from the console transcript: every line between the single BEGIN and the
    single EXIT line, with the console's CRLF mapped back to LF. Returns (bytes, None) or (None, reason)."""
    lines = [line[:-1] if line.endswith("\r") else line for line in raw_log.split("\n")]
    begins = [i for i, line in enumerate(lines) if line.strip().startswith(STEP_BEGIN_KEY + " ")]
    exits = [i for i, line in enumerate(lines) if line.strip().startswith(STEP_EXIT_KEY + " ")]
    if len(begins) != 1 or len(exits) != 1:
        return None, "begin_or_exit_not_exactly_once"
    if begins[0] >= exits[0]:
        return None, "exit_before_begin"
    text = "".join(line + "\n" for line in lines[begins[0] + 1:exits[0]])
    if "�" in text:
        return None, "not_utf8"
    return text.encode("utf-8"), None


# ---- the six lines -----------------------------------------------------------------------------------------


def _shown(value: str) -> str:
    """A value as it appears in a problem name: bounded, and never a long attacker-shaped string."""
    return value if len(value) <= 40 else value[:37] + "..."


def _split(line: str) -> tuple[str, list[tuple[str, str]] | None]:
    """(NAME, [(key, value), ...]) for `FFW_PLATFORM:NAME k=v k=v`; the pairs are None for a line that is not a clean run of
    single-space-separated `key=value` tokens (empty token, trailing space, missing or empty key or value)."""
    head, _, rest = line[len(LINE_PREFIX):].partition(" ")
    pairs: list[tuple[str, str]] = []
    for token in (rest.split(" ") if rest != "" else []):
        key, equals, value = token.partition("=")
        if not equals or not re.fullmatch(r"[a-z_]+", key) or value == "":
            return head, None
        pairs.append((key, value))
    return head, pairs


def _structure(lines: list[str]) -> list[str]:
    """Problems with which lines are there and in what order: foreign or blank lines, unknown names, duplicates, order,
    output after END, and a missing END (a truncated run) or a missing line before it."""
    problems: list[str] = []
    names: list[str | None] = []
    for index, line in enumerate(lines):
        if line == "":
            problems.append(f"platform_blank_line:{index}")
            names.append(None)
        elif not line.startswith(LINE_PREFIX):
            problems.append(f"platform_foreign_line:{index}")
            names.append(None)
        else:
            name = line[len(LINE_PREFIX):].split(" ", 1)[0]
            if name not in ORDER:
                problems.append(f"platform_unknown_line:{_shown(name)}")
                names.append(None)
            else:
                names.append(name)
    known = [name for name in names if name is not None]
    if "END" in known:
        after = len(names) - 1 - max(i for i, name in enumerate(names) if name == "END")
        if after > 0:
            problems.append("platform_after_end")
    for name in ORDER:
        if known.count(name) > 1:
            problems.append(f"platform_duplicate:{name}")
    highest = -1
    for name in known:
        rank = ORDER.index(name)
        if rank < highest:
            problems.append(f"platform_order:{name}")
        highest = max(highest, rank)
    if "END" not in known:
        if known:
            problems.append(f"platform_truncated:after:{known[-1]}")
    else:
        problems.extend(f"platform_missing:{name}" for name in ORDER if name not in known)
    return problems


def _expected_keys(name: str, pairs: list[tuple[str, str]], provider: str | None = None) -> list[str]:
    """The keys a line must carry, in order, given its own status or started value. A selected provider adds `provider` to the
    ENTROPY line, between `provenance` and `reason`, on every status."""
    values = dict(pairs)
    if name == "BEGIN":
        return ["abi", "evidence", "backend", "kernel"]
    if name == "END":
        return ["started", "refused"] if values.get("started") == "0" else ["started"]
    keys = {"KERNEL": ["status"], "CLOCK": ["status", "provenance"], "ENTROPY": ["status", "provenance"],
            "WAKE": ["status", "provenance", "mechanism"]}[name]
    if name == "ENTROPY" and provider is not None:
        keys = keys + ["provider"]
    return keys + ["reason"] if values.get("status") == "REFUSED" else keys


def _values(name: str, pairs: list[tuple[str, str]], ctx: dict[str, Any]) -> list[str]:
    """Problems with the values of a line whose keys are right: each must be in its closed set."""
    grammar, reasons = ctx["grammar"], ctx["reasons"]
    capability = name.lower()
    allowed = {
        "status": grammar["status"], "provenance": grammar["provenance"], "mechanism": grammar["mechanism"],
        "abi": grammar["abi"], "evidence": grammar["evidence"], "backend": list(BACKENDS), "started": ["0", "1"],
    }
    problems = []
    for key, value in pairs:
        if key in allowed:
            if value not in allowed[key]:
                problems.append(f"platform_value:{name}:{key}={_shown(value)}")
        elif key == "reason":
            if value not in reasons.get(capability, []):
                problems.append(f"platform_value:{name}:reason={_shown(value)}")
        elif key == "provider":
            if value != ctx.get("provider"):
                problems.append(f"platform_value:{name}:provider={_shown(value)}")
        elif key == "kernel":
            if not KERNEL_RELEASE.fullmatch(value):
                problems.append(f"platform_value:{name}:kernel={_shown(value)}")
        elif key == "refused":
            cap, _, reason = value.partition(":")
            if cap not in CAPABILITIES or reason not in reasons.get(cap, []):
                problems.append(f"platform_value:{name}:refused={_shown(value)}")
    return problems


def judge_output(data: bytes, arch: str, ctx: dict[str, Any], provider: str | None = None, kernel_sha256: str | None = None) -> dict[str, Any]:
    """Judge the child's stdout for the `arch` guest ("mips" or "ppc"). Returns the record that goes in the receipt:
    `verdict` ("green", "degraded" or "red"), `problems` (named; empty unless red), the six lines, what each capability
    reported, whether it started, and the `kernel=` value, which is recorded and never compared. With `provider` (a key of
    `PROVIDERS`) the run is judged as the explicit legacy-provider run: the ENTROPY line must carry that `provider=`, and the record
    names the provider and its claim; without it the judge is exactly what it was and rejects the token.

    A provider run is also judged against the kernel image it booted: `kernel_sha256` must be the pinned digest of `arch` (`JUDGED_KERNEL_SHA256`). The degraded
    and the unreachable cells, and the per-kernel statement in the claim, belong to that image alone; any other value (none, malformed, another image) is red
    with the named problem first (`image_problem`), the transcript is still judged without the cells, and a start on an unjudged image is red too. A run
    without a provider ignores `kernel_sha256`."""
    image = None if provider is None else image_problem(arch, kernel_sha256)
    record = _judge_output(data, arch, ctx, provider, image)
    if image is not None:
        record["problems"].insert(0, image)
        record["verdict"] = "red"
        record.pop("degraded_because", None)
    return record


def _judge_output(data: bytes, arch: str, ctx: dict[str, Any], provider: str | None, image: str | None) -> dict[str, Any]:
    """`judge_output` for a transcript, with `image` the problem with the kernel image (None for the pinned one, and for a run with no provider)."""
    if arch not in GUEST_ABI:
        raise ValueError(f"unknown guest {arch!r}")
    if provider is not None:
        provider_arg(provider)                  # an unknown name raises, like an unknown guest
    ctx = dict(ctx, provider=provider)
    problems: list[str] = []
    record: dict[str, Any] = {
        "verdict": "red", "problems": problems, "lines": [], "outcomes": {}, "started": None, "kernel_release": None,
    }
    if provider is not None:
        record["provider"], record["claim"] = provider, f"{PROVIDER_CLAIM}; {PROVIDER_READ[arch] if image is None else PROVIDER_READ_UNJUDGED}"
    if not data:
        problems.append("platform_empty_output")
        return record
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        problems.append("platform_not_ascii")
        return record
    lines = text.split("\n")
    if text.endswith("\n"):
        lines = lines[:-1]
    else:
        problems.append("platform_not_newline_terminated")
    record["lines"] = list(lines)
    problems.extend(_structure(lines))
    if problems:
        return record

    parsed: dict[str, list[tuple[str, str]]] = {}
    for name, line in zip(ORDER, lines):
        _, pairs = _split(line)
        if pairs is None:
            problems.append(f"platform_malformed:{name}")
            continue
        keys = [key for key, _ in pairs]
        if keys != _expected_keys(name, pairs, provider):
            if provider is not None and name == "ENTROPY" and keys == _expected_keys(name, pairs):
                problems.append("platform_provider_missing:ENTROPY")      # the guest ran the default provider
            else:
                problems.append(f"platform_fields:{name}:{','.join(keys) if keys else 'none'}")
            continue
        value_problems = _values(name, pairs, ctx)
        problems.extend(value_problems)
        parsed[name] = pairs
    if problems:
        return record

    begin = dict(parsed["BEGIN"])
    record["kernel_release"] = begin["kernel"]
    outcome = {cap: dict(parsed[CAPABILITY_LINE[cap]]) for cap in CAPABILITIES}
    record["outcomes"] = {cap: fields["status"] for cap, fields in outcome.items()}
    end = dict(parsed["END"])
    record["started"] = end["started"] == "1"

    if begin["backend"] != "kernel":
        problems.append("platform_backend_simulated")
    else:
        expected_abi, expected_evidence = GUEST_ABI[arch]
        if (begin["abi"], begin["evidence"]) != (expected_abi, expected_evidence):
            problems.append(f"platform_abi:{begin['abi']}_{begin['evidence']}_for_{arch}")
    for cap in CAPABILITIES[1:]:
        name, fields = CAPABILITY_LINE[cap], outcome[cap]
        status, provenance = fields["status"], fields["provenance"]
        if provenance == "simulated":
            problems.append(f"platform_simulated:{name}")
        elif (status == "NOT_RUN") != (provenance == "none"):
            problems.append(f"platform_provenance:{name}:{status}_with_{provenance}")
    refused_before = outcome["kernel"]["status"] == "REFUSED"
    for cap in CAPABILITIES[1:]:
        name, status = CAPABILITY_LINE[cap], outcome[cap]["status"]
        if status == "NOT_RUN" and not refused_before:
            problems.append(f"platform_not_run_unexplained:{name}")
        if outcome["kernel"]["status"] != "PASS" and status != "NOT_RUN":
            problems.append(f"platform_ran_after_kernel_refusal:{name}")
        refused_before = refused_before or status == "REFUSED"
    first = next(((cap, outcome[cap]["reason"]) for cap in CAPABILITIES if outcome[cap]["status"] == "REFUSED"), None)
    every_pass = all(outcome[cap]["status"] == "PASS" for cap in CAPABILITIES)
    if end["started"] == "1":
        if not every_pass:
            problems.append("platform_end_disagrees:started_but_a_capability_did_not_pass")
    elif every_pass:
        problems.append("platform_end_disagrees:refused_but_every_capability_passed")
    elif first is None:
        problems.append("platform_end_disagrees:refusal_not_shown")
    elif end["refused"] != f"{first[0]}:{first[1]}":
        problems.append(f"platform_end_disagrees:names_{_shown(end['refused'])}_but_the_first_refusal_is_{first[0]}:{first[1]}")
    if problems:
        return record

    # Well formed and self-consistent. Whether it shows the positive path is the policy.
    if every_pass and record["started"]:
        record["verdict"] = "green"
    elif first is not None and (arch, first[0], first[1]) in (DEGRADED if provider is None else DEGRADED_PROVIDER if image is None else frozenset()) and sum(
            1 for cap in CAPABILITIES if outcome[cap]["status"] != "PASS") == 1:
        record["verdict"] = "degraded"
        record["degraded_because"] = f"{first[0]}:{first[1]}"
    else:
        problems.extend(f"platform_not_started:{cap}:{outcome[cap]['reason']}" for cap in CAPABILITIES
                        if outcome[cap]["status"] == "REFUSED")
        if provider is not None and image is None:
            problems.extend(f"platform_unreachable_refusal:{cap}:{outcome[cap]['reason']}" for cap in CAPABILITIES
                            if outcome[cap]["status"] == "REFUSED" and (arch, cap, outcome[cap]["reason"]) in UNREACHABLE_PROVIDER_REFUSAL)
    return record


def judge_exit_status(record: dict[str, Any], status: int) -> list[str]:
    """The guest's exit status must agree with the child's own `END`: 0 started, 3 refused. Only meaningful for output that
    parsed; a transcript with problems is already red."""
    if record["started"] is None:
        return []
    expected = 0 if record["started"] else 3
    if status != expected:
        return [f"platform_exit_status_disagrees:status={status}_started={int(record['started'])}"]
    return []


# ---- planted faults ----------------------------------------------------------------------------------------

# Each plant changes a REAL transcript the same guest produced, in one way, and is re-sealed (the guest's byte count and
# FNV are recomputed over the changed region), so the only thing wrong with it is the plant. It counts only against an
# unplanted run of the same guest that was not red, and only if the verifier reports exactly the named problem and no other.
PLANTS: dict[str, dict[str, Any]] = {
    "provenance_double": {
        "plant": "the CLOCK line claims provenance=double (not kernel, simulated or none)",
        "expected": ["platform_value:CLOCK:provenance=double"],
    },
    "provenance_simulated": {
        "plant": "the CLOCK line says provenance=simulated, the value a test double really prints",
        "expected": ["platform_simulated:CLOCK"],
    },
    "backend_simulated": {
        "plant": "the BEGIN line says backend=simulated while every capability still passes",
        "expected": ["platform_backend_simulated"],
    },
    "missing_capability": {
        "plant": "the ENTROPY line is missing from the run",
        "expected": ["platform_missing:ENTROPY"],
    },
    "truncated": {
        "plant": "the run stops after the CLOCK line (no ENTROPY, WAKE or END)",
        "expected": ["platform_truncated:after:CLOCK"],
    },
}


# The plants of a run that selected the legacy provider are the five above plus these (a provider run's baseline carries the token).
PROVIDER_PLANTS: dict[str, dict[str, Any]] = {
    "provider_missing": {
        "plant": "the ENTROPY line has no provider= token (the guest ran the default provider)",
        "expected": ["platform_provider_missing:ENTROPY"],
    },
    "provider_other": {
        "plant": "the ENTROPY line says provider=legacy_dev_random (the evidence-qualified one) when the test environment was selected",
        "expected": ["platform_value:ENTROPY:provider=legacy_dev_random"],
    },
    "provider_unknown": {
        "plant": "the ENTROPY line says provider=urandom (a source that is not a provider)",
        "expected": ["platform_value:ENTROPY:provider=urandom"],
    },
}


def plants_for(provider: str | None = None) -> dict[str, dict[str, Any]]:
    """The plants a run is judged against: the five for the default run, those plus the provider ones for a provider run."""
    if provider is not None:
        provider_arg(provider)                  # an unknown name raises
    return dict(PLANTS) if provider is None else {**PLANTS, **PROVIDER_PLANTS}


def plant_spec(plant: str) -> dict[str, Any]:
    """One plant's description and expected problems, from either set. Raises KeyError for a name in neither."""
    return PLANTS[plant] if plant in PLANTS else PROVIDER_PLANTS[plant]


# The plants that change one value on one line: (line, what it says now, what the plant makes it say).
REPLACEMENTS = {
    "provenance_double": ("CLOCK", "provenance=kernel", "provenance=double"),
    "provenance_simulated": ("CLOCK", "provenance=kernel", "provenance=simulated"),
    "backend_simulated": ("BEGIN", "backend=kernel", "backend=simulated"),
    "provider_other": ("ENTROPY", "provider=legacy_dev_random_test_environment", "provider=legacy_dev_random"),
    "provider_unknown": ("ENTROPY", "provider=legacy_dev_random_test_environment", "provider=urandom"),
}


def plant_transcript(raw_log: str, plant: str) -> str:
    """`raw_log` with the platform step's child lines changed as `PLANTS[plant]` says, and the step's EXIT line re-sealed to
    the changed bytes (the status the guest reported is kept). Raises ValueError if the log has no clean platform step or
    the line to change is not there: a plant that cannot be applied is not a caught control."""
    if plant not in PLANTS and plant not in PROVIDER_PLANTS:
        raise ValueError(f"unknown plant {plant!r}")
    lines = raw_log.split("\n")
    begins = [i for i, line in enumerate(lines) if line.strip().startswith(STEP_BEGIN_KEY + " ")]
    exits = [i for i, line in enumerate(lines) if line.strip().startswith(STEP_EXIT_KEY + " ")]
    if len(begins) != 1 or len(exits) != 1 or begins[0] >= exits[0]:
        raise ValueError("no single platform step to plant in")
    begin, exit_at = begins[0], exits[0]
    crlf = lines[begin + 1].endswith("\r") if begin + 1 < exit_at else False
    child = [line[:-1] if line.endswith("\r") else line for line in lines[begin + 1:exit_at]]
    exit_ok = STEP_EXIT_OK.fullmatch(lines[exit_at].strip())
    if exit_ok is None:
        raise ValueError("the platform step did not end in a success form")

    def index_of(name: str) -> int:
        for i, line in enumerate(child):
            if line.startswith(f"{LINE_PREFIX}{name} "):
                return i
        raise ValueError(f"no {name} line to plant in")

    if plant in REPLACEMENTS:
        name, old, new = REPLACEMENTS[plant]
        i = index_of(name)
        if old not in child[i]:
            raise ValueError(f"the {name} line does not say {old}")
        child[i] = child[i].replace(old, new, 1)
    elif plant == "missing_capability":
        del child[index_of("ENTROPY")]
    elif plant == "provider_missing":
        i = index_of("ENTROPY")
        if " provider=" not in child[i]:
            raise ValueError("the ENTROPY line carries no provider= token")
        child[i] = re.sub(r" provider=\S+", "", child[i], count=1)
    else:
        child = child[: index_of("CLOCK") + 1]
    region = "".join(line + "\n" for line in child).encode("utf-8")
    sealed = (f"{STEP_EXIT_KEY} status={exit_ok.group(1)} stdout_bytes={len(region)} "
              f"stdout_fnv1a64={speaker_expect.fnv1a64(region):016x}")
    exit_line = sealed + ("\r" if lines[exit_at].endswith("\r") else "")
    body = [line + ("\r" if crlf else "") for line in child]
    return "\n".join(lines[: begin + 1] + body + [exit_line] + lines[exit_at + 1:])
