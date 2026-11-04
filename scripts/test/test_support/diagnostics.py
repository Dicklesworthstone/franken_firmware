#!/usr/bin/env python3
"""Bounded, nonblocking, redacting structured diagnostic sink (Q00 / ffw-2qz).

Standard library only (Python 3.9+). Imports no production crate, touches no
network or device, and performs no discovery. It is a test-infrastructure
primitive: the producer side of an audit trail whose *consumer* side
(``audit_log``) re-derives, from the file alone, whether the trail is
complete.

What it guarantees (each is exercised by ``test_diagnostics.py``)
-----------------------------------------------------------------
* ``emit()`` never performs I/O, never waits on the sink and never raises. It
  contends only on one lock that is held for O(1) in-memory work. A slow,
  full, vanished or hung sink therefore cannot stall the caller.
* Everything is bounded: queued events, queued bytes, bytes per event, event
  rate (token bucket), total file bytes, structure depth/items/nodes and
  string length. Exceeding a bound drops and *counts*; it never grows.
* Loss accounting is exact. Every ``emit()`` call ends as exactly one of
  *written* or *dropped with a reason*, so ``emitted == written + dropped``
  holds at all times (modulo the in-flight queue) and, after ``close()``,
  exactly. The file carries the proof: ``audit_log`` re-checks the identity
  from the JSONL alone, independent of the in-process counters.
* Evidence classes. ``critical=True`` marks evidence a qualification verdict
  rests on (case begin/end, oracle verdicts, run summary). Critical events
  bypass the rate limit, evict queued non-critical events when the queue is
  full, and have a reserved slice of the disk budget. If one is nonetheless
  lost, ``EvidenceVerdict.complete`` is False and ``require_complete()``
  raises: qualification is invalid. Absence of error text is never a pass: a
  sink that was never closed, never wrote its header/footer, hung, or whose
  file was truncated is *incomplete*, not "clean".
* Redaction happens before anything is queued. Tokens, keys, account and
  household identifiers, serials, MAC/IP/e-mail, exact secret literals, the
  home directory and audio/binary payloads never reach the file. Member and
  group identifiers are replaced by keyed pseudonyms.

What it does NOT claim
----------------------
* It does not qualify the on-device render path. This is the *harness-side*
  contract (nonblocking, bounded, loss-visible). Real-time deadlines of the
  Rust render path are a Q02/Q03 on-target matter; wall-clock latency is not
  asserted here because it is not deterministic.
* ``max_file_bytes`` bounds what this sink hands to the target. The target's
  own limits (a real full disk, ``RLIMIT_FSIZE``) are reported as sink errors
  and counted as loss; they are not hidden.
* The footer/summary are integrity aids, not signatures. Someone who can
  rewrite the whole file can rewrite the footer; receipts that need tamper
  evidence must pin ``LogAudit.sha256`` somewhere else.
* Redaction is pattern + key based. It is defence in depth, not a proof that
  no secret can appear; callers should still avoid logging secrets and pass
  known secret values as ``RedactionPolicy.literals``.

Typical use
-----------
::

    sink = DiagnosticSink.to_file(run_dir / "diag.jsonl", run_id="r1")
    sink.emit("case.begin", critical=True, case_id="q00.unit.x")
    ...
    verdict = sink.close()
    verdict.require_complete()                # raises EvidenceIncomplete
    audit = audit_log(run_dir / "diag.jsonl")  # independent re-read of the file
    outcome = downgrade_pass_if_incomplete("pass", verdict)

Deterministic testing: pass ``threaded=False`` and drive the writer with
``pump()``; pass a fake ``clock_ns`` (any zero-argument callable returning
integer nanoseconds) and a fixed ``pseudonym_key``.

Log format ``ff.diag.v1`` is JSONL, one ASCII JSON object per line, in order:
``header`` (first), then ``event`` / ``loss`` records, then ``footer`` (last).
"""

from __future__ import annotations

import collections
import dataclasses
import errno
import hashlib
import hmac
import io
import itertools
import json
import math
import os
import re
import sys
import threading
import time
from typing import Any, BinaryIO, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

SCHEMA = "ff.diag.v1"
SUMMARY_SCHEMA = "ff.diag.summary.v1"
REDACTION_POLICY_ID = "ff.redact.v1"
PRODUCER = "ff-diag/1"

LEVELS = ("debug", "info", "warn", "error", "critical")
_LEVEL_ALIASES = {"trace": "debug", "warning": "warn", "err": "error", "fatal": "critical"}

# Every emit() ends as written or as exactly one of these.
DROP_REASONS = (
    "queue_full",            # event queue at max_queue_events
    "queue_bytes",           # event queue at max_queue_bytes
    "evicted_for_critical",  # queued non-critical event evicted to admit a critical one
    "rate_limited",          # token bucket empty (non-critical only)
    "disk_budget",           # would exceed the logical file budget
    "oversize",              # event cannot fit max_event_bytes even after shrinking
    "sink_error",            # the target raised while writing it
    "lost_at_close",         # still queued/in flight when close() gave up
    "closed",                # emitted after close()
    "internal_error",        # the sink itself failed building/queueing it
)

_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_ENVELOPE_SLACK = 160  # bytes reserved for the seq/mono_ns prefix added at enqueue time
# Written before the next record after ANY failed write. A failed write can leave a torn line, and a cut
# that lands exactly before a record's newline leaves a complete-looking JSON object; a bare "\n" would
# "terminate" it into a valid line the sink had already counted as lost. NUL makes the remnant invalid
# JSON wherever the cut fell, so a torn record is never mistaken for a written one.
_RESYNC = b"\x00\n"


# --------------------------------------------------------------------------- #
# limits
# --------------------------------------------------------------------------- #

@dataclasses.dataclass(frozen=True)
class SinkLimits:
    max_queue_events: int = 1024
    max_queue_bytes: int = 1 << 20
    max_event_bytes: int = 16 << 10
    max_file_bytes: int = 8 << 20
    #: slice of ``max_file_bytes`` only critical events, loss markers and the
    #: footer may use. Non-critical events stop at ``max_file_bytes - this``.
    critical_reserve_bytes: int = 256 << 10
    #: slice only the footer may use.
    footer_reserve_bytes: int = 16 << 10
    #: non-critical events per second (token bucket); ``None`` disables.
    max_events_per_sec: Optional[float] = 5000.0
    burst_events: int = 1000
    drain_batch: int = 64
    #: consecutive target failures before the sink is "unavailable" and only probed.
    failure_threshold: int = 3
    retry_interval_s: float = 0.5
    #: write attempts for one critical event before it is counted lost.
    critical_max_attempts: int = 3
    close_timeout_s: float = 5.0
    max_tracked_cases: int = 4096

    def __post_init__(self) -> None:
        def need(cond: bool, msg: str) -> None:
            if not cond:
                raise ValueError("SinkLimits: " + msg)
        need(self.max_queue_events >= 2, "max_queue_events must be >= 2")
        need(self.max_event_bytes >= 512, "max_event_bytes must be >= 512")
        need(self.max_queue_bytes >= self.max_event_bytes, "max_queue_bytes must be >= max_event_bytes")
        need(self.footer_reserve_bytes >= 1024, "footer_reserve_bytes must be >= 1024")
        need(self.critical_reserve_bytes >= self.footer_reserve_bytes,
             "critical_reserve_bytes must be >= footer_reserve_bytes")
        need(self.max_file_bytes >= self.critical_reserve_bytes + self.max_event_bytes,
             "max_file_bytes must exceed critical_reserve_bytes + max_event_bytes")
        need(self.max_events_per_sec is None or self.max_events_per_sec > 0, "max_events_per_sec must be > 0 or None")
        need(self.burst_events >= 1, "burst_events must be >= 1")
        need(self.drain_batch >= 1, "drain_batch must be >= 1")
        need(self.failure_threshold >= 1, "failure_threshold must be >= 1")
        need(self.retry_interval_s >= 0, "retry_interval_s must be >= 0")
        need(self.critical_max_attempts >= 1, "critical_max_attempts must be >= 1")
        need(self.close_timeout_s >= 0, "close_timeout_s must be >= 0")
        need(self.max_tracked_cases >= 1, "max_tracked_cases must be >= 1")


# --------------------------------------------------------------------------- #
# redaction
# --------------------------------------------------------------------------- #

@dataclasses.dataclass(frozen=True)
class RedactionPolicy:
    max_depth: int = 6
    max_items: int = 32
    max_nodes: int = 512
    max_str_len: int = 1024
    #: strings longer than this are cut (at a word boundary) *before* pattern
    #: matching, so regexes never run over unbounded input.
    raw_str_cap: int = 16384
    #: numeric sequences longer than this are summarised, never logged.
    max_numeric_seq: int = 16
    redact_ipv4: bool = True
    redact_ipv6: bool = True
    redact_macs: bool = True
    redact_emails: bool = True
    redact_opaque_tokens: bool = True
    #: replace the user's home directory with "~".
    scrub_home: bool = True
    #: exact secret values (e.g. from the environment) removed wherever they appear.
    literals: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("max_depth", "max_items", "max_nodes", "max_str_len", "raw_str_cap", "max_numeric_seq"):
            if not isinstance(getattr(self, name), int) or getattr(self, name) < 1:
                raise ValueError("RedactionPolicy.%s must be a positive int" % name)
        if self.raw_str_cap < self.max_str_len:
            raise ValueError("RedactionPolicy.raw_str_cap must be >= max_str_len")

    def public(self) -> Dict[str, Any]:
        """Policy description safe to write to the log (never includes literals)."""
        d = dataclasses.asdict(self)
        d.pop("literals", None)
        d["literals"] = len(self.literals)
        d["policy"] = REDACTION_POLICY_ID
        return d


_MARK = {
    "secret": "[REDACTED]",
    "account": "[REDACTED]",
    "site": "[REDACTED]",
    "literal": "[REDACTED]",
    "userinfo": "[REDACTED]",
    "token": "[REDACTED-TOKEN]",
    "opaque": "[REDACTED-TOKEN]",
    "jwt": "[REDACTED-JWT]",
    "pem": "[REDACTED-PRIVATE-KEY]",
    "mac": "[REDACTED-MAC]",
    "ip": "[REDACTED-IP]",
    "ip6": "[REDACTED-IP6]",
    "email": "[REDACTED-EMAIL]",
}

_TOKEN_SPLIT = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
_SECRET_TOKENS = frozenset({
    "token", "tokens", "secret", "secrets", "password", "passwd", "passphrase", "pwd", "apikey",
    "authorization", "auth", "cookie", "cookies", "credential", "credentials", "bearer", "jwt",
    "psk", "signature", "otp",
})
_KEY_PREFIXES = frozenset({
    "api", "private", "secret", "access", "signing", "encryption", "auth", "ssh", "session",
    "master", "license", "shared", "pre",
})
_ACCOUNT_TOKENS = frozenset({"account", "accountid", "household", "email", "username", "login", "phone"})
_SITE_TOKENS = frozenset({
    "serial", "serialnumber", "mac", "macaddr", "bssid", "ssid", "imei", "hwaddr", "ip", "ipaddr",
    "ipv4", "ipv6", "hostname",
})
_AUDIO_TOKENS = frozenset({"pcm", "samples", "audio", "waveform", "payload", "wav"})
_SCALARS = (int, float, bool, type(None))


def classify_key(name: str) -> Optional[str]:
    """Return "secret"/"account"/"site"/"audio" if a field *name* is sensitive, else None.

    Names are split into lower-case words (snake, kebab and camel case), so
    ``max_tokens`` is judged on ``max`` and ``tokens`` but ``monkey`` is not
    judged on ``key``. Callers apply the class to the *value*: numbers and
    booleans always pass (``token_count: 5`` is a counter, not a secret).
    """
    words = tuple(w.lower() for w in _TOKEN_SPLIT.findall(name))
    if not words:
        return None
    wset = set(words)
    if wset & _SECRET_TOKENS or words == ("key",):
        return "secret"
    for a, b in zip(words, words[1:]):
        if b == "key" and a in _KEY_PREFIXES:
            return "secret"
    if wset & _ACCOUNT_TOKENS or ("user", "id") in list(zip(words, words[1:])):
        return "account"
    if wset & _SITE_TOKENS:
        return "site"
    if wset & _AUDIO_TOKENS:
        return "audio"
    return None


_PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:.*?-----END [A-Z0-9 ]*PRIVATE KEY-----|.*\Z)", re.S)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_TOKEN_PREFIX_RE = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}|(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}|tskey-[A-Za-z0-9_-]{8,}"
    r"|AIza[0-9A-Za-z_-]{30,}|ya29\.[A-Za-z0-9_-]{20,})"
)
_USERINFO_RE = re.compile(r"(?<=://)[^/\s:@]+:[^/\s@]+@")
_BEARER_RE = re.compile(r"\b(Bearer|Basic)(\s+)[A-Za-z0-9._~+/=-]{8,}", re.I)
_KV_RE = re.compile(
    r"""(?ix)
    (?P<k>["']?(?<![A-Za-z0-9])(?:access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|token|client[_-]?secret
        |secret|password|passwd|passphrase|pwd|api[_-]?key|apikey|x-api-key|authorization
        |proxy-authorization|set-cookie|cookie|signature|psk|private[_-]?key|session[_-]?id|sessionid
        |household[_-]?id|householdid|account[_-]?id|accountid|serial(?:[_-]?(?:no|number))?)\b["']?)
    (?P<sep>\s*[:=]\s*)
    (?P<v>"[^"]*"|'[^']*'|(?:bearer|basic)\s+[^\s&,;"'}]+|[^\s&,;"'}]+)
    """
)
_MAC_RE = re.compile(r"(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f-])(?!:[0-9A-Fa-f]{2}\b)")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_RE = re.compile(
    r"(?<![\w:.])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?)(?![\w:])"
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
_OPAQUE_RE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])")
_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


def _ipv4_public_identifier(text: str) -> bool:
    try:
        o = [int(p) for p in text.split(".")]
    except ValueError:
        return False
    if len(o) != 4 or any(x > 255 for x in o):
        return False  # version-like string, not an address
    if o[0] == 127 or o[0] == 255 or text == "0.0.0.0":
        return False  # loopback / unspecified / netmask: not identifying
    if o[:3] in ([192, 0, 2], [198, 51, 100], [203, 0, 113]):
        return False  # RFC 5737 documentation ranges: public placeholders
    return True


def _cut_at_boundary(s: str, cap: int) -> str:
    """Cut to ``cap`` chars, backing up to a delimiter so no half-token survives."""
    head = s[:cap]
    lo = max(0, cap - 256)
    i = max(head.rfind(c, lo) for c in (" ", "\n", "\t", ",", ";", "&", "\""))
    if i > 0:
        head = head[:i]
    else:
        head = head[:max(0, cap - 256)]
    return head + "...[cut]"


def _safe_str(obj: Any, limit: int = 512) -> str:
    try:
        return str(obj)[:limit]
    except Exception:  # noqa: BLE001 - arbitrary __str__ must never break logging
        return "<unprintable %s>" % type(obj).__name__


def _safe_repr(obj: Any, limit: int = 200) -> str:
    try:
        return repr(obj)[:limit]
    except Exception:  # noqa: BLE001
        return "<unprintable %s>" % type(obj).__name__


class _Redactor:
    """One-shot structural copier/redactor for a single event."""

    def __init__(self, policy: RedactionPolicy) -> None:
        self.p = policy
        self.counts: Dict[str, int] = {}
        self.nodes = 0
        self.clipped = False
        lits = sorted({l for l in policy.literals if isinstance(l, str) and len(l) >= 4}, key=len, reverse=True)
        self._lits = lits
        home = os.path.expanduser("~") if policy.scrub_home else ""
        self._home = home if len(home) > 1 else ""

    def _hit(self, cls: str, n: int = 1) -> str:
        self.counts[cls] = self.counts.get(cls, 0) + n
        return _MARK.get(cls, "[REDACTED]")

    # -- strings ---------------------------------------------------------- #
    def text(self, s: str, ids: bool = False) -> str:
        p = self.p
        if len(s) > p.raw_str_cap:
            s = _cut_at_boundary(s, p.raw_str_cap)
            self.clipped = True
        for lit in self._lits:
            if lit in s:
                n = s.count(lit)
                s = s.replace(lit, self._hit("literal", n))
        if self._home and self._home in s:
            s = s.replace(self._home, "~")
            self._hit("home")
        s = _PEM_RE.sub(lambda m: self._hit("pem"), s)
        s = _JWT_RE.sub(lambda m: self._hit("jwt"), s)
        s = _TOKEN_PREFIX_RE.sub(lambda m: self._hit("token"), s)
        s = _USERINFO_RE.sub(lambda m: self._hit("userinfo") + "@", s)
        s = _BEARER_RE.sub(lambda m: m.group(1) + m.group(2) + self._hit("token"), s)

        def kv(m: "re.Match[str]") -> str:
            v = m.group("v")
            if v.strip("'\"").startswith("[REDACTED"):
                return m.group(0)
            q = v[0] if v[:1] in ("'", '"') else ""
            return m.group("k") + m.group("sep") + q + self._hit("secret") + q

        s = _KV_RE.sub(kv, s)
        if p.redact_macs:
            s = _MAC_RE.sub(lambda m: self._hit("mac"), s)
        if p.redact_ipv6:
            def ip6(m: "re.Match[str]") -> str:
                t = m.group(0)
                if t in ("::", "::1") or t.lower().startswith("2001:db8"):
                    return t
                return self._hit("ip6")
            s = _IPV6_RE.sub(ip6, s)
        if p.redact_ipv4:
            s = _IPV4_RE.sub(lambda m: self._hit("ip") if _ipv4_public_identifier(m.group(0)) else m.group(0), s)
        if p.redact_emails:
            s = _EMAIL_RE.sub(lambda m: self._hit("email"), s)
        if p.redact_opaque_tokens and not ids:
            def opaque(m: "re.Match[str]") -> str:
                t = m.group(0)
                if _HEX_RE.match(t):
                    return t  # digests are evidence, not secrets
                if not (any(c.isupper() for c in t) and any(c.islower() for c in t) and any(c.isdigit() for c in t)):
                    return t
                return self._hit("opaque")
            s = _OPAQUE_RE.sub(opaque, s)
        if len(s) > p.max_str_len:
            extra = len(s) - p.max_str_len
            s = s[:p.max_str_len] + "...[+%d chars]" % extra
            self.clipped = True
        return s

    def ident(self, value: Any, limit: int) -> str:
        s = value if isinstance(value, str) else _safe_str(value)
        return self.text(s, ids=True)[:limit]

    # -- structures ------------------------------------------------------- #
    def walk(self, obj: Any, depth: int = 0) -> Any:
        self.nodes += 1
        if self.nodes > self.p.max_nodes:
            self.clipped = True
            return "[NODE_LIMIT]"
        if obj is None or isinstance(obj, bool):
            return obj
        if isinstance(obj, int):
            if -(1 << 63) <= obj < (1 << 64):
                return obj
            return "<int:%dbits>" % obj.bit_length()
        if isinstance(obj, float):
            if math.isfinite(obj):
                return obj
            return "NaN" if math.isnan(obj) else ("Infinity" if obj > 0 else "-Infinity")
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, (bytes, bytearray, memoryview)):
            self._hit("audio")
            n = obj.nbytes if isinstance(obj, memoryview) else len(obj)
            return {"redacted": "binary", "len": n}
        if depth >= self.p.max_depth:
            self.clipped = True
            return "[DEPTH_LIMIT]"
        if isinstance(obj, BaseException):
            return {"type": type(obj).__name__, "msg": self.text(_safe_str(obj))}
        if isinstance(obj, Mapping):
            return self._mapping(obj, depth)
        if isinstance(obj, (list, tuple, set, frozenset)):
            return self._sequence(obj, depth)
        return self.text(_safe_repr(obj))

    def _mapping(self, obj: Mapping, depth: int) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        p = self.p
        try:
            total = len(obj)
        except Exception:  # noqa: BLE001
            total = p.max_items
        count = 0
        for k, v in obj.items():
            if count >= p.max_items:
                break
            count += 1
            kname = k if isinstance(k, str) else _safe_str(k, 128)
            ks = self.text(kname)[:64]
            cls = classify_key(kname)
            if cls in ("secret", "account", "site") and not isinstance(v, _SCALARS):
                val: Any = self._hit(cls)
            elif cls == "audio" and self._audio_nonscalar(v):
                self._hit("audio")
                val = {"redacted": "audio_payload", "len": _safe_len(v)}
            else:
                val = self.walk(v, depth + 1)
            if ks in out:
                n = 2
                while "%s#%d" % (ks, n) in out:
                    n += 1
                ks = "%s#%d" % (ks, n)
            out[ks] = val
        if total > count:
            out["_clipped_items"] = total - count
            self.clipped = True
        return out

    @staticmethod
    def _audio_nonscalar(v: Any) -> bool:
        if isinstance(v, _SCALARS):
            return False
        if isinstance(v, str):
            return len(v) > 64
        return True

    def _sequence(self, obj: Any, depth: int) -> List[Any]:
        p = self.p
        if isinstance(obj, (set, frozenset)):
            items = list(itertools.islice(obj, p.max_items + 1))
            n = len(obj)
        else:
            items = obj
            n = len(items)
        if isinstance(obj, (list, tuple)) and n > p.max_numeric_seq:
            probe = items[:64]
            if all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in probe):
                self._hit("audio")
                return [{"redacted": "numeric_sequence", "len": n}]
        out = [self.walk(x, depth + 1) for x in items[: p.max_items]]
        if isinstance(obj, (set, frozenset)):
            out.sort(key=lambda x: json.dumps(x, sort_keys=True, default=str))
        if n > p.max_items:
            out.append("[+%d more]" % (n - p.max_items))
            self.clipped = True
        return out


def _safe_len(v: Any) -> int:
    try:
        return len(v)
    except Exception:  # noqa: BLE001
        return -1


def redact_text(text: str, policy: Optional[RedactionPolicy] = None) -> str:
    """Redact one string with the sink's patterns (for callers that log elsewhere)."""
    return _Redactor(policy or RedactionPolicy()).text(text)


def redact_value(obj: Any, policy: Optional[RedactionPolicy] = None) -> Any:
    """Bounded, redacted, JSON-safe copy of ``obj``."""
    return _Redactor(policy or RedactionPolicy()).walk(obj)


def pseudonymize(key: bytes, kind: str, raw: Any) -> str:
    """Keyed, one-way, stable identifier: ``m-``/``g-``/``x-`` + 12 hex of HMAC-SHA256."""
    digest = hmac.new(key, (kind + "\x00" + str(raw)).encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()[:12]
    return ("m-" if kind == "member" else "g-" if kind == "group" else "x-") + digest


def exception_chain(exc: BaseException, max_depth: int = 8) -> List[Dict[str, str]]:
    """Causal chain (``__cause__`` / implicit ``__context__``) as ``[{"type","msg"}, ...]``.

    Messages are raw here; ``emit(cause=...)`` redacts them. No tracebacks, so
    no file paths leak.
    """
    out: List[Dict[str, str]] = []
    seen = set()
    cur: Optional[BaseException] = exc
    while cur is not None and len(out) < max_depth and id(cur) not in seen:
        seen.add(id(cur))
        out.append({"type": type(cur).__name__, "msg": _safe_str(cur)})
        nxt = cur.__cause__
        if nxt is None and not cur.__suppress_context__:
            nxt = cur.__context__
        cur = nxt
    return out


# --------------------------------------------------------------------------- #
# targets (where bytes go)
# --------------------------------------------------------------------------- #

class FileSink:
    """Append-only file target.

    * Created with ``O_EXCL`` by default, so an existing log is **never**
      appended to or clobbered: reruns keep the original evidence and a second
      sink pointed at the same path becomes "unavailable" instead of corrupting
      the first. Pass ``exclusive=False`` for devices/FIFOs.
    * Opened lazily on first write, so "cannot open" is just another write
      failure handled by the sink's availability state machine.
    * The path is made absolute at construction, so a later ``chdir`` cannot
      redirect the log.
    * ``write`` either writes every byte or raises; a raise after a partial
      write leaves a torn line which the sink terminates before the next record.
    """

    def __init__(self, path: Union[str, "os.PathLike[str]"], *, exclusive: bool = True, fsync_on_close: bool = True) -> None:
        self.path = os.path.abspath(os.fspath(path))
        self._exclusive = exclusive
        self._fsync = fsync_on_close
        self._fd: Optional[int] = None

    def write(self, data: bytes) -> None:
        if self._fd is None:
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_CLOEXEC", 0)
            if self._exclusive:
                flags |= os.O_EXCL
            self._fd = os.open(self.path, flags, 0o666)
        view = memoryview(data)
        off = 0
        while off < len(view):
            n = os.write(self._fd, view[off:])
            if n <= 0:
                raise OSError(errno.EIO, "zero-length write")
            off += n

    def close(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            if self._fsync:
                try:
                    os.fsync(fd)
                except OSError as exc:
                    # fsync is meaningless on some devices; anything else is a real durability failure
                    if exc.errno not in (errno.EINVAL, errno.ENOTSUP, errno.EBADF):
                        raise
        finally:
            os.close(fd)


class FaultableSink:
    """In-memory target with *explicit, recorded* fault injection (test double).

    Every fault here is **injected** and is labelled as such in
    ``fault_schedule``; an ENOSPC raised by this class is not evidence about a
    real disk. Real-OS failure paths are covered separately by tests that use
    ``FileSink`` against ``RLIMIT_FSIZE`` and ``/dev/full`` where available.

    * ``capacity_bytes`` + ``partial_on_full``: "full device" - writes past the
      capacity raise ``ENOSPC`` after storing the bytes that still fit.
    * ``available = False``: every write raises ``EIO`` ("unavailable").
    * ``fail_next(n, exc)``: the next *n* writes raise ``exc``.
    * ``gate()`` / ``permit(n)`` / ``ungate()``: writes block until permitted
      ("slow"/"hung"); ``entered`` is set when a write is blocked in the gate.
    """

    def __init__(self, *, capacity_bytes: Optional[int] = None, partial_on_full: bool = True,
                 gate_timeout_s: float = 30.0) -> None:
        self.data = bytearray()
        self.capacity_bytes = capacity_bytes
        self.partial_on_full = partial_on_full
        self.available = True
        self.writes = 0
        self.closed = False
        self.close_error: Optional[BaseException] = None
        self.entered = threading.Event()
        self.fault_schedule: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._fail_left = 0
        self._fail_exc: Optional[BaseException] = None
        self._sem: Optional[threading.Semaphore] = None
        self._gate_timeout = gate_timeout_s

    # -- fault controls --------------------------------------------------- #
    def gate(self) -> None:
        self._sem = threading.Semaphore(0)
        self._record("gate_on")

    def permit(self, n: int = 1) -> None:
        sem = self._sem
        if sem is not None:
            for _ in range(n):
                sem.release()

    def ungate(self) -> None:
        sem, self._sem = self._sem, None
        if sem is not None:
            for _ in range(1 << 12):  # release any number of blocked writers
                sem.release()
        self._record("gate_off")

    def fail_next(self, n: int, exc: Optional[BaseException] = None) -> None:
        with self._lock:
            self._fail_left = n
            self._fail_exc = exc
        self._record("fail_next", n=n)

    def _record(self, fault: str, **kw: Any) -> None:
        with self._lock:
            self.fault_schedule.append(dict(fault=fault, write_index=self.writes, **kw))

    # -- target API ------------------------------------------------------- #
    def write(self, data: bytes) -> None:
        with self._lock:
            self.writes += 1
            idx = self.writes
        sem = self._sem
        if sem is not None:
            self.entered.set()
            if not sem.acquire(timeout=self._gate_timeout):
                raise TimeoutError("FaultableSink gate was never permitted")
        with self._lock:
            if not self.available:
                self.fault_schedule.append({"fault": "unavailable_eio", "write_index": idx, "injected": True})
                raise OSError(errno.EIO, "injected: sink unavailable")
            if self._fail_left > 0:
                self._fail_left -= 1
                exc = self._fail_exc or OSError(errno.EIO, "injected: scripted failure")
                self.fault_schedule.append({"fault": "fail_next", "write_index": idx, "injected": True})
                raise exc
            cap = self.capacity_bytes
            if cap is not None and len(self.data) + len(data) > cap:
                room = max(0, cap - len(self.data))
                if self.partial_on_full and room:
                    self.data += data[:room]
                self.fault_schedule.append({"fault": "enospc", "write_index": idx, "injected": True, "stored": room if self.partial_on_full else 0})
                raise OSError(errno.ENOSPC, "injected: no space left on device")
            self.data += data

    def close(self) -> None:
        self.closed = True
        if self.close_error is not None:
            raise self.close_error

    # -- inspection ------------------------------------------------------- #
    def text(self) -> str:
        return bytes(self.data).decode("utf-8", "replace")

    def records(self) -> List[Dict[str, Any]]:
        out = []
        for line in bytes(self.data).split(b"\n"):
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
        return out


# --------------------------------------------------------------------------- #
# verdicts
# --------------------------------------------------------------------------- #

class EvidenceIncomplete(Exception):
    """Raised by ``EvidenceVerdict.require_complete`` - qualification is invalid."""

    def __init__(self, verdict: "EvidenceVerdict") -> None:
        super().__init__("diagnostic evidence incomplete: " + ", ".join(verdict.reasons))
        self.verdict = verdict


@dataclasses.dataclass(frozen=True)
class EvidenceVerdict:
    complete: bool
    reasons: Tuple[str, ...]
    critical_lost: int
    critical_lost_cases: Tuple[str, ...]
    dropped_total: int

    def require_complete(self) -> "EvidenceVerdict":
        if not self.complete:
            raise EvidenceIncomplete(self)
        return self

    def as_dict(self) -> Dict[str, Any]:
        return {
            "complete": self.complete,
            "reasons": list(self.reasons),
            "critical_lost": self.critical_lost,
            "critical_lost_cases": list(self.critical_lost_cases),
            "dropped_total": self.dropped_total,
        }


def downgrade_pass_if_incomplete(outcome: str, verdict: Union[EvidenceVerdict, "LogAudit"], *,
                                 pass_value: str = "pass", incomplete_value: str = "incomplete") -> str:
    """A pass cannot rest on lost evidence. Failures stay failures; only a pass is downgraded."""
    if outcome == pass_value and not verdict.complete:
        return incomplete_value
    return outcome


# --------------------------------------------------------------------------- #
# the sink
# --------------------------------------------------------------------------- #

class _Rec:
    __slots__ = ("seq", "line", "nbytes", "critical", "case", "attempts", "kind")

    def __init__(self, seq: int, line: bytes, critical: bool, case: str, kind: str = "event") -> None:
        self.seq = seq
        self.line = line
        self.nbytes = len(line)
        self.critical = critical
        self.case = case
        self.attempts = 0
        self.kind = kind


def _dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _norm_level(level: Any) -> str:
    if isinstance(level, str):
        lv = level.lower()
        lv = _LEVEL_ALIASES.get(lv, lv)
        if lv in LEVELS:
            return lv
    return "info"


class BoundEmitter:
    """A sink view with default envelope fields (e.g. ``case_id``)."""

    def __init__(self, sink: "DiagnosticSink", defaults: Mapping[str, Any]) -> None:
        self._sink = sink
        self._defaults = dict(defaults)

    def emit(self, kind: str, **kw: Any) -> bool:
        merged = dict(self._defaults)
        if isinstance(merged.get("fields"), Mapping) and isinstance(kw.get("fields"), Mapping):
            kw["fields"] = {**merged["fields"], **kw["fields"]}
        merged.update(kw)
        return self._sink.emit(kind, **merged)

    def bind(self, **more: Any) -> "BoundEmitter":
        return BoundEmitter(self._sink, {**self._defaults, **more})


class DiagnosticSink:
    """Bounded, nonblocking, redacting JSONL diagnostic sink. See module docstring."""

    def __init__(self, target: Any, *, run_id: str, limits: Optional[SinkLimits] = None,
                 redaction: Optional[RedactionPolicy] = None,
                 clock_ns: Callable[[], int] = time.monotonic_ns,
                 wall_clock: Optional[Callable[[], float]] = None,
                 pseudonym_key: Union[bytes, str, None] = None, threaded: bool = True,
                 header_extra: Optional[Mapping[str, Any]] = None) -> None:
        if not isinstance(run_id, str) or not _ID_RE.match(run_id):
            raise ValueError("run_id must match %s" % _ID_RE.pattern)
        self._target = target
        self._run_id = run_id
        self._limits = limits or SinkLimits()
        self._policy = redaction or RedactionPolicy()
        self._clock = clock_ns
        self._threaded = bool(threaded)
        if pseudonym_key is None:
            self._key = os.urandom(16)
            self._key_source = "random"
        else:
            self._key = pseudonym_key.encode("utf-8") if isinstance(pseudonym_key, str) else bytes(pseudonym_key)
            self._key_source = "provided"

        self._lock = threading.RLock()
        self._cond = threading.Condition(self._lock)
        self._seq = 0
        self._q_crit: "collections.deque[_Rec]" = collections.deque()
        self._q_norm: "collections.deque[_Rec]" = collections.deque()
        self._qbytes = 0
        self._inflight: List[_Rec] = []
        self._inflight_bytes = 0
        self._bytes_written = 0
        self._state = "ok"
        self._consec = 0
        self._next_probe_ns = 0
        self._needs_resync = False
        self._closing = False
        self._closed = False
        self._stop = False
        self._abandoned = False
        self._writer_hung = False
        self._writer_crashed = False
        self._header_written = False
        self._footer_written = False
        self._close_error: Optional[str] = None
        self._last_error: Optional[str] = None
        self._last_internal_error: Optional[str] = None
        self._lost_cases: Dict[str, int] = {}
        self._loss: Dict[str, Any] = {"n": 0, "crit": 0, "by": {}, "first": None, "last": None}
        self._c: Dict[str, Any] = {
            "emitted": 0, "emitted_critical": 0, "accepted": 0, "written": 0, "written_critical": 0,
            "dropped_total": 0, "dropped": {r: 0 for r in DROP_REASONS},
            "critical_lost": 0, "critical_lost_by_reason": {},
            "truncated_events": 0, "invalid_counters": 0, "clock_errors": 0, "clock_regressions": 0,
            "write_errors": 0, "bytes_written": 0, "queue_peak_events": 0, "queue_peak_bytes": 0,
            "redactions": {},
        }

        origin = self._read_clock()
        self._origin_ns = origin
        self._last_ns = origin
        lim = self._limits
        self._tokens = float(lim.burst_events)
        self._tb_last = origin
        self._noncrit_limit = lim.max_file_bytes - lim.critical_reserve_bytes
        self._crit_limit = lim.max_file_bytes - lim.footer_reserve_bytes

        wall_iso = None
        if wall_clock is not None:
            try:
                wall_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(wall_clock()))
            except Exception:  # noqa: BLE001
                wall_iso = None
        header = {
            "schema": SCHEMA, "type": "header", "producer": PRODUCER, "run": run_id, "seq": 0,
            "mono_ns": origin,
            "timebase": {"clock": "monotonic_ns", "origin_mono_ns": origin, "origin_wall_utc": wall_iso},
            "limits": dataclasses.asdict(lim),
            "redaction": self._policy.public(),
            "pseudonym": {"scheme": "hmac-sha256/12", "key_source": self._key_source},
            "python": sys.version.split()[0], "platform": sys.platform,
        }
        if header_extra:
            red = _Redactor(self._policy)
            header["extra"] = red.walk(dict(header_extra), 1)
        hline = _dumps(header)
        if len(hline) > 4096:
            header["extra"] = {"_dropped": "oversize"}
            hline = _dumps(header)
        rec = _Rec(0, (hline + "\n").encode("ascii"), True, "", "header")
        self._q_crit.append(rec)
        self._qbytes += rec.nbytes

        self._thread: Optional[threading.Thread] = None
        if self._threaded:
            self._thread = threading.Thread(target=self._run, name="ff-diag-writer-" + run_id, daemon=True)
            self._thread.start()

    # -- construction helpers --------------------------------------------- #
    @classmethod
    def to_file(cls, path: Union[str, "os.PathLike[str]"], *, run_id: str, exclusive: bool = True,
                fsync_on_close: bool = True, **kw: Any) -> "DiagnosticSink":
        return cls(FileSink(path, exclusive=exclusive, fsync_on_close=fsync_on_close), run_id=run_id, **kw)

    def __enter__(self) -> "DiagnosticSink":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def path(self) -> Optional[str]:
        return getattr(self._target, "path", None)

    @property
    def critical_lost(self) -> int:
        with self._lock:
            return int(self._c["critical_lost"])

    @property
    def open_error(self) -> Optional[str]:
        """Last target error if the header never reached the target, else None."""
        with self._lock:
            return None if self._header_written else self._last_error

    def pseudonym(self, kind: str, raw: Any) -> str:
        return pseudonymize(self._key, kind, raw)

    def bind(self, **defaults: Any) -> BoundEmitter:
        return BoundEmitter(self, defaults)

    # -- clock ------------------------------------------------------------ #
    def _read_clock(self) -> int:
        try:
            return int(self._clock())
        except Exception:  # noqa: BLE001 - a broken clock must not break emit()
            try:
                self._c["clock_errors"] += 1
            except Exception:  # noqa: BLE001
                pass
            return getattr(self, "_last_ns", 0)

    # -- emit ------------------------------------------------------------- #
    def emit(self, kind: str, *, level: str = "info", critical: bool = False,
             case_id: Any = None, correlation_id: Any = None, member: Any = None, group: Any = None,
             source_epoch: Any = None, command_rev: Any = None, state_rev: Any = None,
             counters: Optional[Mapping[str, Any]] = None, fault: Any = None, cause: Any = None,
             fields: Optional[Mapping[str, Any]] = None) -> bool:
        """Queue one event. Returns True iff it was accepted. Never blocks on I/O, never raises."""
        critical = bool(critical)
        body: Optional[str] = None
        case_key = ""
        flags = {"truncated": False, "invalid_counters": 0, "redactions": {}}
        build_failed = False
        try:
            body, case_key, flags = self._build_body(
                kind, level, critical, case_id, correlation_id, member, group, source_epoch,
                command_rev, state_rev, counters, fault, cause, fields)
        except Exception as exc:  # noqa: BLE001 - emit() must never raise
            build_failed = True
            self._last_internal_error = "%s: %s" % (type(exc).__name__, _safe_str(exc, 120))
        with self._lock:
            self._seq += 1
            seq = self._seq
            c = self._c
            c["emitted"] += 1
            if critical:
                c["emitted_critical"] += 1
            try:
                for k, n in flags["redactions"].items():
                    c["redactions"][k] = c["redactions"].get(k, 0) + n
                c["invalid_counters"] += flags["invalid_counters"]
                if build_failed:
                    return self._drop_locked("internal_error", critical, case_key, seq)
                if body is None:
                    return self._drop_locked("oversize", critical, case_key, seq)
                if self._closing:
                    return self._drop_locked("closed", critical, case_key, seq)
                now = self._read_clock()
                if now < self._last_ns:
                    c["clock_regressions"] += 1
                    now = self._last_ns
                self._last_ns = now
                line = ('{"schema":"%s","type":"event","seq":%d,"mono_ns":%d,' % (SCHEMA, seq, now) + body[1:] + "\n").encode("ascii")
                n = len(line)
                lim = self._limits
                committed = self._bytes_written + self._qbytes + self._inflight_bytes
                qlen = len(self._q_crit) + len(self._q_norm)
                if critical:
                    if committed + n > self._crit_limit:
                        return self._drop_locked("disk_budget", critical, case_key, seq)
                    while (qlen >= lim.max_queue_events or self._qbytes + n > lim.max_queue_bytes) and self._q_norm:
                        old = self._q_norm.popleft()
                        self._qbytes -= old.nbytes
                        qlen -= 1
                        self._drop_locked("evicted_for_critical", False, old.case, old.seq)
                    if qlen >= lim.max_queue_events:
                        return self._drop_locked("queue_full", critical, case_key, seq)
                    if self._qbytes + n > lim.max_queue_bytes:
                        return self._drop_locked("queue_bytes", critical, case_key, seq)
                else:
                    if not self._take_token_locked(now):
                        return self._drop_locked("rate_limited", critical, case_key, seq)
                    if committed + n > self._noncrit_limit:
                        return self._drop_locked("disk_budget", critical, case_key, seq)
                    if qlen >= lim.max_queue_events:
                        return self._drop_locked("queue_full", critical, case_key, seq)
                    if self._qbytes + n > lim.max_queue_bytes:
                        return self._drop_locked("queue_bytes", critical, case_key, seq)
                rec = _Rec(seq, line, critical, case_key)
                (self._q_crit if critical else self._q_norm).append(rec)
                self._qbytes += n
                c["accepted"] += 1
                if flags["truncated"]:
                    c["truncated_events"] += 1
                c["queue_peak_events"] = max(c["queue_peak_events"], qlen + 1)
                c["queue_peak_bytes"] = max(c["queue_peak_bytes"], self._qbytes)
                self._cond.notify_all()
                return True
            except Exception as exc:  # noqa: BLE001
                self._last_internal_error = "%s: %s" % (type(exc).__name__, _safe_str(exc, 120))
                return self._drop_locked("internal_error", critical, case_key, seq)

    def emit_event(self, event: str, critical: bool = False, **fields: Any) -> bool:
        """``emit(event, critical, **fields)`` shape used by the suite runner.

        Recognised envelope keys (``case_id``, ``corr``/``correlation_id``,
        ``level``, ``member``, ``group``, ``source_epoch``, ``command_rev``,
        ``state_rev``, ``counters``, ``fault``, ``cause``) are lifted out; every
        other keyword becomes a free-form field.
        """
        env: Dict[str, Any] = {}
        for src, dst in (("case_id", "case_id"), ("corr", "correlation_id"), ("correlation_id", "correlation_id"),
                         ("level", "level"), ("member", "member"), ("group", "group"),
                         ("source_epoch", "source_epoch"), ("command_rev", "command_rev"),
                         ("state_rev", "state_rev"), ("counters", "counters"), ("fault", "fault"),
                         ("cause", "cause")):
            if src in fields:
                env[dst] = fields.pop(src)
        return self.emit(event, critical=critical, fields=fields or None, **env)

    def _build_body(self, kind: Any, level: Any, critical: bool, case_id: Any, correlation_id: Any,
                    member: Any, group: Any, source_epoch: Any, command_rev: Any, state_rev: Any,
                    counters: Any, fault: Any, cause: Any, fields: Any) -> Tuple[str, str, Dict[str, Any]]:
        red = _Redactor(self._policy)
        ev: Dict[str, Any] = {"level": _norm_level(level), "kind": red.ident(kind, 64) or "unspecified"}
        if critical:
            ev["critical"] = True
        ev["run"] = self._run_id
        case_key = ""
        if case_id is not None:
            case_key = red.ident(case_id, 128)
            ev["case"] = case_key
        if correlation_id is not None:
            ev["corr"] = red.ident(correlation_id, 128)
        if member is not None:
            ev["member"] = self.pseudonym("member", member)
        if group is not None:
            ev["group"] = self.pseudonym("group", group)
        for name, val in (("epoch", source_epoch), ("cmd_rev", command_rev), ("state_rev", state_rev)):
            if val is not None:
                ev[name] = red.walk(val, 5) if isinstance(val, (int, float)) and not isinstance(val, bool) else red.ident(val, 64)
        invalid = 0
        if counters:
            out: Dict[str, Any] = {}
            for i, (k, v) in enumerate(counters.items()):
                if i >= 32:
                    red.clipped = True
                    break
                if isinstance(v, bool) or not isinstance(v, (int, float)) or (isinstance(v, float) and not math.isfinite(v)):
                    invalid += 1
                    continue
                out[red.ident(k, 64)] = v if not isinstance(v, int) or -(1 << 63) <= v < (1 << 64) else 0
            ev["counters"] = out
        if fault is not None:
            ev["fault"] = red.walk(fault, 1)
        if cause is not None:
            seq = [cause] if isinstance(cause, (str, BaseException, Mapping)) else list(cause)[:8]
            ev["cause"] = [red.walk(x, 2) for x in seq[:8]]
        if fields is not None:
            ev["fields"] = red.walk(fields, 1)
        if red.clipped:
            ev["truncated"] = True
        body = _dumps(ev)
        limit = self._limits.max_event_bytes - _ENVELOPE_SLACK
        shrunk = False
        if len(body) > limit:
            shrunk = True
            ev["truncated"] = True
            for key in ("fields", "cause", "fault", "counters"):
                if key in ev:
                    ev[key] = [{"_dropped": "oversize"}] if key == "cause" else {"_dropped": "oversize"}
                    body = _dumps(ev)
                    if len(body) <= limit:
                        break
            if len(body) > limit:
                return None, case_key, {"truncated": True, "invalid_counters": invalid, "redactions": red.counts}  # type: ignore[return-value]
        return body, case_key, {"truncated": bool(red.clipped or shrunk), "invalid_counters": invalid,
                                "redactions": red.counts}

    # -- accounting ------------------------------------------------------- #
    def _drop_locked(self, reason: str, critical: bool, case_key: str, seq: int) -> bool:
        c = self._c
        c["dropped"][reason] += 1
        c["dropped_total"] += 1
        self._loss["n"] += 1
        self._loss["by"][reason] = self._loss["by"].get(reason, 0) + 1
        if self._loss["first"] is None or seq < self._loss["first"]:
            self._loss["first"] = seq
        if self._loss["last"] is None or seq > self._loss["last"]:
            self._loss["last"] = seq
        if critical:
            c["critical_lost"] += 1
            c["critical_lost_by_reason"][reason] = c["critical_lost_by_reason"].get(reason, 0) + 1
            self._loss["crit"] += 1
            key = case_key if (case_key in self._lost_cases or len(self._lost_cases) < self._limits.max_tracked_cases) else "_overflow"
            self._lost_cases[key] = self._lost_cases.get(key, 0) + 1
        return False

    def _take_token_locked(self, now: int) -> bool:
        rate = self._limits.max_events_per_sec
        if rate is None:
            return True
        dt = max(0, now - self._tb_last)
        self._tb_last = now
        self._tokens = min(float(self._limits.burst_events), self._tokens + dt * rate / 1e9)
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    # -- writer ----------------------------------------------------------- #
    def _pop_next_locked(self) -> Optional[_Rec]:
        qc, qn = self._q_crit, self._q_norm
        if qc and (not qn or qc[0].seq < qn[0].seq):
            rec = qc.popleft()
        elif qn:
            rec = qn.popleft()
        else:
            return None
        self._qbytes -= rec.nbytes
        return rec

    def _has_work_locked(self, now: int) -> bool:
        if not (self._q_crit or self._q_norm):
            return False
        return not (self._state != "ok" and now < self._next_probe_ns)

    def _marker_locked(self, first: _Rec) -> Optional[Tuple[bytes, Dict[str, Any]]]:
        loss = self._loss
        if loss["n"] <= 0:
            return None
        snap = {"n": loss["n"], "crit": loss["crit"], "by": dict(loss["by"])}
        obj = {"schema": SCHEMA, "type": "loss", "run": self._run_id, "at_seq": first.seq,
               "first_dropped_seq": loss["first"], "last_dropped_seq": loss["last"],
               "mono_ns": self._last_ns, "dropped": {k: v for k, v in snap["by"].items() if v},
               "dropped_critical": snap["crit"]}
        line = (_dumps(obj) + "\n").encode("ascii")
        committed = self._bytes_written + self._qbytes + self._inflight_bytes
        if committed + len(line) + len(_RESYNC) > self._crit_limit:
            return None
        return line, snap

    def _drain_once(self, *, force: bool = False) -> int:
        """Write one batch. Returns records durably handed to the target."""
        now = self._read_clock()
        with self._lock:
            if self._abandoned:
                return 0
            if self._state != "ok" and not force and now < self._next_probe_ns:
                return 0  # after ANY failure, retries are spaced by retry_interval_s so the attempt budget spans real time
            cap = 1 if self._state != "ok" else self._limits.drain_batch
            batch: List[_Rec] = []
            while len(batch) < cap:
                rec = self._pop_next_locked()
                if rec is None:
                    break
                batch.append(rec)
            if not batch:
                return 0
            self._inflight = list(batch)
            self._inflight_bytes = sum(r.nbytes for r in batch)
            resync = self._needs_resync
            # An in-band loss marker precedes the first NON-header record, so it can never sit ahead of the header.
            marker_idx = 1 if batch[0].kind == "header" else 0
            marker = self._marker_locked(batch[marker_idx]) if len(batch) > marker_idx else None
        written = 0
        for i, rec in enumerate(batch):
            prefix = _RESYNC if resync and i == 0 else b""
            try:
                if i == marker_idx and marker is not None:
                    # The marker is its own write, cleared the moment it lands. If it shared a write
                    # with the record, a failure after the marker landed would leave it pending and
                    # the retry would record the same losses twice.
                    self._target.write(prefix + marker[0])
                    self._on_marker_written(len(prefix) + len(marker[0]), marker[1])
                    prefix = b""
                self._target.write(prefix + rec.line)
            except Exception as exc:  # noqa: BLE001 - target failures are loss, not crashes
                self._on_failure(batch[i:], exc, now)
                return written
            self._on_success(rec, len(prefix) + rec.nbytes)
            written += 1
        with self._cond:
            if not self._abandoned:
                self._inflight = []
                self._inflight_bytes = 0
            self._cond.notify_all()
        return written

    def _on_marker_written(self, nbytes: int, snap: Dict[str, Any]) -> None:
        with self._lock:
            if self._abandoned:
                return
            self._bytes_written += nbytes
            self._c["bytes_written"] = self._bytes_written
            self._loss["n"] -= snap["n"]
            self._loss["crit"] -= snap["crit"]
            for k, v in snap["by"].items():
                self._loss["by"][k] = self._loss["by"].get(k, 0) - v
            if self._loss["n"] <= 0:
                self._loss["first"] = self._loss["last"] = None
            self._needs_resync = False

    def _on_success(self, rec: _Rec, nbytes: int) -> None:
        with self._lock:
            if self._abandoned:
                return
            if self._inflight and self._inflight[0] is rec:
                self._inflight.pop(0)
                self._inflight_bytes -= rec.nbytes
            self._bytes_written += nbytes
            c = self._c
            c["bytes_written"] = self._bytes_written
            if rec.kind == "header":
                self._header_written = True
            else:
                c["written"] += 1
                if rec.critical:
                    c["written_critical"] += 1
            self._consec = 0
            self._state = "ok"
            self._needs_resync = False

    def _on_failure(self, remaining: List[_Rec], exc: BaseException, now: int) -> None:
        with self._cond:
            if self._abandoned:
                return
            lim = self._limits
            self._inflight = []
            self._inflight_bytes = 0
            self._c["write_errors"] += 1
            self._consec += 1
            self._last_error = _Redactor(self._policy).text("%s: %s" % (type(exc).__name__, _safe_str(exc, 200)))[:256]
            self._needs_resync = True
            self._state = "unavailable" if self._consec >= lim.failure_threshold else "degraded"
            self._next_probe_ns = now + int(lim.retry_interval_s * 1e9)
            failing, rest = remaining[0], remaining[1:]
            failing.attempts += 1
            requeue: List[_Rec] = list(rest)
            if failing.critical and failing.attempts < lim.critical_max_attempts:
                requeue.insert(0, failing)
            elif failing.kind != "header":
                self._drop_locked("sink_error", failing.critical, failing.case, failing.seq)
            for r in reversed(requeue):
                (self._q_crit if r.critical else self._q_norm).appendleft(r)
                self._qbytes += r.nbytes
            self._cond.notify_all()

    def _run(self) -> None:
        try:
            while True:
                with self._cond:
                    while True:
                        if self._stop:
                            return
                        now = self._read_clock()
                        if self._has_work_locked(now):
                            break
                        timeout = None
                        if self._q_crit or self._q_norm:
                            timeout = max(0.005, min(self._limits.retry_interval_s, (self._next_probe_ns - now) / 1e9))
                        self._cond.wait(timeout)
                self._drain_once()
        except BaseException as exc:  # noqa: BLE001 - recorded, surfaced in the verdict
            with self._lock:
                self._writer_crashed = True
                self._last_internal_error = "writer: %s: %s" % (type(exc).__name__, _safe_str(exc, 120))

    def pump(self, max_records: Optional[int] = None) -> int:
        """Drive the writer synchronously (``threaded=False`` sinks only)."""
        if self._threaded:
            raise RuntimeError("pump() is for threaded=False sinks")
        total = 0
        while True:
            n = self._drain_once()
            total += n
            if n == 0 or (max_records is not None and total >= max_records):
                return total

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait until nothing is queued or in flight. False on timeout/unavailable sink."""
        if not self._threaded:
            self.pump()
            with self._lock:
                return not (self._q_crit or self._q_norm or self._inflight)
        deadline = time.monotonic() + timeout
        with self._cond:
            while self._q_crit or self._q_norm or self._inflight:
                rem = deadline - time.monotonic()
                if rem <= 0 or self._writer_crashed:
                    return False
                self._cond.wait(rem)
            return True

    # -- close ------------------------------------------------------------ #
    def close(self, timeout: Optional[float] = None) -> EvidenceVerdict:
        """Stop accepting, drain within ``timeout``, write the footer, close the target. Idempotent."""
        with self._cond:
            if self._closed:
                return self._verdict_locked()
            self._closing = True
            self._stop = True
            self._cond.notify_all()
        budget = self._limits.close_timeout_s if timeout is None else timeout
        deadline = time.monotonic() + budget
        thread = self._thread
        if thread is not None:
            thread.join(max(0.05, deadline - time.monotonic()))  # 50 ms floor: an idle healthy writer needs a moment to see _stop
            if thread.is_alive():
                # Cannot kill a thread blocked inside the target. Do not touch the
                # target concurrently: no footer, remaining evidence is lost.
                with self._cond:
                    self._writer_hung = True
                    self._abandon_locked()
                    self._closed = True
                    self._cond.notify_all()
                    return self._verdict_locked()
        fails = 0
        while time.monotonic() <= deadline:
            with self._lock:
                if not (self._q_crit or self._q_norm):
                    break
                before = self._c["write_errors"]
            self._drain_once(force=True)
            with self._lock:
                if self._c["write_errors"] > before:
                    fails += 1
                    if fails >= self._limits.failure_threshold:
                        break
        with self._cond:
            self._lose_remaining_locked()
        self._write_footer()
        try:
            close = getattr(self._target, "close", None)
            if close is not None:
                close()
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self._close_error = _Redactor(self._policy).text("%s: %s" % (type(exc).__name__, _safe_str(exc, 200)))[:256]
        with self._cond:
            self._closed = True
            self._cond.notify_all()
            return self._verdict_locked()

    def _lose_remaining_locked(self) -> None:
        for q in (self._q_crit, self._q_norm):
            while q:
                rec = q.popleft()
                self._qbytes -= rec.nbytes
                if rec.kind != "header":
                    self._drop_locked("lost_at_close", rec.critical, rec.case, rec.seq)
        for rec in self._inflight:
            if rec.kind != "header":
                self._drop_locked("lost_at_close", rec.critical, rec.case, rec.seq)
        self._inflight = []
        self._inflight_bytes = 0

    def _abandon_locked(self) -> None:
        self._abandoned = True
        self._lose_remaining_locked()

    def _footer_locked(self) -> Dict[str, Any]:
        c = self._c
        reasons = self._reasons_locked(include_footer=False, include_closed=False)
        return {
            "schema": SCHEMA, "type": "footer", "run": self._run_id, "mono_ns": self._last_ns,
            "last_seq": self._seq, "evidence_complete": not reasons, "reasons": reasons,
            "stats": {
                "emitted": c["emitted"], "written": c["written"], "written_critical": c["written_critical"],
                "emitted_critical": c["emitted_critical"], "dropped_total": c["dropped_total"],
                "dropped": {k: v for k, v in c["dropped"].items() if v},
                "critical_lost": c["critical_lost"], "critical_lost_cases": sorted(self._lost_cases)[:16],
                "truncated_events": c["truncated_events"], "redactions": dict(c["redactions"]),
                "bytes_written": c["bytes_written"], "write_errors": c["write_errors"], "sink_state": self._state,
            },
        }

    def _write_footer(self) -> None:
        with self._lock:
            if self._abandoned:
                return
            footer = self._footer_locked()
            resync = self._needs_resync
            room = self._limits.max_file_bytes - self._bytes_written
        line = (_dumps(footer) + "\n").encode("ascii")
        if len(line) + len(_RESYNC) > room:  # shrink: totals only
            footer["stats"] = {k: footer["stats"][k] for k in ("emitted", "written", "written_critical", "dropped_total", "critical_lost")}
            footer["reasons"] = footer["reasons"][:4]
            line = (_dumps(footer) + "\n").encode("ascii")
        if len(line) + len(_RESYNC) > room:
            return  # nothing fits: a missing footer is itself the (honest) incomplete signal
        for attempt in range(3):
            try:
                self._target.write((_RESYNC if resync else b"") + line)
            except Exception as exc:  # noqa: BLE001
                resync = True
                with self._lock:
                    self._c["write_errors"] += 1
                    self._last_error = _Redactor(self._policy).text("%s: %s" % (type(exc).__name__, _safe_str(exc, 200)))[:256]
                continue
            with self._lock:
                self._footer_written = True
                self._bytes_written += len(line)
                self._c["bytes_written"] = self._bytes_written
            return

    # -- verdicts / stats -------------------------------------------------- #
    def _reasons_locked(self, *, include_footer: bool = True, include_closed: bool = True) -> List[str]:
        r: List[str] = []
        if include_closed and not self._closed:
            r.append("not_closed")
        if self._c["critical_lost"]:
            r.append("critical_evidence_lost:%d" % self._c["critical_lost"])
        if not self._header_written:
            r.append("header_not_written")
        if include_footer and not self._footer_written:
            r.append("footer_not_written")
        if self._writer_hung:
            r.append("writer_hung")
        if self._writer_crashed:
            r.append("writer_crashed")
        if self._close_error:
            r.append("sink_close_error")
        return r

    def _verdict_locked(self) -> EvidenceVerdict:
        reasons = self._reasons_locked()
        return EvidenceVerdict(
            complete=not reasons, reasons=tuple(reasons), critical_lost=int(self._c["critical_lost"]),
            critical_lost_cases=tuple(sorted(self._lost_cases)), dropped_total=int(self._c["dropped_total"]))

    def verdict(self) -> EvidenceVerdict:
        """Run-level verdict. Only a clean ``close()`` can make it complete."""
        with self._lock:
            return self._verdict_locked()

    def case_verdict(self, case_id: Any) -> EvidenceVerdict:
        """Has critical evidence for this case (or run-level evidence) been lost, or is it still unflushed?

        Does not require the sink to be closed, so a runner can invalidate one
        case without invalidating the others. Call ``flush()`` first if the
        case's critical events must already be durable.
        """
        key = _Redactor(self._policy).ident(case_id, 128)
        with self._lock:
            lost = self._lost_cases.get(key, 0) + (self._lost_cases.get("", 0) if key != "" else 0) + self._lost_cases.get("_overflow", 0)
            reasons: List[str] = []
            if lost:
                reasons.append("critical_evidence_lost:%d" % lost)
            if any(r.critical and r.case == key for r in list(self._q_crit) + self._inflight):
                reasons.append("pending_unflushed")
            if self._writer_hung:
                reasons.append("writer_hung")
            if self._writer_crashed:
                reasons.append("writer_crashed")
            return EvidenceVerdict(
                complete=not reasons, reasons=tuple(reasons), critical_lost=lost,
                critical_lost_cases=(key,) if lost else (), dropped_total=int(self._c["dropped_total"]))

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            c = self._c
            return {
                "run": self._run_id, "emitted": c["emitted"], "emitted_critical": c["emitted_critical"],
                "accepted": c["accepted"], "written": c["written"], "written_critical": c["written_critical"],
                "dropped_total": c["dropped_total"], "dropped": dict(c["dropped"]),
                "critical_lost": c["critical_lost"], "critical_lost_by_reason": dict(c["critical_lost_by_reason"]),
                "critical_lost_cases": sorted(self._lost_cases),
                "truncated_events": c["truncated_events"], "invalid_counters": c["invalid_counters"],
                "clock_errors": c["clock_errors"], "clock_regressions": c["clock_regressions"],
                "write_errors": c["write_errors"], "bytes_written": c["bytes_written"],
                "queued": len(self._q_crit) + len(self._q_norm), "queued_bytes": self._qbytes,
                "inflight": len(self._inflight), "queue_peak_events": c["queue_peak_events"],
                "queue_peak_bytes": c["queue_peak_bytes"], "redactions": dict(c["redactions"]),
                "sink_state": self._state, "last_error": self._last_error,
                "last_internal_error": self._last_internal_error, "closed": self._closed,
                "header_written": self._header_written, "footer_written": self._footer_written,
                "writer_hung": self._writer_hung, "writer_crashed": self._writer_crashed,
                "close_error": self._close_error, "last_seq": self._seq,
                "limits": dataclasses.asdict(self._limits),
            }

    def summary_record(self, log_path: Union[str, "os.PathLike[str]", None] = None) -> Dict[str, Any]:
        """``ff.diag.summary.v1`` record a receipt can embed (counts, verdict, log identity)."""
        v = self.verdict()
        st = self.stats()
        rec: Dict[str, Any] = {
            "schema": SUMMARY_SCHEMA, "run": self._run_id, "evidence_complete": v.complete,
            "reasons": list(v.reasons), "emitted": st["emitted"], "written": st["written"],
            "dropped_total": st["dropped_total"], "dropped": {k: n for k, n in st["dropped"].items() if n},
            "critical_lost": st["critical_lost"], "critical_lost_cases": list(v.critical_lost_cases),
            "sink_state": st["sink_state"], "log": None,
        }
        path = log_path if log_path is not None else self.path
        if path is not None:
            try:
                rec["log"] = _file_identity(os.fspath(path))
            except OSError:
                rec["log"] = None
        return rec


def _file_identity(path: str) -> Dict[str, Any]:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
            size += len(chunk)
    return {"name": os.path.basename(path), "bytes": size, "sha256": h.hexdigest()}


# --------------------------------------------------------------------------- #
# independent audit of a written log
# --------------------------------------------------------------------------- #

@dataclasses.dataclass
class LogAudit:
    complete: bool
    reasons: List[str]
    warnings: List[str]
    run: Optional[str]
    header: Optional[Dict[str, Any]]
    footer: Optional[Dict[str, Any]]
    events: int
    critical_events: int
    loss_markers: int
    dropped_total: Optional[int]
    critical_lost: Optional[int]
    corrupt_lines: int
    blank_lines: int
    truncated_tail: bool
    bytes: int
    sha256: str

    def as_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["schema"] = "ff.diag.audit.v1"
        return d

    def receipt_log_block(self) -> Dict[str, Any]:
        """The ``log`` object shape ``receipts.validate_case_record`` expects.

        An incomplete audit always sets ``truncated`` or ``critical_lost`` (or
        both), so a receipt cannot call it a pass.
        """
        critical = bool((self.critical_lost or 0) > 0 or any(r.startswith("critical_") for r in self.reasons))
        truncated = any(not r.startswith("critical_") for r in self.reasons)
        return {"sha256": self.sha256, "events": self.events, "dropped": int(self.dropped_total or 0),
                "bytes": self.bytes, "truncated": truncated, "critical_lost": critical}


def _int(x: Any) -> Optional[int]:
    return x if isinstance(x, int) and not isinstance(x, bool) else None


def _audit_stream(f: BinaryIO, max_line_bytes: int) -> LogAudit:
    h = hashlib.sha256()
    total = 0
    header = footer = None
    n_header = n_footer = after_footer = 0
    events = crit_events = markers = corrupt = blank = 0
    mk_drop = mk_crit = 0
    last_seq = 0
    last_ns: Optional[int] = None
    seq_bad = ns_bad = run_bad = unknown = 0
    truncated_tail = False
    first_type: Optional[str] = None
    run: Optional[str] = None
    while True:
        line = f.readline(max_line_bytes + 1)
        if not line:
            break
        h.update(line)
        total += len(line)
        if len(line) > max_line_bytes and not line.endswith(b"\n"):
            ended = False
            while True:
                rest = f.readline(max_line_bytes)
                if not rest:
                    break
                h.update(rest)
                total += len(rest)
                if rest.endswith(b"\n"):
                    ended = True
                    break
            corrupt += 1
            if not ended:
                truncated_tail = True
            continue
        terminated = line.endswith(b"\n")
        body = line.strip()
        if not body:
            blank += 1
            continue
        if not terminated:
            truncated_tail = True  # the writer always terminates records: an unterminated tail was cut
            corrupt += 1
            continue
        try:
            rec = json.loads(body.decode("utf-8"))
        except (ValueError, RecursionError):
            corrupt += 1
            continue
        if not isinstance(rec, dict):
            corrupt += 1
            continue
        typ = rec.get("type")
        if footer is not None:
            after_footer += 1
        if first_type is None:
            first_type = typ if isinstance(typ, str) else "?"
        if typ == "header":
            n_header += 1
            if header is None:
                header = rec
                run = rec.get("run") if isinstance(rec.get("run"), str) else None
        elif typ == "footer":
            n_footer += 1
            if footer is None:
                footer = rec
        elif typ == "event":
            events += 1
            if rec.get("critical") is True:
                crit_events += 1
            s = _int(rec.get("seq"))
            if s is None or s <= last_seq:
                seq_bad += 1
            else:
                last_seq = s
            ns = _int(rec.get("mono_ns"))
            if ns is None or (last_ns is not None and ns < last_ns):
                ns_bad += 1
            elif ns is not None:
                last_ns = ns
            if run is not None and rec.get("run") != run:
                run_bad += 1
        elif typ == "loss":
            markers += 1
            d = rec.get("dropped")
            if isinstance(d, dict):
                mk_drop += sum(v for v in d.values() if _int(v) is not None)
            mk_crit += _int(rec.get("dropped_critical")) or 0
        else:
            unknown += 1

    reasons: List[str] = []
    warnings: List[str] = []
    if total == 0:
        reasons.append("empty_log")
    if header is None:
        reasons.append("missing_header")
    else:
        if first_type != "header":
            reasons.append("header_not_first")
        if header.get("schema") != SCHEMA:
            reasons.append("schema_mismatch")
    if n_header > 1:
        reasons.append("duplicate_header")
    if truncated_tail:
        reasons.append("truncated_tail")
    if footer is None:
        reasons.append("missing_footer")
    if n_footer > 1:
        reasons.append("duplicate_footer")
    if after_footer:
        reasons.append("records_after_footer")
    if seq_bad:
        reasons.append("seq_not_monotonic")
    if ns_bad:
        reasons.append("mono_ns_regressed")
    if run_bad:
        reasons.append("run_mismatch")
    dropped_total: Optional[int] = None
    crit_lost: Optional[int] = None
    if footer is not None:
        if footer.get("schema") != SCHEMA:
            reasons.append("schema_mismatch")
        st = footer.get("stats") if isinstance(footer.get("stats"), dict) else {}
        emitted, written = _int(st.get("emitted")), _int(st.get("written"))
        dropped_total, crit_lost = _int(st.get("dropped_total")), _int(st.get("critical_lost"))
        crit_written = _int(st.get("written_critical"))
        if None in (emitted, written, dropped_total, crit_lost, crit_written):
            reasons.append("footer_stats_invalid")
        else:
            assert emitted is not None and written is not None and dropped_total is not None
            assert crit_lost is not None and crit_written is not None
            if written != events:
                reasons.append("event_count_mismatch")
            if crit_written != crit_events:
                reasons.append("critical_count_mismatch")
            if emitted != events + dropped_total:
                reasons.append("loss_accounting_mismatch")
            if crit_lost > 0:
                reasons.append("critical_evidence_lost:%d" % crit_lost)
            if mk_drop > dropped_total:
                reasons.append("loss_marker_overcount")
            if mk_crit > crit_lost:
                reasons.append("critical_loss_hidden")
            if _int(footer.get("last_seq")) != emitted:
                reasons.append("last_seq_mismatch")
            if last_seq > emitted:
                reasons.append("seq_beyond_footer")
            if footer.get("evidence_complete") is not True and crit_lost == 0:
                reasons.append("footer_declares_incomplete")
    if corrupt:
        warnings.append("corrupt_lines:%d" % corrupt)
    if unknown:
        warnings.append("unknown_record_types:%d" % unknown)
    return LogAudit(
        complete=not reasons, reasons=reasons, warnings=warnings, run=run, header=header, footer=footer,
        events=events, critical_events=crit_events, loss_markers=markers, dropped_total=dropped_total,
        critical_lost=crit_lost, corrupt_lines=corrupt, blank_lines=blank, truncated_tail=truncated_tail,
        bytes=total, sha256=h.hexdigest())


def audit_log(path: Union[str, "os.PathLike[str]"], *, max_line_bytes: int = 1 << 20) -> LogAudit:
    """Re-read a diagnostic log and decide, from the file alone, whether it is a complete record.

    Complete requires: header first; footer last and unique; no unterminated
    tail; monotonic ``seq`` and ``mono_ns``; one run id; and the closure
    identity ``footer.emitted == events_in_file + footer.dropped_total``
    computed over the records actually present. Any lost critical event makes
    it incomplete. An unreadable file is incomplete, never an exception.
    """
    try:
        with open(os.fspath(path), "rb") as f:
            return _audit_stream(f, max_line_bytes)
    except OSError as exc:
        name = errno.errorcode.get(exc.errno or 0, "OSError")
        return LogAudit(complete=False, reasons=["log_unreadable:" + name], warnings=[], run=None, header=None,
                        footer=None, events=0, critical_events=0, loss_markers=0, dropped_total=None,
                        critical_lost=None, corrupt_lines=0, blank_lines=0, truncated_tail=False, bytes=0,
                        sha256=hashlib.sha256(b"").hexdigest())


def audit_bytes(data: bytes, *, max_line_bytes: int = 1 << 20) -> LogAudit:
    """``audit_log`` over in-memory bytes (e.g. a ``FaultableSink.data`` buffer)."""
    return _audit_stream(io.BytesIO(data), max_line_bytes)


def format_summary(source: Union[LogAudit, Mapping[str, Any]]) -> str:
    """One concise human line from a ``LogAudit`` or a ``DiagnosticSink.stats()`` mapping."""
    if isinstance(source, LogAudit):
        state = "COMPLETE" if source.complete else "INCOMPLETE (%s)" % ", ".join(source.reasons)
        return "diag run=%s: evidence %s; events=%d critical=%d dropped=%s critical_lost=%s bytes=%d sha256=%s" % (
            source.run, state, source.events, source.critical_events,
            "?" if source.dropped_total is None else source.dropped_total,
            "?" if source.critical_lost is None else source.critical_lost, source.bytes, source.sha256[:12])
    st = source
    drops = ", ".join("%s=%d" % (k, v) for k, v in st.get("dropped", {}).items() if v) or "none"
    ok = st.get("closed") and st.get("footer_written") and st.get("header_written") and not st.get("critical_lost") \
        and not st.get("writer_hung") and not st.get("writer_crashed")
    return "diag run=%s: evidence %s; emitted=%d written=%d dropped=%d (%s) critical_lost=%d sink=%s" % (
        st.get("run"), "COMPLETE" if ok else "INCOMPLETE", st.get("emitted", 0), st.get("written", 0),
        st.get("dropped_total", 0), drops, st.get("critical_lost", 0), st.get("sink_state"))


__all__ = [
    "SCHEMA", "SUMMARY_SCHEMA", "REDACTION_POLICY_ID", "LEVELS", "DROP_REASONS",
    "SinkLimits", "RedactionPolicy", "classify_key", "redact_text", "redact_value", "pseudonymize",
    "exception_chain", "FileSink", "FaultableSink", "EvidenceVerdict", "EvidenceIncomplete",
    "downgrade_pass_if_incomplete", "BoundEmitter", "DiagnosticSink", "LogAudit", "audit_log",
    "audit_bytes", "format_summary",
]


def _main(argv: Sequence[str]) -> int:
    """``diagnostics.py audit LOG`` - print the audit as JSON + a summary line.

    Exit 0 complete, 1 incomplete, 2 usage error.
    """
    if len(argv) != 2 or argv[0] != "audit":
        sys.stderr.write("usage: diagnostics.py audit LOG\n")
        return 2
    audit = audit_log(argv[1])
    sys.stdout.write(json.dumps(audit.as_dict(), sort_keys=True) + "\n")
    sys.stderr.write(format_summary(audit) + "\n")
    return 0 if audit.complete else 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
