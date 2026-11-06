"""U02 independent reference (bead ffw-76j): the signed staged update contract in Python, written from docs/contracts/u02.md.

Standard library only. It is the second implementation of the contract: `crates/franken-update` is the first, and the two agree on
`crates/franken-update/tests/vectors/u02_vectors.json`, which this module's `make_vectors.py` writes. Nothing here opens a device,
a network or a file other than the ones named on its command line.

What it models, in the order a candidate meets it:

1. `parse` - the fixed binary manifest (section 2), bounded, strict, no allocation before a length is checked.
2. `admit` - the signature and then the policy, in one fixed order; the first failing rule names the refusal (section 3).
3. `Artifact` - the staged bytes against the manifest's size and SHA-256 (section 4).
4. `Engine` - the persisted update state machine over an atomic store with a crash model (section 5).
5. `group_decision` / `rollback_decision` - rolling-update compatibility (section 6).

`BUGS` are planted defects, one per check, that the tests switch on to show the vectors and the properties catch them.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

import ed25519_ref as ed

MAGIC = b"FFWM"
FORMAT = 1
DOMAIN = b"ffw-u02-manifest-v1\x00"
MAX_MANIFEST = 512
MIN_MANIFEST = 4 + 1 + 1 + 2 + 8
MAX_PROFILE_ID = 48
MAX_HW_REV = 24
MAX_KERNEL_PROFILE = 40
MAX_LIBC = 16
MAX_KEYS = 4

STAGE_USERSPACE, STAGE_KERNEL, STAGE_BOOTLOADER, STAGE_VENDOR = 1, 2, 3, 4
FLAG_VENDOR_CLAIM, FLAG_BYPASS_CLAIM, FLAG_AB_CLAIM = 1, 2, 4
ISA_PPC32_BE, ISA_MIPS32R2_BE = 1, 2
FEATURES = ("airplay2", "alexa_bridge", "protected_render", "spotify_connect", "synchronized_groups", "tailnet_native")
FEATURES_ALL = (1 << len(FEATURES)) - 1
AUTH_PASSWORD, AUTH_PUBKEY_ONLY, AUTH_INCLUDE_MATCH = 1, 2, 4
FIX_NONE, FIX_UPSTREAM, FIX_REVIEWED = 0, 1, 2
OPENSSH_FIXED = (10, 6, 2)
ZERO32 = bytes(32)

TRIAL_BOOTS = 3
CHECKPOINT = 64        # bytes of staged artifact between persisted progress records (the model's chunk granularity is 16)

BUGS: Tuple[str, ...] = (
    "skip_signature", "no_domain", "unknown_key_accepted", "revoked_key_accepted", "weak_key_accepted", "s_not_reduced",
    "stage_not_checked", "vendor_claim_accepted", "bypass_claim_accepted", "ab_claim_accepted",
    "board_not_checked", "revision_not_checked", "isa_not_checked", "kernel_not_checked", "synthetic_in_production",
    "evidence_not_checked", "feature_not_required", "floor_not_enforced", "downgrade_by_default", "version_reuse_allowed",
    "calibration_not_checked", "settings_not_checked", "backup_ignored", "capacity_not_checked", "ab_without_receipt",
    "synthetic_receipt_for_real", "ssh_fix_ignored", "ssh_password_allowed", "ssh_unqualified_allowed", "ssh_auth_not_checked",
    "size_not_checked", "digest_not_checked", "truncated_accepted",
    "floor_raised_at_stage", "floor_raised_on_rollback", "confirm_forgets_floor", "failed_candidate_retried",
    "restart_forgets_stage", "stale_manifest_copy_trusted", "trial_never_expires", "commit_not_atomic",
    "group_upgrades_others", "disconnected_ignored", "wire_window_ignored", "wire_upper_bound_ignored", "unknown_peer_skipped",
    "restart_skips_admission",
)


class Refusal(Exception):
    """A stable refusal name. Never carries a key, a payload or a path."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def key_id_of(public: bytes) -> bytes:
    return sha256(public)[:8]


def u8(n: int) -> bytes:
    return n.to_bytes(1, "big")


def u16(n: int) -> bytes:
    return n.to_bytes(2, "big")


def u32(n: int) -> bytes:
    return n.to_bytes(4, "big")


# ----------------------------------------------------------------------------------------------------------- 2. manifest


def _label_ok(raw: bytes, upper: bool) -> bool:
    if not raw or not (raw[0:1].isalnum() and raw[0] < 128):
        return False
    for b in raw:
        c = chr(b)
        if not (c.isascii() and (c.isdigit() or (c.isalpha() and (upper or c.islower())) or c in "._-")):
            return False
    return True


def encode_body(m: Dict[str, Any]) -> bytes:
    """The signed bytes of a manifest, from a dict of fields. The builder trusts its input; `parse` is the strict side."""
    out = bytearray(MAGIC)
    out += u8(FORMAT) + u8(m.get("stage", STAGE_USERSPACE)) + u16(m.get("flags", 0)) + m["key_id"]
    for name in ("profile_id", "hw_rev", "kernel_profile"):
        raw = m[name].encode("ascii")
        out += u8(len(raw)) + raw
    out += u8(m["isa"]) + u32(m["version"]) + u32(m["security_version"])
    out += u16(m["settings_schema"]) + u16(m["settings_read_min"]) + u16(m["calibration_schema"])
    out += u16(m["wire_schema"]) + u16(m["wire_read_min"]) + u16(m["wire_read_max"]) + u16(m["features"])
    out += u32(m["artifact_size"]) + m["artifact_sha256"] + m.get("evidence_digest", ZERO32)
    ssh = m.get("ssh")
    if ssh is None:
        out += u8(0)
    else:
        libc = ssh["libc"].encode("ascii")
        out += u8(1) + ssh["source_digest"] + ssh["build_digest"] + u8(len(libc)) + libc
        out += u8(ssh["major"]) + u8(ssh["minor"]) + u8(ssh["portable"]) + u8(ssh["fix"]) + ssh.get("fix_evidence", ZERO32)
        out += u8(ssh["auth"]) + ssh.get("qualification", ZERO32)
    return bytes(out)


def sign_manifest(seed: bytes, body: bytes, bugs: FrozenSet[str] = frozenset()) -> bytes:
    domain = b"" if "no_domain" in bugs else DOMAIN
    return body + ed.sign(seed, domain + body)


class Reader:
    def __init__(self, raw: bytes) -> None:
        self.raw, self.at = raw, 0

    def take(self, n: int) -> bytes:
        if self.at + n > len(self.raw):
            raise Refusal("manifest_too_short")
        out = self.raw[self.at : self.at + n]
        self.at += n
        return out

    def num(self, n: int) -> int:
        return int.from_bytes(self.take(n), "big")


def parse(raw: bytes) -> Dict[str, Any]:
    """Structure only: lengths, magic, reserved bits, string grammar. No signature, no policy. Returns the fields plus `body` and `sig`."""
    if len(raw) > MAX_MANIFEST:
        raise Refusal("manifest_too_long")
    if len(raw) < MIN_MANIFEST + 64:
        raise Refusal("manifest_too_short")
    r = Reader(raw)
    if r.take(4) != MAGIC:
        raise Refusal("bad_magic")
    if r.num(1) != FORMAT:
        raise Refusal("unsupported_format")
    m: Dict[str, Any] = {"stage": r.num(1), "flags": r.num(2), "key_id": r.take(8)}
    if m["flags"] & ~(FLAG_VENDOR_CLAIM | FLAG_BYPASS_CLAIM | FLAG_AB_CLAIM):
        raise Refusal("bad_field")
    if m["stage"] not in (STAGE_USERSPACE, STAGE_KERNEL, STAGE_BOOTLOADER, STAGE_VENDOR):
        raise Refusal("bad_field")
    for name, hi, upper in (("profile_id", MAX_PROFILE_ID, False), ("hw_rev", MAX_HW_REV, True), ("kernel_profile", MAX_KERNEL_PROFILE, False)):
        n = r.num(1)
        if not 1 <= n <= hi:
            raise Refusal("bad_field")
        raw_s = r.take(n)
        if not _label_ok(raw_s, upper):
            raise Refusal("bad_field")
        m[name] = raw_s.decode("ascii")
    m["isa"] = r.num(1)
    if m["isa"] not in (ISA_PPC32_BE, ISA_MIPS32R2_BE):
        raise Refusal("bad_field")
    m["version"], m["security_version"] = r.num(4), r.num(4)
    for name in ("settings_schema", "settings_read_min", "calibration_schema", "wire_schema", "wire_read_min", "wire_read_max", "features"):
        m[name] = r.num(2)
    if m["features"] & ~FEATURES_ALL:
        raise Refusal("bad_field")
    if m["settings_read_min"] > m["settings_schema"] or m["wire_read_min"] > m["wire_schema"] or m["wire_schema"] > m["wire_read_max"] \
            or m["settings_schema"] == 0 \
            or m["calibration_schema"] == 0 or m["wire_schema"] == 0 or m["settings_read_min"] == 0 or m["wire_read_min"] == 0:
        raise Refusal("bad_field")
    m["artifact_size"] = r.num(4)
    if m["artifact_size"] == 0:
        raise Refusal("bad_field")
    m["artifact_sha256"], m["evidence_digest"] = r.take(32), r.take(32)
    present = r.num(1)
    if present not in (0, 1):
        raise Refusal("bad_field")
    m["ssh"] = None
    if present:
        ssh: Dict[str, Any] = {"source_digest": r.take(32), "build_digest": r.take(32)}
        n = r.num(1)
        if not 1 <= n <= MAX_LIBC:
            raise Refusal("bad_field")
        libc = r.take(n)
        if not _label_ok(libc, False):
            raise Refusal("bad_field")
        ssh["libc"] = libc.decode("ascii")
        ssh["major"], ssh["minor"], ssh["portable"], ssh["fix"] = r.num(1), r.num(1), r.num(1), r.num(1)
        ssh["fix_evidence"] = r.take(32)
        ssh["auth"] = r.num(1)
        ssh["qualification"] = r.take(32)
        if ssh["fix"] not in (FIX_NONE, FIX_UPSTREAM, FIX_REVIEWED) or ssh["auth"] & ~7:
            raise Refusal("bad_field")
        if (ssh["fix"] == FIX_REVIEWED) != (ssh["fix_evidence"] != ZERO32):
            raise Refusal("bad_field")
        m["ssh"] = ssh
    body_end = r.at
    m["sig"] = r.take(64)
    if r.at != len(raw):
        raise Refusal("trailing_bytes")
    m["body"] = raw[:body_end]
    m["sha256"] = sha256(raw)
    return m


# --------------------------------------------------------------------------------------------------------- 3. admission


class TrustStore:
    """Up to MAX_KEYS public keys. A key id is DERIVED from the key; a key that is not a canonical prime-order point is refused."""

    def __init__(self, keys: List[Tuple[bytes, bool]], bugs: FrozenSet[str] = frozenset()) -> None:
        if len(keys) > MAX_KEYS:
            raise Refusal("trust_store_full")
        self.keys: Dict[bytes, Tuple[bytes, bool]] = {}
        for public, revoked in keys:
            if len(public) != 32 or (not ed.key_ok(public) and "weak_key_accepted" not in bugs):
                raise Refusal("bad_trust_key")
            kid = key_id_of(public)
            if kid in self.keys:
                raise Refusal("duplicate_trust_key")
            self.keys[kid] = (public, revoked)


class Board:
    def __init__(self, profile_id: str, hw_rev: str, isa: int, kernel_profile: str, synthetic: bool, attested: bool) -> None:
        self.profile_id, self.hw_rev, self.isa, self.kernel_profile = profile_id, hw_rev, isa, kernel_profile
        self.synthetic, self.attested = synthetic, attested


class Installed:
    def __init__(self, version: int, security_version: int, settings_schema: int, settings_read_min: int, calibration_schema: int,
                 wire_schema: int, wire_read_min: int, wire_read_max: int, features: int, sha: bytes) -> None:
        self.version, self.security_version = version, security_version
        self.settings_schema, self.settings_read_min, self.calibration_schema = settings_schema, settings_read_min, calibration_schema
        self.wire_schema, self.wire_read_min, self.wire_read_max, self.features, self.sha = wire_schema, wire_read_min, wire_read_max, features, sha

    def pack(self) -> bytes:
        return (u8(1) + u32(self.version) + u32(self.security_version) + u16(self.settings_schema) + u16(self.settings_read_min)
                + u16(self.calibration_schema) + u16(self.wire_schema) + u16(self.wire_read_min) + u16(self.wire_read_max) + u16(self.features) + self.sha)

    @staticmethod
    def of(m: Dict[str, Any]) -> "Installed":
        return Installed(m["version"], m["security_version"], m["settings_schema"], m["settings_read_min"], m["calibration_schema"],
                         m["wire_schema"], m["wire_read_min"], m["wire_read_max"], m["features"], m["sha256"])


class Context:
    """What the device knows locally; none of it comes from the candidate."""

    def __init__(self, trust: TrustStore, board: Board, production: bool, installed: Optional[Installed], floor: int,
                 evidence: Optional[bytes] = None, required: int = FEATURES_ALL, allow_downgrade: bool = False,
                 settings_backup: Optional[int] = None, staging_bytes: int = 1 << 20, reserve: int = 4096, recovery_path: bool = True,
                 ab_receipt: Optional[Tuple[int, bytes, bool]] = None, failed: Optional[bytes] = None) -> None:
        self.trust, self.board, self.production, self.installed, self.floor = trust, board, production, installed, floor
        self.evidence, self.required, self.allow_downgrade, self.settings_backup = evidence, required, allow_downgrade, settings_backup
        self.staging_bytes, self.reserve, self.recovery_path, self.ab_receipt, self.failed = staging_bytes, reserve, recovery_path, ab_receipt, failed


def verify_signature(ctx: Context, m: Dict[str, Any], bugs: FrozenSet[str]) -> None:
    entry = ctx.trust.keys.get(m["key_id"])
    if entry is None:
        if "unknown_key_accepted" in bugs:
            return
        raise Refusal("unknown_signing_key")
    public, revoked = entry
    if revoked and "revoked_key_accepted" not in bugs:
        raise Refusal("revoked_signing_key")
    if "skip_signature" in bugs:
        return
    domain = b"" if "no_domain" in bugs else DOMAIN
    sig = m["sig"]
    if "s_not_reduced" in bugs:
        # the plant: S is taken modulo L, so a signature with S + L verifies too (malleable)
        s = int.from_bytes(sig[32:], "little") % ed.L
        sig = sig[:32] + s.to_bytes(32, "little")
    if not ed.verify(public, domain + m["body"], sig):
        raise Refusal("bad_signature")


def ssh_check(ctx: Context, ssh: Optional[Dict[str, Any]], bugs: FrozenSet[str]) -> None:
    """An image that adds or retains SSH binds its daemon, its libc, the OpenSSH fix and its authentication; the declaration is a release
    statement, not a scan: nothing here proves what is inside the artifact."""
    if ssh is None:
        return
    version = (ssh["major"], ssh["minor"], ssh["portable"])
    fixed = (ssh["fix"] == FIX_UPSTREAM and version >= OPENSSH_FIXED) or ssh["fix"] == FIX_REVIEWED
    if not fixed and "ssh_fix_ignored" not in bugs:
        raise Refusal("ssh_fix_missing")
    if ssh["source_digest"] == ZERO32 or ssh["build_digest"] == ZERO32:
        raise Refusal("ssh_unbound")
    if ssh["auth"] & AUTH_PASSWORD:
        if ctx.production and "ssh_password_allowed" not in bugs:
            raise Refusal("ssh_password_forbidden")
    elif not (ssh["auth"] & AUTH_PUBKEY_ONLY and ssh["auth"] & AUTH_INCLUDE_MATCH) and "ssh_auth_not_checked" not in bugs:
        raise Refusal("ssh_auth_unresolved")
    if ctx.production and ssh["qualification"] == ZERO32 and "ssh_unqualified_allowed" not in bugs:
        raise Refusal("ssh_unqualified")


def plan_for(ctx: Context, m: Dict[str, Any], bugs: FrozenSet[str]) -> Dict[str, Any]:
    need = m["artifact_size"] + ctx.reserve
    mode, ab = None, "not_proven"
    receipt = ctx.ab_receipt
    if receipt is not None:
        slot, digest, synthetic = receipt
        if synthetic and not ctx.board.synthetic and "synthetic_receipt_for_real" not in bugs:
            raise Refusal("synthetic_receipt_for_real_profile")
        if slot >= need:
            mode, ab = "ab_slots", "proven_by_external_receipt"
    if "ab_without_receipt" in bugs and mode is None:
        mode, ab = "ab_slots", "proven_by_external_receipt"
    if mode is None:
        if not ctx.recovery_path:
            raise Refusal("no_recovery_path")
        mode = "single_slot_recovery"
    return {"mode": mode, "ab": ab, "vendor_acceptance": "not_claimed"}


def admit(ctx: Context, raw: bytes, bugs: FrozenSet[str] = frozenset()) -> Dict[str, Any]:
    m = parse(raw)
    verify_signature(ctx, m, bugs)
    if m["stage"] != STAGE_USERSPACE and "stage_not_checked" not in bugs:
        raise Refusal("stage_forbidden")
    if m["flags"] & FLAG_VENDOR_CLAIM and "vendor_claim_accepted" not in bugs:
        raise Refusal("vendor_claim_forbidden")
    if m["flags"] & FLAG_BYPASS_CLAIM and "bypass_claim_accepted" not in bugs:
        raise Refusal("bypass_claim_forbidden")
    if m["flags"] & FLAG_AB_CLAIM and "ab_claim_accepted" not in bugs:
        raise Refusal("ab_claim_forbidden")
    board = ctx.board
    if m["profile_id"] != board.profile_id and "board_not_checked" not in bugs:
        raise Refusal("wrong_board")
    if m["hw_rev"] != board.hw_rev and "revision_not_checked" not in bugs:
        raise Refusal("hardware_revision_mismatch")
    if m["isa"] != board.isa and "isa_not_checked" not in bugs:
        raise Refusal("isa_mismatch")
    if m["kernel_profile"] != board.kernel_profile and "kernel_not_checked" not in bugs:
        raise Refusal("kernel_profile_mismatch")
    if ctx.production:
        if (board.synthetic or not board.attested) and "synthetic_in_production" not in bugs:
            raise Refusal("profile_not_attested")
        if "evidence_not_checked" not in bugs and (ctx.evidence is None or m["evidence_digest"] != ctx.evidence):
            raise Refusal("evidence_mismatch")
    if m["features"] & ctx.required != ctx.required and "feature_not_required" not in bugs:
        raise Refusal("required_feature_missing")
    inst = ctx.installed
    if m["security_version"] < ctx.floor and "floor_not_enforced" not in bugs:
        raise Refusal("below_security_floor")
    if ctx.failed is not None and m["sha256"] == ctx.failed and "failed_candidate_retried" not in bugs:
        raise Refusal("candidate_previously_failed")
    downgrade = False
    if inst is not None:
        if m["sha256"] == inst.sha:
            raise Refusal("already_installed")
        if m["version"] == inst.version and "version_reuse_allowed" not in bugs:
            raise Refusal("version_reused")
        if m["version"] < inst.version:
            downgrade = True
            if not ctx.allow_downgrade and "downgrade_by_default" not in bugs:
                raise Refusal("downgrade_not_permitted")
        if m["calibration_schema"] != inst.calibration_schema and "calibration_not_checked" not in bugs:
            raise Refusal("calibration_schema_mismatch")
        if "settings_not_checked" not in bugs and not settings_readable(m, inst.settings_schema, ctx.settings_backup, bugs):
            raise Refusal("settings_incompatible")
    ssh_check(ctx, m["ssh"], bugs)
    if "capacity_not_checked" not in bugs and m["artifact_size"] + ctx.reserve > ctx.staging_bytes:
        raise Refusal("insufficient_capacity")
    return {"manifest": m, "plan": plan_for(ctx, m, bugs), "downgrade": downgrade}


def settings_readable(m: Dict[str, Any], stored: int, backup: Optional[int], bugs: FrozenSet[str]) -> bool:
    """Can the candidate read the settings as they are stored (schema `stored`), or restore from a preserved backup of an older schema?"""
    if m["settings_read_min"] <= stored <= m["settings_schema"]:
        return True
    if "backup_ignored" in bugs:
        return False
    return backup is not None and m["settings_read_min"] <= backup <= m["settings_schema"]


# --------------------------------------------------------------------------------------------------------- 4. the artifact


def check_artifact(m: Dict[str, Any], data: bytes, bugs: FrozenSet[str] = frozenset()) -> None:
    """The bytes the staging area holds against the manifest. Truncated and oversized are different refusals from a wrong digest."""
    if len(data) < m["artifact_size"] and "truncated_accepted" not in bugs and "size_not_checked" not in bugs:
        raise Refusal("artifact_truncated")
    if len(data) > m["artifact_size"] and "size_not_checked" not in bugs:
        raise Refusal("artifact_oversized")
    if sha256(data[: m["artifact_size"]] if "size_not_checked" in bugs else data) != m["artifact_sha256"] and "digest_not_checked" not in bugs:
        raise Refusal("artifact_digest_mismatch")


# ------------------------------------------------------------------------------------------------------ 5. the engine

PH_IDLE, PH_STAGING, PH_STAGED, PH_TRIAL = "idle", "staging", "staged", "trial"


class Crash(Exception):
    """The injected power cut of the model (not a refusal): nothing after it happens in this process."""


class Store:
    """The persistence model: records and one mark, committed atomically (U01's `Journal::commit` of several operations is one frame).
    `fail_after` lets that many more commits happen and makes the next one raise `Crash` BEFORE it changes anything; a crash after a
    commit is the next commit raising. Those are the only two outcomes U01's recovery can return, which `tests/u01` proves for the journal."""

    def __init__(self) -> None:
        self.records: Dict[str, bytes] = {}
        self.floor = 0
        self.commits = 0
        self.fail_after: Optional[int] = None

    def commit(self, puts: Dict[str, bytes], deletes: List[str], raise_floor: Optional[int]) -> None:
        if self.fail_after is not None:
            if self.fail_after == 0:
                raise Crash()
            self.fail_after -= 1
        if raise_floor is not None and raise_floor < self.floor:
            raise Refusal("mark_regressed")
        for k, v in puts.items():
            self.records[k] = v
        for k in deletes:
            self.records.pop(k, None)
        if raise_floor is not None:
            self.floor = max(self.floor, raise_floor)
        self.commits += 1


class Staging:
    """The staging medium: a manifest slot and a byte area with a synced prefix. A power cut keeps the synced bytes and a prefix of the
    rest, and the last kept unsynced byte may be torn."""

    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.manifest: Optional[bytes] = None
        self.data = bytearray()
        self.synced = 0

    def write(self, offset: int, chunk: bytes) -> None:
        if offset > len(self.data):
            raise Refusal("staging_gap")
        end = offset + len(chunk)
        if end > self.capacity:
            raise Refusal("insufficient_capacity")
        self.data[offset:end] = chunk

    def sync(self) -> None:
        self.synced = len(self.data)

    def truncate(self, n: int) -> None:
        del self.data[n:]
        self.synced = min(self.synced, n)

    def power_cut(self, keep: int) -> None:
        end = self.synced + max(0, min(keep, len(self.data) - self.synced))
        del self.data[end:]
        if end > self.synced:
            self.data[end - 1] ^= 0x5A
        self.synced = min(self.synced, len(self.data))


def pack_upd(phase: str, sha: bytes, staged: int, boots: int) -> bytes:
    code = {PH_STAGING: 1, PH_STAGED: 2, PH_TRIAL: 3}[phase]
    return u8(1) + u8(code) + sha + u32(staged) + u8(boots)


def unpack_upd(raw: bytes) -> Tuple[str, bytes, int, int]:
    phase = {1: PH_STAGING, 2: PH_STAGED, 3: PH_TRIAL}[raw[1]]
    return phase, raw[2:34], int.from_bytes(raw[34:38], "big"), raw[38]


def unpack_inst(raw: bytes) -> Installed:
    n = lambda a, b: int.from_bytes(raw[a:b], "big")  # noqa: E731
    return Installed(n(1, 5), n(5, 9), n(9, 11), n(11, 13), n(13, 15), n(15, 17), n(17, 19), n(19, 21), n(21, 23), raw[23:55])


class Engine:
    """The update state machine. All durable state is in `store` (the journal) and `staging`; the rest is rebuilt by `restart`."""

    def __init__(self, store: Store, staging: Staging, bugs: FrozenSet[str] = frozenset()) -> None:
        self.store, self.staging, self.bugs = store, staging, bugs
        self.cache: Optional[Dict[str, Any]] = None       # the candidate's parsed manifest
        self.live = 0                                      # bytes of the artifact written so far in this process

    # -- what is persisted
    def installed(self) -> Optional[Installed]:
        raw = self.store.records.get("u02.inst")
        return unpack_inst(raw) if raw else None

    def update(self) -> Optional[Tuple[str, bytes, int, int]]:
        raw = self.store.records.get("u02.upd")
        return unpack_upd(raw) if raw else None

    def phase(self) -> str:
        u = self.update()
        return u[0] if u else PH_IDLE

    def failed(self) -> Optional[bytes]:
        raw = self.store.records.get("u02.fail")
        return raw[1:33] if raw else None

    def ctx(self, base: Context) -> Context:
        return Context(base.trust, base.board, base.production, self.installed(), self.store.floor, base.evidence, base.required,
                       base.allow_downgrade, base.settings_backup, base.staging_bytes, base.reserve, base.recovery_path, base.ab_receipt,
                       self.failed())

    def next_offset(self) -> int:
        return self.live if self.phase() == PH_STAGING else 0

    def snapshot(self) -> Dict[str, Any]:
        inst = self.installed()
        return {"phase": self.phase(), "installed": inst.version if inst else None, "floor": self.store.floor, "next": self.next_offset()}

    # -- transitions
    def begin_stage(self, base: Context, raw: bytes) -> Dict[str, Any]:
        if self.update() is not None:
            raise Refusal("update_in_progress")
        admitted = admit(self.ctx(base), raw, self.bugs)
        m = admitted["manifest"]
        self.staging.manifest, self.staging.data, self.staging.synced = raw, bytearray(), 0
        floor = m["security_version"] if "floor_raised_at_stage" in self.bugs else None
        self.store.commit({"u02.upd": pack_upd(PH_STAGING, m["sha256"], 0, 0)}, [], floor)
        self.cache, self.live = m, 0
        return admitted

    def write_chunk(self, chunk: bytes) -> None:
        u = self.update()
        if u is None or u[0] != PH_STAGING or self.cache is None:
            raise Refusal("not_staging")
        _, sha, checkpoint, _ = u
        if self.live + len(chunk) > self.cache["artifact_size"] and "size_not_checked" not in self.bugs:
            raise Refusal("artifact_oversized")
        self.staging.write(self.live, chunk)
        self.live += len(chunk)
        if self.live - checkpoint >= CHECKPOINT:
            self.staging.sync()
            self.store.commit({"u02.upd": pack_upd(PH_STAGING, sha, self.live, 0)}, [], None)

    def _verify_staged(self, u: Tuple[str, bytes, int, int]) -> None:
        m = self.cache
        assert m is not None
        data = bytes(self.staging.data)
        try:
            check_artifact(m, data, self.bugs)
        except Refusal as e:
            if e.code != "artifact_truncated":
                self.store.commit({"u02.fail": u8(1) + u[1]}, ["u02.upd"], None)
                self.cache, self.live = None, 0
            raise

    def finish_stage(self) -> None:
        u = self.update()
        if u is None or u[0] != PH_STAGING or self.cache is None:
            raise Refusal("not_staging")
        self.staging.sync()
        self._verify_staged(u)
        self.store.commit({"u02.upd": pack_upd(PH_STAGED, u[1], self.cache["artifact_size"], 0)}, [], None)

    def activate(self) -> None:
        u = self.update()
        if u is None or u[0] != PH_STAGED or self.cache is None:
            raise Refusal("not_staged")
        self._verify_staged(u)                               # the bytes ON THE MEDIUM now, not the verdict remembered from before
        self.store.commit({"u02.upd": pack_upd(PH_TRIAL, u[1], u[2], TRIAL_BOOTS)}, [], None)

    def abort(self) -> None:
        u = self.update()
        if u is None:
            raise Refusal("nothing_to_abort")
        if u[0] == PH_TRIAL:
            raise Refusal("trial_in_progress")
        self.store.commit({}, ["u02.upd"], None)
        self.cache, self.live = None, 0

    def report_boot(self, healthy: bool) -> str:
        u = self.update()
        if u is None or u[0] != PH_TRIAL or self.cache is None:
            raise Refusal("not_in_trial")
        _, sha, size, boots = u
        m = self.cache
        if healthy:
            floor = None if "confirm_forgets_floor" in self.bugs else m["security_version"]
            if "commit_not_atomic" in self.bugs:
                self.store.commit({}, [], floor)                                                      # the floor first ...
                self.store.commit({"u02.inst": Installed.of(m).pack()}, ["u02.upd"], None)            # ... then the image
            else:
                self.store.commit({"u02.inst": Installed.of(m).pack()}, ["u02.upd"], floor)
            self.cache, self.live = None, 0
            return "committed"
        boots -= 1
        if "trial_never_expires" in self.bugs:
            boots = max(boots, 1)
        if boots > 0:
            self.store.commit({"u02.upd": pack_upd(PH_TRIAL, sha, size, boots)}, [], None)
            return "retry"
        floor = m["security_version"] if "floor_raised_on_rollback" in self.bugs else None
        self.store.commit({"u02.fail": u8(1) + sha}, ["u02.upd"], floor)
        self.cache, self.live = None, 0
        return "rolled_back"

    # -- a restart: the process is gone; only the store and the staging medium remain
    def restart(self, base: Context) -> "Engine":
        e = Engine(self.store, self.staging, self.bugs)
        u = e.update()
        if u is None:
            return e
        if "restart_forgets_stage" in self.bugs:
            e.store.commit({}, ["u02.upd"], None)
            return e
        # The manifest copy on the staging medium is untrusted: it must hash to what the journal recorded, and it must be ADMITTED AGAIN under the CURRENT
        # policy and the current persisted state (signature, board, production evidence, features, floor, compatibility, capacity). An update in progress is
        # not refused for being in progress: admission never consults the update record.
        copy = self.staging.manifest
        try:
            if copy is None or (sha256(copy) != u[1] and "stale_manifest_copy_trusted" not in self.bugs):
                raise Refusal("staging_manifest_mismatch")
            if "restart_skips_admission" in self.bugs:
                m = parse(copy)
                verify_signature(e.ctx(base), m, self.bugs)
            else:
                m = admit(e.ctx(base), copy, self.bugs)["manifest"]
        except Refusal:
            e.store.commit({}, ["u02.upd"], None)           # nothing to resume: back to Idle with the installed image untouched
            return e
        e.cache = m
        if u[0] == PH_STAGING:
            e.staging.truncate(u[2])                          # what is beyond the persisted checkpoint was never promised
            e.live = u[2]
        else:
            e.live = m["artifact_size"]
        return e


# --------------------------------------------------------------------------------------------------- 6. rolling updates


class Member:
    def __init__(self, ident: str, image: Optional[Installed], connected: bool = True) -> None:
        self.ident, self.image, self.connected = ident, image, connected


def wire_compatible(a: Installed, b: Installed) -> bool:
    """Each image emits exactly its `wire_schema` and reads `wire_read_min..=wire_read_max`. Two images can talk only if EACH can read what the OTHER emits;
    there is no negotiation and no fallback to an older version."""
    return a.wire_read_min <= b.wire_schema <= a.wire_read_max and b.wire_read_min <= a.wire_schema <= b.wire_read_max


def group_decision(members: List[Member], idx: int, cand: Installed, bugs: FrozenSet[str] = frozenset()) -> Dict[str, Any]:
    """May member `idx` take `cand` while the others stay as they are? The answer never includes an action on another member. A member whose image is
    unknown, connected or not, cannot be assessed and blocks the admission."""
    assumed: List[str] = []
    conflicts: List[str] = []
    unknown = sorted(m.ident for j, m in enumerate(members) if j != idx and m.image is None)
    if unknown and "unknown_peer_skipped" not in bugs:
        return {"decision": "refuse", "code": "unknown_member_state", "conflicts": unknown, "assumed": []}
    for j, other in enumerate(members):
        if j == idx:
            continue
        if not other.connected:
            if "disconnected_ignored" in bugs:
                continue
            assumed.append(other.ident)
        if other.image is None:
            continue
        if "wire_window_ignored" in bugs:
            continue
        compatible = wire_compatible(cand, other.image)
        if "wire_upper_bound_ignored" in bugs:
            compatible = cand.wire_read_min <= other.image.wire_schema and other.image.wire_read_min <= cand.wire_schema
        if not compatible:
            conflicts.append(other.ident)
    if conflicts:
        out: Dict[str, Any] = {"decision": "refuse", "code": "wire_incompatible", "conflicts": sorted(conflicts), "assumed": sorted(assumed)}
        if "group_upgrades_others" in bugs:
            out["upgrade_others"] = sorted(conflicts)
        return out
    return {"decision": "admit", "code": "ok", "conflicts": [], "assumed": sorted(assumed)}


def rollback_decision(current_settings_schema: int, backup: Optional[int], target: Installed, bugs: FrozenSet[str] = frozenset()) -> str:
    """After a settings migration, may the member go back to `target`? Only if the target reads what is stored, or a preserved copy."""
    fake = {"settings_read_min": target.settings_read_min, "settings_schema": target.settings_schema}
    return "allow" if settings_readable(fake, current_settings_schema, backup, bugs) else "refuse:settings_incompatible"
