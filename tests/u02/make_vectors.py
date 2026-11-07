#!/usr/bin/env python3
"""Write (or check) the shared U02 vectors: crates/franken-update/tests/vectors/u02_vectors.json.

    make_vectors.py            rewrite the file
    make_vectors.py --check    exit 1 if the committed file differs from what this script writes

The vectors are replayed by crates/franken-update/tests/u02_vectors.rs (central verification) and by tests/u02/e2e.py (host). EVERY
expected value below is written by hand from docs/contracts/u02.md, as a literal next to the case; the generator then asks the reference
model and stops with an error if the model disagrees, so a hand error and a model error cannot hide each other. Signatures come from the
reference signer, which is byte-equal to OpenSSL's Ed25519 on deterministic input (tests/u02/test_u02.py checks that when the `cryptography`
module is present); the keys are the public test keys of RFC 8032 section 7.1. Nothing here is a real key, image or device.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import ed25519_ref as ed  # noqa: E402
import reference as ref  # noqa: E402

OUT = os.path.join(REPO, "crates", "franken-update", "tests", "vectors", "u02_vectors.json")
SCHEMA = "ffw.u02.vectors.v1"

# RFC 8032 section 7.1 test keys 1, 2 and 3 (public test material).
SEEDS = {
    "A": bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
    "B": bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
    "X": bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
}
PUBS = {k: ed.public_from_seed(v) for k, v in SEEDS.items()}

BOARDS = {
    # the catalog's synthetic S5 and S1 fixtures (franken-board-profile, synthetic_test_fixture_catalog): never attested
    "ppc": dict(profile_id="sonos-s5-ppc-rev-1.16.3.1-2", hw_rev="1.16.3.1-2", isa=ref.ISA_PPC32_BE, kernel_profile="linux-2.6.14-ppc32-be",
                synthetic=True, attested=False),
    "mips": dict(profile_id="sonos-s1-mips-rev-1.8.3.7-1", hw_rev="1.8.3.7-1", isa=ref.ISA_MIPS32R2_BE, kernel_profile="linux-2.6.35-mips32r2-be",
                 synthetic=True, attested=False),
    # a stand-in that only exists to exercise the production policy: same identity as "ppc", but marked as not synthetic and attested.
    # It is NOT a board profile of any real unit and nothing outside the policy tests uses it.
    "ppc_policy_standin": dict(profile_id="sonos-s5-ppc-rev-1.16.3.1-2", hw_rev="1.16.3.1-2", isa=ref.ISA_PPC32_BE,
                               kernel_profile="linux-2.6.14-ppc32-be", synthetic=False, attested=True),
}


def pattern(n: int, salt: int = 0) -> bytes:
    return bytes((i * 7 + 3 + salt) & 0xFF for i in range(n))


ART = pattern(160)
ART_SHA = hashlib.sha256(ART).digest()
EVIDENCE = hashlib.sha256(b"synthetic e01 evidence digest for the policy tests").digest()
SSH_GOOD = dict(source_digest=hashlib.sha256(b"ssh daemon source").digest(), build_digest=hashlib.sha256(b"ssh daemon build").digest(),
                libc="musl-1.2.5", major=10, minor=6, portable=2, fix=ref.FIX_UPSTREAM, auth=ref.AUTH_PUBKEY_ONLY | ref.AUTH_INCLUDE_MATCH,
                qualification=hashlib.sha256(b"ssh guest qualification receipt").digest())

BASE = dict(stage=ref.STAGE_USERSPACE, flags=0, profile_id=BOARDS["ppc"]["profile_id"], hw_rev=BOARDS["ppc"]["hw_rev"],
            kernel_profile=BOARDS["ppc"]["kernel_profile"], isa=ref.ISA_PPC32_BE, version=100, security_version=5, settings_schema=3,
            settings_read_min=2, calibration_schema=1, wire_schema=2, wire_read_min=1, wire_read_max=2, features=ref.FEATURES_ALL, artifact_size=len(ART),
            artifact_sha256=ART_SHA, evidence_digest=ref.ZERO32, ssh=None)

INSTALLED = dict(version=90, security_version=4, settings_schema=3, settings_read_min=2, calibration_schema=1, wire_schema=2, wire_read_min=1, wire_read_max=2,
                 features=ref.FEATURES_ALL, sha=hashlib.sha256(b"installed image 90").digest())


def key_id(name: str) -> bytes:
    return ref.key_id_of(PUBS[name])


def manifest(signer: str = "A", **over: Any) -> bytes:
    fields = dict(BASE)
    fields.update(over)
    fields.setdefault("key_id", key_id(over.get("key_name", signer)))
    fields.pop("key_name", None)
    body = ref.encode_body(fields)
    return ref.sign_manifest(SEEDS[signer], body)


def hexs(b: Optional[bytes]) -> Optional[str]:
    return None if b is None else b.hex()


def ctx_default() -> Dict[str, Any]:
    return dict(trust=[{"key": "A", "revoked": False}, {"key": "B", "revoked": False}], board="ppc", production=False,
                installed=dict(INSTALLED, sha=INSTALLED["sha"].hex()), floor=4, evidence=None, required=ref.FEATURES_ALL,
                allow_downgrade=False, settings_backup=None, staging_bytes=1 << 20, reserve=4096, recovery_path=True, ab_receipt=None, failed=None)


def build_ctx(spec: Dict[str, Any], bugs=frozenset()) -> ref.Context:
    trust = ref.TrustStore([(PUBS[t["key"]], t["revoked"]) for t in spec["trust"]], bugs)
    b = BOARDS[spec["board"]]
    board = ref.Board(b["profile_id"], b["hw_rev"], b["isa"], b["kernel_profile"], b["synthetic"], b["attested"])
    inst = None
    if spec["installed"] is not None:
        i = spec["installed"]
        inst = ref.Installed(i["version"], i["security_version"], i["settings_schema"], i["settings_read_min"], i["calibration_schema"],
                             i["wire_schema"], i["wire_read_min"], i["wire_read_max"], i["features"], bytes.fromhex(i["sha"]))
    rc = spec["ab_receipt"]
    receipt = None if rc is None else (rc["slot_bytes"], bytes.fromhex(rc["digest"]), rc["synthetic"])
    return ref.Context(trust, board, spec["production"], inst, spec["floor"], None if spec["evidence"] is None else bytes.fromhex(spec["evidence"]),
                       spec["required"], spec["allow_downgrade"], spec["settings_backup"], spec["staging_bytes"], spec["reserve"],
                       spec["recovery_path"], receipt, None if spec["failed"] is None else bytes.fromhex(spec["failed"]))


def outcome(fn) -> Dict[str, Any]:
    try:
        return {"ok": fn()}
    except ref.Refusal as e:
        return {"refuse": e.code}


def admit_vec(vid: str, title: str, raw: bytes, expect: Dict[str, Any], ctx: Optional[Dict[str, Any]] = None, invariants: Optional[List[str]] = None, **over: Any) -> Dict[str, Any]:
    spec = ctx_default()
    spec.update(over)
    if ctx:
        spec.update(ctx)
    got = outcome(lambda: summarize(ref.admit(build_ctx(spec), raw)))
    assert got == expect, f"{vid}: hand-written {expect} but the model says {got}"
    return {"id": vid, "title": title, "invariants": invariants or [], "ctx": spec, "manifest": raw.hex(), "expect": expect}


def summarize(admitted: Dict[str, Any]) -> Dict[str, Any]:
    p = admitted["plan"]
    return {"mode": p["mode"], "ab": p["ab"], "vendor_acceptance": p["vendor_acceptance"], "downgrade": admitted["downgrade"]}


GOOD = {"mode": "single_slot_recovery", "ab": "not_proven", "vendor_acceptance": "not_claimed", "downgrade": False}


def refuse(code: str) -> Dict[str, Any]:
    return {"refuse": code}


def flip(raw: bytes, index: int, bit: int = 0) -> bytes:
    out = bytearray(raw)
    out[index] ^= 1 << bit
    return bytes(out)


def field_offset(raw: bytes, name: str) -> int:
    """Where a fixed-width field starts in a manifest built from BASE (profile_id, hw_rev and kernel_profile have fixed lengths here)."""
    base = 4 + 1 + 1 + 2 + 8
    base += 1 + len(BASE["profile_id"]) + 1 + len(BASE["hw_rev"]) + 1 + len(BASE["kernel_profile"])
    table = {"isa": 0, "version": 1, "security_version": 5, "settings_schema": 9, "settings_read_min": 11, "calibration_schema": 13,
             "wire_schema": 15, "wire_read_min": 17, "wire_read_max": 19, "features": 21, "artifact_size": 23, "artifact_sha256": 27, "evidence": 59, "ssh": 91}
    return base + table[name]


# ------------------------------------------------------------------------------------------------------- the vector groups


def ed25519_vectors() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    def add(vid: str, title: str, pub: bytes, msg: bytes, sig: bytes, expect: bool) -> None:
        assert ed.verify(pub, msg, sig) == expect, vid
        out.append({"id": vid, "title": title, "public": pub.hex(), "message": msg.hex(), "signature": sig.hex(), "expect": expect})

    rfc1 = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    rfc2 = bytes.fromhex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
    add("U02-ED-001", "RFC 8032 test 1 (empty message)", PUBS["A"], b"", rfc1, True)
    add("U02-ED-002", "RFC 8032 test 2 (one byte)", PUBS["B"], bytes.fromhex("72"), rfc2, True)
    for n, (name, length) in enumerate((("A", 31), ("B", 64), ("X", 200), ("A", 1)), start=3):
        msg = pattern(length, salt=n)
        add(f"U02-ED-{n:03d}", f"a deterministic signature of {length} bytes under key {name}", PUBS[name], msg, ed.sign(SEEDS[name], msg), True)
    msg = pattern(40, salt=9)
    good = ed.sign(SEEDS["A"], msg)
    add("U02-ED-007", "the same message under another key", PUBS["B"], msg, good, False)
    add("U02-ED-008", "one flipped bit in R", PUBS["A"], msg, flip(good, 3), False)
    add("U02-ED-009", "one flipped bit in S", PUBS["A"], msg, flip(good, 40), False)
    add("U02-ED-010", "one flipped bit in the message", PUBS["A"], flip(msg, 5), good, False)
    s = int.from_bytes(good[32:], "little")
    add("U02-ED-011", "S replaced by S + L (malleable): refused although the equation holds", PUBS["A"], msg, good[:32] + (s + ed.L).to_bytes(32, "little"), False)
    add("U02-ED-012", "S equal to L", PUBS["A"], msg, good[:32] + ed.L.to_bytes(32, "little"), False)
    add("U02-ED-013", "a signature one byte short", PUBS["A"], msg, good[:-1], False)
    p1 = (1).to_bytes(32, "little")
    add("U02-ED-014", "public key = the identity point with R = identity and S = 0 (verifies under a naive check)", p1, msg, p1 + bytes(32), False)
    noncanon = (ed.P + 1).to_bytes(32, "little")
    add("U02-ED-015", "R is a non-canonical encoding (y = p + 1)", PUBS["A"], msg, noncanon + good[32:], False)
    return out


def small_order_points() -> List[bytes]:
    """Torsion points, found by multiplying random curve points by L (the prime-order part vanishes). Computed, not typed."""
    found: Dict[bytes, bytes] = {}
    y = 2
    while len(found) < 4 and y < 200:
        pt = ed.decode_point(y.to_bytes(32, "little"))
        y += 1
        if pt is None:
            continue
        t = ed.scalar_mult(ed.L, pt)
        enc = ed.encode_point(t)
        if not ed.is_identity(t):
            found[enc] = enc
    return list(found)


def key_vectors() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    def add(vid: str, title: str, pub: bytes, expect: bool) -> None:
        assert ed.key_ok(pub) == expect, vid
        out.append({"id": vid, "title": title, "public": pub.hex(), "expect": expect})

    for n, name in enumerate("ABX", start=1):
        add(f"U02-KEY-00{n}", f"the RFC 8032 test key {name} is admitted", PUBS[name], True)
    add("U02-KEY-004", "the identity point is refused", (1).to_bytes(32, "little"), False)
    add("U02-KEY-005", "the order-2 point (y = p - 1) is refused", (ed.P - 1).to_bytes(32, "little"), False)
    add("U02-KEY-006", "the order-4 point (y = 0) is refused", bytes(32), False)
    tor = small_order_points()
    assert tor, "no torsion point found"
    for i, t in enumerate(tor[:2], start=7):
        add(f"U02-KEY-00{i}", f"a computed small-order point ({i - 6}) is refused", t, False)
    a = ed.decode_point(PUBS["A"])
    mixed = ed.encode_point(ed.point_add(a, ed.decode_point(tor[0])))
    add("U02-KEY-009", "a prime-order key plus a small-order point (mixed order) is refused", mixed, False)
    add("U02-KEY-010", "a non-canonical encoding (y = p + 1) is refused", (ed.P + 1).to_bytes(32, "little"), False)
    off = next(y for y in range(2, 100) if ed.decode_point(y.to_bytes(32, "little")) is None)
    add("U02-KEY-011", "a y that is not on the curve is refused", off.to_bytes(32, "little"), False)
    add("U02-KEY-012", "a key one byte short is refused", PUBS["A"][:-1], False)
    return out


def trust_vectors() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    tor = small_order_points()
    mixed = ed.encode_point(ed.point_add(ed.decode_point(PUBS["A"]), ed.decode_point(tor[0])))

    def add(vid: str, title: str, keys: List[Any], expect: Dict[str, Any]) -> None:
        def build() -> str:
            ref.TrustStore([(bytes.fromhex(k["public"]), k["revoked"]) for k in keys])
            return "built"

        got = outcome(build)
        assert got == expect, f"{vid}: hand-written {expect}, model {got}"
        out.append({"id": vid, "title": title, "keys": keys, "expect": expect})

    k = lambda pub, revoked=False: {"public": pub.hex(), "revoked": revoked}  # noqa: E731
    a, b, x = PUBS["A"], PUBS["B"], PUBS["X"]
    add("U02-TRUST-001", "three admissible keys, one of them revoked, make a store", [k(a), k(b, True), k(x)], {"ok": "built"})
    add("U02-TRUST-002", "an empty store is a store (nothing can be admitted from it)", [], {"ok": "built"})
    add("U02-TRUST-003", "four keys fit", [k(a), k(b), k(x), k(PUBS["A"], False)][:3] + [k(ed.public_from_seed(bytes(32)))], {"ok": "built"})
    add("U02-TRUST-004", "a fifth key does not", [k(a), k(b), k(x), k(a), k(b)], refuse("trust_store_full"))
    add("U02-TRUST-005", "the same key twice", [k(a), k(a, True)], refuse("duplicate_trust_key"))
    add("U02-TRUST-006", "the identity point", [k(a), k((1).to_bytes(32, "little"))], refuse("bad_trust_key"))
    add("U02-TRUST-007", "a small-order point", [k(tor[0])], refuse("bad_trust_key"))
    add("U02-TRUST-008", "a prime-order key plus a small-order point", [k(mixed)], refuse("bad_trust_key"))
    add("U02-TRUST-009", "a non-canonical encoding", [k((ed.P + 1).to_bytes(32, "little"))], refuse("bad_trust_key"))
    return out


def parse_vectors() -> List[Dict[str, Any]]:
    good = manifest()
    out: List[Dict[str, Any]] = []

    def add(vid: str, title: str, raw: bytes, expect: Dict[str, Any]) -> None:
        got = outcome(lambda: {"version": ref.parse(raw)["version"]})
        assert got == expect, f"{vid}: hand-written {expect}, model {got}"
        out.append({"id": vid, "title": title, "manifest": raw.hex(), "expect": expect})

    add("U02-PARSE-001", "a well-formed manifest parses", good, {"ok": {"version": 100}})
    add("U02-PARSE-002", "empty input", b"", refuse("manifest_too_short"))
    add("U02-PARSE-003", "one byte short of a whole manifest", good[:-1], refuse("manifest_too_short"))
    add("U02-PARSE-004", "one trailing byte", good + b"\x00", refuse("trailing_bytes"))
    add("U02-PARSE-005", "over the 512-byte bound", good + bytes(600), refuse("manifest_too_long"))
    add("U02-PARSE-006", "wrong magic", b"FFWX" + good[4:], refuse("bad_magic"))
    add("U02-PARSE-007", "an unknown format number", good[:4] + b"\x02" + good[5:], refuse("unsupported_format"))
    add("U02-PARSE-008", "an unknown stage number", good[:5] + b"\x09" + good[6:], refuse("bad_field"))
    add("U02-PARSE-009", "a reserved flag bit", good[:6] + b"\x00\x08" + good[8:], refuse("bad_field"))
    add("U02-PARSE-010", "an empty profile id", manifest(profile_id=""), refuse("bad_field"))
    add("U02-PARSE-011", "an upper-case profile id", manifest(profile_id="Sonos-S5"), refuse("bad_field"))
    add("U02-PARSE-012", "a profile id that is too long", manifest(profile_id="a" * 49), refuse("bad_field"))
    add("U02-PARSE-013", "an unknown ISA code", manifest(isa=9), refuse("bad_field"))
    add("U02-PARSE-014", "a feature bit that does not exist", manifest(features=ref.FEATURES_ALL | 64), refuse("bad_field"))
    add("U02-PARSE-015", "an artifact of zero bytes", manifest(artifact_size=0), refuse("bad_field"))
    add("U02-PARSE-016", "a settings read window that is above its own schema", manifest(settings_schema=2, settings_read_min=3), refuse("bad_field"))
    add("U02-PARSE-017", "a schema number of zero", manifest(wire_schema=0), refuse("bad_field"))
    add("U02-PARSE-023", "a wire schema above its own read window", manifest(wire_schema=3, wire_read_min=1, wire_read_max=2), refuse("bad_field"))
    add("U02-PARSE-018", "an SSH flag that is neither 0 nor 1", good[:field_offset(good, "ssh")] + b"\x02" + good[field_offset(good, "ssh") + 1:], refuse("bad_field"))
    add("U02-PARSE-019", "a reviewed-equivalent SSH fix with no evidence digest", manifest(ssh=dict(SSH_GOOD, fix=ref.FIX_REVIEWED)), refuse("bad_field"))
    add("U02-PARSE-020", "an upstream SSH fix that carries an evidence digest", manifest(ssh=dict(SSH_GOOD, fix_evidence=EVIDENCE)), refuse("bad_field"))
    add("U02-PARSE-021", "an SSH libc name with an upper-case letter", manifest(ssh=dict(SSH_GOOD, libc="Musl")), refuse("bad_field"))
    add("U02-PARSE-022", "a manifest with an SSH block parses", manifest(ssh=SSH_GOOD), {"ok": {"version": 100}})
    return out


def admission_vectors() -> List[Dict[str, Any]]:
    v: List[Dict[str, Any]] = []
    add = lambda *a, **k: v.append(admit_vec(*a, **k))  # noqa: E731
    good = manifest()
    add("U02-ADM-001", "a signed manifest for this board, above the floor, is admitted; A/B is not proven and no vendor acceptance is claimed", good, {"ok": GOOD}, invariants=["ADMIT-OK"])
    # -- authenticity
    add("U02-ADM-002", "one flipped bit in the signature", flip(good, len(good) - 3), refuse("bad_signature"), invariants=["SIG"])
    add("U02-ADM-003", "a body field changed after signing", flip(good, field_offset(good, "version") + 3), refuse("bad_signature"), invariants=["SIG"])
    add("U02-ADM-004", "signed by a key that is not trusted", manifest(signer="X"), refuse("unknown_signing_key"), invariants=["TRUST"])
    add("U02-ADM-005", "signed by a trusted key that has been revoked", manifest(signer="B"), refuse("revoked_signing_key"),
        ctx={"trust": [{"key": "A", "revoked": False}, {"key": "B", "revoked": True}]}, invariants=["TRUST"])
    add("U02-ADM-006", "the same manifest from the other trusted key, not revoked, is admitted", manifest(signer="B"), {"ok": GOOD}, invariants=["TRUST"])
    body = ref.encode_body(dict(BASE, key_id=key_id("A")))
    s = int.from_bytes(ed.sign(SEEDS["A"], ref.DOMAIN + body)[32:], "little")
    sig = ed.sign(SEEDS["A"], ref.DOMAIN + body)
    add("U02-ADM-007", "a malleable signature (S + L) over a good body", body + sig[:32] + (s + ed.L).to_bytes(32, "little"), refuse("bad_signature"), invariants=["SIG"])
    add("U02-ADM-008", "signed without the domain prefix", body + ed.sign(SEEDS["A"], body), refuse("bad_signature"), invariants=["SIG"])
    # -- the trust boundary
    for n, (stage, name) in enumerate(((ref.STAGE_KERNEL, "kernel"), (ref.STAGE_BOOTLOADER, "bootloader"), (ref.STAGE_VENDOR, "vendor package")), start=9):
        add(f"U02-ADM-{n:03d}", f"a manifest that targets the {name} stage", manifest(stage=stage), refuse("stage_forbidden"), invariants=["BOUNDARY"])
    add("U02-ADM-012", "a manifest that claims vendor acceptance", manifest(flags=ref.FLAG_VENDOR_CLAIM), refuse("vendor_claim_forbidden"), invariants=["BOUNDARY"])
    add("U02-ADM-013", "a manifest that claims a factory-bypass", manifest(flags=ref.FLAG_BYPASS_CLAIM), refuse("bypass_claim_forbidden"), invariants=["BOUNDARY"])
    add("U02-ADM-014", "a manifest that claims A/B capacity", manifest(flags=ref.FLAG_AB_CLAIM), refuse("ab_claim_forbidden"), invariants=["BOUNDARY", "AB"])
    # -- the board
    add("U02-ADM-015", "a manifest for another board", manifest(profile_id=BOARDS["mips"]["profile_id"]), refuse("wrong_board"), invariants=["BOARD"])
    add("U02-ADM-016", "the right board, another hardware revision", manifest(hw_rev="1.16.3.1-3"), refuse("hardware_revision_mismatch"), invariants=["BOARD"])
    add("U02-ADM-017", "the right board, the other ISA", manifest(isa=ref.ISA_MIPS32R2_BE), refuse("isa_mismatch"), invariants=["BOARD"])
    add("U02-ADM-018", "the right board, another kernel capability profile", manifest(kernel_profile="linux-2.4.27-ppc32-be"), refuse("kernel_profile_mismatch"), invariants=["BOARD"])
    add("U02-ADM-019", "the mips manifest on the mips board is admitted", manifest(profile_id=BOARDS["mips"]["profile_id"], hw_rev=BOARDS["mips"]["hw_rev"],
        isa=ref.ISA_MIPS32R2_BE, kernel_profile=BOARDS["mips"]["kernel_profile"]), {"ok": GOOD}, ctx={"board": "mips"}, invariants=["BOARD"])
    # -- production policy: E01 evidence and attestation
    add("U02-ADM-020", "production refuses a synthetic fixture board", good, refuse("profile_not_attested"), ctx={"production": True}, invariants=["PRODUCTION"])
    add("U02-ADM-021", "production on an attested board with no evidence digest supplied", good, refuse("evidence_mismatch"),
        ctx={"production": True, "board": "ppc_policy_standin"}, invariants=["PRODUCTION"])
    add("U02-ADM-022", "production, attested, the manifest carries the wrong evidence digest", manifest(evidence_digest=hashlib.sha256(b"other").digest()),
        refuse("evidence_mismatch"), ctx={"production": True, "board": "ppc_policy_standin", "evidence": EVIDENCE.hex()}, invariants=["PRODUCTION"])
    add("U02-ADM-023", "production, attested, the evidence digests agree (SSH-free image, qualified features)", manifest(evidence_digest=EVIDENCE), {"ok": GOOD},
        ctx={"production": True, "board": "ppc_policy_standin", "evidence": EVIDENCE.hex()}, invariants=["PRODUCTION"])
    add("U02-ADM-065", "production, a synthetic fixture board, and an evidence digest that matches: the fixture is still refused", manifest(evidence_digest=EVIDENCE),
        refuse("profile_not_attested"), ctx={"production": True, "board": "ppc", "evidence": EVIDENCE.hex()}, invariants=["PRODUCTION"])
    # -- required features
    drop = ref.FEATURES_ALL & ~(1 << ref.FEATURES.index("tailnet_native"))
    add("U02-ADM-024", "an image without a required native feature", manifest(features=drop), refuse("required_feature_missing"), invariants=["FEATURES"])
    add("U02-ADM-025", "the same image under an offline policy that requires none is admitted", manifest(features=drop), {"ok": GOOD}, ctx={"required": 0}, invariants=["FEATURES"])
    # -- anti-rollback
    add("U02-ADM-026", "security version below the floor", manifest(security_version=3), refuse("below_security_floor"), invariants=["ROLLBACK"])
    add("U02-ADM-027", "security version equal to the floor is admitted", manifest(security_version=4), {"ok": GOOD}, invariants=["ROLLBACK"])
    down = dict(GOOD, downgrade=True)
    add("U02-ADM-028", "a lower version at the floor needs an explicit downgrade policy", manifest(version=80, security_version=4), refuse("downgrade_not_permitted"), invariants=["ROLLBACK"])
    add("U02-ADM-029", "the same downgrade under an explicit policy is admitted", manifest(version=80, security_version=4), {"ok": down}, ctx={"allow_downgrade": True}, invariants=["ROLLBACK"])
    add("U02-ADM-030", "consent to downgrade does not lower the floor", manifest(version=80, security_version=3), refuse("below_security_floor"), ctx={"allow_downgrade": True}, invariants=["ROLLBACK"])
    add("U02-ADM-031", "the installed image offered again", manifest(version=90, security_version=4, artifact_sha256=INSTALLED["sha"]), refuse("version_reused"), invariants=["ROLLBACK"])
    raw_same = manifest()
    same_sha = ref.sha256(raw_same)
    add("U02-ADM-032", "the installed manifest offered again", raw_same, refuse("already_installed"), ctx={"installed": dict(INSTALLED, sha=same_sha.hex())}, invariants=["ROLLBACK"])
    add("U02-ADM-033", "a different content under the installed version number", manifest(version=90, security_version=5), refuse("version_reused"), invariants=["ROLLBACK"])
    add("U02-ADM-034", "a candidate that already failed its trial", good, refuse("candidate_previously_failed"), ctx={"failed": ref.sha256(good).hex()}, invariants=["ROLLBACK"])
    add("U02-ADM-035", "another candidate after that failure is admitted", manifest(version=101), {"ok": GOOD}, ctx={"failed": ref.sha256(good).hex()}, invariants=["ROLLBACK"])
    add("U02-ADM-036", "a first install with no installed image and floor 0", good, {"ok": GOOD}, ctx={"installed": None, "floor": 0}, invariants=["ADMIT-OK"])
    # -- old/new settings and calibration
    add("U02-ADM-037", "a different calibration schema is never converted", manifest(calibration_schema=2), refuse("calibration_schema_mismatch"), invariants=["COMPAT"])
    add("U02-ADM-038", "an image that cannot read the stored settings schema", manifest(version=100, settings_schema=2, settings_read_min=1), refuse("settings_incompatible"), invariants=["COMPAT"])
    add("U02-ADM-039", "the same image when a preserved copy of an older schema exists", manifest(settings_schema=2, settings_read_min=1), {"ok": GOOD}, ctx={"settings_backup": 2}, invariants=["COMPAT"])
    add("U02-ADM-040", "a preserved copy the candidate cannot read either", manifest(settings_schema=2, settings_read_min=1), refuse("settings_incompatible"), ctx={"settings_backup": 4}, invariants=["COMPAT"])
    add("U02-ADM-041", "an image whose read window starts above the stored schema", manifest(settings_schema=5, settings_read_min=4), refuse("settings_incompatible"), invariants=["COMPAT"])
    add("U02-ADM-042", "an image one schema ahead that still reads the stored one", manifest(settings_schema=4, settings_read_min=3), {"ok": GOOD}, invariants=["COMPAT"])
    # -- SSH
    add("U02-ADM-043", "an image with no SSH daemon declares none", good, {"ok": GOOD}, ctx={"production": False}, invariants=["SSH"])
    add("U02-ADM-044", "SSH with the upstream fix, public-key-only, bound and qualified", manifest(ssh=SSH_GOOD), {"ok": GOOD}, invariants=["SSH"])
    add("U02-ADM-045", "SSH with no fix", manifest(ssh=dict(SSH_GOOD, fix=ref.FIX_NONE)), refuse("ssh_fix_missing"), invariants=["SSH"])
    add("U02-ADM-046", "SSH that claims the upstream fix at a version before it", manifest(ssh=dict(SSH_GOOD, major=10, minor=5, portable=1)), refuse("ssh_fix_missing"), invariants=["SSH"])
    add("U02-ADM-047", "SSH at 10.6p1 (the portable counter is below the fix)", manifest(ssh=dict(SSH_GOOD, portable=1)), refuse("ssh_fix_missing"), invariants=["SSH"])
    add("U02-ADM-048", "SSH at 10.7p1 is above the fix", manifest(ssh=dict(SSH_GOOD, minor=7, portable=1)), {"ok": GOOD}, invariants=["SSH"])
    add("U02-ADM-049", "an older daemon with a reviewed equivalent and its evidence digest", manifest(ssh=dict(SSH_GOOD, major=9, minor=9, portable=1, fix=ref.FIX_REVIEWED, fix_evidence=EVIDENCE)), {"ok": GOOD}, invariants=["SSH"])
    add("U02-ADM-050", "SSH not bound to a daemon source digest", manifest(ssh=dict(SSH_GOOD, source_digest=ref.ZERO32)), refuse("ssh_unbound"), invariants=["SSH"])
    add("U02-ADM-051", "SSH not bound to a daemon build digest", manifest(ssh=dict(SSH_GOOD, build_digest=ref.ZERO32)), refuse("ssh_unbound"), invariants=["SSH"])
    pw = ref.AUTH_PASSWORD | ref.AUTH_PUBKEY_ONLY | ref.AUTH_INCLUDE_MATCH
    add("U02-ADM-052", "production refuses password authentication", manifest(evidence_digest=EVIDENCE, ssh=dict(SSH_GOOD, auth=pw)), refuse("ssh_password_forbidden"),
        ctx={"production": True, "board": "ppc_policy_standin", "evidence": EVIDENCE.hex()}, invariants=["SSH", "PRODUCTION"])
    add("U02-ADM-053", "a password-enabled lab image is admitted only under the offline policy", manifest(ssh=dict(SSH_GOOD, auth=ref.AUTH_PASSWORD)), {"ok": GOOD}, invariants=["SSH"])
    add("U02-ADM-054", "public-key-only with Include/Match not resolved", manifest(ssh=dict(SSH_GOOD, auth=ref.AUTH_PUBKEY_ONLY)), refuse("ssh_auth_unresolved"), invariants=["SSH"])
    add("U02-ADM-055", "authentication neither password nor public-key-only", manifest(ssh=dict(SSH_GOOD, auth=0)), refuse("ssh_auth_unresolved"), invariants=["SSH"])
    add("U02-ADM-056", "production without a guest qualification receipt", manifest(evidence_digest=EVIDENCE, ssh=dict(SSH_GOOD, qualification=ref.ZERO32)), refuse("ssh_unqualified"),
        ctx={"production": True, "board": "ppc_policy_standin", "evidence": EVIDENCE.hex()}, invariants=["SSH", "PRODUCTION"])
    add("U02-ADM-057", "the same image offline (not qualified yet) is admitted for testing", manifest(ssh=dict(SSH_GOOD, qualification=ref.ZERO32)), {"ok": GOOD}, invariants=["SSH"])
    # -- capacity and A/B
    add("U02-ADM-058", "the artifact and its reserve do not fit the staging area", good, refuse("insufficient_capacity"), ctx={"staging_bytes": len(ART) + 4095}, invariants=["CAPACITY"])
    add("U02-ADM-059", "the artifact and its reserve fit exactly", good, {"ok": GOOD}, ctx={"staging_bytes": len(ART) + 4096}, invariants=["CAPACITY"])
    rc_ok = {"slot_bytes": 1 << 20, "digest": hashlib.sha256(b"capacity receipt").hexdigest(), "synthetic": False}
    ab = dict(GOOD, mode="ab_slots", ab="proven_by_external_receipt")
    add("U02-ADM-060", "an external capacity receipt that covers two slots", good, {"ok": ab}, ctx={"ab_receipt": rc_ok, "board": "ppc_policy_standin"}, invariants=["AB"])
    add("U02-ADM-061", "a capacity receipt too small for the artifact does not claim A/B", good, {"ok": GOOD}, ctx={"ab_receipt": dict(rc_ok, slot_bytes=100), "board": "ppc_policy_standin"}, invariants=["AB"])
    add("U02-ADM-062", "a synthetic receipt for a board that is not a synthetic fixture", good, refuse("synthetic_receipt_for_real_profile"),
        ctx={"ab_receipt": dict(rc_ok, synthetic=True), "board": "ppc_policy_standin"}, invariants=["AB"])
    add("U02-ADM-063", "a synthetic receipt on a synthetic fixture board is the model's own use", good, {"ok": ab}, ctx={"ab_receipt": dict(rc_ok, synthetic=True)}, invariants=["AB"])
    add("U02-ADM-064", "no capacity receipt and no recovery path: nothing is claimed and nothing is planned", good, refuse("no_recovery_path"), ctx={"recovery_path": False}, invariants=["AB"])
    # a receipt is bound by its digest; an all-zero digest is "absent" (as everywhere else), so the slots it names prove nothing
    nodigest = dict(rc_ok, digest=ref.ZERO32.hex())
    add("U02-ADM-066", "a capacity receipt with no digest binds nothing: its slots are not used, A/B is not claimed, and a single slot with a recovery path is planned", good, {"ok": GOOD},
        ctx={"ab_receipt": nodigest, "board": "ppc_policy_standin"}, invariants=["AB"])
    add("U02-ADM-067", "the same receipt with no recovery path: nothing is claimed and nothing is planned", good, refuse("no_recovery_path"),
        ctx={"ab_receipt": nodigest, "recovery_path": False, "board": "ppc_policy_standin"}, invariants=["AB"])
    add("U02-ADM-068", "a synthetic receipt for a real board is refused whether or not it has a digest", good, refuse("synthetic_receipt_for_real_profile"),
        ctx={"ab_receipt": dict(nodigest, synthetic=True), "board": "ppc_policy_standin"}, invariants=["AB"])
    add("U02-ADM-069", "a receipt whose slot is exactly the artifact plus its reserve proves A/B", good, {"ok": ab},
        ctx={"ab_receipt": dict(rc_ok, slot_bytes=len(ART) + 4096), "board": "ppc_policy_standin"}, invariants=["AB"])
    add("U02-ADM-070", "a receipt whose slot is one byte short of the artifact plus its reserve does not", good, {"ok": GOOD},
        ctx={"ab_receipt": dict(rc_ok, slot_bytes=len(ART) + 4095), "board": "ppc_policy_standin"}, invariants=["AB"])
    add("U02-ADM-071", "a digest that is zero except for its last byte is a digest", good, {"ok": ab},
        ctx={"ab_receipt": dict(rc_ok, digest="00" * 31 + "01"), "board": "ppc_policy_standin"}, invariants=["AB"])
    # an evidence digest of zero means none, on either side: two zeros are not a match (the manifest table of docs/contracts/u02.md; ADM-023 is the positive)
    zero, prod = ref.ZERO32.hex(), {"production": True, "board": "ppc_policy_standin"}
    first_only, last_only = b"\x01" + bytes(31), bytes(31) + b"\x01"
    add("U02-ADM-072", "production, attested, the manifest names no evidence and the device was handed an all-zero digest: two zeros are not a match", good,
        refuse("evidence_mismatch"), ctx=dict(prod, evidence=zero), invariants=["PRODUCTION"])
    add("U02-ADM-073", "production, attested, the manifest names no evidence and the device has a digest", good, refuse("evidence_mismatch"),
        ctx=dict(prod, evidence=EVIDENCE.hex()), invariants=["PRODUCTION"])
    add("U02-ADM-074", "production, attested, the manifest names evidence and the device was handed an all-zero digest", manifest(evidence_digest=EVIDENCE),
        refuse("evidence_mismatch"), ctx=dict(prod, evidence=zero), invariants=["PRODUCTION"])
    add("U02-ADM-075", "the same two zeros under an offline policy are admitted: the evidence is a production gate", good, {"ok": GOOD},
        ctx={"board": "ppc_policy_standin", "evidence": zero}, invariants=["PRODUCTION"])
    add("U02-ADM-076", "a synthetic fixture in production with two zeros: the fixture is refused first", good, refuse("profile_not_attested"),
        ctx={"production": True, "board": "ppc", "evidence": zero}, invariants=["PRODUCTION"])
    add("U02-ADM-077", "an unknown signer with two zeros in production: the key is refused first", manifest(signer="X"), refuse("unknown_signing_key"),
        ctx=dict(prod, evidence=zero), invariants=["PRODUCTION", "TRUST"])
    add("U02-ADM-078", "a missing required feature with two zeros in production: the evidence is refused before the feature is looked at", manifest(features=drop),
        refuse("evidence_mismatch"), ctx=dict(prod, evidence=zero), invariants=["PRODUCTION", "FEATURES"])
    add("U02-ADM-079", "a digest that is zero except for its last byte is a digest: carried and handed over, it is admitted", manifest(evidence_digest=last_only), {"ok": GOOD},
        ctx=dict(prod, evidence=last_only.hex()), invariants=["PRODUCTION"])
    add("U02-ADM-080", "a digest that is zero except for its first byte is a digest: carried and handed over, it is admitted", manifest(evidence_digest=first_only), {"ok": GOOD},
        ctx=dict(prod, evidence=first_only.hex()), invariants=["PRODUCTION"])
    return v


def artifact_vectors() -> List[Dict[str, Any]]:
    m = ref.parse(manifest())
    out: List[Dict[str, Any]] = []

    def add(vid: str, title: str, data: bytes, expect: Dict[str, Any]) -> None:
        got = outcome(lambda: (ref.check_artifact(m, data), "verified")[1])
        assert got == expect, f"{vid}: hand-written {expect}, model {got}"
        out.append({"id": vid, "title": title, "manifest": manifest().hex(), "artifact": data.hex(), "expect": expect})

    add("U02-ART-001", "the whole artifact", ART, {"ok": "verified"})
    add("U02-ART-002", "one byte short", ART[:-1], refuse("artifact_truncated"))
    add("U02-ART-003", "nothing staged", b"", refuse("artifact_truncated"))
    add("U02-ART-004", "one byte too many", ART + b"\x00", refuse("artifact_oversized"))
    add("U02-ART-005", "the right length with one bit wrong", flip(ART, 77), refuse("artifact_digest_mismatch"))
    add("U02-ART-006", "the right length and the right content shifted by one", ART[1:] + ART[:1], refuse("artifact_digest_mismatch"))
    return out


def play(spec: Dict[str, Any], ops: List[Dict[str, Any]], arts: Dict[str, bytes], mans: Dict[str, bytes], bugs=frozenset()) -> List[Dict[str, Any]]:
    """Run the reference engine over a script; one `{"result": ..., "state": ...}` per operation. Judges and generators both use this."""
    base = build_ctx(spec, bugs)
    store = ref.Store()
    if spec["installed"] is not None:
        i = spec["installed"]
        store.records["u02.inst"] = ref.Installed(i["version"], i["security_version"], i["settings_schema"], i["settings_read_min"], i["calibration_schema"],
                                                  i["wire_schema"], i["wire_read_min"], i["wire_read_max"], i["features"], bytes.fromhex(i["sha"])).pack()
    store.floor = spec["floor"]
    if spec["failed"] is not None:
        store.records["u02.fail"] = b"\x01" + bytes.fromhex(spec["failed"])
    staging = ref.Staging(spec["staging_bytes"])
    eng = ref.Engine(store, staging, bugs)
    out: List[Dict[str, Any]] = []
    for op in ops:
        kind = op["op"]
        try:
            if kind == "begin":
                eng.begin_stage(base, mans[op["manifest"]])
                res: Dict[str, Any] = {"ok": "staging"}
            elif kind == "write":
                eng.write_chunk(arts[op["artifact"]][op["from"]: op["to"]])
                res = {"ok": "written"}
            elif kind == "finish":
                eng.finish_stage()
                res = {"ok": "staged"}
            elif kind == "activate":
                eng.activate()
                res = {"ok": "trial"}
            elif kind == "boot":
                res = {"ok": eng.report_boot(op["healthy"])}
            elif kind == "abort":
                eng.abort()
                res = {"ok": "idle"}
            elif kind == "restart":
                eng = eng.restart(base)
                res = {"ok": "restarted"}
            elif kind == "restart_with":
                merged = dict(spec, **op["ctx"])
                if "floor" in op["ctx"]:
                    store.floor = max(store.floor, op["ctx"]["floor"])
                base = build_ctx(merged, bugs)
                eng = eng.restart(base)
                res = {"ok": "restarted"}
            elif kind == "power_cut":
                staging.power_cut(op["keep"])
                eng = eng.restart(base)
                res = {"ok": "restarted"}
            elif kind == "corrupt":
                if op["at"] < len(staging.data):
                    staging.data[op["at"]] ^= 1 << op.get("bit", 0)
                res = {"ok": "corrupted"}
            elif kind == "tamper_manifest":
                raw = bytearray(staging.manifest or b"")
                if op["at"] < len(raw):
                    raw[op["at"]] ^= 1
                    staging.manifest = bytes(raw)
                res = {"ok": "tampered"}
            elif kind == "swap_manifest":
                staging.manifest = mans[op["manifest"]]
                res = {"ok": "swapped"}
            else:
                raise AssertionError(kind)
        except ref.Refusal as e:
            res = {"refuse": e.code}
        out.append({"result": res, "state": eng.snapshot()})
    return out


def run_script(name: str, ops: List[Dict[str, Any]], spec: Dict[str, Any], arts: Dict[str, bytes], mans: Dict[str, bytes]) -> List[Dict[str, Any]]:
    """Play a script and require the model to agree with each op's hand-written `expect`."""
    for n, (op, got) in enumerate(zip(ops, play(spec, ops, arts, mans))):
        assert got["result"] == op["expect"]["result"], f"{name} op {n} {op['op']}: hand-written {op['expect']['result']}, model {got['result']}"
        assert got["state"] == op["expect"]["state"], f"{name} op {n} {op['op']}: hand-written state {op['expect']['state']}, model {got['state']}"
    return ops


def S(phase: str, installed: Optional[int], floor: int, nxt: int = 0) -> Dict[str, Any]:
    return {"phase": phase, "installed": installed, "floor": floor, "next": nxt}


def OP(op: str, result: Any, state: Dict[str, Any], **kw: Any) -> Dict[str, Any]:
    return dict({"op": op, "expect": {"result": result if isinstance(result, dict) else {"ok": result}, "state": state}}, **kw)


def R(code: str) -> Dict[str, Any]:
    return {"refuse": code}


def engine_vectors(assets: Dict[str, Any]) -> Dict[str, Any]:
    arts = {"a1": ART, "wrong": flip(ART, 100), "short": ART[:100]}
    m1 = manifest()
    m2 = manifest(version=101, security_version=6, artifact_sha256=ART_SHA)
    m_mips = manifest(profile_id=BOARDS["mips"]["profile_id"], hw_rev=BOARDS["mips"]["hw_rev"], isa=ref.ISA_MIPS32R2_BE, kernel_profile=BOARDS["mips"]["kernel_profile"])
    m_low = manifest(version=80, security_version=4)
    m_floor = manifest(version=102, security_version=3)
    m_low95 = manifest(version=95, security_version=5)
    drop_feature = ref.FEATURES_ALL & ~(1 << ref.FEATURES.index("tailnet_native"))
    mans = {"m1": m1, "m2": m2, "mips": m_mips, "low": m_low, "floorlow": m_floor, "low95": m_low95,
            "mdrop": manifest(features=drop_feature), "mev": manifest(evidence_digest=EVIDENCE)}
    chunk = 16
    writes = [OP("write", "written", S("staging", 90, 4, min((i + 1) * chunk, 160)), artifact="a1", **{"from": i * chunk, "to": (i + 1) * chunk}) for i in range(10)]
    idle0 = S("idle", 90, 4)

    def w(i: int, nxt: int, a: str = "a1") -> Dict[str, Any]:
        return OP("write", "written", S("staging", 90, 4, nxt), artifact=a, **{"from": i * chunk, "to": (i + 1) * chunk})

    scripts: List[Dict[str, Any]] = []

    def add(sid: str, title: str, ops: List[Dict[str, Any]], invariants: List[str], **over: Any) -> None:
        spec = ctx_default()
        spec.update(over)
        scripts.append({"id": sid, "title": title, "invariants": invariants, "ctx": spec, "ops": run_script(sid, ops, spec, arts, mans)})

    assets["artifacts"], assets["manifests"] = {k: v.hex() for k, v in arts.items()}, {k: v.hex() for k, v in mans.items()}
    full = [OP("begin", "staging", S("staging", 90, 4, 0), manifest="m1")] + [w(i, (i + 1) * chunk) for i in range(10)]
    add("U02-ENG-001", "the happy path: stage, verify, trial, confirm; the floor rises only at the confirm", full + [
        OP("finish", "staged", S("staged", 90, 4)), OP("activate", "trial", S("trial", 90, 4)), OP("boot", "committed", S("idle", 100, 5), healthy=True)],
        ["FLOOR-AT-CONFIRM", "HAPPY"])
    add("U02-ENG-002", "a trial that never reports healthy rolls back; the installed image and the floor are untouched, and the candidate is not retried", full + [
        OP("finish", "staged", S("staged", 90, 4)), OP("activate", "trial", S("trial", 90, 4)), OP("boot", "retry", S("trial", 90, 4), healthy=False),
        OP("boot", "retry", S("trial", 90, 4), healthy=False), OP("boot", "rolled_back", idle0, healthy=False),
        OP("begin", R("candidate_previously_failed"), idle0, manifest="m1"), OP("begin", "staging", S("staging", 90, 4, 0), manifest="m2")],
        ["ROLLBACK-SAFE", "NO-RETRY"])
    add("U02-ENG-003", "one unhealthy boot and then a healthy one commits", full + [
        OP("finish", "staged", S("staged", 90, 4)), OP("activate", "trial", S("trial", 90, 4)), OP("boot", "retry", S("trial", 90, 4), healthy=False),
        OP("boot", "committed", S("idle", 100, 5), healthy=True)], ["HAPPY"])
    add("U02-ENG-004", "a truncated artifact keeps its stage open and the missing bytes complete it", [OP("begin", "staging", S("staging", 90, 4, 0), manifest="m1")]
        + [w(i, (i + 1) * chunk) for i in range(9)] + [OP("finish", R("artifact_truncated"), S("staging", 90, 4, 144)), w(9, 160), OP("finish", "staged", S("staged", 90, 4))],
        ["TRUNCATED"])
    add("U02-ENG-005", "bytes beyond the declared size are refused and write nothing", [OP("begin", "staging", S("staging", 90, 4, 0), manifest="m1")]
        + [w(i, (i + 1) * chunk) for i in range(10)] + [OP("write", R("artifact_oversized"), S("staging", 90, 4, 160), artifact="a1", **{"from": 0, "to": 1}),
        OP("finish", "staged", S("staged", 90, 4))], ["TRUNCATED"])
    add("U02-ENG-006", "wrong content of the right length fails its digest, clears the stage and blocks a retry", [OP("begin", "staging", S("staging", 90, 4, 0), manifest="m1")]
        + [w(i, (i + 1) * chunk, "wrong") for i in range(10)] + [OP("finish", R("artifact_digest_mismatch"), idle0), OP("begin", R("candidate_previously_failed"), idle0, manifest="m1"),
        OP("begin", "staging", S("staging", 90, 4, 0), manifest="m2")],
        ["DIGEST"])
    add("U02-ENG-007", "a power cut during staging resumes at the persisted checkpoint and the resent bytes complete the artifact",
        [OP("begin", "staging", S("staging", 90, 4, 0), manifest="m1")] + [w(i, (i + 1) * chunk) for i in range(7)]
        + [OP("power_cut", "restarted", S("staging", 90, 4, 64), keep=20)] + [w(i, (i + 1) * chunk) for i in range(4, 10)] + [OP("finish", "staged", S("staged", 90, 4))],
        ["INTERRUPTED"])
    add("U02-ENG-008", "a restart in every phase keeps the phase (staging resumes at the persisted checkpoint); a restart in the trial can still confirm", full + [
        OP("restart", "restarted", S("staging", 90, 4, 128)), w(8, 144), w(9, 160), OP("finish", "staged", S("staged", 90, 4)), OP("restart", "restarted", S("staged", 90, 4)),
        OP("activate", "trial", S("trial", 90, 4)), OP("restart", "restarted", S("trial", 90, 4)), OP("boot", "committed", S("idle", 100, 5), healthy=True)],
        ["RESTART"])
    add("U02-ENG-009", "bit rot in the staged bytes is caught at activation, not trusted from the earlier verdict", full + [
        OP("finish", "staged", S("staged", 90, 4)), OP("corrupt", "corrupted", S("staged", 90, 4), at=50),
        OP("activate", R("artifact_digest_mismatch"), idle0), OP("begin", R("candidate_previously_failed"), idle0, manifest="m1")], ["CORRUPTION"])
    add("U02-ENG-010", "abort leaves the installed image alone, is allowed before the trial and refused during it, and does not mark the candidate failed", [
        OP("begin", "staging", S("staging", 90, 4, 0), manifest="m1"), OP("begin", R("update_in_progress"), S("staging", 90, 4, 0), manifest="m2"),
        OP("abort", "idle", idle0), OP("abort", R("nothing_to_abort"), idle0), OP("begin", "staging", S("staging", 90, 4, 0), manifest="m1")] + [w(i, (i + 1) * chunk) for i in range(10)] + [
        OP("finish", "staged", S("staged", 90, 4)), OP("activate", "trial", S("trial", 90, 4)), OP("abort", R("trial_in_progress"), S("trial", 90, 4))], ["ABORT"])
    add("U02-ENG-011", "a manifest copy on the staging medium that no longer hashes to the journal's record is not resumed", [
        OP("begin", "staging", S("staging", 90, 4, 0), manifest="m1"), w(0, 16), OP("tamper_manifest", "tampered", S("staging", 90, 4, 16), at=20),
        OP("restart", "restarted", idle0), OP("begin", "staging", S("staging", 90, 4, 0), manifest="m1")], ["STAGING-COPY"])
    add("U02-ENG-012", "no room: the refusal comes before any state changes", [OP("begin", R("insufficient_capacity"), idle0, manifest="m1")], ["CAPACITY"], staging_bytes=1000)
    add("U02-ENG-013", "a manifest for another board never reaches staging", [OP("begin", R("wrong_board"), idle0, manifest="mips"), OP("begin", "staging", S("staging", 90, 4, 0), manifest="m1")], ["BOARD"])
    add("U02-ENG-014", "after a confirm the floor has risen and an image below it cannot come back", full + [
        OP("finish", "staged", S("staged", 90, 4)), OP("activate", "trial", S("trial", 90, 4)), OP("boot", "committed", S("idle", 100, 5), healthy=True),
        OP("begin", R("below_security_floor"), S("idle", 100, 5), manifest="floorlow"), OP("begin", R("below_security_floor"), S("idle", 100, 5), manifest="low"), OP("begin", R("downgrade_not_permitted"), S("idle", 100, 5), manifest="low95"), OP("begin", "staging", S("staging", 100, 5, 0), manifest="m2")], ["ROLLBACK", "FLOOR-AT-CONFIRM"])
    add("U02-ENG-015", "an explicit downgrade at the floor completes and leaves the floor where it was", [
        OP("begin", "staging", S("staging", 90, 4, 0), manifest="low")] + [w(i, (i + 1) * chunk) for i in range(10)] + [
        OP("finish", "staged", S("staged", 90, 4)), OP("activate", "trial", S("trial", 90, 4)), OP("boot", "committed", S("idle", 80, 4), healthy=True)], ["ROLLBACK"], allow_downgrade=True)
    add("U02-ENG-016", "a staged update that is aborted can be started again from the same manifest", full + [
        OP("finish", "staged", S("staged", 90, 4)), OP("abort", "idle", idle0), OP("begin", "staging", S("staging", 90, 4, 0), manifest="m1")], ["ABORT"])
    add("U02-ENG-018", "a different, validly signed manifest swapped into the staging slot does not hash to the journal's record and is not resumed", [
        OP("begin", "staging", S("staging", 90, 4, 0), manifest="m1"), w(0, 16), OP("swap_manifest", "swapped", S("staging", 90, 4, 16), manifest="m2"),
        OP("restart", "restarted", idle0), OP("begin", "staging", S("staging", 90, 4, 0), manifest="m2")], ["STAGING-COPY"])

    # ---- a restart admits the stage AGAIN under the policy of the day (the manifest copy on the staging medium is untrusted)
    def staged_ops(name: str, floor: int = 4) -> List[Dict[str, Any]]:
        return ([OP("begin", "staging", S("staging", 90, floor, 0), manifest=name)] + [w(i, (i + 1) * chunk) for i in range(10)]
                + [OP("finish", "staged", S("staged", 90, floor))])

    def restart_with(result_state: Dict[str, Any], **ctx: Any) -> Dict[str, Any]:
        return OP("restart_with", "restarted", result_state, ctx=ctx)

    staged0 = S("staged", 90, 4)
    add("U02-ENG-019", "control: under an unchanged policy a stage is resumed in every phase, and a trial that was resumed can still be confirmed",
        staged_ops("m1") + [restart_with(staged0), OP("activate", "trial", S("trial", 90, 4)), restart_with(S("trial", 90, 4)),
                            OP("boot", "committed", S("idle", 100, 5), healthy=True)], ["RESTART-ADMISSION"])
    add("U02-ENG-020", "a stage for the board this device used to be is dropped at restart, and the new board refuses the same manifest",
        staged_ops("m1") + [restart_with(idle0, board="mips"), OP("begin", R("wrong_board"), idle0, manifest="m1")], ["RESTART-ADMISSION", "BOARD"])
    add("U02-ENG-021", "turning production on drops a stage that was admitted for a synthetic fixture board",
        staged_ops("m1") + [restart_with(staged0), restart_with(idle0, production=True)], ["RESTART-ADMISSION", "PRODUCTION"])
    add("U02-ENG-022", "a feature the policy now requires drops a stage that lacks it; the same image resumes while the policy still requires none",
        staged_ops("mdrop") + [restart_with(staged0), restart_with(idle0, required=ref.FEATURES_ALL)], ["RESTART-ADMISSION", "FEATURES"], required=0)
    add("U02-ENG-023", "a floor raised above the candidate's security version drops the stage",
        staged_ops("m1") + [restart_with(staged0), restart_with(S("idle", 90, 6), floor=6)], ["RESTART-ADMISSION", "ROLLBACK"])
    add("U02-ENG-024", "consent to downgrade withdrawn drops a downgrade stage; while it stands the stage resumes",
        [OP("begin", "staging", S("staging", 90, 4, 0), manifest="low")] + [w(i, (i + 1) * chunk) for i in range(10)]
        + [OP("finish", "staged", staged0), restart_with(staged0), restart_with(idle0, allow_downgrade=False)], ["RESTART-ADMISSION", "ROLLBACK"], allow_downgrade=True)
    add("U02-ENG-025", "a staging capacity the stage no longer fits drops it",
        staged_ops("m1") + [restart_with(staged0), restart_with(idle0, staging_bytes=1000)], ["RESTART-ADMISSION", "CAPACITY"])
    add("U02-ENG-026", "production evidence that no longer matches the manifest's drops the stage; the matching evidence resumes it",
        staged_ops("mev") + [restart_with(staged0), restart_with(idle0, evidence=hashlib.sha256(b"another board's evidence").hexdigest())], ["RESTART-ADMISSION", "PRODUCTION"],
        production=True, board="ppc_policy_standin", evidence=EVIDENCE.hex())
    add("U02-ENG-027", "a signing key revoked since the stage began drops it",
        staged_ops("m1") + [restart_with(staged0), restart_with(idle0, trust=[{"key": "A", "revoked": True}, {"key": "B", "revoked": False}])], ["RESTART-ADMISSION", "TRUST"])
    add("U02-ENG-028", "a trial under way is dropped, installed image untouched, when the current policy no longer admits its image",
        staged_ops("m1") + [OP("activate", "trial", S("trial", 90, 4)), restart_with(idle0, board="mips"), OP("boot", R("not_in_trial"), idle0, healthy=True)],
        ["RESTART-ADMISSION", "BOARD"])
    add("U02-ENG-029", "with no A/B receipt and no recovery path a single slot cannot be planned, so the stage is dropped; with the recovery path it resumes",
        staged_ops("m1") + [restart_with(staged0), restart_with(idle0, recovery_path=False)], ["RESTART-ADMISSION", "PLAN"])
    add("U02-ENG-017", "writes and a finish with nothing staged are refused", [OP("write", R("not_staging"), idle0, artifact="a1", **{"from": 0, "to": 16}), OP("finish", R("not_staging"), idle0),
        OP("activate", R("not_staged"), idle0), OP("boot", R("not_in_trial"), idle0, healthy=True)], ["ORDER"])
    add("U02-ENG-030", "a device turned to production with an all-zero evidence digest drops a stage whose manifest names no evidence; offline the same stage resumes",
        staged_ops("m1") + [restart_with(staged0), restart_with(idle0, production=True, evidence=ref.ZERO32.hex())], ["RESTART-ADMISSION", "PRODUCTION"],
        board="ppc_policy_standin")
    return {"scripts": scripts}


def group_vectors() -> Dict[str, Any]:
    def img(version: int, wire: int, wmin: int, wmax: Optional[int] = None, settings: int = 3, smin: int = 2) -> Dict[str, Any]:
        """An image emits exactly `wire` and reads `wmin..=wmax` (default: just what it emits)."""
        return dict(INSTALLED, version=version, wire_schema=wire, wire_read_min=wmin, wire_read_max=wire if wmax is None else wmax,
                    settings_schema=settings, settings_read_min=smin, sha=hashlib.sha256(f"img{version}".encode()).hexdigest())

    def to_image(d: Optional[Dict[str, Any]]) -> Optional[ref.Installed]:
        return None if d is None else ref.Installed(d["version"], d["security_version"], d["settings_schema"], d["settings_read_min"], d["calibration_schema"],
                                                    d["wire_schema"], d["wire_read_min"], d["wire_read_max"], d["features"], bytes.fromhex(d["sha"]))

    cases: List[Dict[str, Any]] = []

    def add(vid: str, title: str, members: List[Dict[str, Any]], idx: int, cand: Dict[str, Any], expect: Dict[str, Any]) -> None:
        ms = [ref.Member(m["id"], to_image(m["image"]), m["connected"]) for m in members]
        got = ref.group_decision(ms, idx, to_image(cand))
        assert got == expect, f"{vid}: hand-written {expect}, model {got}"
        cases.append({"id": vid, "title": title, "members": members, "index": idx, "candidate": cand, "expect": expect})

    # old emits 2 and reads 1..2; stage 1 still emits 2 but reads up to 3; stage 2 emits 3 and reads 2..3
    old, stage1, stage2 = img(90, 2, 1, 2), img(100, 2, 1, 3), img(110, 3, 2, 3)
    m = lambda i, image, connected=True: {"id": i, "image": image, "connected": connected}  # noqa: E731
    admit_ok = {"decision": "admit", "code": "ok", "conflicts": [], "assumed": []}
    add("U02-GRP-001", "one upgraded and two old members: stage 1 emits the old wire and reads the new one, so both directions work", [m("a", old), m("b", old), m("c", old)], 0, stage1, admit_ok)
    add("U02-GRP-002", "stage 2 emits wire 3 and an old member reads at most 2: refused, and nobody else is upgraded", [m("a", old), m("b", old)], 0, stage2,
        {"decision": "refuse", "code": "wire_incompatible", "conflicts": ["b"], "assumed": []})
    add("U02-GRP-003", "a candidate that reads only wire 3 cannot read what an old member emits, and the old member cannot read 3", [m("a", old), m("b", old)], 0, img(120, 3, 3, 3),
        {"decision": "refuse", "code": "wire_incompatible", "conflicts": ["b"], "assumed": []})
    add("U02-GRP-004", "the candidate's own read window ends below what a member emits (the member reads the candidate's wire, the candidate cannot read the member's)",
        [m("a", old), m("b", img(100, 3, 1, 3))], 0, img(95, 1, 1, 1),
        {"decision": "refuse", "code": "wire_incompatible", "conflicts": ["b"], "assumed": []})
    add("U02-GRP-005", "stage 2 beside members that already run stage 1 is admitted", [m("a", old), m("b", stage1), m("c", stage1)], 0, stage2, admit_ok)
    add("U02-GRP-006", "a disconnected member counts through its last known image, and the answer says so", [m("a", old), m("b", old, False)], 0, stage1,
        {"decision": "admit", "code": "ok", "conflicts": [], "assumed": ["b"]})
    add("U02-GRP-007", "a disconnected member whose last known image is incompatible blocks the admission", [m("a", old), m("b", old, False)], 0, stage2,
        {"decision": "refuse", "code": "wire_incompatible", "conflicts": ["b"], "assumed": ["b"]})
    add("U02-GRP-008", "a disconnected member nobody has ever seen cannot be assessed", [m("a", old), m("b", None, False)], 0, stage1,
        {"decision": "refuse", "code": "unknown_member_state", "conflicts": ["b"], "assumed": []})
    add("U02-GRP-009", "a CONNECTED member that has reported no image cannot be assessed either", [m("a", old), m("b", None, True)], 0, stage1,
        {"decision": "refuse", "code": "unknown_member_state", "conflicts": ["b"], "assumed": []})
    add("U02-GRP-010", "every member whose state is unknown is named, connected or not, in order", [m("a", old), m("z", None, True), m("c", None, False)], 0, stage1,
        {"decision": "refuse", "code": "unknown_member_state", "conflicts": ["c", "z"], "assumed": []})
    add("U02-GRP-011", "three members, one conflict: only that one is named", [m("a", old), m("b", stage1), m("c", old)], 0, stage2,
        {"decision": "refuse", "code": "wire_incompatible", "conflicts": ["c"], "assumed": []})
    add("U02-GRP-012", "a group of one has nobody to disagree with", [m("a", old)], 0, img(130, 9, 9, 9), admit_ok)
    # the target is a member: an index that names none is refused before any other member is assessed, and a valid target need not be member 0
    no_target = {"decision": "refuse", "code": "invalid_target", "conflicts": [], "assumed": []}
    add("U02-GRP-013", "an empty group has no member to upgrade, so nothing is admitted (every member would otherwise count as somebody else)", [], 0, stage1, no_target)
    add("U02-GRP-014", "index equal to the number of members names nobody", [m("a", old), m("b", old)], 2, stage1, no_target)
    add("U02-GRP-015", "an index far past the group names nobody", [m("a", old), m("b", old), m("c", old)], 7, stage1, no_target)
    add("U02-GRP-016", "an index that names nobody is refused as such, not as a member nobody has heard from", [m("a", old), m("b", None, True)], 5, stage1, no_target)
    add("U02-GRP-017", "the target may be the last member: the others, including member 0, are the ones that are compared", [m("a", old), m("b", old), m("c", old)], 2, stage1, admit_ok)
    add("U02-GRP-018", "the target may be in the middle: both neighbours are compared and only they are named", [m("a", old), m("b", old), m("c", old)], 1, stage2,
        {"decision": "refuse", "code": "wire_incompatible", "conflicts": ["a", "c"], "assumed": []})
    rollbacks: List[Dict[str, Any]] = []

    def rb(vid: str, title: str, stored: int, backup: Optional[int], target: Dict[str, Any], expect: str) -> None:
        got = ref.rollback_decision(stored, backup, to_image(target))
        assert got == expect, f"{vid}: hand-written {expect}, model {got}"
        rollbacks.append({"id": vid, "title": title, "stored_settings_schema": stored, "settings_backup": backup, "target": target, "expect": expect})

    rb("U02-RB-001", "after a migration to schema 4 the old image (reads 1..3) cannot read the stored settings", 4, None, img(90, 2, 1, settings=3, smin=1), "refuse:settings_incompatible")
    rb("U02-RB-002", "the same rollback is allowed when the original schema-3 copy was preserved", 4, 3, img(90, 2, 1, settings=3, smin=1), "allow")
    rb("U02-RB-003", "a preserved copy the old image cannot read does not help", 4, 5, img(90, 2, 1, settings=3, smin=1), "refuse:settings_incompatible")
    rb("U02-RB-004", "an old image that reads the migrated schema needs no copy", 4, None, img(90, 2, 1, settings=4, smin=2), "allow")
    rb("U02-RB-005", "no migration happened: the stored schema is inside the old image's window", 3, None, img(90, 2, 1, settings=3, smin=1), "allow")
    return {"cases": cases, "rollbacks": rollbacks}


def build() -> Dict[str, Any]:
    group = group_vectors()
    assets: Dict[str, Any] = {}
    scripts = engine_vectors(assets)["scripts"]
    return {
        "schema": SCHEMA, "generator": "tests/u02/make_vectors.py (reference: tests/u02/reference.py, ed25519_ref.py)",
        "keys": {k: {"public": PUBS[k].hex(), "key_id": key_id(k).hex(), "source": "RFC 8032 section 7.1 test key"} for k in sorted(PUBS)},
        "boards": BOARDS, "constants": {"max_manifest": ref.MAX_MANIFEST, "checkpoint": ref.CHECKPOINT, "trial_boots": ref.TRIAL_BOOTS,
                                         "features": list(ref.FEATURES)},
        "ed25519": ed25519_vectors(), "keys_check": key_vectors(), "trust": trust_vectors(), "parse": parse_vectors(), "admit": admission_vectors(),
        "artifact": artifact_vectors(), "engine_assets": assets, "engine": scripts, "group": group["cases"], "rollback": group["rollbacks"],
    }


def dumps(doc: Dict[str, Any]) -> str:
    """Top-level keys in order, each list of cases one compact case per line, so a change to one case is one changed line."""
    def j(x: Any) -> str:
        return json.dumps(x, sort_keys=True, separators=(",", ":"))

    lines = ["{"]
    keys = sorted(doc)
    for n, key in enumerate(keys):
        value, comma = doc[key], "," if n + 1 < len(keys) else ""
        if isinstance(value, list):
            lines.append(f' "{key}":[')
            lines += ["  " + j(item) + ("," if i + 1 < len(value) else "") for i, item in enumerate(value)]
            lines.append(" ]" + comma)
        else:
            lines.append(f' "{key}":{j(value)}{comma}')
    lines.append("}")
    return "\n".join(lines) + "\n"


def main(argv: List[str]) -> int:
    text = dumps(build())
    if "--check" in argv:
        if os.path.exists(OUT):
            with open(OUT, encoding="utf-8") as handle:
                have = handle.read()
        else:
            have = ""
        if have != text:
            print(f"{os.path.relpath(OUT, REPO)} differs from what make_vectors.py writes")
            return 1
        print("u02 vectors: up to date")
        return 0
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {os.path.relpath(OUT, REPO)} ({len(text)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
