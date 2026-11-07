"""Checks on the U02 reference, the vectors, the oracle and the judges (bead ffw-76j), run by scripts/e2e/u02 and runnable alone:

    python3 -B -W error -m unittest tests/u02/test_u02.py

They establish that the reference states the contract coherently, that the committed vectors are exactly what the generator writes, that the
Ed25519 oracle agrees with the RFC (and with OpenSSL when it is present), that every planted defect is caught with the control green, that each
admission refusal sits beside the permitted behaviour it must not break, and that the Rust source agrees with the reference in the places a text
check can see. They do not compile or run the Rust.
"""
from __future__ import annotations

import json
import os
import re
import sys
import unittest
from typing import Any, Dict, List

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import ed25519_ref as ed  # noqa: E402
import judge  # noqa: E402
import make_vectors as mv  # noqa: E402
import reference as ref  # noqa: E402

CRATE = os.path.join(REPO, "crates", "franken-update")
CONTRACT = os.path.join(REPO, "docs", "contracts", "u02.md")


def read(*parts: str) -> str:
    with open(os.path.join(*parts), encoding="utf-8") as f:
        return f.read()


def rust_tests(path: str) -> List[str]:
    return re.findall(r"#\[test\]\s*\n\s*fn (\w+)\(", read(path))


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.doc = json.loads(read(mv.OUT))
        self.admit = {v["id"]: v for v in self.doc["admit"]}


class ReferenceAndVectors(Base):
    def test_the_committed_vectors_equal_a_fresh_generation(self) -> None:
        self.assertEqual(read(mv.OUT), mv.dumps(mv.build()))

    def test_the_vector_counts_and_ids(self) -> None:
        counts = {k: len(v) for k, v in self.doc.items() if isinstance(v, list)}
        self.assertEqual(counts, {"admit": 80, "artifact": 6, "ed25519": 15, "engine": 30, "group": 18, "keys_check": 12, "parse": 23, "rollback": 5, "trust": 9})
        ids = [v["id"] for group in counts for v in self.doc[group]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 198)

    def test_every_hand_written_expectation_agrees_with_the_model(self) -> None:
        self.assertEqual(judge.failing(self.doc), [])

    def test_the_constants_are_stated_once(self) -> None:
        c = self.doc["constants"]
        self.assertEqual((c["max_manifest"], c["checkpoint"], c["trial_boots"]), (512, 64, 3))
        self.assertEqual(c["features"], list(ref.FEATURES))
        self.assertEqual(ref.FEATURES, tuple(sorted(ref.FEATURES)), "the bit order is the alphabetical order of P01's required features")

    def test_every_refusal_in_the_vectors_is_a_code_of_the_crate(self) -> None:
        found = set(re.findall(r'"refuse":"([a-z_]+)"', read(mv.OUT).replace(": ", ":")))
        listed = set(re.findall(r'^    "([a-z_]+)",$', read(CRATE, "src", "lib.rs").split("pub const ALL_CODES")[1].split("];")[0], re.M))
        self.assertTrue(found <= listed, sorted(found - listed))
        self.assertEqual(listed - found, {"staging_gap", "profile_invalid", "isa_unsupported", "corrupt_state"})


class Oracle(unittest.TestCase):
    """The pure-integer Ed25519 is a test oracle only: it must agree with the RFC, and with OpenSSL where OpenSSL is available."""

    RFC = [
        ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ]

    def test_it_reproduces_the_rfc_8032_vectors(self) -> None:
        for seed, pub, msg, sig in self.RFC:
            seed, pub, msg, sig = (bytes.fromhex(x) for x in (seed, pub, msg, sig))
            self.assertEqual(ed.public_from_seed(seed), pub)
            self.assertEqual(ed.sign(seed, msg), sig)
            self.assertTrue(ed.verify(pub, msg, sig))
            self.assertFalse(ed.verify(pub, msg + b"x", sig))

    def test_the_keys_of_the_vectors_are_the_rfc_test_keys(self) -> None:
        self.assertEqual(mv.PUBS["A"].hex(), self.RFC[0][1])
        self.assertEqual(mv.PUBS["B"].hex(), self.RFC[1][1])

    def test_it_agrees_with_openssl_when_openssl_is_present(self) -> None:
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        except ImportError:
            self.skipTest("NOT RUN: the `cryptography` module is not installed, so the oracle was not compared with OpenSSL")
        import random

        rnd = random.Random(20261106)
        for _ in range(12):
            seed = bytes(rnd.getrandbits(8) for _ in range(32))
            msg = bytes(rnd.getrandbits(8) for _ in range(rnd.choice([0, 1, 64, 200])))
            key = Ed25519PrivateKey.from_private_bytes(seed)
            pub, sig = key.public_key().public_bytes_raw(), key.sign(msg)
            self.assertEqual(ed.public_from_seed(seed), pub)
            self.assertEqual(ed.sign(seed, msg), sig, "Ed25519 is deterministic: the signatures are byte-equal")
            bad = bytearray(sig)
            bad[rnd.randrange(64)] ^= 1 << rnd.randrange(8)
            try:
                Ed25519PublicKey.from_public_bytes(pub).verify(bytes(bad), msg)
                theirs = True
            except InvalidSignature:
                theirs = False
            self.assertEqual(ed.verify(pub, msg, bytes(bad)), theirs)


class HandDerivedPins(Base):
    def test_the_layout_by_hand(self) -> None:
        key_id = bytes(range(8))
        body = (b"FFWM" + b"\x01" + b"\x01" + b"\x00\x00" + key_id + b"\x05bp-ab" + b"\x031.0" + b"\x06linux1" + b"\x01"
                + (7).to_bytes(4, "big") + (3).to_bytes(4, "big") + b"\x00\x03\x00\x02\x00\x01\x00\x02\x00\x01\x00\x02" + b"\x00\x3f"
                + (96).to_bytes(4, "big") + bytes(32) + bytes(32) + b"\x00")
        self.assertEqual(len(body), 125)       # 16 fixed + 6 + 4 + 7 labels + 1 + 4 + 4 + 12 + 2 + 4 + 32 + 32 + 1
        made = ref.encode_body(dict(key_id=key_id, profile_id="bp-ab", hw_rev="1.0", kernel_profile="linux1", isa=1, version=7, security_version=3,
                                    settings_schema=3, settings_read_min=2, calibration_schema=1, wire_schema=2, wire_read_min=1, wire_read_max=2, features=63,
                                    artifact_size=96, artifact_sha256=bytes(32)))
        self.assertEqual(made, body)
        m = ref.parse(body + bytes(64))
        self.assertEqual((m["version"], m["security_version"], m["settings_schema"], m["settings_read_min"], m["wire_read_min"], m["wire_read_max"],
                          m["features"], m["artifact_size"], m["ssh"], len(m["body"])), (7, 3, 3, 2, 1, 2, 63, 96, None, 125))

    def test_the_signed_bytes_are_the_domain_and_the_body_and_nothing_else(self) -> None:
        raw = mv.manifest()
        m = ref.parse(raw)
        self.assertTrue(ed.verify(mv.PUBS["A"], b"ffw-u02-manifest-v1\x00" + raw[:-64], raw[-64:]))
        self.assertFalse(ed.verify(mv.PUBS["A"], raw[:-64], raw[-64:]), "the same signature without the prefix is not a signature of this use")
        self.assertEqual(m["body"], raw[:-64])

    def _first(self, raw: bytes, **ctx: Any) -> str:
        spec = mv.ctx_default()
        spec.update(ctx)
        try:
            ref.admit(mv.build_ctx(spec), raw)
            return "ok"
        except ref.Refusal as e:
            return e.code

    def test_the_order_of_the_rules_by_hand(self) -> None:
        wrong_board = dict(profile_id=mv.BOARDS["mips"]["profile_id"])
        # signature before board: an unsigned manifest for another board is a bad signature, not a wrong board
        self.assertEqual(self._first(mv.manifest(**wrong_board)[:-1] + b"\x00" if mv.manifest(**wrong_board)[-1] else mv.manifest(**wrong_board)[:-1] + b"\x01", ), "bad_signature")
        # trust boundary before board
        self.assertEqual(self._first(mv.manifest(stage=ref.STAGE_KERNEL, **wrong_board)), "stage_forbidden")
        # board before floor
        self.assertEqual(self._first(mv.manifest(security_version=1, **wrong_board)), "wrong_board")
        # floor before downgrade
        self.assertEqual(self._first(mv.manifest(version=80, security_version=1)), "below_security_floor")
        # production attestation before the feature rule
        self.assertEqual(self._first(mv.manifest(features=0), production=True), "profile_not_attested")
        # settings before SSH, SSH before capacity
        bad_ssh = dict(mv.SSH_GOOD, fix=ref.FIX_NONE)
        self.assertEqual(self._first(mv.manifest(settings_schema=2, settings_read_min=1, ssh=bad_ssh)), "settings_incompatible")
        self.assertEqual(self._first(mv.manifest(ssh=bad_ssh), staging_bytes=10), "ssh_fix_missing")
        self.assertEqual(self._first(mv.manifest(), staging_bytes=10), "insufficient_capacity")

    def test_the_floor_moves_only_at_the_confirm_by_hand(self) -> None:
        script = next(s for s in self.doc["engine"] if s["id"] == "U02-ENG-001")
        floors = [op["expect"]["state"]["floor"] for op in script["ops"]]
        self.assertEqual(set(floors[:-1]), {4}, "staging, verifying and activating leave the floor at 4")
        self.assertEqual(floors[-1], 5, "the confirm raises it to the candidate's security version")
        rolled = next(s for s in self.doc["engine"] if s["id"] == "U02-ENG-002")
        self.assertEqual({op["expect"]["state"]["floor"] for op in rolled["ops"]}, {4}, "a failed trial never raises it")

    def test_a_stage_survives_a_restart_at_the_persisted_checkpoint_and_no_further_by_hand(self) -> None:
        # chunks of 16 bytes: the checkpoint is persisted when 64 bytes have been written since the last one, i.e. at 64 and at 128
        script = next(s for s in self.doc["engine"] if s["id"] == "U02-ENG-008")
        restart = next(op for op in script["ops"] if op["op"] == "restart")
        self.assertEqual(restart["expect"]["state"]["next"], 128)
        cut = next(op for op in next(s for s in self.doc["engine"] if s["id"] == "U02-ENG-007")["ops"] if op["op"] == "power_cut")
        self.assertEqual(cut["expect"]["state"]["next"], 64)

    def test_trust_store_pins(self) -> None:
        a, b = mv.PUBS["A"], mv.PUBS["B"]
        self.assertEqual(ref.key_id_of(a), ref.sha256(a)[:8])
        with self.assertRaises(ref.Refusal) as caught:
            ref.TrustStore([(a, False)] * 2)
        self.assertEqual(caught.exception.code, "duplicate_trust_key")
        with self.assertRaises(ref.Refusal) as caught:
            ref.TrustStore([(a, False), (b, False), (mv.PUBS["X"], False), (a, False), (b, False)])
        self.assertEqual(caught.exception.code, "trust_store_full")


class PairedNegativesAndPositives(Base):
    PAIRS = [("U02-ADM-005", "U02-ADM-006"), ("U02-ADM-020", "U02-ADM-023"), ("U02-ADM-024", "U02-ADM-025"), ("U02-ADM-026", "U02-ADM-027"),
             ("U02-ADM-028", "U02-ADM-029"), ("U02-ADM-038", "U02-ADM-039"), ("U02-ADM-052", "U02-ADM-053"), ("U02-ADM-056", "U02-ADM-057"),
             ("U02-ADM-058", "U02-ADM-059"), ("U02-ADM-062", "U02-ADM-063"), ("U02-ADM-064", "U02-ADM-001"), ("U02-ADM-034", "U02-ADM-035"),
             ("U02-ADM-015", "U02-ADM-019"), ("U02-ADM-045", "U02-ADM-044"), ("U02-ADM-046", "U02-ADM-048"), ("U02-ADM-067", "U02-ADM-066"),
             ("U02-ADM-068", "U02-ADM-066"), ("U02-ADM-021", "U02-ADM-023"), ("U02-ADM-022", "U02-ADM-023"), ("U02-ADM-072", "U02-ADM-023"),
             ("U02-ADM-073", "U02-ADM-023"), ("U02-ADM-074", "U02-ADM-023"), ("U02-ADM-076", "U02-ADM-023"), ("U02-ADM-077", "U02-ADM-001"),
             ("U02-ADM-078", "U02-ADM-023")]

    def test_each_refusal_is_paired_with_the_permitted_behaviour_it_must_not_break(self) -> None:
        for refusal, positive in self.PAIRS:
            with self.subTest(refusal=refusal):
                self.assertIn("refuse", self.admit[refusal]["expect"])
                self.assertIn("ok", self.admit[positive]["expect"])

    def test_the_artifact_refusals_sit_beside_the_whole_artifact(self) -> None:
        by = {v["id"]: v["expect"] for v in self.doc["artifact"]}
        self.assertEqual(by["U02-ART-001"], {"ok": "verified"})
        self.assertTrue(all("refuse" in by[i] for i in ("U02-ART-002", "U02-ART-003", "U02-ART-004", "U02-ART-005", "U02-ART-006")))

    def test_every_group_refusal_has_an_admission_beside_it(self) -> None:
        decisions = [v["expect"]["decision"] for v in self.doc["group"]]
        self.assertIn("admit", decisions)
        self.assertIn("refuse", decisions)

    def test_a_refusal_in_a_script_is_followed_by_the_legitimate_operation(self) -> None:
        for sid in ("U02-ENG-002", "U02-ENG-004", "U02-ENG-005", "U02-ENG-006", "U02-ENG-010", "U02-ENG-013", "U02-ENG-014"):
            script = next(s for s in self.doc["engine"] if s["id"] == sid)
            results = [op["expect"]["result"] for op in script["ops"]]
            first = next(i for i, r in enumerate(results) if "refuse" in r)
            self.assertTrue(any("ok" in r for r in results[first + 1:]), f"{sid}: nothing legitimate after the first refusal")


class PlantedDefects(Base):
    def test_the_baseline_is_green_before_any_defect_is_credited(self) -> None:
        self.assertEqual(judge.failing(self.doc), [])
        self.assertEqual(judge.unsound(self.doc), [])

    def test_there_are_50_distinct_planted_defects(self) -> None:
        self.assertEqual((len(ref.BUGS), len(set(ref.BUGS))), (50, 50))

    def test_every_planted_defect_is_caught_by_the_vectors_and_removing_it_restores_green(self) -> None:
        for bug in ref.BUGS:
            if bug in judge.NEEDS_A_CRASH:
                continue
            with self.subTest(bug=bug):
                self.assertTrue(judge.failing(self.doc, frozenset({bug})), f"{bug} was not caught by any vector")
                self.assertEqual(judge.failing(self.doc), [], f"{bug}: the remove-the-plant control is not green")

    def test_every_defect_that_makes_the_model_accept_too_much_is_caught_by_the_properties_alone(self) -> None:
        for bug in ref.BUGS:
            if bug in judge.NEEDS_A_CRASH or bug in judge.OVER_REFUSAL:
                continue
            with self.subTest(bug=bug):
                self.assertTrue(judge.unsound(self.doc, frozenset({bug})), f"{bug} is invisible to the stored-expectation-free properties")
                self.assertEqual(judge.unsound(self.doc), [], f"{bug}: the control is not green")

    def test_the_one_over_refusing_defect_is_caught_by_a_stored_positive(self) -> None:
        self.assertEqual(judge.OVER_REFUSAL, {"backup_ignored"})
        failed = judge.failing(self.doc, frozenset({"backup_ignored"}))
        self.assertTrue({"U02-ADM-039", "U02-RB-002"} <= set(failed), failed)

    def _confirm_with_a_cut(self, bugs: frozenset, fail_after: int) -> ref.Store:
        base = mv.build_ctx(mv.ctx_default())
        store = ref.Store()
        i = mv.INSTALLED
        store.records["u02.inst"] = ref.Installed(i["version"], i["security_version"], i["settings_schema"], i["settings_read_min"], i["calibration_schema"],
                                                  i["wire_schema"], i["wire_read_min"], i["wire_read_max"], i["features"], i["sha"]).pack()
        store.floor = 4
        eng = ref.Engine(store, ref.Staging(1 << 20), bugs)
        eng.begin_stage(base, mv.manifest())
        for n in range(0, len(mv.ART), 16):
            eng.write_chunk(mv.ART[n:n + 16])
        eng.finish_stage()
        eng.activate()
        store.fail_after = fail_after
        try:
            eng.report_boot(True)
        except ref.Crash:
            pass
        return store

    def test_a_cut_in_the_confirm_never_leaves_the_floor_above_the_installed_image(self) -> None:
        for fail_after in (0, 1):
            store = self._confirm_with_a_cut(frozenset(), fail_after)
            installed = ref.unpack_inst(store.records["u02.inst"])
            self.assertLessEqual(store.floor, installed.security_version, f"sound engine, cut after {fail_after} commits")
            self.assertIn((installed.version, store.floor), {(90, 4), (100, 5)}, "exactly the old or exactly the new state")

    def test_the_non_atomic_confirm_is_caught_by_that_cut(self) -> None:
        store = self._confirm_with_a_cut(frozenset({"commit_not_atomic"}), 1)
        installed = ref.unpack_inst(store.records["u02.inst"])
        self.assertGreater(store.floor, installed.security_version, "the floor was raised and the image was not installed")


class RustAgreement(Base):
    def setUp(self) -> None:
        super().setUp()
        self.src = {n: read(CRATE, "src", n) for n in ("lib.rs", "sig.rs", "manifest.rs", "policy.rs", "engine.rs", "group.rs")}

    def test_the_codes_of_the_reference_are_the_codes_of_the_crate(self) -> None:
        listed = set(re.findall(r'^    "([a-z_]+)",$', self.src["lib.rs"].split("pub const ALL_CODES")[1].split("];")[0], re.M))
        arms = set(re.findall(r'=> "([a-z_]+)",', self.src["lib.rs"]))
        self.assertEqual(listed, arms, "every code in the list has an arm in `code()` and the reverse")
        used = set(re.findall(r'Refusal\("([a-z_]+)"\)', read(HERE, "reference.py")))
        self.assertTrue(used - {"mark_regressed", "staging_manifest_mismatch"} <= listed, sorted(used - listed))
        self.assertEqual(listed - used, {"profile_invalid", "isa_unsupported", "corrupt_state"})

    def test_the_constants_agree(self) -> None:
        man, eng, pol = self.src["manifest.rs"], self.src["engine.rs"], self.src["policy.rs"]
        self.assertIn(f"pub const MAX_MANIFEST: usize = {ref.MAX_MANIFEST};", man)
        self.assertIn(f"pub const CHECKPOINT: usize = {ref.CHECKPOINT};", eng)
        self.assertIn(f"pub const TRIAL_BOOTS: u8 = {ref.TRIAL_BOOTS};", eng)
        self.assertIn(f"pub const MAX_KEYS: usize = {ref.MAX_KEYS};", pol)
        self.assertIn('pub const DOMAIN: &[u8] = b"ffw-u02-manifest-v1\\0";', man)
        self.assertIn(f"pub const OPENSSH_FIXED: (u8, u8, u8) = {ref.OPENSSH_FIXED};", man)
        for name, value in (("MAX_PROFILE_ID", ref.MAX_PROFILE_ID), ("MAX_HW_REV", ref.MAX_HW_REV), ("MAX_KERNEL_PROFILE", ref.MAX_KERNEL_PROFILE), ("MAX_LIBC", ref.MAX_LIBC)):
            self.assertIn(f"pub const {name}: usize = {value};", man)
        names = re.findall(r'"([a-z0-9_]+)"', man.split("pub const FEATURES")[1].split("];")[0])
        self.assertEqual(names, list(ref.FEATURES))

    def test_the_confirm_is_one_transaction_and_the_floor_is_raised_nowhere_else(self) -> None:
        eng = self.src["engine.rs"]
        healthy = eng.split("if healthy {")[1].split("return Ok(BootOutcome::Committed);")[0]
        self.assertEqual(healthy.count("self.commit("), 1)
        for part in ("KEY_INSTALLED", "&[KEY_UPDATE]", "Some(u64::from(m.security_version))"):
            self.assertIn(part, healthy)
        self.assertEqual(eng.count("Some(u64::from("), 1, "the only place a floor value is passed to a commit")
        calls = re.findall(r"self\s*\.commit\(", eng) + re.findall(r"engine\s*\.commit\(", eng)
        self.assertEqual(len(calls), len(re.findall(r"(?:self|engine)\s*\.commit\(", eng)))
        nones = len(re.findall(r"None,?\s*\)", eng))
        self.assertGreaterEqual(nones, len(calls) - 1, "every other commit passes no floor")

    def test_the_signature_primitive_is_the_dependency_and_nothing_is_written_here(self) -> None:
        sig = self.src["sig.rs"]
        self.assertIn("use ed25519_dalek::{Signature, VerifyingKey};", sig)
        self.assertIn("verify_strict", sig)
        self.assertIn("is_torsion_free", sig)
        self.assertIn("is_weak", sig)
        crate = "\n".join(self.src.values())
        for word in ("fn fe_", "fn point_add", "scalar_mult", "fn sign(", "hmac", "Hmac", "rand"):
            self.assertNotIn(word, crate, word)
        self.assertIsNone(re.search(r"\bSigningKey\b", crate), "this crate verifies; it holds no signing key type")
        self.assertIn("#![forbid(unsafe_code)]", self.src["lib.rs"])
        self.assertNotIn("unsafe ", crate)
        manifest = read(CRATE, "Cargo.toml")
        self.assertIn("ed25519-dalek.workspace = true", manifest)
        self.assertIn("franken-journal = { path = \"../franken-journal\" }", manifest)
        self.assertNotIn("hmac", manifest)

    def test_the_y_canonical_byte_test_matches_the_definition(self) -> None:
        def canonical(b: bytes) -> bool:
            if b[31] & 0x7F != 0x7F:
                return True
            if any(x != 0xFF for x in b[1:31]):
                return True
            return b[0] < 0xED

        for y in (0, 1, ed.P - 19, ed.P - 1, ed.P, ed.P + 1, ed.P + 18, 2**255 - 1, 2**254, ed.P - 2):
            raw = y.to_bytes(32, "little")
            self.assertEqual(canonical(raw), y < ed.P, y)
            self.assertEqual(canonical(raw[:31] + bytes([raw[31] | 0x80])), y < ed.P, y)
        self.assertIn("bytes[0] < 0xED", self.src["sig.rs"])


    def test_the_rust_sources_have_the_repaired_shape(self) -> None:
        """Text checks only (nothing here compiles the Rust): the places the review found broken are broken in no way a regex can see."""
        eng, grp, man, pol = self.src["engine.rs"], self.src["group.rs"], self.src["manifest.rs"], self.src["policy.rs"]
        opened = eng.split("pub fn open(")[1].split("pub fn into_parts")[0]
        self.assertIn("policy::admit(&engine.policy, &state, &copy)", opened, "a restart admits the stage again")
        self.assertNotIn("verify_signature", opened, "and does not stop at the signature")
        self.assertNotIn("Manifest::parse", opened)
        self.assertIn("wire_read_max", grp.split("pub fn wire_compatible")[1].split("pub fn group_decision")[0], "the window has an upper bound")
        self.assertIn("other.image.is_none()", grp.split("pub fn group_decision")[1], "an unknown image blocks, connected or not")
        target = grp.split("pub fn group_decision")[1].split("let mut unknown")[0]
        self.assertIn("index >= members.len()", target, "a target that names no member is checked before anyone is assessed")
        self.assertIn('code: "invalid_target"', target)
        self.assertIn("|| wire_schema > wire_read_max", man)
        self.assertIn("pub const INSTALLED_LEN: usize = 55;", pol)
        self.assertIn("receipt.digest != ZERO32 && u64::from(receipt.slot_bytes) >= need", pol, "a receipt with no digest never proves A/B")
        self.assertEqual(len(ref.Installed(1, 1, 1, 1, 1, 1, 1, 1, 1, bytes(32)).pack()), 55)
        restart = read(CRATE, "tests", "u02_restart.rs")
        self.assertNotIn("persisted().expect(\"a readable state\")", restart.split("fn cut_every_step")[1].split("fn u02_cut_every_step_of_a_successful")[0],
                         "the crash oracle compares the exact tuple, not the lossy summary")


class ReceiptDigest(Base):
    """A capacity receipt is bound by its digest: ZERO32 means absent, so it proves nothing however large the slot it names."""

    def setUp(self) -> None:
        super().setUp()
        v = self.admit["U02-ADM-060"]
        self.spec, self.raw = v["ctx"], bytes.fromhex(v["manifest"])
        self.need = ref.parse(self.raw)["artifact_size"] + self.spec["reserve"]

    def plan(self, slot: int, digest: bytes, synthetic: bool = False, recovery: bool = True, bugs: frozenset = frozenset()) -> Any:
        receipt = None if slot < 0 else {"slot_bytes": slot, "digest": digest.hex(), "synthetic": synthetic}
        ctx = dict(self.spec, recovery_path=recovery, ab_receipt=receipt)
        got = judge._outcome(lambda: judge._summary(ref.admit(mv.build_ctx(ctx, bugs), self.raw, bugs)))
        return (got["ok"]["mode"], got["ok"]["ab"]) if "ok" in got else got["refuse"]

    def test_only_a_receipt_with_a_digest_and_room_proves_two_slots(self) -> None:
        proven, single = ("ab_slots", "proven_by_external_receipt"), ("single_slot_recovery", "not_proven")
        for digest in (b"\x07" * 32, b"\x01" + bytes(31), bytes(31) + b"\x01"):         # the permitted positives: any digest but zero, exact fit
            self.assertEqual(self.plan(self.need, digest), proven, digest.hex())
        self.assertEqual(self.plan(self.need - 1, b"\x07" * 32), single)
        self.assertEqual(self.plan(-1, bytes(32)), single)
        self.assertEqual(self.plan(2**32 - 1, bytes(32)), single, "no digest, a huge slot: nothing is proven")
        self.assertEqual(self.plan(2**32 - 1, bytes(32), recovery=False), "no_recovery_path")
        for digest in (bytes(32), b"\x07" * 32):
            self.assertEqual(self.plan(self.need, digest, synthetic=True), "synthetic_receipt_for_real_profile")

    def test_the_planted_defect_proves_ab_on_a_receipt_with_no_digest(self) -> None:
        bug = frozenset({"zero_digest_receipt_accepted"})
        self.assertEqual(self.plan(2**32 - 1, bytes(32), bugs=bug), ("ab_slots", "proven_by_external_receipt"))


class EvidenceDigest(Base):
    """In production the manifest's evidence digest must equal the one handed to the device, and zero means none on either side: two zeros are not a match."""

    def verdict(self, raw: bytes, evidence: Any, production: bool = True, board: str = "ppc_policy_standin", bugs: frozenset = frozenset()) -> str:
        ctx = dict(mv.ctx_default(), production=production, board=board, evidence=None if evidence is None else evidence.hex())
        got = judge._outcome(lambda: judge._summary(ref.admit(mv.build_ctx(ctx, bugs), raw, bugs)))
        return "admitted" if "ok" in got else got["refuse"]

    def test_production_matches_only_a_nonzero_digest_that_both_sides_carry(self) -> None:
        none, e = bytes(32), mv.EVIDENCE
        first, last = b"\x01" + bytes(31), bytes(31) + b"\x01"
        for digest in (e, first, last):                                  # the permitted positives: any digest but zero, the same on both sides
            self.assertEqual(self.verdict(mv.manifest(evidence_digest=digest), digest), "admitted", digest.hex())
        for carried, handed in ((none, none), (none, None), (none, e), (e, none), (e, None), (e, first)):
            with self.subTest(carried=carried.hex()[:4], handed=None if handed is None else handed.hex()[:4]):
                self.assertEqual(self.verdict(mv.manifest(evidence_digest=carried), handed), "evidence_mismatch")
        self.assertEqual(self.verdict(mv.manifest(), none, production=False), "admitted", "the evidence is a production gate")

    def test_an_earlier_rule_names_its_own_refusal_and_a_later_one_waits_for_the_evidence(self) -> None:
        none, drop = bytes(32), ref.FEATURES_ALL & ~(1 << ref.FEATURES.index("tailnet_native"))
        self.assertEqual(self.verdict(mv.manifest(), none, board="ppc"), "profile_not_attested")
        self.assertEqual(self.verdict(mv.manifest(signer="X"), none), "unknown_signing_key")
        self.assertEqual(self.verdict(mv.manifest(features=drop), none), "evidence_mismatch")
        self.assertEqual(self.verdict(mv.manifest(features=drop, evidence_digest=mv.EVIDENCE), mv.EVIDENCE), "required_feature_missing")

    def test_the_planted_defect_matches_two_zeros_and_nothing_else_changes(self) -> None:
        bug = frozenset({"zero_evidence_matches"})
        self.assertEqual(self.verdict(mv.manifest(), bytes(32), bugs=bug), "admitted")
        for carried, handed in ((bytes(32), None), (bytes(32), mv.EVIDENCE), (mv.EVIDENCE, bytes(32))):
            self.assertEqual(self.verdict(mv.manifest(evidence_digest=carried), handed, bugs=bug), "evidence_mismatch")

    def test_the_restart_script_drops_the_stage_only_when_production_and_two_zeros_arrive(self) -> None:
        script = next(s for s in self.doc["engine"] if s["id"] == "U02-ENG-030")
        results = [(op["op"], op["expect"]["state"]["phase"]) for op in script["ops"]]
        self.assertEqual(results[-3:], [("finish", "staged"), ("restart_with", "staged"), ("restart_with", "idle")])
        self.assertEqual(script["ctx"]["production"], False)

    def test_the_rust_gate_reads_zero_as_none_before_it_compares(self) -> None:
        pol = read(CRATE, "src", "policy.rs")
        self.assertIn("matches!(policy.evidence, Some(e) if e != ZERO32 && e == m.evidence_digest)", pol)
        self.assertNotIn("policy.evidence != Some(m.evidence_digest)", pol)

    def test_the_real_journal_restart_table_has_the_zero_evidence_case(self) -> None:
        restart = read(CRATE, "tests", "u02_restart.rs")
        case = restart.split("production is turned on with an all-zero evidence digest over an image that names none")[1].split("Case {")[0]
        self.assertIn("p.production = true;", case)
        self.assertIn("p.evidence = Some([0u8; 32]);", case)
        self.assertIn("refusal: UpdateError::EvidenceMismatch", case)


class GroupTarget(Base):
    """`group_decision(members, index, candidate)`: the member that takes the candidate has to exist."""

    def setUp(self) -> None:
        super().setUp()
        v = next(x for x in self.doc["group"] if x["id"] == "U02-GRP-001")
        self.members = [ref.Member(m["id"], judge._image(m["image"]), m["connected"]) for m in v["members"]]
        self.candidate = judge._image(v["candidate"])

    def test_an_index_that_names_no_member_is_invalid_and_every_real_index_is_not(self) -> None:
        for at in range(len(self.members)):                                   # the permitted positive: everyone is compatible, any member may take it
            self.assertEqual(ref.group_decision(self.members, at, self.candidate)["code"], "ok", at)
        nobody = {"decision": "refuse", "code": "invalid_target", "conflicts": [], "assumed": []}
        for members, at in (([], 0), (self.members, len(self.members)), (self.members, 99), (self.members, -1)):
            self.assertEqual(ref.group_decision(members, at, self.candidate), nobody, (len(members), at))
        unheard = self.members + [ref.Member("z", None, True)]                # an unknown peer does not change what a missing target is
        self.assertEqual(ref.group_decision(unheard, 9, self.candidate), nobody)

    def test_the_planted_defect_answers_ok_for_a_member_that_does_not_exist(self) -> None:
        bug = frozenset({"target_unchecked"})
        self.assertEqual(ref.group_decision([], 0, self.candidate, bug)["decision"], "admit")
        self.assertEqual(ref.group_decision(self.members, len(self.members), self.candidate, bug)["decision"], "admit")


class RustInventoryAgrees(Base):
    """`u02_vectors.rs` holds a hand-written inventory of the vector file. The Rust has not been compiled, so the same obligations are run here over the
    committed vectors, and the constants typed in the Rust are compared with the sources they stand for."""

    def setUp(self) -> None:
        super().setUp()
        self.rs = read(CRATE, "tests", "u02_vectors.rs")
        self.lib = read(CRATE, "src", "lib.rs")

    def block(self, opening: str) -> str:
        return self.rs.split(opening)[1].split("];")[0]

    def required(self) -> List[Any]:
        table = self.block("const REQUIRED: &[(&str, &str, &str)] = &[")
        rows = re.findall(r'\(\s*"(U02-[A-Z]+-\d{3})",\s*"([a-z_]+)",\s*"(U02-[A-Z]+-\d{3})",?\s*\)', table)
        self.assertEqual(table.count('"U02-'), 2 * len(rows), "every row of the Rust table was read")
        return rows

    def named(self) -> set:
        def walk(node: Any) -> List[str]:
            if isinstance(node, dict):
                return [x for k, v in node.items() for x in ([v] if k == "refuse" else []) + walk(v)]
            if isinstance(node, list):
                return [x for item in node for x in walk(item)]
            return []
        return set(walk(self.doc))

    def test_every_cited_refusal_is_there_with_its_code_beside_a_permitted_case(self) -> None:
        by_id = {v["id"]: v for group in ("admit", "artifact") for v in self.doc[group]}
        rows = self.required()
        self.assertEqual(len({r for r, _, _ in rows}), len(rows), "a refusal is cited once")
        for refusal, code, positive in rows:
            with self.subTest(refusal=refusal):
                self.assertEqual(by_id[refusal]["expect"], {"refuse": code})
                self.assertIn("ok", by_id[positive]["expect"])

    def test_the_pairs_this_file_pins_are_all_cited_by_the_rust_table(self) -> None:
        cited = {(r, p) for r, _, p in self.required()}
        for pair in PairedNegativesAndPositives.PAIRS:
            self.assertIn(pair, cited)

    def test_the_exempt_codes_the_families_and_the_decisions_are_what_the_sources_say(self) -> None:
        listed = set(re.findall(r'^    "([a-z_]+)",$', self.lib.split("pub const ALL_CODES")[1].split("];")[0], re.M))
        outside = set(re.findall(r'"([a-z_]+)"', self.block("const OUTSIDE_THE_VECTORS: [&str; 4] = [")))
        self.assertTrue(outside <= listed)
        self.assertEqual(self.named(), listed - outside, "every code of the crate is exercised by a vector except the exempt four, and no vector names another")
        decisions = set(re.findall(r'"([a-z_]+)"', self.block("const GROUP_CODES: [&str; 4] = [")))
        self.assertEqual({v["expect"]["code"] for v in self.doc["group"]}, decisions)
        answered = set(re.findall(r'"code": "([a-z_]+)"', read(HERE, "reference.py").split("def group_decision")[1].split("def rollback_decision")[0]))
        self.assertEqual(answered, decisions, "the decisions the reference can give are the ones the Rust inventory lists")
        families = dict(re.findall(r'\("([a-z0-9_]+)", "([A-Z]+)"\)', self.block("const FAMILIES: [(&str, &str); 9] = [")))
        self.assertEqual(sorted(families), sorted(k for k, v in self.doc.items() if isinstance(v, list)))
        for section, family in families.items():
            self.assertTrue(all(re.fullmatch(rf"U02-{family}-\d{{3}}", v["id"]) for v in self.doc[section]), section)

    def test_a_target_other_than_member_0_is_admitted_and_refused_by_some_vector(self) -> None:
        later = [v for v in self.doc["group"] if 0 < v["index"] < len(v["members"])]
        self.assertIn("ok", {v["expect"]["code"] for v in later})
        self.assertIn("wire_incompatible", {v["expect"]["code"] for v in later})


class BoundedRunner(Base):
    """The runner's children go through U01's owned-process primitive: output is capped, the deadline kills the whole process group, and there is no fallback."""

    def setUp(self) -> None:
        super().setUp()
        import e2e
        self.e2e = e2e

    def _dead(self, pid: int) -> bool:
        import subprocess
        import time
        for _ in range(60):
            state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, check=False, timeout=5).stdout.strip()
            if not state or state.startswith("Z"):
                return True
            time.sleep(0.05)
        return False

    def test_a_child_that_ends_normally_returns_decoded_text_and_its_status(self) -> None:
        done = self.e2e.run_bounded([sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"], "a small child")
        self.assertEqual((done.returncode, done.stdout, done.stderr), (3, "out\n", "err\n"))

    def test_a_flood_of_output_is_a_failure_and_never_a_truncation_into_a_pass(self) -> None:
        with self.assertRaisesRegex(AssertionError, "wrote more than"):
            self.e2e.run_bounded([sys.executable, "-c", "import sys\nwhile True: sys.stdout.write('x' * 65536)"], "a flooding child")

    def test_a_child_past_its_deadline_is_killed_with_everything_it_started(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "grandchild.pid")
            code = ("import subprocess, sys, time\n"
                    "g = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
                    f"open({marker!r}, 'w').write(str(g.pid))\n"
                    "time.sleep(120)\n")
            with self.assertRaisesRegex(AssertionError, "timed out"):
                self.e2e.run_bounded([sys.executable, "-c", code], "a child that never ends", timeout=2)
            with open(marker, encoding="utf-8") as f:
                pid = int(f.read())
        self.assertTrue(self._dead(pid), "the grandchild outlived the deadline of its parent")

    def test_the_runner_never_falls_back_to_an_unbounded_one(self) -> None:
        source = read(HERE, "e2e.py")
        self.assertNotIn("subprocess.run(", source)
        self.assertNotIn("capture_output", source)
        saved = self.e2e._U01_E2E
        self.e2e._U01_E2E = os.path.join(REPO, "tests", "u01", "this_file_does_not_exist.py")
        try:
            with self.assertRaises((AssertionError, OSError)):
                self.e2e.run_bounded([sys.executable, "-c", "print('must not run')"], "a child without its primitive")
        finally:
            self.e2e._U01_E2E = saved


class Contract(Base):
    def setUp(self) -> None:
        super().setUp()
        self.text = read(CONTRACT)

    def test_it_states_the_counts_the_sources_have(self) -> None:
        self.assertIn("198 cases: 15 signature, 12 key, 9 trust-store, 23 parse, 80 admission, 6 artifact, 30 engine scripts, 18 group, 5 rollback", self.text)
        self.assertIn("**50 planted defects**", self.text)
        vec, rst = rust_tests(os.path.join(CRATE, "tests", "u02_vectors.rs")), rust_tests(os.path.join(CRATE, "tests", "u02_restart.rs"))
        self.assertIn(f"u02_vectors.rs` ({len(vec)} tests)", self.text)
        self.assertIn(f"u02_restart.rs` ({len(rst)} tests)", self.text)

    def test_every_case_it_cites_exists(self) -> None:
        ids = {v["id"] for group in ("admit", "artifact", "ed25519", "engine", "group", "keys_check", "parse", "rollback", "trust") for v in self.doc[group]}
        for family, first, tail in re.findall(r"U02-([A-Z]+)-(\d+)((?:\.\.\d+|/\d+)*)", self.text):
            numbers = [int(first)] + [int(n) for n in re.findall(r"/(\d+)", tail)]
            for rng in re.findall(r"\.\.(\d+)", tail):
                numbers += list(range(int(first), int(rng) + 1))
            for n in numbers:
                self.assertIn(f"U02-{family}-{n:03d}", ids, f"the contract cites U02-{family}-{n:03d}")

    def test_every_test_it_names_exists(self) -> None:
        names = set(rust_tests(os.path.join(CRATE, "tests", "u02_vectors.rs"))) | set(rust_tests(os.path.join(CRATE, "tests", "u02_restart.rs")))
        for named in re.findall(r"`(u02_[a-z0-9_]+)`", self.text):
            self.assertIn(named, names, named)

    def test_it_does_not_claim_what_it_does_not_have(self) -> None:
        for phrase in ("Not a claim of A/B capacity", "Not a vendor acceptance claim and not a bypass", "No SSH server exists in the current", "**Not claimed:**",
                       "Rust crate has not been compiled or run", "a test oracle only and ships nowhere"):
            self.assertIn(phrase, self.text)


if __name__ == "__main__":
    unittest.main()
