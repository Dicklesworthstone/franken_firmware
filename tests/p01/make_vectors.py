#!/usr/bin/env python3
"""Write (or check) the shared P01 contract vectors.

    make_vectors.py            rewrite crates/franken-board-profile/tests/vectors/p01_contract_vectors.json
    make_vectors.py --check    exit 1 if the committed file differs from what this script writes

The vectors are replayed by the Rust test crates/franken-board-profile/tests/p01_contract.rs (central
verification) and by tests/p01/run_cases.py (host). The EXPECTED values below are written by hand from the
rules in docs/contracts/p01.md; nothing here asks either implementation what the answer is. Only digests of
the base contract (and of a mutated copy, where a vector checks receipt identity) are computed, because a
digest is not something to type by hand.
"""
from __future__ import annotations

import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import reference as ref  # noqa: E402

VECTORS_DIR = os.path.join(REPO, "crates", "franken-board-profile", "tests", "vectors")
BASE_FILE = os.path.join(VECTORS_DIR, "p01_workspace_contract.json")
OUT_FILE = os.path.join(VECTORS_DIR, "p01_contract_vectors.json")
SCHEMA = "ffw.p01.vectors.v1"

H1 = "a1" * 32
H2 = "b2" * 32
H3 = "c3" * 32
H4 = "d4" * 32
BAD = "zz"

REQUIRED = ["airplay2", "alexa_bridge", "protected_render", "spotify_connect", "synchronized_groups",
            "tailnet_native"]
EVIDENCE = {"protected_render": "physical_output", "synchronized_groups": "physical_output",
            "spotify_connect": "real_service", "airplay2": "real_service", "tailnet_native": "real_service",
            "alexa_bridge": "real_service"}
PPC_FULL = "speaker-ppc-full"


def S(path, value):
    return {"op": "set", "path": path, "value": value}


def R(path):
    return {"op": "remove", "path": path}


def P(path, value):
    return {"op": "push", "path": path, "value": value}


def art(aid, tail):
    return f"/artifacts/id={aid}/{tail}"


def qual(feature, sha, target, profile, kind=None, receipt=None):
    return {"feature": feature,
            "evidence": {"kind": kind or EVIDENCE[feature], "artifact_sha256": sha, "target": target,
                         "profile": profile, "receipt_id": receipt if receipt is not None else f"rcpt-{feature}"}}


def qualify_ppc_full(sha=H1, with_sha=True):
    """Every required feature of speaker-ppc-full qualified with correctly bound evidence."""
    ops = [S(art(PPC_FULL, "sha256"), sha)] if with_sha else []
    for feature in REQUIRED:
        ops.append(P(art(PPC_FULL, "qualifications"), qual(feature, sha, "powerpc_be", "full_native")))
    return ops


def qual_path(feature, tail):
    return art(PPC_FULL, f"qualifications/feature={feature}/{tail}")


def validate(vid, title, ops, codes, subjects=None, admission=None):
    v = {"id": vid, "title": title, "kind": "validate", "ops": ops, "expect_codes": codes}
    if subjects is not None:
        v["expect_subjects"] = subjects
    if admission is not None:
        v["expect_admission"] = admission
    return v


def parse(vid, title, ops):
    return {"id": vid, "title": title, "kind": "parse", "ops": ops, "expect_codes": ["parse_error"]}


def admit(vid, title, ops, artifact, qualified, blocks):
    return {"id": vid, "title": title, "kind": "admission", "ops": ops, "artifact": artifact,
            "expect": {"qualified": qualified, "blocks": blocks}}


def observed(vid, title, ops, rows, codes, subjects=None, require_all=False):
    v = {"id": vid, "title": title, "kind": "observed", "ops": ops, "rows": copy.deepcopy(rows),
         "require_all": require_all,
         "expect_codes": codes}
    if subjects is not None:
        v["expect_subjects"] = subjects
    return v


def build(base):
    base_digest = ref.digest(base)

    def row(aid, target, profile, sha, machine=None, klass=1, be=True, digest=None, triple=None):
        triple_ = {"host": "host", "mips_be": "mips-unknown-linux-musl",
                   "powerpc_be": "powerpc-unknown-linux-musl"}[target]
        machine_ = {"host": 0, "mips_be": 8, "powerpc_be": 20}[target]
        return {"id": aid, "target": target, "triple": triple or triple_, "profile": profile, "sha256": sha,
                "elf_machine": machine_ if machine is None else machine, "elf_class": klass,
                "elf_big_endian": be, "contract_digest": digest or base_digest}

    mips = row("speaker-mips-full", "mips_be", "full_native", H3)
    ppc = row(PPC_FULL, "powerpc_be", "full_native", H4)

    v: list = []
    # --- baseline and digest
    v.append(validate("P01-V-001", "the declared workspace contract is valid", [], []))
    v.append({"id": "P01-V-002", "title": "the contract digest is the pinned canonical-JSON SHA-256",
              "kind": "digest", "ops": [], "expect_digest": base_digest})
    v.append({"id": "P01-V-003", "title": "changing one field changes the digest", "kind": "digest",
              "ops": [S(art("speaker-host-full", "sha256"), H1)], "expect_changed": True})
    v.append(admit("P01-V-004", "a full-native speaker with no evidence is not qualified, every required feature named",
                   [], PPC_FULL, False,
                   ["required_feature_unqualified:" + f for f in REQUIRED]))
    v.append(admit("P01-V-005", "the minimal renderer cannot be qualified: disabled required features stay blocked",
                   [], "speaker-ppc-min", False,
                   ["required_feature_disabled:airplay2", "required_feature_disabled:alexa_bridge",
                    "required_feature_disabled:spotify_connect", "required_feature_disabled:tailnet_native",
                    "required_feature_unqualified:protected_render",
                    "required_feature_unqualified:synchronized_groups"]))
    v.append(admit("P01-V-006", "the bootstrap probe is never a qualified product artifact", [],
                   "hello-init-ppc", False, ["required_feature_disabled:" + f for f in REQUIRED]))
    v.append(validate("P01-V-007", "permitted positive: every required feature qualified with bound evidence",
                      qualify_ppc_full() + [S(art(PPC_FULL, "status"), "qualified")], [],
                      admission={"artifact": PPC_FULL, "qualified": True, "blocks": []}))
    v.append(validate("P01-V-008", "permitted positive: an optional feature may be qualified by a host simulation",
                      [S(art(PPC_FULL, "sha256"), H1),
                       P(art(PPC_FULL, "qualifications"),
                         qual("artwork", H1, "powerpc_be", "full_native", kind="host_simulation"))], []))

    # --- distinct ISA artifacts, no universal claim
    v.append(validate("P01-V-010", "a PowerPC artifact marked MIPS is refused",
                      [S(art(PPC_FULL, "isa"), "mips32_be")], ["isa_target_mismatch"],
                      {"isa_target_mismatch": [PPC_FULL]}))
    v.append(validate("P01-V-011", "a PowerPC artifact carrying the MIPS triple is refused",
                      [S(art(PPC_FULL, "triple"), "mips-unknown-linux-musl")], ["triple_target_mismatch"],
                      {"triple_target_mismatch": [PPC_FULL]}))
    v.append(validate("P01-V-012", "an artifact claiming to run on PowerPC and MIPS is refused",
                      [P(art(PPC_FULL, "runs_on"), "mips_be")], ["universal_artifact_claim"],
                      {"universal_artifact_claim": [PPC_FULL]}))
    v.append(validate("P01-V-013", "an artifact that runs on nothing is refused",
                      [S(art(PPC_FULL, "runs_on"), [])], ["universal_artifact_claim"]))
    v.append(parse("P01-V-014", "an ARM target does not parse: no ARM artifact is admitted",
                   [S(art(PPC_FULL, "target"), "arm_le")]))
    v.append(validate("P01-V-015", "an ARM triple on a PowerPC artifact is refused",
                      [S(art(PPC_FULL, "triple"), "arm-unknown-linux-gnueabihf")], ["triple_target_mismatch"]))
    v.append(validate("P01-V-016", "a host artifact declaring a device ISA is refused",
                      [S(art("speaker-host-full", "isa"), "powerpc32_be")], ["isa_target_mismatch"],
                      {"isa_target_mismatch": ["speaker-host-full"]}))
    v.append(validate("P01-V-017", "a malformed artifact digest is refused",
                      [S(art("speaker-mips-full", "sha256"), BAD)], ["bad_digest"],
                      {"bad_digest": ["speaker-mips-full"]}))
    v.append(validate("P01-V-018", "two artifacts with one id are refused",
                      [S(art("speaker-ppc-min", "id"), PPC_FULL)], ["duplicate_artifact"],
                      {"duplicate_artifact": [PPC_FULL]}))
    v.append(validate("P01-V-019", "two artifacts with one crate, target and profile are refused",
                      [S(art("speaker-ppc-min", "profile"), "full_native")], ["duplicate_artifact"],
                      {"duplicate_artifact": ["franken-speaker/powerpc_be/full_native"]}))
    v.append(validate("P01-V-020", "an artifact of an unknown crate is refused",
                      [S(art("speaker-host-full", "crate"), "franken-ghost")], ["unknown_artifact_crate"]))
    v.append(validate("P01-V-021", "an artifact of an unknown profile is refused",
                      [S(art("speaker-host-full", "profile"), "turbo")], ["unknown_profile"]))
    v.append(validate("P01-V-022", "an excluded crate may only produce artifacts for the targets it declares",
                      [S("/excluded/name=ffw-hello-init/targets", ["mips_be"])], ["artifact_target_not_declared"],
                      {"artifact_target_not_declared": ["hello-init-ppc"]}))
    v.append(validate("P01-V-023", "a device artifact built without panic = abort is refused",
                      [S("/cargo_profiles/name=release/panic", "unwind")], ["device_profile_not_abort"],
                      {"device_profile_not_abort": ["speaker-mips-full", "speaker-mips-min",
                                                    "speaker-ppc-full", "speaker-ppc-min"]}))
    v.append(validate("P01-V-024", "the bootstrap probe is held to panic = abort too",
                      [S("/cargo_profiles/name=bootstrap_release/panic", "unwind")],
                      ["device_profile_not_abort"],
                      {"device_profile_not_abort": ["hello-init-mips", "hello-init-ppc"]}))

    # --- the crate graph
    v.append(validate("P01-V-030", "a crate depending on itself is refused",
                      [P("/crates/name=franken-hal/deps", "franken-hal")], ["self_dependency"],
                      {"self_dependency": ["franken-hal"]}))
    v.append(validate("P01-V-031", "a dependency on a non-member is refused",
                      [P("/crates/name=franken-hal/deps", "franken-ghost")], ["unknown_dependency"],
                      {"unknown_dependency": ["franken-hal->franken-ghost"]}))
    v.append(validate("P01-V-032", "a two-crate dependency cycle is detected",
                      [P("/crates/name=franken-board-profile/deps", "franken-hal")],
                      ["dependency_cycle", "layer_violation"],
                      {"dependency_cycle": ["franken-board-profile,franken-hal"],
                       "layer_violation": ["franken-board-profile->franken-hal"]}))
    v.append(validate("P01-V-033", "a cycle that exists only through a dev-dependency is detected",
                      [P("/crates/name=franken-board-profile/dev_deps", "franken-hal")],
                      ["dev_dependency_cycle"],
                      {"dev_dependency_cycle": ["franken-board-profile,franken-hal"]}))
    v.append(validate("P01-V-034", "a normal dependency onto a higher layer is refused even without a cycle",
                      [P("/crates/name=franken-hal/deps", "franken-clock")], ["layer_violation"],
                      {"layer_violation": ["franken-hal->franken-clock"]}))
    v.append(validate("P01-V-035", "a three-crate cycle is reported once with its members",
                      [P("/crates/name=franken-clock/deps", "franken-stream"),
                       P("/crates/name=franken-dsp/deps", "franken-clock")],
                      ["dependency_cycle", "layer_violation"],
                      {"dependency_cycle": ["franken-clock,franken-dsp,franken-stream"],
                       "layer_violation": ["franken-clock->franken-stream", "franken-dsp->franken-clock"]}))

    # --- single ownership
    v.append(validate("P01-V-040", "a crate with an empty owner is refused",
                      [S("/crates/name=franken-hal/owner", "")], ["asset_owner_mismatch", "owner_missing"],
                      {"owner_missing": ["franken-hal"]}))
    v.append(validate("P01-V-041", "a crate with no ownership entry is refused",
                      [R("/assets/path=crates~1franken-hal")], ["asset_unowned"],
                      {"asset_unowned": ["franken-hal"]}))
    v.append(validate("P01-V-042", "one path with two different owners is refused",
                      [P("/assets", {"path": "crates/franken-hal", "owner": "ZZ9", "kind": "crate"})],
                      ["asset_conflicting_owners"], {"asset_conflicting_owners": ["crates/franken-hal"]}))
    v.append(validate("P01-V-043", "one path listed twice is refused",
                      [P("/assets", {"path": "crates/franken-hal", "owner": "E04", "kind": "crate"})],
                      ["asset_duplicate"], {"asset_duplicate": ["crates/franken-hal"]}))
    v.append(validate("P01-V-044", "an ownership entry that disagrees with the crate record is refused",
                      [S("/assets/path=crates~1franken-hal/owner", "E99")], ["asset_owner_mismatch"],
                      {"asset_owner_mismatch": ["franken-hal"]}))
    v.append(validate("P01-V-045", "a test fixture with an empty owner is refused",
                      [S("/assets/path=tests~1d01/owner", "")], ["owner_missing"],
                      {"owner_missing": ["tests/d01"]}))
    v.append(validate("P01-V-046", "scoped unsafe is refused for a library, and for anything a device image contains",
                      [S("/crates/name=franken-dsp/unsafe_policy", "deny_with_scoped_allow")],
                      ["unsafe_in_device_closure", "unsafe_policy_not_permitted"],
                      {"unsafe_in_device_closure": ["speaker-mips-full:franken-dsp", "speaker-mips-min:franken-dsp",
                                                    "speaker-ppc-full:franken-dsp", "speaker-ppc-min:franken-dsp"],
                       "unsafe_policy_not_permitted": ["franken-dsp"]}))
    v.append(validate("P01-V-047", "the bootstrap-probe policy is refused for a workspace crate",
                      [S("/crates/name=franken-hal/unsafe_policy", "bootstrap_probe")],
                      ["unsafe_policy_not_permitted"], {"unsafe_policy_not_permitted": ["franken-hal"]}))
    v.append(validate("P01-V-048", "an excluded crate must declare the bootstrap-probe policy",
                      [S("/excluded/name=ffw-hello-init/unsafe_policy", "forbid")],
                      ["unsafe_policy_not_permitted"], {"unsafe_policy_not_permitted": ["ffw-hello-init"]}))
    v.append(validate("P01-V-049", "a pending member that reuses a member's name is refused",
                      [P("/pending_members", {"name": "franken-hal", "path": "crates/franken-baseline",
                                              "owner": "E02", "reason": "root edit pending"})],
                      ["duplicate_crate"], {"duplicate_crate": ["franken-hal"]}))

    # --- required versus optional features
    v.append(validate("P01-V-050", "a required feature cannot be removed by omitting it from a profile",
                      [R("/profiles/name=full_native/features/feature=tailnet_native")],
                      ["required_feature_missing"], {"required_feature_missing": ["full_native:tailnet_native"]},
                      admission=None))
    v.append(validate("P01-V-051", "a full-product profile cannot disable a required feature",
                      [S("/profiles/name=full_native/features/feature=tailnet_native/state", "disabled"),
                       S("/profiles/name=full_native/features/feature=tailnet_native/disabled_reason",
                         "temporarily off")],
                      ["full_profile_disables_required"],
                      {"full_profile_disables_required": ["full_native:tailnet_native"]}))
    v.append(validate("P01-V-052", "disabling a required feature with no reason is refused twice over",
                      [S("/profiles/name=full_native/features/feature=tailnet_native/state", "disabled")],
                      ["disabled_without_reason", "full_profile_disables_required"]))
    v.append(validate("P01-V-053", "a narrow profile must say why it is narrow",
                      [S("/profiles/name=minimal_renderer/narrow_reason", "")],
                      ["narrow_profile_without_reason"],
                      {"narrow_profile_without_reason": ["minimal_renderer"]}))
    v.append(validate("P01-V-054", "a selection of a feature outside the registry is refused",
                      [P("/profiles/name=full_native/features",
                         {"feature": "teleport", "state": "enabled", "disabled_reason": ""})],
                      ["unknown_feature"], {"unknown_feature": ["full_native:teleport"]}))
    v.append(validate("P01-V-055", "selecting a feature twice in one profile is refused",
                      [P("/profiles/name=full_native/features",
                         {"feature": "artwork", "state": "enabled", "disabled_reason": ""})],
                      ["duplicate_feature_selection"],
                      {"duplicate_feature_selection": ["full_native:artwork"]}))
    v.append(validate("P01-V-056", "permitted positive: an optional feature may be disabled, with a reason",
                      [S("/profiles/name=full_native/features/feature=artwork/state", "disabled"),
                       S("/profiles/name=full_native/features/feature=artwork/disabled_reason",
                         "artwork is optional and omitted in this build")], []))
    v.append(validate("P01-V-057", "a native service depending on another native service is refused",
                      [S("/features/name=airplay2/requires", ["protected_render", "spotify_connect"])],
                      ["native_feature_requires_native"],
                      {"native_feature_requires_native": ["airplay2->spotify_connect"]}))
    v.append(validate("P01-V-058", "the minimal renderer depending on a native service is refused",
                      [S("/features/name=synchronized_groups/requires", ["protected_render", "tailnet_native"])],
                      ["core_feature_requires_native"],
                      {"core_feature_requires_native": ["synchronized_groups->tailnet_native"]}))
    v.append(validate("P01-V-059", "a feature requirement cycle is detected",
                      [S("/features/name=protected_render/requires", ["synchronized_groups"])],
                      ["feature_cycle"], {"feature_cycle": ["protected_render,synchronized_groups"]}))
    v.append(validate("P01-V-060", "a feature requiring itself is refused",
                      [S("/features/name=artwork/requires", ["artwork"])], ["feature_cycle"],
                      {"feature_cycle": ["artwork"]}))
    v.append(validate("P01-V-061", "a requirement on a feature outside the registry is refused",
                      [S("/features/name=artwork/requires", ["ghost"])], ["unknown_feature"],
                      {"unknown_feature": ["artwork->ghost"]}))
    v.append(validate("P01-V-062", "a feature owned by a non-member crate is refused",
                      [S("/features/name=artwork/owner_crate", "franken-ghost")], ["feature_owner_unknown"],
                      {"feature_owner_unknown": ["artwork"]}))
    v.append(validate("P01-V-063", "a feature that names no qualifying evidence kind is refused",
                      [S("/features/name=artwork/accepted_evidence", [])], ["evidence_policy_empty"],
                      {"evidence_policy_empty": ["artwork"]}))
    v.append(validate("P01-V-064", "a feature listed twice in the registry is refused",
                      [P("/features", copy.deepcopy(next(f for f in base["features"] if f["name"] == "artwork")))],
                      ["duplicate_feature"], {"duplicate_feature": ["artwork"]}))
    v.append(validate("P01-V-065", "a profile naming an undeclared cargo profile is refused",
                      [S("/profiles/name=full_native/cargo_profile", "turbo")], ["unknown_cargo_profile"],
                      {"unknown_cargo_profile": ["full_native"]}))
    v.append(validate("P01-V-066", "a cargo profile listed twice is refused",
                      [P("/cargo_profiles", copy.deepcopy(next(c for c in base["cargo_profiles"] if c["name"] == "release")))],
                      ["duplicate_cargo_profile"], {"duplicate_cargo_profile": ["release"]}))
    v.append(validate("P01-V-067", "a build profile listed twice is refused",
                      [P("/profiles", copy.deepcopy(next(p for p in base["profiles"] if p["name"] == "bootstrap_probe")))],
                      ["duplicate_profile"], {"duplicate_profile": ["bootstrap_probe"]}))

    # --- disabled required features can never become qualified; evidence is bound to identity
    v.append(validate("P01-V-070", "evidence on a feature the profile disables is refused",
                      [S(art("speaker-ppc-min", "sha256"), H2),
                       P(art("speaker-ppc-min", "qualifications"),
                         qual("spotify_connect", H2, "powerpc_be", "minimal_renderer"))],
                      ["qualified_while_disabled"],
                      {"qualified_while_disabled": ["speaker-ppc-min:spotify_connect"]}))
    v.append(admit("P01-V-071", "even with evidence attached, a disabled required feature still blocks admission",
                   [S(art("speaker-ppc-min", "sha256"), H2),
                    P(art("speaker-ppc-min", "qualifications"),
                      qual("spotify_connect", H2, "powerpc_be", "minimal_renderer"))],
                   "speaker-ppc-min", False,
                   ["required_feature_disabled:airplay2", "required_feature_disabled:alexa_bridge",
                    "required_feature_disabled:spotify_connect", "required_feature_disabled:tailnet_native",
                    "required_feature_unqualified:protected_render",
                    "required_feature_unqualified:synchronized_groups"]))
    v.append(validate("P01-V-072", "asserting 'qualified' while required features are disabled is refused",
                      [S(art("speaker-ppc-min", "status"), "qualified")], ["qualification_not_supported"],
                      {"qualification_not_supported": ["speaker-ppc-min"]}))
    v.append(validate("P01-V-073", "asserting 'qualified' with no evidence at all is refused",
                      [S(art("speaker-mips-full", "status"), "qualified")], ["qualification_not_supported"],
                      {"qualification_not_supported": ["speaker-mips-full"]}))
    v.append(validate("P01-V-074", "evidence gathered for another artifact digest is stale",
                      qualify_ppc_full() + [S(qual_path("alexa_bridge", "evidence/artifact_sha256"), H2)],
                      ["stale_evidence"], {"stale_evidence": [PPC_FULL + ":alexa_bridge"]}))
    v.append(validate("P01-V-075", "evidence gathered for another target is stale",
                      qualify_ppc_full() + [S(qual_path("alexa_bridge", "evidence/target"), "mips_be")],
                      ["stale_evidence"]))
    v.append(validate("P01-V-076", "evidence gathered for another profile is stale",
                      qualify_ppc_full() + [S(qual_path("alexa_bridge", "evidence/profile"), "minimal_renderer")],
                      ["stale_evidence"]))
    v.append(validate("P01-V-077", "evidence cannot bind to an artifact whose digest is not yet known",
                      qualify_ppc_full(with_sha=False), ["stale_evidence"],
                      {"stale_evidence": [PPC_FULL + ":" + f for f in REQUIRED]}))
    v.append(validate("P01-V-078", "a host simulation cannot qualify a native service",
                      qualify_ppc_full() + [S(qual_path("spotify_connect", "evidence/kind"), "host_simulation")],
                      ["evidence_kind_insufficient"],
                      {"evidence_kind_insufficient": [PPC_FULL + ":spotify_connect"]},
                      admission={"artifact": PPC_FULL, "qualified": False,
                                 "blocks": ["evidence_kind_insufficient:spotify_connect"]}))
    v.append(validate("P01-V-079", "evidence that cites no receipt is refused",
                      qualify_ppc_full() + [S(qual_path("protected_render", "evidence/receipt_id"), "")],
                      ["evidence_receipt_missing"],
                      {"evidence_receipt_missing": [PPC_FULL + ":protected_render"]}))
    v.append(validate("P01-V-080", "a qualification for a feature outside the registry is refused",
                      [S(art(PPC_FULL, "sha256"), H1),
                       P(art(PPC_FULL, "qualifications"), qual("teleport", H1, "powerpc_be", "full_native",
                                                               kind="host_simulation"))],
                      ["unknown_feature"], {"unknown_feature": [PPC_FULL + ":teleport"]}))
    v.append(admit("P01-V-081", "stale evidence blocks admission by name",
                   qualify_ppc_full() + [S(qual_path("tailnet_native", "evidence/profile"), "minimal_renderer")],
                   PPC_FULL, False, ["stale_evidence:tailnet_native"]))

    # --- test-only and host-only code stays out of device images
    HARNESS = "/profiles/name=full_native/features/feature=virtual_house_harness/state"
    v.append(validate("P01-V-089", "permitted positive: a counted exception covers a test-only crate that a device profile enables",
                      [S(HARNESS, "enabled"),
                       P("/test_support_exceptions", {"from": "franken-speaker", "to": "franken-test-support",
                                                      "reason": "harness build for a hardware-in-the-loop rig"})],
                      []))
    v.append(validate("P01-V-090", "enabling the harness in a device profile puts a test-only crate in the image",
                      [S(HARNESS, "enabled")], ["test_support_in_device_closure"],
                      {"test_support_in_device_closure": ["speaker-mips-full:franken-test-support",
                                                          "speaker-ppc-full:franken-test-support"]}))
    v.append(validate("P01-V-091", "an exception that names no test-support edge is stale",
                      [P("/test_support_exceptions", {"from": "franken-speaker", "to": "franken-hal", "reason": "x"})],
                      ["stale_exception"], {"stale_exception": ["franken-speaker->franken-hal"]}))
    v.append(validate("P01-V-092", "an exception with no reason is refused",
                      [P("/test_support_exceptions", {"from": "franken-speaker", "to": "franken-test-support",
                                                      "reason": ""})],
                      ["exception_without_reason"],
                      {"exception_without_reason": ["franken-speaker->franken-test-support"]}))
    v.append(validate("P01-V-093", "a host tool in a device closure is refused",
                      [P("/crates/name=franken-speaker/deps", "franken-alloc-probe")],
                      ["host_tool_in_device_closure", "layer_violation", "unsafe_in_device_closure"],
                      {"host_tool_in_device_closure": [
                          "speaker-mips-full:franken-alloc-probe", "speaker-mips-min:franken-alloc-probe",
                          "speaker-ppc-full:franken-alloc-probe", "speaker-ppc-min:franken-alloc-probe"],
                       "layer_violation": ["franken-speaker->franken-alloc-probe"]}))

    # --- a dependency that exists only under a feature
    GATE = "/crates/name=franken-speaker/optional_deps"
    v.append(validate("P01-V-094", "an optional dependency gated by a feature with no Cargo flag is refused",
                      [S("/features/name=virtual_house_harness/cargo_feature", "")], ["optional_dep_without_flag"],
                      {"optional_dep_without_flag": ["franken-speaker->franken-test-support"]}))
    v.append(validate("P01-V-095", "the gating flag must belong to the crate that carries the dependency",
                      [S("/features/name=virtual_house_harness/owner_crate", "franken-control")],
                      ["optional_dep_wrong_owner"],
                      {"optional_dep_wrong_owner": ["franken-speaker->franken-test-support"]}))
    v.append(validate("P01-V-096", "an optional dependency gated by an unknown feature is refused",
                      [S(GATE, [{"dep": "franken-test-support", "feature": "ghost"}])], ["unknown_feature"],
                      {"unknown_feature": ["franken-speaker->franken-test-support"]}))
    v.append(validate("P01-V-097", "an optional dependency on a non-member is refused",
                      [P(GATE, {"dep": "franken-ghost", "feature": "virtual_house_harness"})],
                      ["unknown_dependency"], {"unknown_dependency": ["franken-speaker->franken-ghost"]}))
    v.append(validate("P01-V-098", "an optional dependency onto a higher layer is refused like any normal edge",
                      [P(GATE, {"dep": "franken-alloc-probe", "feature": "virtual_house_harness"})],
                      ["layer_violation"], {"layer_violation": ["franken-speaker->franken-alloc-probe"]}))
    v.append(validate("P01-V-099", "an optional edge takes part in cycle detection",
                      [P("/crates/name=franken-hal/optional_deps",
                         {"dep": "franken-speaker", "feature": "virtual_house_harness"})],
                      ["dependency_cycle", "layer_violation", "optional_dep_wrong_owner"],
                      {"dependency_cycle": ["franken-hal,franken-speaker"],
                       "layer_violation": ["franken-hal->franken-speaker"],
                       "optional_dep_wrong_owner": ["franken-hal->franken-speaker"]}))

    # --- schema
    v.append(validate("P01-V-100", "a different schema version is refused",
                      [S("/schema_version", "ffw.build_contract.v0")], ["schema_version_mismatch"]))
    v.append(parse("P01-V-101", "an unknown field is not tolerated",
                   [S(art("speaker-host-full", "extra"), 1)]))
    v.append(parse("P01-V-102", "a missing field is not defaulted",
                   [R(art("speaker-host-full", "sha256"))]))
    v.append(parse("P01-V-103", "a field of the wrong type is not coerced",
                   [S("/crates/name=franken-hal/layer", "four")]))
    v.append(parse("P01-V-104", "an unknown enum value is not accepted",
                   [S("/crates/name=franken-hal/role", "firmware")]))

    # --- exact artifact identity in a receipt
    v.append(observed("P01-O-001", "permitted positive: distinct, correctly identified device artifacts",
                      [], [mips, ppc], []))
    v.append(observed("P01-O-002", "a PowerPC artifact whose ELF says MIPS is refused", [],
                      [mips, row(PPC_FULL, "powerpc_be", "full_native", H4, machine=8)],
                      ["elf_machine_mismatch"], {"elf_machine_mismatch": [PPC_FULL]}))
    v.append(observed("P01-O-003", "a little-endian device ELF is refused", [],
                      [row("speaker-mips-full", "mips_be", "full_native", H3, be=False)],
                      ["elf_not_32bit_big_endian"]))
    v.append(observed("P01-O-004", "a 64-bit device ELF is refused", [],
                      [row("speaker-mips-full", "mips_be", "full_native", H3, klass=2)],
                      ["elf_not_32bit_big_endian"]))
    v.append(observed("P01-O-005", "one digest reported for both PowerPC and MIPS is a universal claim", [],
                      [mips, row(PPC_FULL, "powerpc_be", "full_native", H3)],
                      ["universal_artifact_claim"], {"universal_artifact_claim": [H3]}))
    v.append(observed("P01-O-006", "an artifact the contract does not declare is refused", [],
                      [row("speaker-sparc-full", "mips_be", "full_native", H3)], ["unknown_artifact"],
                      {"unknown_artifact": ["speaker-sparc-full"]}))
    v.append(observed("P01-O-007", "a receipt produced against another contract is refused", [],
                      [row("speaker-mips-full", "mips_be", "full_native", H3, digest="0" * 64)],
                      ["contract_digest_mismatch"]))
    v.append(observed("P01-O-008", "an observed target that differs from the declaration is refused", [],
                      [row(PPC_FULL, "mips_be", "full_native", H4, triple="powerpc-unknown-linux-musl",
                           machine=20)],
                      ["observed_target_mismatch"]))
    v.append(observed("P01-O-009", "an observed profile that differs from the declaration is refused", [],
                      [row("speaker-mips-full", "mips_be", "minimal_renderer", H3)],
                      ["observed_profile_mismatch"]))
    v.append(observed("P01-O-010", "one artifact id reported with two digests is refused", [],
                      [mips, row("speaker-mips-full", "mips_be", "full_native", H4)],
                      ["artifact_digest_conflict"], {"artifact_digest_conflict": ["speaker-mips-full"]}))
    v.append(observed("P01-O-011", "with require_all, every declared artifact must be observed", [], [mips],
                      ["artifact_not_observed"],
                      {"artifact_not_observed": ["hello-init-mips", "hello-init-ppc", "speaker-host-full",
                                                 "speaker-mips-min", "speaker-ppc-full", "speaker-ppc-min"]},
                      require_all=True))
    v.append(observed("P01-O-012", "a malformed observed digest is refused", [],
                      [row("speaker-mips-full", "mips_be", "full_native", BAD)], ["bad_digest"]))
    v.append(observed("P01-O-013", "an observed digest that differs from the digest the contract records is refused",
                      [S(art("speaker-mips-full", "sha256"), H1)], [mips], ["observed_digest_mismatch"]))
    v.append(observed("P01-O-014", "an observed triple that differs from the declaration is refused", [],
                      [row(PPC_FULL, "powerpc_be", "full_native", H4, triple="mips-unknown-linux-musl")],
                      ["triple_target_mismatch"]))
    v.append(observed("P01-O-015", "permitted positive: a host artifact needs no ELF identity", [],
                      [row("speaker-host-full", "host", "host_full", H1, klass=0, be=False)], []))
    return {"schema": SCHEMA, "base": "p01_workspace_contract.json", "base_digest": base_digest, "vectors": v}


def fix_observed_digests(base, doc):
    """Rows must carry the digest of the contract AFTER the vector's mutations, unless a vector overrides it."""
    for vec in doc["vectors"]:
        if vec["kind"] != "observed" or not vec["ops"]:
            continue
        mutated = ref.digest(ref.apply_ops(base, vec["ops"]))
        for r in vec["rows"]:
            if r["contract_digest"] == doc["base_digest"]:
                r["contract_digest"] = mutated


def main(argv):
    with open(BASE_FILE, encoding="utf-8") as f:
        base = json.load(f)
    doc = build(base)
    fix_observed_digests(base, doc)
    ids = [v["id"] for v in doc["vectors"]]
    assert len(ids) == len(set(ids)), "duplicate vector id"
    text = json.dumps(doc, indent=1, ensure_ascii=True) + "\n"
    if "--check" in argv:
        try:
            with open(OUT_FILE, encoding="utf-8") as f:
                same = f.read() == text
        except OSError:
            same = False
        print("vectors: up to date" if same else "vectors: OUT OF DATE (run make_vectors.py)")
        return 0 if same else 1
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {len(ids)} vectors, base digest {doc['base_digest']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
