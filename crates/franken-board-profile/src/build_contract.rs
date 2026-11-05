//! Workspace build, target and profile contract (`P01` / `ffw-h3g`).
//!
//! A [`WorkspaceContract`] is data with a schema version and a canonical digest. It binds, in one
//! place, what the workspace says about itself: which crates exist and who owns them, which
//! dependency edges are allowed, which features are required and which are optional, which build
//! profiles select them, and which distinct per-ISA artifacts are produced from the one shared
//! source. It extends this crate's board-profile identity (see [`crate::CpuIsa`]); it does not
//! replace it.
//!
//! What the validator refuses (each refusal is a stable code in [`code`]):
//!
//! - **No universal artifact.** An artifact has exactly one target. A PowerPC and a MIPS artifact are
//!   different artifacts with different digests; one digest claimed for two targets is refused, and
//!   an artifact whose declared ISA, triple or observed ELF machine disagrees with its target is
//!   refused. There is no ARM target: it is not admitted without evidence, so it does not parse.
//! - **A disabled required feature can never become qualified.** [`WorkspaceContract::admission`]
//!   *computes* qualification from the feature selection and the bound evidence; an artifact that
//!   merely asserts `qualified` while a required feature is disabled, missing or unevidenced is
//!   refused, and evidence cannot be attached to a feature the artifact's profile disables.
//! - **Evidence is bound to identity.** A qualification names the artifact digest, target and
//!   profile it was gathered for. Evidence for another artifact, target or profile is stale, and a
//!   host simulation cannot stand in for evidence the feature requires from a real service or
//!   physical output.
//! - **A required feature cannot be removed by omission.** Every profile must select every required
//!   feature in the registry, enabled or disabled-with-a-reason.
//! - **Native services are independent.** A native-service feature may depend only on core features,
//!   and a core feature may not depend on a native service.
//! - **The crate graph is a layered DAG** with one owner per crate, interface and fixture, and no
//!   test-only crate in a device artifact's dependency closure unless a counted exception names it.
//!   A dependency that Cargo makes optional is modelled as such: it is part of an artifact's closure only
//!   when that artifact's profile enables the feature that activates it, and that feature must have a real
//!   Cargo flag owned by the same crate.
//!
//! Host checks here are offline and do not prove device operation. Whether the declared contract
//! matches the actual manifests is checked by `tests/p01` against `Cargo.toml` and `Cargo.lock`.

use crate::CpuIsa;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const BUILD_CONTRACT_SCHEMA_VERSION: &str = "ffw.build_contract.v1";

/// Stable error codes. They are shared verbatim with `tests/p01/reference.py`.
pub mod code {
    pub const PARSE_ERROR: &str = "parse_error";
    pub const SCHEMA_VERSION_MISMATCH: &str = "schema_version_mismatch";
    pub const DUPLICATE_CRATE: &str = "duplicate_crate";
    pub const DUPLICATE_CARGO_PROFILE: &str = "duplicate_cargo_profile";
    pub const DUPLICATE_FEATURE: &str = "duplicate_feature";
    pub const DUPLICATE_PROFILE: &str = "duplicate_profile";
    pub const DUPLICATE_ARTIFACT: &str = "duplicate_artifact";
    pub const UNKNOWN_DEPENDENCY: &str = "unknown_dependency";
    pub const SELF_DEPENDENCY: &str = "self_dependency";
    pub const DEPENDENCY_CYCLE: &str = "dependency_cycle";
    pub const DEV_DEPENDENCY_CYCLE: &str = "dev_dependency_cycle";
    pub const LAYER_VIOLATION: &str = "layer_violation";
    pub const OWNER_MISSING: &str = "owner_missing";
    pub const ASSET_UNOWNED: &str = "asset_unowned";
    pub const ASSET_DUPLICATE: &str = "asset_duplicate";
    pub const ASSET_CONFLICTING_OWNERS: &str = "asset_conflicting_owners";
    pub const ASSET_OWNER_MISMATCH: &str = "asset_owner_mismatch";
    pub const UNSAFE_POLICY_NOT_PERMITTED: &str = "unsafe_policy_not_permitted";
    pub const UNKNOWN_CARGO_PROFILE: &str = "unknown_cargo_profile";
    pub const DEVICE_PROFILE_NOT_ABORT: &str = "device_profile_not_abort";
    pub const UNKNOWN_FEATURE: &str = "unknown_feature";
    pub const FEATURE_OWNER_UNKNOWN: &str = "feature_owner_unknown";
    pub const FEATURE_CYCLE: &str = "feature_cycle";
    pub const NATIVE_FEATURE_REQUIRES_NATIVE: &str = "native_feature_requires_native";
    pub const CORE_FEATURE_REQUIRES_NATIVE: &str = "core_feature_requires_native";
    pub const EVIDENCE_POLICY_EMPTY: &str = "evidence_policy_empty";
    pub const REQUIRED_FEATURE_MISSING: &str = "required_feature_missing";
    pub const DUPLICATE_FEATURE_SELECTION: &str = "duplicate_feature_selection";
    pub const DISABLED_WITHOUT_REASON: &str = "disabled_without_reason";
    pub const FULL_PROFILE_DISABLES_REQUIRED: &str = "full_profile_disables_required";
    pub const NARROW_PROFILE_WITHOUT_REASON: &str = "narrow_profile_without_reason";
    pub const UNKNOWN_ARTIFACT_CRATE: &str = "unknown_artifact_crate";
    pub const UNKNOWN_PROFILE: &str = "unknown_profile";
    pub const ARTIFACT_TARGET_NOT_DECLARED: &str = "artifact_target_not_declared";
    pub const UNIVERSAL_ARTIFACT_CLAIM: &str = "universal_artifact_claim";
    pub const TRIPLE_TARGET_MISMATCH: &str = "triple_target_mismatch";
    pub const ISA_TARGET_MISMATCH: &str = "isa_target_mismatch";
    pub const BAD_DIGEST: &str = "bad_digest";
    pub const QUALIFIED_WHILE_DISABLED: &str = "qualified_while_disabled";
    pub const EVIDENCE_KIND_INSUFFICIENT: &str = "evidence_kind_insufficient";
    pub const EVIDENCE_RECEIPT_MISSING: &str = "evidence_receipt_missing";
    pub const STALE_EVIDENCE: &str = "stale_evidence";
    pub const QUALIFICATION_NOT_SUPPORTED: &str = "qualification_not_supported";
    pub const STALE_EXCEPTION: &str = "stale_exception";
    pub const EXCEPTION_WITHOUT_REASON: &str = "exception_without_reason";
    pub const TEST_SUPPORT_IN_DEVICE_CLOSURE: &str = "test_support_in_device_closure";
    pub const HOST_TOOL_IN_DEVICE_CLOSURE: &str = "host_tool_in_device_closure";
    pub const UNSAFE_IN_DEVICE_CLOSURE: &str = "unsafe_in_device_closure";
    pub const OPTIONAL_DEP_WITHOUT_FLAG: &str = "optional_dep_without_flag";
    pub const OPTIONAL_DEP_WRONG_OWNER: &str = "optional_dep_wrong_owner";
    // Observed-artifact (receipt) codes.
    pub const CONTRACT_DIGEST_MISMATCH: &str = "contract_digest_mismatch";
    pub const UNKNOWN_ARTIFACT: &str = "unknown_artifact";
    pub const OBSERVED_TARGET_MISMATCH: &str = "observed_target_mismatch";
    pub const OBSERVED_PROFILE_MISMATCH: &str = "observed_profile_mismatch";
    pub const OBSERVED_DIGEST_MISMATCH: &str = "observed_digest_mismatch";
    pub const ELF_MACHINE_MISMATCH: &str = "elf_machine_mismatch";
    pub const ELF_NOT_32BIT_BIG_ENDIAN: &str = "elf_not_32bit_big_endian";
    pub const ARTIFACT_DIGEST_CONFLICT: &str = "artifact_digest_conflict";
    pub const ARTIFACT_NOT_OBSERVED: &str = "artifact_not_observed";
}

/// A contract violation: a stable `code`, the `subject` it is about, and a human `detail`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContractError {
    pub code: &'static str,
    pub subject: String,
    pub detail: String,
}

impl ContractError {
    fn new(code: &'static str, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code,
            subject: subject.into(),
            detail: detail.into(),
        }
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}]: {}", self.code, self.subject, self.detail)
    }
}

impl std::error::Error for ContractError {}

/// Where a built artifact runs. Every variant is its own ISA artifact; there is no universal one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactTarget {
    Host,
    MipsBe,
    PowerpcBe,
}

impl ArtifactTarget {
    pub const ALL: [Self; 3] = [Self::Host, Self::MipsBe, Self::PowerpcBe];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::MipsBe => "mips_be",
            Self::PowerpcBe => "powerpc_be",
        }
    }

    /// The Rust target triple; `"host"` stands for whatever the build host is.
    #[must_use]
    pub const fn triple(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::MipsBe => "mips-unknown-linux-musl",
            Self::PowerpcBe => "powerpc-unknown-linux-musl",
        }
    }

    /// The ISA label an artifact for this target must declare; empty for the host.
    #[must_use]
    pub const fn isa_label(self) -> &'static str {
        match self {
            Self::Host => "",
            Self::MipsBe => "mips32_be",
            Self::PowerpcBe => "powerpc32_be",
        }
    }

    /// `e_machine` of an ELF built for this target (`EM_MIPS` = 8, `EM_PPC` = 20); 0 for the host.
    #[must_use]
    pub const fn elf_machine(self) -> u32 {
        match self {
            Self::Host => 0,
            Self::MipsBe => 8,
            Self::PowerpcBe => 20,
        }
    }

    #[must_use]
    pub const fn is_device(self) -> bool {
        !matches!(self, Self::Host)
    }

    /// The board-profile ISA this target corresponds to (`None` for the host).
    #[must_use]
    pub const fn cpu_isa(self) -> Option<CpuIsa> {
        match self {
            Self::Host => None,
            Self::MipsBe => Some(CpuIsa::Mips32R2BigEndian),
            Self::PowerpcBe => Some(CpuIsa::PowerPc32BigEndian),
        }
    }

    #[must_use]
    pub fn from_triple(triple: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|target| target.is_device() && target.triple() == triple)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrateRole {
    Library,
    Platform,
    Application,
    TestSupport,
    HostTool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsafePolicy {
    /// `unsafe_code = "forbid"` through the workspace lint table.
    Forbid,
    /// `unsafe_code = "deny"` with a scoped, commented allow. Test and host tools only.
    DenyWithScopedAllow,
    /// A freestanding bootstrap probe outside the workspace. Never a product artifact.
    BootstrapProbe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CargoProfileSpec {
    pub name: String,
    pub opt_level: String,
    pub lto: String,
    pub codegen_units: u32,
    pub panic: String,
    pub strip: String,
}

/// A normal dependency that exists only when a registry feature is enabled: Cargo's
/// `dep = { optional = true }` gated by the feature's `cargo_feature` flag. The edge is real, and is checked
/// like any other normal edge, but it is part of an artifact's dependency closure only when that artifact's
/// profile enables `feature`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionalDep {
    pub dep: String,
    /// The registry feature that activates the dependency. Its `cargo_feature` is the Cargo flag.
    pub feature: String,
}

/// A workspace member crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrateSpec {
    pub name: String,
    pub path: String,
    pub owner: String,
    pub role: CrateRole,
    pub layer: u32,
    pub unsafe_policy: UnsafePolicy,
    /// Workspace members this crate depends on in `[dependencies]` (not optional).
    pub deps: Vec<String>,
    /// Workspace members this crate depends on in `[dependencies]` with `optional = true`.
    pub optional_deps: Vec<OptionalDep>,
    /// Workspace members this crate depends on in `[dev-dependencies]`.
    pub dev_deps: Vec<String>,
}

/// A crate that is deliberately outside the workspace (listed in the root `exclude`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcludedCrate {
    pub name: String,
    pub path: String,
    pub owner: String,
    pub reason: String,
    pub unsafe_policy: UnsafePolicy,
    pub targets: Vec<ArtifactTarget>,
}

/// A crate that exists on disk but is not yet a workspace member. Declared, counted, never silent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingMember {
    pub name: String,
    pub path: String,
    pub owner: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Crate,
    Interface,
    Fixture,
}

/// One path with exactly one owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedAsset {
    pub path: String,
    pub owner: String,
    pub kind: AssetKind,
}

/// A named, counted allowance for one normal dependency edge onto a test-only crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestSupportException {
    pub from: String,
    pub to: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureKind {
    Core,
    NativeService,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureRequirement {
    Required,
    Optional,
}

/// What kind of run produced a piece of evidence. These are distinct categories, not a ladder: a
/// host simulation never substitutes for a real-service or physical-output result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    HostSimulation,
    GuestExecution,
    RealService,
    PhysicalOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureSpec {
    pub name: String,
    pub kind: FeatureKind,
    pub requirement: FeatureRequirement,
    pub owner_crate: String,
    /// The Cargo feature flag that gates it; empty while it is compiled in unconditionally.
    pub cargo_feature: String,
    pub requires: Vec<String>,
    /// The evidence kinds that may qualify this feature.
    pub accepted_evidence: Vec<EvidenceKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureState {
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureSelection {
    pub feature: String,
    pub state: FeatureState,
    /// Required text when `state` is `disabled`.
    pub disabled_reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileScope {
    /// The whole product: no required feature may be disabled.
    FullProduct,
    /// A named, narrower profile. It may disable required features, which then stay blocked.
    NamedNarrow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildProfile {
    pub name: String,
    pub cargo_profile: String,
    pub scope: ProfileScope,
    pub narrow_reason: String,
    pub features: Vec<FeatureSelection>,
}

/// The identity a qualification was gathered for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBinding {
    pub kind: EvidenceKind,
    pub artifact_sha256: String,
    pub target: ArtifactTarget,
    pub profile: String,
    pub receipt_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureQualification {
    pub feature: String,
    pub evidence: EvidenceBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactStatus {
    Unqualified,
    Qualified,
}

/// One built artifact: one crate, one target, one profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSpec {
    pub id: String,
    #[serde(rename = "crate")]
    pub crate_name: String,
    /// The binary name; empty for a library artifact.
    pub bin: String,
    pub target: ArtifactTarget,
    pub triple: String,
    /// The declared ISA label; empty for the host.
    pub isa: String,
    pub profile: String,
    /// Where this artifact claims to run. It must be exactly `[target]`.
    pub runs_on: Vec<ArtifactTarget>,
    pub status: ArtifactStatus,
    /// The digest of the built artifact; empty until one has been observed.
    pub sha256: String,
    pub qualifications: Vec<FeatureQualification>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceContract {
    pub schema_version: String,
    pub cargo_profiles: Vec<CargoProfileSpec>,
    pub crates: Vec<CrateSpec>,
    pub excluded: Vec<ExcludedCrate>,
    pub pending_members: Vec<PendingMember>,
    pub assets: Vec<OwnedAsset>,
    pub test_support_exceptions: Vec<TestSupportException>,
    pub features: Vec<FeatureSpec>,
    pub profiles: Vec<BuildProfile>,
    pub artifacts: Vec<ArtifactSpec>,
}

/// The computed qualification of one artifact. Never read from the data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Admission {
    pub artifact: String,
    pub qualified: bool,
    /// Sorted `reason:feature` strings; empty exactly when `qualified`.
    pub blocks: Vec<String>,
}

/// What a build host reports about one built artifact (a receipt row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedArtifact {
    pub id: String,
    pub target: ArtifactTarget,
    pub triple: String,
    pub profile: String,
    pub sha256: String,
    /// ELF `e_machine`; 0 when the file is not an ELF (the host).
    pub elf_machine: u32,
    /// ELF class byte: 1 = 32-bit, 2 = 64-bit; 0 when not an ELF.
    pub elf_class: u32,
    pub elf_big_endian: bool,
    pub contract_digest: String,
}

// ---------------------------------------------------------------------------------------------
// Canonical form and digest

/// Compact JSON with object keys sorted: the form every digest is taken over.
#[must_use]
pub fn canonical_json_value(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => out.push_str(&serde_json::to_string(text).unwrap_or_default()),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push(':');
                if let Some(item) = map.get(key.as_str()) {
                    write_canonical(item, out);
                }
            }
            out.push('}');
        }
    }
}

fn is_hex64(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// ---------------------------------------------------------------------------------------------
// Graph helpers

type Graph = BTreeMap<String, BTreeSet<String>>;

/// Every node reachable from each node by one or more edges.
fn reachability(graph: &Graph) -> BTreeMap<String, BTreeSet<String>> {
    let mut out = BTreeMap::new();
    for (start, first) in graph {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut stack: Vec<String> = first.iter().cloned().collect();
        while let Some(node) = stack.pop() {
            if seen.insert(node.clone())
                && let Some(next) = graph.get(&node)
            {
                stack.extend(next.iter().cloned());
            }
        }
        out.insert(start.clone(), seen);
    }
    out
}

/// Strongly connected components with more than one member, each sorted. A self-loop is not a
/// cycle here; it has its own code.
fn cycles(graph: &Graph) -> BTreeSet<Vec<String>> {
    let reach = reachability(graph);
    let mut found = BTreeSet::new();
    for (node, from_node) in &reach {
        let mut component: Vec<String> = from_node
            .iter()
            .filter(|other| {
                *other != node && reach.get(*other).is_some_and(|back| back.contains(node))
            })
            .cloned()
            .collect();
        if !component.is_empty() {
            component.push(node.clone());
            component.sort();
            found.insert(component);
        }
    }
    found
}

/// `start` and everything it reaches.
fn closure(graph: &Graph, start: &str) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![start.to_string()];
    while let Some(node) = stack.pop() {
        if seen.insert(node.clone())
            && let Some(next) = graph.get(&node)
        {
            stack.extend(next.iter().cloned());
        }
    }
    seen
}

// ---------------------------------------------------------------------------------------------
// The contract

impl WorkspaceContract {
    /// Parse a contract. Any malformed document, unknown field or unknown enum value (an ARM target,
    /// say) is a single `parse_error`; nothing is partially accepted.
    pub fn from_json(text: &str) -> Result<Self, ContractError> {
        serde_json::from_str(text)
            .map_err(|err| ContractError::new(code::PARSE_ERROR, "contract", err.to_string()))
    }

    /// Parse a contract from an already-decoded document.
    pub fn from_value(value: Value) -> Result<Self, ContractError> {
        serde_json::from_value(value)
            .map_err(|err| ContractError::new(code::PARSE_ERROR, "contract", err.to_string()))
    }

    /// The canonical JSON text this contract's digest is taken over.
    #[must_use]
    pub fn canonical_json(&self) -> String {
        match serde_json::to_value(self) {
            Ok(value) => canonical_json_value(&value),
            Err(_) => String::new(),
        }
    }

    /// SHA-256 over [`Self::canonical_json`], lowercase hex.
    #[must_use]
    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(self.canonical_json().as_bytes()))
    }

    fn crate_index(&self) -> BTreeMap<&str, &CrateSpec> {
        self.crates
            .iter()
            .map(|spec| (spec.name.as_str(), spec))
            .collect()
    }

    /// Every normal edge the manifests can ever produce: `deps` plus `optional_deps`, over known,
    /// distinct crates.
    fn declared_graph(&self) -> Graph {
        let idx = self.crate_index();
        let mut graph: Graph = BTreeMap::new();
        for spec in &self.crates {
            let edges = graph.entry(spec.name.clone()).or_default();
            let optional = spec.optional_deps.iter().map(|opt| &opt.dep);
            for dep in spec.deps.iter().chain(optional) {
                if dep != &spec.name && idx.contains_key(dep.as_str()) {
                    edges.insert(dep.clone());
                }
            }
        }
        graph
    }

    /// The normal edges that are live in `art`'s build: every plain dependency, and an optional one only
    /// when the artifact's profile enables the feature that activates it.
    fn active_graph(&self, art: &ArtifactSpec) -> Graph {
        let idx = self.crate_index();
        let enabled: BTreeSet<&str> = self
            .profiles
            .iter()
            .find(|profile| profile.name == art.profile)
            .map(|profile| {
                profile
                    .features
                    .iter()
                    .filter(|selection| selection.state == FeatureState::Enabled)
                    .map(|selection| selection.feature.as_str())
                    .collect()
            })
            .unwrap_or_default();
        let mut graph: Graph = BTreeMap::new();
        for spec in &self.crates {
            let edges = graph.entry(spec.name.clone()).or_default();
            for dep in &spec.deps {
                if dep != &spec.name && idx.contains_key(dep.as_str()) {
                    edges.insert(dep.clone());
                }
            }
            for opt in &spec.optional_deps {
                if opt.dep != spec.name
                    && idx.contains_key(opt.dep.as_str())
                    && enabled.contains(opt.feature.as_str())
                {
                    edges.insert(opt.dep.clone());
                }
            }
        }
        graph
    }

    /// Every violation, sorted and de-duplicated. Empty means the contract is internally valid.
    #[must_use]
    pub fn validate(&self) -> Vec<ContractError> {
        let mut errs = Vec::new();
        if self.schema_version != BUILD_CONTRACT_SCHEMA_VERSION {
            errs.push(ContractError::new(
                code::SCHEMA_VERSION_MISMATCH,
                "contract",
                format!(
                    "schema_version {:?}, expected {BUILD_CONTRACT_SCHEMA_VERSION:?}",
                    self.schema_version
                ),
            ));
        }
        self.check_unique_names(&mut errs);
        self.check_graph(&mut errs);
        self.check_ownership(&mut errs);
        self.check_unsafe_policy(&mut errs);
        self.check_features(&mut errs);
        self.check_optional_deps(&mut errs);
        self.check_profiles(&mut errs);
        self.check_artifacts(&mut errs);
        self.check_test_support(&mut errs);
        errs.sort();
        errs.dedup();
        errs
    }

    fn check_unique_names(&self, errs: &mut Vec<ContractError>) {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let names = self
            .crates
            .iter()
            .map(|spec| spec.name.as_str())
            .chain(self.excluded.iter().map(|spec| spec.name.as_str()))
            .chain(self.pending_members.iter().map(|spec| spec.name.as_str()));
        for name in names {
            if !seen.insert(name) {
                errs.push(ContractError::new(
                    code::DUPLICATE_CRATE,
                    name,
                    "crate name listed more than once across members, excluded and pending",
                ));
            }
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for spec in &self.cargo_profiles {
            if !seen.insert(spec.name.as_str()) {
                errs.push(ContractError::new(
                    code::DUPLICATE_CARGO_PROFILE,
                    spec.name.as_str(),
                    "cargo profile listed more than once",
                ));
            }
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for spec in &self.features {
            if !seen.insert(spec.name.as_str()) {
                errs.push(ContractError::new(
                    code::DUPLICATE_FEATURE,
                    spec.name.as_str(),
                    "feature listed more than once in the registry",
                ));
            }
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for spec in &self.profiles {
            if !seen.insert(spec.name.as_str()) {
                errs.push(ContractError::new(
                    code::DUPLICATE_PROFILE,
                    spec.name.as_str(),
                    "build profile listed more than once",
                ));
            }
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut identities: BTreeSet<(String, ArtifactTarget, String)> = BTreeSet::new();
        for spec in &self.artifacts {
            if !seen.insert(spec.id.as_str()) {
                errs.push(ContractError::new(
                    code::DUPLICATE_ARTIFACT,
                    spec.id.as_str(),
                    "artifact id listed more than once",
                ));
            }
            let identity = (spec.crate_name.clone(), spec.target, spec.profile.clone());
            if !identities.insert(identity) {
                errs.push(ContractError::new(
                    code::DUPLICATE_ARTIFACT,
                    format!(
                        "{}/{}/{}",
                        spec.crate_name,
                        spec.target.as_str(),
                        spec.profile
                    ),
                    "two artifacts share one crate, target and profile",
                ));
            }
        }
    }

    fn check_graph(&self, errs: &mut Vec<ContractError>) {
        let idx = self.crate_index();
        let mut union: Graph = BTreeMap::new();
        for spec in &self.crates {
            union.entry(spec.name.clone()).or_default();
        }
        let edges = self.crates.iter().flat_map(|spec| {
            spec.deps
                .iter()
                .map(move |dep| (spec, dep, false))
                .chain(
                    spec.optional_deps
                        .iter()
                        .map(move |opt| (spec, &opt.dep, false)),
                )
                .chain(spec.dev_deps.iter().map(move |dep| (spec, dep, true)))
        });
        for (spec, dep, is_dev) in edges {
            let edge = format!("{}->{dep}", spec.name);
            if dep == &spec.name {
                errs.push(ContractError::new(
                    code::SELF_DEPENDENCY,
                    spec.name.as_str(),
                    "a crate lists itself as a dependency",
                ));
                continue;
            }
            let Some(target) = idx.get(dep.as_str()) else {
                errs.push(ContractError::new(
                    code::UNKNOWN_DEPENDENCY,
                    edge,
                    "dependency is not a workspace member",
                ));
                continue;
            };
            union
                .entry(spec.name.clone())
                .or_default()
                .insert(dep.clone());
            if !is_dev && target.layer >= spec.layer {
                errs.push(ContractError::new(
                    code::LAYER_VIOLATION,
                    edge,
                    format!(
                        "normal dependency must point to a lower layer ({} -> {})",
                        spec.layer, target.layer
                    ),
                ));
            }
        }
        let normal = self.declared_graph();
        let normal_cycles = cycles(&normal);
        for component in &normal_cycles {
            errs.push(ContractError::new(
                code::DEPENDENCY_CYCLE,
                component.join(","),
                format!("normal dependency cycle among {}", component.join(", ")),
            ));
        }
        for component in cycles(&union) {
            if !normal_cycles.contains(&component) {
                errs.push(ContractError::new(
                    code::DEV_DEPENDENCY_CYCLE,
                    component.join(","),
                    format!(
                        "dependency cycle through dev-dependencies among {}",
                        component.join(", ")
                    ),
                ));
            }
        }
    }

    fn check_ownership(&self, errs: &mut Vec<ContractError>) {
        let mut by_path: BTreeMap<&str, Vec<&OwnedAsset>> = BTreeMap::new();
        for asset in &self.assets {
            by_path.entry(asset.path.as_str()).or_default().push(asset);
            if asset.owner.trim().is_empty() {
                errs.push(ContractError::new(
                    code::OWNER_MISSING,
                    asset.path.as_str(),
                    "asset has an empty owner",
                ));
            }
        }
        for (path, group) in &by_path {
            if group.len() > 1 {
                let owners: BTreeSet<&str> =
                    group.iter().map(|asset| asset.owner.as_str()).collect();
                let which = if owners.len() > 1 {
                    code::ASSET_CONFLICTING_OWNERS
                } else {
                    code::ASSET_DUPLICATE
                };
                errs.push(ContractError::new(
                    which,
                    *path,
                    "a path must have exactly one owner and one entry",
                ));
            }
        }
        let crate_like = self
            .crates
            .iter()
            .map(|spec| (spec.name.as_str(), spec.path.as_str(), spec.owner.as_str()))
            .chain(
                self.excluded
                    .iter()
                    .map(|spec| (spec.name.as_str(), spec.path.as_str(), spec.owner.as_str())),
            )
            .chain(
                self.pending_members
                    .iter()
                    .map(|spec| (spec.name.as_str(), spec.path.as_str(), spec.owner.as_str())),
            );
        for (name, path, owner) in crate_like {
            if owner.trim().is_empty() {
                errs.push(ContractError::new(
                    code::OWNER_MISSING,
                    name,
                    "crate has an empty owner",
                ));
            }
            match by_path.get(path).and_then(|group| group.first()) {
                None => errs.push(ContractError::new(
                    code::ASSET_UNOWNED,
                    name,
                    format!("no ownership entry for {path}"),
                )),
                Some(asset) if asset.owner != owner || asset.kind != AssetKind::Crate => {
                    errs.push(ContractError::new(
                        code::ASSET_OWNER_MISMATCH,
                        name,
                        format!("ownership entry for {path} disagrees with the crate record"),
                    ));
                }
                Some(_) => {}
            }
        }
    }

    fn check_unsafe_policy(&self, errs: &mut Vec<ContractError>) {
        for spec in &self.crates {
            let allowed = match spec.unsafe_policy {
                UnsafePolicy::Forbid => true,
                UnsafePolicy::DenyWithScopedAllow => {
                    matches!(spec.role, CrateRole::HostTool | CrateRole::TestSupport)
                }
                UnsafePolicy::BootstrapProbe => false,
            };
            if !allowed {
                errs.push(ContractError::new(
                    code::UNSAFE_POLICY_NOT_PERMITTED,
                    spec.name.as_str(),
                    "this unsafe policy is not permitted for a workspace crate of this role",
                ));
            }
        }
        for spec in &self.excluded {
            if spec.unsafe_policy != UnsafePolicy::BootstrapProbe {
                errs.push(ContractError::new(
                    code::UNSAFE_POLICY_NOT_PERMITTED,
                    spec.name.as_str(),
                    "an excluded crate must declare the bootstrap-probe policy",
                ));
            }
        }
    }

    fn check_features(&self, errs: &mut Vec<ContractError>) {
        let members = self.crate_index();
        let features: BTreeMap<&str, &FeatureSpec> = self
            .features
            .iter()
            .map(|spec| (spec.name.as_str(), spec))
            .collect();
        let mut graph: Graph = BTreeMap::new();
        for spec in &self.features {
            let edges = graph.entry(spec.name.clone()).or_default();
            if !members.contains_key(spec.owner_crate.as_str()) {
                errs.push(ContractError::new(
                    code::FEATURE_OWNER_UNKNOWN,
                    spec.name.as_str(),
                    format!(
                        "owner crate {:?} is not a workspace member",
                        spec.owner_crate
                    ),
                ));
            }
            if spec.accepted_evidence.is_empty() {
                errs.push(ContractError::new(
                    code::EVIDENCE_POLICY_EMPTY,
                    spec.name.as_str(),
                    "a feature must name the evidence kinds that can qualify it",
                ));
            }
            for required in &spec.requires {
                let edge = format!("{}->{required}", spec.name);
                if required == &spec.name {
                    errs.push(ContractError::new(
                        code::FEATURE_CYCLE,
                        spec.name.as_str(),
                        "a feature lists itself as a requirement",
                    ));
                    continue;
                }
                let Some(other) = features.get(required.as_str()) else {
                    errs.push(ContractError::new(
                        code::UNKNOWN_FEATURE,
                        edge,
                        "required feature is not in the registry",
                    ));
                    continue;
                };
                edges.insert(required.clone());
                match (spec.kind, other.kind) {
                    (FeatureKind::NativeService, FeatureKind::NativeService) => {
                        errs.push(ContractError::new(
                            code::NATIVE_FEATURE_REQUIRES_NATIVE,
                            edge,
                            "native services must not depend on each other",
                        ));
                    }
                    (FeatureKind::Core, FeatureKind::NativeService) => {
                        errs.push(ContractError::new(
                            code::CORE_FEATURE_REQUIRES_NATIVE,
                            edge,
                            "the minimal renderer must not depend on a native service",
                        ));
                    }
                    _ => {}
                }
            }
        }
        for component in cycles(&graph) {
            errs.push(ContractError::new(
                code::FEATURE_CYCLE,
                component.join(","),
                format!("feature requirement cycle among {}", component.join(", ")),
            ));
        }
    }

    /// An optional dependency must be gated by a registry feature that has a real Cargo flag, and that
    /// flag must belong to the crate that carries the dependency.
    fn check_optional_deps(&self, errs: &mut Vec<ContractError>) {
        let features: BTreeMap<&str, &FeatureSpec> = self
            .features
            .iter()
            .map(|spec| (spec.name.as_str(), spec))
            .collect();
        for spec in &self.crates {
            for opt in &spec.optional_deps {
                let subject = format!("{}->{}", spec.name, opt.dep);
                let Some(feature) = features.get(opt.feature.as_str()) else {
                    errs.push(ContractError::new(
                        code::UNKNOWN_FEATURE,
                        subject,
                        format!(
                            "optional dependency is gated by unknown feature {:?}",
                            opt.feature
                        ),
                    ));
                    continue;
                };
                if feature.cargo_feature.is_empty() {
                    errs.push(ContractError::new(
                        code::OPTIONAL_DEP_WITHOUT_FLAG,
                        subject.clone(),
                        "the gating feature has no Cargo flag, so the dependency cannot be optional",
                    ));
                }
                if feature.owner_crate != spec.name {
                    errs.push(ContractError::new(
                        code::OPTIONAL_DEP_WRONG_OWNER,
                        subject,
                        "the Cargo flag belongs to another crate than the one carrying the dependency",
                    ));
                }
            }
        }
    }

    fn check_profiles(&self, errs: &mut Vec<ContractError>) {
        let features: BTreeMap<&str, &FeatureSpec> = self
            .features
            .iter()
            .map(|spec| (spec.name.as_str(), spec))
            .collect();
        let cargo_profiles: BTreeSet<&str> = self
            .cargo_profiles
            .iter()
            .map(|spec| spec.name.as_str())
            .collect();
        for profile in &self.profiles {
            if !cargo_profiles.contains(profile.cargo_profile.as_str()) {
                errs.push(ContractError::new(
                    code::UNKNOWN_CARGO_PROFILE,
                    profile.name.as_str(),
                    format!("cargo profile {:?} is not declared", profile.cargo_profile),
                ));
            }
            if profile.scope == ProfileScope::NamedNarrow && profile.narrow_reason.trim().is_empty()
            {
                errs.push(ContractError::new(
                    code::NARROW_PROFILE_WITHOUT_REASON,
                    profile.name.as_str(),
                    "a narrow profile must say why it is narrow",
                ));
            }
            let mut selected: BTreeMap<&str, &FeatureSelection> = BTreeMap::new();
            for selection in &profile.features {
                let subject = format!("{}:{}", profile.name, selection.feature);
                let Some(spec) = features.get(selection.feature.as_str()) else {
                    errs.push(ContractError::new(
                        code::UNKNOWN_FEATURE,
                        subject,
                        "selection names a feature that is not in the registry",
                    ));
                    continue;
                };
                if selected
                    .insert(selection.feature.as_str(), selection)
                    .is_some()
                {
                    errs.push(ContractError::new(
                        code::DUPLICATE_FEATURE_SELECTION,
                        subject.clone(),
                        "feature selected more than once in one profile",
                    ));
                }
                if selection.state == FeatureState::Disabled {
                    if selection.disabled_reason.trim().is_empty() {
                        errs.push(ContractError::new(
                            code::DISABLED_WITHOUT_REASON,
                            subject.clone(),
                            "a disabled feature must say why",
                        ));
                    }
                    if spec.requirement == FeatureRequirement::Required
                        && profile.scope == ProfileScope::FullProduct
                    {
                        errs.push(ContractError::new(
                            code::FULL_PROFILE_DISABLES_REQUIRED,
                            subject,
                            "a full-product profile cannot disable a required feature",
                        ));
                    }
                }
            }
            for spec in &self.features {
                if spec.requirement == FeatureRequirement::Required
                    && !selected.contains_key(spec.name.as_str())
                {
                    errs.push(ContractError::new(
                        code::REQUIRED_FEATURE_MISSING,
                        format!("{}:{}", profile.name, spec.name),
                        "a required feature cannot be removed by omitting it from a profile",
                    ));
                }
            }
        }
    }

    fn check_artifacts(&self, errs: &mut Vec<ContractError>) {
        let members = self.crate_index();
        let excluded: BTreeMap<&str, &ExcludedCrate> = self
            .excluded
            .iter()
            .map(|spec| (spec.name.as_str(), spec))
            .collect();
        let profiles: BTreeMap<&str, &BuildProfile> = self
            .profiles
            .iter()
            .map(|spec| (spec.name.as_str(), spec))
            .collect();
        let cargo_profiles: BTreeMap<&str, &CargoProfileSpec> = self
            .cargo_profiles
            .iter()
            .map(|spec| (spec.name.as_str(), spec))
            .collect();
        let features: BTreeMap<&str, &FeatureSpec> = self
            .features
            .iter()
            .map(|spec| (spec.name.as_str(), spec))
            .collect();
        for art in &self.artifacts {
            let id = art.id.as_str();
            if let Some(extra) = excluded.get(art.crate_name.as_str()) {
                if !extra.targets.contains(&art.target) {
                    errs.push(ContractError::new(
                        code::ARTIFACT_TARGET_NOT_DECLARED,
                        id,
                        "the excluded crate does not declare this target",
                    ));
                }
            } else if !members.contains_key(art.crate_name.as_str()) {
                errs.push(ContractError::new(
                    code::UNKNOWN_ARTIFACT_CRATE,
                    id,
                    format!(
                        "crate {:?} is neither a member nor excluded",
                        art.crate_name
                    ),
                ));
            }
            if art.runs_on.as_slice() != [art.target] {
                errs.push(ContractError::new(
                    code::UNIVERSAL_ARTIFACT_CLAIM,
                    id,
                    "an artifact runs on exactly its own target; no artifact is universal",
                ));
            }
            if art.triple != art.target.triple() {
                errs.push(ContractError::new(
                    code::TRIPLE_TARGET_MISMATCH,
                    id,
                    format!(
                        "triple {:?} does not belong to target {}",
                        art.triple,
                        art.target.as_str()
                    ),
                ));
            }
            if art.isa != art.target.isa_label() {
                errs.push(ContractError::new(
                    code::ISA_TARGET_MISMATCH,
                    id,
                    format!(
                        "isa {:?} does not belong to target {}",
                        art.isa,
                        art.target.as_str()
                    ),
                ));
            }
            if !art.sha256.is_empty() && !is_hex64(&art.sha256) {
                errs.push(ContractError::new(
                    code::BAD_DIGEST,
                    id,
                    "sha256 must be 64 lowercase hex digits or empty",
                ));
            }
            let Some(profile) = profiles.get(art.profile.as_str()) else {
                errs.push(ContractError::new(
                    code::UNKNOWN_PROFILE,
                    id,
                    format!("profile {:?} is not declared", art.profile),
                ));
                continue;
            };
            if art.target.is_device()
                && cargo_profiles
                    .get(profile.cargo_profile.as_str())
                    .is_some_and(|spec| spec.panic != "abort")
            {
                errs.push(ContractError::new(
                    code::DEVICE_PROFILE_NOT_ABORT,
                    id,
                    "a device artifact must be built with panic = abort",
                ));
            }
            for qual in &art.qualifications {
                let subject = format!("{id}:{}", qual.feature);
                let Some(spec) = features.get(qual.feature.as_str()) else {
                    errs.push(ContractError::new(
                        code::UNKNOWN_FEATURE,
                        subject,
                        "qualification names a feature that is not in the registry",
                    ));
                    continue;
                };
                let enabled = profile.features.iter().any(|selection| {
                    selection.feature == qual.feature && selection.state == FeatureState::Enabled
                });
                if !enabled {
                    errs.push(ContractError::new(
                        code::QUALIFIED_WHILE_DISABLED,
                        subject.clone(),
                        "a feature the artifact's profile disables cannot carry qualification",
                    ));
                }
                if !spec.accepted_evidence.contains(&qual.evidence.kind) {
                    errs.push(ContractError::new(
                        code::EVIDENCE_KIND_INSUFFICIENT,
                        subject.clone(),
                        "this evidence kind cannot qualify the feature",
                    ));
                }
                if qual.evidence.receipt_id.trim().is_empty() {
                    errs.push(ContractError::new(
                        code::EVIDENCE_RECEIPT_MISSING,
                        subject.clone(),
                        "evidence must cite the receipt it came from",
                    ));
                }
                if !binding_matches(art, &qual.evidence) {
                    errs.push(ContractError::new(
                        code::STALE_EVIDENCE,
                        subject,
                        "evidence is not bound to this artifact's digest, target and profile",
                    ));
                }
            }
            if art.status == ArtifactStatus::Qualified
                && self
                    .admission(id)
                    .is_some_and(|admission| !admission.qualified)
            {
                errs.push(ContractError::new(
                    code::QUALIFICATION_NOT_SUPPORTED,
                    id,
                    "status is qualified but the computed admission is not",
                ));
            }
        }
    }

    fn check_test_support(&self, errs: &mut Vec<ContractError>) {
        let idx = self.crate_index();
        let declared = self.declared_graph();
        for exception in &self.test_support_exceptions {
            let subject = format!("{}->{}", exception.from, exception.to);
            let is_edge = declared
                .get(&exception.from)
                .is_some_and(|edges| edges.contains(&exception.to));
            let to_is_test_support = idx
                .get(exception.to.as_str())
                .is_some_and(|spec| spec.role == CrateRole::TestSupport);
            if !is_edge || !to_is_test_support {
                errs.push(ContractError::new(
                    code::STALE_EXCEPTION,
                    subject.clone(),
                    "exception does not match a normal or optional dependency edge onto a test-support crate",
                ));
            }
            if exception.reason.trim().is_empty() {
                errs.push(ContractError::new(
                    code::EXCEPTION_WITHOUT_REASON,
                    subject,
                    "an exception must say why it exists",
                ));
            }
        }
        for art in &self.artifacts {
            if !art.target.is_device() || !idx.contains_key(art.crate_name.as_str()) {
                continue;
            }
            let active = self.active_graph(art);
            let reach = closure(&active, &art.crate_name);
            for member in &reach {
                let Some(spec) = idx.get(member.as_str()) else {
                    continue;
                };
                let subject = format!("{}:{member}", art.id);
                if spec.role == CrateRole::TestSupport {
                    let covered = self.test_support_exceptions.iter().any(|exception| {
                        exception.to == *member
                            && reach.contains(&exception.from)
                            && active
                                .get(&exception.from)
                                .is_some_and(|edges| edges.contains(&exception.to))
                    });
                    if !covered {
                        errs.push(ContractError::new(
                            code::TEST_SUPPORT_IN_DEVICE_CLOSURE,
                            subject.clone(),
                            "a test-only crate is in a device artifact's dependency closure",
                        ));
                    }
                }
                if spec.role == CrateRole::HostTool {
                    errs.push(ContractError::new(
                        code::HOST_TOOL_IN_DEVICE_CLOSURE,
                        subject.clone(),
                        "a host tool is in a device artifact's dependency closure",
                    ));
                }
                if spec.unsafe_policy == UnsafePolicy::DenyWithScopedAllow {
                    errs.push(ContractError::new(
                        code::UNSAFE_IN_DEVICE_CLOSURE,
                        subject,
                        "a crate with a scoped unsafe allowance is in a device artifact's closure",
                    ));
                }
            }
        }
    }

    /// The computed qualification of `artifact_id`: `None` for an unknown artifact. An artifact is
    /// qualified only if every required feature is enabled in its profile and carries evidence of an
    /// accepted kind bound to this artifact. There is no other way to be qualified.
    #[must_use]
    pub fn admission(&self, artifact_id: &str) -> Option<Admission> {
        let art = self.artifacts.iter().find(|spec| spec.id == artifact_id)?;
        let profile = self.profiles.iter().find(|spec| spec.name == art.profile);
        let mut blocks = Vec::new();
        for spec in &self.features {
            if spec.requirement != FeatureRequirement::Required {
                continue;
            }
            let state = profile.and_then(|profile| {
                profile
                    .features
                    .iter()
                    .find(|selection| selection.feature == spec.name)
                    .map(|selection| selection.state)
            });
            match state {
                None => {
                    blocks.push(format!("required_feature_missing:{}", spec.name));
                    continue;
                }
                Some(FeatureState::Disabled) => {
                    blocks.push(format!("required_feature_disabled:{}", spec.name));
                    continue;
                }
                Some(FeatureState::Enabled) => {}
            }
            match art
                .qualifications
                .iter()
                .find(|qual| qual.feature == spec.name)
            {
                None => blocks.push(format!("required_feature_unqualified:{}", spec.name)),
                Some(qual) if !spec.accepted_evidence.contains(&qual.evidence.kind) => {
                    blocks.push(format!("evidence_kind_insufficient:{}", spec.name));
                }
                Some(qual) if !binding_matches(art, &qual.evidence) => {
                    blocks.push(format!("stale_evidence:{}", spec.name));
                }
                Some(_) => {}
            }
        }
        blocks.sort();
        Some(Admission {
            artifact: art.id.clone(),
            qualified: blocks.is_empty(),
            blocks,
        })
    }

    /// Check what a build host reported against the contract. This is where exact artifact and
    /// profile identity is held to the declaration: target, triple, profile, digest, ELF machine,
    /// class and byte order, and that no digest is claimed for two targets. With `require_all`, every
    /// declared artifact must also have been observed.
    #[must_use]
    pub fn verify_observed(
        &self,
        observed: &[ObservedArtifact],
        require_all: bool,
    ) -> Vec<ContractError> {
        let mut errs = Vec::new();
        let digest = self.digest();
        let declared: BTreeMap<&str, &ArtifactSpec> = self
            .artifacts
            .iter()
            .map(|spec| (spec.id.as_str(), spec))
            .collect();
        let mut digests_by_id: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        let mut targets_by_digest: BTreeMap<&str, BTreeSet<ArtifactTarget>> = BTreeMap::new();
        for obs in observed {
            let id = obs.id.as_str();
            if obs.contract_digest != digest {
                errs.push(ContractError::new(
                    code::CONTRACT_DIGEST_MISMATCH,
                    id,
                    "the receipt was produced against a different contract",
                ));
            }
            if !is_hex64(&obs.sha256) {
                errs.push(ContractError::new(
                    code::BAD_DIGEST,
                    id,
                    "sha256 must be 64 lowercase hex digits",
                ));
            }
            digests_by_id
                .entry(id)
                .or_default()
                .insert(obs.sha256.as_str());
            targets_by_digest
                .entry(obs.sha256.as_str())
                .or_default()
                .insert(obs.target);
            let Some(spec) = declared.get(id) else {
                errs.push(ContractError::new(
                    code::UNKNOWN_ARTIFACT,
                    id,
                    "observed artifact is not declared in the contract",
                ));
                continue;
            };
            if obs.target != spec.target {
                errs.push(ContractError::new(
                    code::OBSERVED_TARGET_MISMATCH,
                    id,
                    "observed target differs from the declared target",
                ));
            }
            if obs.triple != spec.triple {
                errs.push(ContractError::new(
                    code::TRIPLE_TARGET_MISMATCH,
                    id,
                    "observed triple differs from the declared triple",
                ));
            }
            if obs.profile != spec.profile {
                errs.push(ContractError::new(
                    code::OBSERVED_PROFILE_MISMATCH,
                    id,
                    "observed profile differs from the declared profile",
                ));
            }
            if !spec.sha256.is_empty() && spec.sha256 != obs.sha256 {
                errs.push(ContractError::new(
                    code::OBSERVED_DIGEST_MISMATCH,
                    id,
                    "observed digest differs from the digest the contract records",
                ));
            }
            if spec.target.is_device() {
                if obs.elf_machine != spec.target.elf_machine() {
                    errs.push(ContractError::new(
                        code::ELF_MACHINE_MISMATCH,
                        id,
                        format!(
                            "ELF e_machine {} is not {} for target {}",
                            obs.elf_machine,
                            spec.target.elf_machine(),
                            spec.target.as_str()
                        ),
                    ));
                }
                if obs.elf_class != 1 || !obs.elf_big_endian {
                    errs.push(ContractError::new(
                        code::ELF_NOT_32BIT_BIG_ENDIAN,
                        id,
                        "a device artifact must be a 32-bit big-endian ELF",
                    ));
                }
            }
        }
        for (id, digests) in &digests_by_id {
            if digests.len() > 1 {
                errs.push(ContractError::new(
                    code::ARTIFACT_DIGEST_CONFLICT,
                    *id,
                    "one artifact id was reported with more than one digest",
                ));
            }
        }
        for (digest, targets) in &targets_by_digest {
            if targets.len() > 1 {
                errs.push(ContractError::new(
                    code::UNIVERSAL_ARTIFACT_CLAIM,
                    *digest,
                    "one digest was reported for more than one target",
                ));
            }
        }
        if require_all {
            let seen: BTreeSet<&str> = observed.iter().map(|obs| obs.id.as_str()).collect();
            for id in declared.keys() {
                if !seen.contains(id) {
                    errs.push(ContractError::new(
                        code::ARTIFACT_NOT_OBSERVED,
                        *id,
                        "declared artifact has no observation",
                    ));
                }
            }
        }
        errs.sort();
        errs.dedup();
        errs
    }
}

/// Evidence is bound only to the exact artifact (digest), target and profile it was gathered for.
fn binding_matches(art: &ArtifactSpec, evidence: &EvidenceBinding) -> bool {
    !art.sha256.is_empty()
        && evidence.artifact_sha256 == art.sha256
        && evidence.target == art.target
        && evidence.profile == art.profile
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_target_agrees_with_the_board_profile_isa() {
        for target in ArtifactTarget::ALL {
            match target.cpu_isa() {
                Some(isa) => {
                    assert_eq!(isa.target_triple(), Some(target.triple()), "{target:?}");
                    assert!(target.is_device());
                    assert_eq!(ArtifactTarget::from_triple(target.triple()), Some(target));
                }
                None => assert!(!target.is_device()),
            }
        }
        // No ARM target exists, and the host triple is not a device triple.
        assert_eq!(
            ArtifactTarget::from_triple("arm-unknown-linux-gnueabihf"),
            None
        );
        assert_eq!(ArtifactTarget::from_triple("host"), None);
    }

    #[test]
    fn target_strings_match_their_serde_names() {
        for target in ArtifactTarget::ALL {
            let json = serde_json::to_string(&target).expect("serializes");
            assert_eq!(json, format!("\"{}\"", target.as_str()));
        }
        assert!(serde_json::from_str::<ArtifactTarget>("\"arm_le\"").is_err());
    }

    #[test]
    fn elf_machines_are_distinct_for_the_two_device_isas() {
        assert_eq!(ArtifactTarget::MipsBe.elf_machine(), 8);
        assert_eq!(ArtifactTarget::PowerpcBe.elf_machine(), 20);
        assert_eq!(ArtifactTarget::Host.elf_machine(), 0);
        assert_ne!(
            ArtifactTarget::MipsBe.isa_label(),
            ArtifactTarget::PowerpcBe.isa_label()
        );
    }

    #[test]
    fn canonical_json_sorts_keys_and_is_compact() {
        let value: Value =
            serde_json::from_str(r#"{"b": [1, {"z": true, "a": null}], "a": "x\ny"}"#)
                .expect("valid json");
        assert_eq!(
            canonical_json_value(&value),
            r#"{"a":"x\ny","b":[1,{"a":null,"z":true}]}"#
        );
        let permuted: Value = serde_json::from_str(r#"{"a":"x\ny","b":[1,{"a":null,"z":true}]}"#)
            .expect("valid json");
        assert_eq!(
            canonical_json_value(&value),
            canonical_json_value(&permuted)
        );
    }

    fn graph(edges: &[(&str, Vec<&str>)]) -> Graph {
        edges
            .iter()
            .map(|(from, to)| {
                (
                    (*from).to_string(),
                    to.iter().map(|name| (*name).to_string()).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn cycle_detection_finds_each_component_once_and_ignores_acyclic_edges() {
        let acyclic = graph(&[("a", vec!["b", "c"]), ("b", vec!["c"]), ("c", vec![])]);
        assert!(cycles(&acyclic).is_empty());

        let two = graph(&[("a", vec!["b"]), ("b", vec!["a"]), ("c", vec!["a"])]);
        let found: Vec<Vec<String>> = cycles(&two).into_iter().collect();
        assert_eq!(found, vec![vec!["a".to_string(), "b".to_string()]]);

        let three = graph(&[
            ("a", vec!["b"]),
            ("b", vec!["c"]),
            ("c", vec!["a"]),
            ("d", vec![]),
        ]);
        let found: Vec<Vec<String>> = cycles(&three).into_iter().collect();
        assert_eq!(
            found,
            vec![vec!["a".to_string(), "b".to_string(), "c".to_string()]]
        );

        let two_separate = graph(&[
            ("a", vec!["b"]),
            ("b", vec!["a"]),
            ("x", vec!["y"]),
            ("y", vec!["x"]),
        ]);
        assert_eq!(cycles(&two_separate).len(), 2);

        // A self-loop is reported by its own code, not as a cycle.
        let looped = graph(&[("a", vec!["a"])]);
        assert!(cycles(&looped).is_empty());
    }

    #[test]
    fn closure_includes_the_start_and_everything_below_it() {
        let g = graph(&[
            ("a", vec!["b"]),
            ("b", vec!["c"]),
            ("c", vec![]),
            ("z", vec!["a"]),
        ]);
        let reach: Vec<String> = closure(&g, "a").into_iter().collect();
        assert_eq!(reach, vec!["a", "b", "c"]);
    }

    #[test]
    fn hex64_accepts_only_lowercase_sha256_text() {
        assert!(is_hex64(&"a".repeat(64)));
        assert!(!is_hex64(&"A".repeat(64)));
        assert!(!is_hex64(&"a".repeat(63)));
        assert!(!is_hex64(&"g".repeat(64)));
        assert!(!is_hex64(""));
    }
}
