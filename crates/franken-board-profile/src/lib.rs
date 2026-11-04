//! Board profile manifest and hardware identity reconciliation (`E01` / `ffw-xdi`).
//!
//! Evidence-binding rules enforced here (see `FIRMWARE_ASSESSMENT.md` and `inventory/INVENTORY.md`):
//!
//! - Every profile fact carries a [`FactStatus`]. A profile is *attested* only when every fact is
//!   [`FactStatus::Attested`]. [`canonical_board_catalog`] is a catalog of **non-admissible
//!   hypotheses**: nothing in the repository yet attests a hardware revision, an image-to-model
//!   join for the ISA, a measured output delay, a driver ABI or a kernel capability profile.
//! - Never derive CPU ISA, SoC or calibration from a model number or product era.
//!   Unknown stays [`CpuIsa::Unknown`] / [`FactStatus::Unknown`]; contradictory evidence is
//!   [`FactStatus::Contested`] and is never resolved by picking a side.
//! - [`BoardProfile::verify_integrity`] is the offline admission gate. It refuses hypothesis
//!   profiles. It accepts a clearly labelled [`EvidenceProvenance::SyntheticTestFixture`] profile
//!   (see [`synthetic_test_fixture_catalog`]) so simulation and tests can exercise the stack
//!   offline. Production admission is a separate update-design decision and does not exist yet.
//! - [`reconcile_inventory_observations`] decides activation eligibility for a real device. It
//!   additionally refuses synthetic fixtures and requires per-field evidence: a hardware revision
//!   that matches a row, ISA evidence from binary forensics that agrees with the row, and a
//!   nominal RAM value with an explicit unit that equals the row. MB and MiB are different byte
//!   counts; a bare number has no unit.
//! - Profile ids use the shared formula (see [`profile_id_for`]), identical to `identity.py`.
//!
//! Host checks here do not prove device operation.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const BOARD_PROFILE_SCHEMA_VERSION: &str = "ffw.board_profile.v2";

/// Text stored in a string fact that no evidence supports.
pub const UNVERIFIED: &str = "unverified";

const BYTES_PER_MIB: u64 = 1024 * 1024;

/// CPU instruction set and endianness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuIsa {
    PowerPc32BigEndian,
    Mips32R2BigEndian,
    Arm32LittleEndianUnverified,
    /// No evidence selects an ISA. Never inferred from a model number or product era.
    Unknown,
}

impl CpuIsa {
    #[must_use]
    pub const fn target_triple(self) -> Option<&'static str> {
        match self {
            Self::PowerPc32BigEndian => Some("powerpc-unknown-linux-musl"),
            Self::Mips32R2BigEndian => Some("mips-unknown-linux-musl"),
            Self::Arm32LittleEndianUnverified | Self::Unknown => None,
        }
    }

    /// Widest atomic the ISA is known to provide; `0` when the ISA is unknown.
    #[must_use]
    pub const fn max_atomic_width_bits(self) -> u8 {
        match self {
            Self::PowerPc32BigEndian
            | Self::Mips32R2BigEndian
            | Self::Arm32LittleEndianUnverified => 32,
            Self::Unknown => 0,
        }
    }
}

/// Evidence provenance level for each field or profile attribute.
///
/// Declaration order is evidence strength: a smaller discriminant is stronger evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProvenance {
    /// Directly extracted from a decrypted firmware image / ELF / kernel module.
    DirectBinaryForensics,
    /// Captured from read-only LAN UPnP `/xml/device_description.xml` + `/status/zp`.
    /// These carry no CPU information.
    SanitizedInventoryObservation,
    /// Conservative bound from `FIRMWARE_ASSESSMENT.md` or a published teardown. Not admissible.
    AssessmentHypothesis,
    /// Fabricated data for offline simulation and tests. Never evidence of any real board.
    SyntheticTestFixture,
}

/// Evidence status of one profile fact. Only [`FactStatus::Attested`] (and, offline only,
/// [`FactStatus::SyntheticFixture`]) supports admission. The default is the fail-closed one.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FactStatus {
    /// Nothing supports a value.
    #[default]
    Unknown,
    /// A published teardown or assessment suggests a value; no attested join to this unit.
    Hypothesis,
    /// Two sources disagree; no side is picked.
    Contested,
    /// The device reported a number, but its unit or meaning is not established.
    DeviceReported,
    /// Established by evidence bound to this model and revision.
    Attested,
    /// Fabricated for offline simulation and tests.
    SyntheticFixture,
}

/// Evidence status of each fact a board profile asserts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FactStatuses {
    pub hardware_revision: FactStatus,
    pub isa: FactStatus,
    pub nominal_capacity: FactStatus,
    pub calibration: FactStatus,
    pub driver_and_routing: FactStatus,
    pub kernel_capability: FactStatus,
}

impl FactStatuses {
    /// Every fact has the same status.
    #[must_use]
    pub const fn uniform(status: FactStatus) -> Self {
        Self {
            hardware_revision: status,
            isa: status,
            nominal_capacity: status,
            calibration: status,
            driver_and_routing: status,
            kernel_capability: status,
        }
    }

    fn entries(&self) -> [(&'static str, FactStatus); 6] {
        [
            ("hardware_revision", self.hardware_revision),
            ("isa", self.isa),
            ("nominal_capacity", self.nominal_capacity),
            ("calibration", self.calibration),
            ("driver_and_routing", self.driver_and_routing),
            ("kernel_capability", self.kernel_capability),
        ]
    }

    /// Names of the facts whose status does not support admission.
    #[must_use]
    pub fn unattested(&self, allow_synthetic: bool) -> Vec<&'static str> {
        let mut missing = Vec::new();
        for (name, status) in self.entries() {
            let supported = status == FactStatus::Attested
                || (allow_synthetic && status == FactStatus::SyntheticFixture);
            if !supported {
                missing.push(name);
            }
        }
        missing
    }
}

/// Physical transducer driver role assigned to a hardware TDM/I2S output channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransducerRole {
    TweeterLeft,
    TweeterRight,
    MidLeft,
    MidRight,
    WooferCenter,
    WooferMono,
    TweeterMono,
    SubwooferLfe,
    ArrayMidWoofer(u8),
    ArrayTweeter(u8),
}

/// Amplifier safety policy for a profile or reconciliation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmplifierPolicy {
    /// Safe startup order required: assert hardware mute pin -> configure DAC/DSP -> prime silence -> unmute.
    AdmittedSafeStartupOrder,
    /// Offline decode sink only; hardware amplifier enablement is strictly forbidden.
    ForbiddenFailMuted,
}

/// Structured reason code when a device observation cannot be admitted to an audio board profile.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedReasonCode {
    MissingHardwareRevision,
    UnknownModelOrRevision {
        model_number: String,
        hw_rev: String,
    },
    ConflictingIsaEvidence {
        observed_isas: Vec<CpuIsa>,
    },
    ConflictingHardwareRevision {
        observed_revisions: Vec<String>,
    },
    ConflictingModelNumber {
        observed_models: Vec<String>,
    },
    UnknownMemoryUnit {
        raw_unit: String,
    },
    NonAudioAppliance {
        model_number: String,
    },
    ProfileDigestMismatch {
        expected_sha256: String,
        computed_sha256: String,
    },
    /// The matched profile is a hypothesis or synthetic fixture, or some of its facts are unattested.
    UnattestedProfile {
        profile_id: String,
        unattested_facts: Vec<String>,
    },
    /// No observation carried ISA evidence. An ISA is never taken from the catalog row alone.
    MissingIsaEvidence,
    /// ISA evidence came from a source that cannot establish a CPU (inventory XML, assessment).
    InsufficientIsaEvidence {
        provenance: EvidenceProvenance,
    },
    MissingNominalRam,
    NominalRamMismatch {
        observed_bytes: u64,
        profile_bytes: u64,
    },
    ConflictingNominalRam {
        observed_bytes: Vec<u64>,
    },
    /// A model number or hardware revision is not in the accepted grammar.
    MalformedIdentityField {
        field: String,
    },
}

/// Versioned board profile binding hardware revision, ISA, audio routing, and calibration bounds.
///
/// Numeric and string fields are only as good as the matching entry in [`BoardProfile::facts`];
/// a value whose fact is not attested is a hypothesis (or a zero/`unverified` placeholder).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardProfile {
    pub schema_version: String,
    pub profile_id: String,
    pub model_number: String,
    pub model_name: String,
    pub supported_hw_rev: String,
    /// Hint only. Software generation is per-device state, not board identity.
    pub legacy_sw_gen_hint: u8,
    pub cpu_isa: CpuIsa,
    pub float_abi: String,
    pub max_atomic_width_bits: u8,
    pub nominal_ram_mib: u32,
    pub nominal_flash_mib: u32,
    pub kernel_capability_profile: String,
    pub audio_driver_abi: String,
    pub hardware_channels: u8,
    pub channel_routing: Vec<TransducerRole>,
    pub amplifier_policy: AmplifierPolicy,
    pub calibrated_output_delay_us: u32,
    pub calibration_uncertainty_us: u32,
    pub provenance: EvidenceProvenance,
    /// Missing in serialized data means every fact is unknown (fail closed).
    #[serde(default)]
    pub facts: FactStatuses,
    pub integrity_sha256: String,
}

impl BoardProfile {
    /// Compute canonical SHA-256 digest over all fields except `integrity_sha256`.
    #[must_use]
    pub fn compute_digest(&self) -> String {
        let mut clone = self.clone();
        clone.integrity_sha256.clear();
        let canonical = serde_json::to_vec(&clone).unwrap_or_default();
        hex::encode(Sha256::digest(canonical))
    }

    #[must_use]
    pub fn with_computed_digest(mut self) -> Self {
        self.integrity_sha256 = self.compute_digest();
        self
    }

    #[must_use]
    pub fn is_synthetic_fixture(&self) -> bool {
        self.provenance == EvidenceProvenance::SyntheticTestFixture
    }

    fn unattested_facts(&self, allow_synthetic: bool) -> Vec<String> {
        let mut missing: Vec<String> = self
            .facts
            .unattested(allow_synthetic)
            .into_iter()
            .map(str::to_string)
            .collect();
        let provenance_supported = match self.provenance {
            EvidenceProvenance::AssessmentHypothesis => false,
            EvidenceProvenance::SyntheticTestFixture => allow_synthetic,
            EvidenceProvenance::DirectBinaryForensics
            | EvidenceProvenance::SanitizedInventoryObservation => true,
        };
        if !provenance_supported {
            missing.push("provenance".to_string());
        }
        missing
    }

    /// Facts that keep this profile from activating a real device. Synthetic fixtures never
    /// qualify here, so a non-empty list also covers every fixture.
    #[must_use]
    pub fn activation_blockers(&self) -> Vec<String> {
        self.unattested_facts(false)
    }

    fn non_audio(&self) -> UnsupportedReasonCode {
        UnsupportedReasonCode::NonAudioAppliance {
            model_number: self.model_number.clone(),
        }
    }

    /// Offline admission gate: digest, audio capability, then evidence.
    ///
    /// Hypothesis profiles are refused. Synthetic fixtures are accepted (offline simulation and
    /// tests only). Real-device activation additionally requires [`Self::activation_blockers`] to
    /// be empty, which [`reconcile_inventory_observations`] enforces.
    pub fn verify_integrity(&self) -> Result<(), UnsupportedReasonCode> {
        let computed = self.compute_digest();
        if self.integrity_sha256 != computed {
            return Err(UnsupportedReasonCode::ProfileDigestMismatch {
                expected_sha256: self.integrity_sha256.clone(),
                computed_sha256: computed,
            });
        }
        if self.hardware_channels == 0 {
            return Err(self.non_audio());
        }
        let unattested = self.unattested_facts(self.is_synthetic_fixture());
        if !unattested.is_empty() {
            return Err(UnsupportedReasonCode::UnattestedProfile {
                profile_id: self.profile_id.clone(),
                unattested_facts: unattested,
            });
        }
        if self.amplifier_policy == AmplifierPolicy::ForbiddenFailMuted {
            return Err(self.non_audio());
        }
        Ok(())
    }
}

/// Canonical model number: ASCII alphanumerics plus `_ . -`, 1 to 24 characters, upper-cased.
/// Same grammar as `identity.py`.
#[must_use]
pub fn canonical_model_number(raw: &str) -> Option<String> {
    let s = raw.trim();
    let first = s.chars().next()?;
    if s.len() > 24
        || !first.is_ascii_alphanumeric()
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return None;
    }
    Some(s.to_ascii_uppercase())
}

fn canonical_dotted(part: &str, min: usize, max: usize) -> Option<String> {
    let components: Vec<&str> = part.split('.').collect();
    if components.len() < min || components.len() > max {
        return None;
    }
    let mut out = Vec::with_capacity(components.len());
    for component in components {
        if component.is_empty()
            || component.len() > 5
            || !component.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        out.push(component.parse::<u32>().ok()?.to_string());
    }
    Some(out.join("."))
}

/// Canonical hardware revision: 1 to 6 dotted numbers, optionally `-` and 1 to 4 dotted numbers,
/// each at most 5 digits, leading zeros removed. Same grammar as `identity.py`.
#[must_use]
pub fn canonical_hardware_revision(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s.len() > 32 {
        return None;
    }
    let (main, suffix) = match s.split_once('-') {
        Some((main, suffix)) => (main, Some(suffix)),
        None => (s, None),
    };
    let main = canonical_dotted(main, 1, 6)?;
    match suffix {
        None => Some(main),
        Some(suffix) => Some(format!("{main}-{}", canonical_dotted(suffix, 1, 4)?)),
    }
}

/// Shared board-profile id: `bp-` plus the first 16 hex characters of the SHA-256 of the compact,
/// key-sorted JSON `{"hardware_revision","kind":"board-profile-id","product_model","schema":"ffw.identity/v1"}`
/// built from the canonical model and revision. Identical to `identity.profile_id_for`.
/// `None` when either input is outside the accepted grammar.
#[must_use]
pub fn profile_id_for(model_number: &str, hw_rev: &str) -> Option<String> {
    let model = canonical_model_number(model_number)?;
    let rev = canonical_hardware_revision(hw_rev)?;
    let canonical = format!(
        "{{\"hardware_revision\":\"{rev}\",\"kind\":\"board-profile-id\",\"product_model\":\"{model}\",\"schema\":\"ffw.identity/v1\"}}"
    );
    let digest = hex::encode(Sha256::digest(canonical.as_bytes()));
    Some(format!("bp-{}", &digest[..16]))
}

/// Device-reported nominal RAM and flash, in the device's own (unit-unstated) numbers, from
/// `inventory/INVENTORY.md`. This is the only capacity evidence in the repository.
fn device_reported_capacity_mib(model_number: &str) -> Option<(u32, u32)> {
    match canonical_model_number(model_number)?.as_str() {
        "S5" => Some((32, 32)),
        "S1" => Some((128, 64)),
        "S12" => Some((256, 256)),
        "S3" | "SUB" => Some((128, 64)),
        "S9" => Some((128, 128)),
        "ZB100" | "BR100" => Some((8, 8)),
        _ => None,
    }
}

struct HypothesisSpec {
    model_number: &'static str,
    model_name: &'static str,
    hw_rev: &'static str,
    sw_gen_hint: u8,
    isa: CpuIsa,
    isa_status: FactStatus,
    routing: Vec<TransducerRole>,
}

fn hypothesis_profile(spec: HypothesisSpec) -> BoardProfile {
    let (ram, flash) = device_reported_capacity_mib(spec.model_number)
        .expect("every hypothesis row has a device-reported capacity");
    let channels = u8::try_from(spec.routing.len()).expect("channel count fits in u8");
    let driver_status = if spec.routing.is_empty() {
        FactStatus::Unknown
    } else {
        FactStatus::Hypothesis
    };
    BoardProfile {
        schema_version: BOARD_PROFILE_SCHEMA_VERSION.to_string(),
        profile_id: profile_id_for(spec.model_number, spec.hw_rev)
            .expect("every hypothesis row has a canonical model and revision"),
        model_number: spec.model_number.to_string(),
        model_name: spec.model_name.to_string(),
        supported_hw_rev: spec.hw_rev.to_string(),
        legacy_sw_gen_hint: spec.sw_gen_hint,
        cpu_isa: spec.isa,
        float_abi: UNVERIFIED.to_string(),
        max_atomic_width_bits: spec.isa.max_atomic_width_bits(),
        nominal_ram_mib: ram,
        nominal_flash_mib: flash,
        kernel_capability_profile: UNVERIFIED.to_string(),
        audio_driver_abi: UNVERIFIED.to_string(),
        hardware_channels: channels,
        channel_routing: spec.routing,
        amplifier_policy: AmplifierPolicy::ForbiddenFailMuted,
        calibrated_output_delay_us: 0,
        calibration_uncertainty_us: 0,
        provenance: EvidenceProvenance::AssessmentHypothesis,
        facts: FactStatuses {
            hardware_revision: FactStatus::Hypothesis,
            isa: spec.isa_status,
            nominal_capacity: FactStatus::DeviceReported,
            calibration: FactStatus::Unknown,
            driver_and_routing: driver_status,
            kernel_capability: FactStatus::Unknown,
        },
        integrity_sha256: String::new(),
    }
    .with_computed_digest()
}

/// The repository's board catalog: nine rows, **every one a non-admissible hypothesis**.
///
/// - Capacities are the device-reported numbers from `inventory/INVENTORY.md` (unit unstated).
/// - The hardware-revision strings are unattested. None appears in the sanitized inventory, and an
///   offline comparison with the owner-local `device_description.xml` captures found 0 of these 9
///   (model, revision) pairs on any unit. Real values carry a two-component suffix (shape
///   `1.2.3.4-5.6`), unlike these. A row only matches an observation stating the same revision.
/// - ISA: only the S5 and S3 (PowerPC) and S12 (Arm) rows carry a hypothesis, from published
///   teardowns and an unjoined ELF header. S1 evidence conflicts (`Contested`), and Sub, Playbar
///   and the Bridge have no ISA evidence (`Unknown`).
/// - Float ABI, kernel capability, driver ABI strings and the calibrated delay are not
///   established and are stored as `unverified` / `0` with status `Unknown`.
/// - Channel routing is a teardown hypothesis; the amplifier policy is `ForbiddenFailMuted`.
#[must_use]
pub fn canonical_board_catalog() -> Vec<BoardProfile> {
    let playbar_routing: Vec<TransducerRole> = (0..6)
        .map(TransducerRole::ArrayMidWoofer)
        .chain((0..3).map(TransducerRole::ArrayTweeter))
        .collect();
    vec![
        hypothesis_profile(HypothesisSpec {
            model_number: "S5",
            model_name: "Play:5 (Gen 1)",
            hw_rev: "1.16.3.1-2",
            sw_gen_hint: 1,
            isa: CpuIsa::PowerPc32BigEndian,
            isa_status: FactStatus::Hypothesis,
            routing: vec![
                TransducerRole::TweeterLeft,
                TransducerRole::TweeterRight,
                TransducerRole::MidLeft,
                TransducerRole::MidRight,
                TransducerRole::WooferCenter,
            ],
        }),
        hypothesis_profile(HypothesisSpec {
            model_number: "S1",
            model_name: "Play:1 (Rev 1)",
            hw_rev: "1.8.3.7-1",
            sw_gen_hint: 2,
            isa: CpuIsa::Unknown,
            isa_status: FactStatus::Contested,
            routing: vec![TransducerRole::WooferMono, TransducerRole::TweeterMono],
        }),
        hypothesis_profile(HypothesisSpec {
            model_number: "S1",
            model_name: "Play:1 (Rev 2)",
            hw_rev: "1.8.3.7-2",
            sw_gen_hint: 2,
            isa: CpuIsa::Unknown,
            isa_status: FactStatus::Contested,
            routing: vec![TransducerRole::WooferMono, TransducerRole::TweeterMono],
        }),
        hypothesis_profile(HypothesisSpec {
            model_number: "S12",
            model_name: "Play:1 (S2 Edition)",
            hw_rev: "1.20.1.6-2",
            sw_gen_hint: 2,
            isa: CpuIsa::Arm32LittleEndianUnverified,
            isa_status: FactStatus::Hypothesis,
            routing: vec![TransducerRole::WooferMono, TransducerRole::TweeterMono],
        }),
        hypothesis_profile(HypothesisSpec {
            model_number: "S3",
            model_name: "Play:3 (Rev 1)",
            hw_rev: "1.8.1.2-1",
            sw_gen_hint: 2,
            isa: CpuIsa::PowerPc32BigEndian,
            isa_status: FactStatus::Hypothesis,
            routing: vec![
                TransducerRole::MidLeft,
                TransducerRole::MidRight,
                TransducerRole::TweeterMono,
            ],
        }),
        hypothesis_profile(HypothesisSpec {
            model_number: "S3",
            model_name: "Play:3 (Rev 2)",
            hw_rev: "1.8.1.2-2",
            sw_gen_hint: 2,
            isa: CpuIsa::PowerPc32BigEndian,
            isa_status: FactStatus::Hypothesis,
            routing: vec![
                TransducerRole::MidLeft,
                TransducerRole::MidRight,
                TransducerRole::TweeterMono,
            ],
        }),
        hypothesis_profile(HypothesisSpec {
            model_number: "Sub",
            model_name: "Sonos Sub (Gen 1/2)",
            hw_rev: "1.8.2.4-2",
            sw_gen_hint: 2,
            isa: CpuIsa::Unknown,
            isa_status: FactStatus::Unknown,
            routing: vec![TransducerRole::SubwooferLfe],
        }),
        hypothesis_profile(HypothesisSpec {
            model_number: "S9",
            model_name: "Playbar",
            hw_rev: "1.9.1.10-2",
            sw_gen_hint: 1,
            isa: CpuIsa::Unknown,
            isa_status: FactStatus::Unknown,
            routing: playbar_routing,
        }),
        hypothesis_profile(HypothesisSpec {
            model_number: "ZB100",
            model_name: "Sonos Bridge (Non-Audio)",
            hw_rev: "1.5.0.0-1",
            sw_gen_hint: 1,
            isa: CpuIsa::Unknown,
            isa_status: FactStatus::Unknown,
            routing: Vec::new(),
        }),
    ]
}

/// **Synthetic** catalog for offline simulation and tests. Not evidence of any real board.
///
/// Same shape and values the stack was developed against (so consumer behaviour such as the S5
/// calibrated delay is unchanged), except nominal RAM and flash, which use the device-reported
/// numbers. Every row is [`EvidenceProvenance::SyntheticTestFixture`] with
/// [`FactStatus::SyntheticFixture`] facts: [`BoardProfile::verify_integrity`] accepts them,
/// [`BoardProfile::activation_blockers`] never does, and reconciliation never makes a device
/// eligible against them. The Bridge keeps its legacy label `BR100`.
#[must_use]
pub fn synthetic_test_fixture_catalog() -> Vec<BoardProfile> {
    legacy_synthetic_rows()
        .into_iter()
        .map(|mut profile| {
            if let Some((ram, flash)) = device_reported_capacity_mib(&profile.model_number) {
                profile.nominal_ram_mib = ram;
                profile.nominal_flash_mib = flash;
            }
            profile.provenance = EvidenceProvenance::SyntheticTestFixture;
            profile.facts = FactStatuses::uniform(FactStatus::SyntheticFixture);
            profile.with_computed_digest()
        })
        .collect()
}

/// The pre-repair catalog rows, kept verbatim as the source of the synthetic fixtures.
/// Their provenance, facts and capacities are overwritten by [`synthetic_test_fixture_catalog`].
fn legacy_synthetic_rows() -> Vec<BoardProfile> {
    vec![
        BoardProfile {
            schema_version: BOARD_PROFILE_SCHEMA_VERSION.to_string(),
            profile_id: "sonos-s5-ppc-rev-1.16.3.1-2".to_string(),
            model_number: "S5".to_string(),
            model_name: "Play:5 (Gen 1)".to_string(),
            supported_hw_rev: "1.16.3.1-2".to_string(),
            legacy_sw_gen_hint: 1,
            cpu_isa: CpuIsa::PowerPc32BigEndian,
            float_abi: "hard-float-ppc32".to_string(),
            max_atomic_width_bits: 32,
            nominal_ram_mib: 64,
            nominal_flash_mib: 64,
            kernel_capability_profile: "linux-2.6.14-ppc32-be".to_string(),
            audio_driver_abi: "audiodev.o-cs44800-5ch-tdm".to_string(),
            hardware_channels: 5,
            channel_routing: vec![
                TransducerRole::TweeterLeft,
                TransducerRole::TweeterRight,
                TransducerRole::MidLeft,
                TransducerRole::MidRight,
                TransducerRole::WooferCenter,
            ],
            amplifier_policy: AmplifierPolicy::AdmittedSafeStartupOrder,
            calibrated_output_delay_us: 1_850,
            calibration_uncertainty_us: 150,
            provenance: EvidenceProvenance::DirectBinaryForensics,
            facts: FactStatuses::default(),
            integrity_sha256: String::new(),
        }
        .with_computed_digest(),
        BoardProfile {
            schema_version: BOARD_PROFILE_SCHEMA_VERSION.to_string(),
            profile_id: "sonos-s1-mips-rev-1.8.3.7-1".to_string(),
            model_number: "S1".to_string(),
            model_name: "Play:1 (Rev 1)".to_string(),
            supported_hw_rev: "1.8.3.7-1".to_string(),
            legacy_sw_gen_hint: 1,
            cpu_isa: CpuIsa::Mips32R2BigEndian,
            float_abi: "soft-float-mips32r2-o32".to_string(),
            max_atomic_width_bits: 32,
            nominal_ram_mib: 128,
            nominal_flash_mib: 64,
            kernel_capability_profile: "linux-2.6.35-mips32r2-be".to_string(),
            audio_driver_abi: "audiodev-ar9344-i2s-tpa3116-2ch".to_string(),
            hardware_channels: 2,
            channel_routing: vec![TransducerRole::WooferMono, TransducerRole::TweeterMono],
            amplifier_policy: AmplifierPolicy::AdmittedSafeStartupOrder,
            calibrated_output_delay_us: 1_400,
            calibration_uncertainty_us: 200,
            provenance: EvidenceProvenance::SanitizedInventoryObservation,
            facts: FactStatuses::default(),
            integrity_sha256: String::new(),
        }
        .with_computed_digest(),
        BoardProfile {
            schema_version: BOARD_PROFILE_SCHEMA_VERSION.to_string(),
            profile_id: "sonos-s1-mips-rev-1.8.3.7-2".to_string(),
            model_number: "S1".to_string(),
            model_name: "Play:1 (Rev 2)".to_string(),
            supported_hw_rev: "1.8.3.7-2".to_string(),
            legacy_sw_gen_hint: 1,
            cpu_isa: CpuIsa::Mips32R2BigEndian,
            float_abi: "soft-float-mips32r2-o32".to_string(),
            max_atomic_width_bits: 32,
            nominal_ram_mib: 128,
            nominal_flash_mib: 64,
            kernel_capability_profile: "linux-2.6.35-mips32r2-be".to_string(),
            audio_driver_abi: "audiodev-ar9344-i2s-tpa3116-2ch".to_string(),
            hardware_channels: 2,
            channel_routing: vec![TransducerRole::WooferMono, TransducerRole::TweeterMono],
            amplifier_policy: AmplifierPolicy::AdmittedSafeStartupOrder,
            calibrated_output_delay_us: 1_400,
            calibration_uncertainty_us: 200,
            provenance: EvidenceProvenance::SanitizedInventoryObservation,
            facts: FactStatuses::default(),
            integrity_sha256: String::new(),
        }
        .with_computed_digest(),
        BoardProfile {
            schema_version: BOARD_PROFILE_SCHEMA_VERSION.to_string(),
            profile_id: "sonos-s12-mips-rev-1.20.1.6-2".to_string(),
            model_number: "S12".to_string(),
            model_name: "Play:1 (S2 Edition)".to_string(),
            supported_hw_rev: "1.20.1.6-2".to_string(),
            legacy_sw_gen_hint: 2,
            cpu_isa: CpuIsa::Mips32R2BigEndian,
            float_abi: "soft-float-mips32r2-o32".to_string(),
            max_atomic_width_bits: 32,
            nominal_ram_mib: 128,
            nominal_flash_mib: 64,
            kernel_capability_profile: "linux-2.6.35-mips32r2-be".to_string(),
            audio_driver_abi: "audiodev-ar9344-i2s-tpa3116-2ch".to_string(),
            hardware_channels: 2,
            channel_routing: vec![TransducerRole::WooferMono, TransducerRole::TweeterMono],
            amplifier_policy: AmplifierPolicy::AdmittedSafeStartupOrder,
            calibrated_output_delay_us: 1_400,
            calibration_uncertainty_us: 200,
            provenance: EvidenceProvenance::SanitizedInventoryObservation,
            facts: FactStatuses::default(),
            integrity_sha256: String::new(),
        }
        .with_computed_digest(),
        BoardProfile {
            schema_version: BOARD_PROFILE_SCHEMA_VERSION.to_string(),
            profile_id: "sonos-s3-ppc-rev-1.8.1.2-1".to_string(),
            model_number: "S3".to_string(),
            model_name: "Play:3 (Rev 1)".to_string(),
            supported_hw_rev: "1.8.1.2-1".to_string(),
            legacy_sw_gen_hint: 1,
            cpu_isa: CpuIsa::PowerPc32BigEndian,
            float_abi: "hard-float-ppc32".to_string(),
            max_atomic_width_bits: 32,
            nominal_ram_mib: 64,
            nominal_flash_mib: 64,
            kernel_capability_profile: "linux-2.6.x-ppc32-be".to_string(),
            audio_driver_abi: "audiodev-mpc8314e-sta339bw-3ch".to_string(),
            hardware_channels: 3,
            channel_routing: vec![
                TransducerRole::MidLeft,
                TransducerRole::MidRight,
                TransducerRole::TweeterMono,
            ],
            amplifier_policy: AmplifierPolicy::AdmittedSafeStartupOrder,
            calibrated_output_delay_us: 1_750,
            calibration_uncertainty_us: 250,
            provenance: EvidenceProvenance::AssessmentHypothesis,
            facts: FactStatuses::default(),
            integrity_sha256: String::new(),
        }
        .with_computed_digest(),
        BoardProfile {
            schema_version: BOARD_PROFILE_SCHEMA_VERSION.to_string(),
            profile_id: "sonos-s3-ppc-rev-1.8.1.2-2".to_string(),
            model_number: "S3".to_string(),
            model_name: "Play:3 (Rev 2)".to_string(),
            supported_hw_rev: "1.8.1.2-2".to_string(),
            legacy_sw_gen_hint: 1,
            cpu_isa: CpuIsa::PowerPc32BigEndian,
            float_abi: "hard-float-ppc32".to_string(),
            max_atomic_width_bits: 32,
            nominal_ram_mib: 64,
            nominal_flash_mib: 64,
            kernel_capability_profile: "linux-2.6.x-ppc32-be".to_string(),
            audio_driver_abi: "audiodev-mpc8314e-sta339bw-3ch".to_string(),
            hardware_channels: 3,
            channel_routing: vec![
                TransducerRole::MidLeft,
                TransducerRole::MidRight,
                TransducerRole::TweeterMono,
            ],
            amplifier_policy: AmplifierPolicy::AdmittedSafeStartupOrder,
            calibrated_output_delay_us: 1_750,
            calibration_uncertainty_us: 250,
            provenance: EvidenceProvenance::AssessmentHypothesis,
            facts: FactStatuses::default(),
            integrity_sha256: String::new(),
        }
        .with_computed_digest(),
        BoardProfile {
            schema_version: BOARD_PROFILE_SCHEMA_VERSION.to_string(),
            profile_id: "sonos-sub-ppc-rev-1.8.2.4-2".to_string(),
            model_number: "Sub".to_string(),
            model_name: "Sonos Sub (Gen 1/2)".to_string(),
            supported_hw_rev: "1.8.2.4-2".to_string(),
            legacy_sw_gen_hint: 1,
            cpu_isa: CpuIsa::PowerPc32BigEndian,
            float_abi: "hard-float-ppc32".to_string(),
            max_atomic_width_bits: 32,
            nominal_ram_mib: 64,
            nominal_flash_mib: 64,
            kernel_capability_profile: "linux-2.6.x-ppc32-be".to_string(),
            audio_driver_abi: "audiodev-mpc8314e-sub-lfe-1ch".to_string(),
            hardware_channels: 1,
            channel_routing: vec![TransducerRole::SubwooferLfe],
            amplifier_policy: AmplifierPolicy::AdmittedSafeStartupOrder,
            calibrated_output_delay_us: 2_200,
            calibration_uncertainty_us: 300,
            provenance: EvidenceProvenance::AssessmentHypothesis,
            facts: FactStatuses::default(),
            integrity_sha256: String::new(),
        }
        .with_computed_digest(),
        BoardProfile {
            schema_version: BOARD_PROFILE_SCHEMA_VERSION.to_string(),
            profile_id: "sonos-s9-ppc-rev-1.9.1.10-2".to_string(),
            model_number: "S9".to_string(),
            model_name: "Playbar".to_string(),
            supported_hw_rev: "1.9.1.10-2".to_string(),
            legacy_sw_gen_hint: 1,
            cpu_isa: CpuIsa::PowerPc32BigEndian,
            float_abi: "hard-float-ppc32".to_string(),
            max_atomic_width_bits: 32,
            nominal_ram_mib: 128,
            nominal_flash_mib: 64,
            kernel_capability_profile: "linux-2.6.x-ppc32-be".to_string(),
            audio_driver_abi: "audiodev-mpc8377e-playbar-9ch".to_string(),
            hardware_channels: 9,
            channel_routing: vec![
                TransducerRole::ArrayMidWoofer(0),
                TransducerRole::ArrayMidWoofer(1),
                TransducerRole::ArrayMidWoofer(2),
                TransducerRole::ArrayMidWoofer(3),
                TransducerRole::ArrayMidWoofer(4),
                TransducerRole::ArrayMidWoofer(5),
                TransducerRole::ArrayTweeter(0),
                TransducerRole::ArrayTweeter(1),
                TransducerRole::ArrayTweeter(2),
            ],
            amplifier_policy: AmplifierPolicy::AdmittedSafeStartupOrder,
            calibrated_output_delay_us: 1_900,
            calibration_uncertainty_us: 250,
            provenance: EvidenceProvenance::AssessmentHypothesis,
            facts: FactStatuses::default(),
            integrity_sha256: String::new(),
        }
        .with_computed_digest(),
        BoardProfile {
            schema_version: BOARD_PROFILE_SCHEMA_VERSION.to_string(),
            profile_id: "sonos-br100-bridge-rev-1.5.0.0-1".to_string(),
            model_number: "BR100".to_string(),
            model_name: "Sonos Bridge (Non-Audio)".to_string(),
            supported_hw_rev: "1.5.0.0-1".to_string(),
            legacy_sw_gen_hint: 1,
            cpu_isa: CpuIsa::Arm32LittleEndianUnverified,
            float_abi: "soft-float-arm".to_string(),
            max_atomic_width_bits: 32,
            nominal_ram_mib: 32,
            nominal_flash_mib: 16,
            kernel_capability_profile: "linux-2.4.26-arm-unverified".to_string(),
            audio_driver_abi: "none-non-audio-bridge".to_string(),
            hardware_channels: 0,
            channel_routing: Vec::new(),
            amplifier_policy: AmplifierPolicy::ForbiddenFailMuted,
            calibrated_output_delay_us: 0,
            calibration_uncertainty_us: 0,
            provenance: EvidenceProvenance::AssessmentHypothesis,
            facts: FactStatuses::default(),
            integrity_sha256: String::new(),
        }
        .with_computed_digest(),
    ]
}

/// ISA evidence for one observation, with its own provenance. An ISA only counts when it comes
/// from binary forensics; inventory XML carries no CPU information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsaEvidence {
    pub isa: CpuIsa,
    pub provenance: EvidenceProvenance,
}

/// Sanitized observation of a device from inventory or binary forensics.
/// Contains no real IPs, MACs, serial numbers, or household IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizedDeviceObservation {
    /// Pseudonymous stable device slot ID (e.g. `dev-slot-01`).
    pub pseudonymous_device_id: String,
    /// Optional ephemeral network endpoint label (may change across observations).
    pub endpoint_hint: Option<String>,
    /// Optional room display label (may be renamed by user across observations).
    pub room_label_hint: Option<String>,
    pub model_number: String,
    pub hw_rev: Option<String>,
    pub isa_evidence: Option<IsaEvidence>,
    /// Nominal RAM as text with an explicit unit (`"64 MiB"`, `"64 MB"`). A bare number is rejected.
    pub nominal_ram_spec: Option<String>,
    /// Source of the identity fields (model, revision, RAM). Clamped to inventory strength: an
    /// inventory observation cannot claim to be binary forensics.
    pub provenance: EvidenceProvenance,
}

/// Result of reconciling one or more observations for a pseudonymous device slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciledDeviceRecord {
    pub pseudonymous_device_id: String,
    pub eligible_for_audio_activation: bool,
    pub selected_profile_id: Option<String>,
    pub amplifier_policy: AmplifierPolicy,
    /// Strongest evidence actually used: binary-forensics ISA evidence if it was accepted,
    /// otherwise the (clamped) identity provenance.
    pub highest_provenance: EvidenceProvenance,
    pub observed_room_labels: Vec<String>,
    pub observed_endpoint_hints: Vec<String>,
    pub unresolved_reasons: Vec<UnsupportedReasonCode>,
}

/// Parse a nominal size such as `"64 MiB"` or `"128MB"` into bytes.
///
/// Grammar: ASCII digits, at most one ASCII space, then one of `B KiB MiB GiB KB MB GB`
/// (case-sensitive). `MB` is 10^6 bytes and `MiB` is 2^20; they are never conflated. A bare
/// number, an unknown unit, zero, a tab/NBSP/extra space, or overflow is `UnknownMemoryUnit`.
pub fn parse_nominal_bytes(spec: &str) -> Result<u64, UnsupportedReasonCode> {
    let unknown = || UnsupportedReasonCode::UnknownMemoryUnit {
        raw_unit: spec.chars().take(32).collect(),
    };
    let trimmed = spec.trim();
    let digits_end = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (digits, rest) = trimmed.split_at(digits_end);
    if digits.is_empty() || digits.len() > 15 {
        return Err(unknown());
    }
    let unit = rest.strip_prefix(' ').unwrap_or(rest);
    let factor: u64 = match unit {
        "B" => 1,
        "KiB" => 1 << 10,
        "MiB" => 1 << 20,
        "GiB" => 1 << 30,
        "KB" => 1_000,
        "MB" => 1_000_000,
        "GB" => 1_000_000_000,
        _ => return Err(unknown()),
    };
    let value: u64 = digits.parse().map_err(|_| unknown())?;
    if value == 0 {
        return Err(unknown());
    }
    value.checked_mul(factor).ok_or_else(unknown)
}

fn push_unique<T: PartialEq>(items: &mut Vec<T>, item: T) {
    if !items.contains(&item) {
        items.push(item);
    }
}

/// An inventory-sourced observation cannot be stronger than inventory evidence.
fn clamp_identity_provenance(provenance: EvidenceProvenance) -> EvidenceProvenance {
    if (provenance as u8) < (EvidenceProvenance::SanitizedInventoryObservation as u8) {
        EvidenceProvenance::SanitizedInventoryObservation
    } else {
        provenance
    }
}

fn row_matches(profile: &BoardProfile, model: &str, rev: &str) -> bool {
    canonical_model_number(&profile.model_number).as_deref() == Some(model)
        && canonical_hardware_revision(&profile.supported_hw_rev).as_deref() == Some(rev)
}

fn check_matched_profile(
    profile: &BoardProfile,
    isas: &[CpuIsa],
    rams: &[u64],
    reasons: &mut Vec<UnsupportedReasonCode>,
) {
    match profile.verify_integrity() {
        Err(reason) => reasons.push(reason),
        Ok(()) => {
            // Passed the offline gate; real-device activation never accepts synthetic fixtures.
            let blockers = profile.activation_blockers();
            if !blockers.is_empty() {
                reasons.push(UnsupportedReasonCode::UnattestedProfile {
                    profile_id: profile.profile_id.clone(),
                    unattested_facts: blockers,
                });
            }
        }
    }
    if let [observed] = isas
        && *observed != profile.cpu_isa
    {
        let mut pair = vec![*observed, profile.cpu_isa];
        pair.sort();
        reasons.push(UnsupportedReasonCode::ConflictingIsaEvidence {
            observed_isas: pair,
        });
    }
    let profile_bytes = u64::from(profile.nominal_ram_mib) * BYTES_PER_MIB;
    if let [observed_bytes] = rams
        && *observed_bytes != profile_bytes
    {
        reasons.push(UnsupportedReasonCode::NominalRamMismatch {
            observed_bytes: *observed_bytes,
            profile_bytes,
        });
    }
}

fn reconcile_device(
    dev_id: &str,
    obs_list: &[&SanitizedDeviceObservation],
    catalog: &[BoardProfile],
) -> ReconciledDeviceRecord {
    let mut models: Vec<String> = Vec::new();
    let mut revs: Vec<String> = Vec::new();
    let mut isas: Vec<CpuIsa> = Vec::new();
    let mut rams: Vec<u64> = Vec::new();
    let mut rooms: Vec<String> = Vec::new();
    let mut endpoints: Vec<String> = Vec::new();
    let mut reasons: Vec<UnsupportedReasonCode> = Vec::new();
    let mut missing_rev = false;
    let mut best_prov = EvidenceProvenance::SyntheticTestFixture;

    for obs in obs_list {
        let identity_prov = clamp_identity_provenance(obs.provenance);
        if (identity_prov as u8) < (best_prov as u8) {
            best_prov = identity_prov;
        }
        match canonical_model_number(&obs.model_number) {
            Some(model) => push_unique(&mut models, model),
            None => reasons.push(UnsupportedReasonCode::MalformedIdentityField {
                field: "model_number".to_string(),
            }),
        }
        match obs.hw_rev.as_deref().map(str::trim) {
            Some(raw) if !raw.is_empty() => match canonical_hardware_revision(raw) {
                Some(rev) => push_unique(&mut revs, rev),
                None => reasons.push(UnsupportedReasonCode::MalformedIdentityField {
                    field: "hw_rev".to_string(),
                }),
            },
            _ => missing_rev = true,
        }
        if let Some(evidence) = &obs.isa_evidence {
            if evidence.provenance != EvidenceProvenance::DirectBinaryForensics {
                reasons.push(UnsupportedReasonCode::InsufficientIsaEvidence {
                    provenance: evidence.provenance,
                });
            } else if evidence.isa != CpuIsa::Unknown {
                push_unique(&mut isas, evidence.isa);
            }
        }
        if let Some(spec) = &obs.nominal_ram_spec {
            match parse_nominal_bytes(spec) {
                Ok(bytes) => push_unique(&mut rams, bytes),
                Err(reason) => reasons.push(reason),
            }
        }
        if let Some(room) = &obs.room_label_hint {
            push_unique(&mut rooms, room.clone());
        }
        if let Some(endpoint) = &obs.endpoint_hint {
            push_unique(&mut endpoints, endpoint.clone());
        }
    }

    models.sort();
    revs.sort();
    isas.sort();
    rams.sort_unstable();
    rooms.sort();
    endpoints.sort();

    let isa_rejected = reasons
        .iter()
        .any(|r| matches!(r, UnsupportedReasonCode::InsufficientIsaEvidence { .. }));
    if isas.is_empty() && !isa_rejected {
        reasons.push(UnsupportedReasonCode::MissingIsaEvidence);
    }
    let ram_rejected = reasons
        .iter()
        .any(|r| matches!(r, UnsupportedReasonCode::UnknownMemoryUnit { .. }));
    if rams.is_empty() && !ram_rejected {
        reasons.push(UnsupportedReasonCode::MissingNominalRam);
    }
    if models.len() > 1 {
        reasons.push(UnsupportedReasonCode::ConflictingModelNumber {
            observed_models: models.clone(),
        });
    }
    if revs.len() > 1 {
        reasons.push(UnsupportedReasonCode::ConflictingHardwareRevision {
            observed_revisions: revs.clone(),
        });
    }
    if missing_rev || revs.is_empty() {
        reasons.push(UnsupportedReasonCode::MissingHardwareRevision);
    }
    if isas.len() > 1 {
        reasons.push(UnsupportedReasonCode::ConflictingIsaEvidence {
            observed_isas: isas.clone(),
        });
    }
    if rams.len() > 1 {
        reasons.push(UnsupportedReasonCode::ConflictingNominalRam {
            observed_bytes: rams.clone(),
        });
    }

    let mut matched: Option<&BoardProfile> = None;
    if let [model] = models.as_slice()
        && let [rev] = revs.as_slice()
    {
        match catalog.iter().find(|p| row_matches(p, model, rev)) {
            Some(profile) => {
                matched = Some(profile);
                check_matched_profile(profile, &isas, &rams, &mut reasons);
            }
            None => reasons.push(UnsupportedReasonCode::UnknownModelOrRevision {
                model_number: model.clone(),
                hw_rev: rev.clone(),
            }),
        }
    }

    reasons.sort();
    reasons.dedup();

    if !isas.is_empty() {
        best_prov = EvidenceProvenance::DirectBinaryForensics;
    }
    let eligible = reasons.is_empty() && matched.is_some();
    let amplifier_policy = match matched {
        Some(profile) if eligible => profile.amplifier_policy,
        _ => AmplifierPolicy::ForbiddenFailMuted,
    };

    ReconciledDeviceRecord {
        pseudonymous_device_id: dev_id.to_string(),
        eligible_for_audio_activation: eligible,
        selected_profile_id: matched.map(|p| p.profile_id.clone()),
        amplifier_policy,
        highest_provenance: best_prov,
        observed_room_labels: rooms,
        observed_endpoint_hints: endpoints,
        unresolved_reasons: reasons,
    }
}

/// Reconcile an arbitrarily ordered batch of [`SanitizedDeviceObservation`] records
/// against a board catalog.
///
/// Invariants:
/// - Order-independent (permutation invariant): sorting observations or arriving in
///   different batch orders produces identical [`ReconciledDeviceRecord`] outputs.
/// - Renamed rooms (`room_label_hint`) and changed DHCP addresses (`endpoint_hint`)
///   for the same `pseudonymous_device_id` merge cleanly without creating duplicate
///   devices or invalidating hardware identity.
/// - Conflicting `model_number`, `hw_rev`, ISA evidence or nominal RAM across observations for
///   the same `pseudonymous_device_id` remain visible in `unresolved_reasons` and
///   force `eligible_for_audio_activation = false` and `AmplifierPolicy::ForbiddenFailMuted`.
/// - Eligibility needs all of: a unique canonical model and revision matching a catalog row;
///   a row whose facts are all attested (hypothesis and synthetic rows never qualify); ISA
///   evidence from binary forensics equal to the row's ISA (absence is a reason, not a pass);
///   and a nominal RAM value with an explicit unit equal to the row's.
#[must_use]
pub fn reconcile_inventory_observations(
    observations: &[SanitizedDeviceObservation],
    catalog: &[BoardProfile],
) -> BTreeMap<String, ReconciledDeviceRecord> {
    let mut grouped: BTreeMap<String, Vec<&SanitizedDeviceObservation>> = BTreeMap::new();
    for obs in observations {
        grouped
            .entry(obs.pseudonymous_device_id.clone())
            .or_default()
            .push(obs);
    }
    let mut results = BTreeMap::new();
    for (dev_id, obs_list) in grouped {
        let record = reconcile_device(&dev_id, &obs_list, catalog);
        results.insert(dev_id, record);
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Device-reported nominal RAM/flash copied by hand from `inventory/INVENTORY.md`
    /// (an independent oracle for the catalog; the units are not stated by the device).
    const INVENTORY_REPORTED: [(&str, u32, u32); 7] = [
        ("S5", 32, 32),
        ("S1", 128, 64),
        ("S12", 256, 256),
        ("S3", 128, 64),
        ("Sub", 128, 64),
        ("S9", 128, 128),
        ("ZB100", 8, 8),
    ];

    /// Fabricated revision used only by the unit-test attested profile below.
    const TEST_REV: &str = "7.7.7.7-7";

    fn reported(model: &str) -> (u32, u32) {
        INVENTORY_REPORTED
            .iter()
            .find(|(m, _, _)| *m == model)
            .map(|(_, ram, flash)| (*ram, *flash))
            .expect("model is in the inventory table")
    }

    /// A fully attested profile fabricated for these unit tests only. No catalog row looks like
    /// this: it exists to exercise the permitted positive path of reconciliation.
    fn attested_test_profile(isa: CpuIsa, ram_mib: u32) -> BoardProfile {
        BoardProfile {
            schema_version: BOARD_PROFILE_SCHEMA_VERSION.to_string(),
            profile_id: profile_id_for("S5", TEST_REV).expect("canonical"),
            model_number: "S5".to_string(),
            model_name: "unit-test-only attested profile".to_string(),
            supported_hw_rev: TEST_REV.to_string(),
            legacy_sw_gen_hint: 1,
            cpu_isa: isa,
            float_abi: "unit-test-only".to_string(),
            max_atomic_width_bits: isa.max_atomic_width_bits(),
            nominal_ram_mib: ram_mib,
            nominal_flash_mib: 32,
            kernel_capability_profile: "unit-test-only".to_string(),
            audio_driver_abi: "unit-test-only".to_string(),
            hardware_channels: 2,
            channel_routing: vec![TransducerRole::WooferMono, TransducerRole::TweeterMono],
            amplifier_policy: AmplifierPolicy::AdmittedSafeStartupOrder,
            calibrated_output_delay_us: 1,
            calibration_uncertainty_us: 1,
            provenance: EvidenceProvenance::SanitizedInventoryObservation,
            facts: FactStatuses::uniform(FactStatus::Attested),
            integrity_sha256: String::new(),
        }
        .with_computed_digest()
    }

    fn direct(isa: CpuIsa) -> Option<IsaEvidence> {
        Some(IsaEvidence {
            isa,
            provenance: EvidenceProvenance::DirectBinaryForensics,
        })
    }

    fn good_obs(device: &str) -> SanitizedDeviceObservation {
        SanitizedDeviceObservation {
            pseudonymous_device_id: device.to_string(),
            endpoint_hint: None,
            room_label_hint: None,
            model_number: "S5".to_string(),
            hw_rev: Some(TEST_REV.to_string()),
            isa_evidence: direct(CpuIsa::PowerPc32BigEndian),
            nominal_ram_spec: Some("64 MiB".to_string()),
            provenance: EvidenceProvenance::SanitizedInventoryObservation,
        }
    }

    fn one(obs: SanitizedDeviceObservation, catalog: &[BoardProfile]) -> ReconciledDeviceRecord {
        let id = obs.pseudonymous_device_id.clone();
        reconcile_inventory_observations(&[obs], catalog)
            .remove(&id)
            .expect("device is present")
    }

    #[test]
    fn canonical_rows_are_non_admissible_hypotheses_with_valid_digests() {
        let catalog = canonical_board_catalog();
        assert_eq!(catalog.len(), 9);
        for p in &catalog {
            assert_eq!(p.integrity_sha256, p.compute_digest(), "{}", p.profile_id);
            assert_eq!(p.provenance, EvidenceProvenance::AssessmentHypothesis);
            assert_eq!(p.amplifier_policy, AmplifierPolicy::ForbiddenFailMuted);
            assert!(!p.is_synthetic_fixture());
            assert!(!p.activation_blockers().is_empty(), "{}", p.profile_id);
            if p.model_number == "ZB100" {
                assert_eq!(
                    p.verify_integrity(),
                    Err(UnsupportedReasonCode::NonAudioAppliance {
                        model_number: "ZB100".to_string()
                    })
                );
            } else {
                assert!(
                    matches!(
                        p.verify_integrity(),
                        Err(UnsupportedReasonCode::UnattestedProfile { .. })
                    ),
                    "hypothesis row {} must not be admitted",
                    p.profile_id
                );
            }
        }
    }

    #[test]
    fn s5_hypothesis_names_every_unattested_fact() {
        let s5 = canonical_board_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .expect("S5 row");
        let facts: Vec<String> = [
            "hardware_revision",
            "isa",
            "nominal_capacity",
            "calibration",
            "driver_and_routing",
            "kernel_capability",
            "provenance",
        ]
        .iter()
        .map(|name| (*name).to_string())
        .collect();
        assert_eq!(
            s5.verify_integrity(),
            Err(UnsupportedReasonCode::UnattestedProfile {
                profile_id: s5.profile_id.clone(),
                unattested_facts: facts,
            })
        );
    }

    #[test]
    fn canonical_rows_match_inventory_and_declare_unknowns_instead_of_inventing() {
        for p in canonical_board_catalog() {
            let (ram, flash) = reported(&p.model_number);
            assert_eq!(
                (p.nominal_ram_mib, p.nominal_flash_mib),
                (ram, flash),
                "{}",
                p.profile_id
            );
            assert_eq!(p.facts.nominal_capacity, FactStatus::DeviceReported);
            assert_eq!(p.facts.hardware_revision, FactStatus::Hypothesis);
            assert_eq!(p.facts.calibration, FactStatus::Unknown);
            assert_eq!(p.facts.kernel_capability, FactStatus::Unknown);
            assert_eq!(
                (p.calibrated_output_delay_us, p.calibration_uncertainty_us),
                (0, 0)
            );
            for text in [
                &p.float_abi,
                &p.kernel_capability_profile,
                &p.audio_driver_abi,
            ] {
                assert_eq!(text, UNVERIFIED);
            }
            assert_eq!(p.max_atomic_width_bits, p.cpu_isa.max_atomic_width_bits());
            let (want_isa, want_status) = match p.model_number.as_str() {
                "S5" | "S3" => (CpuIsa::PowerPc32BigEndian, FactStatus::Hypothesis),
                "S12" => (CpuIsa::Arm32LittleEndianUnverified, FactStatus::Hypothesis),
                "S1" => (CpuIsa::Unknown, FactStatus::Contested),
                _ => (CpuIsa::Unknown, FactStatus::Unknown),
            };
            assert_eq!((p.cpu_isa, p.facts.isa), (want_isa, want_status));
        }
    }

    #[test]
    fn canonical_json_carries_none_of_the_invented_facts() {
        let json = serde_json::to_string(&canonical_board_catalog())
            .expect("catalog serializes")
            .to_lowercase();
        for invented in [
            "ar9344", "mpc8314", "mpc8377", "cs44800", "2.6.14", "2.6.35", "2.4.26", "br100",
        ] {
            assert!(
                !json.contains(invented),
                "invented fact `{invented}` present"
            );
        }
    }

    #[test]
    fn profile_ids_use_the_shared_formula_with_golden_vectors() {
        // Computed independently with Python: sha256 of the compact key-sorted JSON, first 16 hex.
        assert_eq!(
            profile_id_for("S5", "1.8.3.1-2").as_deref(),
            Some("bp-a54934d5ce72d8e7")
        );
        assert_eq!(
            profile_id_for("S5", "1.20.1.6-2").as_deref(),
            Some("bp-592228c461a48f9b")
        );
        // Non-canonical spellings of one (model, revision) give one id.
        assert_eq!(
            profile_id_for(" s5 ", "01.008.3.1-02"),
            profile_id_for("S5", "1.8.3.1-2")
        );
        assert_eq!(profile_id_for("sub", "1.2"), profile_id_for("SUB", "1.2"));
        assert_ne!(
            profile_id_for("S5", "1.8.3.1-2"),
            profile_id_for("S3", "1.8.3.1-2")
        );
        assert_ne!(
            profile_id_for("S5", "1.8.3.1-2"),
            profile_id_for("S5", "1.8.3.1-3")
        );
        for rejected in [
            ("", "1.2"),
            ("S5", ""),
            ("S 5", "1.2"),
            ("S5", "v1.2"),
            ("S5", "1.2-"),
        ] {
            assert_eq!(profile_id_for(rejected.0, rejected.1), None, "{rejected:?}");
        }
        for p in canonical_board_catalog() {
            assert_eq!(
                Some(p.profile_id.clone()),
                profile_id_for(&p.model_number, &p.supported_hw_rev)
            );
            assert!(p.profile_id.starts_with("bp-"));
        }
    }

    #[test]
    fn canonicalizers_accept_and_reject_the_shared_grammar() {
        for (raw, want) in [
            ("1.8.3.1-2", "1.8.3.1-2"),
            (" 01.008.3.1-02 ", "1.8.3.1-2"),
            ("7", "7"),
            ("1.2.3.4.5.6-1.2.3.4", "1.2.3.4.5.6-1.2.3.4"),
        ] {
            assert_eq!(
                canonical_hardware_revision(raw).as_deref(),
                Some(want),
                "{raw}"
            );
        }
        for bad in [
            "",
            "-",
            "1.",
            ".1",
            "1..2",
            "v1",
            "1.2-",
            "1.2-3-4",
            "1.2.3.4.5.6.7",
            "123456",
            "1.2-1.2.3.4.5",
            "1 .2",
            "\u{0661}.2",
        ] {
            assert_eq!(canonical_hardware_revision(bad), None, "{bad:?}");
        }
        assert_eq!(canonical_model_number(" Sub ").as_deref(), Some("SUB"));
        assert_eq!(canonical_model_number("zb100").as_deref(), Some("ZB100"));
        let too_long = "S".repeat(25);
        for bad in ["", "  ", "S 5", "-S5", "S5!", "ÄS5", too_long.as_str()] {
            assert_eq!(canonical_model_number(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn nominal_bytes_parser_keeps_units_distinct_and_rejects_guessing() {
        assert_eq!(parse_nominal_bytes("128 MB"), Ok(128_000_000));
        assert_eq!(parse_nominal_bytes("128MB"), Ok(128_000_000));
        assert_eq!(parse_nominal_bytes(" 128 MiB "), Ok(134_217_728));
        assert_eq!(parse_nominal_bytes("1 GiB"), Ok(1 << 30));
        assert_eq!(parse_nominal_bytes("512 B"), Ok(512));
        assert_ne!(
            parse_nominal_bytes("128 MB"),
            parse_nominal_bytes("128 MiB")
        );
        for bad in [
            "128",
            "128 mb",
            "128 Mbit",
            "128 Terawords",
            "128\tMB",
            "128  MB",
            "128\u{a0}MB",
            "0 MB",
            "-8 MB",
            "1.5 GB",
            "MB",
            "",
            "999999999999999 GB",
        ] {
            assert!(
                matches!(
                    parse_nominal_bytes(bad),
                    Err(UnsupportedReasonCode::UnknownMemoryUnit { .. })
                ),
                "{bad:?}"
            );
        }
        assert_eq!(
            parse_nominal_bytes("128 Terawords"),
            Err(UnsupportedReasonCode::UnknownMemoryUnit {
                raw_unit: "128 Terawords".to_string()
            })
        );
    }

    #[test]
    fn fixture_catalog_is_synthetic_admissible_offline_and_never_activation_eligible() {
        let fixtures = synthetic_test_fixture_catalog();
        assert_eq!(fixtures.len(), 9);
        for p in &fixtures {
            assert!(p.is_synthetic_fixture());
            assert_eq!(p.facts, FactStatuses::uniform(FactStatus::SyntheticFixture));
            assert_eq!(p.integrity_sha256, p.compute_digest());
            let key = if p.model_number == "BR100" {
                "ZB100"
            } else {
                p.model_number.as_str()
            };
            let (ram, flash) = reported(key);
            assert_eq!((p.nominal_ram_mib, p.nominal_flash_mib), (ram, flash));
            if p.model_number == "BR100" {
                assert_eq!(
                    p.verify_integrity(),
                    Err(UnsupportedReasonCode::NonAudioAppliance {
                        model_number: "BR100".to_string()
                    })
                );
            } else {
                assert_eq!(p.verify_integrity(), Ok(()), "{}", p.profile_id);
                assert_eq!(
                    p.amplifier_policy,
                    AmplifierPolicy::AdmittedSafeStartupOrder
                );
            }
            assert!(
                !p.activation_blockers().is_empty(),
                "synthetic fixture {} must never qualify for activation",
                p.profile_id
            );
        }
        // The synthetic S5 keeps the legacy calibrated delay that downstream clock tests pin.
        let s5 = fixtures
            .iter()
            .find(|p| p.model_number == "S5")
            .expect("S5 fixture");
        assert_eq!(
            (s5.calibrated_output_delay_us, s5.calibration_uncertainty_us),
            (1_850, 150)
        );
    }

    #[test]
    fn relabelling_or_downgrading_a_fixture_makes_the_offline_gate_refuse_it() {
        let s5 = synthetic_test_fixture_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .expect("S5 fixture");
        assert_eq!(s5.verify_integrity(), Ok(()));

        let mut as_hypothesis = s5.clone();
        as_hypothesis.provenance = EvidenceProvenance::AssessmentHypothesis;
        let as_hypothesis = as_hypothesis.with_computed_digest();
        assert!(matches!(
            as_hypothesis.verify_integrity(),
            Err(UnsupportedReasonCode::UnattestedProfile { .. })
        ));

        let mut one_fact_unknown = s5;
        one_fact_unknown.facts.isa = FactStatus::Hypothesis;
        let one_fact_unknown = one_fact_unknown.with_computed_digest();
        assert_eq!(
            one_fact_unknown.verify_integrity(),
            Err(UnsupportedReasonCode::UnattestedProfile {
                profile_id: one_fact_unknown.profile_id.clone(),
                unattested_facts: vec!["isa".to_string()],
            })
        );
    }

    #[test]
    fn editing_a_fact_or_value_after_the_digest_is_detected() {
        let base = synthetic_test_fixture_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .expect("S5 fixture");
        let mut flipped = base.clone();
        flipped.facts.isa = FactStatus::Attested;
        assert!(matches!(
            flipped.verify_integrity(),
            Err(UnsupportedReasonCode::ProfileDigestMismatch { .. })
        ));
        let mut resized = base;
        resized.nominal_ram_mib += 1;
        assert!(matches!(
            resized.verify_integrity(),
            Err(UnsupportedReasonCode::ProfileDigestMismatch { .. })
        ));
    }

    #[test]
    fn missing_facts_deserialize_fail_closed() {
        let partial: FactStatuses =
            serde_json::from_str(r#"{"isa":"attested"}"#).expect("partial facts parse");
        assert_eq!(partial.isa, FactStatus::Attested);
        assert_eq!(partial.hardware_revision, FactStatus::Unknown);
        assert_eq!(FactStatuses::default().unattested(true).len(), 6);

        let fixtures = synthetic_test_fixture_catalog();
        let mut value = serde_json::to_value(&fixtures[0]).expect("profile serializes");
        value
            .as_object_mut()
            .expect("profile is an object")
            .remove("facts");
        let stripped: BoardProfile =
            serde_json::from_value(value).expect("old-shape profile parses");
        assert_eq!(stripped.facts, FactStatuses::default());
        assert!(stripped.verify_integrity().is_err());
    }

    #[test]
    fn complete_attested_evidence_is_eligible_and_order_independent() {
        let catalog = [attested_test_profile(CpuIsa::PowerPc32BigEndian, 64)];
        let a = SanitizedDeviceObservation {
            endpoint_hint: Some("ep-dhcp-101".to_string()),
            room_label_hint: Some("Office Old".to_string()),
            ..good_obs("dev-01")
        };
        let b = SanitizedDeviceObservation {
            endpoint_hint: Some("ep-dhcp-202".to_string()),
            room_label_hint: Some("Office New".to_string()),
            ..good_obs("dev-01")
        };
        let forward = reconcile_inventory_observations(&[a.clone(), b.clone()], &catalog);
        let reverse = reconcile_inventory_observations(&[b, a], &catalog);
        assert_eq!(forward, reverse);

        let rec = &forward["dev-01"];
        assert!(
            rec.eligible_for_audio_activation,
            "{:?}",
            rec.unresolved_reasons
        );
        assert_eq!(
            rec.selected_profile_id.as_deref(),
            Some(catalog[0].profile_id.as_str())
        );
        assert_eq!(
            rec.amplifier_policy,
            AmplifierPolicy::AdmittedSafeStartupOrder
        );
        assert_eq!(
            rec.highest_provenance,
            EvidenceProvenance::DirectBinaryForensics
        );
        assert_eq!(rec.observed_room_labels, vec!["Office New", "Office Old"]);
        assert_eq!(
            rec.observed_endpoint_hints,
            vec!["ep-dhcp-101", "ep-dhcp-202"]
        );
        assert!(rec.unresolved_reasons.is_empty());
    }

    #[test]
    fn non_canonical_spellings_select_the_same_row() {
        let catalog = [attested_test_profile(CpuIsa::PowerPc32BigEndian, 64)];
        let obs = SanitizedDeviceObservation {
            model_number: " s5 ".to_string(),
            hw_rev: Some("07.07.7.7-07".to_string()),
            ..good_obs("dev-spelling")
        };
        let rec = one(obs, &catalog);
        assert!(
            rec.eligible_for_audio_activation,
            "{:?}",
            rec.unresolved_reasons
        );
    }

    #[test]
    fn each_missing_or_weak_piece_of_evidence_blocks_activation_with_its_own_reason() {
        let catalog = [attested_test_profile(CpuIsa::PowerPc32BigEndian, 64)];
        let sanitized_isa = Some(IsaEvidence {
            isa: CpuIsa::PowerPc32BigEndian,
            provenance: EvidenceProvenance::SanitizedInventoryObservation,
        });
        let hypothesis_isa = Some(IsaEvidence {
            isa: CpuIsa::PowerPc32BigEndian,
            provenance: EvidenceProvenance::AssessmentHypothesis,
        });
        let cases = [
            (
                "no ISA evidence at all",
                SanitizedDeviceObservation {
                    isa_evidence: None,
                    ..good_obs("d")
                },
                UnsupportedReasonCode::MissingIsaEvidence,
            ),
            (
                "ISA from inventory XML",
                SanitizedDeviceObservation {
                    isa_evidence: sanitized_isa,
                    ..good_obs("d")
                },
                UnsupportedReasonCode::InsufficientIsaEvidence {
                    provenance: EvidenceProvenance::SanitizedInventoryObservation,
                },
            ),
            (
                "ISA from an assessment hypothesis",
                SanitizedDeviceObservation {
                    isa_evidence: hypothesis_isa,
                    ..good_obs("d")
                },
                UnsupportedReasonCode::InsufficientIsaEvidence {
                    provenance: EvidenceProvenance::AssessmentHypothesis,
                },
            ),
            (
                "direct ISA evidence contradicts the row",
                SanitizedDeviceObservation {
                    isa_evidence: direct(CpuIsa::Mips32R2BigEndian),
                    ..good_obs("d")
                },
                UnsupportedReasonCode::ConflictingIsaEvidence {
                    observed_isas: vec![CpuIsa::PowerPc32BigEndian, CpuIsa::Mips32R2BigEndian],
                },
            ),
            (
                "RAM 32 MiB against a 64 MiB row",
                SanitizedDeviceObservation {
                    nominal_ram_spec: Some("32 MiB".to_string()),
                    ..good_obs("d")
                },
                UnsupportedReasonCode::NominalRamMismatch {
                    observed_bytes: 32 * 1_048_576,
                    profile_bytes: 64 * 1_048_576,
                },
            ),
            (
                "64 MB is not 64 MiB",
                SanitizedDeviceObservation {
                    nominal_ram_spec: Some("64 MB".to_string()),
                    ..good_obs("d")
                },
                UnsupportedReasonCode::NominalRamMismatch {
                    observed_bytes: 64_000_000,
                    profile_bytes: 67_108_864,
                },
            ),
            (
                "bare RAM number has no unit",
                SanitizedDeviceObservation {
                    nominal_ram_spec: Some("64".to_string()),
                    ..good_obs("d")
                },
                UnsupportedReasonCode::UnknownMemoryUnit {
                    raw_unit: "64".to_string(),
                },
            ),
            (
                "no RAM value",
                SanitizedDeviceObservation {
                    nominal_ram_spec: None,
                    ..good_obs("d")
                },
                UnsupportedReasonCode::MissingNominalRam,
            ),
            (
                "no hardware revision",
                SanitizedDeviceObservation {
                    hw_rev: None,
                    ..good_obs("d")
                },
                UnsupportedReasonCode::MissingHardwareRevision,
            ),
            (
                "blank hardware revision",
                SanitizedDeviceObservation {
                    hw_rev: Some("   ".to_string()),
                    ..good_obs("d")
                },
                UnsupportedReasonCode::MissingHardwareRevision,
            ),
            (
                "revision not in the catalog",
                SanitizedDeviceObservation {
                    hw_rev: Some("8.8.8.8-8".to_string()),
                    ..good_obs("d")
                },
                UnsupportedReasonCode::UnknownModelOrRevision {
                    model_number: "S5".to_string(),
                    hw_rev: "8.8.8.8-8".to_string(),
                },
            ),
            (
                "model not in the catalog",
                SanitizedDeviceObservation {
                    model_number: "S9".to_string(),
                    ..good_obs("d")
                },
                UnsupportedReasonCode::UnknownModelOrRevision {
                    model_number: "S9".to_string(),
                    hw_rev: TEST_REV.to_string(),
                },
            ),
            (
                "malformed model number",
                SanitizedDeviceObservation {
                    model_number: "S 5".to_string(),
                    ..good_obs("d")
                },
                UnsupportedReasonCode::MalformedIdentityField {
                    field: "model_number".to_string(),
                },
            ),
            (
                "malformed hardware revision",
                SanitizedDeviceObservation {
                    hw_rev: Some("v1.2".to_string()),
                    ..good_obs("d")
                },
                UnsupportedReasonCode::MalformedIdentityField {
                    field: "hw_rev".to_string(),
                },
            ),
        ];
        // Permitted positive counterpart: the unmodified observation is eligible.
        assert!(one(good_obs("d"), &catalog).eligible_for_audio_activation);
        for (label, obs, want) in cases {
            let rec = one(obs, &catalog);
            assert!(!rec.eligible_for_audio_activation, "{label}");
            assert_eq!(
                rec.amplifier_policy,
                AmplifierPolicy::ForbiddenFailMuted,
                "{label}"
            );
            assert!(
                rec.unresolved_reasons.contains(&want),
                "{label}: got {:?}",
                rec.unresolved_reasons
            );
        }
        // A single missing field yields exactly that one reason (no collateral noise).
        let rec = one(
            SanitizedDeviceObservation {
                hw_rev: None,
                ..good_obs("d")
            },
            &catalog,
        );
        assert_eq!(
            rec.unresolved_reasons,
            vec![UnsupportedReasonCode::MissingHardwareRevision]
        );
        assert_eq!(rec.selected_profile_id, None);
    }

    #[test]
    fn conflicting_observations_stay_visible_and_ineligible() {
        let catalog = [attested_test_profile(CpuIsa::PowerPc32BigEndian, 64)];
        let with = |f: fn(&mut SanitizedDeviceObservation)| {
            let mut obs = good_obs("dev-conflict");
            f(&mut obs);
            obs
        };
        let cases = [
            (
                "two revisions",
                with(|o| o.hw_rev = Some("8.8.8.8-8".to_string())),
                UnsupportedReasonCode::ConflictingHardwareRevision {
                    observed_revisions: vec!["7.7.7.7-7".to_string(), "8.8.8.8-8".to_string()],
                },
            ),
            (
                "two models",
                with(|o| o.model_number = "S3".to_string()),
                UnsupportedReasonCode::ConflictingModelNumber {
                    observed_models: vec!["S3".to_string(), "S5".to_string()],
                },
            ),
            (
                "two RAM values",
                with(|o| o.nominal_ram_spec = Some("32 MiB".to_string())),
                UnsupportedReasonCode::ConflictingNominalRam {
                    observed_bytes: vec![32 * 1_048_576, 64 * 1_048_576],
                },
            ),
            (
                "two ISAs",
                with(|o| o.isa_evidence = direct(CpuIsa::Mips32R2BigEndian)),
                UnsupportedReasonCode::ConflictingIsaEvidence {
                    observed_isas: vec![CpuIsa::PowerPc32BigEndian, CpuIsa::Mips32R2BigEndian],
                },
            ),
        ];
        for (label, second, want) in cases {
            for batch in [
                [good_obs("dev-conflict"), second.clone()],
                [second.clone(), good_obs("dev-conflict")],
            ] {
                let rec = reconcile_inventory_observations(&batch, &catalog)
                    .remove("dev-conflict")
                    .expect("device is present");
                assert!(!rec.eligible_for_audio_activation, "{label}");
                assert!(
                    rec.unresolved_reasons.contains(&want),
                    "{label}: {:?}",
                    rec.unresolved_reasons
                );
            }
        }
    }

    #[test]
    fn hypothesis_and_synthetic_rows_never_make_a_device_eligible() {
        // Perfect evidence for the S5 hypothesis row's own (unattested) revision and capacity.
        let hypotheses = canonical_board_catalog();
        let s5 = hypotheses
            .iter()
            .find(|p| p.model_number == "S5")
            .expect("S5 hypothesis row");
        let obs = SanitizedDeviceObservation {
            hw_rev: Some(s5.supported_hw_rev.clone()),
            nominal_ram_spec: Some("32 MiB".to_string()),
            ..good_obs("dev-hyp")
        };
        let rec = one(obs.clone(), &hypotheses);
        assert_eq!(
            rec.selected_profile_id.as_deref(),
            Some(s5.profile_id.as_str())
        );
        assert!(!rec.eligible_for_audio_activation);
        assert_eq!(rec.amplifier_policy, AmplifierPolicy::ForbiddenFailMuted);
        assert_eq!(
            rec.unresolved_reasons.len(),
            1,
            "{:?}",
            rec.unresolved_reasons
        );
        assert!(matches!(
            rec.unresolved_reasons[0],
            UnsupportedReasonCode::UnattestedProfile { .. }
        ));

        // The synthetic fixture row with the same identity passes the offline gate but never
        // qualifies a real device.
        let fixtures = synthetic_test_fixture_catalog();
        let fx = fixtures
            .iter()
            .find(|p| p.model_number == "S5")
            .expect("S5 fixture row");
        assert_eq!(fx.verify_integrity(), Ok(()));
        let rec = one(obs, &fixtures);
        assert_eq!(
            rec.selected_profile_id.as_deref(),
            Some(fx.profile_id.as_str())
        );
        assert!(!rec.eligible_for_audio_activation);
        assert_eq!(
            rec.unresolved_reasons.len(),
            1,
            "{:?}",
            rec.unresolved_reasons
        );
        assert!(matches!(
            rec.unresolved_reasons[0],
            UnsupportedReasonCode::UnattestedProfile { .. }
        ));
    }

    #[test]
    fn bridge_is_never_an_audio_target() {
        let catalog = canonical_board_catalog();
        let bridge = catalog
            .iter()
            .find(|p| p.model_number == "ZB100")
            .expect("bridge row");
        let obs = SanitizedDeviceObservation {
            model_number: "ZB100".to_string(),
            hw_rev: Some(bridge.supported_hw_rev.clone()),
            isa_evidence: None,
            nominal_ram_spec: Some("8 MiB".to_string()),
            ..good_obs("dev-bridge")
        };
        let rec = one(obs, &catalog);
        assert!(!rec.eligible_for_audio_activation);
        assert!(
            rec.unresolved_reasons
                .contains(&UnsupportedReasonCode::NonAudioAppliance {
                    model_number: "ZB100".to_string()
                })
        );
    }

    #[test]
    fn identity_provenance_is_clamped_and_isa_evidence_is_what_raises_it() {
        let catalog = [attested_test_profile(CpuIsa::PowerPc32BigEndian, 64)];
        // An inventory observation that labels itself binary forensics is clamped.
        let boastful = SanitizedDeviceObservation {
            provenance: EvidenceProvenance::DirectBinaryForensics,
            isa_evidence: None,
            ..good_obs("dev-boast")
        };
        assert_eq!(
            one(boastful, &catalog).highest_provenance,
            EvidenceProvenance::SanitizedInventoryObservation
        );
        // Accepted binary-forensics ISA evidence is what yields the stronger level.
        assert_eq!(
            one(good_obs("dev-direct"), &catalog).highest_provenance,
            EvidenceProvenance::DirectBinaryForensics
        );
        // Synthetic-only observations stay at the weakest level.
        let synthetic = SanitizedDeviceObservation {
            provenance: EvidenceProvenance::SyntheticTestFixture,
            isa_evidence: None,
            ..good_obs("dev-syn")
        };
        assert_eq!(
            one(synthetic, &catalog).highest_provenance,
            EvidenceProvenance::SyntheticTestFixture
        );
    }

    #[test]
    fn fact_statuses_report_unattested_names_in_a_stable_order() {
        let mut facts = FactStatuses::uniform(FactStatus::Attested);
        assert!(facts.unattested(false).is_empty());
        facts.calibration = FactStatus::Unknown;
        facts.isa = FactStatus::Contested;
        assert_eq!(facts.unattested(false), vec!["isa", "calibration"]);
        let synthetic = FactStatuses::uniform(FactStatus::SyntheticFixture);
        assert!(synthetic.unattested(true).is_empty());
        assert_eq!(synthetic.unattested(false).len(), 6);
    }
}
