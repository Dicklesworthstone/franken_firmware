//! Sanitized board profile manifest and hardware identity reconciliation (`E01` / `ffw-xdi`).
//!
//! Enforces the standing architecture rules from `FIRMWARE_ASSESSMENT.md` and `docs/SLIM_RUNTIME_DESIGN.md`:
//! - Never derive CPU ISA or calibration from model number or product era (`swGen`) alone;
//!   both model AND exact hardware revision (`hw_rev`) + ISA evidence are required.
//! - Unknown, missing-revision, conflicting-ISA, or non-audio (`BR100` Bridge) records
//!   are rejected before opening any output device (`AmplifierPolicy::ForbiddenFailMuted`).
//! - Merging sanitized device observations across reordered batches is commutative,
//!   associative, and idempotent: identical evidence sets always produce the exact
//!   same profile binding and SHA-256 manifest digest, while conflicts stay visible
//!   and ineligible for activation.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const BOARD_PROFILE_SCHEMA_VERSION: &str = "ffw.board_profile.v1";

/// CPU instruction set and endianness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuIsa {
    PowerPc32BigEndian,
    Mips32R2BigEndian,
    Arm32LittleEndianUnverified,
}

impl CpuIsa {
    #[must_use]
    pub const fn target_triple(self) -> Option<&'static str> {
        match self {
            Self::PowerPc32BigEndian => Some("powerpc-unknown-linux-musl"),
            Self::Mips32R2BigEndian => Some("mips-unknown-linux-musl"),
            Self::Arm32LittleEndianUnverified => None,
        }
    }

    #[must_use]
    pub const fn max_atomic_width_bits(self) -> u8 {
        match self {
            Self::PowerPc32BigEndian
            | Self::Mips32R2BigEndian
            | Self::Arm32LittleEndianUnverified => 32,
        }
    }
}

/// Evidence provenance level for each field or profile attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProvenance {
    /// Directly extracted from a decrypted firmware image / ELF / kernel module (e.g. `S5` `audiodev.o`).
    DirectBinaryForensics,
    /// Captured from read-only LAN UPnP `/xml/device_description.xml` + `/status/zp`.
    SanitizedInventoryObservation,
    /// Conservative architecture bound from `FIRMWARE_ASSESSMENT.md` pending direct extraction.
    AssessmentHypothesis,
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
}

/// Versioned board profile binding hardware revision, ISA, audio routing, and calibration bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardProfile {
    pub schema_version: String,
    pub profile_id: String,
    pub model_number: String,
    pub model_name: String,
    pub supported_hw_rev: String,
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
    pub integrity_sha256: String,
}

impl BoardProfile {
    /// Compute canonical SHA-256 digest over all fields except `integrity_sha256`.
    #[must_use]
    pub fn compute_digest(&self) -> String {
        let mut clone = self.clone();
        clone.integrity_sha256.clear();
        let canonical = serde_json::to_vec(&clone).unwrap_or_default();
        hex::encode(Sha256::digest(&canonical))
    }

    #[must_use]
    pub fn with_computed_digest(mut self) -> Self {
        self.integrity_sha256 = self.compute_digest();
        self
    }

    pub fn verify_integrity(&self) -> Result<(), UnsupportedReasonCode> {
        let computed = self.compute_digest();
        if self.integrity_sha256 != computed {
            return Err(UnsupportedReasonCode::ProfileDigestMismatch {
                expected_sha256: self.integrity_sha256.clone(),
                computed_sha256: computed,
            });
        }
        if self.hardware_channels == 0
            || self.amplifier_policy == AmplifierPolicy::ForbiddenFailMuted
        {
            return Err(UnsupportedReasonCode::NonAudioAppliance {
                model_number: self.model_number.clone(),
            });
        }
        Ok(())
    }
}

/// Return the canonical catalog of 9 hardware revision profiles from `inventory/INVENTORY.md`.
#[must_use]
pub fn canonical_board_catalog() -> Vec<BoardProfile> {
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
            integrity_sha256: String::new(),
        }
        .with_computed_digest(),
    ]
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
    pub observed_isa: Option<CpuIsa>,
    pub nominal_ram_spec: Option<String>,
    pub provenance: EvidenceProvenance,
}

/// Result of reconciling one or more observations for a pseudonymous device slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciledDeviceRecord {
    pub pseudonymous_device_id: String,
    pub eligible_for_audio_activation: bool,
    pub selected_profile_id: Option<String>,
    pub amplifier_policy: AmplifierPolicy,
    pub highest_provenance: EvidenceProvenance,
    pub observed_room_labels: Vec<String>,
    pub observed_endpoint_hints: Vec<String>,
    pub unresolved_reasons: Vec<UnsupportedReasonCode>,
}

/// Parse a nominal RAM specification string (e.g. `"64 MiB"`, `"128MB"`).
/// Rejects unknown or ambiguous units.
pub fn parse_nominal_ram_mib(spec: &str) -> Result<u32, UnsupportedReasonCode> {
    let trimmed = spec.trim();
    for suffix in ["MiB", "MB"] {
        if let Some(num_str) = trimmed.strip_suffix(suffix)
            && let Ok(v) = num_str.trim().parse::<u32>()
            && v > 0
        {
            return Ok(v);
        }
    }
    Err(UnsupportedReasonCode::UnknownMemoryUnit {
        raw_unit: spec.to_string(),
    })
}

/// Reconcile an arbitrarily ordered batch of [`SanitizedDeviceObservation`] records
/// against the canonical board catalog.
///
/// Invariants:
/// - Order-independent (permutation invariant): sorting observations or arriving in
///   different batch orders produces identical [`ReconciledDeviceRecord`] outputs.
/// - Renamed rooms (`room_label_hint`) and changed DHCP addresses (`endpoint_hint`)
///   for the same `pseudonymous_device_id` merge cleanly without creating duplicate
///   devices or invalidating hardware identity.
/// - Conflicting `model_number`, `hw_rev`, or `observed_isa` across observations for
///   the same `pseudonymous_device_id` remain visible in `unresolved_reasons` and
///   force `eligible_for_audio_activation = false` and `AmplifierPolicy::ForbiddenFailMuted`.
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
        let mut models = Vec::new();
        let mut revs = Vec::new();
        let mut isas = Vec::new();
        let mut rooms = Vec::new();
        let mut endpoints = Vec::new();
        let mut reasons = Vec::new();
        let mut missing_rev = false;
        let mut best_prov = EvidenceProvenance::AssessmentHypothesis;

        for obs in &obs_list {
            // Rank DirectBinaryForensics < SanitizedInventoryObservation < AssessmentHypothesis in enum order
            if (obs.provenance as u8) < (best_prov as u8) {
                best_prov = obs.provenance;
            }
            if !models.contains(&obs.model_number) {
                models.push(obs.model_number.clone());
            }
            match &obs.hw_rev {
                Some(r) if !r.trim().is_empty() => {
                    if !revs.contains(r) {
                        revs.push(r.clone());
                    }
                }
                _ => {
                    missing_rev = true;
                }
            }
            if let Some(isa) = obs.observed_isa
                && !isas.contains(&isa)
            {
                isas.push(isa);
            }
            if let Some(room) = &obs.room_label_hint
                && !rooms.contains(room)
            {
                rooms.push(room.clone());
            }
            if let Some(ep) = &obs.endpoint_hint
                && !endpoints.contains(ep)
            {
                endpoints.push(ep.clone());
            }
            if let Some(ram_spec) = &obs.nominal_ram_spec
                && let Err(e) = parse_nominal_ram_mib(ram_spec)
                && !reasons.contains(&e)
            {
                reasons.push(e);
            }
        }

        models.sort();
        revs.sort();
        isas.sort();
        rooms.sort();
        endpoints.sort();

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

        let mut selected_profile_id = None;
        let mut eligible = false;
        let mut amp_policy = AmplifierPolicy::ForbiddenFailMuted;

        if reasons.is_empty() && models.len() == 1 && revs.len() == 1 {
            let model = &models[0];
            let rev = &revs[0];
            if let Some(profile) = catalog
                .iter()
                .find(|p| &p.model_number == model && &p.supported_hw_rev == rev)
            {
                if let Some(&obs_isa) = isas.first()
                    && obs_isa != profile.cpu_isa
                {
                    let mut pair = vec![obs_isa, profile.cpu_isa];
                    pair.sort();
                    reasons.push(UnsupportedReasonCode::ConflictingIsaEvidence {
                        observed_isas: pair,
                    });
                } else {
                    match profile.verify_integrity() {
                        Ok(()) => {
                            selected_profile_id = Some(profile.profile_id.clone());
                            eligible = true;
                            amp_policy = profile.amplifier_policy;
                        }
                        Err(reason) => {
                            selected_profile_id = Some(profile.profile_id.clone());
                            reasons.push(reason);
                        }
                    }
                }
            } else {
                reasons.push(UnsupportedReasonCode::UnknownModelOrRevision {
                    model_number: model.clone(),
                    hw_rev: rev.clone(),
                });
            }
        }

        reasons.sort();
        reasons.dedup();

        results.insert(
            dev_id.clone(),
            ReconciledDeviceRecord {
                pseudonymous_device_id: dev_id,
                eligible_for_audio_activation: eligible,
                selected_profile_id,
                amplifier_policy: amp_policy,
                highest_provenance: best_prov,
                observed_room_labels: rooms,
                observed_endpoint_hints: endpoints,
                unresolved_reasons: reasons,
            },
        );
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_catalog_profiles_have_valid_digests_and_bridge_is_fail_muted() {
        let catalog = canonical_board_catalog();
        assert_eq!(catalog.len(), 9);
        for profile in &catalog {
            assert_eq!(profile.integrity_sha256, profile.compute_digest());
            if profile.model_number == "BR100" {
                assert_eq!(
                    profile.verify_integrity(),
                    Err(UnsupportedReasonCode::NonAudioAppliance {
                        model_number: "BR100".to_string()
                    })
                );
                assert_eq!(
                    profile.amplifier_policy,
                    AmplifierPolicy::ForbiddenFailMuted
                );
            } else {
                assert!(profile.verify_integrity().is_ok());
                assert_eq!(
                    profile.amplifier_policy,
                    AmplifierPolicy::AdmittedSafeStartupOrder
                );
            }
        }
    }

    #[test]
    fn reconciliation_is_permutation_invariant_and_tolerates_room_rename_and_ip_change() {
        let catalog = canonical_board_catalog();
        let obs_a = SanitizedDeviceObservation {
            pseudonymous_device_id: "dev-s5-01".to_string(),
            endpoint_hint: Some("ep-dhcp-101".to_string()),
            room_label_hint: Some("Office Old".to_string()),
            model_number: "S5".to_string(),
            hw_rev: Some("1.16.3.1-2".to_string()),
            observed_isa: Some(CpuIsa::PowerPc32BigEndian),
            nominal_ram_spec: Some("64 MiB".to_string()),
            provenance: EvidenceProvenance::SanitizedInventoryObservation,
        };
        let obs_b = SanitizedDeviceObservation {
            pseudonymous_device_id: "dev-s5-01".to_string(),
            endpoint_hint: Some("ep-dhcp-202".to_string()),
            room_label_hint: Some("Office New".to_string()),
            model_number: "S5".to_string(),
            hw_rev: Some("1.16.3.1-2".to_string()),
            observed_isa: Some(CpuIsa::PowerPc32BigEndian),
            nominal_ram_spec: Some("64 MiB".to_string()),
            provenance: EvidenceProvenance::DirectBinaryForensics,
        };

        let r1 = reconcile_inventory_observations(&[obs_a.clone(), obs_b.clone()], &catalog);
        let r2 = reconcile_inventory_observations(&[obs_b, obs_a], &catalog);
        assert_eq!(r1, r2);

        let rec = &r1["dev-s5-01"];
        assert!(rec.eligible_for_audio_activation);
        assert_eq!(
            rec.selected_profile_id.as_deref(),
            Some("sonos-s5-ppc-rev-1.16.3.1-2")
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
    fn ambiguous_or_conflicting_evidence_never_silently_selects_a_board() {
        let catalog = canonical_board_catalog();
        let observations = vec![
            // Case 1: absent hardware revision -> rejected, even though S5 only has 1 rev in catalog
            SanitizedDeviceObservation {
                pseudonymous_device_id: "dev-missing-rev".to_string(),
                endpoint_hint: None,
                room_label_hint: None,
                model_number: "S5".to_string(),
                hw_rev: None,
                observed_isa: Some(CpuIsa::PowerPc32BigEndian),
                nominal_ram_spec: Some("64 MiB".to_string()),
                provenance: EvidenceProvenance::SanitizedInventoryObservation,
            },
            // Case 2: conflicting ISA evidence (claiming MIPS on a PowerPC S5) -> rejected
            SanitizedDeviceObservation {
                pseudonymous_device_id: "dev-conflict-isa".to_string(),
                endpoint_hint: None,
                room_label_hint: None,
                model_number: "S5".to_string(),
                hw_rev: Some("1.16.3.1-2".to_string()),
                observed_isa: Some(CpuIsa::Mips32R2BigEndian),
                nominal_ram_spec: Some("64 MiB".to_string()),
                provenance: EvidenceProvenance::SanitizedInventoryObservation,
            },
            // Case 3: unknown nominal memory unit -> rejected
            SanitizedDeviceObservation {
                pseudonymous_device_id: "dev-bad-mem-unit".to_string(),
                endpoint_hint: None,
                room_label_hint: None,
                model_number: "S1".to_string(),
                hw_rev: Some("1.8.3.7-2".to_string()),
                observed_isa: Some(CpuIsa::Mips32R2BigEndian),
                nominal_ram_spec: Some("128 Terawords".to_string()),
                provenance: EvidenceProvenance::SanitizedInventoryObservation,
            },
            // Case 4: Bridge BR100 non-audio appliance -> rejected for audio
            SanitizedDeviceObservation {
                pseudonymous_device_id: "dev-bridge".to_string(),
                endpoint_hint: None,
                room_label_hint: None,
                model_number: "BR100".to_string(),
                hw_rev: Some("1.5.0.0-1".to_string()),
                observed_isa: Some(CpuIsa::Arm32LittleEndianUnverified),
                nominal_ram_spec: Some("32 MiB".to_string()),
                provenance: EvidenceProvenance::SanitizedInventoryObservation,
            },
        ];

        let reconciled = reconcile_inventory_observations(&observations, &catalog);
        for (id, rec) in &reconciled {
            assert!(
                !rec.eligible_for_audio_activation,
                "device {id} should not be eligible"
            );
            assert_eq!(rec.amplifier_policy, AmplifierPolicy::ForbiddenFailMuted);
            assert!(!rec.unresolved_reasons.is_empty());
        }
        assert_eq!(
            reconciled["dev-missing-rev"].unresolved_reasons,
            vec![UnsupportedReasonCode::MissingHardwareRevision]
        );
        assert_eq!(
            reconciled["dev-bad-mem-unit"].unresolved_reasons,
            vec![UnsupportedReasonCode::UnknownMemoryUnit {
                raw_unit: "128 Terawords".to_string()
            }]
        );
    }
}
