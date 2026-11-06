//! Signed staged artifact and update policy (`U02` / `ffw-76j`). The specification is `docs/contracts/u02.md`; `tests/u02/reference.py`
//! is an independent implementation of it that writes the vectors this crate replays (`tests/vectors/u02_vectors.json`).
//!
//! What a candidate update meets, in order: [`manifest`] (a fixed binary layout, bounded and strict), the signature and then
//! [`policy::admit`] (board, trust boundary, anti-rollback, old/new settings compatibility, SSH declaration, capacity), the staged bytes
//! against the manifest's size and SHA-256 ([`engine::check_artifact`]), and the persisted state machine ([`engine::Engine`]) over U01's
//! journal with a staging medium behind a trait. [`group`] is the rolling-update model: one upgraded member, one old, one disconnected,
//! and a rollback after a settings migration.
//!
//! Trust. Our signing key and the factory boot chain are different trust domains and this crate only ever speaks for the first. A manifest
//! can name one target stage, our userspace payload; a kernel, a bootloader or a vendor package, and any claim of vendor acceptance, a
//! factory bypass or A/B capacity, are refused by name. Nothing in a [`policy::Plan`] can say that the vendor accepted anything or that A/B
//! is proven unless an external capacity receipt says so. The signature is Ed25519 verified by `ed25519-dalek` (see [`sig`]); this crate
//! implements no curve arithmetic.
//!
//! Offline only. Nothing here opens a device, a network or a file. A synthetic fixture board never passes the production policy.

#![forbid(unsafe_code)]

pub mod engine;
pub mod group;
pub mod manifest;
pub mod policy;
pub mod sig;

use std::fmt;

/// A refusal. [`UpdateError::code`] is its stable name; no variant carries a key, a payload or a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateError {
    ManifestTooShort,
    ManifestTooLong,
    BadMagic,
    UnsupportedFormat,
    BadField,
    TrailingBytes,
    UnknownSigningKey,
    RevokedSigningKey,
    BadSignature,
    StageForbidden,
    VendorClaimForbidden,
    BypassClaimForbidden,
    AbClaimForbidden,
    WrongBoard,
    HardwareRevisionMismatch,
    IsaMismatch,
    KernelProfileMismatch,
    ProfileNotAttested,
    EvidenceMismatch,
    RequiredFeatureMissing,
    BelowSecurityFloor,
    CandidatePreviouslyFailed,
    AlreadyInstalled,
    VersionReused,
    DowngradeNotPermitted,
    CalibrationSchemaMismatch,
    SettingsIncompatible,
    SshFixMissing,
    SshUnbound,
    SshPasswordForbidden,
    SshAuthUnresolved,
    SshUnqualified,
    InsufficientCapacity,
    SyntheticReceiptForRealProfile,
    NoRecoveryPath,
    ArtifactTruncated,
    ArtifactOversized,
    ArtifactDigestMismatch,
    UpdateInProgress,
    NotStaging,
    NotStaged,
    NotInTrial,
    NothingToAbort,
    TrialInProgress,
    StagingGap,
    BadTrustKey,
    DuplicateTrustKey,
    TrustStoreFull,
    ProfileInvalid,
    IsaUnsupported,
    CorruptState,
    /// The journal refused or failed; the payload is its own stable code (`poisoned`, `storage`, `mark_regressed`, ...).
    Journal(&'static str),
}

/// Every stable refusal name except the journal's, in declaration order. The vectors may only use these (plus the journal's codes).
pub const ALL_CODES: &[&str] = &[
    "manifest_too_short",
    "manifest_too_long",
    "bad_magic",
    "unsupported_format",
    "bad_field",
    "trailing_bytes",
    "unknown_signing_key",
    "revoked_signing_key",
    "bad_signature",
    "stage_forbidden",
    "vendor_claim_forbidden",
    "bypass_claim_forbidden",
    "ab_claim_forbidden",
    "wrong_board",
    "hardware_revision_mismatch",
    "isa_mismatch",
    "kernel_profile_mismatch",
    "profile_not_attested",
    "evidence_mismatch",
    "required_feature_missing",
    "below_security_floor",
    "candidate_previously_failed",
    "already_installed",
    "version_reused",
    "downgrade_not_permitted",
    "calibration_schema_mismatch",
    "settings_incompatible",
    "ssh_fix_missing",
    "ssh_unbound",
    "ssh_password_forbidden",
    "ssh_auth_unresolved",
    "ssh_unqualified",
    "insufficient_capacity",
    "synthetic_receipt_for_real_profile",
    "no_recovery_path",
    "artifact_truncated",
    "artifact_oversized",
    "artifact_digest_mismatch",
    "update_in_progress",
    "not_staging",
    "not_staged",
    "not_in_trial",
    "nothing_to_abort",
    "trial_in_progress",
    "staging_gap",
    "bad_trust_key",
    "duplicate_trust_key",
    "trust_store_full",
    "profile_invalid",
    "isa_unsupported",
    "corrupt_state",
];

impl UpdateError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ManifestTooShort => "manifest_too_short",
            Self::ManifestTooLong => "manifest_too_long",
            Self::BadMagic => "bad_magic",
            Self::UnsupportedFormat => "unsupported_format",
            Self::BadField => "bad_field",
            Self::TrailingBytes => "trailing_bytes",
            Self::UnknownSigningKey => "unknown_signing_key",
            Self::RevokedSigningKey => "revoked_signing_key",
            Self::BadSignature => "bad_signature",
            Self::StageForbidden => "stage_forbidden",
            Self::VendorClaimForbidden => "vendor_claim_forbidden",
            Self::BypassClaimForbidden => "bypass_claim_forbidden",
            Self::AbClaimForbidden => "ab_claim_forbidden",
            Self::WrongBoard => "wrong_board",
            Self::HardwareRevisionMismatch => "hardware_revision_mismatch",
            Self::IsaMismatch => "isa_mismatch",
            Self::KernelProfileMismatch => "kernel_profile_mismatch",
            Self::ProfileNotAttested => "profile_not_attested",
            Self::EvidenceMismatch => "evidence_mismatch",
            Self::RequiredFeatureMissing => "required_feature_missing",
            Self::BelowSecurityFloor => "below_security_floor",
            Self::CandidatePreviouslyFailed => "candidate_previously_failed",
            Self::AlreadyInstalled => "already_installed",
            Self::VersionReused => "version_reused",
            Self::DowngradeNotPermitted => "downgrade_not_permitted",
            Self::CalibrationSchemaMismatch => "calibration_schema_mismatch",
            Self::SettingsIncompatible => "settings_incompatible",
            Self::SshFixMissing => "ssh_fix_missing",
            Self::SshUnbound => "ssh_unbound",
            Self::SshPasswordForbidden => "ssh_password_forbidden",
            Self::SshAuthUnresolved => "ssh_auth_unresolved",
            Self::SshUnqualified => "ssh_unqualified",
            Self::InsufficientCapacity => "insufficient_capacity",
            Self::SyntheticReceiptForRealProfile => "synthetic_receipt_for_real_profile",
            Self::NoRecoveryPath => "no_recovery_path",
            Self::ArtifactTruncated => "artifact_truncated",
            Self::ArtifactOversized => "artifact_oversized",
            Self::ArtifactDigestMismatch => "artifact_digest_mismatch",
            Self::UpdateInProgress => "update_in_progress",
            Self::NotStaging => "not_staging",
            Self::NotStaged => "not_staged",
            Self::NotInTrial => "not_in_trial",
            Self::NothingToAbort => "nothing_to_abort",
            Self::TrialInProgress => "trial_in_progress",
            Self::StagingGap => "staging_gap",
            Self::BadTrustKey => "bad_trust_key",
            Self::DuplicateTrustKey => "duplicate_trust_key",
            Self::TrustStoreFull => "trust_store_full",
            Self::ProfileInvalid => "profile_invalid",
            Self::IsaUnsupported => "isa_unsupported",
            Self::CorruptState => "corrupt_state",
            Self::Journal(code) => code,
        }
    }
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for UpdateError {}

impl From<franken_journal::JournalError> for UpdateError {
    fn from(error: franken_journal::JournalError) -> Self {
        Self::Journal(error.code())
    }
}

/// SHA-256 of the concatenation of `parts`.
#[must_use]
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}
