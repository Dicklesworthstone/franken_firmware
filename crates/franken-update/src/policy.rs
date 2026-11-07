//! Admission (`docs/contracts/u02.md` section 3): what the device knows locally, and the one fixed order in which a candidate meets it.
//! The first rule a candidate breaks names the refusal; nothing about a refused candidate is kept.
//!
//! Order: structure, trust (key, then signature), the trust boundary, the board, the production policy (E01 evidence), required features,
//! anti-rollback, old/new settings and calibration, the SSH declaration, capacity. The signature is checked before any other field of the
//! candidate is believed.

use franken_board_profile::{BoardProfile, CpuIsa};

use crate::UpdateError;
use crate::manifest::{
    AUTH_INCLUDE_MATCH, AUTH_PASSWORD, AUTH_PUBKEY_ONLY, DOMAIN, FLAG_AB_CLAIM, FLAG_BYPASS_CLAIM,
    FLAG_VENDOR_CLAIM, Isa, Manifest, OPENSSH_FIXED, SshDeclaration, SshFix, Stage, ZERO32,
};
use crate::sig;

pub const MAX_KEYS: usize = 4;
/// Length of a packed [`Installed`].
pub const INSTALLED_LEN: usize = 55;
/// What a plan says about the vendor. There is no other value.
pub const VENDOR_ACCEPTANCE: &str = "not_claimed";

/// The first eight bytes of the SHA-256 of a public key.
#[must_use]
pub fn key_id_of(public: &[u8; 32]) -> [u8; 8] {
    let digest = crate::sha256(&[&public[..]]);
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    pub key_id: [u8; 8],
    pub public: [u8; 32],
    pub revoked: bool,
}

/// Up to [`MAX_KEYS`] public keys. A key id is derived from the key, never supplied, and a key that is not [`sig::key_admissible`] is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustStore {
    keys: Vec<TrustedKey>,
}

impl TrustStore {
    /// # Errors
    /// [`UpdateError::TrustStoreFull`], [`UpdateError::BadTrustKey`] or [`UpdateError::DuplicateTrustKey`].
    pub fn new(keys: &[([u8; 32], bool)]) -> Result<Self, UpdateError> {
        if keys.len() > MAX_KEYS {
            return Err(UpdateError::TrustStoreFull);
        }
        let mut out: Vec<TrustedKey> = Vec::with_capacity(keys.len());
        for (public, revoked) in keys {
            if !sig::key_admissible(public) {
                return Err(UpdateError::BadTrustKey);
            }
            let key_id = key_id_of(public);
            if out.iter().any(|known| known.key_id == key_id) {
                return Err(UpdateError::DuplicateTrustKey);
            }
            out.push(TrustedKey {
                key_id,
                public: *public,
                revoked: *revoked,
            });
        }
        Ok(Self { keys: out })
    }

    fn find(&self, key_id: &[u8; 8]) -> Option<&TrustedKey> {
        self.keys.iter().find(|key| &key.key_id == key_id)
    }
}

/// The board this device is, as far as an update is concerned. It comes from E01's [`BoardProfile`], never from a candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Board {
    pub profile_id: String,
    pub hw_rev: String,
    pub isa: Isa,
    pub kernel_profile: String,
    /// The profile is a fabricated test fixture: it never passes the production policy.
    pub synthetic: bool,
    /// Every fact of the profile is attested by evidence (E01's `activation_blockers` is empty).
    pub attested: bool,
}

impl Board {
    /// # Errors
    /// [`UpdateError::ProfileInvalid`] when the profile fails its own integrity and admission gate, [`UpdateError::IsaUnsupported`] when its
    /// ISA is not one this update format can name.
    pub fn from_profile(profile: &BoardProfile) -> Result<Self, UpdateError> {
        profile
            .verify_integrity()
            .map_err(|_| UpdateError::ProfileInvalid)?;
        let isa = match profile.cpu_isa {
            CpuIsa::PowerPc32BigEndian => Isa::Ppc32Be,
            CpuIsa::Mips32R2BigEndian => Isa::Mips32R2Be,
            _ => return Err(UpdateError::IsaUnsupported),
        };
        Ok(Self {
            profile_id: profile.profile_id.clone(),
            hw_rev: profile.supported_hw_rev.clone(),
            isa,
            kernel_profile: profile.kernel_capability_profile.clone(),
            synthetic: profile.is_synthetic_fixture(),
            attested: profile.activation_blockers().is_empty(),
        })
    }
}

/// The summary of the image that is installed, as the journal keeps it (`u02.inst`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub version: u32,
    pub security_version: u32,
    pub settings_schema: u16,
    pub settings_read_min: u16,
    pub calibration_schema: u16,
    pub wire_schema: u16,
    pub wire_read_min: u16,
    pub wire_read_max: u16,
    pub features: u16,
    pub sha: [u8; 32],
}

impl Installed {
    #[must_use]
    pub fn of(m: &Manifest) -> Self {
        Self {
            version: m.version,
            security_version: m.security_version,
            settings_schema: m.settings_schema,
            settings_read_min: m.settings_read_min,
            calibration_schema: m.calibration_schema,
            wire_schema: m.wire_schema,
            wire_read_min: m.wire_read_min,
            wire_read_max: m.wire_read_max,
            features: m.features,
            sha: m.sha256,
        }
    }

    #[must_use]
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INSTALLED_LEN);
        out.push(1);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.security_version.to_be_bytes());
        for n in [
            self.settings_schema,
            self.settings_read_min,
            self.calibration_schema,
            self.wire_schema,
            self.wire_read_min,
            self.wire_read_max,
            self.features,
        ] {
            out.extend_from_slice(&n.to_be_bytes());
        }
        out.extend_from_slice(&self.sha);
        out
    }

    /// `None` for anything that is not exactly a packed record of this format.
    #[must_use]
    pub fn unpack(raw: &[u8]) -> Option<Self> {
        if raw.len() != INSTALLED_LEN || raw[0] != 1 {
            return None;
        }
        let be16 = |at: usize| u16::from_be_bytes([raw[at], raw[at + 1]]);
        let be32 = |at: usize| u32::from_be_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]]);
        let mut sha = [0u8; 32];
        sha.copy_from_slice(&raw[23..55]);
        Some(Self {
            version: be32(1),
            security_version: be32(5),
            settings_schema: be16(9),
            settings_read_min: be16(11),
            calibration_schema: be16(13),
            wire_schema: be16(15),
            wire_read_min: be16(17),
            wire_read_max: be16(19),
            features: be16(21),
            sha,
        })
    }
}

/// An external statement that a board's flash holds two slots of a given size. The digest binds the receipt; this crate cannot check its
/// content. A receipt for a synthetic fixture is refused for any board that is not one. A receipt whose digest is all zero (`ZERO32` means absent
/// everywhere else in this crate) binds nothing: whatever slot size it names, it never proves A/B.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbReceipt {
    pub slot_bytes: u32,
    pub digest: [u8; 32],
    pub synthetic: bool,
}

/// What the device is configured with; none of it comes from a candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub trust: TrustStore,
    pub board: Board,
    /// Production admission. `false` is an offline test configuration.
    pub production: bool,
    /// E01's evidence digest for this board, as supplied by the owner of that output. `None` means none was supplied.
    pub evidence: Option<[u8; 32]>,
    /// Feature bits an image must carry (P01's required features).
    pub required: u16,
    /// Explicit consent to install a lower `version`. It never lowers the security floor.
    pub allow_downgrade: bool,
    /// The settings schema of a preserved copy made before a migration, if one exists.
    pub settings_backup: Option<u16>,
    pub staging_bytes: u32,
    pub reserve: u32,
    pub recovery_path: bool,
    pub ab_receipt: Option<AbReceipt>,
}

/// What the journal says right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dynamic {
    pub installed: Option<Installed>,
    pub floor: u64,
    pub failed: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    AbSlots,
    SingleSlotRecovery,
}

impl Mode {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AbSlots => "ab_slots",
            Self::SingleSlotRecovery => "single_slot_recovery",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbStatus {
    NotProven,
    ProvenByExternalReceipt,
}

impl AbStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotProven => "not_proven",
            Self::ProvenByExternalReceipt => "proven_by_external_receipt",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    pub mode: Mode,
    pub ab: AbStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    pub manifest: Manifest,
    pub plan: Plan,
    pub downgrade: bool,
}

/// Verify the signature of `m`: the key must be trusted and not revoked, and the signature must verify over `DOMAIN || body`.
///
/// # Errors
/// [`UpdateError::UnknownSigningKey`], [`UpdateError::RevokedSigningKey`] or [`UpdateError::BadSignature`].
pub fn verify_signature(policy: &Policy, m: &Manifest) -> Result<(), UpdateError> {
    let key = policy
        .trust
        .find(&m.key_id)
        .ok_or(UpdateError::UnknownSigningKey)?;
    if key.revoked {
        return Err(UpdateError::RevokedSigningKey);
    }
    let mut signed = Vec::with_capacity(DOMAIN.len() + m.body.len());
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(&m.body);
    if sig::verify(&key.public, &signed, &m.signature) {
        Ok(())
    } else {
        Err(UpdateError::BadSignature)
    }
}

/// Can an image that writes settings schema `schema` and reads `read_min..=schema` read settings stored at `stored`, or restore from a
/// preserved copy at `backup`?
#[must_use]
pub fn settings_readable(read_min: u16, schema: u16, stored: u16, backup: Option<u16>) -> bool {
    let reads = |n: u16| (read_min..=schema).contains(&n);
    reads(stored) || backup.is_some_and(reads)
}

fn ssh_check(policy: &Policy, ssh: Option<&SshDeclaration>) -> Result<(), UpdateError> {
    let Some(ssh) = ssh else {
        return Ok(());
    };
    let version = (ssh.major, ssh.minor, ssh.portable);
    let fixed =
        (ssh.fix == SshFix::Upstream && version >= OPENSSH_FIXED) || ssh.fix == SshFix::Reviewed;
    if !fixed {
        return Err(UpdateError::SshFixMissing);
    }
    if ssh.source_digest == ZERO32 || ssh.build_digest == ZERO32 {
        return Err(UpdateError::SshUnbound);
    }
    if ssh.auth & AUTH_PASSWORD != 0 {
        if policy.production {
            return Err(UpdateError::SshPasswordForbidden);
        }
    } else if ssh.auth & AUTH_PUBKEY_ONLY == 0 || ssh.auth & AUTH_INCLUDE_MATCH == 0 {
        return Err(UpdateError::SshAuthUnresolved);
    }
    if policy.production && ssh.qualification == ZERO32 {
        return Err(UpdateError::SshUnqualified);
    }
    Ok(())
}

fn plan_for(policy: &Policy, m: &Manifest) -> Result<Plan, UpdateError> {
    let need = u64::from(m.artifact_size) + u64::from(policy.reserve);
    let mut chosen = None;
    if let Some(receipt) = policy.ab_receipt {
        if receipt.synthetic && !policy.board.synthetic {
            return Err(UpdateError::SyntheticReceiptForRealProfile);
        }
        if receipt.digest != ZERO32 && u64::from(receipt.slot_bytes) >= need {
            chosen = Some(Plan {
                mode: Mode::AbSlots,
                ab: AbStatus::ProvenByExternalReceipt,
            });
        }
    }
    match chosen {
        Some(plan) => Ok(plan),
        None if policy.recovery_path => Ok(Plan {
            mode: Mode::SingleSlotRecovery,
            ab: AbStatus::NotProven,
        }),
        None => Err(UpdateError::NoRecoveryPath),
    }
}

/// Admit a candidate manifest, or name the first rule it breaks.
///
/// # Errors
/// See `docs/contracts/u02.md` section 3 for the order and every name.
pub fn admit(policy: &Policy, state: &Dynamic, raw: &[u8]) -> Result<Admitted, UpdateError> {
    let m = Manifest::parse(raw)?;
    verify_signature(policy, &m)?;
    if m.stage != Stage::Userspace {
        return Err(UpdateError::StageForbidden);
    }
    if m.flags & FLAG_VENDOR_CLAIM != 0 {
        return Err(UpdateError::VendorClaimForbidden);
    }
    if m.flags & FLAG_BYPASS_CLAIM != 0 {
        return Err(UpdateError::BypassClaimForbidden);
    }
    if m.flags & FLAG_AB_CLAIM != 0 {
        return Err(UpdateError::AbClaimForbidden);
    }
    let board = &policy.board;
    if m.profile_id != board.profile_id {
        return Err(UpdateError::WrongBoard);
    }
    if m.hw_rev != board.hw_rev {
        return Err(UpdateError::HardwareRevisionMismatch);
    }
    if m.isa != board.isa {
        return Err(UpdateError::IsaMismatch);
    }
    if m.kernel_profile != board.kernel_profile {
        return Err(UpdateError::KernelProfileMismatch);
    }
    if policy.production {
        if board.synthetic || !board.attested {
            return Err(UpdateError::ProfileNotAttested);
        }
        if policy.evidence != Some(m.evidence_digest) {
            return Err(UpdateError::EvidenceMismatch);
        }
    }
    if m.features & policy.required != policy.required {
        return Err(UpdateError::RequiredFeatureMissing);
    }
    if u64::from(m.security_version) < state.floor {
        return Err(UpdateError::BelowSecurityFloor);
    }
    if state.failed == Some(m.sha256) {
        return Err(UpdateError::CandidatePreviouslyFailed);
    }
    let mut downgrade = false;
    if let Some(installed) = &state.installed {
        if m.sha256 == installed.sha {
            return Err(UpdateError::AlreadyInstalled);
        }
        if m.version == installed.version {
            return Err(UpdateError::VersionReused);
        }
        if m.version < installed.version {
            downgrade = true;
            if !policy.allow_downgrade {
                return Err(UpdateError::DowngradeNotPermitted);
            }
        }
        if m.calibration_schema != installed.calibration_schema {
            return Err(UpdateError::CalibrationSchemaMismatch);
        }
        if !settings_readable(
            m.settings_read_min,
            m.settings_schema,
            installed.settings_schema,
            policy.settings_backup,
        ) {
            return Err(UpdateError::SettingsIncompatible);
        }
    }
    ssh_check(policy, m.ssh.as_ref())?;
    if u64::from(m.artifact_size) + u64::from(policy.reserve) > u64::from(policy.staging_bytes) {
        return Err(UpdateError::InsufficientCapacity);
    }
    let plan = plan_for(policy, &m)?;
    Ok(Admitted {
        manifest: m,
        plan,
        downgrade,
    })
}
