//! The per-board manifest (`docs/contracts/u02.md` section 2): a fixed binary layout, parsed strictly and without allocating before a
//! length has been checked. Parsing says nothing about authenticity; [`crate::policy::admit`] verifies the signature before it trusts a field.
//!
//! All integers are big endian. The signed bytes are `DOMAIN || body`, where the body is everything before the 64-byte signature, so a
//! signature made for another purpose under the same key cannot be replayed as a manifest.

use crate::UpdateError;
use crate::sig::SIGNATURE_LEN;

pub const MAGIC: [u8; 4] = *b"FFWM";
pub const FORMAT: u8 = 1;
/// Domain separation prefix of every signed manifest.
pub const DOMAIN: &[u8] = b"ffw-u02-manifest-v1\0";
pub const MAX_MANIFEST: usize = 512;
const MIN_FIXED: usize = 4 + 1 + 1 + 2 + 8;
pub const MAX_PROFILE_ID: usize = 48;
pub const MAX_HW_REV: usize = 24;
pub const MAX_KERNEL_PROFILE: usize = 40;
pub const MAX_LIBC: usize = 16;

pub const FLAG_VENDOR_CLAIM: u16 = 1;
pub const FLAG_BYPASS_CLAIM: u16 = 2;
pub const FLAG_AB_CLAIM: u16 = 4;

/// The six required native features of the P01 workspace contract, in the order of their bits (alphabetical).
pub const FEATURES: [&str; 6] = [
    "airplay2",
    "alexa_bridge",
    "protected_render",
    "spotify_connect",
    "synchronized_groups",
    "tailnet_native",
];
pub const FEATURES_ALL: u16 = (1 << FEATURES.len()) - 1;

pub const AUTH_PASSWORD: u8 = 1;
pub const AUTH_PUBKEY_ONLY: u8 = 2;
pub const AUTH_INCLUDE_MATCH: u8 = 4;
/// The first OpenSSH release that contains the musl/no-PAM password fix (4353fdc): major, minor, portable counter.
pub const OPENSSH_FIXED: (u8, u8, u8) = (10, 6, 2);
pub const ZERO32: [u8; 32] = [0; 32];

/// What the artifact replaces. Only our own userspace payload is ever admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Userspace,
    Kernel,
    Bootloader,
    VendorPackage,
}

impl Stage {
    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Userspace),
            2 => Some(Self::Kernel),
            3 => Some(Self::Bootloader),
            4 => Some(Self::VendorPackage),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isa {
    Ppc32Be,
    Mips32R2Be,
}

impl Isa {
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Ppc32Be),
            2 => Some(Self::Mips32R2Be),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshFix {
    None,
    /// The daemon is at or above the upstream release that carries the fix.
    Upstream,
    /// An older daemon with a reviewed equivalent, bound by the digest of that review.
    Reviewed,
}

/// What an image that adds or retains an SSH daemon declares. A release statement, not a scan: nothing here proves what is in the artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshDeclaration {
    pub source_digest: [u8; 32],
    pub build_digest: [u8; 32],
    pub libc: String,
    pub major: u8,
    pub minor: u8,
    pub portable: u8,
    pub fix: SshFix,
    pub fix_evidence: [u8; 32],
    pub auth: u8,
    pub qualification: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub stage: Stage,
    pub flags: u16,
    pub key_id: [u8; 8],
    pub profile_id: String,
    pub hw_rev: String,
    pub kernel_profile: String,
    pub isa: Isa,
    pub version: u32,
    pub security_version: u32,
    pub settings_schema: u16,
    pub settings_read_min: u16,
    pub calibration_schema: u16,
    pub wire_schema: u16,
    pub wire_read_min: u16,
    /// The newest wire schema this image can still read; a peer that emits a schema above it cannot be heard.
    pub wire_read_max: u16,
    pub features: u16,
    pub artifact_size: u32,
    pub artifact_sha256: [u8; 32],
    pub evidence_digest: [u8; 32],
    pub ssh: Option<SshDeclaration>,
    /// The signed bytes without the domain prefix: everything before the signature.
    pub body: Vec<u8>,
    pub signature: [u8; SIGNATURE_LEN],
    /// SHA-256 of the whole manifest as received: its identity in the journal.
    pub sha256: [u8; 32],
}

struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], UpdateError> {
        let end = self
            .at
            .checked_add(n)
            .ok_or(UpdateError::ManifestTooShort)?;
        let out = self
            .raw
            .get(self.at..end)
            .ok_or(UpdateError::ManifestTooShort)?;
        self.at = end;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], UpdateError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, UpdateError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, UpdateError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, UpdateError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    /// A length-prefixed ASCII label of `1..=max` bytes. `upper` allows upper-case letters (hardware revisions); the other labels are lower case.
    fn label(&mut self, max: usize, upper: bool) -> Result<String, UpdateError> {
        let n = usize::from(self.u8()?);
        if n == 0 || n > max {
            return Err(UpdateError::BadField);
        }
        let raw = self.take(n)?;
        if !label_ok(raw, upper) {
            return Err(UpdateError::BadField);
        }
        String::from_utf8(raw.to_vec()).map_err(|_| UpdateError::BadField)
    }
}

/// First byte a letter or digit; every byte a digit, a letter (any case if `upper`, lower case otherwise) or one of `._-`.
fn label_ok(raw: &[u8], upper: bool) -> bool {
    match raw.first() {
        Some(first) if first.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    raw.iter().all(|&b| {
        b.is_ascii_digit()
            || (b.is_ascii_alphabetic() && (upper || b.is_ascii_lowercase()))
            || matches!(b, b'.' | b'_' | b'-')
    })
}

impl Manifest {
    /// Parse the structure: lengths, magic, reserved bits and string grammar. No signature and no policy.
    ///
    /// # Errors
    /// The first structural rule the bytes break; see `docs/contracts/u02.md` section 2.
    pub fn parse(raw: &[u8]) -> Result<Self, UpdateError> {
        if raw.len() > MAX_MANIFEST {
            return Err(UpdateError::ManifestTooLong);
        }
        if raw.len() < MIN_FIXED + SIGNATURE_LEN {
            return Err(UpdateError::ManifestTooShort);
        }
        let mut r = Reader { raw, at: 0 };
        if r.array::<4>()? != MAGIC {
            return Err(UpdateError::BadMagic);
        }
        if r.u8()? != FORMAT {
            return Err(UpdateError::UnsupportedFormat);
        }
        let stage_code = r.u8()?;
        let flags = r.u16()?;
        let key_id = r.array::<8>()?;
        if flags & !(FLAG_VENDOR_CLAIM | FLAG_BYPASS_CLAIM | FLAG_AB_CLAIM) != 0 {
            return Err(UpdateError::BadField);
        }
        let stage = Stage::from_code(stage_code).ok_or(UpdateError::BadField)?;
        let profile_id = r.label(MAX_PROFILE_ID, false)?;
        let hw_rev = r.label(MAX_HW_REV, true)?;
        let kernel_profile = r.label(MAX_KERNEL_PROFILE, false)?;
        let isa = Isa::from_code(r.u8()?).ok_or(UpdateError::BadField)?;
        let version = r.u32()?;
        let security_version = r.u32()?;
        let settings_schema = r.u16()?;
        let settings_read_min = r.u16()?;
        let calibration_schema = r.u16()?;
        let wire_schema = r.u16()?;
        let wire_read_min = r.u16()?;
        let wire_read_max = r.u16()?;
        let features = r.u16()?;
        if features & !FEATURES_ALL != 0 {
            return Err(UpdateError::BadField);
        }
        if settings_read_min > settings_schema
            || wire_read_min > wire_schema
            || wire_schema > wire_read_max
            || settings_schema == 0
            || calibration_schema == 0
            || wire_schema == 0
            || settings_read_min == 0
            || wire_read_min == 0
        {
            return Err(UpdateError::BadField);
        }
        let artifact_size = r.u32()?;
        if artifact_size == 0 {
            return Err(UpdateError::BadField);
        }
        let artifact_sha256 = r.array::<32>()?;
        let evidence_digest = r.array::<32>()?;
        let ssh = match r.u8()? {
            0 => None,
            1 => Some(parse_ssh(&mut r)?),
            _ => return Err(UpdateError::BadField),
        };
        let body_len = r.at;
        let signature = r.array::<SIGNATURE_LEN>()?;
        if r.at != raw.len() {
            return Err(UpdateError::TrailingBytes);
        }
        Ok(Self {
            stage,
            flags,
            key_id,
            profile_id,
            hw_rev,
            kernel_profile,
            isa,
            version,
            security_version,
            settings_schema,
            settings_read_min,
            calibration_schema,
            wire_schema,
            wire_read_min,
            wire_read_max,
            features,
            artifact_size,
            artifact_sha256,
            evidence_digest,
            ssh,
            body: raw[..body_len].to_vec(),
            signature,
            sha256: crate::sha256(&[raw]),
        })
    }
}

fn parse_ssh(r: &mut Reader<'_>) -> Result<SshDeclaration, UpdateError> {
    let source_digest = r.array::<32>()?;
    let build_digest = r.array::<32>()?;
    let libc = r.label(MAX_LIBC, false)?;
    let major = r.u8()?;
    let minor = r.u8()?;
    let portable = r.u8()?;
    let fix_code = r.u8()?;
    let fix_evidence = r.array::<32>()?;
    let auth = r.u8()?;
    let qualification = r.array::<32>()?;
    let fix = match fix_code {
        0 => SshFix::None,
        1 => SshFix::Upstream,
        2 => SshFix::Reviewed,
        _ => return Err(UpdateError::BadField),
    };
    if auth & !(AUTH_PASSWORD | AUTH_PUBKEY_ONLY | AUTH_INCLUDE_MATCH) != 0 {
        return Err(UpdateError::BadField);
    }
    if (fix == SshFix::Reviewed) != (fix_evidence != ZERO32) {
        return Err(UpdateError::BadField);
    }
    Ok(SshDeclaration {
        source_digest,
        build_digest,
        libc,
        major,
        minor,
        portable,
        fix,
        fix_evidence,
        auth,
        qualification,
    })
}
