//! The per-boot incarnation of a shim's event subscription table (`docs/contracts/g03.md` section 11 item 5).
//!
//! A subscription id is a UUID-shaped string: its first ten bytes are the boot's incarnation (less the six bits a version-4 UUID
//! fixes) and its last six bytes are a counter that starts again at 1 on every boot. So the incarnation is the ONLY thing that makes
//! an id of this boot differ from the same-numbered id of an earlier boot. With one constant incarnation, a controller that kept its
//! id across a restart finds it valid again the moment a fresh subscription takes the same number, and its stale renewal or
//! unsubscribe then extends or removes the NEW subscription. So every boot of a shim takes its incarnation from the host, once, at
//! startup, and the endpoint's own legacy constructor and goldens keep their fixture nonce (`ControlPlane::new`).
//!
//! * **The source is the host's entropy device**, read for ten bytes. Nothing is derived from a clock, a counter, a process id or an
//!   address: those repeat across boots, which is the defect.
//! * **A failure is typed and stops the startup before anything is bound** ([`IncarnationError`]). There is no fixed fallback value.
//!   A draw of ten identical bytes is refused too: it is what a device that reports success without producing entropy gives, and it
//!   would hand every boot the same ids. That is a sanity check, not a randomness test.
//! * **74 bits remain.** The core fixes six bits of the ten bytes (the UUID version and variant) and keeps the other 74 in the id, so
//!   two boots share a namespace with probability 2^-74. That is a boot namespace for stale-id refusal, not impossible uniqueness and
//!   not authentication: an id is not a secret.
//!
//! What it is not: the device's entropy. A device build takes its incarnation from `franken_platform::secure_entropy` (P02: one
//! explicitly selected provider and no insecure fallback, `/dev/urandom` refused there on purpose) and passes it to
//! `ControlPlane::with_incarnation`. This reader is for the loopback shim, which exists in harness and test builds only.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use franken_control::fsonos::gena::INCARNATION_BYTES;

/// The host's entropy device. Where it does not exist the open fails, and the startup is refused.
const HOST_ENTROPY: &str = "/dev/urandom";

/// Why a boot incarnation could not be had. No path and no byte is carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncarnationError {
    /// The entropy device could not be opened or read: the kind of the I/O error.
    Unavailable(io::ErrorKind),
    /// The device ended before ten bytes had been read.
    Short,
    /// The ten bytes read were all the same: a device that reports success without producing entropy.
    Degenerate,
}

impl IncarnationError {
    /// A fixed word for the startup error and the log.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable(_) => "entropy_unavailable",
            Self::Short => "entropy_short",
            Self::Degenerate => "entropy_degenerate",
        }
    }
}

fn unavailable(error: &io::Error) -> IncarnationError {
    IncarnationError::Unavailable(error.kind())
}

/// The incarnation of this boot, read from the host's entropy device.
///
/// # Errors
/// [`IncarnationError`] if the device cannot be opened or read, ends early, or gives ten identical bytes.
pub fn host_incarnation() -> Result<[u8; INCARNATION_BYTES], IncarnationError> {
    incarnation_from(Path::new(HOST_ENTROPY))
}

/// [`host_incarnation`] over the device at `device`. The path is a seam so the failing cases can be reached with real files and
/// devices; production passes only [`HOST_ENTROPY`].
pub(super) fn incarnation_from(device: &Path) -> Result<[u8; INCARNATION_BYTES], IncarnationError> {
    let mut file = File::open(device).map_err(|error| unavailable(&error))?;
    let mut bytes = [0_u8; INCARNATION_BYTES];
    if let Err(error) = file.read_exact(&mut bytes) {
        return Err(match error.kind() {
            io::ErrorKind::UnexpectedEof => IncarnationError::Short,
            _ => unavailable(&error),
        });
    }
    if bytes.iter().all(|byte| *byte == bytes[0]) {
        return Err(IncarnationError::Degenerate);
    }
    Ok(bytes)
}
