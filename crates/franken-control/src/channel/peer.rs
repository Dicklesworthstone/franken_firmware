//! Peer identity, roles and the authority contract of the control channel (N02 / `ffw-ugf`).
//!
//! Who may talk to the channel is decided by a [`PeerAuthority`]. What this module fixes is the
//! *contract* the channel relies on:
//!
//! * [`PeerAuthority::authenticate`] checks a proof over the exact bytes of a request and changes no
//!   state, whether it succeeds or fails. An unauthenticated caller leaves no trace.
//! * An authenticated peer is described by an [`Authenticated`] snapshot. [`PeerAuthority::is_current`]
//!   says whether that snapshot is still true. Revoking a peer, or changing the epoch its key is bound
//!   to, makes every earlier snapshot stale, so a command accepted a moment ago cannot run after the
//!   authority behind it has gone.
//! * A revoked identity does not come back by replaying an old admission: admission carries a version,
//!   revocation leaves a tombstone at that version, and only a strictly higher version is admitted.
//! * The set of distinct identities that can ever authenticate is bounded by [`MAX_PEERS`], which in
//!   turn bounds every per-peer table in the channel.
//!
//! [`PeerDirectory`] implements the contract over a [`SecretStore`] (P01): keys live in the store and
//! nowhere else, and the proof is **HMAC-SHA256** under the peer's key over a fixed context label and
//! the request's signed bytes, compared in constant time. The full 32-byte tag is carried.
//!
//! **What this does not decide.** How a peer obtains its key (pairing and provisioning) and key
//! rotation policy belong to P03, U01 and N01. Where keys persist is [`crate::channel::custody`]'s: it writes
//! each admission, revocation and rebinding to U01's journal before it takes effect and rebuilds the directory
//! from the journal at boot (the only [`SecretStore`] in this crate is a volatile one, compiled for tests). A key is only required to be at least [`MIN_KEY_LEN`] bytes; its
//! entropy cannot be checked here. **Authentication is not freshness:** a valid request that was held
//! back and delivered later is still a valid request. What bounds it is the epoch it names, the
//! revision it expects, and the one-outcome-per-`(peer, seq)` ledger, not a timestamp.

use std::collections::BTreeMap;
use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::contracts::secret_store::{
    SecretError, SecretHandle, SecretKind, SecretStore, SecretValue,
};

type HmacSha256 = Hmac<Sha256>;

/// Longest peer id, in bytes. Equal to the secret store's slot limit so an id can name its key slot.
pub const MAX_PEER_ID_LEN: usize = 32;
/// Longest authentication proof, in bytes.
pub const MAX_PROOF_LEN: usize = 64;
/// Length of the tag [`compute_proof`] produces: a full HMAC-SHA256 output.
pub const PROOF_LEN: usize = 32;
/// Shortest key [`PeerDirectory::admit`] accepts, in bytes.
pub const MIN_KEY_LEN: usize = 16;
/// Most distinct identities an authority may ever admit, revoked ones included.
pub const MAX_PEERS: usize = 16;
/// Explicit control-plane identity budget. The fleet profile is for host development only.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ControlProfile {
    #[default]
    Legacy,
    FleetDevelopment,
}

impl ControlProfile {
    #[must_use]
    pub const fn max_identities(self) -> usize {
        match self {
            Self::Legacy => MAX_PEERS,
            Self::FleetDevelopment => 33,
        }
    }
}
/// Domain-separation label hashed before every request. It ties a proof to this protocol and
/// version, so a tag computed for another purpose under the same key is not a valid request proof.
pub const AUTH_CONTEXT: &[u8] = b"FFCP-v1-auth";
/// Domain-separation label hashed before every reply (N02 section 9.1). It differs from [`AUTH_CONTEXT`], so a
/// tag made for a request is never a valid reply tag, and the reverse, although both are made under the same key.
pub const REPLY_CONTEXT: &[u8] = b"FFCR-v1-reply";

/// Why a peer id or a proof could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PeerError {
    #[error("invalid peer id: {reason}")]
    InvalidPeerId { reason: &'static str },
    #[error("an authentication proof must be 1 to {max} bytes, not {len}")]
    InvalidProofLength { len: usize, max: usize },
}

/// A validated peer identity: one to [`MAX_PEER_ID_LEN`] bytes of `a-z`, `0-9`, `.`, `_` and `-`,
/// starting with a letter or digit. It names a peer; it is not a credential.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(String);

impl PeerId {
    /// Validate and wrap a peer id.
    pub fn parse(raw: &str) -> Result<Self, PeerError> {
        if raw.is_empty() {
            return Err(PeerError::InvalidPeerId { reason: "empty" });
        }
        if raw.len() > MAX_PEER_ID_LEN {
            return Err(PeerError::InvalidPeerId {
                reason: "longer than the peer id limit",
            });
        }
        let starts_ok = raw
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        if !starts_ok {
            return Err(PeerError::InvalidPeerId {
                reason: "must start with a lowercase letter or a digit",
            });
        }
        let alphabet_ok = raw.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        });
        if !alphabet_ok {
            return Err(PeerError::InvalidPeerId {
                reason: "only a-z, 0-9, '.', '_' and '-' are allowed",
            });
        }
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Heap bytes retained by this identity.
    #[must_use]
    pub fn owned_heap_bytes(&self) -> usize {
        self.0.capacity()
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a peer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PeerRole {
    /// A remote controller, bound to one group epoch: it is held to the epoch and revision checks.
    Controller,
    /// The person at the device. Never refused for epoch or revision reasons, because it acts on what
    /// is audible in front of it; it still authenticates, is rate-limited and is deduplicated.
    LocalUser,
}

/// An authentication proof (a message authentication tag), bounded, carried with a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthProof(Vec<u8>);

impl AuthProof {
    /// One to [`MAX_PROOF_LEN`] bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, PeerError> {
        if bytes.is_empty() || bytes.len() > MAX_PROOF_LEN {
            return Err(PeerError::InvalidProofLength {
                len: bytes.len(),
                max: MAX_PROOF_LEN,
            });
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Why authentication failed. The messages say nothing about keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthFailure {
    #[error("the peer is not admitted")]
    UnknownPeer,
    #[error("the peer's admission was revoked")]
    Revoked,
    #[error("the authentication proof does not match the request")]
    BadProof,
}

/// A successful authentication, as of one version of the peer's admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    pub peer: PeerId,
    pub role: PeerRole,
    /// The group epoch this peer's key is bound to; `None` for a peer that is not epoch-scoped.
    pub bound_epoch: Option<u64>,
    /// Admission version. A change of binding or a re-admission produces a different one.
    pub version: u64,
}

/// A copied current admission, without cloning its already-known identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAdmission {
    pub role: PeerRole,
    pub bound_epoch: Option<u64>,
    pub version: u64,
}

/// The authority the control channel asks about every request. See the module documentation for the
/// contract an implementation must keep.
pub trait PeerAuthority {
    /// Identity budget of this authority. Existing implementations retain the legacy profile.
    fn control_profile(&self) -> ControlProfile {
        ControlProfile::Legacy
    }
    /// Verify `proof` over `message` for `peer`. Changes no state, on success or failure.
    fn authenticate(
        &self,
        peer: &PeerId,
        message: &[u8],
        proof: &AuthProof,
    ) -> Result<Authenticated, AuthFailure>;

    /// Whether `auth` still describes the peer: admitted, not revoked, same binding, same version.
    fn is_current(&self, auth: &Authenticated) -> bool;
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; PROOF_LEN] {
    // HMAC accepts a key of any length, so this cannot fail.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    for part in parts {
        mac.update(part);
    }
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; PROOF_LEN];
    tag.copy_from_slice(&full[..PROOF_LEN]);
    tag
}

/// The proof a peer holding `key` attaches to a request whose signed bytes are `message`.
#[must_use]
pub fn compute_proof(key: &[u8], message: &[u8]) -> AuthProof {
    AuthProof(compute_proof_fixed(key, message).to_vec())
}

/// The same request proof in fixed storage, for bounded local READY signing.
#[must_use]
pub fn compute_proof_fixed(key: &[u8], message: &[u8]) -> [u8; PROOF_LEN] {
    hmac_sha256(key, &[AUTH_CONTEXT, message])
}

/// The tag a channel holding `key` puts on a reply whose signed bytes are `message`. A client holding the same key
/// recomputes it with [`reply_tag_matches`].
#[must_use]
pub fn compute_reply_tag(key: &[u8], message: &[u8]) -> AuthProof {
    AuthProof(hmac_sha256(key, &[REPLY_CONTEXT, message]).to_vec())
}

/// Whether `tag` is the reply tag of `message` under `key`, compared in constant time.
#[must_use]
pub fn reply_tag_matches(key: &[u8], message: &[u8], tag: &[u8]) -> bool {
    constant_time_eq(&hmac_sha256(key, &[REPLY_CONTEXT, message]), tag)
}

/// An authority that can put a reply tag on behalf of a peer it currently admits (N02 section 9.1).
///
/// Kept apart from [`PeerAuthority`] so that an authority that only verifies requests, such as a test double,
/// stays valid. It changes no state.
pub trait ReplySigner {
    /// The reply tag of `message` under `peer`'s key, or `None` if the peer is not admitted now (unknown or
    /// revoked) or its key cannot be read. A revoked peer is never signed for.
    fn sign_reply(&self, peer: &PeerId, message: &[u8]) -> Option<AuthProof>;
}

/// Equality that does not stop at the first differing byte. Lengths are not secret.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Why an admission was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitError {
    AlreadyAdmitted,
    /// A failed restore requires a fresh directory; no partial authority may be used.
    RestoreFailed,
    /// The directory already knows `MAX_PEERS` distinct identities.
    Full,
    /// `offered` is not above the tombstone left by an earlier revocation.
    Resurrection {
        tombstone: u64,
        offered: u64,
    },
    /// The key is shorter than [`MIN_KEY_LEN`]. Only its length is reported, never its content.
    KeyTooShort {
        len: usize,
        min: usize,
    },
    Key(SecretError),
}

/// What a directory remembers about the identities it has revoked, in a form the owner can store and give
/// back after a restart (N02 acceptance row 6, "tombstone generations across restart").
///
/// Where and how it is stored is U01's. The channel only produces it ([`PeerDirectory::tombstones`]) and
/// accepts it ([`PeerDirectory::restore_tombstones`]). Without it a restart forgets every revocation, and
/// the stale admission U01 may still hold for a revoked identity would bring its old key back.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tombstones {
    /// Bumped by every revocation that wiped a peer. A snapshot whose generation is below the directory's
    /// is missing a revocation: **store the new snapshot before treating a revocation as done**.
    pub generation: u64,
    /// One entry per revoked identity, in identity order: the version it was revoked at. Only a strictly
    /// higher version re-admits it.
    pub entries: Vec<(PeerId, u64)>,
}

/// Why a [`Tombstones`] snapshot could not be restored. Nothing was changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RestoreError {
    /// Tombstones are restored first, into a directory that has admitted and revoked nobody, so no
    /// admission can precede the memory of its revocation.
    #[error(
        "tombstones can only be restored into a directory that has admitted and revoked nobody"
    )]
    NotFresh,
    /// A directory never knows more than [`MAX_PEERS`] identities.
    #[error("a snapshot holds at most {max} tombstones")]
    TooMany { max: usize },
    /// A well-formed snapshot has one entry per identity.
    #[error("the snapshot names one identity twice")]
    Duplicate,
}

struct PeerRecord {
    role: PeerRole,
    bound_epoch: Option<u64>,
    version: u64,
}

/// The peers that may speak, their roles, the epoch each key is bound to, and the keys themselves
/// (held in a [`SecretStore`], never in this struct).
pub struct PeerDirectory<S: SecretStore> {
    keys: S,
    profile: ControlProfile,
    restore_failed: bool,
    peers: BTreeMap<PeerId, PeerRecord>,
    tombstones: BTreeMap<PeerId, u64>,
    tombstone_generation: u64,
}

fn key_handle(peer: &PeerId) -> Result<SecretHandle, SecretError> {
    SecretHandle::new(SecretKind::ControlPeerKey, peer.as_str())
}

impl<S: SecretStore> PeerDirectory<S> {
    /// A directory with no peers, keeping its keys in `keys`. The store must have room for
    /// [`MAX_PEERS`] keys.
    pub fn with_store(keys: S) -> Self {
        Self::with_profile(keys, ControlProfile::Legacy)
    }

    /// Select the identity budget explicitly; the supplied store must support it.
    pub fn with_profile(keys: S, profile: ControlProfile) -> Self {
        Self {
            keys,
            profile,
            restore_failed: false,
            peers: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            tombstone_generation: 0,
        }
    }

    #[must_use]
    pub const fn profile(&self) -> ControlProfile {
        self.profile
    }

    pub(super) fn is_fresh_for_restore(&self) -> bool {
        !self.restore_failed && self.peers.is_empty() && self.tombstones.is_empty()
    }

    /// A failed journal restore must not leave a partially authenticated directory.
    pub(super) fn discard_failed_restore(&mut self) {
        for peer in self.peers.keys() {
            if let Ok(handle) = key_handle(peer) {
                let _ = self.keys.remove(&handle);
            }
        }
        self.peers.clear();
        self.tombstones.clear();
        self.tombstone_generation = 0;
        self.restore_failed = true;
    }

    fn known_identities(&self) -> usize {
        let revoked_only = self
            .tombstones
            .keys()
            .filter(|id| !self.peers.contains_key(*id))
            .count();
        self.peers.len() + revoked_only
    }

    /// Whether [`PeerDirectory::admit`] would take `peer` at `version` with a key of `key_len` bytes, judged
    /// on what the directory holds now: the identity is not already live, a tombstone is exceeded, there is
    /// room for one more identity, and the key is long enough. Changes nothing.
    ///
    /// It cannot say whether the key store will take the key (that is `admit`'s own last step), so an owner
    /// that must not act on a refusal it could have foreseen (the custody module stores the admission
    /// before it takes effect) asks here first.
    ///
    /// # Errors
    /// The first rule the admission would break, in the order `admit` checks them.
    pub fn check_admit(
        &self,
        peer: &PeerId,
        key_len: usize,
        version: u64,
    ) -> Result<(), AdmitError> {
        if self.restore_failed {
            return Err(AdmitError::RestoreFailed);
        }
        if self.peers.contains_key(peer) {
            return Err(AdmitError::AlreadyAdmitted);
        }
        if let Some(&tombstone) = self.tombstones.get(peer) {
            if version <= tombstone {
                return Err(AdmitError::Resurrection {
                    tombstone,
                    offered: version,
                });
            }
        } else if self.known_identities() >= self.profile.max_identities() {
            return Err(AdmitError::Full);
        }
        if key_len < MIN_KEY_LEN {
            return Err(AdmitError::KeyTooShort {
                len: key_len,
                min: MIN_KEY_LEN,
            });
        }
        Ok(())
    }

    /// The version `peer` is admitted at, or `None` if it is not live (never admitted, or revoked).
    #[must_use]
    pub fn version_of(&self, peer: &PeerId) -> Option<u64> {
        self.peers.get(peer).map(|record| record.version)
    }

    /// Admit `peer` at `version` with `key`, optionally bound to a group epoch.
    pub fn admit(
        &mut self,
        peer: &PeerId,
        role: PeerRole,
        key: &[u8],
        bound_epoch: Option<u64>,
        version: u64,
    ) -> Result<(), AdmitError> {
        self.check_admit(peer, key.len(), version)?;
        let handle = key_handle(peer).map_err(AdmitError::Key)?;
        let value = SecretValue::new(key.to_vec()).map_err(AdmitError::Key)?;
        self.keys.insert(&handle, value).map_err(AdmitError::Key)?;
        self.peers.insert(
            peer.clone(),
            PeerRecord {
                role,
                bound_epoch,
                version,
            },
        );
        Ok(())
    }

    /// Revoke `peer`: its key is wiped and a tombstone is left at its current version.
    pub fn revoke(&mut self, peer: &PeerId) -> bool {
        let Some(record) = self.peers.remove(peer) else {
            return false;
        };
        self.tombstones.insert(peer.clone(), record.version);
        self.tombstone_generation = self.tombstone_generation.saturating_add(1);
        if let Ok(handle) = key_handle(peer) {
            let _ = self.keys.remove(&handle);
        }
        true
    }

    /// The revocations to store, so that a restart does not forget them. See [`Tombstones`].
    #[must_use]
    pub fn tombstones(&self) -> Tombstones {
        Tombstones {
            generation: self.tombstone_generation,
            entries: self
                .tombstones
                .iter()
                .map(|(peer, version)| (peer.clone(), *version))
                .collect(),
        }
    }

    /// The generation [`PeerDirectory::tombstones`] would carry now.
    #[must_use]
    pub const fn tombstone_generation(&self) -> u64 {
        self.tombstone_generation
    }

    /// Put a stored snapshot back after a restart. It goes into a **fresh** directory, before any
    /// admission, so the stale admission of a revoked identity that U01 may still hold is refused as the
    /// resurrection it is. A snapshot that is too big or names an identity twice is refused whole.
    pub fn restore_tombstones(&mut self, snapshot: &Tombstones) -> Result<(), RestoreError> {
        if self.restore_failed || !self.peers.is_empty() || !self.tombstones.is_empty() {
            return Err(RestoreError::NotFresh);
        }
        if snapshot.entries.len() > self.profile.max_identities() {
            return Err(RestoreError::TooMany {
                max: self.profile.max_identities(),
            });
        }
        let mut restored = BTreeMap::new();
        for (peer, version) in &snapshot.entries {
            if restored.insert(peer.clone(), *version).is_some() {
                return Err(RestoreError::Duplicate);
            }
        }
        self.tombstones = restored;
        self.tombstone_generation = snapshot.generation;
        Ok(())
    }

    /// Change the epoch a peer's key is bound to. Every earlier snapshot of the peer goes stale.
    /// Returns `None` without changing either binding or version if the peer is absent or its
    /// admission generation is exhausted. Generations never wrap or reuse an earlier snapshot.
    pub fn rebind(&mut self, peer: &PeerId, bound_epoch: Option<u64>) -> Option<u64> {
        let record = self.peers.get_mut(peer)?;
        let next_version = record.version.checked_add(1)?;
        record.bound_epoch = bound_epoch;
        record.version = next_version;
        Some(record.version)
    }

    /// How many keys the store holds for this directory.
    #[must_use]
    pub fn key_slots(&self) -> usize {
        self.keys.list().len()
    }
}

impl<S: SecretStore> ReplySigner for PeerDirectory<S> {
    fn sign_reply(&self, peer: &PeerId, message: &[u8]) -> Option<AuthProof> {
        if !self.peers.contains_key(peer) {
            return None;
        }
        let handle = key_handle(peer).ok()?;
        self.keys
            .with_secret(&handle, |_, key| compute_reply_tag(key, message))
            .ok()
    }
}

impl<S: SecretStore> PeerDirectory<S> {
    /// Verify against this directory's current enrolled key without cloning the peer or proof.
    /// The supplied handle must be the actual ControlPeerKey slot for `peer`.
    pub fn authenticate_fixed(
        &self,
        peer: &PeerId,
        handle: &SecretHandle,
        message: &[u8],
        proof: &[u8; PROOF_LEN],
    ) -> Result<PeerAdmission, AuthFailure> {
        let record = self.peer_record(peer)?;
        self.authenticate_tag(peer, record, handle, message, proof)
    }

    fn peer_record(&self, peer: &PeerId) -> Result<&PeerRecord, AuthFailure> {
        self.peers.get(peer).ok_or_else(|| {
            if self.tombstones.contains_key(peer) {
                AuthFailure::Revoked
            } else {
                AuthFailure::UnknownPeer
            }
        })
    }

    fn authenticate_tag(
        &self,
        peer: &PeerId,
        record: &PeerRecord,
        handle: &SecretHandle,
        message: &[u8],
        proof: &[u8],
    ) -> Result<PeerAdmission, AuthFailure> {
        if handle.kind() != SecretKind::ControlPeerKey || handle.slot().as_str() != peer.as_str() {
            return Err(AuthFailure::BadProof);
        }
        let expected = self
            .keys
            .with_secret(handle, |_, key| compute_proof_fixed(key, message))
            .map_err(|_| AuthFailure::UnknownPeer)?;
        if !constant_time_eq(&expected, proof) {
            return Err(AuthFailure::BadProof);
        }
        Ok(PeerAdmission {
            role: record.role,
            bound_epoch: record.bound_epoch,
            version: record.version,
        })
    }
}

impl<S: SecretStore> PeerAuthority for PeerDirectory<S> {
    fn control_profile(&self) -> ControlProfile {
        self.profile
    }
    fn authenticate(
        &self,
        peer: &PeerId,
        message: &[u8],
        proof: &AuthProof,
    ) -> Result<Authenticated, AuthFailure> {
        let record = self.peer_record(peer)?;
        let handle = key_handle(peer).map_err(|_| AuthFailure::UnknownPeer)?;
        let admission = self.authenticate_tag(peer, record, &handle, message, proof.as_bytes())?;
        Ok(Authenticated {
            peer: peer.clone(),
            role: admission.role,
            bound_epoch: admission.bound_epoch,
            version: admission.version,
        })
    }

    fn is_current(&self, auth: &Authenticated) -> bool {
        self.peers
            .get(&auth.peer)
            .is_some_and(|r| r.version == auth.version)
    }
}

/// A directory kept in memory, for tests. The store behind it is volatile by construction.
#[cfg(test)]
pub mod ephemeral {
    use super::PeerDirectory;
    use crate::contracts::secret_store::{EphemeralSecretStore, MAX_SECRETS};

    pub type EphemeralPeers = PeerDirectory<EphemeralSecretStore>;

    impl PeerDirectory<EphemeralSecretStore> {
        #[must_use]
        pub fn new() -> Self {
            Self::with_store(EphemeralSecretStore::with_capacity(MAX_SECRETS))
        }
    }

    impl Default for PeerDirectory<EphemeralSecretStore> {
        fn default() -> Self {
            Self::new()
        }
    }

    /// A deterministic test key for `peer`: long enough to be admitted, different for every peer.
    /// It is a fixture, not a secret.
    #[must_use]
    pub fn test_key(peer: &str) -> Vec<u8> {
        format!("key-{peer}-0123456789abcdef").into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use franken_session::AuthorityToken;

    use super::ephemeral::{EphemeralPeers, test_key};
    use super::*;
    use crate::channel::pipeline::{ChannelConfig, ControlChannel, Rejection, SubmitResult};
    use crate::channel::request::{ControlCommand, ControlRequest, RequestBody};
    use crate::channel::testkit::fixture_session;

    fn id(raw: &str) -> PeerId {
        PeerId::parse(raw).unwrap()
    }

    #[test]
    fn fixed_request_proof_uses_real_current_directory_and_exact_handle() {
        let mut directory = admitted();
        let peer = id("ctl-a");
        let handle = SecretHandle::new(SecretKind::ControlPeerKey, peer.as_str()).unwrap();
        let message = b"actual-ready-binding";
        let proof = compute_proof_fixed(&test_key("ctl-a"), message);
        let actual = directory
            .authenticate_fixed(&peer, &handle, message, &proof)
            .unwrap();
        let legacy = directory
            .authenticate(&peer, message, &compute_proof(&test_key("ctl-a"), message))
            .unwrap();
        assert_eq!(
            actual,
            PeerAdmission {
                role: legacy.role,
                bound_epoch: legacy.bound_epoch,
                version: legacy.version
            }
        );
        assert!(peer.owned_heap_bytes() >= peer.as_str().len());
        assert!(handle.owned_heap_bytes() >= handle.slot().as_str().len());
        let wrong_key = compute_proof_fixed(&test_key("ctl-b"), message);
        assert_eq!(
            directory.authenticate_fixed(&peer, &handle, message, &wrong_key),
            Err(AuthFailure::BadProof)
        );
        let reply = compute_reply_tag(&test_key("ctl-a"), message);
        let wrong_domain: [u8; PROOF_LEN] = reply.as_bytes().try_into().unwrap();
        assert_eq!(
            directory.authenticate_fixed(&peer, &handle, message, &wrong_domain),
            Err(AuthFailure::BadProof)
        );
        let wrong_slot = SecretHandle::new(SecretKind::ControlPeerKey, "ctl-b").unwrap();
        let wrong_kind = SecretHandle::new(SecretKind::StreamAuthKey, peer.as_str()).unwrap();
        assert_eq!(
            directory.authenticate_fixed(&peer, &wrong_slot, message, &proof),
            Err(AuthFailure::BadProof)
        );
        assert_eq!(
            directory.authenticate_fixed(&peer, &wrong_kind, message, &proof),
            Err(AuthFailure::BadProof)
        );
        assert_ne!(
            actual,
            PeerAdmission {
                role: PeerRole::LocalUser,
                ..actual
            }
        );
        assert_ne!(
            actual,
            PeerAdmission {
                version: actual.version + 1,
                ..actual
            }
        );
        directory
            .rebind(&peer, Some(actual.bound_epoch.unwrap_or(0) + 1))
            .unwrap();
        let rebound = directory
            .authenticate_fixed(&peer, &handle, message, &proof)
            .unwrap();
        assert_ne!(actual, rebound);
        assert!(directory.revoke(&peer));
        assert_eq!(
            directory.authenticate_fixed(&peer, &handle, message, &proof),
            Err(AuthFailure::Revoked)
        );
    }

    fn sign(peer: &str, message: &[u8]) -> AuthProof {
        compute_proof(&test_key(peer), message)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn admitted() -> EphemeralPeers {
        let mut peers = EphemeralPeers::new();
        peers
            .admit(
                &id("ctl-a"),
                PeerRole::Controller,
                &test_key("ctl-a"),
                Some(10),
                1,
            )
            .unwrap();
        peers
            .admit(
                &id("panel"),
                PeerRole::LocalUser,
                &test_key("panel"),
                None,
                1,
            )
            .unwrap();
        peers
    }

    #[test]
    fn peer_ids_are_bounded_lowercase_labels() {
        let longest = "x".repeat(MAX_PEER_ID_LEN);
        for raw in ["ctl-a", "a", "0", "a.b_c-d", longest.as_str()] {
            assert_eq!(PeerId::parse(raw).unwrap().as_str(), raw);
        }
        let long = "x".repeat(MAX_PEER_ID_LEN + 1);
        for raw in [
            "",
            "Ctl",
            "has space",
            "user@example.com",
            "-lead",
            ".lead",
            "tok-SECRET",
            "caf\u{e9}",
            long.as_str(),
        ] {
            assert!(
                matches!(PeerId::parse(raw), Err(PeerError::InvalidPeerId { .. })),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn a_peer_id_error_never_echoes_the_input() {
        let text = format!("{}", PeerId::parse("tok-SECRET-9f3a").unwrap_err());
        assert!(!text.contains("SECRET"), "{text}");
    }

    #[test]
    fn proofs_are_one_to_the_limit_bytes() {
        assert!(AuthProof::new(vec![1]).is_ok());
        assert!(AuthProof::new(vec![1; MAX_PROOF_LEN]).is_ok());
        for len in [0, MAX_PROOF_LEN + 1] {
            assert_eq!(
                AuthProof::new(vec![1; len]).unwrap_err(),
                PeerError::InvalidProofLength {
                    len,
                    max: MAX_PROOF_LEN
                }
            );
        }
    }

    /// RFC 4231 test cases 1 and 2, through the same primitive the proofs use.
    #[test]
    fn the_hmac_primitive_matches_the_published_test_vectors() {
        let case1 = hmac_sha256(&[0x0b; 20], &[b"Hi There"]);
        assert_eq!(
            hex(&case1),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        let case2 = hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]);
        assert_eq!(
            hex(&case2),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// Pinned from Python's `hmac.new(key, b"FFCP-v1-auth" + message, hashlib.sha256)`, a different
    /// implementation of the same standard, so the label and the order of the parts are checked too.
    #[test]
    fn a_proof_is_hmac_sha256_over_the_context_label_then_the_message() {
        let proof = compute_proof(b"key-ctl-a-0123456789abcdef", b"message");
        assert_eq!(proof.as_bytes().len(), PROOF_LEN);
        assert_eq!(
            hex(proof.as_bytes()),
            "7a6401ff5b93d113a8ee226fb855e5a036ae8e25bffbde7d8ef1142df41e8806"
        );
        // Not the bare HMAC of the message: the label is part of what is authenticated.
        assert_ne!(
            proof.as_bytes(),
            hmac_sha256(b"key-ctl-a-0123456789abcdef", &[b"message"]).as_slice()
        );
    }

    #[test]
    fn a_valid_proof_authenticates_with_role_binding_and_version() {
        let peers = admitted();
        let msg = b"set volume 30";
        let auth = peers
            .authenticate(&id("ctl-a"), msg, &sign("ctl-a", msg))
            .unwrap();
        assert_eq!(auth.peer, id("ctl-a"));
        assert_eq!(auth.role, PeerRole::Controller);
        assert_eq!(auth.bound_epoch, Some(10));
        assert_eq!(auth.version, 1);
        let panel = peers
            .authenticate(&id("panel"), msg, &sign("panel", msg))
            .unwrap();
        assert_eq!((panel.role, panel.bound_epoch), (PeerRole::LocalUser, None));
    }

    #[test]
    fn the_wrong_key_a_changed_message_and_an_unknown_peer_are_all_refused_distinctly() {
        let peers = admitted();
        let msg = b"stop";
        let forged = compute_proof(b"an-attackers-key-0123456789", msg);
        assert_eq!(
            peers.authenticate(&id("ctl-a"), msg, &forged),
            Err(AuthFailure::BadProof)
        );
        // A genuine proof for one message does not carry over to another.
        let genuine = sign("ctl-a", msg);
        assert_eq!(
            peers.authenticate(&id("ctl-a"), b"stop!", &genuine),
            Err(AuthFailure::BadProof)
        );
        // A genuine proof does not carry over to another peer.
        assert_eq!(
            peers.authenticate(&id("panel"), msg, &genuine),
            Err(AuthFailure::BadProof)
        );
        assert_eq!(
            peers.authenticate(&id("nobody"), msg, &genuine),
            Err(AuthFailure::UnknownPeer)
        );
    }

    #[test]
    fn a_proof_of_the_wrong_length_is_refused_even_when_it_is_a_prefix_of_the_right_one() {
        let peers = admitted();
        let msg = b"stop";
        let genuine = sign("ctl-a", msg);
        let bytes = genuine.as_bytes();
        for cut in [1, 8, 16, PROOF_LEN - 1] {
            let short = AuthProof::new(bytes[..cut].to_vec()).unwrap();
            assert_eq!(
                peers.authenticate(&id("ctl-a"), msg, &short),
                Err(AuthFailure::BadProof),
                "a {cut}-byte prefix"
            );
        }
        let mut long = bytes.to_vec();
        long.push(0);
        assert_eq!(
            peers.authenticate(&id("ctl-a"), msg, &AuthProof::new(long).unwrap()),
            Err(AuthFailure::BadProof)
        );
    }

    #[test]
    fn the_proof_is_sensitive_to_every_input() {
        let key = b"a-key-of-sixteen-bytes-or-more";
        let base = compute_proof(key, b"message");
        assert_ne!(
            base,
            compute_proof(b"A-key-of-sixteen-bytes-or-more", b"message")
        );
        assert_ne!(base, compute_proof(key, b"messagf"));
        assert_ne!(base, compute_proof(key, b"message\0"));
        assert_ne!(base, compute_proof(key, b"messag"));
        assert_eq!(base, compute_proof(key, b"message"));
        assert_eq!(base.as_bytes().len(), PROOF_LEN);
    }

    #[test]
    fn a_key_shorter_than_the_minimum_is_refused_without_echoing_it() {
        let mut peers = EphemeralPeers::new();
        let short = b"too-short";
        let err = peers
            .admit(&id("ctl-a"), PeerRole::Controller, short, Some(1), 1)
            .unwrap_err();
        assert_eq!(
            err,
            AdmitError::KeyTooShort {
                len: short.len(),
                min: MIN_KEY_LEN
            }
        );
        assert!(!format!("{err:?}").contains("too-short"));
        assert_eq!(peers.key_slots(), 0, "nothing was stored");
        // Exactly the minimum is accepted.
        assert!(
            peers
                .admit(
                    &id("ctl-a"),
                    PeerRole::Controller,
                    &[7; MIN_KEY_LEN],
                    Some(1),
                    1
                )
                .is_ok()
        );
    }

    #[test]
    fn authentication_changes_no_state() {
        let peers = admitted();
        let slots = peers.key_slots();
        let msg = b"x";
        let _ = peers.authenticate(&id("ctl-a"), msg, &sign("ctl-a", msg));
        let _ = peers.authenticate(&id("ctl-a"), msg, &AuthProof::new(vec![9; 8]).unwrap());
        let _ = peers.authenticate(&id("nobody"), msg, &AuthProof::new(vec![9; 8]).unwrap());
        assert_eq!(peers.key_slots(), slots);
    }

    #[test]
    fn revocation_wipes_the_key_stales_snapshots_and_names_the_failure() {
        let mut peers = admitted();
        let msg = b"mute";
        let proof = sign("ctl-a", msg);
        let snapshot = peers.authenticate(&id("ctl-a"), msg, &proof).unwrap();
        assert!(peers.is_current(&snapshot));
        let slots = peers.key_slots();

        assert!(peers.revoke(&id("ctl-a")));
        assert!(!peers.revoke(&id("ctl-a")), "revoking twice is a no-op");
        assert_eq!(peers.key_slots(), slots - 1, "the key was removed");
        assert!(!peers.is_current(&snapshot));
        // The same genuine proof that worked a moment ago is now refused as revoked.
        assert_eq!(
            peers.authenticate(&id("ctl-a"), msg, &proof),
            Err(AuthFailure::Revoked)
        );
    }

    #[test]
    fn a_revoked_identity_is_not_resurrected_by_replaying_its_old_admission() {
        let mut peers = admitted();
        peers.revoke(&id("ctl-a"));
        for stale in [0, 1] {
            assert_eq!(
                peers.admit(
                    &id("ctl-a"),
                    PeerRole::Controller,
                    &test_key("ctl-a"),
                    Some(10),
                    stale
                ),
                Err(AdmitError::Resurrection {
                    tombstone: 1,
                    offered: stale
                }),
                "version {stale}"
            );
        }
        // A strictly higher version is a deliberate re-admission, with a new key.
        let new_key = b"a-replacement-key-0123456789".to_vec();
        peers
            .admit(&id("ctl-a"), PeerRole::Controller, &new_key, Some(10), 2)
            .unwrap();
        let msg = b"play";
        let ok = peers
            .authenticate(&id("ctl-a"), msg, &compute_proof(&new_key, msg))
            .unwrap();
        assert_eq!(ok.version, 2);
        // The old key does not work any more.
        assert_eq!(
            peers.authenticate(&id("ctl-a"), msg, &sign("ctl-a", msg)),
            Err(AuthFailure::BadProof)
        );
    }

    #[test]
    fn a_snapshot_taken_before_re_admission_or_rebinding_is_stale() {
        let mut peers = admitted();
        let msg = b"m";
        let before = peers
            .authenticate(&id("ctl-a"), msg, &sign("ctl-a", msg))
            .unwrap();
        assert_eq!(peers.rebind(&id("ctl-a"), Some(11)), Some(2));
        assert!(!peers.is_current(&before));
        let after = peers
            .authenticate(&id("ctl-a"), msg, &sign("ctl-a", msg))
            .unwrap();
        assert_eq!((after.bound_epoch, after.version), (Some(11), 2));
        assert!(peers.is_current(&after));
        assert_eq!(peers.rebind(&id("nobody"), None), None);
    }

    #[test]
    fn rebind_generation_exhaustion_preserves_authenticated_binding_without_wrapping() {
        for initial_version in [u64::MAX - 1, u64::MAX] {
            let mut peers = EphemeralPeers::new();
            let peer = id("ctl-a");
            let message = b"generation-boundary";
            let proof = sign("ctl-a", message);
            peers
                .admit(
                    &peer,
                    PeerRole::Controller,
                    &test_key("ctl-a"),
                    Some(10),
                    initial_version,
                )
                .unwrap();
            let before = peers.authenticate(&peer, message, &proof).unwrap();
            if initial_version == u64::MAX - 1 {
                // The last legal transition succeeds and invalidates the previous snapshot.
                assert_eq!(peers.rebind(&peer, Some(11)), Some(u64::MAX));
                assert!(!peers.is_current(&before));
            }
            let ceiling = peers.authenticate(&peer, message, &proof).unwrap();
            assert_eq!(ceiling.version, u64::MAX);
            assert_eq!(
                ceiling.bound_epoch,
                Some(if initial_version == u64::MAX - 1 {
                    11
                } else {
                    10
                })
            );
            let tombstones = peers.tombstones();
            for rejected_binding in [None, Some(12), ceiling.bound_epoch] {
                assert_eq!(peers.rebind(&peer, rejected_binding), None);
                assert_eq!(peers.version_of(&peer), Some(u64::MAX));
                assert_eq!(peers.authenticate(&peer, message, &proof).unwrap(), ceiling);
                assert!(peers.is_current(&ceiling));
                assert_eq!(peers.key_slots(), 1);
                assert_eq!(peers.tombstones(), tombstones);
            }
            // Refusal does not prevent revocation, nor permit resurrection at the ceiling.
            assert!(peers.revoke(&peer));
            assert!(!peers.is_current(&ceiling));
            assert_eq!(peers.key_slots(), 0);
            assert_eq!(
                peers.authenticate(&peer, message, &proof),
                Err(AuthFailure::Revoked)
            );
            assert_eq!(
                peers.admit(
                    &peer,
                    PeerRole::Controller,
                    &test_key("ctl-a"),
                    Some(12),
                    u64::MAX
                ),
                Err(AdmitError::Resurrection {
                    tombstone: u64::MAX,
                    offered: u64::MAX
                })
            );
        }
    }

    #[test]
    fn a_double_admission_is_refused_and_keeps_the_first_key() {
        let mut peers = admitted();
        assert_eq!(
            peers.admit(
                &id("ctl-a"),
                PeerRole::LocalUser,
                b"another-key-0123456789",
                None,
                9
            ),
            Err(AdmitError::AlreadyAdmitted)
        );
        let msg = b"m";
        let auth = peers
            .authenticate(&id("ctl-a"), msg, &sign("ctl-a", msg))
            .unwrap();
        assert_eq!(auth.role, PeerRole::Controller);
    }

    #[test]
    fn the_number_of_identities_ever_admitted_is_bounded_and_revoked_ones_count() {
        let mut peers = EphemeralPeers::new();
        for i in 0..MAX_PEERS {
            let name = format!("p{i}");
            peers
                .admit(
                    &id(&name),
                    PeerRole::Controller,
                    &test_key(&name),
                    Some(1),
                    1,
                )
                .unwrap();
        }
        let extra = test_key("one-more");
        assert_eq!(
            peers.admit(&id("one-more"), PeerRole::Controller, &extra, Some(1), 1),
            Err(AdmitError::Full)
        );
        // Revoking one does not free its identity: the tombstone still counts.
        peers.revoke(&id("p0"));
        assert_eq!(
            peers.admit(&id("one-more"), PeerRole::Controller, &extra, Some(1), 1),
            Err(AdmitError::Full)
        );
        // But the revoked identity itself can come back at a higher version.
        assert!(
            peers
                .admit(
                    &id("p0"),
                    PeerRole::Controller,
                    &test_key("p0-again"),
                    Some(1),
                    2
                )
                .is_ok()
        );
    }

    // ------------------------------------------------------------------ tombstones across a restart

    fn name_n(i: usize) -> String {
        format!("p{i}")
    }

    fn snapshot_of(count: usize) -> Tombstones {
        Tombstones {
            generation: count as u64,
            entries: (0..count).map(|i| (id(&name_n(i)), 1)).collect(),
        }
    }

    #[test]
    fn tombstones_are_exported_one_per_revoked_identity_with_a_generation() {
        let mut peers = admitted();
        assert_eq!(peers.tombstones(), Tombstones::default());
        // Revoking someone who is not admitted changes nothing, generation included.
        assert!(!peers.revoke(&id("nobody")));
        assert_eq!(peers.tombstone_generation(), 0);

        assert!(peers.revoke(&id("ctl-a")));
        assert!(!peers.revoke(&id("ctl-a")), "already revoked");
        assert_eq!(
            peers.tombstones(),
            Tombstones {
                generation: 1,
                entries: vec![(id("ctl-a"), 1)]
            }
        );

        // A rebinding raises the version; a revocation after it leaves the higher tombstone, in order.
        peers.rebind(&id("panel"), None);
        assert!(peers.revoke(&id("panel")));
        assert_eq!(
            peers.tombstones(),
            Tombstones {
                generation: 2,
                entries: vec![(id("ctl-a"), 1), (id("panel"), 2)]
            }
        );
    }

    #[test]
    fn a_restored_directory_refuses_to_resurrect_a_revoked_identity_at_or_below_its_tombstone() {
        let mut before = admitted();
        before.revoke(&id("ctl-a"));
        let stored = before.tombstones();

        let mut after = EphemeralPeers::new();
        after.restore_tombstones(&stored).unwrap();
        assert_eq!(
            after.tombstones(),
            stored,
            "the snapshot round-trips, generation included"
        );
        for stale in [0, 1] {
            assert_eq!(
                after.admit(
                    &id("ctl-a"),
                    PeerRole::Controller,
                    &test_key("ctl-a"),
                    Some(10),
                    stale
                ),
                Err(AdmitError::Resurrection {
                    tombstone: 1,
                    offered: stale
                }),
                "version {stale}"
            );
        }
        // The deliberate re-admission, one version up with a new key, works; the old key does not.
        let new_key = b"a-replacement-key-0123456789".to_vec();
        after
            .admit(&id("ctl-a"), PeerRole::Controller, &new_key, Some(10), 2)
            .unwrap();
        let msg = b"play";
        assert!(
            after
                .authenticate(&id("ctl-a"), msg, &compute_proof(&new_key, msg))
                .is_ok()
        );
        assert_eq!(
            after.authenticate(&id("ctl-a"), msg, &sign("ctl-a", msg)),
            Err(AuthFailure::BadProof)
        );
        // The generation carries on from the restored one.
        assert!(after.revoke(&id("ctl-a")));
        assert_eq!(after.tombstone_generation(), 2);
    }

    #[test]
    fn the_generation_tells_the_owner_a_revocation_is_not_yet_stored() {
        let mut peers = admitted();
        let stored = peers.tombstones();
        assert_eq!(peers.tombstone_generation(), stored.generation);
        peers.revoke(&id("ctl-a"));
        assert_ne!(
            peers.tombstone_generation(),
            stored.generation,
            "the stored snapshot is now behind: store the new one before the revocation counts as done"
        );
        let stored = peers.tombstones();
        assert_eq!(peers.tombstone_generation(), stored.generation);
    }

    #[test]
    fn a_snapshot_that_cannot_be_restored_is_refused_whole_and_changes_nothing() {
        // Not into a directory that has admitted somebody, nor one that has revoked somebody.
        let mut used = admitted();
        assert_eq!(
            used.restore_tombstones(&Tombstones::default()),
            Err(RestoreError::NotFresh)
        );
        let mut revoked = EphemeralPeers::new();
        revoked
            .restore_tombstones(&snapshot_of(1))
            .expect("a fresh directory takes a snapshot");
        assert_eq!(
            revoked.restore_tombstones(&snapshot_of(1)),
            Err(RestoreError::NotFresh)
        );

        // Too many, and a duplicate: refused, and the directory is still fresh afterwards.
        let mut fresh = EphemeralPeers::new();
        assert_eq!(
            fresh.restore_tombstones(&snapshot_of(MAX_PEERS + 1)),
            Err(RestoreError::TooMany { max: MAX_PEERS })
        );
        let mut twice = snapshot_of(2);
        twice.entries[1].0 = twice.entries[0].0.clone();
        assert_eq!(
            fresh.restore_tombstones(&twice),
            Err(RestoreError::Duplicate)
        );
        assert_eq!(fresh.tombstones(), Tombstones::default());
        assert!(
            fresh.restore_tombstones(&snapshot_of(MAX_PEERS)).is_ok(),
            "exactly the bound is fine"
        );
    }

    #[test]
    fn restored_tombstones_still_count_as_identities_ever_admitted() {
        let mut peers = EphemeralPeers::new();
        peers.restore_tombstones(&snapshot_of(MAX_PEERS)).unwrap();
        let key = test_key("one-more");
        assert_eq!(
            peers.admit(&id("one-more"), PeerRole::Controller, &key, Some(1), 1),
            Err(AdmitError::Full)
        );
        // A revoked identity itself can still come back at a higher version.
        assert!(
            peers
                .admit(&id("p0"), PeerRole::Controller, &test_key("p0"), Some(1), 2)
                .is_ok()
        );
    }

    // ------------------------------------------------------------------ the judge, through the channel

    /// What the persistence layer gives back across the restart. `Faithful` is exactly what was stored; the
    /// others are faults a careless owner could have: nothing stored, versions off by one, a snapshot taken
    /// before the revocation (a crash between the revocation and the store), and nothing stored where U01
    /// also happens not to replay the revoked identity's old record.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Persisted {
        Faithful,
        Lost,
        OffByOne,
        Stale,
        LostNotReplayed,
    }

    /// `ctl-a` is revoked; the process restarts into a fresh directory; U01 replays the admissions it still
    /// holds, the revoked identity's among them; then the revoked key signs a command.
    ///
    /// What a faithful restart must show is **exactly** what the directory showed before it: the stale
    /// admission is refused as a resurrection, and the key is answered `Revoked`, with nothing settled and
    /// the volume untouched. "Some rejection" is not enough: `UnknownPeer` would mean the restart forgot
    /// who was revoked. Failures begin with `RESURRECTED` (the key, or its admission, got back in) or
    /// `WRONG-REASON` (it was refused, but not as `Revoked`).
    fn judge_a_revoked_peer_stays_revoked_across_a_restart(
        persisted: Persisted,
    ) -> Result<(), String> {
        let mut before = admitted();
        let taken_before_the_revocation = before.tombstones();
        before.revoke(&id("ctl-a"));
        let stored = before.tombstones();

        let handed_back = match persisted {
            Persisted::Faithful => stored,
            Persisted::Lost | Persisted::LostNotReplayed => Tombstones::default(),
            Persisted::OffByOne => Tombstones {
                generation: stored.generation,
                entries: stored
                    .entries
                    .iter()
                    .map(|(peer, version)| (peer.clone(), version - 1))
                    .collect(),
            },
            Persisted::Stale => taken_before_the_revocation,
        };
        let mut after = EphemeralPeers::new();
        after
            .restore_tombstones(&handed_back)
            .map_err(|e| format!("RESTORE: {e}"))?;

        // U01's records, replayed as they were. The revoked identity's must be refused as a resurrection.
        if persisted != Persisted::LostNotReplayed {
            let replay = after.admit(
                &id("ctl-a"),
                PeerRole::Controller,
                &test_key("ctl-a"),
                Some(10),
                1,
            );
            if !matches!(
                replay,
                Err(AdmitError::Resurrection {
                    tombstone: 1,
                    offered: 1
                })
            ) {
                return Err(format!(
                    "RESURRECTED: the stale admission of the revoked identity gave {replay:?}"
                ));
            }
        }
        after
            .admit(
                &id("panel"),
                PeerRole::LocalUser,
                &test_key("panel"),
                None,
                1,
            )
            .map_err(|e| format!("setup: {e:?}"))?;

        let mut session = fixture_session(10);
        let mut config = ChannelConfig::provisional();
        config.session_seq_base = 1_000;
        let mut channel = ControlChannel::new(after, config).map_err(|e| format!("setup: {e}"))?;
        let token = AuthorityToken::issue(&session, 100_000_000_000);
        channel
            .install_lease(&session, token, 0)
            .map_err(|e| format!("setup: {e}"))?;
        let body = RequestBody::new(
            id("ctl-a"),
            1,
            10,
            Some(session.state_revision),
            ControlCommand::SetGroupVolume { volume: 99 },
        )
        .map_err(|e| format!("setup: {e}"))?;
        let proof = compute_proof(&test_key("ctl-a"), &body.signing_bytes());
        let result = channel.submit(0, ControlRequest::new(body, proof));
        let settled = channel.step(0, &mut session);
        if !settled.is_empty() || session.group_master_volume != 50 {
            return Err(format!(
                "RESURRECTED: the revoked key was answered {result:?}, {} commands settled, group volume {}",
                settled.len(),
                session.group_master_volume
            ));
        }
        let revoked = SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::Revoked));
        if result != revoked {
            return Err(format!(
                "WRONG-REASON: the revoked key was answered {result:?}, not as Revoked: the restart no longer remembers the revocation"
            ));
        }
        Ok(())
    }

    #[test]
    fn a_faithful_restart_keeps_a_revoked_peer_revoked() {
        assert_eq!(
            judge_a_revoked_peer_stays_revoked_across_a_restart(Persisted::Faithful),
            Ok(())
        );
    }

    #[test]
    fn a_restart_answers_a_revoked_key_exactly_as_the_directory_did_before() {
        // Before: a revoked identity is Revoked, a stranger is UnknownPeer. After a faithful restore the
        // same, because the answer comes from the remembered tombstone and nothing else.
        let message = b"play";
        let mut before = admitted();
        before.revoke(&id("ctl-a"));
        let mut after = EphemeralPeers::new();
        after.restore_tombstones(&before.tombstones()).unwrap();
        for directory in [&before, &after] {
            assert_eq!(
                directory.authenticate(&id("ctl-a"), message, &sign("ctl-a", message)),
                Err(AuthFailure::Revoked)
            );
            assert_eq!(
                directory.authenticate(&id("ghost"), message, &sign("ctl-a", message)),
                Err(AuthFailure::UnknownPeer)
            );
        }
    }

    #[test]
    fn each_planted_persistence_fault_fails_the_judge_by_name() {
        // A judge that fails everything proves nothing, so the faithful restart passes first.
        assert_eq!(
            judge_a_revoked_peer_stays_revoked_across_a_restart(Persisted::Faithful),
            Ok(())
        );
        for (fault, tag) in [
            (Persisted::Lost, "RESURRECTED"),
            (Persisted::OffByOne, "RESURRECTED"),
            (Persisted::Stale, "RESURRECTED"),
            (Persisted::LostNotReplayed, "WRONG-REASON"),
        ] {
            let verdict = judge_a_revoked_peer_stays_revoked_across_a_restart(fault);
            assert!(
                verdict.as_ref().is_err_and(|e| e.starts_with(tag)),
                "{fault:?} was not caught as {tag}: {verdict:?}"
            );
        }
    }

    #[test]
    fn a_deliberate_re_admission_at_a_higher_version_works_through_the_channel_after_a_restart() {
        let mut before = admitted();
        before.revoke(&id("ctl-a"));
        let mut after = EphemeralPeers::new();
        after.restore_tombstones(&before.tombstones()).unwrap();
        let new_key = b"a-replacement-key-0123456789".to_vec();
        after
            .admit(&id("ctl-a"), PeerRole::Controller, &new_key, Some(10), 2)
            .unwrap();

        let mut session = fixture_session(10);
        let mut config = ChannelConfig::provisional();
        config.session_seq_base = 1_000;
        let mut channel = ControlChannel::new(after, config).unwrap();
        let token = AuthorityToken::issue(&session, 100_000_000_000);
        channel.install_lease(&session, token, 0).unwrap();
        let body = RequestBody::new(
            id("ctl-a"),
            1,
            10,
            Some(session.state_revision),
            ControlCommand::SetGroupVolume { volume: 99 },
        )
        .unwrap();
        let proof = compute_proof(&new_key, &body.signing_bytes());
        assert!(matches!(
            channel.submit(0, ControlRequest::new(body, proof)),
            SubmitResult::Queued { .. }
        ));
        assert_eq!(channel.step(0, &mut session).len(), 1);
        assert_eq!(session.group_master_volume, 99);
    }
}
