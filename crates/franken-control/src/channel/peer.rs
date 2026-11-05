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
//! **What this does not decide.** How a peer obtains its key (pairing and provisioning), where keys
//! persist (the only store in this crate is a volatile one, compiled for tests), and key rotation
//! policy belong to P03, U01 and N01. A key is only required to be at least [`MIN_KEY_LEN`] bytes; its
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
/// Domain-separation label hashed before every request. It ties a proof to this protocol and
/// version, so a tag computed for another purpose under the same key is not a valid request proof.
pub const AUTH_CONTEXT: &[u8] = b"FFCP-v1-auth";

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

/// The authority the control channel asks about every request. See the module documentation for the
/// contract an implementation must keep.
pub trait PeerAuthority {
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
    AuthProof(hmac_sha256(key, &[AUTH_CONTEXT, message]).to_vec())
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

struct PeerRecord {
    role: PeerRole,
    bound_epoch: Option<u64>,
    version: u64,
}

/// The peers that may speak, their roles, the epoch each key is bound to, and the keys themselves
/// (held in a [`SecretStore`], never in this struct).
pub struct PeerDirectory<S: SecretStore> {
    keys: S,
    peers: BTreeMap<PeerId, PeerRecord>,
    tombstones: BTreeMap<PeerId, u64>,
}

fn key_handle(peer: &PeerId) -> Result<SecretHandle, SecretError> {
    SecretHandle::new(SecretKind::ControlPeerKey, peer.as_str())
}

impl<S: SecretStore> PeerDirectory<S> {
    /// A directory with no peers, keeping its keys in `keys`. The store must have room for
    /// [`MAX_PEERS`] keys.
    pub fn with_store(keys: S) -> Self {
        Self {
            keys,
            peers: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        }
    }

    fn known_identities(&self) -> usize {
        let revoked_only = self
            .tombstones
            .keys()
            .filter(|id| !self.peers.contains_key(*id))
            .count();
        self.peers.len() + revoked_only
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
        } else if self.known_identities() >= MAX_PEERS {
            return Err(AdmitError::Full);
        }
        if key.len() < MIN_KEY_LEN {
            return Err(AdmitError::KeyTooShort {
                len: key.len(),
                min: MIN_KEY_LEN,
            });
        }
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
        if let Ok(handle) = key_handle(peer) {
            let _ = self.keys.remove(&handle);
        }
        true
    }

    /// Change the epoch a peer's key is bound to. Every earlier snapshot of the peer goes stale.
    pub fn rebind(&mut self, peer: &PeerId, bound_epoch: Option<u64>) -> Option<u64> {
        let record = self.peers.get_mut(peer)?;
        record.bound_epoch = bound_epoch;
        record.version += 1;
        Some(record.version)
    }

    /// How many keys the store holds for this directory.
    #[must_use]
    pub fn key_slots(&self) -> usize {
        self.keys.list().len()
    }
}

impl<S: SecretStore> PeerAuthority for PeerDirectory<S> {
    fn authenticate(
        &self,
        peer: &PeerId,
        message: &[u8],
        proof: &AuthProof,
    ) -> Result<Authenticated, AuthFailure> {
        let Some(record) = self.peers.get(peer) else {
            return Err(if self.tombstones.contains_key(peer) {
                AuthFailure::Revoked
            } else {
                AuthFailure::UnknownPeer
            });
        };
        let handle = key_handle(peer).map_err(|_| AuthFailure::UnknownPeer)?;
        let expected = self
            .keys
            .with_secret(&handle, |_, key| hmac_sha256(key, &[AUTH_CONTEXT, message]))
            .map_err(|_| AuthFailure::UnknownPeer)?;
        if !constant_time_eq(&expected, proof.as_bytes()) {
            return Err(AuthFailure::BadProof);
        }
        Ok(Authenticated {
            peer: peer.clone(),
            role: record.role,
            bound_epoch: record.bound_epoch,
            version: record.version,
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
    use super::ephemeral::{EphemeralPeers, test_key};
    use super::*;

    fn id(raw: &str) -> PeerId {
        PeerId::parse(raw).unwrap()
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
}
