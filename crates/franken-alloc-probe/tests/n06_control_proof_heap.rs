//! Actual calling-thread allocator checks for the N06 fixed request-proof seam.
//!
//! Uses the real PeerDirectory and existing allocator probe with a functional bounded
//! in-memory credential store. These are offline host tests of the proof/verification
//! helpers, not full READY emission, arbitrary store behavior, stack, RSS or board fit.
//! Provisioning and owned handles are outside the measured windows. The fixture store
//! follows the existing N02 heap test; its remove/reinsert generations do not prove
//! uninterrupted key custody. That is the actual media owner's separate responsibility.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::hint::black_box;

use franken_alloc_probe::{CountingAllocator, is_active, measure};
use franken_control::channel::peer::{
    AuthFailure, AuthProof, PeerAuthority, PeerDirectory, PeerId, PeerRole, compute_proof,
    compute_proof_fixed, compute_reply_tag,
};
use franken_control::contracts::secret_store::{
    Generation, MAX_SECRETS, SecretError, SecretHandle, SecretKind, SecretMeta, SecretStore,
    SecretValue,
};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator::new();

// Explicit synthetic fixture bytes, not a device/account credential.
const KEY: [u8; 32] = [0x5a; 32];
const MESSAGE: &[u8] = b"n06-fixed-proof-heap-fixture";
const EPOCH: u64 = 10;
const VERSION: u64 = 7;

// Independent Python stdlib HMAC-SHA256 anchor over AUTH_CONTEXT || MESSAGE.
const REQUEST_ANCHOR: [u8; 32] = [
    0x67, 0x9e, 0x96, 0x62, 0xcc, 0x80, 0x54, 0xa7, 0xf4, 0xf4, 0x04, 0x11, 0xd6, 0x2f, 0x82, 0xc9,
    0x18, 0xd5, 0x96, 0x90, 0xbd, 0xe4, 0xec, 0xcb, 0x3e, 0x00, 0x62, 0x97, 0xa8, 0xfc, 0x45, 0xd7,
];

/// An in-memory secret store for the real `PeerDirectory` (the library's own is test-only and not visible from here).
#[derive(Default)]
struct MapStore {
    entries: BTreeMap<SecretHandle, (Generation, SecretValue)>,
}

impl SecretStore for MapStore {
    fn insert(
        &mut self,
        handle: &SecretHandle,
        value: SecretValue,
    ) -> Result<Generation, SecretError> {
        if self.entries.contains_key(handle) {
            return Err(SecretError::AlreadyExists {
                handle: handle.clone(),
            });
        }
        if self.entries.len() >= MAX_SECRETS {
            return Err(SecretError::StoreFull { max: MAX_SECRETS });
        }
        self.entries
            .insert(handle.clone(), (Generation::FIRST, value));
        Ok(Generation::FIRST)
    }

    fn replace(
        &mut self,
        handle: &SecretHandle,
        value: SecretValue,
        expected: Generation,
    ) -> Result<Generation, SecretError> {
        let entry = self
            .entries
            .get_mut(handle)
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })?;
        if entry.0 != expected {
            return Err(SecretError::StaleGeneration {
                handle: handle.clone(),
                expected: expected.get(),
                actual: entry.0.get(),
            });
        }
        let next = entry
            .0
            .successor()
            .ok_or_else(|| SecretError::GenerationExhausted {
                handle: handle.clone(),
            })?;
        entry.1 = value;
        entry.0 = next;
        Ok(next)
    }

    fn remove(&mut self, handle: &SecretHandle) -> Result<(), SecretError> {
        self.entries
            .remove(handle)
            .map(|_| ())
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })
    }

    fn generation(&self, handle: &SecretHandle) -> Result<Generation, SecretError> {
        self.entries
            .get(handle)
            .map(|entry| entry.0)
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })
    }

    fn with_secret<R>(
        &self,
        handle: &SecretHandle,
        f: impl FnOnce(Generation, &[u8]) -> R,
    ) -> Result<R, SecretError> {
        let entry = self
            .entries
            .get(handle)
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })?;
        Ok(f(entry.0, entry.1.expose()))
    }

    fn list(&self) -> Vec<SecretMeta> {
        self.entries
            .iter()
            .map(|(handle, entry)| SecretMeta {
                handle: handle.clone(),
                generation: entry.0,
                byte_len: entry.1.byte_len(),
            })
            .collect()
    }
}

fn fixture() -> (PeerDirectory<MapStore>, PeerId, SecretHandle) {
    let peer = PeerId::parse("n06-node-a").expect("fixture peer");
    let handle = SecretHandle::new(SecretKind::ControlPeerKey, peer.as_str())
        .expect("fixture control handle");
    let mut directory = PeerDirectory::with_store(MapStore::default());
    directory
        .admit(&peer, PeerRole::Controller, &KEY, Some(EPOCH), VERSION)
        .expect("actual directory admission");
    (directory, peer, handle)
}

#[test]
fn n06_fixed_proof_valid_sign_verify_allocate_no_heap() {
    assert!(
        is_active(),
        "allocator sensor must observe a real allocation"
    );
    let (directory, peer, handle) = fixture();
    let ((proof, admission), anchor_delta) = measure(|| {
        let proof = compute_proof_fixed(black_box(&KEY), black_box(MESSAGE));
        let admission = directory.authenticate_fixed(&peer, &handle, MESSAGE, &proof);
        black_box((proof, admission))
    });
    assert_eq!(
        proof, REQUEST_ANCHOR,
        "request-domain independent HMAC anchor"
    );
    let admission = admission.expect("fixed proof must authenticate actual enrolled key");
    assert_eq!(admission.role, PeerRole::Controller);
    assert_eq!(admission.bound_epoch, Some(EPOCH));
    assert_eq!(admission.version, VERSION);
    assert!(
        anchor_delta.is_zero(),
        "anchor path allocated: {anchor_delta:?}"
    );

    let (verified, delta) = measure(|| {
        let mut verified = 0_u64;
        for sequence in 0_u64..512 {
            let message = sequence.to_be_bytes();
            let proof = compute_proof_fixed(black_box(&KEY), black_box(&message));
            if let Ok(admission) = directory.authenticate_fixed(&peer, &handle, &message, &proof)
                && admission.role == PeerRole::Controller
                && admission.bound_epoch == Some(EPOCH)
                && admission.version == VERSION
            {
                verified += 1;
            }
        }
        black_box(verified)
    });
    assert_eq!(verified, 512, "each varying signed request must verify");
    assert!(
        delta.is_zero(),
        "fixed sign/verify path allocated: {delta:?}"
    );
    assert_eq!(delta.bytes_requested, 0);
    println!(
        "N06-READY-PROOF-HEAP {{\"schema\":\"n06.ready-proof-heap.v1\",\"iterations\":512,\"verified\":{verified},\"allocations\":{},\"reallocations\":{},\"deallocations\":{},\"bytes_requested\":{}}}",
        delta.allocations, delta.reallocations, delta.deallocations, delta.bytes_requested
    );
}

#[test]
fn n06_fixed_proof_refusals_and_legacy_unknown_preserve_no_heap() {
    assert!(is_active(), "allocator sensor must be installed");
    let (mut directory, peer, handle) = fixture();
    let good = compute_proof_fixed(&KEY, MESSAGE);
    let mut corrupt = good;
    corrupt[0] ^= 1;
    let wrong_key = compute_proof_fixed(&[0xa5; 32], MESSAGE);
    let reply = compute_reply_tag(&KEY, MESSAGE);
    let mut wrong_domain = [0; 32];
    wrong_domain.copy_from_slice(reply.as_bytes());
    let wrong_slot = SecretHandle::new(SecretKind::ControlPeerKey, "different-slot").unwrap();
    let wrong_kind = SecretHandle::new(SecretKind::StreamAuthKey, peer.as_str()).unwrap();
    let unknown = PeerId::parse("unknown-node").unwrap();
    let unknown_handle = SecretHandle::new(SecretKind::ControlPeerKey, unknown.as_str()).unwrap();
    let legacy_proof = AuthProof::new(good.to_vec()).unwrap();
    let ((refused, legacy_unknown), delta) = measure(|| {
        let refused = [
            directory.authenticate_fixed(&peer, &handle, MESSAGE, &corrupt),
            directory.authenticate_fixed(&peer, &handle, MESSAGE, &wrong_key),
            directory.authenticate_fixed(&peer, &handle, b"wrong-message", &good),
            directory.authenticate_fixed(&peer, &handle, MESSAGE, &wrong_domain),
            directory.authenticate_fixed(&peer, &wrong_kind, MESSAGE, &good),
            directory.authenticate_fixed(&peer, &wrong_slot, MESSAGE, &good),
            directory.authenticate_fixed(&unknown, &unknown_handle, MESSAGE, &good),
        ];
        let legacy_unknown = directory.authenticate(&unknown, MESSAGE, &legacy_proof);
        black_box((refused, legacy_unknown))
    });
    for result in &refused[..6] {
        assert_eq!(result, &Err(AuthFailure::BadProof));
    }
    assert_eq!(refused[6], Err(AuthFailure::UnknownPeer));
    assert_eq!(legacy_unknown, Err(AuthFailure::UnknownPeer));
    assert!(
        delta.is_zero(),
        "rejected proof/unknown-peer path allocated: {delta:?}"
    );
    assert_eq!(delta.bytes_requested, 0);

    assert!(directory.revoke(&peer), "actual directory revocation");
    let (revoked, revoked_delta) =
        measure(|| directory.authenticate_fixed(&peer, &handle, MESSAGE, &good));
    assert_eq!(revoked, Err(AuthFailure::Revoked));
    assert!(
        revoked_delta.is_zero(),
        "revoked peer path allocated: {revoked_delta:?}"
    );
}

#[test]
fn n06_fixed_proof_allocator_sensor_observes_real_legacy_auth() {
    assert!(
        is_active(),
        "do not accept a vacuous zero-allocation result"
    );
    let (directory, peer, _) = fixture();
    let proof = compute_proof(&KEY, MESSAGE);
    assert_eq!(proof.as_bytes(), REQUEST_ANCHOR.as_slice());
    let (actual, delta) = measure(|| directory.authenticate(&peer, MESSAGE, &proof));
    let actual = actual.expect("legacy permitted behavior must still authenticate");
    assert_eq!(actual.peer, peer);
    assert_eq!(actual.role, PeerRole::Controller);
    assert_eq!(actual.bound_epoch, Some(EPOCH));
    assert_eq!(actual.version, VERSION);
    assert!(
        delta.allocations > 0,
        "the owned authenticated identity must register an allocation"
    );
    assert!(delta.bytes_requested >= peer.as_str().len());
    println!(
        "N06-READY-PROOF-SENSOR {{\"schema\":\"n06.ready-proof-sensor.v1\",\"allocations\":{},\"bytes_requested\":{}}}",
        delta.allocations, delta.bytes_requested
    );
}
