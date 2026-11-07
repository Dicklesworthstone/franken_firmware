//! Peer key custody on the settings journal (N02 / `ffw-ugf`, over U01 / `ffw-mgb`).
//!
//! The directory of peers ([`PeerDirectory`]) keeps each key in a [`SecretStore`], and the only store this
//! crate has is a volatile one. After a restart nobody would be admitted, and a revoked identity that U01 still held
//! would be admitted again. This module is the storing: it writes each admission, revocation and rebinding to
//! [`franken_journal`]'s `Credentials` namespace, in an order that keeps the live directory and the journal
//! from disagreeing, and it rebuilds the directory from the journal at boot.
//!
//! # The four calls
//!
//! * [`restore_peers`], at boot, into a directory that has admitted and revoked nobody: reads every control-peer
//!   credential from the result of `Journal::open` and puts it back (live keys with their roles, epoch bindings and
//!   versions, and the tombstones of revoked identities).
//! * [`admit_durably`], instead of `PeerDirectory::admit`.
//! * [`revoke_durably`], instead of `PeerDirectory::revoke`.
//! * [`rebind_durably`], instead of `PeerDirectory::rebind`.
//!
//! The owner of the channel reaches the directory through `ControlChannel::authority_mut`.
//!
//! # What is stored
//!
//! One credential per identity, id `cp:` followed by the peer label. `:` is outside a peer label's alphabet and a
//! credential of another kind (a provider token, a pairing key) does not start with `cp:`, so the two cannot be
//! mistaken for each other. The credential's version is the admission version. Its secret is a small record:
//!
//! ```text
//! offset  size  field
//!      0     1  format, 1
//!      1     1  role: 1 controller, 2 local user
//!      2     1  bound: 0 the key is not epoch-scoped, 1 it is bound to the epoch that follows
//!      3     8  the bound epoch, big-endian; zero when bound is 0
//!     11     n  the key (16 or more bytes)
//! ```
//!
//! Role, binding and key are one record so that a rebinding replaces all of them in one journal transaction.
//! A revoked identity is U01's `Revoked` credential: it keeps its slot and its version and holds no key, so a
//! stale admission cannot bring it back. The journal's per-credential limits bound the record: on the device
//! configuration the label is at most 29 bytes (32 less the prefix) and the key at most 117 (128 less the header).
//! The smallest configuration, which holds 16 bytes per secret, cannot hold a peer at all, and says so.
//!
//! # The order, and why
//!
//! * **Admit and rebind store first.** The directory is asked whether it would accept the change (it changes
//!   nothing), the journal commits, and only then does the directory change. If the journal refuses or fails,
//!   nothing in the directory moved, so a peer is never live without being stored. If the journal commits and the
//!   directory then refuses (its key store is full), the call says so: the credential is stored and is live from the
//!   next boot, and the peer is merely not live now, which denies and never grants.
//! * **Revoke takes effect first.** A revocation is a withdrawal of trust, so the directory refuses the key at once
//!   and the journal is written after. If the write fails, the call returns [`CustodyError::NotDurable`]: the key is
//!   dead for this run and **will be live again after a restart** unless the revocation is made again once the
//!   journal works. Calling [`revoke_durably`] again is safe: it finishes what the failed call did not. The
//!   revocation is not "done" until the call returns `Ok`.
//! * **Recovery is old or new.** U01 recovers exactly the old or exactly the new state of a commit cut short by a
//!   power failure. Each of the three stores is one transaction, so after a cut the peer is exactly as it was
//!   (absent, live, or bound to the old epoch) or exactly as it became, and never between. A rebinding written as a
//!   revocation followed by an admission would show a revoked peer between the two; the cut sweep in the tests catches
//!   that.
//!
//! # What an unreadable journal costs
//!
//! If the journal cannot be opened, or neither segment is valid, the directory is left empty: no remote peer
//! authenticates (`UnknownPeer`) until it is paired again. That is fail-closed, and it is also a lost pairing: the keys
//! lived in the journal. [`restore_peers`] says which ([`Restored::Unreadable`]) so the owner can raise an alarm.
//! A record in the journal that is not a control peer's is left alone. A control-peer record that cannot be read
//! (an unknown format, a label that is not a peer id, a key that is too short) is **not admitted** and is counted in
//! `skipped`.
//!
//! # What this does not do
//!
//! * **Pair.** How a peer obtains its key, how it is rotated and how a pairing is approved are N01's, P03's and
//!   U01's. This stores what the owner admits. The tests use fixed fixture keys.
//! * **Encrypt or hide.** Persistence is not encryption and not hardware-backed custody (U01's own limit). The
//!   journal's memory holds every secret in the clear beside the directory's key store, so a key is in RAM twice.
//!   The record buffer built for a write is zeroed afterwards on a best-effort basis, as [`SecretValue`] is.
//! * **Detect a medium put back to an older image.** A rolled-back image holds older admissions and older
//!   tombstones and is valid. U01 puts physical rollback out of scope, and so does this.
//! * **Cover U01's `reset_pairing`.** That operation revokes every credential in the journal. The directory in memory
//!   learns of it at the next restore, not at once.
//! * **Restore a tombstone generation.** [`Tombstones::generation`] counts revocations in one run. After a restore it
//!   is the number of revoked identities, which is the most the journal can say.
//! * **Bound the wear.** Each call writes one journal frame.
//!
//! The tests run on U01's in-memory medium with fault injection. That is not a flash part, and nothing here has
//! run on a device.
//!
//! [`SecretStore`]: crate::contracts::secret_store::SecretStore
//! [`SecretValue`]: crate::contracts::secret_store::SecretValue

use franken_journal::{Credential, Journal, JournalError, Recovery, Source, Storage};

use super::peer::{
    AdmitError, MAX_PEERS, MIN_KEY_LEN, PeerDirectory, PeerId, PeerRole, RestoreError, Tombstones,
};
use super::pipeline::Cause;
use crate::contracts::secret_store::SecretStore;

/// The first bytes of every control peer's credential id in the journal.
pub const ID_PREFIX: &[u8] = b"cp:";

/// The format byte of a stored record.
const FORMAT: u8 = 1;
/// The bytes before the key: format, role, bound flag and the eight-byte epoch.
const HEADER_LEN: usize = 11;

/// The credential id of `peer`: [`ID_PREFIX`] followed by its label.
fn credential_id(peer: &PeerId) -> Vec<u8> {
    let mut id = ID_PREFIX.to_vec();
    id.extend_from_slice(peer.as_str().as_bytes());
    id
}

/// The peer a credential id names, if it is a control peer's and its label is a peer id.
fn peer_of(id: &[u8]) -> Option<PeerId> {
    let label = id.strip_prefix(ID_PREFIX)?;
    PeerId::parse(std::str::from_utf8(label).ok()?).ok()
}

/// The record stored in a credential's secret. See the module documentation for the layout.
fn encode_record(role: PeerRole, bound_epoch: Option<u64>, key: &[u8]) -> Vec<u8> {
    let role_byte = match role {
        PeerRole::Controller => 1,
        PeerRole::LocalUser => 2,
    };
    let mut record = vec![FORMAT, role_byte, u8::from(bound_epoch.is_some())];
    record.extend_from_slice(&bound_epoch.unwrap_or(0).to_be_bytes());
    record.extend_from_slice(key);
    record
}

/// The role, the binding and the key of a stored record, or `None` if it is not exactly what
/// [`encode_record`] writes: a different format, an unknown role, a flag other than 0 or 1, an epoch where
/// none is bound, or a key shorter than [`MIN_KEY_LEN`].
fn decode_record(raw: &[u8]) -> Option<(PeerRole, Option<u64>, &[u8])> {
    if raw.len() < HEADER_LEN + MIN_KEY_LEN || raw[0] != FORMAT {
        return None;
    }
    let role = match raw[1] {
        1 => PeerRole::Controller,
        2 => PeerRole::LocalUser,
        _ => return None,
    };
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&raw[3..HEADER_LEN]);
    let bound = match raw[2] {
        0 if epoch == [0u8; 8] => None,
        1 => Some(u64::from_be_bytes(epoch)),
        _ => return None,
    };
    Some((role, bound, &raw[HEADER_LEN..]))
}

/// A stored record with its binding replaced.
fn rebound_record(raw: &[u8], bound_epoch: Option<u64>) -> Option<Vec<u8>> {
    let (role, _old, key) = decode_record(raw)?;
    Some(encode_record(role, bound_epoch, key))
}

/// What [`restore_peers`] found, and what it did to the directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restored {
    /// The medium was blank: the first boot of this device. Nobody was ever stored. The directory is as it was.
    FreshMedium,
    /// The journal was read. `live` identities were admitted at their stored version, role, binding and key,
    /// `revoked` tombstones were restored, and `skipped` control-peer records could not be read and were
    /// **not admitted**. Records that are not a control peer's are not counted.
    Peers {
        live: usize,
        revoked: usize,
        skipped: usize,
    },
    /// The journal could not be read (the [`Cause`] says why; its documentation speaks of the mark, and here it
    /// means the credentials). The directory is as it was, which for a fresh one is empty: no remote peer
    /// authenticates until it is paired again. The owner should raise an alarm.
    Unreadable(Cause),
}

/// Why the journal's peers could not be put into the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreFailed {
    /// The journal holds more control-peer identities than a directory knows ([`MAX_PEERS`]). Nothing was changed.
    TooMany { max: usize },
    /// The tombstones were refused, most likely because the directory is not fresh: restore goes first, before
    /// any admission, so no admission can precede the memory of its revocation. Nothing was changed.
    Tombstones(RestoreError),
    /// The directory refused a live peer after the tombstones were in (its key store refused the key). The
    /// directory is **partly filled**: discard it and start again from an empty one, which fails closed.
    Admit(AdmitError),
}

/// Why a call could not be completed. No variant carries a key or a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyError {
    /// The directory would not take the admission (already live, at or below a tombstone, no room, key too
    /// short). Nothing was written.
    Admit(AdmitError),
    /// The journal refused or failed (a value too long, a label that does not fit with its prefix, a version
    /// not above the stored one, a storage fault). Nothing in the directory changed. After a storage fault the
    /// journal is poisoned: reopen it and restore into a fresh directory before trusting either side.
    Journal(JournalError),
    /// The credential is stored but the live directory refused it (its key store refused). The peer is not live
    /// in this run and is admitted at the next restore.
    StoredNotLive(AdmitError),
    /// A revocation took effect in the directory for this run, and the journal could not store it. After a restart
    /// the key is live again unless the revocation is made again. Calling [`revoke_durably`] again finishes it.
    NotDurable(JournalError),
    /// The identity is not live in the directory.
    NotLive,
    /// The directory and the journal disagree about a live identity: the journal holds no live credential for it,
    /// or one at another version. Nothing was changed.
    OutOfStep { directory: u64, stored: Option<u64> },
    /// The stored record for the identity cannot be read, so it cannot be rewritten. Nothing was changed.
    Unreadable,
    /// The admission version cannot be raised further. Nothing was changed.
    VersionExhausted,
}

/// What [`revoke_durably`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revoked {
    /// The journal holds a tombstone for the identity (this call wrote it, or an earlier one did), and the
    /// directory refuses the key.
    Durable,
    /// The identity was live in the directory and the journal never held it, so there was nothing to write: it
    /// is revoked for this run only, and a restart does not bring it back because the journal does not know it.
    MemoryOnly,
    /// Neither the directory nor the journal held a live identity of that name. Nothing was revoked.
    NothingLive,
}

/// Put the journal's control peers into `directory`, at boot, before any admission and before the channel is
/// built.
///
/// A blank medium restores nothing. An intact journal restores its tombstones first and then its live peers
/// ([`PeerDirectory::restore_tombstones`], [`PeerDirectory::admit`]), so a live record can never be admitted at or
/// below a tombstone. A journal that failed to open, or was formatted empty because neither segment was valid,
/// restores nothing and says so ([`Restored::Unreadable`]); the directory stays empty and no remote peer
/// authenticates.
///
/// # Errors
/// [`RestoreFailed`]: the journal holds more identities than a directory knows, the directory was not fresh, or its
/// key store refused a key.
pub fn restore_peers<S: SecretStore, St: Storage>(
    directory: &mut PeerDirectory<S>,
    opened: &Result<(Journal<St>, Recovery), JournalError>,
) -> Result<Restored, RestoreFailed> {
    let journal = match opened {
        Err(error) => return Ok(Restored::Unreadable(Cause::OpenFailed(error.code()))),
        Ok((_, recovery)) if recovery.source == Source::Unrecoverable => {
            return Ok(Restored::Unreadable(Cause::Unrecoverable));
        }
        Ok((_, recovery)) if recovery.source == Source::Blank => return Ok(Restored::FreshMedium),
        Ok((journal, _)) => journal,
    };
    let mut live = Vec::new();
    let mut revoked = Vec::new();
    let mut skipped = 0usize;
    for (id, credential) in &journal.state().credentials {
        if !id.starts_with(ID_PREFIX) {
            continue;
        }
        match (peer_of(id), credential) {
            (Some(peer), Credential::Revoked { version }) => revoked.push((peer, *version)),
            (Some(peer), Credential::Live { version, secret }) => match decode_record(secret) {
                Some((role, bound, key)) => live.push((peer, role, bound, key, *version)),
                None => skipped += 1,
            },
            (None, _) => skipped += 1,
        }
    }
    if live.len() + revoked.len() > MAX_PEERS {
        return Err(RestoreFailed::TooMany { max: MAX_PEERS });
    }
    let (live_count, revoked_count) = (live.len(), revoked.len());
    let snapshot = Tombstones {
        generation: u64::try_from(revoked_count).unwrap_or(u64::MAX),
        entries: revoked,
    };
    directory
        .restore_tombstones(&snapshot)
        .map_err(RestoreFailed::Tombstones)?;
    for (peer, role, bound, key, version) in live {
        directory
            .admit(&peer, role, key, bound, version)
            .map_err(RestoreFailed::Admit)?;
    }
    Ok(Restored::Peers {
        live: live_count,
        revoked: revoked_count,
        skipped,
    })
}

/// Admit `peer`, storing the credential before the admission takes effect. Replaces `PeerDirectory::admit`.
///
/// # Errors
/// [`CustodyError::Admit`] if the directory would refuse (nothing written), [`CustodyError::Journal`] if the
/// journal refuses or fails (nothing changed in the directory), or [`CustodyError::StoredNotLive`] if the journal
/// committed and the directory's key store then refused.
pub fn admit_durably<S: SecretStore, St: Storage>(
    directory: &mut PeerDirectory<S>,
    journal: &mut Journal<St>,
    peer: &PeerId,
    role: PeerRole,
    key: &[u8],
    bound_epoch: Option<u64>,
    version: u64,
) -> Result<(), CustodyError> {
    directory
        .check_admit(peer, key.len(), version)
        .map_err(CustodyError::Admit)?;
    let mut record = encode_record(role, bound_epoch, key);
    let stored = journal.install(&credential_id(peer), version, &record);
    record.fill(0);
    stored.map_err(CustodyError::Journal)?;
    directory
        .admit(peer, role, key, bound_epoch, version)
        .map_err(CustodyError::StoredNotLive)
}

/// Revoke `peer`: the directory refuses its key at once, and the tombstone is then stored. Replaces
/// `PeerDirectory::revoke`. Safe to call again.
///
/// # Errors
/// [`CustodyError::NotDurable`] if the journal could not store the tombstone. The key is dead for this run
/// and live again after a restart unless this is called again once the journal works.
pub fn revoke_durably<S: SecretStore, St: Storage>(
    directory: &mut PeerDirectory<S>,
    journal: &mut Journal<St>,
    peer: &PeerId,
) -> Result<Revoked, CustodyError> {
    let was_live = directory.revoke(peer);
    match journal.revoke(&credential_id(peer)) {
        Ok(_) | Err(JournalError::AlreadyRevoked) => Ok(Revoked::Durable),
        Err(JournalError::NotFound) if was_live => Ok(Revoked::MemoryOnly),
        Err(JournalError::NotFound) => Ok(Revoked::NothingLive),
        Err(cause) => Err(CustodyError::NotDurable(cause)),
    }
}

/// Change the epoch `peer`'s key is bound to, storing the new record (one version higher, same role and key)
/// before the directory changes. Returns the new version. Replaces `PeerDirectory::rebind`.
///
/// # Errors
/// [`CustodyError::NotLive`] if the identity is not live; [`CustodyError::OutOfStep`] if the journal holds no
/// live credential for it at the directory's version; [`CustodyError::Unreadable`] if its stored record cannot
/// be read; [`CustodyError::VersionExhausted`]; or [`CustodyError::Journal`] if the journal refuses or fails.
/// In each case nothing in the directory changed.
pub fn rebind_durably<S: SecretStore, St: Storage>(
    directory: &mut PeerDirectory<S>,
    journal: &mut Journal<St>,
    peer: &PeerId,
    bound_epoch: Option<u64>,
) -> Result<u64, CustodyError> {
    let live = directory.version_of(peer).ok_or(CustodyError::NotLive)?;
    let id = credential_id(peer);
    let mut record = match journal.credential(&id) {
        Some(Credential::Live { version, secret }) if *version == live => {
            rebound_record(secret, bound_epoch).ok_or(CustodyError::Unreadable)?
        }
        Some(Credential::Live { version, .. }) => {
            return Err(CustodyError::OutOfStep {
                directory: live,
                stored: Some(*version),
            });
        }
        Some(Credential::Revoked { .. }) | None => {
            return Err(CustodyError::OutOfStep {
                directory: live,
                stored: None,
            });
        }
    };
    let next = live.checked_add(1).ok_or(CustodyError::VersionExhausted)?;
    let stored = journal.install(&id, next, &record);
    record.fill(0);
    stored.map_err(CustodyError::Journal)?;
    directory
        .rebind(peer, bound_epoch)
        .ok_or(CustodyError::NotLive)
}

#[cfg(test)]
mod tests {
    use franken_journal::codec::SEG_HEADER;
    use franken_journal::{Limits, MemStorage};
    use franken_session::{AuthorityToken, UnifiedGroupSession};

    use super::*;
    use crate::channel::limiter::RateLimit;
    use crate::channel::peer::ephemeral::{EphemeralPeers, test_key};
    use crate::channel::peer::{AuthFailure, compute_proof};
    use crate::channel::pipeline::{
        ChannelConfig, ControlChannel, HIGH_WATER_KEY, Outcome, Rejection,
        Restored as MarkRestored, SubmitResult, restore_from_open, step_then_store,
    };
    use crate::channel::request::{ControlCommand, ControlRequest, RequestBody};
    use crate::channel::testkit::fixture_session;

    const EPOCH: u64 = 10;
    const MS: u64 = 1_000_000;

    // How many cuts of each store leave the old state and how many the new one, as `(old, new)`. They were
    // worked out before the Rust ran, by running the same sweep over U01's independent Python journal
    // (`tests/u01/reference.py`) with the same records: a store is one frame, programmed and then synced, so
    // the cut at the sync that keeps every byte of the frame, and the uncut run, leave the new state, and every
    // shorter prefix, and the cut before the program, leave the old one. The journal's frame is 71 bytes for an
    // admission and for a rebinding and 24 bytes for a revocation, which gives 72 + 2 and 25 + 2.
    const PREDICTED_ADMIT: (usize, usize) = (72, 2);
    const PREDICTED_REVOKE: (usize, usize) = (25, 2);
    const PREDICTED_REBIND: (usize, usize) = (72, 2);

    fn id(raw: &str) -> PeerId {
        PeerId::parse(raw).unwrap()
    }

    fn limits() -> Limits {
        Limits::standard()
    }

    fn blank_medium() -> MemStorage {
        MemStorage::new(limits().segment_bytes)
    }

    fn set_group(volume: u8) -> ControlCommand {
        ControlCommand::SetGroupVolume { volume }
    }

    /// A key a peer is given when it is re-admitted one version up: not the one it had.
    fn renewed_key(peer: &str) -> Vec<u8> {
        format!("renewed-{peer}-0123456789abcdef").into_bytes()
    }

    fn config() -> ChannelConfig {
        let mut config = ChannelConfig::provisional();
        config.ordinary_rate = RateLimit::new(100_000, MS).unwrap();
        config.priority_rate = RateLimit::new(100_000, MS).unwrap();
        config.session_seq_base = 1_000;
        config
    }

    /// One incarnation of the process: an empty directory (restored from the journal if `restores`), a channel over
    /// it with a lease for the session, and the journal opened on the medium (none if it could not be opened).
    struct Life<'m> {
        channel: ControlChannel<EphemeralPeers>,
        session: UnifiedGroupSession,
        journal: Option<Journal<&'m mut MemStorage>>,
        restored: Option<Restored>,
    }

    impl<'m> Life<'m> {
        fn boot(medium: &'m mut MemStorage, restores: bool) -> Self {
            let opened = Journal::open(medium, limits());
            let mut directory = EphemeralPeers::new();
            let restored = restores.then(|| restore_peers(&mut directory, &opened).unwrap());
            let journal = opened.ok().map(|(journal, _recovery)| journal);
            let session = fixture_session(EPOCH);
            let mut channel = ControlChannel::new(directory, config()).unwrap();
            let token = AuthorityToken::issue(&session, 100_000 * MS);
            channel.install_lease(&session, token, 0).unwrap();
            Self {
                channel,
                session,
                journal,
                restored,
            }
        }

        /// A request as `peer` composes it with `key`: it names the session's current revision.
        fn request(&self, peer: &str, key: &[u8], seq: u64, epoch: u64) -> ControlRequest {
            let body = RequestBody::new(
                id(peer),
                seq,
                epoch,
                Some(self.session.state_revision),
                set_group(70),
            )
            .unwrap();
            let proof = compute_proof(key, &body.signing_bytes());
            ControlRequest::new(body, proof)
        }

        /// A request that names no revision: a controller's is turned away for it, the local user's is not.
        fn request_without_revision(
            &self,
            peer: &str,
            key: &[u8],
            seq: u64,
            epoch: u64,
        ) -> ControlRequest {
            let body = RequestBody::new(id(peer), seq, epoch, None, set_group(70)).unwrap();
            let proof = compute_proof(key, &body.signing_bytes());
            ControlRequest::new(body, proof)
        }

        /// What the channel says at its door, without a step.
        fn door(&mut self, request: ControlRequest) -> SubmitResult {
            self.channel.submit(0, request)
        }

        /// Submit and step: how the command settled. `LOCKED-OUT` if the door did not queue it.
        fn commit(
            &mut self,
            request: ControlRequest,
            peer: &str,
            seq: u64,
        ) -> Result<Outcome, String> {
            let queued = self.door(request);
            if !matches!(queued, SubmitResult::Queued { .. }) {
                return Err(format!(
                    "LOCKED-OUT: submitting ({peer}, {seq}) gave {queued:?}"
                ));
            }
            self.channel
                .step(0, &mut self.session)
                .into_iter()
                .find(|s| s.peer.as_str() == peer && s.seq == seq)
                .map(|s| s.outcome)
                .ok_or_else(|| format!("setup: ({peer}, {seq}) was not settled by that step"))
        }

        fn ops_done(&self) -> usize {
            self.journal.as_ref().map_or(0, |j| j.storage().ops_done())
        }

        fn pending_before(&self) -> Vec<usize> {
            self.journal
                .as_ref()
                .map_or_else(Vec::new, |j| j.storage().pending_before().to_vec())
        }

        /// Cut the power when storage operation `n` is about to start, keeping `k` bytes of what is unsynced.
        fn arm_cut(&mut self, n: usize, k: usize) {
            if let Some(journal) = self.journal.as_mut() {
                let storage = journal.storage_mut();
                storage.cut_after_ops = Some(n);
                storage.cut_budget = k;
            }
        }
    }

    /// How an owner behaves. `Faithful` goes through custody; each other variant is a fault an owner could have.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Owner {
        Faithful,
        /// Admits, revokes and rebinds in the directory only; nothing reaches the journal.
        NeverStores,
        /// Admits and rebinds through custody and revokes in the directory only.
        RevokesInMemoryOnly,
        /// Admits and revokes through custody and rebinds in the directory only.
        RebindsInMemoryOnly,
    }

    impl Owner {
        fn admit(self, life: &mut Life<'_>, name: &str, key: &[u8], bound: Option<u64>, v: u64) {
            let peer = id(name);
            let directory = life.channel.authority_mut();
            if self == Self::NeverStores {
                directory
                    .admit(&peer, PeerRole::Controller, key, bound, v)
                    .unwrap();
            } else {
                let journal = life.journal.as_mut().unwrap();
                admit_durably(
                    directory,
                    journal,
                    &peer,
                    PeerRole::Controller,
                    key,
                    bound,
                    v,
                )
                .unwrap();
            }
        }

        /// The person at the device: a local user, not bound to an epoch, version 1.
        fn admit_local(self, life: &mut Life<'_>, name: &str, key: &[u8]) {
            let peer = id(name);
            let directory = life.channel.authority_mut();
            if self == Self::NeverStores {
                directory
                    .admit(&peer, PeerRole::LocalUser, key, None, 1)
                    .unwrap();
            } else {
                let journal = life.journal.as_mut().unwrap();
                admit_durably(directory, journal, &peer, PeerRole::LocalUser, key, None, 1)
                    .unwrap();
            }
        }

        fn revoke(self, life: &mut Life<'_>, name: &str) {
            let peer = id(name);
            let directory = life.channel.authority_mut();
            if matches!(self, Self::NeverStores | Self::RevokesInMemoryOnly) {
                assert!(directory.revoke(&peer));
            } else {
                let journal = life.journal.as_mut().unwrap();
                assert_eq!(
                    revoke_durably(directory, journal, &peer),
                    Ok(Revoked::Durable)
                );
            }
        }

        fn rebind(self, life: &mut Life<'_>, name: &str, bound: Option<u64>) {
            let peer = id(name);
            let directory = life.channel.authority_mut();
            if matches!(self, Self::NeverStores | Self::RebindsInMemoryOnly) {
                assert_eq!(directory.rebind(&peer, bound), Some(2));
            } else {
                let journal = life.journal.as_mut().unwrap();
                assert_eq!(rebind_durably(directory, journal, &peer, bound), Ok(2));
            }
        }
    }

    /// The first process: three controllers admitted at version 1 bound to the epoch and a local user, one command
    /// from the first controller that commits, the second revoked, the third rebound to epoch 11 (version 2). Then
    /// it dies: only the durable bytes of its medium survive.
    fn first_life(medium: &mut MemStorage, owner: Owner) {
        let mut one = Life::boot(medium, true);
        for name in ["ctl-a", "ctl-b", "ctl-c"] {
            owner.admit(&mut one, name, &test_key(name), Some(EPOCH), 1);
        }
        owner.admit_local(&mut one, "panel", &test_key("panel"));
        let request = one.request("ctl-a", &test_key("ctl-a"), 1, EPOCH);
        assert!(matches!(
            one.commit(request, "ctl-a", 1),
            Ok(Outcome::Committed { .. })
        ));
        owner.revoke(&mut one, "ctl-b");
        owner.rebind(&mut one, "ctl-c", Some(11));
    }

    /// The second process opens what survived and restores (unless `restores` is false). Then, through the
    /// channel:
    ///
    /// * `ctl-a` must still be admitted with its key (`LOCKED-OUT`);
    /// * `ctl-b`'s genuine key must be refused **exactly** as `Revoked` (`RESURRECTED` if it was accepted,
    ///   `WRONG-REASON` for any other refusal);
    /// * `ctl-c` must be bound to epoch 11, so a request at epoch 10 is turned away at the door as
    ///   `EpochNotBound { bound: 11, request: 10 }` (`BINDING-LOST` if it was queued) and one at epoch 11 is queued
    ///   with the original key (`LOCKED-OUT`);
    /// * the roles came back: `panel`, the local user, may name no revision and is queued, and `ctl-a`, a controller,
    ///   is turned away for naming none (`ROLE-LOST`);
    /// * `ctl-b` re-admitted at its tombstone version is refused as `Resurrection` (`RESURRECTED`), and one version
    ///   up with a new key it works, while its old key is refused as `BadProof` (`OLD-KEY-LIVE`).
    ///
    /// Returns what the second process restored.
    fn judge_the_second_life(image: &[u8], restores: bool) -> Result<Option<Restored>, String> {
        let mut reborn = MemStorage::from_image(limits().segment_bytes, image);
        let mut two = Life::boot(&mut reborn, restores);
        let restored = two.restored;

        let request = two.request("ctl-a", &test_key("ctl-a"), 1, EPOCH);
        match two.commit(request, "ctl-a", 1)? {
            Outcome::Committed { .. } => {}
            other => return Err(format!("LOCKED-OUT: ctl-a's command gave {other:?}")),
        }

        let request = two.request("ctl-b", &test_key("ctl-b"), 1, EPOCH);
        match two.door(request) {
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::Revoked)) => {}
            SubmitResult::Queued { .. } => {
                return Err(
                    "RESURRECTED: ctl-b's revoked key was accepted after the restart".into(),
                );
            }
            other => return Err(format!("WRONG-REASON: ctl-b gave {other:?}, not Revoked")),
        }

        let request = two.request("ctl-c", &test_key("ctl-c"), 1, EPOCH);
        match two.door(request) {
            SubmitResult::Rejected(Rejection::EpochNotBound {
                bound: 11,
                request: EPOCH,
            }) => {}
            SubmitResult::Queued { .. } => {
                return Err(
                    "BINDING-LOST: ctl-c's key was accepted at the epoch it was rebound away from"
                        .into(),
                );
            }
            other => {
                return Err(format!(
                    "WRONG-REASON: ctl-c at the old epoch gave {other:?}"
                ));
            }
        }
        let request = two.request("ctl-c", &test_key("ctl-c"), 2, 11);
        if !matches!(two.door(request), SubmitResult::Queued { .. }) {
            return Err("LOCKED-OUT: ctl-c's key was not accepted at its bound epoch".into());
        }

        let request = two.request_without_revision("panel", &test_key("panel"), 1, EPOCH);
        if !matches!(two.door(request), SubmitResult::Queued { .. }) {
            return Err(
                "ROLE-LOST: the local user's command without a revision was not queued".into(),
            );
        }
        let request = two.request_without_revision("ctl-a", &test_key("ctl-a"), 9, EPOCH);
        if !matches!(
            two.door(request),
            SubmitResult::Rejected(Rejection::RevisionRequired { .. })
        ) {
            return Err(
                "ROLE-LOST: a controller's command without a revision was not refused for it"
                    .into(),
            );
        }

        let again = {
            let directory = two.channel.authority_mut();
            let journal = two.journal.as_mut().ok_or("setup: the journal is absent")?;
            admit_durably(
                directory,
                journal,
                &id("ctl-b"),
                PeerRole::Controller,
                &test_key("ctl-b"),
                Some(EPOCH),
                1,
            )
        };
        if again
            != Err(CustodyError::Admit(AdmitError::Resurrection {
                tombstone: 1,
                offered: 1,
            }))
        {
            return Err(format!(
                "RESURRECTED: re-admitting ctl-b at its tombstone version gave {again:?}"
            ));
        }
        let renewed = {
            let directory = two.channel.authority_mut();
            let journal = two.journal.as_mut().ok_or("setup: the journal is absent")?;
            admit_durably(
                directory,
                journal,
                &id("ctl-b"),
                PeerRole::Controller,
                &renewed_key("ctl-b"),
                Some(EPOCH),
                2,
            )
        };
        if renewed != Ok(()) {
            return Err(format!(
                "LOCKED-OUT: re-admitting ctl-b one version up gave {renewed:?}"
            ));
        }
        let request = two.request("ctl-b", &renewed_key("ctl-b"), 2, EPOCH);
        if !matches!(two.door(request), SubmitResult::Queued { .. }) {
            return Err("LOCKED-OUT: ctl-b's new key was not accepted".into());
        }
        let request = two.request("ctl-b", &test_key("ctl-b"), 3, EPOCH);
        match two.door(request) {
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::BadProof)) => {}
            SubmitResult::Queued { .. } => {
                return Err(
                    "OLD-KEY-LIVE: ctl-b's old key was accepted after its key was replaced".into(),
                );
            }
            other => {
                return Err(format!(
                    "WRONG-REASON: ctl-b's old key gave {other:?}, not BadProof"
                ));
            }
        }
        Ok(restored)
    }

    #[test]
    fn peers_admitted_revoked_and_rebound_through_custody_come_back_after_a_process_death() {
        let mut medium = blank_medium();
        first_life(&mut medium, Owner::Faithful);
        assert_eq!(
            judge_the_second_life(medium.durable(), true),
            Ok(Some(Restored::Peers {
                live: 3,
                revoked: 1,
                skipped: 0
            }))
        );
    }

    #[test]
    fn each_planted_custody_fault_fails_the_round_trip_judge_by_name() {
        // A judge that fails everything proves nothing, so the faithful round trip passes first.
        let mut medium = blank_medium();
        first_life(&mut medium, Owner::Faithful);
        assert!(judge_the_second_life(medium.durable(), true).is_ok());
        for (owner, restores, tag) in [
            // Nothing is stored, so nobody is admitted after the restart.
            (Owner::NeverStores, true, "LOCKED-OUT"),
            // The revocation never reaches the journal, so the key is live again.
            (Owner::RevokesInMemoryOnly, true, "RESURRECTED"),
            // The rebinding never reaches the journal, so the old binding is back.
            (Owner::RebindsInMemoryOnly, true, "BINDING-LOST"),
            // The second process never restores, so its directory is empty.
            (Owner::Faithful, false, "LOCKED-OUT"),
        ] {
            let mut medium = blank_medium();
            first_life(&mut medium, owner);
            let verdict = judge_the_second_life(medium.durable(), restores);
            assert!(
                verdict.as_ref().is_err_and(|e| e.starts_with(tag)),
                "{owner:?} (restores: {restores}) was not caught as {tag}: {verdict:?}"
            );
        }
    }

    /// The three stores a cut can interrupt.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Store {
        /// `ctl-d` admitted at version 1: old = unknown, new = live.
        Admit,
        /// `ctl-b` revoked: old = live, new = revoked.
        Revoke,
        /// `ctl-c` rebound to epoch 11: old = bound to 10, new = bound to 11.
        Rebind,
    }

    /// A fault in how a store is written, for the sweep to catch.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Flaw {
        Sound,
        /// A rebinding written as a revocation and then an admission one version higher: two transactions.
        RebindInTwoCommits,
    }

    /// What one run of the store left.
    struct StoreRun {
        /// Whether the call returned `Ok`.
        returned_ok: bool,
        /// The storage operations before and after the call.
        ops: (usize, usize),
        /// The bytes pending before each of those operations (an uncut run only).
        pending: Vec<usize>,
        durable: Vec<u8>,
    }

    fn rebind_in_two_commits<S: SecretStore, St: Storage>(
        directory: &mut PeerDirectory<S>,
        journal: &mut Journal<St>,
        peer: &PeerId,
        bound: Option<u64>,
    ) -> Result<u64, CustodyError> {
        let live = directory.version_of(peer).ok_or(CustodyError::NotLive)?;
        let key = test_key(peer.as_str());
        journal
            .revoke(&credential_id(peer))
            .map_err(CustodyError::Journal)?;
        journal
            .install(
                &credential_id(peer),
                live + 1,
                &encode_record(PeerRole::Controller, bound, &key),
            )
            .map_err(CustodyError::Journal)?;
        directory.rebind(peer, bound).ok_or(CustodyError::NotLive)
    }

    /// The first process admits `ctl-a`, `ctl-b` and `ctl-c` and then runs one store, cut at `cut` (operation, byte
    /// budget) if given, and dies.
    fn run_one_store(which: Store, cut: Option<(usize, usize)>, flaw: Flaw) -> StoreRun {
        let mut medium = blank_medium();
        let (returned_ok, ops, pending) = {
            let mut one = Life::boot(&mut medium, true);
            for name in ["ctl-a", "ctl-b", "ctl-c"] {
                Owner::Faithful.admit(&mut one, name, &test_key(name), Some(EPOCH), 1);
            }
            let before = one.ops_done();
            if let Some((n, k)) = cut {
                one.arm_cut(n, k);
            }
            let returned_ok = {
                let directory = one.channel.authority_mut();
                let journal = one.journal.as_mut().unwrap();
                match (which, flaw) {
                    (Store::Admit, _) => admit_durably(
                        directory,
                        journal,
                        &id("ctl-d"),
                        PeerRole::Controller,
                        &test_key("ctl-d"),
                        Some(EPOCH),
                        1,
                    )
                    .is_ok(),
                    (Store::Revoke, _) => revoke_durably(directory, journal, &id("ctl-b")).is_ok(),
                    (Store::Rebind, Flaw::Sound) => {
                        rebind_durably(directory, journal, &id("ctl-c"), Some(11)).is_ok()
                    }
                    (Store::Rebind, Flaw::RebindInTwoCommits) => {
                        rebind_in_two_commits(directory, journal, &id("ctl-c"), Some(11)).is_ok()
                    }
                }
            };
            let after = one.ops_done();
            let pending = if cut.is_none() {
                one.pending_before()[before..after].to_vec()
            } else {
                Vec::new()
            };
            (returned_ok, (before, after), pending)
        };
        StoreRun {
            returned_ok,
            ops,
            pending,
            durable: medium.durable().to_vec(),
        }
    }

    /// The second process after one cut: what the recovered medium holds for the identity the store concerned.
    /// `Ok(false)` is the old state, `Ok(true)` the new one, and anything else is `OLD-OR-NEW`. An earlier admission
    /// (`ctl-a`) must be untouched (`LOST-OTHER`).
    fn recovered(which: Store, durable: &[u8]) -> Result<bool, String> {
        let mut reborn = MemStorage::from_image(limits().segment_bytes, durable);
        let mut two = Life::boot(&mut reborn, true);
        let request = two.request("ctl-a", &test_key("ctl-a"), 1, EPOCH);
        if !matches!(two.door(request), SubmitResult::Queued { .. }) {
            return Err("LOST-OTHER: a cut of one store damaged an earlier admission".into());
        }
        match which {
            Store::Admit => {
                let request = two.request("ctl-d", &test_key("ctl-d"), 1, EPOCH);
                match two.door(request) {
                    SubmitResult::Queued { .. } => Ok(true),
                    SubmitResult::Rejected(Rejection::Unauthenticated(
                        AuthFailure::UnknownPeer,
                    )) => Ok(false),
                    other => Err(format!(
                        "OLD-OR-NEW: ctl-d gave {other:?}, neither unknown (old) nor admitted (new)"
                    )),
                }
            }
            Store::Revoke => {
                let request = two.request("ctl-b", &test_key("ctl-b"), 1, EPOCH);
                match two.door(request) {
                    SubmitResult::Queued { .. } => Ok(false),
                    SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::Revoked)) => {
                        Ok(true)
                    }
                    other => Err(format!(
                        "OLD-OR-NEW: ctl-b gave {other:?}, neither live (old) nor revoked (new)"
                    )),
                }
            }
            Store::Rebind => {
                let at_old = two.request("ctl-c", &test_key("ctl-c"), 1, EPOCH);
                let at_new = two.request("ctl-c", &test_key("ctl-c"), 2, 11);
                let (old_door, new_door) = (two.door(at_old), two.door(at_new));
                match (&old_door, &new_door) {
                    (
                        SubmitResult::Queued { .. },
                        SubmitResult::Rejected(Rejection::EpochNotBound {
                            bound: 10,
                            request: 11,
                        }),
                    ) => Ok(false),
                    (
                        SubmitResult::Rejected(Rejection::EpochNotBound {
                            bound: 11,
                            request: EPOCH,
                        }),
                        SubmitResult::Queued { .. },
                    ) => Ok(true),
                    _ => Err(format!(
                        "OLD-OR-NEW: ctl-c gave {old_door:?} at epoch {EPOCH} and {new_door:?} at epoch 11, neither the old binding nor the new one"
                    )),
                }
            }
        }
    }

    /// Cut the power at every storage operation and every byte budget of one store, and judge each recovery.
    /// A call that returned `Ok` must have left the new state (`LOST-ACKNOWLEDGED`). Returns how many cuts left
    /// the old state and how many the new one.
    fn judge_every_cut_of(which: Store, flaw: Flaw) -> Result<(usize, usize), String> {
        let uncut = run_one_store(which, None, flaw);
        let (before, after) = uncut.ops;
        if after <= before || uncut.pending.len() != after - before {
            return Err(format!(
                "setup: the store ran operations {before}..{after}, with {} pending counts",
                uncut.pending.len()
            ));
        }
        let mut cuts = vec![None];
        for (index, budget) in uncut.pending.iter().enumerate() {
            for k in 0..=*budget {
                cuts.push(Some((before + index, k)));
            }
        }
        let (mut old, mut new) = (0, 0);
        for cut in cuts {
            let run = run_one_store(which, cut, flaw);
            let is_new =
                recovered(which, &run.durable).map_err(|e| format!("{e} (cut {cut:?})"))?;
            if run.returned_ok && !is_new {
                return Err(format!(
                    "LOST-ACKNOWLEDGED: the call returned Ok and the recovered state is the old one (cut {cut:?})"
                ));
            }
            if is_new {
                new += 1;
            } else {
                old += 1;
            }
        }
        Ok((old, new))
    }

    #[test]
    fn every_cut_of_an_admission_store_leaves_the_peer_unknown_or_admitted() {
        let (old, new) = judge_every_cut_of(Store::Admit, Flaw::Sound).unwrap();
        // The sweep is not vacuous: some cuts leave the old state and some the new one.
        assert!(old > 0, "no cut left the old state");
        assert!(new > 0, "no cut left the new state");
        assert_eq!((old, new), PREDICTED_ADMIT);
    }

    #[test]
    fn every_cut_of_a_revocation_store_leaves_the_peer_live_or_revoked_and_never_unknown() {
        let (old, new) = judge_every_cut_of(Store::Revoke, Flaw::Sound).unwrap();
        assert!(old > 0, "no cut left the old state");
        assert!(new > 0, "no cut left the new state");
        assert_eq!((old, new), PREDICTED_REVOKE);
    }

    #[test]
    fn every_cut_of_a_rebind_store_leaves_the_old_binding_or_the_new_one() {
        let (old, new) = judge_every_cut_of(Store::Rebind, Flaw::Sound).unwrap();
        assert!(old > 0, "no cut left the old state");
        assert!(new > 0, "no cut left the new state");
        assert_eq!((old, new), PREDICTED_REBIND);
    }

    #[test]
    fn a_rebind_written_as_two_commits_is_caught_by_the_cut_sweep() {
        // The faithful rebinding passes the whole sweep first.
        assert!(judge_every_cut_of(Store::Rebind, Flaw::Sound).is_ok());
        let verdict = judge_every_cut_of(Store::Rebind, Flaw::RebindInTwoCommits);
        assert!(
            verdict.as_ref().is_err_and(|e| e.starts_with("OLD-OR-NEW")),
            "a rebinding in two commits was not caught as OLD-OR-NEW: {verdict:?}"
        );
    }

    /// The store of an admission is cut at its first operation. The call must fail with the journal's storage
    /// fault and `ctl-a` must stay unknown (`LIVE-BUT-UNSTORED` if the directory trusts it). With `memory_first`
    /// the owner admits in the directory before it stores.
    fn judge_a_failed_admission(memory_first: bool) -> Result<(), String> {
        let mut medium = blank_medium();
        let mut one = Life::boot(&mut medium, true);
        let next = one.ops_done();
        one.arm_cut(next, 0);
        let peer = id("ctl-a");
        let key = test_key("ctl-a");
        let result = {
            let directory = one.channel.authority_mut();
            let journal = one.journal.as_mut().unwrap();
            if memory_first {
                directory
                    .admit(&peer, PeerRole::Controller, &key, Some(EPOCH), 1)
                    .map_err(CustodyError::Admit)
                    .and_then(|()| {
                        journal
                            .install(
                                &credential_id(&peer),
                                1,
                                &encode_record(PeerRole::Controller, Some(EPOCH), &key),
                            )
                            .map(|_| ())
                            .map_err(CustodyError::Journal)
                    })
            } else {
                admit_durably(
                    directory,
                    journal,
                    &peer,
                    PeerRole::Controller,
                    &key,
                    Some(EPOCH),
                    1,
                )
            }
        };
        if !matches!(result, Err(CustodyError::Journal(JournalError::Storage(_)))) {
            return Err(format!("setup: the cut store gave {result:?}"));
        }
        if one
            .journal
            .as_ref()
            .is_some_and(|j| j.credential(&credential_id(&peer)).is_some())
        {
            return Err("setup: the journal holds the credential of a store that failed".into());
        }
        let request = one.request("ctl-a", &key, 1, EPOCH);
        match one.door(request) {
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::UnknownPeer)) => Ok(()),
            SubmitResult::Queued { .. } => Err(
                "LIVE-BUT-UNSTORED: the directory trusts a peer whose admission was never stored"
                    .into(),
            ),
            other => Err(format!(
                "WRONG-REASON: ctl-a gave {other:?}, not UnknownPeer"
            )),
        }
    }

    #[test]
    fn a_failed_admission_store_leaves_the_directory_unchanged_and_an_owner_that_admits_first_is_caught()
     {
        assert_eq!(judge_a_failed_admission(false), Ok(()));
        let verdict = judge_a_failed_admission(true);
        assert!(
            verdict
                .as_ref()
                .is_err_and(|e| e.starts_with("LIVE-BUT-UNSTORED")),
            "admitting before storing was not caught as LIVE-BUT-UNSTORED: {verdict:?}"
        );
    }

    /// An owner that stores a revocation before it revokes in the directory: if the store fails, the key stays live.
    fn plant_revoke_store_first<S: SecretStore, St: Storage>(
        directory: &mut PeerDirectory<S>,
        journal: &mut Journal<St>,
        peer: &PeerId,
    ) -> Result<Revoked, CustodyError> {
        journal
            .revoke(&credential_id(peer))
            .map_err(CustodyError::NotDurable)?;
        directory.revoke(peer);
        Ok(Revoked::Durable)
    }

    /// `ctl-b` is admitted durably and then its revocation's store fails. The call must report
    /// [`CustodyError::NotDurable`] and the key must be dead now (`STILL-LIVE` if not). After a restart the key is
    /// back, as the error said it might be, and a second call finishes the revocation, which then survives a
    /// third boot (`RETRY-FAILED`, `NOT-DURABLE`).
    fn judge_a_failed_revocation(store_first: bool) -> Result<(), String> {
        let mut medium = blank_medium();
        {
            let mut one = Life::boot(&mut medium, true);
            Owner::Faithful.admit(&mut one, "ctl-b", &test_key("ctl-b"), Some(EPOCH), 1);
            let next = one.ops_done();
            one.arm_cut(next, 0);
            let result = {
                let directory = one.channel.authority_mut();
                let journal = one.journal.as_mut().unwrap();
                if store_first {
                    plant_revoke_store_first(directory, journal, &id("ctl-b"))
                } else {
                    revoke_durably(directory, journal, &id("ctl-b"))
                }
            };
            if !matches!(
                result,
                Err(CustodyError::NotDurable(JournalError::Storage(_)))
            ) {
                return Err(format!("setup: the cut store gave {result:?}"));
            }
            let request = one.request("ctl-b", &test_key("ctl-b"), 1, EPOCH);
            match one.door(request) {
                SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::Revoked)) => {}
                SubmitResult::Queued { .. } => {
                    return Err(
                        "STILL-LIVE: the key was accepted after a revocation whose store failed"
                            .into(),
                    );
                }
                other => return Err(format!("WRONG-REASON: ctl-b gave {other:?}, not Revoked")),
            }
        }
        let mut reborn = MemStorage::from_image(limits().segment_bytes, medium.durable());
        {
            let mut two = Life::boot(&mut reborn, true);
            let request = two.request("ctl-b", &test_key("ctl-b"), 1, EPOCH);
            if !matches!(two.door(request), SubmitResult::Queued { .. }) {
                return Err(
                    "setup: the revocation that never reached the journal should leave the key live after a restart".into(),
                );
            }
            let retried = revoke_durably(
                two.channel.authority_mut(),
                two.journal.as_mut().unwrap(),
                &id("ctl-b"),
            );
            if retried != Ok(Revoked::Durable) {
                return Err(format!("RETRY-FAILED: the second call gave {retried:?}"));
            }
        }
        let image = reborn.durable().to_vec();
        let mut third = MemStorage::from_image(limits().segment_bytes, &image);
        let mut three = Life::boot(&mut third, true);
        let request = three.request("ctl-b", &test_key("ctl-b"), 1, EPOCH);
        match three.door(request) {
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::Revoked)) => Ok(()),
            other => Err(format!(
                "NOT-DURABLE: after the retry and a restart ctl-b gave {other:?}, not Revoked"
            )),
        }
    }

    #[test]
    fn a_revocation_whose_store_failed_is_dead_now_returns_after_a_restart_and_the_retry_completes_it()
     {
        assert_eq!(judge_a_failed_revocation(false), Ok(()));
        let verdict = judge_a_failed_revocation(true);
        assert!(
            verdict.as_ref().is_err_and(|e| e.starts_with("STILL-LIVE")),
            "storing a revocation before taking it was not caught as STILL-LIVE: {verdict:?}"
        );
    }

    #[test]
    fn an_unreadable_journal_restores_an_empty_directory_and_says_so() {
        let seg = limits().segment_bytes;
        let mut medium = blank_medium();
        first_life(&mut medium, Owner::Faithful);
        let healthy = medium.durable().to_vec();

        // Neither segment holds a valid state, though the medium is not blank.
        let mut image = healthy.clone();
        for base in [0, seg] {
            image[base..base + SEG_HEADER].fill(0);
        }
        let mut damaged = MemStorage::from_image(seg, &image);
        {
            let mut two = Life::boot(&mut damaged, true);
            assert_eq!(
                two.restored,
                Some(Restored::Unreadable(Cause::Unrecoverable))
            );
            for (name, seq, epoch) in [("ctl-a", 1, EPOCH), ("ctl-b", 1, EPOCH), ("ctl-c", 1, 11)] {
                let request = two.request(name, &test_key(name), seq, epoch);
                assert_eq!(
                    two.door(request),
                    SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::UnknownPeer)),
                    "{name} was admitted from a journal that could not be read"
                );
            }
            // The journal was formatted empty and takes a new pairing.
            let directory = two.channel.authority_mut();
            let journal = two.journal.as_mut().unwrap();
            assert_eq!(
                admit_durably(
                    directory,
                    journal,
                    &id("ctl-a"),
                    PeerRole::Controller,
                    &test_key("ctl-a"),
                    Some(EPOCH),
                    1
                ),
                Ok(())
            );
        }
        let image_after = damaged.durable().to_vec();
        let mut again = MemStorage::from_image(seg, &image_after);
        let mut three = Life::boot(&mut again, true);
        assert_eq!(
            three.restored,
            Some(Restored::Peers {
                live: 1,
                revoked: 0,
                skipped: 0
            })
        );
        let request = three.request("ctl-a", &test_key("ctl-a"), 1, EPOCH);
        assert!(matches!(
            three.commit(request, "ctl-a", 1),
            Ok(Outcome::Committed { .. })
        ));

        // The medium does not answer: the journal cannot be opened at all.
        let mut dead = MemStorage::from_image(seg, &healthy);
        dead.power_cut(0, false);
        let mut four = Life::boot(&mut dead, true);
        assert_eq!(
            four.restored,
            Some(Restored::Unreadable(Cause::OpenFailed("storage")))
        );
        assert!(four.journal.is_none());
        let request = four.request("ctl-a", &test_key("ctl-a"), 1, EPOCH);
        assert_eq!(
            four.door(request),
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::UnknownPeer))
        );
    }

    #[test]
    fn records_of_another_kind_and_records_that_cannot_be_read_are_skipped_and_counted() {
        let mut medium = blank_medium();
        {
            let mut one = Life::boot(&mut medium, true);
            Owner::Faithful.admit(&mut one, "ctl-a", &test_key("ctl-a"), Some(EPOCH), 1);
            Owner::Faithful.admit(&mut one, "ctl-b", &test_key("ctl-b"), Some(EPOCH), 1);
            Owner::Faithful.revoke(&mut one, "ctl-b");
            let journal = one.journal.as_mut().unwrap();
            // Another kind of credential: not ours, not counted, never admitted.
            journal.install(b"spotify-token", 1, b"not a peer").unwrap();
            // A control peer record in a format this code does not know.
            let mut unknown_format = encode_record(PeerRole::Controller, None, &test_key("ctl-x"));
            unknown_format[0] = 9;
            journal.install(b"cp:ctl-x", 1, &unknown_format).unwrap();
            // A label that is not a peer id (an upper-case letter).
            let record = encode_record(PeerRole::Controller, None, &test_key("ctl-y"));
            journal.install(b"cp:BAD", 1, &record).unwrap();
            // A key shorter than a key may be.
            let short = encode_record(PeerRole::Controller, None, b"too-short");
            journal.install(b"cp:ctl-z", 1, &short).unwrap();
        }
        let mut reborn = MemStorage::from_image(limits().segment_bytes, medium.durable());
        let mut two = Life::boot(&mut reborn, true);
        assert_eq!(
            two.restored,
            Some(Restored::Peers {
                live: 1,
                revoked: 1,
                skipped: 3
            })
        );
        let request = two.request("ctl-a", &test_key("ctl-a"), 1, EPOCH);
        assert!(matches!(two.door(request), SubmitResult::Queued { .. }));
        for (name, key) in [
            ("ctl-x", test_key("ctl-x")),
            ("ctl-z", b"too-short".to_vec()),
            ("spotify-token", b"not a peer".to_vec()),
        ] {
            let body = RequestBody::new(id(name), 1, EPOCH, Some(2), set_group(70)).unwrap();
            let request =
                ControlRequest::new(body.clone(), compute_proof(&key, &body.signing_bytes()));
            assert_eq!(
                two.door(request),
                SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::UnknownPeer)),
                "{name} was admitted from a record that is not a readable control peer"
            );
        }
    }

    #[test]
    fn the_record_bytes_are_the_ones_a_person_wrote_and_the_decoder_is_strict() {
        let key = b"0123456789abcdef";
        // Format 1, controller, bound to epoch 10 (eight bytes, big-endian), then the key.
        let mut bound = vec![1u8, 1, 1, 0, 0, 0, 0, 0, 0, 0, 10];
        bound.extend_from_slice(key);
        assert_eq!(encode_record(PeerRole::Controller, Some(10), key), bound);
        // Format 1, local user, not bound (the epoch bytes are zero), then the key.
        let mut free = vec![1u8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        free.extend_from_slice(key);
        assert_eq!(encode_record(PeerRole::LocalUser, None, key), free);
        // The largest epoch survives.
        let mut top = vec![1u8, 1, 1, 255, 255, 255, 255, 255, 255, 255, 255];
        top.extend_from_slice(key);
        assert_eq!(
            encode_record(PeerRole::Controller, Some(u64::MAX), key),
            top
        );
        assert_eq!(
            decode_record(&bound),
            Some((PeerRole::Controller, Some(10), key.as_slice()))
        );
        assert_eq!(
            decode_record(&free),
            Some((PeerRole::LocalUser, None, key.as_slice()))
        );
        assert_eq!(
            decode_record(&top),
            Some((PeerRole::Controller, Some(u64::MAX), key.as_slice()))
        );
        // Everything else is refused.
        let mutate = |at: usize, value: u8| {
            let mut raw = bound.clone();
            raw[at] = value;
            raw
        };
        assert_eq!(decode_record(&mutate(0, 0)), None, "format 0");
        assert_eq!(decode_record(&mutate(0, 2)), None, "format 2");
        assert_eq!(decode_record(&mutate(1, 0)), None, "role 0");
        assert_eq!(decode_record(&mutate(1, 3)), None, "role 3");
        assert_eq!(decode_record(&mutate(2, 2)), None, "bound flag 2");
        let mut unbound_with_epoch = free.clone();
        unbound_with_epoch[10] = 1;
        assert_eq!(
            decode_record(&unbound_with_epoch),
            None,
            "an epoch where none is bound"
        );
        assert_eq!(decode_record(&[]), None, "empty");
        assert_eq!(decode_record(&bound[..HEADER_LEN]), None, "no key");
        assert_eq!(
            decode_record(&bound[..HEADER_LEN + MIN_KEY_LEN - 1]),
            None,
            "a key one byte short"
        );
        assert!(decode_record(&bound[..HEADER_LEN + MIN_KEY_LEN]).is_some());
        // The credential id.
        assert_eq!(credential_id(&id("ctl-a")), b"cp:ctl-a".to_vec());
        assert_eq!(peer_of(b"cp:ctl-a"), Some(id("ctl-a")));
        assert_eq!(peer_of(b"ctl-a"), None, "no prefix");
        assert_eq!(peer_of(b"cp:"), None, "no label");
        assert_eq!(peer_of(b"cp:CTL"), None, "not a peer label");
        assert_eq!(peer_of(&[b'c', b'p', b':', 0xff]), None, "not text");
        // A rebinding changes the binding and nothing else: the role and the key stay.
        let mut controller_unbound = vec![1u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        controller_unbound.extend_from_slice(key);
        assert_eq!(rebound_record(&bound, None), Some(controller_unbound));
        let mut local_bound = vec![1u8, 2, 1, 0, 0, 0, 0, 0, 0, 0, 10];
        local_bound.extend_from_slice(key);
        assert_eq!(rebound_record(&free, Some(10)), Some(local_bound));
        assert_eq!(rebound_record(&bound[..HEADER_LEN], Some(1)), None);
    }

    #[test]
    fn the_smallest_journal_refuses_every_admission_and_a_label_that_does_not_fit_is_refused_and_nothing_changes()
     {
        // The smallest configuration holds 16 bytes per secret: the header alone leaves no room for a key.
        let tiny = Limits::tiny();
        let mut small = MemStorage::new(tiny.segment_bytes);
        let (mut journal, _) = Journal::open(&mut small, tiny).unwrap();
        let mut directory = EphemeralPeers::new();
        assert_eq!(
            admit_durably(
                &mut directory,
                &mut journal,
                &id("ctl-a"),
                PeerRole::Controller,
                &test_key("ctl-a"),
                Some(EPOCH),
                1
            ),
            Err(CustodyError::Journal(JournalError::ValueTooLong))
        );
        assert_eq!(directory.version_of(&id("ctl-a")), None);
        assert!(journal.credential(&credential_id(&id("ctl-a"))).is_none());

        // The device configuration: a label of 29 bytes fits with its prefix and 30 does not.
        let mut medium = blank_medium();
        let (mut journal, _) = Journal::open(&mut medium, limits()).unwrap();
        let mut directory = EphemeralPeers::new();
        let fits = "a".repeat(29);
        let too_long = "a".repeat(30);
        assert_eq!(
            admit_durably(
                &mut directory,
                &mut journal,
                &id(&too_long),
                PeerRole::Controller,
                &test_key("ctl-a"),
                None,
                1
            ),
            Err(CustodyError::Journal(JournalError::InvalidKey))
        );
        assert_eq!(directory.version_of(&id(&too_long)), None);
        assert_eq!(
            admit_durably(
                &mut directory,
                &mut journal,
                &id(&fits),
                PeerRole::Controller,
                &test_key("ctl-a"),
                None,
                1
            ),
            Ok(())
        );
        // A key of 117 bytes fits beside the header and one of 118 does not.
        assert_eq!(
            admit_durably(
                &mut directory,
                &mut journal,
                &id("ctl-b"),
                PeerRole::Controller,
                &[7u8; 118],
                None,
                1
            ),
            Err(CustodyError::Journal(JournalError::ValueTooLong))
        );
        assert_eq!(directory.version_of(&id("ctl-b")), None);
        assert_eq!(
            admit_durably(
                &mut directory,
                &mut journal,
                &id("ctl-b"),
                PeerRole::Controller,
                &[7u8; 117],
                None,
                1
            ),
            Ok(())
        );
        // The directory's own refusals come first and write nothing.
        let frames = journal.frames_written();
        assert_eq!(
            admit_durably(
                &mut directory,
                &mut journal,
                &id("ctl-b"),
                PeerRole::Controller,
                &[7u8; 117],
                None,
                1
            ),
            Err(CustodyError::Admit(AdmitError::AlreadyAdmitted))
        );
        assert_eq!(
            admit_durably(
                &mut directory,
                &mut journal,
                &id("ctl-c"),
                PeerRole::Controller,
                b"short",
                None,
                1
            ),
            Err(CustodyError::Admit(AdmitError::KeyTooShort {
                len: 5,
                min: MIN_KEY_LEN
            }))
        );
        assert_eq!(journal.frames_written(), frames);
        // Version 0 is refused by the journal and changes nothing.
        assert_eq!(
            admit_durably(
                &mut directory,
                &mut journal,
                &id("ctl-c"),
                PeerRole::Controller,
                &test_key("ctl-c"),
                None,
                0
            ),
            Err(CustodyError::Journal(JournalError::BadVersion))
        );
        assert_eq!(directory.version_of(&id("ctl-c")), None);
    }

    #[test]
    fn a_rebind_or_a_revocation_the_journal_has_not_seen_is_refused_or_reported_and_changes_nothing()
     {
        let mut medium = blank_medium();
        let (mut journal, _) = Journal::open(&mut medium, limits()).unwrap();
        let mut directory = EphemeralPeers::new();

        // An identity that is not live cannot be rebound; nothing is revoked that was never live.
        assert_eq!(
            rebind_durably(&mut directory, &mut journal, &id("ctl-a"), Some(11)),
            Err(CustodyError::NotLive)
        );
        assert_eq!(
            revoke_durably(&mut directory, &mut journal, &id("ctl-a")),
            Ok(Revoked::NothingLive)
        );

        // Live in the directory only (admitted without custody): a rebinding is refused, and a revocation
        // takes effect for this run only.
        directory
            .admit(
                &id("ctl-a"),
                PeerRole::Controller,
                &test_key("ctl-a"),
                Some(EPOCH),
                1,
            )
            .unwrap();
        let frames = journal.frames_written();
        assert_eq!(
            rebind_durably(&mut directory, &mut journal, &id("ctl-a"), Some(11)),
            Err(CustodyError::OutOfStep {
                directory: 1,
                stored: None
            })
        );
        assert_eq!(directory.version_of(&id("ctl-a")), Some(1));
        assert_eq!(journal.frames_written(), frames);
        assert_eq!(
            revoke_durably(&mut directory, &mut journal, &id("ctl-a")),
            Ok(Revoked::MemoryOnly)
        );
        assert_eq!(directory.version_of(&id("ctl-a")), None);

        // The journal holds the identity at another version than the directory: refused, nothing changed.
        admit_durably(
            &mut directory,
            &mut journal,
            &id("ctl-b"),
            PeerRole::Controller,
            &test_key("ctl-b"),
            Some(EPOCH),
            1,
        )
        .unwrap();
        journal
            .install(
                &credential_id(&id("ctl-b")),
                2,
                &encode_record(PeerRole::Controller, Some(EPOCH), &test_key("ctl-b")),
            )
            .unwrap();
        assert_eq!(
            rebind_durably(&mut directory, &mut journal, &id("ctl-b"), Some(11)),
            Err(CustodyError::OutOfStep {
                directory: 1,
                stored: Some(2)
            })
        );
        assert_eq!(directory.version_of(&id("ctl-b")), Some(1));

        // A revocation is safe to repeat.
        assert_eq!(
            revoke_durably(&mut directory, &mut journal, &id("ctl-b")),
            Ok(Revoked::Durable)
        );
        assert_eq!(
            revoke_durably(&mut directory, &mut journal, &id("ctl-b")),
            Ok(Revoked::Durable)
        );
        assert_eq!(
            rebind_durably(&mut directory, &mut journal, &id("ctl-b"), None),
            Err(CustodyError::NotLive)
        );
    }

    #[test]
    fn the_credentials_and_the_revision_mark_share_one_journal_and_both_come_back() {
        let mut medium = blank_medium();
        {
            let mut one = Life::boot(&mut medium, true);
            Owner::Faithful.admit(&mut one, "ctl-a", &test_key("ctl-a"), Some(EPOCH), 1);
            Owner::Faithful.admit(&mut one, "ctl-b", &test_key("ctl-b"), Some(EPOCH), 1);
            let request = one.request("ctl-a", &test_key("ctl-a"), 1, EPOCH);
            assert!(matches!(one.door(request), SubmitResult::Queued { .. }));
            let journal = one.journal.as_mut().unwrap();
            let settled = step_then_store(&mut one.channel, 0, &mut one.session, journal).unwrap();
            assert!(matches!(settled[0].outcome, Outcome::Committed { .. }));
            Owner::Faithful.revoke(&mut one, "ctl-b");
            let state = one.journal.as_ref().unwrap().state();
            assert_eq!(state.marks.get(HIGH_WATER_KEY), Some(&3));
            assert_eq!(state.credentials.len(), 2);
        }
        let mut reborn = MemStorage::from_image(limits().segment_bytes, medium.durable());
        let opened = Journal::open(&mut reborn, limits());
        let mut directory = EphemeralPeers::new();
        assert_eq!(
            restore_peers(&mut directory, &opened),
            Ok(Restored::Peers {
                live: 1,
                revoked: 1,
                skipped: 0
            })
        );
        let mut channel = ControlChannel::new(directory, config()).unwrap();
        assert_eq!(
            restore_from_open(&mut channel, &opened),
            Ok(MarkRestored::Mark(3))
        );
        let session = fixture_session(EPOCH);
        assert_eq!(channel.high_water(&session), 3);
        for (name, want) in [("ctl-a", true), ("ctl-b", false)] {
            let body = RequestBody::new(id(name), 1, EPOCH, Some(3), set_group(70)).unwrap();
            let request = ControlRequest::new(
                body.clone(),
                compute_proof(&test_key(name), &body.signing_bytes()),
            );
            let queued = matches!(channel.submit(0, request), SubmitResult::Queued { .. });
            assert_eq!(queued, want, "{name}");
        }
    }

    // ------------------------------------------------------------------------------ the identity cap, on both sides
    //
    // `MAX_PEERS` (the directory) and the journal's credential entries (`Limits::standard`) both count distinct identities,
    // live and revoked together, and both are sixteen. The expectations for the journal's half were worked out before the
    // Rust ran, with U01's independent Python journal (`tests/u01/reference.py`, the device limits, these record bytes):
    // sixteen identities and the revision mark fit; the seventeenth is `namespace_full`; a revocation keeps its slot; a
    // version at or below the tombstone is `revoked`; one version up re-admits in place; `reset_pairing` revokes all and
    // keeps every slot; another kind of credential holds a slot like a peer does.

    /// The `i`-th identity of the maximum profile: the local user first, then controllers.
    fn profile_name(i: usize) -> String {
        if i == 0 {
            "local".to_string()
        } else {
            format!("ctl-{i:02}")
        }
    }

    fn profile_role(i: usize) -> PeerRole {
        if i == 0 {
            PeerRole::LocalUser
        } else {
            PeerRole::Controller
        }
    }

    /// Admit the `i`-th identity of the maximum profile at `version`, stored before it is live.
    fn admit_at<St: Storage>(
        directory: &mut EphemeralPeers,
        journal: &mut Journal<St>,
        i: usize,
        version: u64,
    ) -> Result<(), CustodyError> {
        let name = profile_name(i);
        admit_durably(
            directory,
            journal,
            &id(&name),
            profile_role(i),
            &test_key(&name),
            Some(EPOCH),
            version,
        )
    }

    /// Admit identities `0..count` of the maximum profile at version 1. Each must be within the cap.
    fn admit_profile<St: Storage>(
        directory: &mut EphemeralPeers,
        journal: &mut Journal<St>,
        count: usize,
    ) {
        for i in 0..count {
            assert_eq!(
                admit_at(directory, journal, i, 1),
                Ok(()),
                "identity {i} ({}) is within the cap",
                profile_name(i)
            );
        }
    }

    /// The process comes back: what survived on `medium` is the whole new medium.
    fn reopened(medium: &MemStorage) -> MemStorage {
        MemStorage::from_image(limits().segment_bytes, medium.durable())
    }

    #[test]
    fn sixteen_identities_are_stored_and_restored_together_and_the_seventeenth_is_refused_before_any_write()
     {
        let mut medium = blank_medium();
        {
            let (mut journal, _) = Journal::open(&mut medium, limits()).unwrap();
            let mut directory = EphemeralPeers::new();
            admit_profile(&mut directory, &mut journal, MAX_PEERS);
            // The revision mark lives in the same journal, beside the sixteen credentials.
            journal.raise_mark(HIGH_WATER_KEY, 7).unwrap();
            assert_eq!(journal.state().credentials.len(), MAX_PEERS);
            // The seventeenth is refused by the directory, first, and the journal is not touched.
            let frames = journal.frames_written();
            assert_eq!(
                admit_at(&mut directory, &mut journal, MAX_PEERS, 1),
                Err(CustodyError::Admit(AdmitError::Full))
            );
            assert_eq!(journal.frames_written(), frames);
            assert_eq!(directory.version_of(&id(&profile_name(MAX_PEERS))), None);
            assert!(
                journal
                    .credential(&credential_id(&id(&profile_name(MAX_PEERS))))
                    .is_none()
            );
        }
        // After a restart all sixteen are back with their stored version, and so is the mark.
        let mut reborn = reopened(&medium);
        let opened = Journal::open(&mut reborn, limits());
        let mut directory = EphemeralPeers::new();
        assert_eq!(
            restore_peers(&mut directory, &opened),
            Ok(Restored::Peers {
                live: MAX_PEERS,
                revoked: 0,
                skipped: 0
            })
        );
        for i in 0..MAX_PEERS {
            assert_eq!(
                directory.version_of(&id(&profile_name(i))),
                Some(1),
                "{}",
                profile_name(i)
            );
        }
        let (mut journal, _) = opened.unwrap();
        assert_eq!(journal.state().marks.get(HIGH_WATER_KEY), Some(&7));
        // The cap is still the cap: the seventeenth is refused again, and nothing is written for it.
        let frames = journal.frames_written();
        assert_eq!(
            admit_at(&mut directory, &mut journal, MAX_PEERS, 1),
            Err(CustodyError::Admit(AdmitError::Full))
        );
        assert_eq!(journal.frames_written(), frames);
    }

    #[test]
    fn a_revoked_identity_keeps_its_slot_on_both_sides_and_comes_back_only_one_version_up() {
        let (revoked, extra) = (3, MAX_PEERS);
        let mut medium = blank_medium();
        {
            let (mut journal, _) = Journal::open(&mut medium, limits()).unwrap();
            let mut directory = EphemeralPeers::new();
            admit_profile(&mut directory, &mut journal, MAX_PEERS);
            assert_eq!(
                revoke_durably(&mut directory, &mut journal, &id(&profile_name(revoked))),
                Ok(Revoked::Durable)
            );
            // The slot is kept: a new identity is still refused, and nothing is written for it.
            let frames = journal.frames_written();
            assert_eq!(
                admit_at(&mut directory, &mut journal, extra, 1),
                Err(CustodyError::Admit(AdmitError::Full))
            );
            assert_eq!(journal.frames_written(), frames);
        }
        let mut reborn = reopened(&medium);
        {
            let opened = Journal::open(&mut reborn, limits());
            let mut directory = EphemeralPeers::new();
            assert_eq!(
                restore_peers(&mut directory, &opened),
                Ok(Restored::Peers {
                    live: MAX_PEERS - 1,
                    revoked: 1,
                    skipped: 0
                })
            );
            let (mut journal, _) = opened.unwrap();
            // Nonresurrection: the admission it had before is refused, at the same version, after the restart.
            let frames = journal.frames_written();
            assert_eq!(
                admit_at(&mut directory, &mut journal, revoked, 1),
                Err(CustodyError::Admit(AdmitError::Resurrection {
                    tombstone: 1,
                    offered: 1
                }))
            );
            assert_eq!(
                admit_at(&mut directory, &mut journal, extra, 1),
                Err(CustodyError::Admit(AdmitError::Full))
            );
            assert_eq!(journal.frames_written(), frames);
            // One version up it is admitted again, in the slot it kept, so it fits at the cap on both sides.
            assert_eq!(admit_at(&mut directory, &mut journal, revoked, 2), Ok(()));
            assert_eq!(directory.version_of(&id(&profile_name(revoked))), Some(2));
            assert_eq!(journal.state().credentials.len(), MAX_PEERS);
        }
        let mut third = reopened(&reborn);
        let opened = Journal::open(&mut third, limits());
        let mut directory = EphemeralPeers::new();
        assert_eq!(
            restore_peers(&mut directory, &opened),
            Ok(Restored::Peers {
                live: MAX_PEERS,
                revoked: 0,
                skipped: 0
            })
        );
        assert_eq!(directory.version_of(&id(&profile_name(revoked))), Some(2));
    }

    #[test]
    fn a_pairing_reset_at_the_cap_keeps_every_slot_so_only_known_identities_return_one_version_up()
    {
        let (known, never_seen) = (5, MAX_PEERS);
        let mut medium = blank_medium();
        {
            let (mut journal, _) = Journal::open(&mut medium, limits()).unwrap();
            let mut directory = EphemeralPeers::new();
            admit_profile(&mut directory, &mut journal, MAX_PEERS);
            journal.reset_pairing().unwrap();
            assert_eq!(journal.state().credentials.len(), MAX_PEERS);
        }
        let mut reborn = reopened(&medium);
        let opened = Journal::open(&mut reborn, limits());
        let mut directory = EphemeralPeers::new();
        assert_eq!(
            restore_peers(&mut directory, &opened),
            Ok(Restored::Peers {
                live: 0,
                revoked: MAX_PEERS,
                skipped: 0
            })
        );
        for i in 0..MAX_PEERS {
            assert_eq!(
                directory.version_of(&id(&profile_name(i))),
                None,
                "{}",
                profile_name(i)
            );
        }
        let (mut journal, _) = opened.unwrap();
        // A label that was never seen has no slot to come back to, and nothing is written for it.
        let frames = journal.frames_written();
        assert_eq!(
            admit_at(&mut directory, &mut journal, never_seen, 1),
            Err(CustodyError::Admit(AdmitError::Full))
        );
        // The old admission of a known label is the resurrection it is.
        assert_eq!(
            admit_at(&mut directory, &mut journal, known, 1),
            Err(CustodyError::Admit(AdmitError::Resurrection {
                tombstone: 1,
                offered: 1
            }))
        );
        assert_eq!(journal.frames_written(), frames);
        // A known label returns one version up, in its own slot.
        assert_eq!(admit_at(&mut directory, &mut journal, known, 2), Ok(()));
        assert_eq!(directory.version_of(&id(&profile_name(known))), Some(2));
    }

    #[test]
    fn a_slot_held_by_another_kind_of_credential_leaves_one_fewer_for_peers_and_the_journal_refuses_the_last()
     {
        let mut medium = blank_medium();
        {
            let (mut journal, _) = Journal::open(&mut medium, limits()).unwrap();
            let mut directory = EphemeralPeers::new();
            // Not a control peer's, so the directory never counts it, but it takes one of the journal's sixteen slots.
            journal.install(b"spotify-token", 1, b"not a peer").unwrap();
            admit_profile(&mut directory, &mut journal, MAX_PEERS - 1);
            // The directory has room for one more identity and the journal has none: the journal's refusal is the
            // last word, and neither side changed.
            let frames = journal.frames_written();
            let last = MAX_PEERS - 1;
            assert_eq!(
                admit_at(&mut directory, &mut journal, last, 1),
                Err(CustodyError::Journal(JournalError::NamespaceFull))
            );
            assert_eq!(journal.frames_written(), frames);
            assert_eq!(directory.version_of(&id(&profile_name(last))), None);
            assert_eq!(directory.key_slots(), MAX_PEERS - 1);
        }
        // The other fifteen survive a restart; the other kind of credential is not counted among the peers.
        let mut reborn = reopened(&medium);
        let opened = Journal::open(&mut reborn, limits());
        let mut directory = EphemeralPeers::new();
        assert_eq!(
            restore_peers(&mut directory, &opened),
            Ok(Restored::Peers {
                live: MAX_PEERS - 1,
                revoked: 0,
                skipped: 0
            })
        );
        assert_eq!(directory.key_slots(), MAX_PEERS - 1);
    }

    #[test]
    fn a_journal_with_more_control_peers_than_a_directory_knows_is_refused_whole_and_admits_nobody()
    {
        // A journal configured for one credential more than `MAX_PEERS`: a configuration the directory cannot match.
        let mut big = limits();
        big.credentials.entries = MAX_PEERS + 1;
        let stored = |count: usize| {
            let mut medium = MemStorage::new(big.segment_bytes);
            {
                let (mut journal, _) = Journal::open(&mut medium, big.clone()).unwrap();
                for i in 0..count {
                    let name = profile_name(i);
                    let record = encode_record(profile_role(i), None, &test_key(&name));
                    journal
                        .install(&credential_id(&id(&name)), 1, &record)
                        .unwrap();
                }
            }
            MemStorage::from_image(big.segment_bytes, medium.durable())
        };

        // Seventeen identities: refused whole, nothing admitted, no key stored.
        let mut reborn = stored(MAX_PEERS + 1);
        let opened = Journal::open(&mut reborn, big.clone());
        let mut directory = EphemeralPeers::new();
        assert_eq!(
            restore_peers(&mut directory, &opened),
            Err(RestoreFailed::TooMany { max: MAX_PEERS })
        );
        for i in 0..=MAX_PEERS {
            assert_eq!(
                directory.version_of(&id(&profile_name(i))),
                None,
                "{}",
                profile_name(i)
            );
        }
        assert_eq!(directory.key_slots(), 0);

        // The permitted positive, on the very same configuration: sixteen identities restore in full.
        let mut reborn = stored(MAX_PEERS);
        let opened = Journal::open(&mut reborn, big.clone());
        let mut directory = EphemeralPeers::new();
        assert_eq!(
            restore_peers(&mut directory, &opened),
            Ok(Restored::Peers {
                live: MAX_PEERS,
                revoked: 0,
                skipped: 0
            })
        );
        assert_eq!(directory.key_slots(), MAX_PEERS);
    }
}
