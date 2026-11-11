//! Durable host-development composition of N02 custody, G03 dispatch and N06 agreement.
//!
//! The caller supplies storage, its secret store, clock and group session. No fixture keys,
//! sockets, implicit lease, device admission or distributed media cutover are provided here.
//! One journal owns credentials, command floors and proposal identifiers across restarts.

use std::collections::BTreeSet;

use franken_journal::{Journal, JournalError, Limits, Source, Storage};
use franken_session::{AuthorityToken, MembershipError, UnifiedGroupSession};

use super::custody::{self, CustodyError, RestoreFailed, Revoked};
use super::endpoint::{Endpoint, FecHandled, FecIngressStats};
use super::fec_negotiation::{FecCoordinator, FecError, FecProposal, MemberBinding};
use super::peer::{ControlProfile, PeerDirectory, PeerId, PeerRole};
use super::pipeline::{
    ChannelConfig, ConfigError, ControlChannel, Durability, Durable, HighWaterError, Restored,
    RestoredFloors, Settlement, Stepper, StoreFailed, restore_from_open,
    restore_seq_floors_from_open,
};
use crate::contracts::secret_store::SecretStore;
use crate::fsonos::{Context, Handled, HttpRequest};

const PROPOSAL_MARK: &[u8] = b"n06.prop";

#[derive(Debug)]
pub enum BootError {
    Channel(ConfigError),
    Restore(HighWaterError),
    Unavailable(&'static str),
    Peers(RestoreFailed),
    UnreadablePeers,
    Storage(JournalError),
}

/// Observable recovery status; relative-only degradation does not disable local silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootStatus {
    pub mark: Restored,
    pub floors: RestoredFloors,
    pub peers: custody::Restored,
}

#[derive(Debug)]
pub enum AgreementError {
    Unavailable,
    Exhausted,
    NoAttempt,
    ReservedLegacyIdentity,
    LegacyIdentityCapacity,
    LegacyConfigurationLocked,
    Protocol(FecError),
    Storage(JournalError),
}

/// Explicit 33-identity host profile, retaining one endpoint across negotiation attempts.
/// The media membership ceiling remains the session's existing 21-member limit.
pub struct FleetControlOwner<K: SecretStore, S: Storage> {
    channel: ControlChannel<PeerDirectory<K>>,
    journal: Journal<S>,
    endpoint: Endpoint,
    coordinator: Option<FecCoordinator>,
    legacy_peers: BTreeSet<PeerId>,
    ingress_started: bool,
}

impl<K: SecretStore, S: Storage> FleetControlOwner<K, S> {
    /// Open once, restore all authority before exposing it, and reserve required Marks slots.
    /// Unclaimed nonblank legacy media is refused; this is never an implicit migration.
    /// An interruption after initial journal formatting but before its first claim can leave
    /// empty, counterless nonblank media. This intentionally refuses with the same diagnostic;
    /// explicit provisioning is required rather than guessing that no earlier round existed.
    pub fn boot(
        keys: K,
        storage: S,
        config: ChannelConfig,
    ) -> Result<(Self, BootStatus), BootError> {
        let (mut journal, recovery) = Journal::open(storage, Limits::fleet_control_development())
            .map_err(BootError::Storage)?;
        if recovery.source == Source::Blank {
            custody::claim_fleet_profile_with_marks(
                &mut journal,
                &recovery,
                &[(super::pipeline::HIGH_WATER_KEY, 0), (PROPOSAL_MARK, 0)],
            )
            .map_err(BootError::Storage)?;
        } else if !journal.state().marks.contains_key(PROPOSAL_MARK) {
            return Err(BootError::Unavailable("proposal_counter_missing"));
        }
        let opened = Ok((journal, recovery));
        let mut directory = PeerDirectory::with_profile(keys, ControlProfile::FleetDevelopment);
        let peers = custody::restore_peers(&mut directory, &opened).map_err(BootError::Peers)?;
        if matches!(
            peers,
            custody::Restored::Unreadable(_) | custody::Restored::Peers { skipped: 1.., .. }
        ) {
            return Err(BootError::UnreadablePeers);
        }
        let mut channel = ControlChannel::new(directory, config).map_err(BootError::Channel)?;
        let mark = restore_from_open(&mut channel, &opened).map_err(BootError::Restore)?;
        let floors =
            restore_seq_floors_from_open(&mut channel, &opened).map_err(BootError::Restore)?;
        if matches!(mark, Restored::Refusing(_)) {
            return Err(BootError::Unavailable("unreadable_high_water"));
        }
        let (journal, _) = opened.map_err(BootError::Storage)?;
        if !journal
            .state()
            .marks
            .contains_key(super::pipeline::HIGH_WATER_KEY)
        {
            return Err(BootError::Unavailable("high_water_missing"));
        }
        Ok((
            Self {
                channel,
                journal,
                endpoint: Endpoint::new(),
                coordinator: None,
                legacy_peers: BTreeSet::new(),
                ingress_started: false,
            },
            BootStatus {
                mark,
                floors,
                peers,
            },
        ))
    }

    /// Read-only authority for transport routing and immediately revalidated sender handoff.
    pub fn authority(&self) -> &PeerDirectory<K> {
        self.channel.authority()
    }

    /// Trusted composition configures every SOAP bridge before opening any ingress, including
    /// after reboot. Such a peer can use legacy SOAP but never stable-number N02 control.
    pub fn reserve_legacy_peer(&mut self, peer: &PeerId) -> Result<(), AgreementError> {
        if self.legacy_peers.contains(peer) {
            return Ok(());
        }
        if self.ingress_started {
            return Err(AgreementError::LegacyConfigurationLocked);
        }
        if !self.legacy_peers.contains(peer)
            && self.legacy_peers.len() >= ControlProfile::FleetDevelopment.max_identities()
        {
            return Err(AgreementError::LegacyIdentityCapacity);
        }
        self.legacy_peers.insert(peer.clone());
        Ok(())
    }

    pub fn install_lease(
        &mut self,
        session: &UnifiedGroupSession,
        token: AuthorityToken,
        now_ns: u64,
    ) -> Result<(), MembershipError> {
        self.channel.install_lease(session, token, now_ns)
    }

    fn latch_poisoned(&mut self) {
        if self.journal.is_poisoned() {
            self.channel.latch_durability("owner_storage_poisoned");
            self.coordinator = None;
        }
    }

    pub fn admit(
        &mut self,
        peer: &PeerId,
        role: PeerRole,
        key: &[u8],
        epoch: Option<u64>,
        version: u64,
    ) -> Result<(), CustodyError> {
        let result = custody::admit_durably(
            self.channel.authority_mut(),
            &mut self.journal,
            peer,
            role,
            key,
            epoch,
            version,
        );
        if matches!(&result, Err(CustodyError::StoredNotLive(_))) {
            self.channel
                .latch_durability("owner_custody_desynchronized");
            self.coordinator = None;
        }
        self.latch_poisoned();
        result
    }

    pub fn revoke(&mut self, peer: &PeerId) -> Result<Revoked, CustodyError> {
        let result = custody::revoke_durably(self.channel.authority_mut(), &mut self.journal, peer);
        self.latch_poisoned();
        result
    }

    pub fn rebind(&mut self, peer: &PeerId, epoch: Option<u64>) -> Result<u64, CustodyError> {
        let result =
            custody::rebind_durably(self.channel.authority_mut(), &mut self.journal, peer, epoch);
        self.latch_poisoned();
        result
    }

    fn healthy(&self) -> bool {
        self.channel.durability() == Durability::Healthy && !self.journal.is_poisoned()
    }

    /// Allocate a reboot-monotonic identifier before publishing a new attempt. The endpoint's
    /// authentication work allowance is retained, including after a failed attempt.
    pub fn begin_agreement(
        &mut self,
        session: &UnifiedGroupSession,
        proposer: PeerId,
        role: PeerRole,
        bindings: Vec<MemberBinding>,
        timing: (u64, u64),
    ) -> Result<&FecProposal, AgreementError> {
        if !self.healthy() {
            return Err(AgreementError::Unavailable);
        }
        let id = self
            .journal
            .state()
            .marks
            .get(PROPOSAL_MARK)
            .copied()
            .ok_or(AgreementError::Unavailable)?
            .checked_add(1)
            .ok_or(AgreementError::Exhausted)?;
        let coordinator = FecCoordinator::new_with_profile(
            session,
            proposer,
            role,
            bindings,
            (timing.0, timing.1, id),
            ControlProfile::FleetDevelopment,
        )
        .map_err(AgreementError::Protocol)?;
        if let Err(error) = self.journal.raise_mark(PROPOSAL_MARK, id) {
            self.channel.latch_durability("owner_proposal_not_durable");
            self.coordinator = None;
            return Err(AgreementError::Storage(error));
        }
        self.coordinator = Some(coordinator);
        Ok(self
            .coordinator
            .as_ref()
            .expect("installed above")
            .proposal())
    }

    /// Handle actual N02/FFCN bytes with the restored shared authority. Accepted N02 commands
    /// still require `step`; an enqueue response never claims a committed effect.
    pub fn receive(
        &mut self,
        now_ns: u64,
        session: &UnifiedGroupSession,
        datagram: &[u8],
    ) -> Result<FecHandled, AgreementError> {
        self.ingress_started = true;
        if datagram.starts_with(&super::fec_negotiation::MAGIC) {
            if !self.healthy() {
                return Err(AgreementError::Unavailable);
            }
            let coordinator = self.coordinator.as_mut().ok_or(AgreementError::NoAttempt)?;
            Ok(self.endpoint.handle_with_fec(
                &mut self.channel,
                coordinator,
                now_ns,
                session,
                datagram,
            ))
        } else {
            let legacy = match super::wire::decode_datagram(datagram) {
                Ok(super::wire::Datagram::Request(request)) => {
                    self.legacy_peers.contains(request.body().peer())
                }
                Ok(super::wire::Datagram::Ack(ack)) => {
                    self.legacy_peers.contains(ack.body().peer())
                }
                Err(_) => false,
            };
            if legacy {
                return Err(AgreementError::ReservedLegacyIdentity);
            }
            Ok(FecHandled::Control(self.endpoint.handle(
                &mut self.channel,
                now_ns,
                session,
                datagram,
            )))
        }
    }

    pub fn step(
        &mut self,
        now_ns: u64,
        session: &mut UnifiedGroupSession,
    ) -> Result<Vec<Settlement>, StoreFailed> {
        self.ingress_started = true;
        Durable::new(&mut self.journal).step(&mut self.channel, now_ns, session)
    }

    /// Use the existing G03 endpoint with the same journal, authority and durable stepper.
    pub fn handle_soap(
        &mut self,
        endpoint: &mut crate::fsonos::Endpoint,
        session: &mut UnifiedGroupSession,
        now_ns: u64,
        request: &HttpRequest<'_>,
    ) -> Handled {
        if self.reserve_legacy_peer(endpoint.legacy_peer()).is_err() {
            return Self::empty_response(503);
        }
        self.ingress_started = true;
        if request.ingress == crate::fsonos::Ingress::Tailnet
            && request.headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("X-Franken-Peer")
                    && (*value == endpoint.legacy_peer().as_str()
                        || self.legacy_peers.iter().any(|peer| peer.as_str() == *value))
            })
        {
            // The legacy bridge never supplies stable client sequence numbers. Allowing its
            // identity here would opt authenticated relative commands out of durable floors.
            return Self::empty_response(401);
        }
        endpoint.handle(
            &mut Context {
                channel: &mut self.channel,
                session,
                stepper: &mut Durable::new(&mut self.journal),
                now_ns,
            },
            request,
        )
    }

    fn empty_response(status: u16) -> Handled {
        Handled {
            response: crate::fsonos::HttpResponse {
                status,
                headers: Vec::new(),
                body: String::new(),
            },
            notifications: Vec::new(),
            settled_others: Vec::new(),
        }
    }

    /// Read-only pair for SenderEndpoint's existing selection method, which revalidates again
    /// immediately before its local cutover. This is not receiver preflight or group activation.
    pub fn agreement_context(
        &self,
        session: &UnifiedGroupSession,
    ) -> Result<(&FecCoordinator, &PeerDirectory<K>), AgreementError> {
        if !self.healthy() {
            return Err(AgreementError::Unavailable);
        }
        let coordinator = self.coordinator.as_ref().ok_or(AgreementError::NoAttempt)?;
        coordinator
            .validated_selection(self.authority(), session)
            .map_err(AgreementError::Protocol)?;
        Ok((coordinator, self.authority()))
    }

    /// The current authenticated proposal and authority, before member acknowledgments.
    /// This context is not receiver resource or clock readiness.
    pub fn proposal_context(
        &self,
        session: &UnifiedGroupSession,
    ) -> Result<(&FecCoordinator, &PeerDirectory<K>), AgreementError> {
        if !self.healthy() {
            return Err(AgreementError::Unavailable);
        }
        let coordinator = self.coordinator.as_ref().ok_or(AgreementError::NoAttempt)?;
        coordinator
            .current_proposal_authority(self.authority(), session)
            .map_err(AgreementError::Protocol)?;
        Ok((coordinator, self.authority()))
    }

    pub const fn ingress_stats(&self) -> FecIngressStats {
        self.endpoint.fec_ingress_stats()
    }

    pub fn into_storage(self) -> S {
        self.journal.into_storage()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::fec_negotiation::{Ingress, MessageKind, encode, signing_bytes};
    use crate::channel::peer::{AdmitError, compute_proof};
    use crate::channel::testkit::fixture_session;
    use crate::contracts::secret_store::EphemeralSecretStore;
    use franken_journal::MemStorage;
    use franken_session::{ChannelRole, FencedControlCommand, GroupCommandPayload};

    type Owner = FleetControlOwner<EphemeralSecretStore, MemStorage>;
    const EPOCH: u64 = 10;

    fn id(name: &str) -> PeerId {
        PeerId::parse(name).unwrap()
    }

    fn key(name: &str) -> Vec<u8> {
        format!("public-owner-test-key-{name}-0123456789abcdef").into_bytes()
    }

    fn boot(storage: MemStorage) -> (Owner, BootStatus) {
        Owner::boot(
            EphemeralSecretStore::fleet_control_development(),
            storage,
            ChannelConfig::provisional(),
        )
        .unwrap()
    }

    fn blank() -> Owner {
        boot(MemStorage::new(
            Limits::fleet_control_development().segment_bytes,
        ))
        .0
    }

    fn session() -> UnifiedGroupSession {
        let mut session = fixture_session(EPOCH);
        let board = franken_board_profile::synthetic_test_fixture_catalog()
            .into_iter()
            .find(|board| board.model_number == "S5")
            .unwrap();
        for i in 2_u64..21 {
            session
                .apply_command(FencedControlCommand {
                    epoch: EPOCH,
                    command_seq: i + 1,
                    payload: GroupCommandPayload::AdmitMember {
                        member_id: format!("room-{i:02}"),
                        board: board.clone(),
                        role: ChannelRole::Stereo,
                    },
                })
                .unwrap();
        }
        session
    }

    fn enroll(owner: &mut Owner, session: &UnifiedGroupSession) -> Vec<MemberBinding> {
        let mut bindings = Vec::new();
        for (i, member) in session.members.keys().enumerate() {
            let peer = id(&format!("peer-{i:02}"));
            owner
                .admit(
                    &peer,
                    PeerRole::Controller,
                    &key(peer.as_str()),
                    Some(EPOCH),
                    1,
                )
                .unwrap();
            bindings.push(MemberBinding {
                member: member.clone(),
                peer,
                role: PeerRole::Controller,
            });
        }
        for name in
            std::iter::once("proposer".to_string()).chain((0..11).map(|i| format!("extra-{i:02}")))
        {
            owner
                .admit(
                    &id(&name),
                    PeerRole::Controller,
                    &key(&name),
                    Some(EPOCH),
                    1,
                )
                .unwrap();
        }
        bindings
    }

    fn wire(owner: &Owner, kind: MessageKind, peer: &PeerId, proposal: &FecProposal) -> Vec<u8> {
        let generation = owner.authority().version_of(peer).unwrap();
        let bytes = signing_bytes(kind, peer, generation, proposal);
        encode(
            kind,
            peer,
            generation,
            proposal,
            &compute_proof(&key(peer.as_str()), &bytes),
        )
        .unwrap()
    }

    fn begin(
        owner: &mut Owner,
        session: &UnifiedGroupSession,
        bindings: Vec<MemberBinding>,
    ) -> FecProposal {
        owner
            .begin_agreement(
                session,
                id("proposer"),
                PeerRole::Controller,
                bindings,
                (42, 900_000_000),
            )
            .unwrap()
            .clone()
    }

    #[test]
    fn fleet_owner_verified_proposal_context_requires_real_ingress_and_current_round() {
        let session = session();
        let mut owner = blank();
        let bindings = enroll(&mut owner, &session);
        assert!(matches!(
            owner.proposal_context(&session),
            Err(AgreementError::NoAttempt)
        ));
        let proposal = begin(&mut owner, &session, bindings.clone());
        assert!(matches!(
            owner.proposal_context(&session),
            Err(AgreementError::Protocol(FecError::MissingAcknowledgments))
        ));
        let message = wire(&owner, MessageKind::Proposal, &id("proposer"), &proposal);
        let mut forged = message.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(
            owner.receive(0, &session, &forged).unwrap(),
            FecHandled::Fec(Err(FecError::Authentication))
        );
        assert!(matches!(
            owner.proposal_context(&session),
            Err(AgreementError::Protocol(FecError::MissingAcknowledgments))
        ));
        assert_eq!(
            owner.receive(10_000_000, &session, &message).unwrap(),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        let token = {
            let (coordinator, authority) = owner.proposal_context(&session).unwrap();
            coordinator.validated_proposal(authority, &session).unwrap()
        };
        assert_eq!(token.proposal().proposal_id(), proposal.proposal_id());
        assert!(matches!(
            owner.agreement_context(&session),
            Err(AgreementError::Protocol(FecError::MissingAcknowledgments))
        ));
        let later = begin(&mut owner, &session, bindings);
        let next = wire(&owner, MessageKind::Proposal, &id("proposer"), &later);
        assert_eq!(
            owner.receive(20_000_000, &session, &next).unwrap(),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        let (coordinator, authority) = owner.proposal_context(&session).unwrap();
        assert_eq!(
            token.revalidate(coordinator, authority, &session),
            Err(FecError::Stale)
        );
        assert_eq!(
            coordinator
                .validated_proposal(authority, &session)
                .unwrap()
                .proposal()
                .proposal_id(),
            later.proposal_id()
        );
    }

    #[test]
    fn fleet_owner_restores_33_credentials_and_requires_21_real_signed_member_acks() {
        let session = session();
        let mut owner = blank();
        let bindings = enroll(&mut owner, &session);
        assert_eq!(owner.journal.state().credentials.len(), 33);
        assert!(
            bindings
                .iter()
                .all(|binding| owner.authority().version_of(&binding.peer) == Some(1))
        );
        assert!(matches!(
            owner.admit(
                &id("overflow"),
                PeerRole::Controller,
                &key("overflow"),
                Some(EPOCH),
                1
            ),
            Err(CustodyError::Admit(AdmitError::Full))
        ));
        let proposal = begin(&mut owner, &session, bindings.clone());
        let proposal_wire = wire(&owner, MessageKind::Proposal, &id("proposer"), &proposal);
        let mut tampered = proposal_wire.clone();
        *tampered.last_mut().unwrap() ^= 0x80;
        assert_eq!(
            owner.receive(0, &session, &tampered).unwrap(),
            FecHandled::Fec(Err(FecError::Authentication))
        );
        assert_eq!(
            owner.receive(10_000_000, &session, &proposal_wire).unwrap(),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        for (i, binding) in bindings.iter().take(20).enumerate() {
            let bytes = wire(&owner, MessageKind::Ack, &binding.peer, &proposal);
            assert_eq!(
                owner
                    .receive((i as u64 + 2) * 10_000_000, &session, &bytes)
                    .unwrap(),
                FecHandled::Fec(Ok(Ingress::Acknowledged))
            );
        }
        assert!(matches!(
            owner.agreement_context(&session),
            Err(AgreementError::Protocol(FecError::MissingAcknowledgments))
        ));
        let final_ack = wire(&owner, MessageKind::Ack, &bindings[20].peer, &proposal);
        assert_eq!(
            owner.receive(230_000_000, &session, &final_ack).unwrap(),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        assert_eq!(
            owner
                .agreement_context(&session)
                .unwrap()
                .0
                .validated_selection(owner.authority(), &session)
                .unwrap()
                .members()
                .len(),
            21
        );

        let (mut restored, status) = boot(owner.into_storage());
        assert_eq!(
            status.peers,
            custody::Restored::Peers {
                live: 33,
                revoked: 0,
                skipped: 0
            }
        );
        assert!(matches!(
            restored.receive(0, &session, &final_ack),
            Err(AgreementError::NoAttempt)
        ));
        let next = begin(&mut restored, &session, bindings);
        assert_eq!(next.proposal_id(), proposal.proposal_id() + 1);
        assert_eq!(
            restored.receive(0, &session, &final_ack).unwrap(),
            FecHandled::Fec(Err(FecError::Conflict))
        );
        let next_wire = wire(&restored, MessageKind::Proposal, &id("proposer"), &next);
        assert_eq!(
            restored.receive(10_000_000, &session, &next_wire).unwrap(),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        assert!(matches!(
            restored.agreement_context(&session),
            Err(AgreementError::Protocol(FecError::MissingAcknowledgments))
        ));
    }

    #[test]
    fn fleet_owner_revoke_and_rebind_survive_boot_without_resurrection() {
        let mut owner = blank();
        let peer = id("controller");
        owner
            .admit(
                &peer,
                PeerRole::Controller,
                &key("controller"),
                Some(EPOCH),
                1,
            )
            .unwrap();
        assert_eq!(owner.rebind(&peer, Some(EPOCH + 1)), Ok(2));
        let (mut owner, _) = boot(owner.into_storage());
        assert_eq!(owner.authority().version_of(&peer), Some(2));
        assert_eq!(owner.revoke(&peer), Ok(Revoked::Durable));
        let (mut owner, status) = boot(owner.into_storage());
        assert_eq!(
            status.peers,
            custody::Restored::Peers {
                live: 0,
                revoked: 1,
                skipped: 0
            }
        );
        assert!(
            owner
                .admit(
                    &peer,
                    PeerRole::Controller,
                    &key("controller"),
                    Some(EPOCH),
                    2
                )
                .is_err()
        );
        owner
            .admit(
                &peer,
                PeerRole::Controller,
                &key("controller"),
                Some(EPOCH),
                3,
            )
            .unwrap();
        assert_eq!(owner.authority().version_of(&peer), Some(3));
    }

    #[test]
    fn fleet_owner_new_round_cannot_refill_endpoint_fec_work_budget() {
        let session = fixture_session(EPOCH);
        let mut owner = blank();
        let bindings = enroll(&mut owner, &session);
        let proposal = begin(&mut owner, &session, bindings.clone());
        let bytes = wire(&owner, MessageKind::Proposal, &id("proposer"), &proposal);
        for _ in 0..64 {
            assert!(matches!(
                owner.receive(0, &session, &bytes).unwrap(),
                FecHandled::Fec(Ok(_))
            ));
        }
        let next = begin(&mut owner, &session, bindings);
        let bytes = wire(&owner, MessageKind::Proposal, &id("proposer"), &next);
        assert!(matches!(
            owner.receive(0, &session, &bytes).unwrap(),
            FecHandled::RateLimited { .. }
        ));
        assert_eq!(owner.ingress_stats().admitted, 64);
        assert_eq!(owner.ingress_stats().rate_limited, 1);
        assert_eq!(
            owner.receive(10_000_000, &session, &bytes).unwrap(),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
    }

    #[test]
    fn fleet_owner_reserves_marks_before_unrelated_capacity_is_consumed() {
        let mut owner = blank();
        assert_eq!(owner.journal.state().marks.len(), 3);
        for i in 0..5 {
            owner
                .journal
                .raise_mark(format!("other-{i}").as_bytes(), 1)
                .unwrap();
        }
        assert!(owner.journal.raise_mark(b"one-too-many", 1).is_err());
        owner
            .journal
            .raise_mark(super::super::pipeline::HIGH_WATER_KEY, 7)
            .unwrap();
        owner.journal.raise_mark(PROPOSAL_MARK, 8).unwrap();
        let (restored, _) = boot(owner.into_storage());
        assert_eq!(restored.journal.state().marks.get(PROPOSAL_MARK), Some(&8));
        assert_eq!(
            restored
                .journal
                .state()
                .marks
                .get(super::super::pipeline::HIGH_WATER_KEY),
            Some(&7)
        );
    }

    #[test]
    fn fleet_owner_rejects_corrupt_peer_state_and_exhausted_proposal_ids() {
        let session = fixture_session(EPOCH);
        let mut owner = blank();
        let bindings = enroll(&mut owner, &session);
        owner.journal.raise_mark(PROPOSAL_MARK, u64::MAX).unwrap();
        assert!(matches!(
            owner.begin_agreement(
                &session,
                id("proposer"),
                PeerRole::Controller,
                bindings,
                (42, 0)
            ),
            Err(AgreementError::Exhausted)
        ));
        assert!(owner.coordinator.is_none());
        owner
            .journal
            .install(b"cp:corrupt", 1, b"invalid-record")
            .unwrap();
        assert!(matches!(
            Owner::boot(
                EphemeralSecretStore::fleet_control_development(),
                owner.into_storage(),
                ChannelConfig::provisional()
            ),
            Err(BootError::UnreadablePeers)
        ));
    }

    #[test]
    fn fleet_owner_refuses_existing_counterless_media_instead_of_reusing_round_ids() {
        // Also pin the deliberate availability boundary: interruption after formatting but
        // before claiming needs explicit provisioning, never an inferred safe counter reset.
        let (formatted, _) = Journal::open(
            MemStorage::new(Limits::fleet_control_development().segment_bytes),
            Limits::fleet_control_development(),
        )
        .unwrap();
        assert!(matches!(
            Owner::boot(
                EphemeralSecretStore::fleet_control_development(),
                formatted.into_storage(),
                ChannelConfig::provisional(),
            ),
            Err(BootError::Unavailable("proposal_counter_missing"))
        ));
        let (mut journal, recovery) = Journal::open(
            MemStorage::new(Limits::fleet_control_development().segment_bytes),
            Limits::fleet_control_development(),
        )
        .unwrap();
        custody::claim_fleet_profile(&mut journal, &recovery).unwrap();
        assert!(matches!(
            Owner::boot(
                EphemeralSecretStore::fleet_control_development(),
                journal.into_storage(),
                ChannelConfig::provisional(),
            ),
            Err(BootError::Unavailable("proposal_counter_missing"))
        ));
        // A fully initialized owner's own reboot remains admitted and never resets its mark.
        let (restored, _) = boot(blank().into_storage());
        assert_eq!(restored.journal.state().marks.get(PROPOSAL_MARK), Some(&0));
    }

    fn soap_relative(
        owner: &mut Owner,
        endpoint: &mut crate::fsonos::Endpoint,
        session: &mut UnifiedGroupSession,
        revision: u64,
        seq: u64,
        signing_key: &[u8],
    ) -> Handled {
        use crate::channel::request::{ControlCommand, RequestBody};
        use crate::fsonos::{Ingress, Service};
        let body = RequestBody::new(
            id("controller"),
            seq,
            EPOCH,
            Some(revision),
            ControlCommand::AdjustMemberVolume {
                member_id: "kitchen".into(),
                delta: 10,
            },
        )
        .unwrap();
        let proof = compute_proof(signing_key, &body.signing_bytes());
        let proof: String = proof
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let service = Service::RenderingControl;
        let xml = format!(
            "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:SetRelativeVolume xmlns:u=\"{}\"><InstanceID>0</InstanceID><Channel>Master</Channel><Adjustment>10</Adjustment></u:SetRelativeVolume></s:Body></s:Envelope>",
            service.urn()
        );
        let action = format!("\"{}#SetRelativeVolume\"", service.urn());
        let seq = seq.to_string();
        let epoch = EPOCH.to_string();
        let revision = revision.to_string();
        let headers = [
            ("SOAPACTION", action.as_str()),
            ("X-Franken-Peer", "controller"),
            ("X-Franken-Seq", seq.as_str()),
            ("X-Franken-Epoch", epoch.as_str()),
            ("X-Franken-Revision", revision.as_str()),
            ("X-Franken-Proof", proof.as_str()),
        ];
        owner.handle_soap(
            endpoint,
            session,
            1_000_000_000,
            &HttpRequest {
                method: "POST",
                path: service.control_path(),
                peer_ip: "192.0.2.10".parse().unwrap(),
                ingress: Ingress::Tailnet,
                headers: &headers,
                body: xml.as_bytes(),
            },
        )
    }

    fn soap_endpoint() -> crate::fsonos::Endpoint {
        crate::fsonos::Endpoint::new(
            crate::fsonos::EndpointConfig::provisional("kitchen"),
            crate::fsonos::LegacyBridge::new(id("legacy-bridge"), key("legacy-bridge")),
            1,
            1,
        )
        .unwrap()
    }

    #[test]
    fn fleet_owner_g03_commit_retry_and_restart_use_the_same_durable_authority() {
        let mut owner = blank();
        let mut session = fixture_session(EPOCH);
        owner
            .admit(
                &id("controller"),
                PeerRole::Controller,
                &key("controller"),
                Some(EPOCH),
                1,
            )
            .unwrap();
        owner
            .admit(
                &id("legacy-bridge"),
                PeerRole::Controller,
                &key("legacy-bridge"),
                Some(EPOCH),
                1,
            )
            .unwrap();
        owner
            .install_lease(&session, AuthorityToken::issue(&session, u64::MAX), 0)
            .unwrap();
        let mut endpoint = soap_endpoint();
        // A legitimate legacy request precedes authenticated control. Its unstable retry IDs
        // must never disable the distinct controller's durable floor.
        let legacy_body = b"<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:SetVolume xmlns:u=\"urn:schemas-upnp-org:service:RenderingControl:1\"><InstanceID>0</InstanceID><Channel>Master</Channel><DesiredVolume>50</DesiredVolume></u:SetVolume></s:Body></s:Envelope>";
        let legacy_headers = [(
            "SOAPACTION",
            "\"urn:schemas-upnp-org:service:RenderingControl:1#SetVolume\"",
        )];
        let legacy = owner.handle_soap(
            &mut endpoint,
            &mut session,
            0,
            &HttpRequest {
                method: "POST",
                path: crate::fsonos::Service::RenderingControl.control_path(),
                peer_ip: "192.0.2.10".parse().unwrap(),
                ingress: crate::fsonos::Ingress::LocalLegacy,
                headers: &legacy_headers,
                body: legacy_body,
            },
        );
        assert_eq!(legacy.response.status, 200, "{}", legacy.response.body);
        let revision = session.state_revision;
        let answer = soap_relative(
            &mut owner,
            &mut endpoint,
            &mut session,
            revision,
            1,
            &key("controller"),
        );
        assert_eq!(answer.response.status, 200, "{}", answer.response.body);
        assert_eq!(session.members["kitchen"].volume_0_to_100, 60);
        assert_eq!(session.state_revision, revision + 1);
        let duplicate = soap_relative(
            &mut owner,
            &mut endpoint,
            &mut session,
            revision,
            1,
            &key("controller"),
        );
        assert_eq!(duplicate.response.status, 200);
        assert_eq!(session.state_revision, revision + 1);

        let (mut restored, status) = boot(owner.into_storage());
        assert_eq!(status.floors, RestoredFloors::Table { identities: 1 });
        restored
            .install_lease(&session, AuthorityToken::issue(&session, u64::MAX), 0)
            .unwrap();
        let mut endpoint = soap_endpoint();
        let replay = soap_relative(
            &mut restored,
            &mut endpoint,
            &mut session,
            revision,
            1,
            &key("controller"),
        );
        assert_eq!(replay.response.status, 500);
        assert!(replay.response.body.contains("<errorCode>801</errorCode>"));
        assert_eq!(session.state_revision, revision + 1);
        let current = session.state_revision;
        let forged = soap_relative(
            &mut restored,
            &mut endpoint,
            &mut session,
            current,
            2,
            &key("wrong-key"),
        );
        assert_ne!(forged.response.status, 200);
        assert_eq!(session.state_revision, current);
        let valid = soap_relative(
            &mut restored,
            &mut endpoint,
            &mut session,
            current,
            2,
            &key("controller"),
        );
        assert_eq!(valid.response.status, 200, "{}", valid.response.body);
        assert_eq!(session.members["kitchen"].volume_0_to_100, 70);
        assert_eq!(session.state_revision, current + 1);
        eprintln!(
            "FLEET_OWNER host-model: restored_peers={:?} floors={:?} final_revision={} volume={}",
            status.peers,
            status.floors,
            session.state_revision,
            session.members["kitchen"].volume_0_to_100
        );
    }

    fn control_wire(
        peer: &str,
        seq: u64,
        command: super::super::request::ControlCommand,
        revision: Option<u64>,
    ) -> Vec<u8> {
        use crate::channel::request::{ControlRequest, RequestBody};
        let body = RequestBody::new(id(peer), seq, EPOCH, revision, command).unwrap();
        let proof = compute_proof(&key(peer), &body.signing_bytes());
        super::super::wire::encode_request(&ControlRequest::new(body, proof)).unwrap()
    }

    #[test]
    fn fleet_owner_legacy_identity_cannot_bypass_durable_control_through_raw_wire() {
        use crate::channel::request::ControlCommand;
        let mut owner = blank();
        let mut session = fixture_session(EPOCH);
        for peer in ["legacy-bridge", "controller"] {
            owner
                .admit(&id(peer), PeerRole::Controller, &key(peer), Some(EPOCH), 1)
                .unwrap();
        }
        owner
            .install_lease(&session, AuthorityToken::issue(&session, u64::MAX), 0)
            .unwrap();
        owner.reserve_legacy_peer(&id("legacy-bridge")).unwrap();
        let set = || ControlCommand::SetMemberVolume {
            member_id: "kitchen".into(),
            volume: 60,
        };
        let revision = session.state_revision;
        assert!(matches!(
            owner.receive(
                0,
                &session,
                &control_wire("legacy-bridge", 1, set(), Some(revision))
            ),
            Err(AgreementError::ReservedLegacyIdentity)
        ));
        // Preserve the initially observed failure as a negative control: authentication
        // alone cannot omit the observed revision, even for an absolute volume command.
        assert!(matches!(
            owner
                .receive(0, &session, &control_wire("controller", 1, set(), None))
                .unwrap(),
            FecHandled::Control(super::super::endpoint::Handled::Request {
                result: super::super::pipeline::SubmitResult::Rejected(
                    super::super::pipeline::Rejection::RevisionRequired { .. }
                ),
                ..
            })
        ));
        assert_eq!(owner.step(0, &mut session).unwrap().len(), 0);
        assert_eq!(session.state_revision, revision);
        assert!(matches!(
            owner
                .receive(
                    0,
                    &session,
                    &control_wire("controller", 1, set(), Some(revision))
                )
                .unwrap(),
            FecHandled::Control(super::super::endpoint::Handled::Request {
                result: super::super::pipeline::SubmitResult::Queued { .. },
                ..
            })
        ));
        assert_eq!(owner.step(0, &mut session).unwrap().len(), 1);
        assert_eq!(session.members["kitchen"].volume_0_to_100, 60);
        assert_eq!(session.state_revision, revision + 1);

        // An endpoint configured to reuse the controller as its legacy bridge cannot silently
        // turn authenticated relative control into an unstable-ID principal.
        let mut shared = crate::fsonos::Endpoint::new(
            crate::fsonos::EndpointConfig::provisional("kitchen"),
            crate::fsonos::LegacyBridge::new(id("controller"), key("controller")),
            1,
            1,
        )
        .unwrap();
        let revision = session.state_revision;
        let refused = soap_relative(
            &mut owner,
            &mut shared,
            &mut session,
            revision,
            2,
            &key("controller"),
        );
        assert_eq!(
            refused.response.status, 503,
            "late bridge reconfiguration is refused"
        );
        assert_eq!(session.state_revision, revision);

        // The exact pending-before-reservation counterexample: a stable relative request
        // must retain its durable floor even when a later caller wants the same legacy ID.
        let mut owner = blank();
        let mut session = fixture_session(EPOCH);
        owner
            .admit(
                &id("controller"),
                PeerRole::Controller,
                &key("controller"),
                Some(EPOCH),
                1,
            )
            .unwrap();
        owner
            .install_lease(&session, AuthorityToken::issue(&session, u64::MAX), 0)
            .unwrap();
        let body = crate::channel::request::RequestBody::new(
            id("controller"),
            1,
            EPOCH,
            Some(session.state_revision),
            ControlCommand::AdjustMemberVolume {
                member_id: "kitchen".into(),
                delta: 10,
            },
        )
        .unwrap();
        let proof = compute_proof(&key("controller"), &body.signing_bytes());
        let bytes = crate::channel::wire::encode_request(
            &crate::channel::request::ControlRequest::new(body, proof),
        )
        .unwrap();
        owner.receive(0, &session, &bytes).unwrap();
        assert!(matches!(
            owner.reserve_legacy_peer(&id("controller")),
            Err(AgreementError::LegacyConfigurationLocked)
        ));
        let legacy_headers = [(
            "SOAPACTION",
            "\"urn:schemas-upnp-org:service:RenderingControl:1#SetVolume\"",
        )];
        let legacy_body = b"<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:SetVolume xmlns:u=\"urn:schemas-upnp-org:service:RenderingControl:1\"><InstanceID>0</InstanceID><Channel>Master</Channel><DesiredVolume>90</DesiredVolume></u:SetVolume></s:Body></s:Envelope>";
        let rejected = owner.handle_soap(
            &mut shared,
            &mut session,
            0,
            &HttpRequest {
                method: "POST",
                path: crate::fsonos::Service::RenderingControl.control_path(),
                peer_ip: "192.0.2.10".parse().unwrap(),
                ingress: crate::fsonos::Ingress::LocalLegacy,
                headers: &legacy_headers,
                body: legacy_body,
            },
        );
        assert_eq!(rejected.response.status, 503);
        assert_eq!(
            session.members["kitchen"].volume_0_to_100, 50,
            "refused reconfiguration must not step earlier work"
        );
        assert_eq!(owner.step(0, &mut session).unwrap().len(), 1);
        assert_eq!(owner.channel.seq_floor(&id("controller")), Some(1));
        assert_eq!(session.members["kitchen"].volume_0_to_100, 60);
        let (_, status) = boot(owner.into_storage());
        assert_eq!(status.floors, RestoredFloors::Table { identities: 1 });
    }

    #[test]
    fn fleet_owner_failed_proposal_persistence_preserves_local_silence() {
        use crate::channel::request::ControlCommand;
        let mut owner = blank();
        let mut session = fixture_session(EPOCH);
        let bindings = enroll(&mut owner, &session);
        owner
            .install_lease(&session, AuthorityToken::issue(&session, u64::MAX), 0)
            .unwrap();
        owner
            .admit(&id("panel"), PeerRole::LocalUser, &key("panel"), None, 1)
            .unwrap();
        let first = begin(&mut owner, &session, bindings.clone());
        let next_operation = owner.journal.storage().ops_done();
        owner.journal.storage_mut().fail_op_at = Some(next_operation);
        assert!(matches!(
            owner.begin_agreement(
                &session,
                id("proposer"),
                PeerRole::Controller,
                bindings,
                (42, 0)
            ),
            Err(AgreementError::Storage(_))
        ));
        assert_eq!(
            owner.journal.state().marks.get(PROPOSAL_MARK),
            Some(&first.proposal_id())
        );
        assert!(!owner.healthy());
        assert!(owner.coordinator.is_none());
        let remote = control_wire(
            "proposer",
            1,
            ControlCommand::SetMemberVolume {
                member_id: "kitchen".into(),
                volume: 90,
            },
            Some(session.state_revision),
        );
        assert!(matches!(
            owner.receive(0, &session, &remote).unwrap(),
            FecHandled::Control(super::super::endpoint::Handled::Request {
                result: super::super::pipeline::SubmitResult::Queued { .. },
                ..
            })
        ));
        let refused = owner.step(0, &mut session).unwrap();
        assert_eq!(refused.len(), 1);
        assert_eq!(
            refused[0].outcome,
            super::super::pipeline::Outcome::Refused(
                super::super::pipeline::Refusal::InternalFault
            )
        );
        assert_eq!(session.members["kitchen"].volume_0_to_100, 50);
        let local = control_wire(
            "panel",
            1,
            ControlCommand::SetMemberMute {
                member_id: "kitchen".into(),
                muted: true,
            },
            None,
        );
        owner.receive(1, &session, &local).unwrap();
        assert_eq!(owner.step(1, &mut session).unwrap().len(), 1);
        assert!(session.members["kitchen"].muted);
        assert!(
            !owner.healthy(),
            "local silence must not clear the failed durability latch"
        );
    }
}
