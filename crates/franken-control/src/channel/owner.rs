//! Durable host-development composition of N02 custody, G03 dispatch and N06 agreement.
//!
//! The caller supplies storage, its secret store, clock and group session. No fixture keys,
//! sockets, implicit lease, device admission or distributed media cutover are provided here.
//! One journal owns credentials, command floors and proposal identifiers across restarts.

use std::collections::BTreeSet;

use franken_journal::{Journal, JournalError, Limits, Namespace, Source, Storage};
use franken_session::{
    AuthorityToken, ChannelRole, GroupMembership, MembershipConfig, MembershipError,
    UnifiedGroupSession,
};

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

// One local desired member, not a live session or a full group snapshot.
const RECOVERY_BINDING_KEY: &[u8] = b"n02.binding";
const RECOVERY_BINDING_VERSION: u8 = 1;
const MAX_RECOVERY_LABEL_BYTES: usize = 64;

/// Stable provisioned identity and desired local member; no authority, output
/// grant, live membership, calibrated profile or physical rollback proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryBinding {
    group_id: String,
    configured_issuer: PeerId,
    incarnation: [u8; 16],
    member_id: String,
    profile_id: String,
    role: ChannelRole,
}

impl RecoveryBinding {
    #[must_use]
    pub fn group_id(&self) -> &str {
        &self.group_id
    }
    #[must_use]
    pub fn configured_issuer(&self) -> &PeerId {
        &self.configured_issuer
    }
    #[must_use]
    pub const fn incarnation(&self) -> &[u8; 16] {
        &self.incarnation
    }
    #[must_use]
    pub fn member_id(&self) -> &str {
        &self.member_id
    }
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }
    #[must_use]
    pub const fn role(&self) -> ChannelRole {
        self.role
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(246);
        bytes.push(RECOVERY_BINDING_VERSION);
        for label in [&self.group_id[..], self.configured_issuer.as_str()] {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.extend_from_slice(&self.incarnation);
        for label in [&self.member_id[..], &self.profile_id[..]] {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(match self.role {
            ChannelRole::Stereo => 1,
            ChannelRole::LeftMono => 2,
            ChannelRole::RightMono => 3,
            ChannelRole::MonoSum => 4,
            ChannelRole::SubLfe => 5,
        });
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, RecoveryBindingError> {
        fn label<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a str, RecoveryBindingError> {
            let len = usize::from(*bytes.get(*pos).ok_or(RecoveryBindingError::Malformed)?);
            *pos += 1;
            let end = pos
                .checked_add(len)
                .ok_or(RecoveryBindingError::Malformed)?;
            let value = std::str::from_utf8(
                bytes
                    .get(*pos..end)
                    .ok_or(RecoveryBindingError::Malformed)?,
            )
            .map_err(|_| RecoveryBindingError::Malformed)?;
            *pos = end;
            Ok(value)
        }
        if bytes.first() != Some(&RECOVERY_BINDING_VERSION) {
            return Err(RecoveryBindingError::Malformed);
        }
        let mut pos = 1;
        let group = label(bytes, &mut pos)?;
        let issuer = label(bytes, &mut pos)?;
        let configured_issuer =
            PeerId::parse(issuer).map_err(|_| RecoveryBindingError::Malformed)?;
        let end = pos.checked_add(16).ok_or(RecoveryBindingError::Malformed)?;
        let incarnation: [u8; 16] = bytes
            .get(pos..end)
            .ok_or(RecoveryBindingError::Malformed)?
            .try_into()
            .map_err(|_| RecoveryBindingError::Malformed)?;
        pos = end;
        let member = label(bytes, &mut pos)?;
        let profile = label(bytes, &mut pos)?;
        let role = match bytes.get(pos) {
            Some(1) => ChannelRole::Stereo,
            Some(2) => ChannelRole::LeftMono,
            Some(3) => ChannelRole::RightMono,
            Some(4) => ChannelRole::MonoSum,
            Some(5) => ChannelRole::SubLfe,
            _ => return Err(RecoveryBindingError::Malformed),
        };
        if pos + 1 != bytes.len()
            || !valid_label(group)
            || !valid_member(member)
            || !valid_label(profile)
            || incarnation == [0; 16]
        {
            return Err(RecoveryBindingError::Malformed);
        }
        Ok(Self {
            group_id: group.to_owned(),
            configured_issuer,
            incarnation,
            member_id: member.to_owned(),
            profile_id: profile.to_owned(),
            role,
        })
    }
}

fn valid_label(label: &str) -> bool {
    !label.is_empty() && label.len() <= MAX_RECOVERY_LABEL_BYTES
}
fn valid_member(member: &str) -> bool {
    valid_label(member)
        && member.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// Refusal to store or decode a stable provisioning binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryBindingError {
    Unavailable,
    NotFresh,
    InvalidGroup,
    InvalidIncarnation,
    InvalidMember,
    InvalidProfile,
    IssuerNotAdmitted,
    Conflict,
    Malformed,
    Storage(JournalError),
}

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

/// Why a trusted new-group provisioning request could not form a fresh owner bundle.
#[derive(Debug)]
pub enum FreshGroupError {
    NotFresh,
    InvalidIdentity,
    Authority(MembershipError),
}

/// One freshly provisioned control owner and the group state it constructed.
/// Fields are private: an arbitrary reconstructed session cannot form this bundle.
pub struct FreshFleetGroup<K: SecretStore, S: Storage> {
    control: FleetControlOwner<K, S>,
    membership: GroupMembership,
    session: UnifiedGroupSession,
    authority: AuthorityToken,
}

impl<K: SecretStore, S: Storage> FreshFleetGroup<K, S> {
    /// Consume the bundle once. The receiving owner must not accept separately
    /// reconstructed parts as a substitute for this fresh input.
    pub fn into_parts(
        self,
    ) -> (
        FleetControlOwner<K, S>,
        GroupMembership,
        UnifiedGroupSession,
        AuthorityToken,
    ) {
        (self.control, self.membership, self.session, self.authority)
    }
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
    /// Only this process's fresh provisioning is known, not reconstructed history.
    fresh_control_provisioning: bool,
    fresh_group_constructed: bool,
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
        let fresh_control_provisioning = recovery.source == Source::Blank;
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
                fresh_control_provisioning,
                fresh_group_constructed: false,
            },
            BootStatus {
                mark,
                floors,
                peers,
            },
        ))
    }

    /// Store one desired local member's fixed provisioning identity. Issuer
    /// enrollment is checked, but proves neither issuer role nor current authority.
    /// The caller supplies the nonzero incarnation; uniqueness and physical
    /// rollback resistance are not established here. Existing media never acquire
    /// a missing binding through this method.
    pub fn provision_recovery_binding(
        &mut self,
        group_id: &str,
        issuer: &PeerId,
        incarnation: [u8; 16],
        member_id: &str,
        profile_id: &str,
        role: ChannelRole,
    ) -> Result<(), RecoveryBindingError> {
        if !self.healthy() {
            return Err(RecoveryBindingError::Unavailable);
        }
        if !self.fresh_control_provisioning
            || self.fresh_group_constructed
            || self.ingress_started
            || self.coordinator.is_some()
        {
            return Err(RecoveryBindingError::NotFresh);
        }
        if !valid_label(group_id) {
            return Err(RecoveryBindingError::InvalidGroup);
        }
        if incarnation == [0; 16] {
            return Err(RecoveryBindingError::InvalidIncarnation);
        }
        if !valid_member(member_id) {
            return Err(RecoveryBindingError::InvalidMember);
        }
        if !valid_label(profile_id) {
            return Err(RecoveryBindingError::InvalidProfile);
        }
        if self.authority().version_of(issuer).is_none() {
            return Err(RecoveryBindingError::IssuerNotAdmitted);
        }
        let candidate = RecoveryBinding {
            group_id: group_id.to_owned(),
            configured_issuer: issuer.clone(),
            incarnation,
            member_id: member_id.to_owned(),
            profile_id: profile_id.to_owned(),
            role,
        };
        if let Some(existing) = self.recovery_binding()? {
            return if existing == candidate {
                Ok(())
            } else {
                Err(RecoveryBindingError::Conflict)
            };
        }
        let result = self.journal.put(
            Namespace::Records,
            RECOVERY_BINDING_KEY,
            &candidate.encode(),
        );
        self.latch_poisoned();
        result.map(|_| ()).map_err(RecoveryBindingError::Storage)
    }

    /// Read the same-journal binding; `None` is absence, never recovery authority.
    pub fn recovery_binding(&self) -> Result<Option<RecoveryBinding>, RecoveryBindingError> {
        if !self.healthy() {
            return Err(RecoveryBindingError::Unavailable);
        }
        self.journal
            .state()
            .records
            .get(RECOVERY_BINDING_KEY)
            .map(|bytes| RecoveryBinding::decode(bytes))
            .transpose()
    }

    /// Read-only authority for transport routing and immediately revalidated sender handoff.
    pub fn authority(&self) -> &PeerDirectory<K> {
        self.channel.authority()
    }

    /// Whether this session can no longer safely allocate a control sequence.
    #[must_use]
    pub fn session_sequence_exhausted(&self, session: &UnifiedGroupSession) -> bool {
        self.channel.session_sequence_exhausted(session)
    }

    /// Check the currently held channel lease against this session and its
    /// configured early-expiry margin without cloning the authority token.
    #[must_use]
    pub fn lease_is_live(&self, session: &UnifiedGroupSession, now_ns: u64) -> bool {
        self.channel.lease().is_some_and(|token| {
            token
                .check_with_margin(session, now_ns, self.channel.config().lease_margin_ns)
                .is_ok()
        })
    }

    /// Whether this owner's constructed fresh group can still be used.
    /// Only the consuming fresh-group constructor sets this state; existing
    /// media and arbitrary sessions do not establish it. A storage failure
    /// revokes it. This does not prove recovery from erased or rolled-back media.
    #[must_use]
    pub fn fresh_group_is_healthy(&self) -> bool {
        self.fresh_group_constructed && self.healthy()
    }

    /// Construct a new group's session and membership within this fresh owner.
    /// Group identity and authority are explicit trusted provisioning inputs;
    /// no member is admitted and no device, credential enrollment or recovery
    /// is implied. `now_ns` and the lease share the caller's group timebase.
    pub fn provision_fresh_group(
        mut self,
        group_id: &str,
        issuer_id: &str,
        epoch: u64,
        config: MembershipConfig,
        authority: AuthorityToken,
        now_ns: u64,
    ) -> Result<FreshFleetGroup<K, S>, FreshGroupError> {
        if !self.fresh_control_provisioning
            || self.fresh_group_constructed
            || !self.healthy()
            || self.ingress_started
            || self.coordinator.is_some()
            || self.journal.state().marks.get(PROPOSAL_MARK) != Some(&0)
        {
            return Err(FreshGroupError::NotFresh);
        }
        if group_id.is_empty() || issuer_id.is_empty() || epoch == 0 {
            return Err(FreshGroupError::InvalidIdentity);
        }
        if self
            .recovery_binding()
            .map_err(|_| FreshGroupError::NotFresh)?
            .is_some_and(|binding| {
                binding.group_id != group_id || binding.configured_issuer.as_str() != issuer_id
            })
        {
            return Err(FreshGroupError::NotFresh);
        }
        let session = UnifiedGroupSession::new(group_id, issuer_id, epoch);
        if self.channel.session_sequence_exhausted(&session) {
            return Err(FreshGroupError::NotFresh);
        }
        authority
            .check_with_margin(&session, now_ns, config.lease.clock_uncertainty_ns)
            .map_err(FreshGroupError::Authority)?;
        self.install_lease(&session, authority.clone(), now_ns)
            .map_err(FreshGroupError::Authority)?;
        let membership = GroupMembership::new(config);
        self.fresh_group_constructed = true;
        Ok(FreshFleetGroup {
            control: self,
            membership,
            session,
            authority,
        })
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
        self.receive_inner(now_ns, None, session, datagram)
    }

    /// Receive through the same endpoint budget using trusted group time for V2.
    /// The caller must derive it from an independently admitted next-epoch clock
    /// in the bound presentation domain; this number does not prove admission.
    pub fn receive_with_group_time(
        &mut self,
        now_ns: u64,
        group_now_ns: u64,
        session: &UnifiedGroupSession,
        datagram: &[u8],
    ) -> Result<FecHandled, AgreementError> {
        self.receive_inner(
            now_ns,
            Some(super::fec_negotiation::FecIngressTime::raw(group_now_ns)),
            session,
            datagram,
        )
    }

    /// Receive using an independently admitted future clock on the same local
    /// monotonic timebase as the endpoint limiter. Unusable clocks invalidate
    /// an installed future round without blocking ordinary N02/v1 control.
    pub fn receive_with_future_clock(
        &mut self,
        now_ns: u64,
        future_clock: &franken_clock::group::GroupClock,
        session: &UnifiedGroupSession,
        datagram: &[u8],
    ) -> Result<FecHandled, AgreementError> {
        let ingress_time = self
            .coordinator
            .as_ref()
            .and_then(|coordinator| coordinator.trusted_future_time(future_clock, now_ns));
        if ingress_time.is_none() {
            if let Some(coordinator) = &self.coordinator {
                coordinator.invalidate_existing_prepare_clock();
            }
            return self.receive_inner(now_ns, None, session, datagram);
        }
        self.receive_inner(now_ns, ingress_time, session, datagram)
    }

    fn receive_inner(
        &mut self,
        now_ns: u64,
        ingress_time: Option<super::fec_negotiation::FecIngressTime>,
        session: &UnifiedGroupSession,
        datagram: &[u8],
    ) -> Result<FecHandled, AgreementError> {
        self.ingress_started = true;
        // FFCN is observed by the shared endpoint below. Ordinary control keeps
        // its existing result while independently fencing an installed round.
        if !datagram.starts_with(&super::fec_negotiation::MAGIC)
            && let (Some(ingress_time), Some(coordinator)) =
                (ingress_time, self.coordinator.as_ref())
        {
            coordinator.observe_existing_group_time(ingress_time.group_now_ns);
        }
        if datagram.starts_with(&super::fec_negotiation::MAGIC) {
            if !self.healthy() {
                return Err(AgreementError::Unavailable);
            }
            let coordinator = self.coordinator.as_mut().ok_or(AgreementError::NoAttempt)?;
            Ok(match ingress_time {
                Some(ingress_time) => self.endpoint.handle_with_fec_at_clock(
                    &mut self.channel,
                    coordinator,
                    now_ns,
                    ingress_time,
                    session,
                    datagram,
                ),
                None => self.endpoint.handle_with_fec(
                    &mut self.channel,
                    coordinator,
                    now_ns,
                    session,
                    datagram,
                ),
            })
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

    fn blank_with_config(config: ChannelConfig) -> Owner {
        Owner::boot(
            EphemeralSecretStore::fleet_control_development(),
            MemStorage::new(Limits::fleet_control_development().segment_bytes),
            config,
        )
        .unwrap()
        .0
    }

    fn token(group: &str, issuer: &str, epoch: u64) -> AuthorityToken {
        AuthorityToken {
            group_id: group.to_string(),
            issuer_id: issuer.to_string(),
            epoch,
            expires_at_ns: 1_000_000_000_000,
        }
    }

    fn fresh_group(
        owner: Owner,
    ) -> Result<FreshFleetGroup<EphemeralSecretStore, MemStorage>, FreshGroupError> {
        owner.provision_fresh_group(
            "grp",
            "coord",
            EPOCH,
            MembershipConfig::default(),
            token("grp", "coord", EPOCH),
            0,
        )
    }

    fn bind_local(
        owner: &mut Owner,
        group: &str,
        issuer: &PeerId,
        incarnation: [u8; 16],
        member: &str,
        profile: &str,
        role: ChannelRole,
    ) -> Result<(), RecoveryBindingError> {
        owner.provision_recovery_binding(group, issuer, incarnation, member, profile, role)
    }

    #[test]
    fn recovery_binding_is_durable_write_once_and_does_not_restore_authority() {
        let mut owner = blank();
        let issuer = id("coord");
        let other = id("other");
        owner
            .admit(&issuer, PeerRole::Controller, &key("coord"), Some(EPOCH), 1)
            .unwrap();
        owner
            .admit(&other, PeerRole::Controller, &key("other"), Some(EPOCH), 1)
            .unwrap();
        assert_eq!(owner.recovery_binding(), Ok(None));
        let before = owner.journal.state().clone();
        bind_local(
            &mut owner,
            "grp",
            &issuer,
            [7; 16],
            "kitchen",
            "profile-a",
            ChannelRole::LeftMono,
        )
        .unwrap();
        let expected = owner.recovery_binding().unwrap().unwrap();
        assert_eq!(
            (
                expected.group_id(),
                expected.configured_issuer(),
                expected.incarnation()
            ),
            ("grp", &issuer, &[7; 16])
        );
        assert_eq!(
            (expected.member_id(), expected.profile_id(), expected.role()),
            ("kitchen", "profile-a", ChannelRole::LeftMono)
        );
        assert_eq!(owner.journal.state().credentials, before.credentials);
        assert_eq!(owner.journal.state().marks, before.marks);
        let established = owner.journal.state().clone();
        bind_local(
            &mut owner,
            "grp",
            &issuer,
            [7; 16],
            "kitchen",
            "profile-a",
            ChannelRole::LeftMono,
        )
        .unwrap();
        assert_eq!(owner.journal.state(), &established);
        for result in [
            bind_local(
                &mut owner,
                "other",
                &issuer,
                [7; 16],
                "kitchen",
                "profile-a",
                ChannelRole::LeftMono,
            ),
            bind_local(
                &mut owner,
                "grp",
                &other,
                [7; 16],
                "kitchen",
                "profile-a",
                ChannelRole::LeftMono,
            ),
            bind_local(
                &mut owner,
                "grp",
                &issuer,
                [8; 16],
                "kitchen",
                "profile-a",
                ChannelRole::LeftMono,
            ),
            bind_local(
                &mut owner,
                "grp",
                &issuer,
                [7; 16],
                "bedroom",
                "profile-a",
                ChannelRole::LeftMono,
            ),
            bind_local(
                &mut owner,
                "grp",
                &issuer,
                [7; 16],
                "kitchen",
                "profile-b",
                ChannelRole::LeftMono,
            ),
            bind_local(
                &mut owner,
                "grp",
                &issuer,
                [7; 16],
                "kitchen",
                "profile-a",
                ChannelRole::RightMono,
            ),
        ] {
            assert_eq!(result, Err(RecoveryBindingError::Conflict));
        }
        assert_eq!(owner.journal.state(), &established);
        let (mut reopened, _) = boot(owner.into_storage());
        assert_eq!(reopened.recovery_binding(), Ok(Some(expected)));
        assert_eq!(reopened.authority().version_of(&issuer), Some(1));
        assert!(!reopened.fresh_group_is_healthy());
        assert!(!reopened.lease_is_live(&fixture_session(EPOCH), 0));
        assert_eq!(
            bind_local(
                &mut reopened,
                "grp",
                &issuer,
                [7; 16],
                "kitchen",
                "profile-a",
                ChannelRole::LeftMono
            ),
            Err(RecoveryBindingError::NotFresh)
        );
    }

    #[test]
    fn recovery_binding_bounds_roles_and_fresh_identity_consistency() {
        let issuer = id(&"i".repeat(32));
        for role in [
            ChannelRole::Stereo,
            ChannelRole::LeftMono,
            ChannelRole::RightMono,
            ChannelRole::MonoSum,
            ChannelRole::SubLfe,
        ] {
            let binding = RecoveryBinding {
                group_id: "g".repeat(64),
                configured_issuer: issuer.clone(),
                incarnation: [1; 16],
                member_id: "m".repeat(64),
                profile_id: "p".repeat(64),
                role,
            };
            let bytes = binding.encode();
            assert_eq!(bytes.len(), 246);
            assert!(bytes.len() <= Limits::fleet_control_development().records.value_max);
            assert_eq!(RecoveryBinding::decode(&bytes), Ok(binding));
        }
        let mut owner = blank();
        let peer = id("coord");
        assert_eq!(
            bind_local(
                &mut owner,
                "grp",
                &peer,
                [1; 16],
                "kitchen",
                "p",
                ChannelRole::Stereo
            ),
            Err(RecoveryBindingError::IssuerNotAdmitted)
        );
        owner
            .admit(&peer, PeerRole::Controller, &key("coord"), Some(EPOCH), 1)
            .unwrap();
        assert_eq!(
            bind_local(
                &mut owner,
                "",
                &peer,
                [1; 16],
                "kitchen",
                "p",
                ChannelRole::Stereo
            ),
            Err(RecoveryBindingError::InvalidGroup)
        );
        assert_eq!(
            bind_local(
                &mut owner,
                &"g".repeat(65),
                &peer,
                [1; 16],
                "kitchen",
                "p",
                ChannelRole::Stereo
            ),
            Err(RecoveryBindingError::InvalidGroup)
        );
        assert_eq!(
            bind_local(
                &mut owner,
                "grp",
                &peer,
                [0; 16],
                "kitchen",
                "p",
                ChannelRole::Stereo
            ),
            Err(RecoveryBindingError::InvalidIncarnation)
        );
        for invalid in ["", "A", "bad/name", &"m".repeat(65)] {
            assert_eq!(
                bind_local(
                    &mut owner,
                    "grp",
                    &peer,
                    [1; 16],
                    invalid,
                    "p",
                    ChannelRole::Stereo
                ),
                Err(RecoveryBindingError::InvalidMember)
            );
        }
        for invalid in ["", &"p".repeat(65)] {
            assert_eq!(
                bind_local(
                    &mut owner,
                    "grp",
                    &peer,
                    [1; 16],
                    "kitchen",
                    invalid,
                    ChannelRole::Stereo
                ),
                Err(RecoveryBindingError::InvalidProfile)
            );
        }
        assert_eq!(owner.recovery_binding(), Ok(None));
        bind_local(
            &mut owner,
            "grp",
            &peer,
            [1; 16],
            "kitchen",
            "p",
            ChannelRole::Stereo,
        )
        .unwrap();
        assert!(matches!(
            owner.provision_fresh_group(
                "wrong",
                "coord",
                EPOCH,
                MembershipConfig::default(),
                token("wrong", "coord", EPOCH),
                0
            ),
            Err(FreshGroupError::NotFresh)
        ));

        let mut matching = blank();
        matching
            .admit(&peer, PeerRole::Controller, &key("coord"), Some(EPOCH), 1)
            .unwrap();
        bind_local(
            &mut matching,
            "grp",
            &peer,
            [1; 16],
            "kitchen",
            "p",
            ChannelRole::Stereo,
        )
        .unwrap();
        assert!(fresh_group(matching).is_ok());
    }

    #[test]
    fn recovery_binding_maximum_fits_real_journal_and_reopens() {
        let mut owner = blank();
        let too_long = id(&"i".repeat(32));
        assert_eq!(
            owner.admit(&too_long, PeerRole::Controller, &key("max"), Some(EPOCH), 1),
            Err(CustodyError::Journal(JournalError::InvalidKey))
        );
        assert_eq!(owner.recovery_binding(), Ok(None));
        let issuer = id(&"i".repeat(29));
        owner
            .admit(&issuer, PeerRole::Controller, &key("max"), Some(EPOCH), 1)
            .unwrap();
        let group = "g".repeat(64);
        let member = "m".repeat(64);
        let profile = "p".repeat(64);
        bind_local(
            &mut owner,
            &group,
            &issuer,
            [5; 16],
            &member,
            &profile,
            ChannelRole::SubLfe,
        )
        .unwrap();
        assert_eq!(
            owner
                .journal
                .state()
                .records
                .get(RECOVERY_BINDING_KEY)
                .unwrap()
                .len(),
            243
        );
        let (reopened, _) = boot(owner.into_storage());
        let binding = reopened.recovery_binding().unwrap().unwrap();
        assert_eq!(
            (
                binding.group_id(),
                binding.member_id(),
                binding.profile_id()
            ),
            (&group[..], &member[..], &profile[..])
        );
        assert_eq!(binding.configured_issuer(), &issuer);
        assert_eq!(binding.role(), ChannelRole::SubLfe);
    }

    #[test]
    fn recovery_binding_failed_sync_reopens_old_or_new_but_never_reports_success() {
        let issuer = id("coord");
        for persists in [false, true] {
            let mut owner = blank();
            owner
                .admit(&issuer, PeerRole::Controller, &key("coord"), Some(EPOCH), 1)
                .unwrap();
            let next_sync = owner.journal.storage().ops_done() + 1;
            owner.journal.storage_mut().sync_fail_at = Some(next_sync);
            owner.journal.storage_mut().sync_fail_persists = persists;
            assert!(matches!(
                bind_local(
                    &mut owner,
                    "grp",
                    &issuer,
                    [1; 16],
                    "kitchen",
                    "p",
                    ChannelRole::Stereo
                ),
                Err(RecoveryBindingError::Storage(JournalError::Storage(_)))
            ));
            assert_eq!(
                owner.recovery_binding(),
                Err(RecoveryBindingError::Unavailable)
            );
            let mut medium = owner.into_storage();
            medium.restart();
            let (reopened, _) = boot(medium);
            let result = reopened.recovery_binding().unwrap();
            assert_eq!(result.is_some(), persists);
            if let Some(binding) = result {
                assert_eq!(binding.group_id(), "grp");
                assert_eq!(binding.member_id(), "kitchen");
            }
            assert!(!reopened.fresh_group_is_healthy());
            assert!(!reopened.lease_is_live(&fixture_session(EPOCH), 0));
        }
    }

    #[test]
    fn recovery_binding_rejects_malformed_records_without_overwriting() {
        let issuer = id("coord");
        let mut owner = blank();
        owner
            .admit(&issuer, PeerRole::Controller, &key("coord"), Some(EPOCH), 1)
            .unwrap();
        let good = RecoveryBinding {
            group_id: "grp".into(),
            configured_issuer: issuer.clone(),
            incarnation: [1; 16],
            member_id: "kitchen".into(),
            profile_id: "p".into(),
            role: ChannelRole::Stereo,
        }
        .encode();
        let mut invalids = vec![vec![], vec![2], good[..good.len() - 1].to_vec()];
        let mut trailing = good.clone();
        trailing.push(0);
        invalids.push(trailing);
        let mut bad_group = good.clone();
        bad_group[2] = 0xff;
        invalids.push(bad_group);
        let mut bad_issuer = good.clone();
        bad_issuer[6] = b'!';
        invalids.push(bad_issuer);
        let mut bad_role = good.clone();
        *bad_role.last_mut().unwrap() = 6;
        invalids.push(bad_role);
        let mut zero_inc = good.clone();
        zero_inc[11..27].fill(0);
        invalids.push(zero_inc);
        for bad in invalids {
            owner
                .journal
                .put(Namespace::Records, RECOVERY_BINDING_KEY, &bad)
                .unwrap();
            assert_eq!(
                owner.recovery_binding(),
                Err(RecoveryBindingError::Malformed)
            );
            assert_eq!(
                bind_local(
                    &mut owner,
                    "grp",
                    &issuer,
                    [1; 16],
                    "kitchen",
                    "p",
                    ChannelRole::Stereo
                ),
                Err(RecoveryBindingError::Malformed)
            );
            assert_eq!(
                owner.journal.state().records.get(RECOVERY_BINDING_KEY),
                Some(&bad)
            );
        }
    }

    #[test]
    fn recovery_binding_full_record_space_and_io_failure_stay_closed() {
        let issuer = id("coord");
        let mut full = blank();
        full.admit(&issuer, PeerRole::Controller, &key("coord"), Some(EPOCH), 1)
            .unwrap();
        for key in [b"a", b"b", b"c", b"d"] {
            full.journal.put(Namespace::Records, key, b"x").unwrap();
        }
        assert_eq!(
            bind_local(
                &mut full,
                "grp",
                &issuer,
                [1; 16],
                "kitchen",
                "p",
                ChannelRole::Stereo
            ),
            Err(RecoveryBindingError::Storage(JournalError::NamespaceFull))
        );
        assert_eq!(full.recovery_binding(), Ok(None));
        let mut owner = blank();
        owner
            .admit(&issuer, PeerRole::Controller, &key("coord"), Some(EPOCH), 1)
            .unwrap();
        let op = owner.journal.storage().ops_done();
        owner.journal.storage_mut().fail_op_at = Some(op);
        assert!(matches!(
            bind_local(
                &mut owner,
                "grp",
                &issuer,
                [1; 16],
                "kitchen",
                "p",
                ChannelRole::Stereo
            ),
            Err(RecoveryBindingError::Storage(JournalError::Storage(_)))
        ));
        assert_eq!(
            owner.recovery_binding(),
            Err(RecoveryBindingError::Unavailable)
        );
        let mut medium = owner.into_storage();
        medium.fail_op_at = None;
        let (mut reopened, _) = boot(medium);
        assert_eq!(reopened.recovery_binding(), Ok(None));
        assert_eq!(reopened.authority().version_of(&issuer), Some(1));
        assert_eq!(
            bind_local(
                &mut reopened,
                "grp",
                &issuer,
                [1; 16],
                "kitchen",
                "p",
                ChannelRole::Stereo
            ),
            Err(RecoveryBindingError::NotFresh)
        );
    }

    #[test]
    fn fresh_control_qualification_is_not_inferred_from_an_absent_restart_marker() {
        let fresh = blank();
        assert!(!fresh.fresh_group_is_healthy());
        assert!(!fresh.session_sequence_exhausted(&fixture_session(EPOCH)));
        let (fresh, membership, session, authority) = fresh_group(fresh).unwrap().into_parts();
        assert!(fresh.fresh_group_is_healthy());
        assert_eq!(
            (
                &*session.group_id,
                &*session.coordinator_id,
                session.current_epoch
            ),
            ("grp", "coord", EPOCH)
        );
        assert_eq!(session.state_revision, 0);
        assert!(session.members.is_empty());
        assert!(membership.lease_is_live(&session, &authority, 0));
        let (restarted, _) = boot(fresh.into_storage());
        assert!(!restarted.fresh_group_is_healthy());
        assert!(!restarted.session_sequence_exhausted(&fixture_session(EPOCH)));
        assert!(matches!(
            fresh_group(restarted),
            Err(FreshGroupError::NotFresh)
        ));
    }

    #[test]
    fn a_latched_storage_failure_revokes_fresh_control_qualification() {
        let (mut owner, _, _, _) = fresh_group(blank()).unwrap().into_parts();
        assert!(owner.fresh_group_is_healthy());
        owner.channel.latch_durability("test_store_failure");
        assert!(!owner.fresh_group_is_healthy());
    }

    #[test]
    fn fresh_bundle_cannot_be_provisioned_a_second_time_after_unpacking() {
        let (owner, _, mut original_session, _) = fresh_group(blank()).unwrap().into_parts();
        original_session
            .apply_command(FencedControlCommand {
                epoch: EPOCH,
                command_seq: 1,
                payload: GroupCommandPayload::SetGroupVolume {
                    volume_0_to_100: 75,
                },
            })
            .unwrap();
        assert_eq!(original_session.group_master_volume, 75);
        assert!(owner.fresh_group_is_healthy());
        assert!(matches!(fresh_group(owner), Err(FreshGroupError::NotFresh)));
    }

    #[test]
    fn fresh_bundle_rejects_exhausted_counter_and_accepts_neighbor() {
        let mut config = ChannelConfig::provisional();
        config.session_seq_base = u64::MAX;
        assert!(matches!(
            fresh_group(blank_with_config(config)),
            Err(FreshGroupError::NotFresh)
        ));
        config.session_seq_base = u64::MAX - 1;
        let (owner, _, session, _) = fresh_group(blank_with_config(config)).unwrap().into_parts();
        assert!(owner.fresh_group_is_healthy());
        assert!(!owner.session_sequence_exhausted(&session));
    }

    #[test]
    fn channel_margin_is_checked_at_provision_and_each_live_lease_query() {
        let mut config = ChannelConfig::provisional();
        config.lease_margin_ns = 100;
        let mut authority = token("grp", "coord", EPOCH);
        authority.expires_at_ns = 100;
        assert!(matches!(
            blank_with_config(config).provision_fresh_group(
                "grp",
                "coord",
                EPOCH,
                MembershipConfig::default(),
                authority.clone(),
                0,
            ),
            Err(FreshGroupError::Authority(
                MembershipError::AuthorityExpired { .. }
            ))
        ));

        authority.expires_at_ns = 101;
        let (owner, membership, session, actual) = blank_with_config(config)
            .provision_fresh_group(
                "grp",
                "coord",
                EPOCH,
                MembershipConfig::default(),
                authority,
                0,
            )
            .unwrap()
            .into_parts();
        assert!(membership.lease_is_live(&session, &actual, 0));
        assert!(owner.lease_is_live(&session, 0));
        assert!(!owner.lease_is_live(&session, 1));
        assert!(membership.lease_is_live(&session, &actual, 1));
        assert!(!owner.lease_is_live(&UnifiedGroupSession::new("other", "coord", EPOCH), 0));
        assert!(!owner.lease_is_live(&UnifiedGroupSession::new("grp", "other", EPOCH), 0));
        assert!(!owner.lease_is_live(&UnifiedGroupSession::new("grp", "coord", EPOCH + 1), 0));
        assert!(!blank().lease_is_live(&session, 0));
    }

    #[test]
    fn fresh_provisioning_rejects_invalid_identity_authority_and_used_owner() {
        assert!(matches!(
            blank().provision_fresh_group(
                "",
                "coord",
                EPOCH,
                MembershipConfig::default(),
                token("grp", "coord", EPOCH),
                0
            ),
            Err(FreshGroupError::InvalidIdentity)
        ));
        assert!(matches!(
            blank().provision_fresh_group(
                "grp",
                "coord",
                0,
                MembershipConfig::default(),
                token("grp", "coord", 0),
                0
            ),
            Err(FreshGroupError::InvalidIdentity)
        ));
        assert!(matches!(
            blank().provision_fresh_group(
                "grp",
                "coord",
                EPOCH,
                MembershipConfig::default(),
                token("wrong", "coord", EPOCH),
                0
            ),
            Err(FreshGroupError::Authority(MembershipError::WrongGroup))
        ));
        assert!(matches!(
            blank().provision_fresh_group(
                "grp",
                "coord",
                EPOCH,
                MembershipConfig::default(),
                token("grp", "wrong", EPOCH),
                0
            ),
            Err(FreshGroupError::Authority(
                MembershipError::NotConfiguredIssuer
            ))
        ));
        assert!(matches!(
            blank().provision_fresh_group(
                "grp",
                "coord",
                EPOCH,
                MembershipConfig::default(),
                token("grp", "coord", EPOCH + 1),
                0
            ),
            Err(FreshGroupError::Authority(
                MembershipError::FutureAuthority { .. }
            ))
        ));
        let mut expired = token("grp", "coord", EPOCH);
        expired.expires_at_ns = 0;
        assert!(matches!(
            blank().provision_fresh_group(
                "grp",
                "coord",
                EPOCH,
                MembershipConfig::default(),
                expired,
                0
            ),
            Err(FreshGroupError::Authority(
                MembershipError::AuthorityExpired { .. }
            ))
        ));
        let mut margin = MembershipConfig::default();
        margin.lease.clock_uncertainty_ns = 100;
        let mut short = token("grp", "coord", EPOCH);
        short.expires_at_ns = 100;
        assert!(matches!(
            blank().provision_fresh_group("grp", "coord", EPOCH, margin, short, 0),
            Err(FreshGroupError::Authority(
                MembershipError::AuthorityExpired { .. }
            ))
        ));
        let mut used = blank();
        used.step(0, &mut fixture_session(EPOCH)).unwrap();
        assert!(matches!(fresh_group(used), Err(FreshGroupError::NotFresh)));
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
    fn prior_session_agreement_cannot_be_relabelled_as_fresh_provisioning() {
        let mut owner = blank();
        let prior = session();
        let bindings = enroll(&mut owner, &prior);
        let _proposal = begin(&mut owner, &prior, bindings);
        assert!(!owner.ingress_started);
        assert!(matches!(fresh_group(owner), Err(FreshGroupError::NotFresh)));
    }

    /// Real next-epoch clock locked by probe exchanges and admitted for `start`.
    /// `local_base` permits a fresh clock on the same monotonic timeline later.
    fn typed_test_clock(
        epoch: u64,
        start: u64,
        local_base: u64,
    ) -> franken_clock::group::GroupClock {
        use franken_clock::group::{GroupClock, GroupClockConfig, ProbeResponse, StartSchedule};
        let mut clock =
            GroupClock::new(GroupClockConfig::standard().unwrap(), epoch, 7, 100).unwrap();
        for k in 1..=4_u64 {
            let t1 = local_base + k * 10_000_000;
            let request = clock.next_probe(t1);
            clock
                .on_response(
                    ProbeResponse {
                        epoch,
                        leader: 7,
                        seq: request.seq,
                        t1_echo_ns: request.t1_local_ns,
                        t2_group_ns: k * 10_000_000 + 400_000,
                        t3_group_ns: k * 10_000_000 + 450_000,
                    },
                    t1 + 850_000,
                )
                .unwrap();
        }
        clock
            .admit(
                StartSchedule {
                    epoch,
                    start_group_ns: start,
                },
                local_base + 50_000_000,
            )
            .unwrap();
        clock
    }

    struct TypedClockRig {
        owner: Owner,
        session: UnifiedGroupSession,
        prepare: Vec<u8>,
        ready: Vec<u8>,
        legacy_ack: Vec<u8>,
        target_member: String,
        clock: franken_clock::group::GroupClock,
    }

    fn typed_clock_rig() -> TypedClockRig {
        use crate::channel::fec_negotiation::{
            PrepareBinding, PrepareDescriptor, encode_prepare, encode_ready, prepare_signing_bytes,
            ready_signing_bytes,
        };
        let session = session();
        let mut owner = blank();
        // A one-token test policy exposes both admission and refusal without
        // changing the production endpoint's default burst or refill rules.
        owner.endpoint = Endpoint::with_fec_rate_limit(
            super::super::limiter::RateLimit::new(1, 10_000_000).unwrap(),
            0,
        );
        let bindings = enroll(&mut owner, &session);
        owner
            .install_lease(&session, AuthorityToken::issue(&session, u64::MAX), 0)
            .unwrap();
        let proposal = begin(&mut owner, &session, bindings.clone());
        let proposer = id("proposer");
        let proposed = wire(&owner, MessageKind::Proposal, &proposer, &proposal);
        assert_eq!(
            owner.receive(0, &session, &proposed).unwrap(),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        let target = &bindings[0];
        let ack = wire(&owner, MessageKind::Ack, &target.peer, &proposal);
        assert_eq!(
            owner.receive(10_000_000, &session, &ack).unwrap(),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        let descriptor = PrepareDescriptor::new(
            proposal,
            &target.member,
            target.peer.clone(),
            42,
            0,
            900_000_000,
            800_000_000,
            "media-key",
            1,
        )
        .unwrap();
        let binding = PrepareBinding::new(descriptor, [7; 32]);
        let proposer_version = owner.authority().version_of(&proposer).unwrap();
        let signed = prepare_signing_bytes(&binding, &proposer, proposer_version);
        let prepare = encode_prepare(
            &binding,
            &proposer,
            proposer_version,
            &compute_proof(&key("proposer"), &signed),
        )
        .unwrap();
        let peer_version = owner.authority().version_of(&target.peer).unwrap();
        let signed = ready_signing_bytes(&binding, &target.peer, peer_version);
        let ready = encode_ready(
            &binding,
            &target.peer,
            peer_version,
            &compute_proof(&key(target.peer.as_str()), &signed),
        )
        .unwrap();
        TypedClockRig {
            owner,
            session,
            prepare,
            ready,
            legacy_ack: ack,
            target_member: target.member.clone(),
            clock: typed_test_clock(EPOCH + 1, 900_000_000, 0),
        }
    }

    #[test]
    fn fleet_owner_typed_future_clock_accepts_real_admitted_prepare_and_ready() {
        use franken_clock::group::{ClockStatus, Output};
        let mut rig = typed_clock_rig();
        assert_eq!(rig.clock.status(70_000_000), ClockStatus::Locked);
        assert!(matches!(rig.clock.output(70_000_000), Output::Armed { .. }));
        assert_eq!(
            rig.owner
                .receive_with_future_clock(70_000_000, &rig.clock, &rig.session, &rig.prepare)
                .unwrap(),
            FecHandled::Fec(Ok(Ingress::Prepared))
        );
        let group_now = rig.clock.group_ns(70_000_000).unwrap();
        let token = {
            let (coordinator, authority) = rig.owner.proposal_context(&rig.session).unwrap();
            coordinator
                .validated_prepare(authority, &rig.session, &rig.target_member, group_now)
                .unwrap()
        };
        assert_eq!(
            rig.owner
                .receive_with_future_clock(80_000_000, &rig.clock, &rig.session, &rig.ready)
                .unwrap(),
            FecHandled::Fec(Ok(Ingress::Ready))
        );
        assert_eq!(
            rig.owner
                .receive_with_future_clock(90_000_000, &rig.clock, &rig.session, &rig.ready)
                .unwrap(),
            FecHandled::Fec(Ok(Ingress::Duplicate))
        );
        let (coordinator, authority) = rig.owner.proposal_context(&rig.session).unwrap();
        let group_now = rig.clock.group_ns(90_000_000).unwrap();
        assert_eq!(
            token.revalidate(coordinator, authority, &rig.session, group_now),
            Ok(())
        );
        assert_eq!(
            coordinator
                .ready_assertions(authority, &rig.session, group_now)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn fleet_owner_typed_clock_rejects_wrong_unlocked_expired_and_fences_round() {
        use crate::channel::request::ControlCommand;
        use franken_clock::group::{ClockStatus, GroupClock, GroupClockConfig};
        for case in ["wrong-epoch", "unlocked", "expired", "wrong-start"] {
            let mut rig = typed_clock_rig();
            assert_eq!(
                rig.owner
                    .receive_with_future_clock(70_000_000, &rig.clock, &rig.session, &rig.prepare)
                    .unwrap(),
                FecHandled::Fec(Ok(Ingress::Prepared))
            );
            let token = {
                let (coordinator, authority) = rig.owner.proposal_context(&rig.session).unwrap();
                coordinator
                    .validated_prepare(
                        authority,
                        &rig.session,
                        &rig.target_member,
                        rig.clock.group_ns(70_000_000).unwrap(),
                    )
                    .unwrap()
            };
            let mut bad = match case {
                "wrong-epoch" => typed_test_clock(EPOCH, 900_000_000, 0),
                "unlocked" => {
                    GroupClock::new(GroupClockConfig::standard().unwrap(), EPOCH + 1, 7, 100)
                        .unwrap()
                }
                "expired" => typed_test_clock(EPOCH + 1, 900_000_000, 0),
                "wrong-start" => typed_test_clock(EPOCH + 1, 910_000_000, 0),
                _ => unreachable!(),
            };
            let local_base = if case == "expired" { 4_000_000_000 } else { 0 };
            if case == "expired" {
                bad.set_buffer_until(Some(80_000_000));
                assert_eq!(bad.status(local_base + 80_000_000), ClockStatus::Expired);
            }
            if case == "unlocked" {
                assert_eq!(bad.status(80_000_000), ClockStatus::Unlocked);
            }
            let before = rig.owner.ingress_stats();
            assert_eq!(
                rig.owner
                    .receive_with_future_clock(
                        local_base + 80_000_000,
                        &bad,
                        &rig.session,
                        &rig.ready
                    )
                    .unwrap(),
                FecHandled::Fec(Err(FecError::Stale)),
                "{case}"
            );
            assert!(
                matches!(
                    rig.owner
                        .receive_with_future_clock(
                            local_base + 80_000_000,
                            &bad,
                            &rig.session,
                            &rig.ready
                        )
                        .unwrap(),
                    FecHandled::RateLimited { .. }
                ),
                "{case}"
            );
            let later_good =
                (local_base != 0).then(|| typed_test_clock(EPOCH + 1, 900_000_000, local_base));
            let good = later_good.as_ref().unwrap_or(&rig.clock);
            assert_eq!(
                rig.owner
                    .receive_with_future_clock(
                        local_base + 90_000_000,
                        good,
                        &rig.session,
                        &rig.ready
                    )
                    .unwrap(),
                FecHandled::Fec(Err(FecError::Stale)),
                "{case}"
            );
            let after = rig.owner.ingress_stats();
            assert_eq!(after.received, before.received + 3);
            assert_eq!(after.admitted, before.admitted + 2);
            assert_eq!(after.rate_limited, before.rate_limited + 1);
            let (coordinator, authority) = rig.owner.proposal_context(&rig.session).unwrap();
            assert_eq!(
                token.revalidate(
                    coordinator,
                    authority,
                    &rig.session,
                    good.group_ns(local_base + 90_000_000).unwrap()
                ),
                Err(FecError::Stale)
            );
            assert_eq!(
                rig.owner
                    .receive_with_future_clock(
                        local_base + 100_000_000,
                        &bad,
                        &rig.session,
                        &rig.legacy_ack
                    )
                    .unwrap(),
                FecHandled::Fec(Ok(Ingress::Duplicate)),
                "{case}"
            );
            // An invalid future clock must not disable an actual authenticated N02 command.
            let command = control_wire(
                "proposer",
                1,
                ControlCommand::SetMemberVolume {
                    member_id: "kitchen".into(),
                    volume: 60,
                },
                Some(rig.session.state_revision),
            );
            assert!(
                matches!(
                    rig.owner
                        .receive_with_future_clock(
                            local_base + 110_000_000,
                            &bad,
                            &rig.session,
                            &command
                        )
                        .unwrap(),
                    FecHandled::Control(super::super::endpoint::Handled::Request {
                        result: super::super::pipeline::SubmitResult::Queued { .. },
                        ..
                    })
                ),
                "{case}"
            );
            assert_eq!(
                rig.owner
                    .step(local_base + 110_000_000, &mut rig.session)
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(rig.session.members["kitchen"].volume_0_to_100, 60);
        }
    }

    #[test]
    fn fleet_owner_typed_clock_first_prepare_checks_the_authenticated_start() {
        use franken_clock::group::{GroupClock, GroupClockConfig};
        let mut rig = typed_clock_rig();
        let unlocked =
            GroupClock::new(GroupClockConfig::standard().unwrap(), EPOCH + 1, 7, 100).unwrap();
        assert_eq!(
            rig.owner
                .receive_with_future_clock(60_000_000, &unlocked, &rig.session, &rig.prepare)
                .unwrap(),
            FecHandled::Fec(Err(FecError::Stale))
        );
        assert_eq!(
            rig.owner
                .receive_with_future_clock(70_000_000, &rig.clock, &rig.session, &rig.prepare)
                .unwrap(),
            FecHandled::Fec(Ok(Ingress::Prepared))
        );

        let mut rig = typed_clock_rig();
        let wrong_start = typed_test_clock(EPOCH + 1, 910_000_000, 0);
        assert_eq!(
            rig.owner
                .receive_with_future_clock(70_000_000, &wrong_start, &rig.session, &rig.prepare)
                .unwrap(),
            FecHandled::Fec(Err(FecError::Stale))
        );
        {
            let (coordinator, authority) = rig.owner.proposal_context(&rig.session).unwrap();
            assert!(matches!(
                coordinator.validated_prepare(
                    authority,
                    &rig.session,
                    &rig.target_member,
                    rig.clock.group_ns(70_000_000).unwrap()
                ),
                Err(FecError::MissingAcknowledgments)
            ));
        }
        assert_eq!(
            rig.owner
                .receive_with_future_clock(80_000_000, &rig.clock, &rig.session, &rig.prepare)
                .unwrap(),
            FecHandled::Fec(Ok(Ingress::Prepared))
        );
        assert_eq!(
            rig.owner
                .receive_with_future_clock(90_000_000, &rig.clock, &rig.session, &rig.ready)
                .unwrap(),
            FecHandled::Fec(Ok(Ingress::Ready))
        );
    }

    #[test]
    fn fleet_owner_trusted_time_on_ordinary_control_fences_existing_prepare() {
        use crate::channel::fec_negotiation::{
            PrepareBinding, PrepareDescriptor, encode_prepare, prepare_signing_bytes,
        };
        let session = session();
        let mut owner = blank();
        let bindings = enroll(&mut owner, &session);
        let proposal = begin(&mut owner, &session, bindings.clone());
        let proposer = id("proposer");
        let proposed = wire(&owner, MessageKind::Proposal, &proposer, &proposal);
        assert_eq!(
            owner.receive(0, &session, &proposed).unwrap(),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        let target = &bindings[0];
        let ack = wire(&owner, MessageKind::Ack, &target.peer, &proposal);
        assert_eq!(
            owner.receive(10_000_000, &session, &ack).unwrap(),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        let descriptor = PrepareDescriptor::new(
            proposal,
            &target.member,
            target.peer.clone(),
            42,
            0,
            900_000_000,
            800_000_000,
            "media-key",
            1,
        )
        .unwrap();
        let binding = PrepareBinding::new(descriptor, [7; 32]);
        let version = owner.authority().version_of(&proposer).unwrap();
        let signed = prepare_signing_bytes(&binding, &proposer, version);
        let prepared = encode_prepare(
            &binding,
            &proposer,
            version,
            &compute_proof(&key("proposer"), &signed),
        )
        .unwrap();
        assert_eq!(
            owner
                .receive_with_group_time(20_000_000, 700_000_000, &session, &prepared)
                .unwrap(),
            FecHandled::Fec(Ok(Ingress::Prepared))
        );
        let token = {
            let (coordinator, authority) = owner.proposal_context(&session).unwrap();
            coordinator
                .validated_prepare(authority, &session, &target.member, 700_000_000)
                .unwrap()
        };
        assert!(matches!(
            owner
                .receive_with_group_time(30_000_000, 800_000_000, &session, b"not-control")
                .unwrap(),
            FecHandled::Control(super::super::endpoint::Handled::Malformed(_))
        ));
        let (coordinator, authority) = owner.proposal_context(&session).unwrap();
        assert_eq!(
            token.revalidate(coordinator, authority, &session, 750_000_000),
            Err(FecError::Stale)
        );
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
    fn failed_exhaustion_mark_cannot_qualify_restarted_fleet_owner() {
        use crate::channel::request::ControlCommand;
        let (mut owner, _, mut session, _) = fresh_group(blank()).unwrap().into_parts();
        owner
            .admit(&id("panel"), PeerRole::LocalUser, &key("panel"), None, 1)
            .unwrap();
        session.state_revision = u64::MAX;
        let stop = ControlCommand::StopGroupPlayback {
            now_ns: 1_000,
            irrevocable_dma_tail_ns: 500,
        };
        assert!(matches!(
            owner
                .receive(0, &session, &control_wire("panel", 1, stop, None))
                .unwrap(),
            FecHandled::Control(super::super::endpoint::Handled::Request {
                result: super::super::pipeline::SubmitResult::Queued { .. },
                ..
            })
        ));
        owner.journal.storage_mut().power_cut(0, false);
        let failed = owner.step(0, &mut session).unwrap_err();
        assert_eq!(failed.applied.len(), 1);
        assert!(matches!(
            failed.applied[0].outcome,
            super::super::pipeline::Outcome::Committed { revision: u64::MAX }
        ));
        assert!(session.last_group_stop().is_some());
        assert!(!owner.fresh_group_is_healthy());
        let image = owner.journal.storage().durable().to_vec();
        let restored_storage =
            MemStorage::from_image(Limits::fleet_control_development().segment_bytes, &image);
        let (restored, _) = boot(restored_storage);
        let rebuilt = fixture_session(EPOCH);
        assert!(!restored.session_sequence_exhausted(&rebuilt));
        assert!(!restored.fresh_group_is_healthy());
        assert!(matches!(
            fresh_group(restored),
            Err(FreshGroupError::NotFresh)
        ));
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
