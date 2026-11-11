//! Authenticated, bounded N06 capability agreement on the N02 control ingress.
//!
//! This coordinator prepares a selection only. It neither advances an epoch nor
//! changes the active media path; the owner must preflight and perform cutover.
//! Each message authenticates the full proposal and the member-set snapshot.
//! The caller must use a fresh proposal ID for each attempt, including restarts.

use std::collections::{BTreeMap, BTreeSet};

use franken_session::UnifiedGroupSession;
use sha2::{Digest, Sha256};

use super::peer::{
    AuthProof, Authenticated, ControlProfile, PROOF_LEN, PeerAuthority, PeerId, PeerRole,
};

pub const MAGIC: [u8; 4] = *b"FFCN";
const VERSION: u8 = 1;
const MAX_GROUP_BYTES: usize = 64;
const MAX_WIRE_BYTES: usize = 320;
pub const PROFILE: &str = "n06.host-hybrid.k4-r4.v1";
pub const CODING_REVISION: &str = "14032b8f2c832ee7ef1946404f5efb18162af045";
pub const K: u8 = 4;
pub const N: u8 = 8;
pub const DATAGRAM_BYTES: u16 = 1152;

/// Explicit mapping from a group member to its enrolled control identity and allowed role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberBinding {
    pub member: String,
    pub peer: PeerId,
    pub role: PeerRole,
}

/// The complete proposal authenticated by the coordinator and every member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FecProposal {
    group: String,
    stream: u64,
    current_epoch: u64,
    next_epoch: u64,
    origin_ns: u64,
    proposal_id: u64,
    membership_revision: u64,
    membership_digest: [u8; 32],
}

impl FecProposal {
    #[must_use]
    pub fn group(&self) -> &str {
        &self.group
    }
    #[must_use]
    pub const fn stream(&self) -> u64 {
        self.stream
    }
    #[must_use]
    pub const fn current_epoch(&self) -> u64 {
        self.current_epoch
    }
    #[must_use]
    pub const fn next_epoch(&self) -> u64 {
        self.next_epoch
    }
    #[must_use]
    pub const fn origin_ns(&self) -> u64 {
        self.origin_ns
    }
    #[must_use]
    pub const fn proposal_id(&self) -> u64 {
        self.proposal_id
    }
    #[must_use]
    pub const fn membership_revision(&self) -> u64 {
        self.membership_revision
    }
    #[must_use]
    pub const fn membership_digest(&self) -> &[u8; 32] {
        &self.membership_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Proposal,
    Ack,
}

/// Build canonical bytes for a peer to authenticate with `compute_proof`.
/// The proof uses the existing N02 `PeerAuthority` domain and covers the magic,
/// kind, identity, current peer admission generation, proposal, fixed profile
/// and all framing bytes. A rebind or readmission requires a fresh proof.
pub fn signing_bytes(
    kind: MessageKind,
    peer: &PeerId,
    generation: u64,
    proposal: &FecProposal,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_WIRE_BYTES);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(match kind {
        MessageKind::Proposal => 1,
        MessageKind::Ack => 2,
    });
    put_label(&mut out, peer.as_str());
    out.extend_from_slice(&generation.to_be_bytes());
    put_label(&mut out, &proposal.group);
    for value in [
        proposal.stream,
        proposal.current_epoch,
        proposal.next_epoch,
        proposal.origin_ns,
        proposal.proposal_id,
        proposal.membership_revision,
    ] {
        out.extend_from_slice(&value.to_be_bytes());
    }
    out.extend_from_slice(&proposal.membership_digest);
    put_label(&mut out, PROFILE);
    put_label(&mut out, CODING_REVISION);
    out.extend_from_slice(&[K, N]);
    out.extend_from_slice(&DATAGRAM_BYTES.to_be_bytes());
    out
}

/// Append the full N02 peer proof to canonical signing bytes.
pub fn encode(
    kind: MessageKind,
    peer: &PeerId,
    generation: u64,
    proposal: &FecProposal,
    proof: &AuthProof,
) -> Result<Vec<u8>, FecError> {
    if proof.as_bytes().len() != PROOF_LEN {
        return Err(FecError::Malformed);
    }
    let mut wire = signing_bytes(kind, peer, generation, proposal);
    wire.extend_from_slice(proof.as_bytes());
    if wire.len() > MAX_WIRE_BYTES {
        return Err(FecError::Malformed);
    }
    Ok(wire)
}

fn put_label(out: &mut Vec<u8>, value: &str) {
    // All inputs are bounded at construction or are fixed constants.
    out.push(u8::try_from(value.len()).expect("validated bounded label"));
    out.extend_from_slice(value.as_bytes());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecError {
    Malformed,
    Authentication,
    Unauthorized,
    Stale,
    Unsupported,
    Conflict,
    MissingAcknowledgments,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ingress {
    Proposed,
    Acknowledged,
    Duplicate,
}

/// An immutable member binding in an authenticated proposal.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedFecMember {
    member: Box<str>,
    peer: Box<str>,
    role: PeerRole,
}

impl VerifiedFecMember {
    #[must_use]
    pub fn member(&self) -> &str {
        &self.member
    }

    #[must_use]
    pub fn peer(&self) -> &str {
        &self.peer
    }

    #[must_use]
    pub const fn role(&self) -> PeerRole {
        self.role
    }
}

/// A proposal authenticated through the existing ingress. This does not certify
/// acknowledgments, resources, clock/start readiness or distributed activation.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedFecProposal {
    proposal: FecProposal,
    members: Box<[VerifiedFecMember]>,
    proposer: Box<str>,
    proposer_role: PeerRole,
    proposer_version: u64,
    profile: ControlProfile,
}

impl VerifiedFecProposal {
    #[must_use]
    pub const fn proposal(&self) -> &FecProposal {
        &self.proposal
    }

    #[must_use]
    pub fn members(&self) -> &[VerifiedFecMember] {
        &self.members
    }

    /// Owned allocation bytes, separate from the inline token, for overlap accounting.
    #[must_use]
    pub fn owned_heap_bytes(&self) -> usize {
        self.proposal
            .group
            .capacity()
            .saturating_add(self.proposer.len())
            .saturating_add(std::mem::size_of_val(&*self.members))
            .saturating_add(self.members.iter().fold(0usize, |sum, member| {
                sum.saturating_add(member.member.len())
                    .saturating_add(member.peer.len())
            }))
    }

    #[must_use]
    pub fn resident_bytes(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(self.owned_heap_bytes())
    }

    /// Revalidate against the currently installed attempt and current authority.
    pub fn revalidate<A: PeerAuthority>(
        &self,
        coordinator: &FecCoordinator,
        authority: &A,
        session: &UnifiedGroupSession,
    ) -> Result<(), FecError> {
        let auth = coordinator.current_proposal_authority(authority, session)?;
        if self.profile != coordinator.profile
            || self.proposal != coordinator.expected
            || self.proposer.as_ref() != auth.peer.as_str()
            || self.proposer_role != auth.role
            || self.proposer_version != auth.version
            || self.members.len() != coordinator.members.len()
            || self
                .members
                .iter()
                .zip(coordinator.members.values())
                .any(|(saved, current)| {
                    saved.member.as_ref() != current.member.as_str()
                        || saved.peer.as_ref() != current.peer.as_str()
                        || saved.role != current.role
                })
        {
            return Err(FecError::Stale);
        }
        Ok(())
    }
}

/// A selected profile backed by a verified proposal and every required peer ack.
/// Its fields cannot be fabricated by a control-path caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFecSelection {
    proposal: FecProposal,
    members: Vec<MemberBinding>,
}
impl VerifiedFecSelection {
    #[must_use]
    pub const fn proposal(&self) -> &FecProposal {
        &self.proposal
    }
    #[must_use]
    pub fn members(&self) -> &[MemberBinding] {
        &self.members
    }
    #[must_use]
    pub const fn profile(&self) -> &'static str {
        PROFILE
    }
    #[must_use]
    pub const fn coding_revision(&self) -> &'static str {
        CODING_REVISION
    }
    #[must_use]
    pub const fn k(&self) -> u8 {
        K
    }
    #[must_use]
    pub const fn n(&self) -> u8 {
        N
    }
    #[must_use]
    pub const fn datagram_bytes(&self) -> u16 {
        DATAGRAM_BYTES
    }
}

/// One bounded negotiation attempt over an immutable group snapshot.
pub struct FecCoordinator {
    profile: ControlProfile,
    expected: FecProposal,
    proposer: PeerId,
    proposer_role: PeerRole,
    members: BTreeMap<String, MemberBinding>,
    proposal_auth: Option<Authenticated>,
    acknowledgments: BTreeMap<PeerId, Authenticated>,
}

impl FecCoordinator {
    /// Bind the trusted caller's expected proposal and complete group mapping.
    /// A fresh, nonzero proposal ID is required even after a process restart.
    pub fn new(
        session: &UnifiedGroupSession,
        proposer: PeerId,
        proposer_role: PeerRole,
        bindings: Vec<MemberBinding>,
        stream: u64,
        origin_ns: u64,
        proposal_id: u64,
    ) -> Result<Self, FecError> {
        Self::new_with_profile(
            session,
            proposer,
            proposer_role,
            bindings,
            (stream, origin_ns, proposal_id),
            ControlProfile::Legacy,
        )
    }

    /// Construct a negotiation using an explicitly selected control identity budget.
    pub fn new_with_profile(
        session: &UnifiedGroupSession,
        proposer: PeerId,
        proposer_role: PeerRole,
        bindings: Vec<MemberBinding>,
        timing: (u64, u64, u64),
        profile: ControlProfile,
    ) -> Result<Self, FecError> {
        let (stream, origin_ns, proposal_id) = timing;
        if session.current_epoch == 0
            || session.group_id.is_empty()
            || session.group_id.len() > MAX_GROUP_BYTES
            || stream == 0
            || proposal_id == 0
            || bindings.is_empty()
            || bindings.len() > franken_session::MAX_GROUP_MEMBERS
            || bindings.len() > profile.max_identities()
        {
            return Err(FecError::Malformed);
        }
        let next_epoch = session
            .current_epoch
            .checked_add(1)
            .ok_or(FecError::Stale)?;
        let mut members = BTreeMap::new();
        let mut peers = BTreeSet::new();
        for binding in bindings {
            if binding.member.is_empty()
                || binding.member.len() > 64
                || !session.members.contains_key(&binding.member)
                || !peers.insert(binding.peer.clone())
                || members.insert(binding.member.clone(), binding).is_some()
            {
                return Err(FecError::Unauthorized);
            }
        }
        if members.len() != session.members.len()
            || peers.len() + usize::from(!peers.contains(&proposer)) > profile.max_identities()
        {
            return Err(FecError::Unauthorized);
        }
        let mut digest = Sha256::new();
        digest.update(b"FFCN-v1-members");
        for (member, binding) in &members {
            digest.update([member.len() as u8]);
            digest.update(member.as_bytes());
            digest.update([binding.peer.as_str().len() as u8]);
            digest.update(binding.peer.as_str().as_bytes());
            digest.update([match binding.role {
                PeerRole::Controller => 1,
                PeerRole::LocalUser => 2,
            }]);
        }
        let expected = FecProposal {
            group: session.group_id.clone(),
            stream,
            current_epoch: session.current_epoch,
            next_epoch,
            origin_ns,
            proposal_id,
            membership_revision: session.state_revision,
            membership_digest: digest.finalize().into(),
        };
        Ok(Self {
            profile,
            expected,
            proposer,
            proposer_role,
            members,
            proposal_auth: None,
            acknowledgments: BTreeMap::new(),
        })
    }

    #[must_use]
    pub const fn proposal(&self) -> &FecProposal {
        &self.expected
    }

    fn snapshot_matches(&self, session: &UnifiedGroupSession) -> bool {
        session.group_id == self.expected.group
            && session.current_epoch == self.expected.current_epoch
            && session.state_revision == self.expected.membership_revision
            && session.members.len() == self.members.len()
            && session.members.keys().eq(self.members.keys())
    }

    pub(super) fn current_proposal_authority<A: PeerAuthority>(
        &self,
        authority: &A,
        session: &UnifiedGroupSession,
    ) -> Result<&Authenticated, FecError> {
        if authority.control_profile() != self.profile {
            return Err(FecError::Unauthorized);
        }
        if !self.snapshot_matches(session) {
            return Err(FecError::Stale);
        }
        let auth = self
            .proposal_auth
            .as_ref()
            .ok_or(FecError::MissingAcknowledgments)?;
        if auth.peer != self.proposer
            || auth.role != self.proposer_role
            || auth.bound_epoch != Some(self.expected.current_epoch)
            || !authority.is_current(auth)
        {
            return Err(FecError::Authentication);
        }
        Ok(auth)
    }

    /// Handoff of an actually authenticated proposal, before member acknowledgments.
    pub fn validated_proposal<A: PeerAuthority>(
        &self,
        authority: &A,
        session: &UnifiedGroupSession,
    ) -> Result<VerifiedFecProposal, FecError> {
        let auth = self.current_proposal_authority(authority, session)?;
        Ok(VerifiedFecProposal {
            proposal: self.expected.clone(),
            members: self
                .members
                .values()
                .map(|binding| VerifiedFecMember {
                    member: binding.member.as_str().into(),
                    peer: binding.peer.as_str().into(),
                    role: binding.role,
                })
                .collect(),
            proposer: auth.peer.as_str().into(),
            proposer_role: auth.role,
            proposer_version: auth.version,
            profile: self.profile,
        })
    }

    /// Decode and authenticate after the endpoint has charged its fixed ingress allowance.
    /// Keeping this internal prevents a second public, unthrottled wire ingress path.
    pub(super) fn ingest<A: PeerAuthority>(
        &mut self,
        wire: &[u8],
        authority: &A,
        session: &UnifiedGroupSession,
    ) -> Result<Ingress, FecError> {
        if authority.control_profile() != self.profile {
            return Err(FecError::Unauthorized);
        }
        let DecodedMessage {
            kind,
            peer,
            generation,
            proposal,
            supported,
            signed_len,
            proof,
        } = decode(wire)?;
        let auth = authority
            .authenticate(&peer, &wire[..signed_len], &proof)
            .map_err(|_| FecError::Authentication)?;
        if auth.peer != peer || !authority.is_current(&auth) {
            return Err(FecError::Authentication);
        }
        if auth.version != generation {
            return Err(FecError::Stale);
        }
        if !supported {
            return Err(FecError::Unsupported);
        }
        if !self.snapshot_matches(session) {
            return Err(FecError::Stale);
        }
        if proposal != self.expected {
            return Err(FecError::Conflict);
        }
        if auth.bound_epoch != Some(self.expected.current_epoch) {
            return Err(FecError::Stale);
        }
        match kind {
            MessageKind::Proposal => {
                if peer != self.proposer || auth.role != self.proposer_role {
                    return Err(FecError::Unauthorized);
                }
                if let Some(previous) = &self.proposal_auth {
                    return if *previous == auth {
                        Ok(Ingress::Duplicate)
                    } else {
                        Err(FecError::Conflict)
                    };
                }
                self.proposal_auth = Some(auth);
                Ok(Ingress::Proposed)
            }
            MessageKind::Ack => {
                let Some(proposer) = &self.proposal_auth else {
                    return Err(FecError::MissingAcknowledgments);
                };
                if !authority.is_current(proposer)
                    || self
                        .acknowledgments
                        .values()
                        .any(|previous| !authority.is_current(previous))
                {
                    return Err(FecError::Authentication);
                }
                let Some(binding) = self.members.values().find(|binding| binding.peer == peer)
                else {
                    return Err(FecError::Unauthorized);
                };
                if binding.role != auth.role {
                    return Err(FecError::Unauthorized);
                }
                if let Some(previous) = self.acknowledgments.get(&peer) {
                    return if *previous == auth {
                        Ok(Ingress::Duplicate)
                    } else {
                        Err(FecError::Conflict)
                    };
                }
                self.acknowledgments.insert(peer, auth);
                Ok(Ingress::Acknowledged)
            }
        }
    }

    /// Recheck group and all peer admissions at the selection boundary. The
    /// caller must repeat this check immediately before its own cutover preflight.
    pub fn validated_selection<A: PeerAuthority>(
        &self,
        authority: &A,
        session: &UnifiedGroupSession,
    ) -> Result<VerifiedFecSelection, FecError> {
        if authority.control_profile() != self.profile {
            return Err(FecError::Unauthorized);
        }
        if !self.snapshot_matches(session) {
            return Err(FecError::Stale);
        }
        let Some(proposer) = &self.proposal_auth else {
            return Err(FecError::MissingAcknowledgments);
        };
        if !authority.is_current(proposer) {
            return Err(FecError::Authentication);
        }
        if self.acknowledgments.len() != self.members.len() {
            return Err(FecError::MissingAcknowledgments);
        }
        for member in self.members.values() {
            let Some(auth) = self.acknowledgments.get(&member.peer) else {
                return Err(FecError::MissingAcknowledgments);
            };
            if !authority.is_current(auth) {
                return Err(FecError::Authentication);
            }
        }
        Ok(VerifiedFecSelection {
            proposal: self.expected.clone(),
            members: self.members.values().cloned().collect(),
        })
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], FecError> {
        let end = self.pos.checked_add(count).ok_or(FecError::Malformed)?;
        let value = self.bytes.get(self.pos..end).ok_or(FecError::Malformed)?;
        self.pos = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, FecError> {
        Ok(self.take(1)?[0])
    }
    fn number(&mut self) -> Result<u64, FecError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| FecError::Malformed)?,
        ))
    }
    fn label(&mut self) -> Result<&'a str, FecError> {
        let len = usize::from(self.byte()?);
        std::str::from_utf8(self.take(len)?).map_err(|_| FecError::Malformed)
    }
}

struct DecodedMessage {
    kind: MessageKind,
    peer: PeerId,
    generation: u64,
    proposal: FecProposal,
    supported: bool,
    signed_len: usize,
    proof: AuthProof,
}

fn decode(wire: &[u8]) -> Result<DecodedMessage, FecError> {
    if wire.len() > MAX_WIRE_BYTES {
        return Err(FecError::Malformed);
    }
    let mut c = Cursor {
        bytes: wire,
        pos: 0,
    };
    if c.take(4)? != MAGIC || c.byte()? != VERSION {
        return Err(FecError::Malformed);
    }
    let kind = match c.byte()? {
        1 => MessageKind::Proposal,
        2 => MessageKind::Ack,
        _ => return Err(FecError::Malformed),
    };
    let peer = PeerId::parse(c.label()?).map_err(|_| FecError::Malformed)?;
    let generation = c.number()?;
    let group = c.label()?;
    if group.is_empty() || group.len() > MAX_GROUP_BYTES {
        return Err(FecError::Malformed);
    }
    let proposal = FecProposal {
        group: group.to_owned(),
        stream: c.number()?,
        current_epoch: c.number()?,
        next_epoch: c.number()?,
        origin_ns: c.number()?,
        proposal_id: c.number()?,
        membership_revision: c.number()?,
        membership_digest: c.take(32)?.try_into().map_err(|_| FecError::Malformed)?,
    };
    // Parse every field even if an earlier value is unsupported, so the
    // proof covers the exact complete proposal before capability decisions.
    let profile = c.label()?;
    let revision = c.label()?;
    let k = c.byte()?;
    let n = c.byte()?;
    let packet_size = c.take(2)?;
    let supported = profile == PROFILE
        && revision == CODING_REVISION
        && k == K
        && n == N
        && packet_size == DATAGRAM_BYTES.to_be_bytes();
    let signed_len = c.pos;
    let proof = AuthProof::new(c.take(PROOF_LEN)?.to_vec()).map_err(|_| FecError::Malformed)?;
    if c.pos != wire.len() {
        return Err(FecError::Malformed);
    }
    Ok(DecodedMessage {
        kind,
        peer,
        generation,
        proposal,
        supported,
        signed_len,
        proof,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::endpoint::{Endpoint, FecHandled, Handled};
    use crate::channel::peer::compute_proof;
    use crate::channel::peer::ephemeral::{EphemeralPeers, test_key};
    use crate::channel::pipeline::{ChannelConfig, ControlChannel, SubmitResult};
    use crate::channel::request::{ControlCommand, ControlRequest, RequestBody};
    use crate::channel::testkit::fixture_session;
    use crate::channel::wire::encode_request;

    const EPOCH: u64 = 10;
    fn id(value: &str) -> PeerId {
        PeerId::parse(value).unwrap()
    }

    struct Rig {
        session: UnifiedGroupSession,
        channel: ControlChannel<EphemeralPeers>,
        endpoint: Endpoint,
        fec: FecCoordinator,
        now_ns: u64,
    }

    impl Rig {
        fn new() -> Self {
            // The existing fixture has S1/S2-class synthetic board members.
            let session = fixture_session(EPOCH);
            let mut peers = EphemeralPeers::new();
            for name in ["leader", "member-s1", "member-s2", "stranger"] {
                peers
                    .admit(
                        &id(name),
                        PeerRole::Controller,
                        &test_key(name),
                        Some(EPOCH),
                        1,
                    )
                    .unwrap();
            }
            let bindings = vec![
                MemberBinding {
                    member: "kitchen".into(),
                    peer: id("member-s1"),
                    role: PeerRole::Controller,
                },
                MemberBinding {
                    member: "den".into(),
                    peer: id("member-s2"),
                    role: PeerRole::Controller,
                },
            ];
            let fec = FecCoordinator::new(
                &session,
                id("leader"),
                PeerRole::Controller,
                bindings,
                42,
                900_000_000,
                721,
            )
            .unwrap();
            Self {
                session,
                channel: ControlChannel::new(peers, ChannelConfig::provisional()).unwrap(),
                endpoint: Endpoint::new(),
                fec,
                now_ns: 0,
            }
        }
        fn wire(&self, kind: MessageKind, name: &str, proposal: &FecProposal) -> Vec<u8> {
            let peer = id(name);
            let generation = self.channel.authority().version_of(&peer).unwrap();
            let signed = signing_bytes(kind, &peer, generation, proposal);
            encode(
                kind,
                &peer,
                generation,
                proposal,
                &compute_proof(&test_key(name), &signed),
            )
            .unwrap()
        }
        fn send(&mut self, wire: &[u8]) -> FecHandled {
            // These tests isolate agreement semantics. Advance the injected clock by one
            // default refill interval; endpoint/fec_ingress_tests covers same-time floods.
            let now_ns = self.now_ns;
            self.now_ns += 10_000_000;
            self.endpoint.handle_with_fec(
                &mut self.channel,
                &mut self.fec,
                now_ns,
                &self.session,
                wire,
            )
        }
        fn signed(&mut self, kind: MessageKind, name: &str) -> FecHandled {
            let wire = self.wire(kind, name, self.fec.proposal());
            self.send(&wire)
        }
        fn select(&self) -> Result<VerifiedFecSelection, FecError> {
            self.fec
                .validated_selection(self.channel.authority(), &self.session)
        }
    }

    #[test]
    fn n06_verified_proposal_requires_authenticated_ingress_but_not_member_acks() {
        let mut rig = Rig::new();
        rig.endpoint = Endpoint::with_fec_rate_limit(
            crate::channel::limiter::RateLimit::new(1, 1_000_000_000).unwrap(),
            0,
        );
        assert_eq!(
            rig.fec
                .validated_proposal(rig.channel.authority(), &rig.session),
            Err(FecError::MissingAcknowledgments)
        );
        let mut forged = rig.wire(MessageKind::Proposal, "leader", rig.fec.proposal());
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(
            rig.send(&forged),
            FecHandled::Fec(Err(FecError::Authentication))
        );
        assert_eq!(
            rig.fec
                .validated_proposal(rig.channel.authority(), &rig.session),
            Err(FecError::MissingAcknowledgments)
        );
        assert!(matches!(
            rig.signed(MessageKind::Proposal, "leader"),
            FecHandled::RateLimited { .. }
        ));
        assert_eq!(
            rig.fec
                .validated_proposal(rig.channel.authority(), &rig.session),
            Err(FecError::MissingAcknowledgments)
        );
        rig.now_ns = 1_000_000_000;
        let before = rig.session.clone();
        assert_eq!(
            rig.signed(MessageKind::Proposal, "leader"),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        let verified = rig
            .fec
            .validated_proposal(rig.channel.authority(), &rig.session)
            .unwrap();
        assert_eq!(verified.proposal(), rig.fec.proposal());
        assert_eq!(verified.members().len(), 2);
        assert_eq!(verified.members()[0].member(), "den");
        assert_eq!(verified.members()[0].peer(), "member-s2");
        assert_eq!(verified.members()[0].role(), PeerRole::Controller);
        assert_eq!(
            verified.resident_bytes(),
            std::mem::size_of::<VerifiedFecProposal>() + verified.owned_heap_bytes()
        );
        assert!(verified.owned_heap_bytes() > 0);
        assert_eq!(
            verified.revalidate(&rig.fec, rig.channel.authority(), &rig.session),
            Ok(())
        );
        assert_eq!(rig.select(), Err(FecError::MissingAcknowledgments));
        assert_eq!(rig.session.group_id, before.group_id);
        assert_eq!(rig.session.current_epoch, before.current_epoch);
        assert_eq!(rig.session.state_revision, before.state_revision);
        assert_eq!(rig.session.members, before.members);
    }

    #[test]
    fn n06_verified_proposal_rejects_stale_session_round_profile_and_peer() {
        use crate::channel::peer::PeerDirectory;
        use crate::contracts::secret_store::EphemeralSecretStore;
        let mut rig = Rig::new();
        assert_eq!(
            rig.signed(MessageKind::Proposal, "stranger"),
            FecHandled::Fec(Err(FecError::Unauthorized))
        );
        assert_eq!(
            rig.fec
                .validated_proposal(rig.channel.authority(), &rig.session),
            Err(FecError::MissingAcknowledgments)
        );
        assert_eq!(
            rig.signed(MessageKind::Proposal, "leader"),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        let verified = rig
            .fec
            .validated_proposal(rig.channel.authority(), &rig.session)
            .unwrap();
        let mut stale = rig.session.clone();
        stale.state_revision += 1;
        assert_eq!(
            verified.revalidate(&rig.fec, rig.channel.authority(), &stale),
            Err(FecError::Stale)
        );
        let wrong_profile = PeerDirectory::with_profile(
            EphemeralSecretStore::fleet_control_development(),
            ControlProfile::FleetDevelopment,
        );
        assert_eq!(
            verified.revalidate(&rig.fec, &wrong_profile, &rig.session),
            Err(FecError::Unauthorized)
        );
        assert_eq!(
            rig.fec.validated_proposal(&wrong_profile, &rig.session),
            Err(FecError::Unauthorized)
        );
        let bindings = rig.fec.members.values().cloned().collect();
        rig.fec = FecCoordinator::new(
            &rig.session,
            id("leader"),
            PeerRole::Controller,
            bindings,
            42,
            900_000_000,
            722,
        )
        .unwrap();
        assert_eq!(
            rig.signed(MessageKind::Proposal, "leader"),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        assert_eq!(
            verified.revalidate(&rig.fec, rig.channel.authority(), &rig.session),
            Err(FecError::Stale)
        );
        let current = rig
            .fec
            .validated_proposal(rig.channel.authority(), &rig.session)
            .unwrap();
        assert!(
            rig.channel
                .authority_mut()
                .rebind(&id("leader"), Some(EPOCH))
                .is_some()
        );
        assert_eq!(
            current.revalidate(&rig.fec, rig.channel.authority(), &rig.session),
            Err(FecError::Authentication)
        );
        assert_eq!(
            rig.fec
                .validated_proposal(rig.channel.authority(), &rig.session),
            Err(FecError::Authentication)
        );

        let mut revoked = Rig::new();
        assert_eq!(
            revoked.signed(MessageKind::Proposal, "leader"),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        let token = revoked
            .fec
            .validated_proposal(revoked.channel.authority(), &revoked.session)
            .unwrap();
        assert!(revoked.channel.authority_mut().revoke(&id("leader")));
        assert_eq!(
            token.revalidate(&revoked.fec, revoked.channel.authority(), &revoked.session),
            Err(FecError::Authentication)
        );
    }

    #[test]
    fn encoded_peer_authenticated_proposal_and_all_mixed_members_select_exact_profile() {
        let mut rig = Rig::new();
        assert_eq!(rig.select(), Err(FecError::MissingAcknowledgments));
        assert_eq!(
            rig.signed(MessageKind::Proposal, "leader"),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        assert_eq!(
            rig.signed(MessageKind::Proposal, "leader"),
            FecHandled::Fec(Ok(Ingress::Duplicate))
        );
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s1"),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        assert_eq!(rig.select(), Err(FecError::MissingAcknowledgments));
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s1"),
            FecHandled::Fec(Ok(Ingress::Duplicate))
        );
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s2"),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        let selected = rig.select().unwrap();
        assert_eq!(
            (
                selected.profile(),
                selected.coding_revision(),
                selected.k(),
                selected.n(),
                selected.datagram_bytes()
            ),
            (PROFILE, CODING_REVISION, 4, 8, 1152)
        );
        assert_eq!(
            (
                selected.proposal().group(),
                selected.proposal().stream(),
                selected.proposal().current_epoch(),
                selected.proposal().next_epoch(),
                selected.proposal().origin_ns(),
                selected.proposal().proposal_id()
            ),
            ("grp", 42, 10, 11, 900_000_000, 721)
        );
        assert_eq!(selected.members().len(), 2);
        assert_eq!(
            rig.session.current_epoch, EPOCH,
            "selection does not perform cutover"
        );
    }

    #[test]
    fn fleet_control_profile_requires_real_twenty_one_member_acknowledgments() {
        use crate::channel::peer::PeerDirectory;
        use crate::contracts::secret_store::EphemeralSecretStore;
        use franken_session::{ChannelRole, FencedControlCommand, GroupCommandPayload};

        let mut session = fixture_session(EPOCH);
        let board = franken_board_profile::synthetic_test_fixture_catalog()
            .into_iter()
            .find(|profile| profile.model_number == "S5")
            .unwrap();
        for i in 2..21 {
            session
                .apply_command(FencedControlCommand {
                    epoch: EPOCH,
                    command_seq: i as u64 + 1,
                    payload: GroupCommandPayload::AdmitMember {
                        member_id: format!("member-{i:02}"),
                        board: board.clone(),
                        role: ChannelRole::Stereo,
                    },
                })
                .unwrap();
        }
        let mut directory = PeerDirectory::with_profile(
            EphemeralSecretStore::fleet_control_development(),
            ControlProfile::FleetDevelopment,
        );
        let mut bindings = Vec::new();
        for (i, member) in session.members.keys().enumerate() {
            let peer = format!("peer-{i:02}");
            directory
                .admit(
                    &id(&peer),
                    PeerRole::Controller,
                    &test_key(&peer),
                    Some(EPOCH),
                    1,
                )
                .unwrap();
            bindings.push(MemberBinding {
                member: member.clone(),
                peer: id(&peer),
                role: PeerRole::Controller,
            });
        }
        directory
            .admit(
                &id("proposer"),
                PeerRole::Controller,
                &test_key("proposer"),
                Some(EPOCH),
                1,
            )
            .unwrap();
        assert!(
            FecCoordinator::new(
                &session,
                id("proposer"),
                PeerRole::Controller,
                bindings.clone(),
                42,
                900_000_000,
                721
            )
            .is_err()
        );
        let mut coordinator = FecCoordinator::new_with_profile(
            &session,
            id("proposer"),
            PeerRole::Controller,
            bindings.clone(),
            (42, 900_000_000, 721),
            ControlProfile::FleetDevelopment,
        )
        .unwrap();
        let mut channel = ControlChannel::new(directory, ChannelConfig::provisional()).unwrap();
        let mut endpoint = Endpoint::new();
        let mut now = 0;
        for (index, name) in std::iter::once("proposer".to_string())
            .chain(bindings.iter().map(|b| b.peer.as_str().to_string()))
            .enumerate()
        {
            let kind = if index == 0 {
                MessageKind::Proposal
            } else {
                MessageKind::Ack
            };
            let peer = id(&name);
            let signed = signing_bytes(kind, &peer, 1, coordinator.proposal());
            let wire = encode(
                kind,
                &peer,
                1,
                coordinator.proposal(),
                &compute_proof(&test_key(&name), &signed),
            )
            .unwrap();
            if index == 21 {
                assert_eq!(
                    coordinator.validated_selection(channel.authority(), &session),
                    Err(FecError::MissingAcknowledgments)
                );
                let mut wrong = wire.clone();
                *wrong.last_mut().unwrap() ^= 1;
                assert_eq!(
                    endpoint.handle_with_fec(&mut channel, &mut coordinator, now, &session, &wrong),
                    FecHandled::Fec(Err(FecError::Authentication))
                );
                now += 10_000_000;
            }
            assert_eq!(
                endpoint.handle_with_fec(&mut channel, &mut coordinator, now, &session, &wire),
                FecHandled::Fec(Ok(if index == 0 {
                    Ingress::Proposed
                } else {
                    Ingress::Acknowledged
                }))
            );
            now += 10_000_000;
        }
        assert_eq!(
            coordinator
                .validated_selection(channel.authority(), &session)
                .unwrap()
                .members()
                .len(),
            21
        );
    }

    #[test]
    fn fleet_control_profile_accepts_32_bindings_and_separate_proposer_only() {
        use franken_session::{ChannelRole, FencedControlCommand, GroupCommandPayload};
        let mut session = fixture_session(EPOCH);
        let board = franken_board_profile::synthetic_test_fixture_catalog()
            .into_iter()
            .find(|profile| profile.model_number == "S5")
            .unwrap();
        for i in 2..32 {
            session
                .apply_command(FencedControlCommand {
                    epoch: EPOCH,
                    command_seq: i as u64 + 1,
                    payload: GroupCommandPayload::AdmitMember {
                        member_id: format!("member-{i:02}"),
                        board: board.clone(),
                        role: ChannelRole::Stereo,
                    },
                })
                .unwrap();
        }
        let bindings: Vec<_> = session
            .members
            .keys()
            .enumerate()
            .map(|(i, member)| MemberBinding {
                member: member.clone(),
                peer: id(&format!("peer-{i:02}")),
                role: PeerRole::Controller,
            })
            .collect();
        assert!(
            FecCoordinator::new_with_profile(
                &session,
                id("proposer"),
                PeerRole::Controller,
                bindings.clone(),
                (42, 900_000_000, 721),
                ControlProfile::FleetDevelopment
            )
            .is_ok()
        );
        assert!(
            FecCoordinator::new(
                &session,
                id("proposer"),
                PeerRole::Controller,
                bindings.clone(),
                42,
                900_000_000,
                721
            )
            .is_err()
        );
        let mut duplicate = bindings;
        duplicate[31].peer = duplicate[0].peer.clone();
        assert!(matches!(
            FecCoordinator::new_with_profile(
                &session,
                id("proposer"),
                PeerRole::Controller,
                duplicate,
                (42, 900_000_000, 721),
                ControlProfile::FleetDevelopment
            ),
            Err(FecError::Unauthorized)
        ));
        session
            .apply_command(FencedControlCommand {
                epoch: EPOCH,
                command_seq: 33,
                payload: GroupCommandPayload::AdmitMember {
                    member_id: "extra".into(),
                    board,
                    role: ChannelRole::Stereo,
                },
            })
            .unwrap();
        let too_many: Vec<_> = session
            .members
            .keys()
            .enumerate()
            .map(|(i, member)| MemberBinding {
                member: member.clone(),
                peer: id(&format!("peer-{i:02}")),
                role: PeerRole::Controller,
            })
            .collect();
        assert!(matches!(
            FecCoordinator::new_with_profile(
                &session,
                id("proposer"),
                PeerRole::Controller,
                too_many,
                (42, 900_000_000, 721),
                ControlProfile::FleetDevelopment
            ),
            Err(FecError::Malformed)
        ));
    }

    #[test]
    fn bad_proofs_unknown_role_malformed_and_conflicts_never_count_as_acks() {
        let mut rig = Rig::new();
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s1"),
            FecHandled::Fec(Err(FecError::MissingAcknowledgments))
        );
        assert_eq!(
            rig.signed(MessageKind::Proposal, "stranger"),
            FecHandled::Fec(Err(FecError::Unauthorized))
        );
        assert_eq!(
            rig.signed(MessageKind::Proposal, "leader"),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        let mut forged = rig.wire(MessageKind::Ack, "member-s1", rig.fec.proposal());
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert_eq!(
            rig.send(&forged),
            FecHandled::Fec(Err(FecError::Authentication))
        );
        assert_eq!(
            rig.signed(MessageKind::Ack, "stranger"),
            FecHandled::Fec(Err(FecError::Unauthorized))
        );
        let mut wrong = rig.fec.proposal().clone();
        wrong.next_epoch += 1;
        let wire = rig.wire(MessageKind::Ack, "member-s1", &wrong);
        assert_eq!(rig.send(&wire), FecHandled::Fec(Err(FecError::Conflict)));
        let mut unsupported = rig.wire(MessageKind::Ack, "member-s1", rig.fec.proposal());
        let position = unsupported
            .windows(PROFILE.len())
            .position(|part| part == PROFILE.as_bytes())
            .unwrap();
        unsupported[position] ^= 1;
        let signed_len = unsupported.len() - PROOF_LEN;
        let proof = compute_proof(&test_key("member-s1"), &unsupported[..signed_len]);
        unsupported[signed_len..].copy_from_slice(proof.as_bytes());
        assert_eq!(
            rig.send(&unsupported),
            FecHandled::Fec(Err(FecError::Unsupported))
        );
        let good = rig.wire(MessageKind::Ack, "member-s1", rig.fec.proposal());
        assert_eq!(
            rig.send(&good[..good.len() - 1]),
            FecHandled::Fec(Err(FecError::Malformed))
        );
        assert_eq!(rig.select(), Err(FecError::MissingAcknowledgments));
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s1"),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s2"),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        assert!(
            rig.select().is_ok(),
            "valid peers still succeed after rejected attempts"
        );
    }

    #[test]
    fn stale_membership_rebind_and_revocation_invalidate_selection_without_cutover() {
        let mut rig = Rig::new();
        rig.signed(MessageKind::Proposal, "leader");
        rig.signed(MessageKind::Ack, "member-s1");
        rig.signed(MessageKind::Ack, "member-s2");
        assert!(rig.select().is_ok());
        rig.session.state_revision += 1;
        assert_eq!(rig.select(), Err(FecError::Stale));
        rig.session.state_revision -= 1;
        assert!(rig.select().is_ok());
        assert!(
            rig.channel
                .authority_mut()
                .rebind(&id("member-s1"), Some(EPOCH))
                .is_some()
        );
        assert_eq!(rig.select(), Err(FecError::Authentication));
        assert_eq!(rig.session.current_epoch, EPOCH);

        let mut rig = Rig::new();
        rig.signed(MessageKind::Proposal, "leader");
        rig.signed(MessageKind::Ack, "member-s1");
        rig.signed(MessageKind::Ack, "member-s2");
        let held_ack = rig.wire(MessageKind::Ack, "member-s2", rig.fec.proposal());
        assert!(rig.select().is_ok());
        assert!(rig.channel.authority_mut().revoke(&id("member-s2")));
        assert_eq!(rig.select(), Err(FecError::Authentication));
        assert_eq!(
            rig.send(&held_ack),
            FecHandled::Fec(Err(FecError::Authentication))
        );
        assert_eq!(rig.select(), Err(FecError::Authentication));
        assert_eq!(rig.session.current_epoch, EPOCH);

        // Re-admission uses a newer generation: the held proof remains stale,
        // while a new round with fresh proofs can still select the profile.
        rig.channel
            .authority_mut()
            .admit(
                &id("member-s2"),
                PeerRole::Controller,
                &test_key("member-s2"),
                Some(EPOCH),
                2,
            )
            .unwrap();
        assert_eq!(rig.send(&held_ack), FecHandled::Fec(Err(FecError::Stale)));
        assert_eq!(rig.select(), Err(FecError::Authentication));
        let bindings = rig.fec.members.values().cloned().collect();
        rig.fec = FecCoordinator::new(
            &rig.session,
            id("leader"),
            PeerRole::Controller,
            bindings,
            42,
            900_000_000,
            722,
        )
        .unwrap();
        assert_eq!(
            rig.signed(MessageKind::Proposal, "leader"),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s1"),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s2"),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        assert!(rig.select().is_ok());
        assert_eq!(rig.session.current_epoch, EPOCH);
    }

    #[test]
    fn ordinary_n02_control_is_still_dispatched_when_fec_is_missing() {
        let mut rig = Rig::new();
        let body = RequestBody::new(
            id("leader"),
            1,
            EPOCH,
            Some(rig.session.state_revision),
            ControlCommand::SetGroupVolume { volume: 42 },
        )
        .unwrap();
        let proof = compute_proof(&test_key("leader"), &body.signing_bytes());
        let wire = encode_request(&ControlRequest::new(body, proof)).unwrap();
        assert!(matches!(
            rig.send(&wire),
            FecHandled::Control(Handled::Request {
                result: SubmitResult::Queued { .. },
                ..
            })
        ));
        assert_eq!(rig.select(), Err(FecError::MissingAcknowledgments));
        assert_eq!(rig.session.current_epoch, EPOCH);
    }

    #[test]
    fn old_round_ack_wrong_epoch_and_wrong_role_are_refused_with_positive_control() {
        let mut rig = Rig::new();
        assert_eq!(
            rig.signed(MessageKind::Proposal, "leader"),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        let mut old = rig.fec.proposal().clone();
        old.proposal_id -= 1;
        let old_wire = rig.wire(MessageKind::Ack, "member-s1", &old);
        assert_eq!(
            rig.send(&old_wire),
            FecHandled::Fec(Err(FecError::Conflict))
        );
        rig.channel
            .authority_mut()
            .rebind(&id("member-s1"), Some(EPOCH + 1))
            .unwrap();
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s1"),
            FecHandled::Fec(Err(FecError::Stale))
        );
        rig.channel
            .authority_mut()
            .rebind(&id("member-s1"), Some(EPOCH))
            .unwrap();
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s1"),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        assert!(rig.channel.authority_mut().revoke(&id("member-s2")));
        rig.channel
            .authority_mut()
            .admit(
                &id("member-s2"),
                PeerRole::LocalUser,
                &test_key("member-s2"),
                Some(EPOCH),
                2,
            )
            .unwrap();
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s2"),
            FecHandled::Fec(Err(FecError::Unauthorized))
        );
        assert!(rig.channel.authority_mut().revoke(&id("member-s2")));
        rig.channel
            .authority_mut()
            .admit(
                &id("member-s2"),
                PeerRole::Controller,
                &test_key("member-s2"),
                Some(EPOCH),
                3,
            )
            .unwrap();
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s2"),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        assert!(rig.select().is_ok());
    }

    #[test]
    fn delayed_pre_rebind_proposer_proof_is_stale_and_new_generation_succeeds() {
        let mut rig = Rig::new();
        let held = rig.wire(MessageKind::Proposal, "leader", rig.fec.proposal());
        assert_eq!(
            rig.channel
                .authority_mut()
                .rebind(&id("leader"), Some(EPOCH)),
            Some(2)
        );
        assert_eq!(rig.send(&held), FecHandled::Fec(Err(FecError::Stale)));
        let mut forged_generation = held.clone();
        let generation_end = 7 + "leader".len() + 7;
        forged_generation[generation_end] ^= 3; // 1 -> 2, retaining the old proof
        assert_eq!(
            rig.send(&forged_generation),
            FecHandled::Fec(Err(FecError::Authentication))
        );
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s1"),
            FecHandled::Fec(Err(FecError::MissingAcknowledgments))
        );
        assert_eq!(rig.select(), Err(FecError::MissingAcknowledgments));
        assert_eq!(
            rig.signed(MessageKind::Proposal, "leader"),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s1"),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s2"),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        assert!(rig.select().is_ok());
    }

    #[test]
    fn delayed_pre_rebind_member_ack_is_stale_and_new_generation_succeeds() {
        let mut rig = Rig::new();
        assert_eq!(
            rig.signed(MessageKind::Proposal, "leader"),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        let held = rig.wire(MessageKind::Ack, "member-s1", rig.fec.proposal());
        assert_eq!(
            rig.channel
                .authority_mut()
                .rebind(&id("member-s1"), Some(EPOCH)),
            Some(2)
        );
        assert_eq!(rig.send(&held), FecHandled::Fec(Err(FecError::Stale)));
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s2"),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        assert_eq!(rig.select(), Err(FecError::MissingAcknowledgments));
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s1"),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        assert!(rig.select().is_ok());
    }

    #[test]
    fn altered_tuple_wrong_group_and_every_truncation_fail_without_spending_a_member() {
        let mut rig = Rig::new();
        rig.signed(MessageKind::Proposal, "leader");
        let mut other_group = rig.fec.proposal().clone();
        other_group.group = "other".into();
        let wire = rig.wire(MessageKind::Ack, "member-s1", &other_group);
        assert_eq!(rig.send(&wire), FecHandled::Fec(Err(FecError::Conflict)));
        for changed in 0..5 {
            let mut proposal = rig.fec.proposal().clone();
            match changed {
                0 => proposal.stream += 1,
                1 => proposal.origin_ns += 1,
                2 => proposal.membership_revision += 1,
                3 => proposal.membership_digest[0] ^= 1,
                _ => proposal.current_epoch += 1,
            }
            let wire = rig.wire(MessageKind::Ack, "member-s1", &proposal);
            assert_eq!(rig.send(&wire), FecHandled::Fec(Err(FecError::Conflict)));
        }
        let original = rig.wire(MessageKind::Ack, "member-s1", rig.fec.proposal());
        for end in 4..original.len() {
            assert!(
                !matches!(rig.send(&original[..end]), FecHandled::Fec(Ok(_))),
                "truncated at {end}"
            );
        }
        let mut longer = original.clone();
        longer.push(0);
        assert_eq!(rig.send(&longer), FecHandled::Fec(Err(FecError::Malformed)));
        for offset_from_tag in [4, 3, 2, 1] {
            let mut wire = original.clone();
            let signed_len = wire.len() - PROOF_LEN;
            wire[signed_len - offset_from_tag] ^= 1;
            let proof = compute_proof(&test_key("member-s1"), &wire[..signed_len]);
            wire[signed_len..].copy_from_slice(proof.as_bytes());
            assert_eq!(rig.send(&wire), FecHandled::Fec(Err(FecError::Unsupported)));
        }
        let mut wrong_revision = original.clone();
        let pos = wrong_revision
            .windows(CODING_REVISION.len())
            .position(|part| part == CODING_REVISION.as_bytes())
            .unwrap();
        wrong_revision[pos] ^= 1;
        let signed_len = wrong_revision.len() - PROOF_LEN;
        let proof = compute_proof(&test_key("member-s1"), &wrong_revision[..signed_len]);
        wrong_revision[signed_len..].copy_from_slice(proof.as_bytes());
        assert_eq!(
            rig.send(&wrong_revision),
            FecHandled::Fec(Err(FecError::Unsupported))
        );
        assert_eq!(rig.select(), Err(FecError::MissingAcknowledgments));
        assert_eq!(
            rig.send(&original),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s2"),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        assert!(rig.select().is_ok());
    }
}
