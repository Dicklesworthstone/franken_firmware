//! Authenticated, bounded N06 capability agreement on the N02 control ingress.
//!
//! This coordinator prepares a selection only. It neither advances an epoch nor
//! changes the active media path; the owner must preflight and perform cutover.
//! Each message authenticates the full proposal and the member-set snapshot.
//! The caller must use a fresh proposal ID for each attempt, including restarts.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

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
    Prepared,
    Ready,
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

/// One targeted preparation. The slot and store generation belong to this member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareDescriptor {
    proposal: FecProposal,
    member: String,
    peer: PeerId,
    target_stream: u64,
    anchor_frame: u64,
    start_group_ns: u64,
    expires_group_ns: u64,
    key_slot: String,
    key_generation: u64,
}

impl PrepareDescriptor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal: FecProposal,
        member: &str,
        peer: PeerId,
        target_stream: u64,
        anchor_frame: u64,
        start_group_ns: u64,
        expires_group_ns: u64,
        key_slot: &str,
        key_generation: u64,
    ) -> Result<Self, FecError> {
        use crate::contracts::secret_store::SlotName;
        if member.is_empty()
            || member.len() > 64
            || key_generation == 0
            || target_stream == 0
            || SlotName::parse(key_slot).is_err()
        {
            return Err(FecError::Malformed);
        }
        let offset = u64::try_from(u128::from(anchor_frame) * 62_500 / 3)
            .map_err(|_| FecError::Malformed)?;
        if !anchor_frame.is_multiple_of(1024)
            || start_group_ns.checked_sub(offset) != Some(proposal.origin_ns)
            || expires_group_ns > start_group_ns
        {
            return Err(FecError::Conflict);
        }
        Ok(Self {
            proposal,
            member: member.to_owned(),
            peer,
            target_stream,
            anchor_frame,
            start_group_ns,
            expires_group_ns,
            key_slot: key_slot.to_owned(),
            key_generation,
        })
    }

    /// Canonical bounded context for the stream key's fixed-domain commitment.
    #[must_use]
    fn key_context_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"FFCN-v2-key-context");
        put_label(&mut out, &self.proposal.group);
        for n in [
            self.proposal.stream,
            self.proposal.current_epoch,
            self.proposal.next_epoch,
            self.proposal.origin_ns,
            self.proposal.proposal_id,
            self.proposal.membership_revision,
        ] {
            out.extend_from_slice(&n.to_be_bytes());
        }
        out.extend_from_slice(&self.proposal.membership_digest);
        put_label(&mut out, &self.member);
        put_label(&mut out, self.peer.as_str());
        out.extend_from_slice(&self.target_stream.to_be_bytes());
        for n in [
            self.anchor_frame,
            self.start_group_ns,
            self.expires_group_ns,
        ] {
            out.extend_from_slice(&n.to_be_bytes());
        }
        put_label(&mut out, &self.key_slot);
        out.extend_from_slice(&self.key_generation.to_be_bytes());
        out
    }
    #[must_use]
    pub fn commitment_context(&self) -> Vec<u8> {
        self.key_context_bytes()
    }
    /// Write without heap allocation so callers can include transient work in peak accounting.
    pub fn write_commitment_context(
        &self,
        out: &mut [u8; MAX_PREPARE_CONTEXT_BYTES],
    ) -> Result<usize, FecError> {
        let mut w = BoundedWriter::new(out);
        w.bytes(b"FFCN-v2-key-context")?;
        write_proposal(&mut w, &self.proposal)?;
        w.label(&self.member)?;
        w.label(self.peer.as_str())?;
        for value in [
            self.target_stream,
            self.anchor_frame,
            self.start_group_ns,
            self.expires_group_ns,
        ] {
            w.number(value)?;
        }
        w.label(&self.key_slot)?;
        w.number(self.key_generation)?;
        Ok(w.pos)
    }
    #[must_use]
    pub const fn proposal(&self) -> &FecProposal {
        &self.proposal
    }
    #[must_use]
    pub fn member(&self) -> &str {
        &self.member
    }
    #[must_use]
    pub const fn peer(&self) -> &PeerId {
        &self.peer
    }
    #[must_use]
    pub const fn target_stream(&self) -> u64 {
        self.target_stream
    }
    #[must_use]
    pub const fn anchor_frame(&self) -> u64 {
        self.anchor_frame
    }
    #[must_use]
    pub const fn start_group_ns(&self) -> u64 {
        self.start_group_ns
    }
    #[must_use]
    pub const fn expires_group_ns(&self) -> u64 {
        self.expires_group_ns
    }
    #[must_use]
    pub fn key_slot(&self) -> &str {
        &self.key_slot
    }
    #[must_use]
    pub const fn store_generation(&self) -> u64 {
        self.key_generation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareBinding {
    descriptor: PrepareDescriptor,
    key_commitment: [u8; 32],
}
impl PrepareBinding {
    #[must_use]
    pub const fn new(descriptor: PrepareDescriptor, key_commitment: [u8; 32]) -> Self {
        Self {
            descriptor,
            key_commitment,
        }
    }
    #[must_use]
    pub const fn descriptor(&self) -> &PrepareDescriptor {
        &self.descriptor
    }
    fn proposal(&self) -> &FecProposal {
        &self.descriptor.proposal
    }
    fn member(&self) -> &str {
        &self.descriptor.member
    }
    fn peer(&self) -> &PeerId {
        &self.descriptor.peer
    }
    fn anchor_frame(&self) -> u64 {
        self.descriptor.anchor_frame
    }
    fn start_group_ns(&self) -> u64 {
        self.descriptor.start_group_ns
    }
    fn expires_group_ns(&self) -> u64 {
        self.descriptor.expires_group_ns
    }
    fn key_slot(&self) -> &str {
        &self.descriptor.key_slot
    }
    fn key_generation(&self) -> u64 {
        self.descriptor.key_generation
    }
    #[must_use]
    pub const fn key_commitment(&self) -> &[u8; 32] {
        &self.key_commitment
    }
    fn owned_heap_bytes(&self) -> usize {
        self.descriptor.proposal.group.capacity()
            + self.descriptor.member.capacity()
            + self.descriptor.peer.owned_heap_bytes()
            + self.descriptor.key_slot.capacity()
    }
}

pub(super) const PREPARE_VERSION: u8 = 2;
pub const MAX_PREPARE_WIRE_BYTES: usize = 512;
pub const MAX_PREPARE_CONTEXT_BYTES: usize = 384;
const MAX_PREPARE_LEASE_NS: u64 = 5_000_000_000;

struct BoundedWriter<'a> {
    bytes: &'a mut [u8],
    pos: usize,
}
impl<'a> BoundedWriter<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn bytes(&mut self, value: &[u8]) -> Result<(), FecError> {
        let end = self
            .pos
            .checked_add(value.len())
            .ok_or(FecError::Malformed)?;
        self.bytes
            .get_mut(self.pos..end)
            .ok_or(FecError::Malformed)?
            .copy_from_slice(value);
        self.pos = end;
        Ok(())
    }
    fn number(&mut self, value: u64) -> Result<(), FecError> {
        self.bytes(&value.to_be_bytes())
    }
    fn label(&mut self, value: &str) -> Result<(), FecError> {
        self.bytes(&[u8::try_from(value.len()).map_err(|_| FecError::Malformed)?])?;
        self.bytes(value.as_bytes())
    }
}
fn write_proposal(w: &mut BoundedWriter<'_>, proposal: &FecProposal) -> Result<(), FecError> {
    w.label(&proposal.group)?;
    for value in [
        proposal.stream,
        proposal.current_epoch,
        proposal.next_epoch,
        proposal.origin_ns,
        proposal.proposal_id,
        proposal.membership_revision,
    ] {
        w.number(value)?;
    }
    w.bytes(&proposal.membership_digest)
}

/// Write canonical READY signing bytes directly into bounded caller-owned storage.
pub fn write_ready_signing_bytes(
    binding: &PrepareBinding,
    peer: &PeerId,
    version: u64,
    out: &mut [u8; MAX_PREPARE_WIRE_BYTES],
) -> Result<usize, FecError> {
    let mut w = BoundedWriter::new(out);
    w.bytes(&MAGIC)?;
    w.bytes(&[PREPARE_VERSION, 2])?;
    w.label(peer.as_str())?;
    w.number(version)?;
    write_proposal(&mut w, binding.proposal())?;
    w.label(PROFILE)?;
    w.label(CODING_REVISION)?;
    w.bytes(&[K, N])?;
    w.bytes(&DATAGRAM_BYTES.to_be_bytes())?;
    w.label(binding.member())?;
    w.label(binding.peer().as_str())?;
    for value in [
        binding.descriptor.target_stream,
        binding.anchor_frame(),
        binding.start_group_ns(),
        binding.expires_group_ns(),
    ] {
        w.number(value)?;
    }
    w.label(binding.key_slot())?;
    w.number(binding.key_generation())?;
    w.bytes(binding.key_commitment())?;
    Ok(w.pos)
}

/// Append a request-domain proof to already written signing bytes without allocation.
pub fn append_ready_proof(
    out: &mut [u8; MAX_PREPARE_WIRE_BYTES],
    signed_len: usize,
    proof: &[u8; PROOF_LEN],
) -> Result<usize, FecError> {
    let end = signed_len
        .checked_add(PROOF_LEN)
        .ok_or(FecError::Malformed)?;
    out.get_mut(signed_len..end)
        .ok_or(FecError::Malformed)?
        .copy_from_slice(proof);
    Ok(end)
}

fn v2_signing_bytes(binding: &PrepareBinding, peer: &PeerId, version: u64, kind: u8) -> Vec<u8> {
    let mut out = signing_bytes(MessageKind::Proposal, peer, version, binding.proposal());
    out[4] = PREPARE_VERSION;
    out[5] = kind;
    put_label(&mut out, binding.member());
    put_label(&mut out, binding.peer().as_str());
    out.extend_from_slice(&binding.descriptor.target_stream.to_be_bytes());
    for n in [
        binding.anchor_frame(),
        binding.start_group_ns(),
        binding.expires_group_ns(),
    ] {
        out.extend_from_slice(&n.to_be_bytes());
    }
    put_label(&mut out, binding.key_slot());
    out.extend_from_slice(&binding.key_generation().to_be_bytes());
    out.extend_from_slice(binding.key_commitment());
    out
}
#[must_use]
pub fn prepare_signing_bytes(binding: &PrepareBinding, peer: &PeerId, version: u64) -> Vec<u8> {
    v2_signing_bytes(binding, peer, version, 1)
}
#[must_use]
pub fn ready_signing_bytes(binding: &PrepareBinding, peer: &PeerId, version: u64) -> Vec<u8> {
    v2_signing_bytes(binding, peer, version, 2)
}
fn encode_v2(
    binding: &PrepareBinding,
    peer: &PeerId,
    version: u64,
    proof: &AuthProof,
    kind: u8,
) -> Result<Vec<u8>, FecError> {
    if proof.as_bytes().len() != PROOF_LEN {
        return Err(FecError::Malformed);
    }
    let mut wire = v2_signing_bytes(binding, peer, version, kind);
    wire.extend_from_slice(proof.as_bytes());
    if wire.len() > MAX_PREPARE_WIRE_BYTES {
        return Err(FecError::Malformed);
    }
    Ok(wire)
}
pub fn encode_prepare(
    binding: &PrepareBinding,
    peer: &PeerId,
    version: u64,
    proof: &AuthProof,
) -> Result<Vec<u8>, FecError> {
    encode_v2(binding, peer, version, proof, 1)
}
pub fn encode_ready(
    binding: &PrepareBinding,
    peer: &PeerId,
    version: u64,
    proof: &AuthProof,
) -> Result<Vec<u8>, FecError> {
    encode_v2(binding, peer, version, proof, 2)
}

struct PrepareRound {
    binding: PrepareBinding,
    proposer: Authenticated,
    ready: Option<Authenticated>,
}

/// One round's trusted group-time observations. An observed rollback or expiry
/// permanently invalidates the round, including previously issued tokens.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PrepareClock {
    floor: Option<u64>,
    invalid: bool,
}

/// Trusted local ingress context. Only the typed clock path carries an
/// independently admitted start; raw compatibility callers carry time alone.
#[derive(Clone, Copy)]
pub(super) struct FecIngressTime {
    pub(super) group_now_ns: u64,
    admitted_start_ns: Option<u64>,
}

impl FecIngressTime {
    pub(super) const fn raw(group_now_ns: u64) -> Self {
        Self {
            group_now_ns,
            admitted_start_ns: None,
        }
    }
}

/// Authenticated per-member PREPARE, not a resource or activation witness.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedFecPrepare {
    proposal: VerifiedFecProposal,
    binding: PrepareBinding,
}
impl VerifiedFecPrepare {
    #[must_use]
    pub const fn binding(&self) -> &PrepareBinding {
        &self.binding
    }
    #[must_use]
    pub fn owned_heap_bytes(&self) -> usize {
        self.proposal
            .owned_heap_bytes()
            .saturating_add(self.binding.owned_heap_bytes())
    }
    #[must_use]
    pub fn resident_bytes(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(self.owned_heap_bytes())
    }
    pub fn revalidate<A: PeerAuthority>(
        &self,
        coordinator: &FecCoordinator,
        authority: &A,
        session: &UnifiedGroupSession,
        group_now_ns: u64,
    ) -> Result<(), FecError> {
        self.proposal.revalidate(coordinator, authority, session)?;
        let round = coordinator
            .preparations
            .get(self.binding.member())
            .ok_or(FecError::Stale)?;
        let target = coordinator
            .acknowledgments
            .get(self.binding.peer())
            .ok_or(FecError::Stale)?;
        if round.binding != self.binding
            || !authority.is_current(&round.proposer)
            || !authority.is_current(target)
        {
            return Err(FecError::Stale);
        }
        coordinator.observe_group_time(group_now_ns)
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
    preparations: BTreeMap<String, PrepareRound>,
    prepare_clock: Mutex<PrepareClock>,
    prepare_timing: Option<(u64, u64, u64)>,
}

impl FecCoordinator {
    /// Derive time only from an admitted next-epoch clock, and, after the
    /// first PREPARE, from the exact common start owned by this round.
    pub(super) fn trusted_future_time(
        &self,
        clock: &franken_clock::group::GroupClock,
        now_ns: u64,
    ) -> Option<FecIngressTime> {
        use franken_clock::group::Output;
        if clock.epoch() != self.expected.next_epoch {
            return None;
        }
        let Output::Armed { starts_in_ns } = clock.output(now_ns) else {
            return None;
        };
        let group_now = clock.group_ns(now_ns)?;
        let actual_target = group_now.checked_add(starts_in_ns)?;
        let actual_start = actual_target.checked_add(clock.config().output_delay_ns)?;
        if let Some((_, start, _)) = self.prepare_timing
            && actual_start != start
        {
            return None;
        }
        Some(FecIngressTime {
            group_now_ns: group_now,
            admitted_start_ns: Some(actual_start),
        })
    }

    /// A bad trusted clock permanently fences an already-installed future
    /// round; it does not invent a round when no PREPARE has been accepted.
    pub(super) fn invalidate_existing_prepare_clock(&self) {
        if self.prepare_timing.is_some()
            && let Ok(mut clock) = self.prepare_clock.lock()
        {
            clock.invalid = true;
        }
    }

    /// Independently supplied trusted time fences only an already-installed round.
    /// Packet contents cannot create a round or select this observation.
    pub(super) fn observe_existing_group_time(&self, now: u64) {
        if self.prepare_timing.is_some() {
            let _ = self.observe_group_time(now);
        }
    }

    /// Observe caller-supplied trusted group time at a local read/use boundary.
    /// A poisoned lock fails closed, as do rollback and the common deadline.
    fn observe_group_time(&self, now: u64) -> Result<(), FecError> {
        let mut clock = self.prepare_clock.lock().map_err(|_| FecError::Stale)?;
        if clock.invalid {
            return Err(FecError::Stale);
        }
        if clock.floor.is_some_and(|floor| now < floor)
            || self
                .prepare_timing
                .is_some_and(|(_, _, expiry)| now >= expiry)
        {
            clock.invalid = true;
            return Err(FecError::Stale);
        }
        clock.floor = Some(now);
        Ok(())
    }

    /// Charge a successful authenticated ingress observation. Rejected wire does
    /// not modify the clock: only a valid insert or identical retry reaches here.
    fn accept_wire_time(&self, now: u64) -> Result<(), FecError> {
        let mut clock = self.prepare_clock.lock().map_err(|_| FecError::Stale)?;
        if clock.invalid || clock.floor.is_some_and(|floor| now < floor) {
            return Err(FecError::Stale);
        }
        clock.floor = Some(now);
        Ok(())
    }

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
            preparations: BTreeMap::new(),
            prepare_clock: Mutex::new(PrepareClock::default()),
            prepare_timing: None,
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

    /// Retrieve the actual target's authenticated PREPARE, before resource admission.
    pub fn validated_prepare<A: PeerAuthority>(
        &self,
        authority: &A,
        session: &UnifiedGroupSession,
        member: &str,
        group_now_ns: u64,
    ) -> Result<VerifiedFecPrepare, FecError> {
        let proposal = self.validated_proposal(authority, session)?;
        let binding = self
            .preparations
            .get(member)
            .ok_or(FecError::MissingAcknowledgments)?
            .binding
            .clone();
        let token = VerifiedFecPrepare { proposal, binding };
        token.revalidate(self, authority, session, group_now_ns)?;
        Ok(token)
    }

    /// Current unexpired peer assertions. These do not guarantee retained resources or activation.
    pub fn ready_assertions<A: PeerAuthority>(
        &self,
        authority: &A,
        session: &UnifiedGroupSession,
        group_now_ns: u64,
    ) -> Result<Vec<PeerId>, FecError> {
        self.current_proposal_authority(authority, session)?;
        self.observe_group_time(group_now_ns)?;
        let mut ready = Vec::new();
        for round in self.preparations.values() {
            if let Some(auth) = &round.ready {
                if group_now_ns >= round.binding.expires_group_ns()
                    || !authority.is_current(auth)
                    || !authority.is_current(&round.proposer)
                {
                    return Err(FecError::Stale);
                }
                ready.push(auth.peer.clone());
            }
        }
        Ok(ready)
    }

    pub(super) fn ingest_prepare<A: PeerAuthority>(
        &mut self,
        wire: &[u8],
        authority: &A,
        session: &UnifiedGroupSession,
        ingress_time: FecIngressTime,
    ) -> Result<Ingress, FecError> {
        let message = decode_v2(wire)?;
        let auth = authority
            .authenticate(&message.sender, &wire[..message.signed_len], &message.proof)
            .map_err(|_| FecError::Authentication)?;
        if auth.peer != message.sender || !authority.is_current(&auth) {
            return Err(FecError::Authentication);
        }
        if auth.version != message.version || auth.bound_epoch != Some(self.expected.current_epoch)
        {
            return Err(FecError::Stale);
        }
        if !message.supported {
            return Err(FecError::Unsupported);
        }
        let current = self.current_proposal_authority(authority, session)?;
        let binding = message.binding;
        let group_now_ns = ingress_time.group_now_ns;
        if group_now_ns >= binding.expires_group_ns()
            || binding.expires_group_ns().saturating_sub(group_now_ns) > MAX_PREPARE_LEASE_NS
        {
            return Err(FecError::Stale);
        }
        if binding.proposal() != &self.expected {
            return Err(FecError::Conflict);
        }
        // The clock's admitted start is trusted independently of wire bytes.
        // Check the authenticated proposal before any round/time mutation.
        if ingress_time
            .admitted_start_ns
            .is_some_and(|start| start != binding.start_group_ns())
        {
            return Err(FecError::Stale);
        }
        let timing = (
            binding.anchor_frame(),
            binding.start_group_ns(),
            binding.expires_group_ns(),
        );
        if self
            .prepare_timing
            .is_some_and(|existing| existing != timing)
        {
            return Err(FecError::Conflict);
        }
        let target = self
            .members
            .get(binding.member())
            .ok_or(FecError::Unauthorized)?;
        if target.peer != *binding.peer() {
            return Err(FecError::Unauthorized);
        }
        let capability = self
            .acknowledgments
            .get(&target.peer)
            .ok_or(FecError::MissingAcknowledgments)?;
        if capability.role != target.role || !authority.is_current(capability) {
            return Err(FecError::Authentication);
        }
        match message.kind {
            1 => {
                if message.sender != self.proposer
                    || auth.role != self.proposer_role
                    || auth != *current
                {
                    return Err(FecError::Unauthorized);
                }
                if let Some(round) = self.preparations.get(binding.member()) {
                    if round.binding != binding || round.proposer != auth {
                        return Err(FecError::Conflict);
                    }
                    self.accept_wire_time(group_now_ns)?;
                    return Ok(Ingress::Duplicate);
                }
                self.accept_wire_time(group_now_ns)?;
                self.prepare_timing = Some(timing);
                self.preparations.insert(
                    binding.member().to_owned(),
                    PrepareRound {
                        binding,
                        proposer: auth,
                        ready: None,
                    },
                );
                Ok(Ingress::Prepared)
            }
            2 => {
                if message.sender != target.peer || auth.role != target.role {
                    return Err(FecError::Unauthorized);
                }
                let round = self
                    .preparations
                    .get(binding.member())
                    .ok_or(FecError::MissingAcknowledgments)?;
                if round.binding != binding {
                    return Err(FecError::Conflict);
                }
                if !authority.is_current(&round.proposer) {
                    return Err(FecError::Authentication);
                }
                if let Some(previous) = &round.ready {
                    if *previous != auth {
                        return Err(FecError::Conflict);
                    }
                    self.accept_wire_time(group_now_ns)?;
                    return Ok(Ingress::Duplicate);
                }
                self.accept_wire_time(group_now_ns)?;
                let round = self
                    .preparations
                    .get_mut(binding.member())
                    .expect("checked above");
                round.ready = Some(auth);
                Ok(Ingress::Ready)
            }
            _ => Err(FecError::Malformed),
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

struct DecodedPrepare {
    kind: u8,
    sender: PeerId,
    version: u64,
    binding: PrepareBinding,
    signed_len: usize,
    proof: AuthProof,
    supported: bool,
}

fn decode_v2(wire: &[u8]) -> Result<DecodedPrepare, FecError> {
    if wire.len() > MAX_PREPARE_WIRE_BYTES {
        return Err(FecError::Malformed);
    }
    let mut c = Cursor {
        bytes: wire,
        pos: 0,
    };
    if c.take(4)? != MAGIC || c.byte()? != PREPARE_VERSION {
        return Err(FecError::Malformed);
    }
    let kind = c.byte()?;
    if kind != 1 && kind != 2 {
        return Err(FecError::Malformed);
    }
    let sender = PeerId::parse(c.label()?).map_err(|_| FecError::Malformed)?;
    let version = c.number()?;
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
    let member = c.label()?;
    let peer = PeerId::parse(c.label()?).map_err(|_| FecError::Malformed)?;
    let target_stream = c.number()?;
    let anchor = c.number()?;
    let start = c.number()?;
    let expires = c.number()?;
    let slot = c.label()?;
    let generation = c.number()?;
    let commitment = c.take(32)?.try_into().map_err(|_| FecError::Malformed)?;
    let signed_len = c.pos;
    let proof = AuthProof::new(c.take(PROOF_LEN)?.to_vec()).map_err(|_| FecError::Malformed)?;
    if c.pos != wire.len() {
        return Err(FecError::Malformed);
    }
    let descriptor = PrepareDescriptor::new(
        proposal,
        member,
        peer,
        target_stream,
        anchor,
        start,
        expires,
        slot,
        generation,
    )?;
    Ok(DecodedPrepare {
        kind,
        sender,
        version,
        binding: PrepareBinding::new(descriptor, commitment),
        signed_len,
        proof,
        supported,
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

    fn targeted_binding(rig: &Rig) -> PrepareBinding {
        PrepareBinding::new(
            PrepareDescriptor::new(
                rig.fec.proposal().clone(),
                "kitchen",
                id("member-s1"),
                42,
                0,
                900_000_000,
                800_000_000,
                "media-key",
                1,
            )
            .unwrap(),
            [7; 32],
        )
    }

    fn targeted_wire(binding: &PrepareBinding, name: &str, ready: bool) -> Vec<u8> {
        let peer = id(name);
        let bytes = if ready {
            ready_signing_bytes(binding, &peer, 1)
        } else {
            prepare_signing_bytes(binding, &peer, 1)
        };
        let proof = compute_proof(&test_key(name), &bytes);
        if ready {
            encode_ready(binding, &peer, 1, &proof).unwrap()
        } else {
            encode_prepare(binding, &peer, 1, &proof).unwrap()
        }
    }

    fn send_targeted(rig: &mut Rig, wire: &[u8], group_now_ns: u64) -> FecHandled {
        let now = rig.now_ns;
        rig.now_ns += 10_000_000;
        rig.endpoint.handle_with_fec_at_group(
            &mut rig.channel,
            &mut rig.fec,
            now,
            group_now_ns,
            &rig.session,
            wire,
        )
    }

    #[test]
    fn n06_prepare_ready_uses_authenticated_endpoint_and_rejects_stale() {
        let mut rig = Rig::new();
        assert_eq!(
            rig.signed(MessageKind::Proposal, "leader"),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        let no_capability = targeted_wire(&targeted_binding(&rig), "leader", false);
        assert_eq!(
            send_targeted(&mut rig, &no_capability, 700_000_000),
            FecHandled::Fec(Err(FecError::MissingAcknowledgments))
        );
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s1"),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        let before = rig.session.clone();
        let binding = targeted_binding(&rig);
        let mut context_buf = [0; MAX_PREPARE_CONTEXT_BYTES];
        let context_len = binding
            .descriptor()
            .write_commitment_context(&mut context_buf)
            .unwrap();
        assert_eq!(
            &context_buf[..context_len],
            binding.descriptor().commitment_context()
        );
        let mut ready_buf = [0; MAX_PREPARE_WIRE_BYTES];
        let ready_len =
            write_ready_signing_bytes(&binding, &id("member-s1"), 1, &mut ready_buf).unwrap();
        assert_eq!(
            &ready_buf[..ready_len],
            ready_signing_bytes(&binding, &id("member-s1"), 1)
        );
        let prepare = targeted_wire(&binding, "leader", false);
        let ready = targeted_wire(&binding, "member-s1", true);
        let mut bad = prepare.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(
            send_targeted(&mut rig, &bad, 700_000_000),
            FecHandled::Fec(Err(FecError::Authentication))
        );
        assert_eq!(
            send_targeted(&mut rig, &ready, 700_000_000),
            FecHandled::Fec(Err(FecError::MissingAcknowledgments))
        );
        assert_eq!(
            send_targeted(&mut rig, &prepare, 700_000_000),
            FecHandled::Fec(Ok(Ingress::Prepared))
        );
        let token = rig
            .fec
            .validated_prepare(
                rig.channel.authority(),
                &rig.session,
                "kitchen",
                700_000_000,
            )
            .unwrap();
        assert_eq!(token.binding(), &binding);
        assert!(token.owned_heap_bytes() > 0);
        assert_eq!(
            send_targeted(&mut rig, &prepare, 700_000_000),
            FecHandled::Fec(Ok(Ingress::Duplicate))
        );
        assert_eq!(
            send_targeted(&mut rig, &ready, 700_000_001),
            FecHandled::Fec(Ok(Ingress::Ready))
        );
        assert_eq!(
            send_targeted(&mut rig, &ready, 700_000_001),
            FecHandled::Fec(Ok(Ingress::Duplicate))
        );
        assert_eq!(
            send_targeted(&mut rig, &ready, 699_999_999),
            FecHandled::Fec(Err(FecError::Stale))
        );
        assert_eq!(
            token.revalidate(&rig.fec, rig.channel.authority(), &rig.session, 800_000_000),
            Err(FecError::Stale)
        );
        assert_eq!(
            token.revalidate(&rig.fec, rig.channel.authority(), &rig.session, 700_000_001),
            Err(FecError::Stale)
        );
        assert!(rig.channel.authority_mut().revoke(&id("leader")));
        assert_eq!(
            token.revalidate(&rig.fec, rig.channel.authority(), &rig.session, 700_000_001),
            Err(FecError::Authentication)
        );
        assert_eq!(rig.session.group_id, before.group_id);
        assert_eq!(rig.session.current_epoch, before.current_epoch);
        assert_eq!(rig.session.state_revision, before.state_revision);
        assert_eq!(rig.session.members, before.members);
    }

    #[test]
    fn n06_prepare_rejects_wrong_target_timeline_key_and_rate_limit() {
        let mut rig = Rig::new();
        assert_eq!(
            rig.signed(MessageKind::Proposal, "leader"),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s1"),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        let binding = targeted_binding(&rig);
        assert!(
            PrepareDescriptor::new(
                rig.fec.proposal().clone(),
                "kitchen",
                id("member-s1"),
                42,
                1,
                900_000_000,
                800_000_000,
                "media-key",
                1
            )
            .is_err()
        );
        assert!(
            PrepareDescriptor::new(
                rig.fec.proposal().clone(),
                "kitchen",
                id("member-s1"),
                42,
                0,
                900_000_001,
                800_000_000,
                "media-key",
                1
            )
            .is_err()
        );
        let mut wrong = binding.clone();
        wrong.descriptor.peer = id("member-s2");
        let wire = targeted_wire(&wrong, "leader", false);
        assert_eq!(
            send_targeted(&mut rig, &wire, 700_000_000),
            FecHandled::Fec(Err(FecError::Unauthorized))
        );
        let wire = targeted_wire(&binding, "stranger", false);
        assert_eq!(
            send_targeted(&mut rig, &wire, 700_000_000),
            FecHandled::Fec(Err(FecError::Unauthorized))
        );
        let wire = targeted_wire(&binding, "leader", false);
        assert_eq!(
            send_targeted(&mut rig, &wire, 700_000_000),
            FecHandled::Fec(Ok(Ingress::Prepared))
        );
        wrong = binding.clone();
        wrong.key_commitment[0] ^= 1;
        let wire = targeted_wire(&wrong, "member-s1", true);
        assert_eq!(
            send_targeted(&mut rig, &wire, 700_000_000),
            FecHandled::Fec(Err(FecError::Conflict))
        );
        wrong = binding.clone();
        wrong.descriptor.key_generation += 1;
        let wire = targeted_wire(&wrong, "member-s1", true);
        assert_eq!(
            send_targeted(&mut rig, &wire, 700_000_000),
            FecHandled::Fec(Err(FecError::Conflict))
        );
        wrong = binding.clone();
        wrong.descriptor.target_stream += 1;
        let wire = targeted_wire(&wrong, "member-s1", true);
        assert_eq!(
            send_targeted(&mut rig, &wire, 700_000_000),
            FecHandled::Fec(Err(FecError::Conflict))
        );
        wrong = binding.clone();
        wrong.descriptor.proposal.next_epoch += 1;
        let wire = targeted_wire(&wrong, "member-s1", true);
        assert_eq!(
            send_targeted(&mut rig, &wire, 700_000_000),
            FecHandled::Fec(Err(FecError::Conflict))
        );
        let ready = targeted_wire(&binding, "member-s1", true);
        rig.endpoint = Endpoint::with_fec_rate_limit(
            crate::channel::limiter::RateLimit::new(1, 1_000_000_000).unwrap(),
            rig.now_ns,
        );
        assert_eq!(
            send_targeted(&mut rig, &ready, 700_000_000),
            FecHandled::Fec(Ok(Ingress::Ready))
        );
        assert!(matches!(
            send_targeted(&mut rig, &ready, 700_000_000),
            FecHandled::RateLimited { .. }
        ));
    }

    #[test]
    fn n06_two_members_prepare_distinct_streams_and_keys_in_one_round() {
        let mut rig = Rig::new();
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
        let first = targeted_binding(&rig);
        let second = PrepareBinding::new(
            PrepareDescriptor::new(
                rig.fec.proposal().clone(),
                "den",
                id("member-s2"),
                43,
                0,
                900_000_000,
                800_000_000,
                "key-den",
                2,
            )
            .unwrap(),
            [9; 32],
        );
        let first_prepare = targeted_wire(&first, "leader", false);
        let second_prepare = targeted_wire(&second, "leader", false);
        assert_eq!(
            send_targeted(&mut rig, &first_prepare, 700_000_000),
            FecHandled::Fec(Ok(Ingress::Prepared))
        );
        let mut incompatible = second.clone();
        incompatible.descriptor.expires_group_ns -= 1;
        let incompatible_wire = targeted_wire(&incompatible, "leader", false);
        assert_eq!(
            send_targeted(&mut rig, &incompatible_wire, 700_000_000),
            FecHandled::Fec(Err(FecError::Conflict))
        );
        assert_eq!(
            send_targeted(&mut rig, &second_prepare, 700_000_000),
            FecHandled::Fec(Ok(Ingress::Prepared))
        );
        let first_ready = targeted_wire(&first, "member-s1", true);
        let second_ready = targeted_wire(&second, "member-s2", true);
        assert_eq!(
            send_targeted(&mut rig, &first_ready, 700_000_000),
            FecHandled::Fec(Ok(Ingress::Ready))
        );
        assert_eq!(
            send_targeted(&mut rig, &second_ready, 700_000_000),
            FecHandled::Fec(Ok(Ingress::Ready))
        );
        assert_eq!(
            rig.fec
                .ready_assertions(rig.channel.authority(), &rig.session, 700_000_000)
                .unwrap()
                .len(),
            2
        );
        assert!(rig.channel.authority_mut().revoke(&id("member-s2")));
        assert_eq!(
            rig.fec
                .ready_assertions(rig.channel.authority(), &rig.session, 700_000_000),
            Err(FecError::Stale)
        );
    }

    #[test]
    fn n06_authenticated_retries_preserve_binding_deadline_and_admit_other_member() {
        let mut rig = Rig::new();
        assert_eq!(
            rig.signed(MessageKind::Proposal, "leader"),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        for member in ["member-s1", "member-s2"] {
            assert_eq!(
                rig.signed(MessageKind::Ack, member),
                FecHandled::Fec(Ok(Ingress::Acknowledged))
            );
        }
        let first = targeted_binding(&rig);
        let prepare = targeted_wire(&first, "leader", false);
        let ready = targeted_wire(&first, "member-s1", true);
        assert_eq!(
            send_targeted(&mut rig, &prepare, 700_000_000),
            FecHandled::Fec(Ok(Ingress::Prepared))
        );
        let before = rig.endpoint.fec_ingress_stats();
        assert_eq!(
            send_targeted(&mut rig, &prepare, 710_000_000),
            FecHandled::Fec(Ok(Ingress::Duplicate))
        );
        let after = rig.endpoint.fec_ingress_stats();
        assert_eq!(after.received, before.received + 1);
        assert_eq!(after.admitted, before.admitted + 1);
        assert_eq!(rig.fec.preparations.len(), 1);
        assert_eq!(rig.fec.preparations["kitchen"].binding, first);
        assert_eq!(rig.fec.prepare_timing.unwrap().2, 800_000_000);
        assert_eq!(
            send_targeted(&mut rig, &ready, 720_000_000),
            FecHandled::Fec(Ok(Ingress::Ready))
        );
        assert_eq!(
            send_targeted(&mut rig, &ready, 730_000_000),
            FecHandled::Fec(Ok(Ingress::Duplicate))
        );
        assert_eq!(
            rig.fec
                .ready_assertions(rig.channel.authority(), &rig.session, 730_000_000)
                .unwrap(),
            vec![id("member-s1")]
        );
        assert_eq!(rig.fec.preparations.len(), 1);
        assert_eq!(rig.fec.prepare_timing.unwrap().2, 800_000_000);
        let before_clock = *rig.fec.prepare_clock.lock().unwrap();
        assert_eq!(before_clock.floor, Some(730_000_000));
        assert!(!before_clock.invalid);
        let mut changed = first.clone();
        changed.key_commitment[0] ^= 1;
        let changed_prepare = targeted_wire(&changed, "leader", false);
        assert_eq!(
            send_targeted(&mut rig, &changed_prepare, 740_000_000),
            FecHandled::Fec(Err(FecError::Conflict))
        );
        assert_eq!(rig.fec.preparations["kitchen"].binding, first);
        let after_conflict_clock = *rig.fec.prepare_clock.lock().unwrap();
        assert_eq!(after_conflict_clock.floor, Some(740_000_000));
        assert!(!after_conflict_clock.invalid);
        let mut corrupted = ready.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        assert_eq!(
            send_targeted(&mut rig, &corrupted, 740_000_000),
            FecHandled::Fec(Err(FecError::Authentication))
        );
        assert_eq!(*rig.fec.prepare_clock.lock().unwrap(), after_conflict_clock);
        assert_eq!(rig.fec.preparations["kitchen"].binding, first);
        let second = PrepareBinding::new(
            PrepareDescriptor::new(
                rig.fec.proposal().clone(),
                "den",
                id("member-s2"),
                43,
                0,
                900_000_000,
                800_000_000,
                "key-den",
                2,
            )
            .unwrap(),
            [9; 32],
        );
        let second_prepare = targeted_wire(&second, "leader", false);
        let second_ready = targeted_wire(&second, "member-s2", true);
        assert_eq!(
            send_targeted(&mut rig, &second_prepare, 740_000_000),
            FecHandled::Fec(Ok(Ingress::Prepared))
        );
        assert_eq!(
            send_targeted(&mut rig, &second_ready, 750_000_000),
            FecHandled::Fec(Ok(Ingress::Ready))
        );
        assert_eq!(
            rig.fec
                .ready_assertions(rig.channel.authority(), &rig.session, 750_000_000)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(rig.fec.prepare_timing.unwrap().2, 800_000_000);
    }

    #[test]
    fn n06_trusted_ingress_expiry_rollback_and_rate_limited_rollback_latch() {
        fn rig_with_ready() -> (Rig, PrepareBinding, Vec<u8>, VerifiedFecPrepare) {
            let mut rig = Rig::new();
            assert_eq!(
                rig.signed(MessageKind::Proposal, "leader"),
                FecHandled::Fec(Ok(Ingress::Proposed))
            );
            assert_eq!(
                rig.signed(MessageKind::Ack, "member-s1"),
                FecHandled::Fec(Ok(Ingress::Acknowledged))
            );
            let binding = targeted_binding(&rig);
            let prepare = targeted_wire(&binding, "leader", false);
            let ready = targeted_wire(&binding, "member-s1", true);
            assert_eq!(
                send_targeted(&mut rig, &prepare, 700_000_000),
                FecHandled::Fec(Ok(Ingress::Prepared))
            );
            assert_eq!(
                send_targeted(&mut rig, &ready, 710_000_000),
                FecHandled::Fec(Ok(Ingress::Ready))
            );
            assert_eq!(
                send_targeted(&mut rig, &ready, 720_000_000),
                FecHandled::Fec(Ok(Ingress::Duplicate))
            );
            let token = rig
                .fec
                .validated_prepare(
                    rig.channel.authority(),
                    &rig.session,
                    "kitchen",
                    720_000_000,
                )
                .unwrap();
            (rig, binding, ready, token)
        }

        // An actual expired ingress is observed before rejection. A later
        // rollback cannot revive the stored READY or previously issued token.
        let (mut rig, binding, ready, token) = rig_with_ready();
        assert_eq!(
            send_targeted(&mut rig, &ready, 800_000_000),
            FecHandled::Fec(Err(FecError::Stale))
        );
        assert_eq!(
            send_targeted(&mut rig, &ready, 750_000_000),
            FecHandled::Fec(Err(FecError::Stale))
        );
        assert_eq!(
            token.revalidate(&rig.fec, rig.channel.authority(), &rig.session, 750_000_000),
            Err(FecError::Stale)
        );
        assert_eq!(
            rig.fec
                .ready_assertions(rig.channel.authority(), &rig.session, 750_000_000),
            Err(FecError::Stale)
        );
        assert_eq!(rig.fec.preparations["kitchen"].binding, binding);
        assert_eq!(rig.fec.prepare_timing.unwrap().2, 800_000_000);

        // Malformed v2 bytes retain their parser result; the independent
        // trusted deadline observation is not lost with the rejected packet.
        let (mut rig, binding, ready, token) = rig_with_ready();
        assert_eq!(
            send_targeted(&mut rig, b"FFCN\x02", 800_000_000),
            FecHandled::Fec(Err(FecError::Malformed))
        );
        assert_eq!(
            send_targeted(&mut rig, &ready, 750_000_000),
            FecHandled::Fec(Err(FecError::Stale))
        );
        assert_eq!(
            token.revalidate(&rig.fec, rig.channel.authority(), &rig.session, 750_000_000),
            Err(FecError::Stale)
        );
        assert_eq!(rig.fec.preparations["kitchen"].binding, binding);

        // Time is independently observed even on an unparseable v1 FFCN
        // packet refused before decode by the original aggregate limiter.
        let (mut rig, binding, ready, token) = rig_with_ready();
        rig.endpoint = Endpoint::with_fec_rate_limit(
            crate::channel::limiter::RateLimit::new(1, 1_000_000_000).unwrap(),
            rig.now_ns,
        );
        assert_eq!(
            send_targeted(&mut rig, &ready, 750_000_000),
            FecHandled::Fec(Ok(Ingress::Duplicate))
        );
        assert!(matches!(
            send_targeted(&mut rig, b"FFCN\x01", 720_000_000),
            FecHandled::RateLimited { .. }
        ));
        assert_eq!(rig.endpoint.fec_ingress_stats().rate_limited, 1);
        rig.now_ns += 1_000_000_000;
        assert_eq!(
            send_targeted(&mut rig, &ready, 760_000_000),
            FecHandled::Fec(Err(FecError::Stale))
        );
        assert_eq!(
            token.revalidate(&rig.fec, rig.channel.authority(), &rig.session, 760_000_000),
            Err(FecError::Stale)
        );
        assert_eq!(rig.fec.preparations["kitchen"].binding, binding);
        assert_eq!(rig.fec.prepare_timing.unwrap().2, 800_000_000);

        // Existing v1 capability ACK semantics survive trusted-time fencing.
        let (mut rig, _, ready, token) = rig_with_ready();
        let legacy_ack = rig.wire(MessageKind::Ack, "member-s1", rig.fec.proposal());
        assert_eq!(
            send_targeted(&mut rig, &legacy_ack, 800_000_000),
            FecHandled::Fec(Ok(Ingress::Duplicate))
        );
        assert_eq!(
            send_targeted(&mut rig, &ready, 750_000_000),
            FecHandled::Fec(Err(FecError::Stale))
        );
        assert_eq!(
            token.revalidate(&rig.fec, rig.channel.authority(), &rig.session, 750_000_000),
            Err(FecError::Stale)
        );

        // Ordinary malformed control retains its result but its trusted time
        // still fences an existing round through the same endpoint API.
        let (mut rig, _, ready, token) = rig_with_ready();
        assert!(matches!(
            send_targeted(&mut rig, b"not-control", 800_000_000),
            FecHandled::Control(Handled::Malformed(_))
        ));
        assert_eq!(
            send_targeted(&mut rig, &ready, 750_000_000),
            FecHandled::Fec(Err(FecError::Stale))
        );
        assert_eq!(
            token.revalidate(&rig.fec, rig.channel.authority(), &rig.session, 750_000_000),
            Err(FecError::Stale)
        );
    }

    #[test]
    fn n06_prepare_time_observations_latch_expiry_and_in_range_rollback() {
        fn rig_with_ready() -> (Rig, VerifiedFecPrepare) {
            let mut rig = Rig::new();
            assert_eq!(
                rig.signed(MessageKind::Proposal, "leader"),
                FecHandled::Fec(Ok(Ingress::Proposed))
            );
            assert_eq!(
                rig.signed(MessageKind::Ack, "member-s1"),
                FecHandled::Fec(Ok(Ingress::Acknowledged))
            );
            let binding = targeted_binding(&rig);
            let prepare = targeted_wire(&binding, "leader", false);
            let ready = targeted_wire(&binding, "member-s1", true);
            assert_eq!(
                send_targeted(&mut rig, &prepare, 700_000_000),
                FecHandled::Fec(Ok(Ingress::Prepared))
            );
            assert_eq!(
                send_targeted(&mut rig, &ready, 700_000_000),
                FecHandled::Fec(Ok(Ingress::Ready))
            );
            let token = rig
                .fec
                .validated_prepare(
                    rig.channel.authority(),
                    &rig.session,
                    "kitchen",
                    700_000_000,
                )
                .unwrap();
            (rig, token)
        }
        let (rig, token) = rig_with_ready();
        assert_eq!(
            token.revalidate(&rig.fec, rig.channel.authority(), &rig.session, 750_000_000),
            Ok(())
        );
        assert_eq!(
            rig.fec
                .ready_assertions(rig.channel.authority(), &rig.session, 720_000_000),
            Err(FecError::Stale)
        );
        assert_eq!(
            token.revalidate(&rig.fec, rig.channel.authority(), &rig.session, 760_000_000),
            Err(FecError::Stale)
        );
        let (rig, token) = rig_with_ready();
        assert_eq!(
            rig.fec
                .ready_assertions(rig.channel.authority(), &rig.session, 750_000_000)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            token.revalidate(&rig.fec, rig.channel.authority(), &rig.session, 800_000_000),
            Err(FecError::Stale)
        );
        assert_eq!(
            rig.fec
                .ready_assertions(rig.channel.authority(), &rig.session, 750_000_001),
            Err(FecError::Stale)
        );
        assert!(matches!(
            rig.fec.validated_prepare(
                rig.channel.authority(),
                &rig.session,
                "kitchen",
                750_000_001
            ),
            Err(FecError::Stale)
        ));
    }

    #[test]
    fn n06_first_typed_prepare_mismatch_leaves_round_and_clock_unmodified() {
        use franken_clock::group::{GroupClock, GroupClockConfig, ProbeResponse, StartSchedule};
        fn admitted(start: u64) -> GroupClock {
            let mut clock =
                GroupClock::new(GroupClockConfig::standard().unwrap(), EPOCH + 1, 7, 100).unwrap();
            for k in 1..=4_u64 {
                let local = k * 10_000_000;
                let request = clock.next_probe(local);
                clock
                    .on_response(
                        ProbeResponse {
                            epoch: EPOCH + 1,
                            leader: 7,
                            seq: request.seq,
                            t1_echo_ns: request.t1_local_ns,
                            t2_group_ns: local + 400_000,
                            t3_group_ns: local + 450_000,
                        },
                        local + 850_000,
                    )
                    .unwrap();
            }
            clock
                .admit(
                    StartSchedule {
                        epoch: EPOCH + 1,
                        start_group_ns: start,
                    },
                    50_000_000,
                )
                .unwrap();
            clock
        }
        let mut rig = Rig::new();
        assert_eq!(
            rig.signed(MessageKind::Proposal, "leader"),
            FecHandled::Fec(Ok(Ingress::Proposed))
        );
        assert_eq!(
            rig.signed(MessageKind::Ack, "member-s1"),
            FecHandled::Fec(Ok(Ingress::Acknowledged))
        );
        let binding = targeted_binding(&rig);
        let prepare = targeted_wire(&binding, "leader", false);
        let ready = targeted_wire(&binding, "member-s1", true);
        let wrong = admitted(910_000_000);
        let wrong_time = rig.fec.trusted_future_time(&wrong, 70_000_000).unwrap();
        assert_eq!(
            rig.endpoint.handle_with_fec_at_clock(
                &mut rig.channel,
                &mut rig.fec,
                70_000_000,
                wrong_time,
                &rig.session,
                &prepare
            ),
            FecHandled::Fec(Err(FecError::Stale))
        );
        assert!(rig.fec.preparations.is_empty());
        assert_eq!(rig.fec.prepare_timing, None);
        assert_eq!(
            *rig.fec.prepare_clock.lock().unwrap(),
            PrepareClock::default()
        );
        let good = admitted(900_000_000);
        let good_time = rig.fec.trusted_future_time(&good, 80_000_000).unwrap();
        assert_eq!(
            rig.endpoint.handle_with_fec_at_clock(
                &mut rig.channel,
                &mut rig.fec,
                80_000_000,
                good_time,
                &rig.session,
                &prepare
            ),
            FecHandled::Fec(Ok(Ingress::Prepared))
        );
        let good_time = rig.fec.trusted_future_time(&good, 90_000_000).unwrap();
        assert_eq!(
            rig.endpoint.handle_with_fec_at_clock(
                &mut rig.channel,
                &mut rig.fec,
                90_000_000,
                good_time,
                &rig.session,
                &ready
            ),
            FecHandled::Fec(Ok(Ingress::Ready))
        );
    }

    #[test]
    fn n06_prepare_maximum_labels_fit_bounded_nonallocating_encoders() {
        let rig = Rig::new();
        let mut proposal = rig.fec.proposal().clone();
        proposal.group = "g".repeat(64);
        let peer = id(&"p".repeat(32));
        let descriptor = PrepareDescriptor::new(
            proposal,
            &"m".repeat(64),
            peer.clone(),
            42,
            0,
            900_000_000,
            800_000_000,
            &"k".repeat(32),
            1,
        )
        .unwrap();
        let mut context = [0; MAX_PREPARE_CONTEXT_BYTES];
        let length = descriptor.write_commitment_context(&mut context).unwrap();
        assert_eq!(&context[..length], descriptor.commitment_context());
        let binding = PrepareBinding::new(descriptor, [3; 32]);
        let mut wire = [0; MAX_PREPARE_WIRE_BYTES];
        let signed = write_ready_signing_bytes(&binding, &peer, 1, &mut wire).unwrap();
        assert_eq!(&wire[..signed], ready_signing_bytes(&binding, &peer, 1));
        let proof = compute_proof(&test_key("member-s1"), &wire[..signed]);
        let fixed: [u8; PROOF_LEN] = proof.as_bytes().try_into().unwrap();
        let end = append_ready_proof(&mut wire, signed, &fixed).unwrap();
        assert_eq!(
            &wire[..end],
            encode_ready(&binding, &peer, 1, &proof).unwrap()
        );
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
