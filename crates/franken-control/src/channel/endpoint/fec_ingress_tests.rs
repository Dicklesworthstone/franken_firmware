//! Actual HMAC ingress and channel consumers; synthetic clock/network, not board qualification.

use std::cell::Cell;

use franken_session::{AuthorityToken, MemberLifecycleState, UnifiedGroupSession};

use super::*;
use crate::channel::fec_negotiation::{
    FecCoordinator, FecError, FecProposal, Ingress, MemberBinding, MessageKind, encode,
    signing_bytes,
};
use crate::channel::peer::ephemeral::{EphemeralPeers, test_key};
use crate::channel::peer::{
    AuthFailure, AuthProof, Authenticated, PeerId, PeerRole, compute_proof,
};
use crate::channel::pipeline::{ChannelConfig, Outcome, SubmitResult};
use crate::channel::request::{ControlCommand, ControlRequest, Lane, RequestBody};
use crate::channel::testkit::fixture_session;
use crate::channel::wire::encode_request;

const EPOCH: u64 = 10;
const MS: u64 = 1_000_000;

fn id(name: &str) -> PeerId {
    PeerId::parse(name).unwrap()
}

/// Count calls while delegating every proof, freshness and reply to the actual HMAC authority.
struct CountedAuthority {
    peers: EphemeralPeers,
    checks: Cell<u64>,
}

impl PeerAuthority for CountedAuthority {
    fn authenticate(
        &self,
        peer: &PeerId,
        message: &[u8],
        proof: &AuthProof,
    ) -> Result<Authenticated, AuthFailure> {
        self.checks.set(self.checks.get() + 1);
        self.peers.authenticate(peer, message, proof)
    }

    fn is_current(&self, auth: &Authenticated) -> bool {
        self.peers.is_current(auth)
    }
}

impl ReplySigner for CountedAuthority {
    fn sign_reply(&self, peer: &PeerId, message: &[u8]) -> Option<AuthProof> {
        self.peers.sign_reply(peer, message)
    }
}

struct Rig {
    session: UnifiedGroupSession,
    channel: ControlChannel<CountedAuthority>,
    endpoint: Endpoint,
    fec: FecCoordinator,
}

impl Rig {
    fn new(burst: u32, interval_ns: u64, start_ns: u64) -> Self {
        let session = fixture_session(EPOCH);
        let mut peers = EphemeralPeers::new();
        for name in ["leader", "member-s1", "member-s2"] {
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
        peers
            .admit(
                &id("panel"),
                PeerRole::LocalUser,
                &test_key("panel"),
                None,
                1,
            )
            .unwrap();
        let mut channel = ControlChannel::new(
            CountedAuthority {
                peers,
                checks: Cell::new(0),
            },
            ChannelConfig::provisional(),
        )
        .unwrap();
        channel
            .install_lease(&session, AuthorityToken::issue(&session, 1_000_000 * MS), 0)
            .unwrap();
        let fec = Self::coordinator(&session, 721);
        Self {
            session,
            channel,
            endpoint: Endpoint::with_fec_rate_limit(
                RateLimit::new(burst, interval_ns).unwrap(),
                start_ns,
            ),
            fec,
        }
    }

    fn coordinator(session: &UnifiedGroupSession, proposal_id: u64) -> FecCoordinator {
        FecCoordinator::new(
            session,
            id("leader"),
            PeerRole::Controller,
            vec![
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
            ],
            42,
            900_000_000,
            proposal_id,
        )
        .unwrap()
    }

    fn wire(&self, kind: MessageKind, name: &str, proposal: &FecProposal) -> Vec<u8> {
        let peer = id(name);
        let version = self.channel.authority().peers.version_of(&peer).unwrap();
        let bytes = signing_bytes(kind, &peer, version, proposal);
        encode(
            kind,
            &peer,
            version,
            proposal,
            &compute_proof(&test_key(name), &bytes),
        )
        .unwrap()
    }

    fn send(&mut self, now_ns: u64, bytes: &[u8]) -> FecHandled {
        self.endpoint.handle_with_fec(
            &mut self.channel,
            &mut self.fec,
            now_ns,
            &self.session,
            bytes,
        )
    }

    fn signed(&mut self, now_ns: u64, kind: MessageKind, name: &str) -> FecHandled {
        let bytes = self.wire(kind, name, self.fec.proposal());
        self.send(now_ns, &bytes)
    }

    fn bad_proof(&self) -> Vec<u8> {
        let mut bytes = self.wire(MessageKind::Proposal, "leader", self.fec.proposal());
        *bytes.last_mut().unwrap() ^= 1;
        bytes
    }

    fn checks(&self) -> u64 {
        self.channel.authority().checks.get()
    }

    fn complete(&mut self, first_ns: u64, interval_ns: u64) {
        for (index, (kind, name, expected)) in [
            (MessageKind::Proposal, "leader", Ingress::Proposed),
            (MessageKind::Ack, "member-s1", Ingress::Acknowledged),
            (MessageKind::Ack, "member-s2", Ingress::Acknowledged),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                self.signed(first_ns + index as u64 * interval_ns, kind, name),
                FecHandled::Fec(Ok(expected))
            );
        }
        let selection = self
            .fec
            .validated_selection(self.channel.authority(), &self.session)
            .unwrap();
        assert_eq!(selection.members().len(), 2);
        assert_eq!(selection.proposal().stream(), 42);
        assert_eq!(self.session.current_epoch, EPOCH, "no premature cutover");
    }
}

#[test]
fn n06_fec_ingress_budget_bounds_pre_auth_storm_and_recovers_real_selection() {
    let mut rig = Rig::new(2, 10 * MS, 0);
    let bad = rig.bad_proof();
    for index in 0..10_000 {
        let actual = rig.send(0, &bad);
        if index < 2 {
            assert_eq!(actual, FecHandled::Fec(Err(FecError::Authentication)));
        } else {
            assert_eq!(
                actual,
                FecHandled::RateLimited {
                    retry_after_ns: 10 * MS
                }
            );
        }
    }
    assert_eq!(rig.checks(), 2, "refused packets must not reach HMAC");
    assert_eq!(
        rig.fec
            .validated_selection(rig.channel.authority(), &rig.session),
        Err(FecError::MissingAcknowledgments)
    );
    rig.complete(10 * MS, 10 * MS);
    assert_eq!(rig.checks(), 5);
    assert_eq!(
        rig.endpoint.fec_ingress_stats(),
        FecIngressStats {
            received: 10_003,
            admitted: 5,
            rate_limited: 9_998
        }
    );
    assert_eq!(rig.endpoint.stats(), EndpointStats::default());
}

#[test]
fn n06_fec_ingress_budget_charges_malformed_and_oversized_before_authentication() {
    let mut rig = Rig::new(2, 10 * MS, 0);
    assert_eq!(
        rig.send(0, b"FFCN"),
        FecHandled::Fec(Err(FecError::Malformed))
    );
    let mut oversized = vec![0; 321];
    oversized[..4].copy_from_slice(b"FFCN");
    assert_eq!(
        rig.send(0, &oversized),
        FecHandled::Fec(Err(FecError::Malformed))
    );
    assert_eq!(rig.checks(), 0);
    assert_eq!(
        rig.signed(0, MessageKind::Proposal, "leader"),
        FecHandled::RateLimited {
            retry_after_ns: 10 * MS
        }
    );
    rig.complete(10 * MS, 10 * MS);
    assert_eq!(rig.checks(), 3);
}

#[test]
fn n06_fec_ingress_budget_survives_round_replacement_and_peer_rebind() {
    let mut rig = Rig::new(1, 10 * MS, 0);
    assert_eq!(
        rig.signed(0, MessageKind::Proposal, "leader"),
        FecHandled::Fec(Ok(Ingress::Proposed))
    );
    rig.channel
        .authority_mut()
        .peers
        .rebind(&id("leader"), Some(EPOCH))
        .unwrap();
    rig.fec = Rig::coordinator(&rig.session, 722);
    assert_eq!(
        rig.signed(0, MessageKind::Proposal, "leader"),
        FecHandled::RateLimited {
            retry_after_ns: 10 * MS
        }
    );
    assert_eq!(rig.checks(), 1);
    rig.complete(10 * MS, 10 * MS);
    assert_eq!(rig.checks(), 4);
    assert_eq!(rig.fec.proposal().proposal_id(), 722);
}

#[test]
fn n06_fec_ingress_flood_preserves_ordinary_control_and_priority_stop() {
    let mut rig = Rig::new(1, 10 * MS, 0);
    let bad = rig.bad_proof();
    assert_eq!(
        rig.send(0, &bad),
        FecHandled::Fec(Err(FecError::Authentication))
    );
    assert_eq!(
        rig.send(0, &bad),
        FecHandled::RateLimited {
            retry_after_ns: 10 * MS
        }
    );
    for (seq, peer, command, lane) in [
        (
            1,
            "leader",
            ControlCommand::SetGroupVolume { volume: 42 },
            Lane::Ordinary,
        ),
        (
            2,
            "panel",
            ControlCommand::StopGroupPlayback {
                now_ns: 1_000,
                irrevocable_dma_tail_ns: 500,
            },
            Lane::Priority,
        ),
    ] {
        let body = RequestBody::new(
            id(peer),
            seq,
            EPOCH,
            Some(rig.session.state_revision),
            command,
        )
        .unwrap();
        let proof = compute_proof(&test_key(peer), &body.signing_bytes());
        let wire = encode_request(&ControlRequest::new(body, proof)).unwrap();
        assert!(matches!(
            rig.send(0, &wire),
            FecHandled::Control(Handled::Request { result: SubmitResult::Queued { lane: actual }, reply: Some(_) }) if actual == lane
        ));
        let outcomes = rig.channel.step(0, &mut rig.session);
        assert_eq!(outcomes.len(), 1);
        assert!(matches!(outcomes[0].outcome, Outcome::Committed { .. }));
    }
    assert_eq!(rig.session.group_master_volume, 42);
    assert!(rig.session.members.values().all(|member| member.lifecycle
        == MemberLifecycleState::StoppingDmaTail {
            tail_complete_ns: 1_500
        }));
    assert_eq!(
        rig.endpoint.fec_ingress_stats(),
        FecIngressStats {
            received: 2,
            admitted: 1,
            rate_limited: 1
        }
    );
    assert_eq!(rig.endpoint.stats().requests, 2);
}

#[test]
fn n06_fec_ingress_backward_clock_cannot_refund_and_refill_boundary_is_exact() {
    let mut rig = Rig::new(1, 10, 100);
    let bad = rig.bad_proof();
    assert_eq!(
        rig.send(100, &bad),
        FecHandled::Fec(Err(FecError::Authentication))
    );
    for (now_ns, wait) in [(99, 11), (100, 10), (109, 1)] {
        assert_eq!(
            rig.send(now_ns, &bad),
            FecHandled::RateLimited {
                retry_after_ns: wait
            }
        );
    }
    assert_eq!(
        rig.send(110, &bad),
        FecHandled::Fec(Err(FecError::Authentication))
    );
    assert_eq!(rig.checks(), 2);
    assert_eq!(
        rig.send(u64::MAX, &bad),
        FecHandled::Fec(Err(FecError::Authentication))
    );
    assert_eq!(
        rig.send(u64::MAX, &bad),
        FecHandled::RateLimited { retry_after_ns: 1 }
    );
    assert_eq!(rig.checks(), 3);
}

#[test]
fn n06_fec_ingress_diagnostics_saturate_without_changing_admission() {
    let mut rig = Rig::new(1, 10 * MS, 0);
    rig.endpoint.fec_stats = FecIngressStats {
        received: u64::MAX,
        admitted: u64::MAX,
        rate_limited: u64::MAX,
    };
    assert_eq!(
        rig.signed(0, MessageKind::Proposal, "leader"),
        FecHandled::Fec(Ok(Ingress::Proposed))
    );
    assert_eq!(
        rig.signed(0, MessageKind::Ack, "member-s1"),
        FecHandled::RateLimited {
            retry_after_ns: 10 * MS
        }
    );
    assert_eq!(
        rig.signed(10 * MS, MessageKind::Ack, "member-s1"),
        FecHandled::Fec(Ok(Ingress::Acknowledged))
    );
    assert_eq!(
        rig.signed(20 * MS, MessageKind::Ack, "member-s2"),
        FecHandled::Fec(Ok(Ingress::Acknowledged))
    );
    assert!(
        rig.fec
            .validated_selection(rig.channel.authority(), &rig.session)
            .is_ok()
    );
    assert_eq!(
        rig.endpoint.fec_ingress_stats(),
        FecIngressStats {
            received: u64::MAX,
            admitted: u64::MAX,
            rate_limited: u64::MAX
        }
    );
    assert_eq!(rig.checks(), 3);
}
