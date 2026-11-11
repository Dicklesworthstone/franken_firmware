//! Real per-peer HMAC ingress and local sender selection. Volatile fixture key
//! storage is not credential persistence or distributed receiver cutover proof.
use super::*;
use franken_control::channel::{
    endpoint::{Endpoint, FecHandled},
    fec_negotiation::{
        FecCoordinator, FecError, MemberBinding, MessageKind, encode, signing_bytes,
    },
    peer::{PeerDirectory as ControlPeers, PeerId, PeerRole, compute_proof},
    pipeline::{ChannelConfig, ControlChannel},
};
use franken_control::contracts::secret_store::{
    Generation, SecretError, SecretHandle, SecretMeta, SecretStore, SecretValue,
};
use franken_session::{
    ChannelRole, FencedControlCommand, GroupCommandPayload, UnifiedGroupSession,
};
use franken_stream::carrier::{CarrierLimits, HostUdp, PRIMARY_GROUP};
use franken_stream::link::{LinkConfig, PROFILES};

/// Bounded volatile storage around the actual PeerDirectory, not a replacement
/// authentication authority. Every proof is checked by production HMAC code.
#[derive(Default)]
struct FixtureKeys(BTreeMap<SecretHandle, (Generation, SecretValue)>);

impl SecretStore for FixtureKeys {
    fn insert(&mut self, h: &SecretHandle, v: SecretValue) -> Result<Generation, SecretError> {
        if self.0.contains_key(h) {
            return Err(SecretError::AlreadyExists { handle: h.clone() });
        }
        if self.0.len() >= 16 {
            return Err(SecretError::StoreFull { max: 16 });
        }
        self.0.insert(h.clone(), (Generation::FIRST, v));
        Ok(Generation::FIRST)
    }
    fn replace(
        &mut self,
        h: &SecretHandle,
        v: SecretValue,
        expected: Generation,
    ) -> Result<Generation, SecretError> {
        let (generation, value) = self
            .0
            .get_mut(h)
            .ok_or_else(|| SecretError::NotFound { handle: h.clone() })?;
        if *generation != expected {
            return Err(SecretError::StaleGeneration {
                handle: h.clone(),
                expected: expected.get(),
                actual: generation.get(),
            });
        }
        *generation = generation
            .successor()
            .ok_or_else(|| SecretError::GenerationExhausted { handle: h.clone() })?;
        *value = v;
        Ok(*generation)
    }
    fn remove(&mut self, h: &SecretHandle) -> Result<(), SecretError> {
        self.0
            .remove(h)
            .map(|_| ())
            .ok_or_else(|| SecretError::NotFound { handle: h.clone() })
    }
    fn generation(&self, h: &SecretHandle) -> Result<Generation, SecretError> {
        self.0
            .get(h)
            .map(|(g, _)| *g)
            .ok_or_else(|| SecretError::NotFound { handle: h.clone() })
    }
    fn with_secret<R>(
        &self,
        h: &SecretHandle,
        f: impl FnOnce(Generation, &[u8]) -> R,
    ) -> Result<R, SecretError> {
        self.0
            .get(h)
            .map(|(g, v)| f(*g, v.expose()))
            .ok_or_else(|| SecretError::NotFound { handle: h.clone() })
    }
    fn list(&self) -> Vec<SecretMeta> {
        self.0
            .iter()
            .map(|(h, (g, v))| SecretMeta {
                handle: h.clone(),
                generation: *g,
                byte_len: v.byte_len(),
            })
            .collect()
    }
}

fn id(name: &str) -> PeerId {
    PeerId::parse(name).unwrap()
}
fn fixture_key(name: &str) -> [u8; 32] {
    match name {
        "leader" => [31; 32],
        "member-s1" => [41; 32],
        "member-s2" => [42; 32],
        _ => panic!("unknown synthetic fixture identity"),
    }
}

struct ControlRig {
    session: UnifiedGroupSession,
    channel: ControlChannel<ControlPeers<FixtureKeys>>,
    endpoint: Endpoint,
    coordinator: FecCoordinator,
}

impl ControlRig {
    fn new() -> Self {
        let mut session = UnifiedGroupSession::new("fixture-group", "leader", 1);
        let catalog = franken_board_profile::synthetic_test_fixture_catalog();
        for (seq, member, model) in [(1, "s1", "S5"), (2, "s2", "S12")] {
            let board = catalog
                .iter()
                .find(|b| b.model_number == model)
                .unwrap()
                .clone();
            session
                .apply_command(FencedControlCommand {
                    epoch: 1,
                    command_seq: seq,
                    payload: GroupCommandPayload::AdmitMember {
                        member_id: member.into(),
                        board,
                        role: ChannelRole::Stereo,
                    },
                })
                .unwrap();
        }
        let mut peers = ControlPeers::with_store(FixtureKeys::default());
        for name in ["leader", "member-s1", "member-s2"] {
            peers
                .admit(
                    &id(name),
                    PeerRole::Controller,
                    &fixture_key(name),
                    Some(1),
                    1,
                )
                .unwrap();
        }
        let coordinator = FecCoordinator::new(
            &session,
            id("leader"),
            PeerRole::Controller,
            vec![
                MemberBinding {
                    member: "s1".into(),
                    peer: id("member-s1"),
                    role: PeerRole::Controller,
                },
                MemberBinding {
                    member: "s2".into(),
                    peer: id("member-s2"),
                    role: PeerRole::Controller,
                },
            ],
            stream().get(),
            900_000_000,
            721,
        )
        .unwrap();
        Self {
            session,
            channel: ControlChannel::new(peers, ChannelConfig::provisional()).unwrap(),
            endpoint: Endpoint::new(),
            coordinator,
        }
    }

    fn ingress(&mut self, kind: MessageKind, name: &str) {
        let peer = id(name);
        let generation = self.channel.authority().version_of(&peer).unwrap();
        let signed = signing_bytes(kind, &peer, generation, self.coordinator.proposal());
        let wire = encode(
            kind,
            &peer,
            generation,
            self.coordinator.proposal(),
            &compute_proof(&fixture_key(name), &signed),
        )
        .unwrap();
        assert!(matches!(
            self.endpoint.handle_with_fec(
                &mut self.channel,
                &mut self.coordinator,
                0,
                &self.session,
                &wire,
            ),
            FecHandled::Fec(Ok(_))
        ));
    }

    fn acknowledge_all(&mut self) {
        self.ingress(MessageKind::Proposal, "leader");
        self.ingress(MessageKind::Ack, "member-s1");
        self.ingress(MessageKind::Ack, "member-s2");
    }
}

fn local_sender() -> SenderEndpoint<HostUdp> {
    let mut limits = CarrierLimits::baseline();
    limits.pace_bytes_per_sec = 3_000_000;
    limits.pace_burst_bytes = 32_000;
    let carrier =
        CarrierSender::bind(key(), stream(), 1, limits, IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
    let link = LinkManager::new(LinkConfig::baseline(PROFILES[0], 1)).unwrap();
    let mut endpoint = SenderEndpoint::new(carrier, link, 2);
    endpoint.announce(111, 7, address(), address(), 1).unwrap();
    let second = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 11);
    endpoint.announce(222, 8, second, second, 1).unwrap();
    endpoint
}

fn routes() -> Vec<(PeerId, u64)> {
    vec![(id("member-s1"), 111), (id("member-s2"), 222)]
}

#[test]
fn n06_sender_selection_consumes_encoded_all_member_agreement_and_preserves_n01_on_refusal() {
    let mut control = ControlRig::new();
    let mut sender = local_sender();
    let original = sender.carrier().group_view(PRIMARY_GROUP).unwrap();
    assert!(matches!(
        sender.select_acknowledged_host_fec(
            PRIMARY_GROUP,
            &control.coordinator,
            control.channel.authority(),
            &control.session,
            &routes()
        ),
        Err(EndpointError::FecAgreement(
            FecError::MissingAcknowledgments
        ))
    ));
    assert_eq!(
        sender.carrier().group_view(PRIMARY_GROUP).unwrap(),
        original
    );
    assert_eq!(
        sender
            .carrier_mut()
            .submit_media(
                1,
                &OutboundFrame::media(0, 900_000_000, 897_500_000, source(0)[0].to_vec()),
                0
            )
            .unwrap()
            .queued,
        2
    );

    control.acknowledge_all();
    let before = sender.carrier().group_view(PRIMARY_GROUP).unwrap();
    let duplicate_route = [(id("member-s1"), 111), (id("member-s2"), 111)];
    assert!(matches!(
        sender.select_acknowledged_host_fec(
            PRIMARY_GROUP,
            &control.coordinator,
            control.channel.authority(),
            &control.session,
            &duplicate_route
        ),
        Err(EndpointError::FecBinding(_))
    ));
    assert_eq!(sender.carrier().group_view(PRIMARY_GROUP).unwrap(), before);
    sender
        .select_acknowledged_host_fec(
            PRIMARY_GROUP,
            &control.coordinator,
            control.channel.authority(),
            &control.session,
            &routes(),
        )
        .unwrap();
    assert_eq!(sender.carrier().group_view(PRIMARY_GROUP).unwrap().epoch, 2);
    assert_eq!(
        sender
            .carrier_mut()
            .submit_group_fec_window(PRIMARY_GROUP, 2, 0, source(0), 0)
            .unwrap()
            .queued,
        16
    );
    assert_eq!(
        control.session.current_epoch, 1,
        "local selection is not distributed cutover"
    );
}

#[test]
fn n06_sender_selection_revalidates_revocation_and_stream_binding_before_mutation() {
    let mut control = ControlRig::new();
    control.acknowledge_all();
    let mut sender = local_sender();
    let before = sender.carrier().group_view(PRIMARY_GROUP).unwrap();
    assert!(control.channel.authority_mut().revoke(&id("member-s2")));
    assert!(matches!(
        sender.select_acknowledged_host_fec(
            PRIMARY_GROUP,
            &control.coordinator,
            control.channel.authority(),
            &control.session,
            &routes()
        ),
        Err(EndpointError::FecAgreement(FecError::Authentication))
    ));
    assert_eq!(sender.carrier().group_view(PRIMARY_GROUP).unwrap(), before);

    let mut fresh = ControlRig::new();
    fresh.acknowledge_all();
    sender
        .carrier_mut()
        .restart_group(PRIMARY_GROUP, StreamId::new(99).unwrap(), 2)
        .unwrap();
    let restarted = sender.carrier().group_view(PRIMARY_GROUP).unwrap();
    assert!(matches!(
        sender.select_acknowledged_host_fec(
            PRIMARY_GROUP,
            &fresh.coordinator,
            fresh.channel.authority(),
            &fresh.session,
            &routes()
        ),
        Err(EndpointError::FecBinding(_))
    ));
    assert_eq!(
        sender.carrier().group_view(PRIMARY_GROUP).unwrap(),
        restarted
    );
}
