//! Loopback discovery over the actual protocol endpoint and mailbox.
//! This host-only fixture does not model a physical device or renderer.
#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::settled_http::{
        HttpMailboxConfig, HttpMailboxOwner, HttpService, OwnedHttpReply, http_mailbox,
    };
    use crate::settled_render::{ControlResult, OwnerError};
    use franken_control::channel::peer::{
        AuthFailure, AuthProof, Authenticated, PeerAuthority, PeerId,
    };
    use franken_control::channel::pipeline::{ChannelConfig, ControlChannel, DevelopmentVolatile};
    use franken_control::fsonos::{Context, Endpoint, EndpointConfig, LegacyBridge};
    use std::net::UdpSocket;

    // Discovery GET and subscription do not admit a command identity. This
    // authority rejects every credential; it never fabricates an authorized peer.
    struct NoPeers;
    impl PeerAuthority for NoPeers {
        fn authenticate(
            &self,
            _peer: &PeerId,
            _message: &[u8],
            _proof: &AuthProof,
        ) -> Result<Authenticated, AuthFailure> {
            Err(AuthFailure::BadProof)
        }
        fn is_current(&self, _auth: &Authenticated) -> bool {
            false
        }
    }

    struct CoreOwner {
        mailbox: HttpMailboxOwner,
        endpoint: Endpoint,
        channel: ControlChannel<NoPeers>,
        stepper: DevelopmentVolatile,
        session: UnifiedGroupSession,
        requests: Vec<(String, String)>,
    }

    impl CoreOwner {
        fn new(mailbox: HttpMailboxOwner, device: Option<Device>) -> Self {
            let peer = PeerId::parse("fixture-bridge").unwrap();
            let bridge = LegacyBridge::new(peer, b"public-fixture-key-0123456789".to_vec());
            let mut endpoint = Endpoint::new(
                EndpointConfig::provisional(FIXTURE_DEVICE_UUID),
                bridge,
                1,
                1,
            )
            .unwrap();
            if let Some(device) = device {
                endpoint.configure_discovery(device).unwrap();
            }
            Self {
                mailbox,
                endpoint,
                channel: ControlChannel::new(NoPeers, ChannelConfig::provisional()).unwrap(),
                stepper: DevelopmentVolatile,
                session: fixture_session_for(FIXTURE_DEVICE_UUID, FIXTURE_OTHER_UUID).unwrap(),
                requests: Vec::new(),
            }
        }

        fn service(&mut self) -> HttpService {
            let Self {
                mailbox,
                endpoint,
                channel,
                stepper,
                session,
                requests,
            } = self;
            mailbox
                .service_one(|request| {
                    requests.push((request.method.to_owned(), request.path.to_owned()));
                    let control = endpoint.handle(
                        &mut Context {
                            channel: &mut *channel,
                            session: &mut *session,
                            stepper: &mut *stepper,
                            now_ns: START_NS,
                        },
                        &request,
                    );
                    OwnedHttpReply {
                        result: Ok(ControlResult {
                            control,
                            // No renderer is present in this protocol-only fixture.
                            render: Err(OwnerError::Clock),
                            notifications: Vec::new(),
                        }),
                        session: session.clone(),
                    }
                })
                .unwrap()
        }
    }

    fn mailbox_pair(timeout: Duration) -> (HttpMailboxClient, HttpMailboxOwner) {
        http_mailbox(HttpMailboxConfig::new(16 * 1024, 32, timeout).unwrap()).unwrap()
    }

    fn callback_target() -> (TcpListener, CallbackTarget) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target = CallbackTarget::new(listener.local_addr().unwrap(), "/events").unwrap();
        (listener, target)
    }

    fn exchange(addr: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).unwrap();
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..read]);
            assert!(bytes.len() <= 64 * 1024);
        }
        String::from_utf8(bytes).unwrap()
    }

    fn drive_until<T>(owner: &mut CoreOwner, worker: JoinHandle<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(8);
        while !worker.is_finished() {
            assert!(
                Instant::now() < deadline,
                "owner-serviced worker did not finish"
            );
            match owner.service() {
                HttpService::Idle => thread::sleep(Duration::from_millis(1)),
                HttpService::Replied => {}
                other => panic!("owner request did not complete: {other:?}"),
            }
        }
        worker.join().unwrap()
    }

    fn discover(server: &FsonosLoopback) -> String {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let search = b"M-SEARCH * HTTP/1.1\r\nHOST: x\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";
        socket
            .send_to(search, server.discovery_addr().unwrap())
            .unwrap();
        let mut answer = [0_u8; 2048];
        let (length, peer) = socket.recv_from(&mut answer).unwrap();
        assert!(peer.ip().is_loopback());
        String::from_utf8(answer[..length].to_vec()).unwrap()
    }

    fn start_discovery(
        client: HttpMailboxClient,
        policy: Policy,
        target: CallbackTarget,
    ) -> JoinHandle<Result<FsonosLoopback, String>> {
        thread::spawn(move || {
            let identity = DiscoveryIdentity::fixture();
            FsonosLoopback::start_discoverable_eventing_with_mailbox(
                fixture_session_for(FIXTURE_DEVICE_UUID, FIXTURE_OTHER_UUID).unwrap(),
                &identity,
                policy,
                LoopbackLimits::standard(),
                DiscoveryLimits::standard(),
                (target, CallbackLimits::standard()),
                client,
            )
        })
    }

    #[test]
    fn matching_real_core_is_preflighted_before_discovery_and_serves_later_get() {
        let identity = DiscoveryIdentity::fixture();
        let device = identity.device().unwrap();
        let (client, mailbox) = mailbox_pair(Duration::from_millis(800));
        let mut owner = CoreOwner::new(mailbox, Some(device.clone()));
        let (_callback_listener, target) = callback_target();
        let server = drive_until(
            &mut owner,
            start_discovery(client.clone(), Policy::LocalLink, target),
        )
        .unwrap();
        assert!(
            owner
                .requests
                .iter()
                .any(|(method, path)| method == "GET" && path == DESCRIPTION_PATH)
        );
        let answer = discover(&server);
        assert!(answer.starts_with("HTTP/1.1 200"));
        assert!(answer.contains(&device.location()));
        assert!(answer.contains(FIXTURE_DEVICE_UUID));

        let count_before = owner.requests.len();
        let address = server.addr();
        let client_get = thread::spawn(move || {
            exchange(
                address,
                "GET /xml/device_description.xml HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )
        });
        let wire = drive_until(&mut owner, client_get);
        assert!(wire.starts_with("HTTP/1.1 200 "));
        let (head, body) = wire.split_once("\r\n\r\n").unwrap();
        assert_eq!(body, device.description_xml());
        assert!(head.lines().any(|line| {
            line.eq_ignore_ascii_case(&format!("Content-Location: {}", device.location()))
        }));
        assert!(head.lines().any(|line| line.eq_ignore_ascii_case(&format!(
            "Cache-Control: max-age={}",
            franken_control::fsonos::ssdp::MIN_MAX_AGE
        ))));
        assert!(head.lines().any(|line| {
            line.eq_ignore_ascii_case(&format!("Content-Type: {DESCRIPTION_CONTENT_TYPE}"))
        }));
        assert_eq!(owner.requests.len(), count_before + 1);
        assert_eq!(
            owner.requests.last().unwrap(),
            &("GET".to_owned(), DESCRIPTION_PATH.to_owned())
        );
        assert!(server.stop().reconciled());
    }

    fn description_request() -> HttpRequest<'static> {
        HttpRequest {
            method: "GET",
            path: DESCRIPTION_PATH,
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ingress: Ingress::LocalLegacy,
            headers: &[],
            body: &[],
        }
    }

    fn bounded_join<T>(worker: JoinHandle<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(8);
        while !worker.is_finished() {
            assert!(Instant::now() < deadline, "worker did not finish");
            thread::sleep(Duration::from_millis(1));
        }
        worker.join().unwrap()
    }

    #[test]
    fn missing_real_description_refuses_start_and_keeps_attachment_fenced() {
        let (client, mailbox) = mailbox_pair(Duration::from_millis(800));
        let mut owner = CoreOwner::new(mailbox, None);
        let (_listener, target) = callback_target();
        let result = drive_until(
            &mut owner,
            start_discovery(client.clone(), Policy::LocalLink, target),
        );
        let error = result
            .err()
            .expect("unconfigured endpoint must refuse startup");
        assert_eq!(error, "owner discovery response: 404");
        assert!(
            owner
                .requests
                .iter()
                .any(|(method, path)| method == "GET" && path == DESCRIPTION_PATH)
        );
        assert!(matches!(
            client.submit(&description_request()),
            Err(HttpMailboxError::Busy)
        ));
    }

    #[test]
    fn same_description_with_different_owner_location_must_refuse_discovery() {
        let identity = DiscoveryIdentity::fixture();
        let advertised = identity.device().unwrap();
        let alternate = Device::new(
            &identity.uuid,
            Ipv4Addr::LOCALHOST.octets(),
            PLAYER_PORT + 1,
            &identity.room,
            franken_control::fsonos::ssdp::MIN_MAX_AGE,
        )
        .unwrap();
        assert_eq!(advertised.description_xml(), alternate.description_xml());
        assert_ne!(advertised.location(), alternate.location());
        let (client, mailbox) = mailbox_pair(Duration::from_millis(800));
        let mut owner = CoreOwner::new(mailbox, Some(alternate));
        let (_listener, target) = callback_target();
        let result = drive_until(
            &mut owner,
            start_discovery(client.clone(), Policy::LocalLink, target),
        );
        let error = result
            .err()
            .expect("same XML but different real owner LOCATION must refuse startup");
        assert_eq!(error, "owner discovery identity mismatch");
        assert!(matches!(
            client.submit(&description_request()),
            Err(HttpMailboxError::Busy)
        ));
    }

    #[test]
    fn different_real_owner_description_must_refuse_discovery() {
        let identity = DiscoveryIdentity::fixture();
        let advertised = identity.device().unwrap();
        let alternate = Device::new(
            &identity.uuid,
            Ipv4Addr::LOCALHOST.octets(),
            PLAYER_PORT,
            "Other Room",
            franken_control::fsonos::ssdp::MIN_MAX_AGE,
        )
        .unwrap();
        assert_ne!(advertised.description_xml(), alternate.description_xml());
        let (client, mailbox) = mailbox_pair(Duration::from_millis(800));
        let mut owner = CoreOwner::new(mailbox, Some(alternate));
        let (_listener, target) = callback_target();
        let result = drive_until(
            &mut owner,
            start_discovery(client.clone(), Policy::LocalLink, target),
        );
        let error = result
            .err()
            .expect("different real owner description must refuse startup");
        assert_eq!(error, "owner discovery identity mismatch");
        assert!(matches!(
            client.submit(&description_request()),
            Err(HttpMailboxError::Busy)
        ));
    }

    #[test]
    fn tailnet_policy_must_not_start_local_discovery_or_invoke_owner() {
        let (client, mailbox) = mailbox_pair(Duration::from_millis(800));
        let mut owner = CoreOwner::new(
            mailbox,
            Some(DiscoveryIdentity::fixture().device().unwrap()),
        );
        let (_listener, target) = callback_target();
        let result = drive_until(
            &mut owner,
            start_discovery(client, Policy::UnauthenticatedTailnet, target),
        );
        let error = result
            .err()
            .expect("Tailnet must not advertise unauthenticated discovery");
        assert_eq!(error, "owner discovery requires local legacy ingress");
        assert!(owner.requests.is_empty());
    }

    #[test]
    fn queued_work_refuses_attachment_then_real_queued_owner_get_succeeds() {
        let (client, mailbox) = mailbox_pair(Duration::from_millis(800));
        let mut owner = CoreOwner::new(
            mailbox,
            Some(DiscoveryIdentity::fixture().device().unwrap()),
        );
        let pending = client.submit(&description_request()).unwrap();
        let (_listener, target) = callback_target();
        let result = bounded_join(start_discovery(client, Policy::LocalLink, target));
        let error = result
            .err()
            .expect("occupied mailbox must refuse attachment");
        assert_eq!(error, "owner eventing attachment is unavailable");
        assert_eq!(owner.service(), HttpService::Replied);
        assert_eq!(
            pending
                .wait()
                .unwrap()
                .result
                .unwrap()
                .control
                .response
                .status,
            200
        );
    }

    #[test]
    fn unserviced_owner_times_out_and_stays_fenced() {
        let (client, mailbox) = mailbox_pair(Duration::from_millis(300));
        let mut owner = CoreOwner::new(
            mailbox,
            Some(DiscoveryIdentity::fixture().device().unwrap()),
        );
        let (_listener, target) = callback_target();
        let result = bounded_join(start_discovery(client.clone(), Policy::LocalLink, target));
        let error = result
            .err()
            .expect("unserviced owner must refuse readiness");
        assert_eq!(error, "owner discovery response: 504");
        assert_eq!(owner.service(), HttpService::Expired);
        assert!(matches!(
            client.submit(&description_request()),
            Err(HttpMailboxError::Busy)
        ));
    }

    #[test]
    fn disconnected_owner_refuses_discovery_without_readiness() {
        let (client, mailbox) = mailbox_pair(Duration::from_millis(800));
        drop(mailbox);
        let (_listener, target) = callback_target();
        let result = bounded_join(start_discovery(client, Policy::LocalLink, target));
        let error = result
            .err()
            .expect("disconnected owner must refuse readiness");
        assert_eq!(error, "owner eventing attachment is unavailable");
    }

    #[test]
    fn plain_mailbox_rejects_discoverable_eventing_without_owner_eventing_attachment() {
        let (client, mailbox) = mailbox_pair(Duration::from_millis(800));
        let mut owner = CoreOwner::new(
            mailbox,
            Some(DiscoveryIdentity::fixture().device().unwrap()),
        );
        let (_listener, target) = callback_target();
        let worker = thread::spawn(move || {
            let described = FsonosLoopback::describe(
                &DiscoveryIdentity::fixture(),
                DiscoveryLimits::standard(),
            )
            .unwrap();
            FsonosLoopback::start_inner_with(
                fixture_session_for(FIXTURE_DEVICE_UUID, FIXTURE_OTHER_UUID).unwrap(),
                FIXTURE_DEVICE_UUID,
                Policy::LocalLink,
                LoopbackLimits::standard(),
                Some((described, DiscoveryLimits::standard())),
                Some((target, CallbackLimits::standard())),
                (
                    host_incarnation,
                    Box::new(move |_, _, _| Ok(mailbox_control(client))),
                ),
            )
        });
        let result = drive_until(&mut owner, worker);
        let error = result
            .err()
            .expect("plain mailbox cannot own an eventing outbox");
        assert_eq!(error, "control owner does not admit transport-local extras");
        assert!(owner.requests.is_empty());
    }

    #[test]
    fn legacy_discovery_and_eventing_constructor_still_serves_its_description() {
        let (_listener, target) = callback_target();
        let identity = DiscoveryIdentity::fixture();
        let device = identity.device().unwrap();
        let server = FsonosLoopback::start_discoverable_eventing(
            fixture_session_for(FIXTURE_DEVICE_UUID, FIXTURE_OTHER_UUID).unwrap(),
            &identity,
            Policy::LocalLink,
            LoopbackLimits::standard(),
            DiscoveryLimits::standard(),
            target,
            CallbackLimits::standard(),
        )
        .unwrap();
        let answer = discover(&server);
        assert!(answer.starts_with("HTTP/1.1 200"));
        assert!(answer.contains(&device.location()));
        assert!(answer.contains(FIXTURE_DEVICE_UUID));
        let wire = exchange(
            server.addr(),
            "GET /xml/device_description.xml HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(wire.starts_with("HTTP/1.1 200 "));
        assert_eq!(
            wire.split_once("\r\n\r\n").unwrap().1,
            device.description_xml()
        );
        let report = server.stop();
        assert_eq!(report.described, 1);
        assert!(report.reconciled());
    }

    #[test]
    fn same_description_and_location_with_different_owner_cache_age_must_refuse() {
        let identity = DiscoveryIdentity::fixture();
        let advertised = identity.device().unwrap();
        let alternate = Device::new(
            &identity.uuid,
            Ipv4Addr::LOCALHOST.octets(),
            PLAYER_PORT,
            &identity.room,
            franken_control::fsonos::ssdp::MIN_MAX_AGE + 1,
        )
        .unwrap();
        assert_eq!(advertised.description_xml(), alternate.description_xml());
        assert_eq!(advertised.location(), alternate.location());
        let (client, mailbox) = mailbox_pair(Duration::from_millis(800));
        let mut owner = CoreOwner::new(mailbox, Some(alternate));
        let (_listener, target) = callback_target();
        let result = drive_until(
            &mut owner,
            start_discovery(client.clone(), Policy::LocalLink, target),
        );
        let error = result
            .err()
            .expect("different real owner cache age must refuse startup");
        assert_eq!(error, "owner discovery identity mismatch");
        assert!(matches!(
            client.submit(&description_request()),
            Err(HttpMailboxError::Busy)
        ));
    }
}
