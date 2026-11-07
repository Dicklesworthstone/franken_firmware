//! The REAL fsonos client against ONE G03 server that is both discoverable and eventing, over loopback only
//! (`docs/contracts/g03.md` section 11 items 2 and 5).
//!
//! The server is `FsonosLoopback::start_discoverable_eventing`: one listener, one worker, one `franken_control::fsonos::Endpoint`
//! and one group session answer the client's search, serve the device description, take its SOAP and `SUBSCRIBE` requests and deliver
//! the events the core produces to the client's own `EventSink`. The client is `fsonos-proto` as the `fsonos` CLI and daemon use it:
//! `Lan::ssdp_search`, `Transport::http_get`, the description and topology parsers, `control::*`, `Lan::subscribe`, `renew` and
//! `unsubscribe`, and `EventSink` receiving the `NOTIFY` messages. Nothing here is a double; the discoverable and the eventing
//! behaviours are each already tested alone (`discovery.rs`, `eventing.rs`), and what this adds is that one server does both for one
//! client, which it learns of from the search and nowhere else.
//!
//! Safety. `Lan` can also multicast, query mDNS and fetch any URL, and a request for any address it was not routed away from goes to
//! `ip:1400`. So the tests never hold a bare `Lan`: they hold [`Composed`], which is built only from a running discoverable shim
//! (so `Lan::with_ssdp_target` is always called, with the responder's loopback port, and no search can reach the multicast group),
//! is routed from the fixture player (loopback itself) to the shim's ephemeral port, forwards only a SOAP POST, a GET, the search and
//! the RenderingControl event calls of that player, and keeps the trait's `NotWired` default for everything else. A call for another
//! host or URL is refused before the real client is touched. The callback URL a test subscribes with is the `EventSink`'s own
//! loopback address, the one callback the shim allows.
//!
//! What this is not. It is isolated host integration: no daemon, no speaker, no provider, no tailnet and no claim about the real LAN.
//! The description and the fixture session keep the gaps `discovery.rs` names.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;
use std::time::{Duration, Instant};

use franken_speaker::fsonos_loopback as shim;
use fsonos_proto::control::{get_volume, set_mute, set_volume};
use fsonos_proto::gena::{Notify, Subscription};
use fsonos_proto::net::{EventSink, Lan};
use fsonos_proto::soap::RENDERING_CONTROL;
use fsonos_proto::{ProtoError, Transport, description, soap, ssdp, topology};
use shim::{
    CallbackLimits, CallbackReport, CallbackTarget, DiscoveryIdentity, DiscoveryLimits,
    FsonosLoopback, LoopbackLimits, Policy,
};

const DEVICE: &str = shim::FIXTURE_DEVICE_UUID;
const NEIGHBOUR: &str = shim::FIXTURE_OTHER_UUID;
const ROOM: &str = shim::FIXTURE_ROOM;
const PLAYER: IpAddr = shim::FIXTURE_PLAYER_IP;
const TAG: &str = "RenderingControl";
/// How long the real client collects answers. The responder answers at once, so this only bounds the wait.
const SEARCH_WAIT: Duration = Duration::from_millis(700);
/// How long a test waits for an event it expects.
const EXPECT: Duration = Duration::from_secs(5);
/// How long a test waits before concluding that an event will not come.
const QUIET: Duration = Duration::from_millis(300);

/// The real client, reachable only for what these tests exercise, and only toward the composed shim.
struct Composed {
    lan: Lan,
}

impl Composed {
    /// The real `Lan`, routed from the fixture player's address to the shim's HTTP port and pointed at the responder's UDP port.
    fn to(server: &FsonosLoopback) -> Self {
        let search = server
            .discovery_addr()
            .expect("a composed shim is discoverable");
        let lan = Lan::with_timeout(Duration::from_secs(3)).expect("the real client starts");
        let routed = lan.with_routes(vec![(PLAYER, server.addr())]);
        let lan = routed.with_ssdp_target(search);
        Self { lan }
    }

    fn subscribe(&self, host: IpAddr, callback: &str) -> Result<Subscription, ProtoError> {
        only_the_player(host)?;
        let event_path = RENDERING_CONTROL.event_path;
        self.lan.subscribe(host, event_path, callback, 300)
    }

    fn renew(
        &self,
        host: IpAddr,
        sid: &str,
        timeout_secs: u32,
    ) -> Result<Subscription, ProtoError> {
        only_the_player(host)?;
        let event_path = RENDERING_CONTROL.event_path;
        self.lan.renew(host, event_path, sid, timeout_secs)
    }

    fn unsubscribe(&self, host: IpAddr, sid: &str) -> Result<(), ProtoError> {
        only_the_player(host)?;
        let event_path = RENDERING_CONTROL.event_path;
        self.lan.unsubscribe(host, event_path, sid)
    }
}

fn refused(what: &str) -> ProtoError {
    ProtoError::Network {
        target: what.to_string(),
        detail: "refused: not the loopback fixture's player".to_string(),
    }
}

fn only_the_player(host: IpAddr) -> Result<(), ProtoError> {
    if host == PLAYER {
        Ok(())
    } else {
        Err(refused(&host.to_string()))
    }
}

/// Whether `url` names the fixture player on the player port: the only place a GET may go.
fn is_fixture_url(url: &str) -> bool {
    let prefix = format!("http://{PLAYER}:{}/", shim::PLAYER_PORT);
    url.starts_with(&prefix)
}

impl Transport for Composed {
    fn soap_post(
        &self,
        host: IpAddr,
        control_path: &str,
        soap_action: &str,
        body: &str,
    ) -> Result<String, ProtoError> {
        only_the_player(host)?;
        self.lan.soap_post(host, control_path, soap_action, body)
    }

    fn http_get(&self, url: &str) -> Result<String, ProtoError> {
        if !is_fixture_url(url) {
            return Err(refused(url));
        }
        self.lan.http_get(url)
    }

    fn ssdp_search(&self, mx_secs: u8, wait: Duration) -> Result<Vec<ssdp::Advert>, ProtoError> {
        self.lan.ssdp_search(mx_secs, wait)
    }
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// The one server under test: the fixture device, discoverable, whose one allowed callback is `sink`'s own loopback address.
fn serve(sink: &EventSink, policy: Policy) -> FsonosLoopback {
    let identity = DiscoveryIdentity::fixture();
    let session = shim::fixture_session_for(&identity.uuid, NEIGHBOUR).expect("a session");
    let path = format!("/{TAG}");
    let target = CallbackTarget::new(sink.local_addr(), &path).expect("an allowed target");
    let limits = LoopbackLimits::standard();
    let discovery = DiscoveryLimits::standard();
    let callbacks = CallbackLimits::standard();
    FsonosLoopback::start_discoverable_eventing(
        session, &identity, policy, limits, discovery, target, callbacks,
    )
    .expect("the composed shim starts")
}

fn next(sink: &EventSink) -> Notify {
    sink.recv_timeout(EXPECT).expect("a NOTIFY")
}

fn quiet(sink: &EventSink) -> bool {
    sink.recv_timeout(QUIET).is_none()
}

/// The volume and mute the live session holds for the served member.
fn live(server: &FsonosLoopback) -> (u8, bool) {
    let volume = server.with_session(|s| s.members[DEVICE].volume_0_to_100);
    let muted = server.with_session(|s| s.members[DEVICE].muted);
    (volume, muted)
}

/// The `LastChange` document of an event, as the client parses it.
fn changes(event: &Notify) -> fsonos_proto::gena::LastChange {
    event
        .last_change()
        .expect("the client parses the event")
        .expect("a LastChange")
}

/// The `HTTP <status>` detail of a network error.
fn detail(error: &ProtoError) -> Option<&str> {
    match error {
        ProtoError::Network { detail, .. } => Some(detail.as_str()),
        _ => None,
    }
}

/// The delivery report once everything offered has been attempted or counted (bounded wait).
fn settled_events(server: &FsonosLoopback) -> CallbackReport {
    let give_up = Instant::now() + Duration::from_secs(8);
    loop {
        let report = server.callback_report().expect("an eventing shim");
        if report.offered > 0 && report.reconciled() {
            return report;
        }
        assert!(Instant::now() < give_up, "never settled: {report:?}");
        thread::sleep(Duration::from_millis(5));
    }
}

/// The responder's report once it has counted what it read (bounded wait).
fn settled_search(server: &FsonosLoopback) -> shim::DiscoveryReport {
    let give_up = Instant::now() + Duration::from_secs(5);
    loop {
        let report = server.discovery_report().expect("a responder");
        if report.received > 0 && report.reconciled() {
            return report;
        }
        assert!(Instant::now() < give_up, "the responder never counted");
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn the_real_client_finds_describes_controls_and_hears_one_server() {
    let sink = EventSink::start(loopback()).expect("a listener");
    let server = serve(&sink, Policy::LocalLink);
    let client = Composed::to(&server);
    let responder = server.discovery_addr().expect("a discoverable shim");
    assert!(responder.ip().is_loopback());

    // Discovery: the client's own unicast search finds one device and the location a player has.
    let found = client.ssdp_search(1, SEARCH_WAIT).expect("a search");
    assert_eq!(found.len(), 1);
    let advert = &found[0];
    assert_eq!(advert.st, ssdp::SONOS_ST);
    assert_eq!(advert.location, ssdp::description_url(PLAYER));

    // Description: fetched from where the advert says, read by the client's own parser.
    let document = client.http_get(&advert.location).expect("a description");
    let parsed = description::parse_device_description(&document).expect("a parse");
    assert_eq!(parsed.udn.0, DEVICE);
    assert_eq!(parsed.room_name, ROOM);
    assert!(parsed.has_service(soap::RENDERING_CONTROL.service_type));

    // Topology: asked of the host the advert names. The served member is the device the client found.
    let host = topology::host_of_location(&advert.location).expect("a host");
    assert_eq!(host, PLAYER);
    let zones = topology::get_zone_group_state(&client, host).expect("a topology");
    let members = &zones.groups[0].members;
    let served = members
        .iter()
        .find(|member| member.uuid.0 == DEVICE)
        .expect("the served member");
    assert_eq!(served.uuid.0, parsed.udn.0);
    assert_eq!(served.location, advert.location);
    assert_eq!(served.ip(), Some(host));

    // Eventing on the SAME server, at the host the search named: the core grants a SID and the full state follows as SEQ 0.
    let callback = sink.callback_url(TAG);
    let sub = client.subscribe(host, &callback).expect("subscribed");
    assert!(sub.sid.starts_with("uuid:"));
    let first = next(&sink);
    assert_eq!(first.sid, sub.sid);
    assert_eq!(first.seq, 0);
    assert_eq!(first.path, format!("/{TAG}"));
    let (volume, muted) = live(&server);
    let state = changes(&first);
    assert_eq!(state.volume(), Some(volume));
    assert_eq!(state.mute(), Some(muted));

    // Control on the same server: each change is the live session's and reaches the listener as the next event, in order.
    set_volume(&client, host, 30).expect("a set");
    let second = next(&sink);
    assert_eq!(second.sid, sub.sid);
    assert_eq!(second.seq, 1);
    assert_eq!(changes(&second).volume(), Some(30));
    assert_eq!(changes(&second).mute(), None);
    set_mute(&client, host, true).expect("a mute");
    let third = next(&sink);
    assert_eq!(third.seq, 2);
    assert_eq!(changes(&third).mute(), Some(true));
    assert_eq!(changes(&third).volume(), None);
    assert_eq!(live(&server), (30, true));
    assert_eq!(get_volume(&client, host).expect("a volume"), 30);

    // A renewal keeps the SID and sends no event; an unsubscribe ends the events while control keeps answering.
    let renewed = client.renew(host, &sub.sid, 600).expect("renewed");
    assert_eq!(renewed.sid, sub.sid);
    assert!(quiet(&sink), "a renewal sends no event");
    client.unsubscribe(host, &sub.sid).expect("unsubscribed");
    set_volume(&client, host, 40).expect("a set");
    assert_eq!(live(&server).0, 40);
    assert!(quiet(&sink), "nothing is sent after unsubscribe");

    // Every part counted what it did. The search: each datagram read was answered. Events: three offered, three delivered. The
    // HTTP side: the description once, and eight requests the endpoint answered (topology, subscribe, two sets, a read, a renewal, an
    // unsubscribe and the last set), none refused or dropped.
    let heard = settled_search(&server);
    assert_eq!(heard.answered, heard.received);
    assert_eq!(heard.replies_sent, heard.answered);
    assert_eq!(heard.silent + heard.foreign + heard.failed, 0);
    assert!(heard.refusals.is_empty());
    let sent = settled_events(&server);
    assert_eq!(sent.offered, 3);
    assert_eq!(sent.delivered, 3);
    let lost = sent.refused + sent.dropped + sent.failed + sent.unframed;
    assert_eq!(lost, 0);
    let report = server.stop();
    assert_eq!(report.described, 1);
    assert_eq!(report.served, 8);
    assert_eq!(report.refused + report.dropped, 0);
    assert!(report.reconciled());
}

#[test]
fn on_the_tailnet_the_composed_server_describes_nothing_subscribes_nobody_and_sends_nothing() {
    let sink = EventSink::start(loopback()).expect("a listener");
    let callback = sink.callback_url(TAG);
    let location = ssdp::description_url(PLAYER);

    // The permitted counterpart first: on the local link the same server describes itself and grants the subscription.
    let local = serve(&sink, Policy::LocalLink);
    let client = Composed::to(&local);
    assert!(client.http_get(&location).is_ok());
    let sub = client.subscribe(PLAYER, &callback).expect("subscribed");
    assert_eq!(next(&sink).sid, sub.sid);
    drop(client);
    drop(local);

    // Judged as the tailnet, the same two requests are refused by the endpoint, and no event is offered or sent.
    let tailnet = serve(&sink, Policy::UnauthenticatedTailnet);
    let client = Composed::to(&tailnet);
    let error = client.http_get(&location).expect_err("refused");
    assert_eq!(detail(&error), Some("HTTP 405"));
    let error = client.subscribe(PLAYER, &callback).expect_err("refused");
    assert_eq!(detail(&error), Some("SUBSCRIBE: HTTP 401"));
    assert!(quiet(&sink), "nothing is sent to the callback");
    let sent = tailnet.callback_report().expect("an eventing shim");
    assert_eq!(sent.offered, 0);
    assert_eq!(sent.subscribes_refused, 0);
    let report = tailnet.stop();
    assert_eq!(report.described, 0);
    assert_eq!(report.served, 2);
    assert!(report.reconciled());
}

#[test]
fn the_composed_client_reaches_nothing_but_the_one_fixture_player() {
    let sink = EventSink::start(loopback()).expect("a listener");
    let server = serve(&sink, Policy::LocalLink);
    let client = Composed::to(&server);
    let callback = sink.callback_url(TAG);

    // The permitted counterpart: the fixture player's description.
    assert!(client.http_get(&ssdp::description_url(PLAYER)).is_ok());
    // Another host, another URL and a look-alike are refused before the real client is touched, whatever the call.
    let elsewhere = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
    let away = ssdp::description_url(elsewhere);
    assert!(client.http_get(&away).is_err());
    let lookalike = format!("http://{PLAYER}:{}.invalid/", shim::PLAYER_PORT);
    assert!(client.http_get(&lookalike).is_err());
    assert!(get_volume(&client, elsewhere).is_err());
    assert!(client.subscribe(elsewhere, &callback).is_err());
    assert!(client.renew(elsewhere, "uuid:none", 300).is_err());
    assert!(client.unsubscribe(elsewhere, "uuid:none").is_err());

    // Nothing reached the shim for those: only the one description request was served, and no event was offered.
    let sent = server.callback_report().expect("an eventing shim");
    assert_eq!(sent.offered, 0);
    let report = server.stop();
    assert_eq!(report.accepted, 1);
    assert_eq!(report.described, 1);
}
