//! The REAL fsonos client's discovery, device-description and topology path against the REAL G03 endpoint, over loopback only
//! (`docs/contracts/g03.md` section 11 item 2).
//!
//! The client is `fsonos-proto` as the `fsonos` CLI and daemon use it: `Lan::ssdp_search` sends the client's own `M-SEARCH` and
//! collects the answers, `Transport::http_get` fetches the device description, `description::parse_device_description` and
//! `topology::get_zone_group_state` read it, and `control::get_volume` reaches the same device. Nothing is a double. The device is
//! `franken_control::fsonos::ssdp::Device` behind the speaker's loopback shim, started discoverable: its answers and its document
//! are the core's own, written by a loopback-only UDP responder and the shim's HTTP listener.
//!
//! Safety. `Lan` can also multicast, query mDNS and fetch any URL, and a request for any address it was not routed away from goes
//! to `ip:1400`. So the tests never hold a bare `Lan`: they hold [`Confined`], which is built only from a running discoverable shim
//! (so `Lan::with_ssdp_target` is always called, with the responder's loopback port, and no search can reach the multicast group),
//! forwards exactly three calls (a SOAP POST and a GET to the fixture player, and the SSDP search) and keeps the trait's `NotWired`
//! default for everything else. The fixture player is loopback itself, routed to the shim's ephemeral port, so a route that failed
//! to apply would dial `127.0.0.1:1400`, where nothing listens. A call for another host or URL is refused before the real client is
//! touched. The client reads no proxy environment variable.
//!
//! What this is not. It is not a device, the LAN or a speaker, and it makes no queue, playback or provider claim. The device
//! description the core builds has no `modelNumber` or `swGen`, so the client reads those as empty; and the fixture session's
//! coordinator is not among its members. Both are left as the core has them and are not asserted here.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use franken_speaker::fsonos_loopback as shim;
use fsonos_proto::net::Lan;
use fsonos_proto::{ProtoError, Transport, control, description, soap, ssdp, topology};
use shim::{DiscoveryIdentity, DiscoveryLimits, FsonosLoopback, LoopbackLimits, Policy};

const DEVICE: &str = shim::FIXTURE_DEVICE_UUID;
const NEIGHBOUR: &str = shim::FIXTURE_OTHER_UUID;
const THIRD: &str = "00000000-0000-4000-8000-00000000a003";
const ROOM: &str = shim::FIXTURE_ROOM;
const PLAYER: IpAddr = shim::FIXTURE_PLAYER_IP;
/// How long the real client collects answers. The responder answers at once, so this only bounds the wait.
const SEARCH_WAIT: Duration = Duration::from_millis(700);
/// How long a plain loopback socket waits for answers that may never come.
const RAW_WAIT: Duration = Duration::from_millis(300);

/// The real client, reachable only for what these tests exercise, and only toward the shim.
struct Confined {
    lan: Lan,
}

impl Confined {
    /// The real `Lan`, routed from the fixture player's address to the shim's HTTP port and pointed at the responder's UDP port.
    fn at(http: SocketAddr, search: SocketAddr) -> Self {
        let lan = Lan::with_timeout(Duration::from_secs(3)).expect("the real client starts");
        let routed = lan.with_routes(vec![(PLAYER, http)]);
        let lan = routed.with_ssdp_target(search);
        Self { lan }
    }

    fn to(server: &FsonosLoopback) -> Self {
        let search = server.discovery_addr().expect("a discoverable shim");
        Self::at(server.addr(), search)
    }
}

fn refused(what: &str) -> ProtoError {
    ProtoError::Network {
        target: what.to_string(),
        detail: "refused: not the loopback fixture's player".to_string(),
    }
}

/// Whether `url` names the fixture player on the player port: the only place a GET may go.
fn is_fixture_url(url: &str) -> bool {
    let prefix = format!("http://{PLAYER}:{}/", shim::PLAYER_PORT);
    url.starts_with(&prefix)
}

impl Transport for Confined {
    fn soap_post(
        &self,
        host: IpAddr,
        control_path: &str,
        soap_action: &str,
        body: &str,
    ) -> Result<String, ProtoError> {
        if host != PLAYER {
            return Err(refused(&host.to_string()));
        }
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

fn serve_as(identity: &DiscoveryIdentity, policy: Policy) -> FsonosLoopback {
    let session = shim::fixture_session_for(&identity.uuid, NEIGHBOUR).expect("a session");
    let limits = LoopbackLimits::standard();
    let discovery = DiscoveryLimits::standard();
    FsonosLoopback::start_discoverable(session, identity, policy, limits, discovery)
        .expect("the discoverable shim starts")
}

fn serve(policy: Policy) -> FsonosLoopback {
    serve_as(&DiscoveryIdentity::fixture(), policy)
}

/// Datagrams sent from a plain loopback socket to the responder, and every datagram it sends back within the bound.
fn exchange(to: SocketAddr, datagrams: &[String]) -> Vec<String> {
    let any = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let socket = UdpSocket::bind(any).expect("a client socket");
    let wait = Some(RAW_WAIT);
    socket.set_read_timeout(wait).expect("a read timeout");
    for datagram in datagrams {
        socket.send_to(datagram.as_bytes(), to).expect("sent");
    }
    let mut out = Vec::new();
    let mut buf = [0_u8; 2048];
    while out.len() < 32 {
        match socket.recv_from(&mut buf) {
            Ok((n, _)) => out.push(String::from_utf8_lossy(&buf[..n]).into_owned()),
            Err(_) => break,
        }
    }
    out
}

/// The responder's report once it has counted what it read (bounded wait).
fn settled(server: &FsonosLoopback) -> shim::DiscoveryReport {
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

/// What the real client learns about one device, end to end.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    usn: Option<String>,
    udn: String,
    room: String,
    location: String,
    members: Vec<String>,
}

fn survey(server: &FsonosLoopback) -> Seen {
    let client = Confined::to(server);
    let found = client.ssdp_search(1, SEARCH_WAIT).expect("a search");
    assert_eq!(found.len(), 1);
    let advert = found[0].clone();
    let document = client.http_get(&advert.location).expect("a description");
    let parsed = description::parse_device_description(&document).expect("a parse");
    let host = topology::host_of_location(&advert.location).expect("a host");
    let zones = topology::get_zone_group_state(&client, host).expect("a topology");
    let group = &zones.groups[0];
    let mut members: Vec<String> = group
        .members
        .iter()
        .map(|member| member.uuid.0.clone())
        .collect();
    members.sort();
    Seen {
        usn: advert.usn,
        udn: parsed.udn.0,
        room: parsed.room_name,
        location: advert.location,
        members,
    }
}

fn http_status(error: &ProtoError) -> Option<&str> {
    match error {
        ProtoError::Network { detail, .. } => Some(detail.as_str()),
        _ => None,
    }
}

#[test]
fn the_real_client_finds_reads_and_cross_checks_the_device_over_loopback() {
    let server = serve(Policy::LocalLink);
    let client = Confined::to(&server);
    let responder = server.discovery_addr().expect("a discoverable shim");
    assert!(responder.ip().is_loopback());

    // Discovery: one answer, for the type the client searches for, naming the location a player has.
    let found = client.ssdp_search(1, SEARCH_WAIT).expect("a search");
    assert_eq!(found.len(), 1);
    let advert = &found[0];
    assert_eq!(advert.st, ssdp::SONOS_ST);
    assert_eq!(advert.location, ssdp::description_url(PLAYER));
    let usn = format!("uuid:{DEVICE}::{}", ssdp::SONOS_ST);
    assert_eq!(advert.usn.as_deref(), Some(usn.as_str()));
    // A household and a boot counter are what a real player adds; this device invents neither.
    assert_eq!(advert.household, None);
    assert_eq!(advert.boot_seq, None);

    // Description: fetched from where the advert says, read by the client's own parser.
    let document = client.http_get(&advert.location).expect("a description");
    let parsed = description::parse_device_description(&document).expect("a parse");
    assert_eq!(parsed.udn.0, DEVICE);
    assert_eq!(parsed.model_name, "franken-speaker");
    // The room label is the one the client's own parser returns, not an empty default.
    assert_eq!(parsed.room_name, ROOM);
    assert!(parsed.is_renderer());
    assert!(parsed.has_service(soap::RENDERING_CONTROL.service_type));
    assert!(parsed.has_service(soap::GROUP_RENDERING_CONTROL.service_type));
    assert!(parsed.has_service(soap::AV_TRANSPORT.service_type));
    assert!(parsed.has_service(soap::ZONE_GROUP_TOPOLOGY.service_type));
    assert!(!parsed.has_service(soap::CONTENT_DIRECTORY.service_type));

    // Topology: asked of the host the advert names. It is the session's group, coordinator and members.
    let host = topology::host_of_location(&advert.location).expect("a host");
    assert_eq!(host, PLAYER);
    let zones = topology::get_zone_group_state(&client, host).expect("a topology");
    assert_eq!(zones.groups.len(), 1);
    let group = &zones.groups[0];
    let group_id = server.with_session(|s| format!("{}:{}", s.group_id, s.current_epoch));
    let coordinator = server.with_session(|s| s.coordinator_id.clone());
    let member_ids = server.with_session(|s| s.members.keys().cloned().collect::<Vec<_>>());
    assert_eq!(group.id, group_id);
    assert_eq!(group.coordinator.0, coordinator);
    let mut listed: Vec<String> = group.members.iter().map(|m| m.uuid.0.clone()).collect();
    listed.sort();
    assert_eq!(listed, member_ids);

    // The served member is the device the client found: same id, same location, the room, and an address it can route.
    let served = group
        .members
        .iter()
        .find(|member| member.uuid.0 == DEVICE)
        .expect("the served member");
    assert_eq!(served.uuid.0, parsed.udn.0);
    assert_eq!(served.location, advert.location);
    assert_eq!(served.zone_name, ROOM);
    assert_eq!(served.ip(), Some(PLAYER));
    // Its neighbour is listed from the session and has no location to show.
    let neighbour = group
        .members
        .iter()
        .find(|member| member.uuid.0 == NEIGHBOUR)
        .expect("the neighbour");
    assert_eq!(neighbour.location, "");
    assert_eq!(neighbour.ip(), None);

    // The identity found is the one control reaches: the volume the client reads is the live session's.
    let volume = control::get_volume(&client, host).expect("a volume");
    let live = server.with_session(|s| s.members[DEVICE].volume_0_to_100);
    assert_eq!(volume, live);

    // Both sides counted what they did.
    let heard = settled(&server);
    assert_eq!(heard.answered, heard.received);
    assert_eq!(heard.replies_sent, heard.answered);
    assert_eq!(heard.silent + heard.foreign + heard.failed, 0);
    assert!(heard.refusals.is_empty());
    let report = server.stop();
    assert_eq!(report.described, 1);
    assert_eq!(report.served, 2);
    assert_eq!(report.refused + report.dropped, 0);
    assert!(report.reconciled());
}

#[test]
fn only_the_zone_player_answer_is_a_player_for_the_client_and_other_services_are_silent() {
    let server = serve(Policy::LocalLink);
    let to = server.discovery_addr().expect("a discoverable shim");

    // The client's own search with the target widened to everything: the core answers with every target it advertises.
    let everything = ssdp::m_search(1).replace(ssdp::SONOS_ST, "ssdp:all");
    let answers = exchange(to, &[everything]);
    let adverts: Vec<ssdp::Advert> = answers
        .iter()
        .filter_map(|answer| ssdp::parse_response(answer.as_bytes()))
        .collect();
    assert!(adverts.len() > 1);
    assert_eq!(adverts.len(), answers.len());
    let location = ssdp::description_url(PLAYER);
    assert!(adverts.iter().all(|advert| advert.location == location));
    // But only one of them is a ZonePlayer, which is the one answer the client keeps.
    let players = adverts
        .iter()
        .filter(|advert| advert.st.eq_ignore_ascii_case(ssdp::SONOS_ST))
        .count();
    assert_eq!(players, 1);

    // A service the core does not serve gets silence within the bound, and the client's own search beside it finds the player.
    let wanted = soap::CONTENT_DIRECTORY.service_type;
    let catalog = ssdp::m_search(1).replace(ssdp::SONOS_ST, wanted);
    assert!(exchange(to, &[catalog]).is_empty());
    let client = Confined::to(&server);
    let found = client.ssdp_search(1, SEARCH_WAIT).expect("a search");
    assert_eq!(found.len(), 1);

    let heard = settled(&server);
    assert_eq!(heard.silent, 1);
    assert!(heard.answered >= 2);
    assert!(heard.refusals.is_empty());
    assert!(heard.reconciled());
}

#[test]
fn malformed_searches_get_no_answer_and_the_clients_own_search_still_finds_the_device() {
    let server = serve(Policy::LocalLink);
    let to = server.discovery_addr().expect("a discoverable shim");
    let good = ssdp::m_search(1);
    let no_quotes = good.replace("\"ssdp:discover\"", "ssdp:discover");
    let no_delay = good.replace("MX: 1", "MX: 0");
    let truncated = good.trim_end().to_string();
    assert!(exchange(to, &[no_quotes, no_delay, truncated]).is_empty());

    // The permitted counterpart: the same search, unbroken, through the real client.
    let client = Confined::to(&server);
    let found = client.ssdp_search(1, SEARCH_WAIT).expect("a search");
    assert_eq!(found.len(), 1);

    let mut heard = settled(&server);
    heard.refusals.sort_unstable();
    assert_eq!(heard.refusals, ["bad_man", "bad_mx", "unterminated"]);
    assert_eq!(heard.silent + heard.foreign + heard.failed, 0);
    assert!(heard.answered >= 1);
    assert!(heard.reconciled());
}

#[test]
fn a_restarted_device_keeps_its_identity_and_a_different_identity_is_a_different_device() {
    let first = serve(Policy::LocalLink);
    let before = survey(&first);
    assert_eq!(before.udn, DEVICE);
    let old_http = first.addr();
    let old_search = first.discovery_addr().expect("a responder");
    drop(first);

    // While it is down the client finds nothing, within the bound.
    let gone = Confined::at(old_http, old_search);
    let started = Instant::now();
    let found = gone.ssdp_search(1, SEARCH_WAIT).unwrap_or_default();
    assert!(found.is_empty());
    assert!(started.elapsed() < Duration::from_secs(5));

    // Restarted with the same identity on new sockets: the client sees the same device, in the same group, at the same location.
    let second = serve(Policy::LocalLink);
    assert_eq!(survey(&second), before);
    drop(second);

    // Another identity is another device: another id in the answer, the description and the topology.
    let other = DiscoveryIdentity {
        uuid: THIRD.to_string(),
        room: "Den".to_string(),
    };
    let third = serve_as(&other, Policy::LocalLink);
    let after = survey(&third);
    assert_eq!(after.udn, THIRD);
    assert_eq!(after.room, "Den");
    assert_eq!(before.room, ROOM);
    assert_ne!(after.usn, before.usn);
    assert_ne!(after.members, before.members);
    assert!(after.members.iter().all(|member| member.as_str() != DEVICE));
}

#[test]
fn a_tailnet_connection_is_refused_the_description_and_control_that_the_local_link_gets() {
    let local = serve(Policy::LocalLink);
    let client = Confined::to(&local);
    let location = ssdp::description_url(PLAYER);
    assert!(client.http_get(&location).is_ok());
    assert!(control::get_volume(&client, PLAYER).is_ok());
    drop(local);

    let tailnet = serve(Policy::UnauthenticatedTailnet);
    let client = Confined::to(&tailnet);
    // The GET is not a method the endpoint speaks, so it is answered with the bare 405 whatever the ingress; the control POST is 401.
    let error = client.http_get(&location).expect_err("refused");
    assert_eq!(http_status(&error), Some("HTTP 405"));
    let error = control::get_volume(&client, PLAYER).expect_err("refused");
    assert_eq!(http_status(&error), Some("HTTP 401"));
    let report = tailnet.stop();
    assert_eq!(report.described, 0);
    assert_eq!(report.served, 2);
    assert!(report.reconciled());
}

#[test]
fn the_confined_client_refuses_any_host_or_url_but_the_fixture_player() {
    let server = serve(Policy::LocalLink);
    let client = Confined::to(&server);
    // The permitted counterpart: the fixture player's description.
    assert!(client.http_get(&ssdp::description_url(PLAYER)).is_ok());
    let elsewhere = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
    let away = ssdp::description_url(elsewhere);
    assert!(client.http_get(&away).is_err());
    let lookalike = format!("http://{PLAYER}:{}.invalid/", shim::PLAYER_PORT);
    assert!(client.http_get(&lookalike).is_err());
    assert!(control::get_volume(&client, elsewhere).is_err());
    // Nothing reached the shim for those three: only the one description request was served.
    let report = server.stop();
    assert_eq!(report.accepted, 1);
    assert_eq!(report.described, 1);
}
