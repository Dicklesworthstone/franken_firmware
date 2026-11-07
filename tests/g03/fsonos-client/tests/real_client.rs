//! The REAL fsonos client library against the REAL G03 endpoint, over a bounded loopback socket (`docs/contracts/g03.md` section 11 item 1).
//!
//! The client here is `fsonos-proto` as the `fsonos` CLI and daemon use it: the `Lan` transport (the asupersync HTTP client) and the
//! `control` functions (`get_volume`, `set_volume`, `get_mute`, `set_mute`) that frame the SOAP call and parse the answer. Nothing is
//! a double. The endpoint is `franken_control::fsonos::Endpoint` behind the speaker's real control plane, reached through
//! `franken_speaker::fsonos_loopback`: one listener on `127.0.0.1`, bounded in connections, bytes and time.
//!
//! Safety. `Lan` can also do SSDP, mDNS and plain GETs, and a request for any address it was not routed away from goes to `ip:1400`.
//! So the tests never hold a bare `Lan`: they hold [`LoopbackOnly`], which forwards ONE call, a SOAP POST to the fixture player, and
//! keeps the trait's `NotWired` default for everything else. The fixture player is loopback itself, routed by `Lan::with_routes` to the
//! shim's ephemeral port, so a route that failed to apply would dial `127.0.0.1:1400`, where nothing listens, and nothing could leave
//! the host. A call for another host is refused before the real client is touched. The client reads no proxy environment variable.
//!
//! What this is not. It is not the `fsonos` CLI or daemon (they also discover, fetch the device description and read the topology,
//! which this endpoint does not serve yet: contract section 11 item 2), not a device, not the LAN, and not a speaker. It shows that
//! the client's own framing and parsing and the endpoint's answers agree on the wire for volume and mute, and that each refusal
//! arrives at the client as the error it is. Each refusal below is paired with the permitted call in the first test.

use std::net::IpAddr;
use std::time::Duration;

use franken_speaker::fsonos_loopback::{
    FIXTURE_MEMBER, FIXTURE_PLAYER_IP, FsonosLoopback, LoopbackLimits, Policy, fixture_session,
};
use fsonos_proto::control::{get_mute, get_volume, set_mute, set_volume};
use fsonos_proto::net::Lan;
use fsonos_proto::soap::{self, RENDERING_CONTROL, SoapResponse};
use fsonos_proto::{ProtoError, Transport};

/// The real client, reachable only for SOAP to the fixture player.
struct LoopbackOnly {
    lan: Lan,
}

impl LoopbackOnly {
    /// The real `Lan`, routed from the fixture player's address to the shim's loopback port. The route is the client's own test hook
    /// (`Lan::with_routes`); no discovery is ever started.
    fn to(server: &FsonosLoopback) -> Self {
        let lan = Lan::with_timeout(Duration::from_secs(3))
            .expect("the real client starts")
            .with_routes(vec![(FIXTURE_PLAYER_IP, server.addr())]);
        Self { lan }
    }
}

impl Transport for LoopbackOnly {
    fn soap_post(
        &self,
        host: IpAddr,
        control_path: &str,
        soap_action: &str,
        body: &str,
    ) -> Result<String, ProtoError> {
        if host != FIXTURE_PLAYER_IP {
            return Err(ProtoError::Network {
                target: host.to_string(),
                detail: "refused: not the loopback fixture's player".to_string(),
            });
        }
        self.lan.soap_post(host, control_path, soap_action, body)
    }
}

fn serve(policy: Policy) -> FsonosLoopback {
    let session = fixture_session().expect("the fixture session builds");
    FsonosLoopback::start(session, FIXTURE_MEMBER, policy, LoopbackLimits::standard())
        .expect("the loopback shim starts")
}

fn member_volume(server: &FsonosLoopback, member: &str) -> u8 {
    server.with_session(|session| session.members[member].volume_0_to_100)
}

fn member_muted(server: &FsonosLoopback, member: &str) -> bool {
    server.with_session(|session| session.members[member].muted)
}

/// A RenderingControl action through the real client's `soap::call`, for the ones its `control` functions cannot express (an argument
/// out of range, an action that does not exist).
fn rendering(
    client: &LoopbackOnly,
    action: &str,
    args: &[(&str, &str)],
) -> Result<SoapResponse, ProtoError> {
    soap::call(
        client,
        FIXTURE_PLAYER_IP,
        &RENDERING_CONTROL,
        action,
        &soap::args_xml(args),
    )
}

/// A raw SOAP POST through the real transport, for bodies the client's own functions would never build.
fn raw_post(client: &LoopbackOnly, control_path: &str, body: &str) -> Result<String, ProtoError> {
    client.soap_post(
        FIXTURE_PLAYER_IP,
        control_path,
        &soap::soap_action_header(&RENDERING_CONTROL, "SetVolume"),
        body,
    )
}

/// The `HTTP <status>` detail of a network error, or `None` for anything else.
fn http_status_detail(result: Result<String, ProtoError>) -> Option<String> {
    match result {
        Err(ProtoError::Network { detail, .. }) => Some(detail),
        _ => None,
    }
}

#[test]
fn the_real_client_reads_and_sets_volume_and_mute_on_the_real_endpoint_over_loopback() {
    let server = serve(Policy::LocalLink);
    let client = LoopbackOnly::to(&server);
    let ip = FIXTURE_PLAYER_IP;

    // The state the endpoint holds, read by the client as the client parses it.
    assert_eq!(get_volume(&client, ip).expect("a volume"), 50);
    assert_eq!(member_volume(&server, FIXTURE_MEMBER), 50);
    // A set the client frames is applied to the session, and the next read agrees with the session.
    set_volume(&client, ip, 37).expect("a set is acknowledged");
    assert_eq!(member_volume(&server, FIXTURE_MEMBER), 37);
    assert_eq!(get_volume(&client, ip).expect("a volume"), 37);
    // The client clamps a level above 100 itself, so the endpoint is asked for 100 and accepts it.
    set_volume(&client, ip, 250).expect("a clamped set is acknowledged");
    assert_eq!(member_volume(&server, FIXTURE_MEMBER), 100);
    // Mute, both ways.
    assert!(!get_mute(&client, ip).expect("a mute state"));
    set_mute(&client, ip, true).expect("a mute is acknowledged");
    assert!(member_muted(&server, FIXTURE_MEMBER));
    assert!(get_mute(&client, ip).expect("a mute state"));
    set_mute(&client, ip, false).expect("an unmute is acknowledged");
    assert!(!member_muted(&server, FIXTURE_MEMBER));
    assert!(!get_mute(&client, ip).expect("a mute state"));
    // Nothing leaked to the other member.
    assert_eq!(member_volume(&server, "den"), 50);
    assert!(!member_muted(&server, "den"));

    // Nine calls were made (five reads and four sets) and each was answered: the shim counted exactly those, and refused or dropped
    // nothing. A success the client reported without a response the shim wrote would make these differ.
    let report = server.stop();
    assert_eq!(report.accepted, 9);
    assert_eq!((report.served, report.refused, report.dropped), (9, 0, 0));
    assert!(report.reconciled());
}

#[test]
fn the_real_client_reports_each_refusal_as_the_error_it_is_and_nothing_changes() {
    let server = serve(Policy::LocalLink);
    let client = LoopbackOnly::to(&server);

    // An argument out of range: the endpoint's UPnP fault 402 arrives as the client's SoapFault.
    let args = [
        ("InstanceID", "0"),
        ("Channel", "Master"),
        ("DesiredVolume", "101"),
    ];
    let refused = rendering(&client, "SetVolume", &args).err();
    assert!(
        matches!(refused, Some(ProtoError::SoapFault { code: 402, .. })),
        "{refused:?}"
    );
    // An action the service does not have: UPnP 401.
    let refused = rendering(&client, "Frobnicate", &[("InstanceID", "0")]).err();
    assert!(
        matches!(refused, Some(ProtoError::SoapFault { code: 401, .. })),
        "{refused:?}"
    );
    // Not XML: the endpoint answers HTTP 400 with no UPnP body, which the client reports as a network error with that status.
    let detail = http_status_detail(raw_post(
        &client,
        RENDERING_CONTROL.control_path,
        "<not xml",
    ));
    assert_eq!(detail.as_deref(), Some("HTTP 400"));
    // A body over the endpoint's own limit: HTTP 413.
    let big = "a".repeat(9000);
    let detail = http_status_detail(raw_post(&client, RENDERING_CONTROL.control_path, &big));
    assert_eq!(detail.as_deref(), Some("HTTP 413"));
    // A path the endpoint does not serve: HTTP 404.
    let detail = http_status_detail(raw_post(&client, "/nowhere", "<x/>"));
    assert_eq!(detail.as_deref(), Some("HTTP 404"));

    // None of it changed the session.
    assert_eq!(member_volume(&server, FIXTURE_MEMBER), 50);
    assert!(!member_muted(&server, FIXTURE_MEMBER));
    // The permitted counterpart: the same client, afterwards, on the same endpoint, still reads and sets.
    assert_eq!(
        get_volume(&client, FIXTURE_PLAYER_IP).expect("a volume"),
        50
    );
    set_volume(&client, FIXTURE_PLAYER_IP, 20).expect("a set is acknowledged");
    assert_eq!(member_volume(&server, FIXTURE_MEMBER), 20);

    // Every request reached the endpoint, which answered it; the shim refused none of them itself.
    let report = server.stop();
    assert_eq!((report.served, report.refused, report.dropped), (7, 0, 0));
    assert!(report.reconciled());
}

#[test]
fn the_real_client_is_refused_on_an_unauthenticated_tailnet_connection() {
    let server = serve(Policy::UnauthenticatedTailnet);
    let client = LoopbackOnly::to(&server);

    // A read and a command both get HTTP 401 with no body: the client reports a network error with that status and no value.
    let read = get_volume(&client, FIXTURE_PLAYER_IP);
    assert!(
        matches!(&read, Err(ProtoError::Network { detail, .. }) if detail == "HTTP 401"),
        "{read:?}"
    );
    let set = set_volume(&client, FIXTURE_PLAYER_IP, 10);
    assert!(
        matches!(&set, Err(ProtoError::Network { detail, .. }) if detail == "HTTP 401"),
        "{set:?}"
    );
    assert_eq!(
        member_volume(&server, FIXTURE_MEMBER),
        50,
        "the command did not apply"
    );
    // The endpoint answered both; the shim refused nothing itself.
    let report = server.stop();
    assert_eq!((report.served, report.refused, report.dropped), (2, 0, 0));
    // The permitted counterpart is the first test: the same two calls on the local link succeed.
}

#[test]
fn with_no_listener_the_real_client_reports_a_network_error_and_never_a_success() {
    let server = serve(Policy::LocalLink);
    let client = LoopbackOnly::to(&server);
    assert_eq!(
        get_volume(&client, FIXTURE_PLAYER_IP).expect("a volume"),
        50
    );
    let report = server.stop();
    assert_eq!(report.served, 1);
    // The listener is gone: nothing can answer, and the client must not report a volume.
    let after = get_volume(&client, FIXTURE_PLAYER_IP);
    assert!(
        matches!(&after, Err(ProtoError::Network { .. })),
        "{after:?}"
    );
    let after = set_volume(&client, FIXTURE_PLAYER_IP, 5);
    assert!(
        matches!(&after, Err(ProtoError::Network { .. })),
        "{after:?}"
    );
}

#[test]
fn the_test_client_can_reach_only_the_fixture_player_and_has_no_discovery() {
    let server = serve(Policy::LocalLink);
    let client = LoopbackOnly::to(&server);

    // Another address is refused before the real client is touched: no connection reaches the shim.
    let elsewhere: IpAddr = "192.0.2.99".parse().expect("a literal address");
    let refused = get_volume(&client, elsewhere);
    let reason = match &refused {
        Err(ProtoError::Network { detail, .. }) => detail.as_str(),
        _ => "",
    };
    assert!(reason.starts_with("refused"), "{refused:?}");
    assert_eq!(server.report().accepted, 0);
    // Discovery and description fetches are not wired through it at all.
    assert!(matches!(
        client.ssdp_search(1, Duration::from_millis(1)),
        Err(ProtoError::NotWired(_))
    ));
    assert!(matches!(
        client.mdns_search(Duration::from_millis(1)),
        Err(ProtoError::NotWired(_))
    ));
    assert!(matches!(
        client.http_get("http://192.0.2.10:1400/xml/device_description.xml"),
        Err(ProtoError::NotWired(_))
    ));
    assert_eq!(
        server.report().accepted,
        0,
        "still nothing reached the shim"
    );
    // The permitted counterpart: the fixture player is reachable.
    assert_eq!(
        get_volume(&client, FIXTURE_PLAYER_IP).expect("a volume"),
        50
    );
    assert_eq!(server.stop().served, 1);
}
