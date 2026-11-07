//! The REAL fsonos client's GENA path against the REAL G03 endpoint, over loopback only (`docs/contracts/g03.md` section 11 item 5).
//!
//! The client is `fsonos-proto` as the `fsonos` CLI and daemon use it: `Lan::subscribe`, `Lan::renew` and `Lan::unsubscribe` speak to the
//! endpoint, `control::set_volume` and `control::set_mute` change the session, and `EventSink` is the client's own callback listener:
//! it receives the `NOTIFY` messages and parses them with `gena::parse_propertyset` and `Notify::last_change`. The endpoint is
//! `franken_control::fsonos::Endpoint` behind the speaker's loopback shim, started eventing: the notifications the core produces are
//! delivered by the shim's bounded delivery thread to the one allowed callback. Nothing here is a double; the only hand-written
//! listeners are the plain `std` ones that play a callback destination which must NOT be contacted, or one that stalls.
//!
//! Safety. `Lan` can also multicast, query mDNS and fetch any URL, and a request for any address it was not routed away from goes to
//! `ip:1400`. So the tests never hold a bare `Lan`: they hold [`Evented`], which is routed from the fixture player (loopback itself)
//! to the shim's ephemeral port, calls only `subscribe`, `renew` and `unsubscribe` on the RenderingControl event path of that player,
//! forwards a SOAP POST only to that player, and keeps the trait's `NotWired` default for everything else. A route that failed to
//! apply would dial `127.0.0.1:1400`, where nothing listens. The callback URL a test subscribes with is only text sent to the shim.
//!
//! What this is not. It is isolated host integration: no daemon, no speaker, no provider, no tailnet, and no claim about the real LAN.
//! Expiry and the `SEQ` wrap are the core's own tests and are not repeated here.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::thread;
use std::time::{Duration, Instant};

use franken_speaker::fsonos_loopback as shim;
use fsonos_proto::control::{get_volume, set_mute, set_volume};
use fsonos_proto::gena::{Notify, Subscription};
use fsonos_proto::net::{EventSink, Lan};
use fsonos_proto::soap::RENDERING_CONTROL;
use fsonos_proto::{ProtoError, Transport};
use shim::{
    CallbackLimits, CallbackReport, CallbackTarget, FsonosLoopback, LoopbackLimits, Policy,
};

const PLAYER: IpAddr = shim::FIXTURE_PLAYER_IP;
const MEMBER: &str = shim::FIXTURE_MEMBER;
const TAG: &str = "RenderingControl";
/// How long a test waits for an event it expects.
const EXPECT: Duration = Duration::from_secs(5);
/// How long a test waits before concluding that an event will not come.
const QUIET: Duration = Duration::from_millis(300);

/// The real client, reachable only for the RenderingControl events and SOAP of the fixture player.
struct Evented {
    lan: Lan,
}

impl Evented {
    /// The real `Lan`, routed from the fixture player's address to the shim's HTTP port. No discovery is ever started.
    fn to(server: &FsonosLoopback) -> Self {
        let lan = Lan::with_timeout(Duration::from_secs(3)).expect("the real client starts");
        let routed = lan.with_routes(vec![(PLAYER, server.addr())]);
        Self { lan: routed }
    }

    fn subscribe(&self, callback: &str) -> Result<Subscription, ProtoError> {
        let event_path = RENDERING_CONTROL.event_path;
        self.lan.subscribe(PLAYER, event_path, callback, 300)
    }

    fn renew(&self, sid: &str, timeout_secs: u32) -> Result<Subscription, ProtoError> {
        let event_path = RENDERING_CONTROL.event_path;
        self.lan.renew(PLAYER, event_path, sid, timeout_secs)
    }

    fn unsubscribe(&self, sid: &str) -> Result<(), ProtoError> {
        let event_path = RENDERING_CONTROL.event_path;
        self.lan.unsubscribe(PLAYER, event_path, sid)
    }
}

impl Transport for Evented {
    fn soap_post(
        &self,
        host: IpAddr,
        control_path: &str,
        soap_action: &str,
        body: &str,
    ) -> Result<String, ProtoError> {
        if host != PLAYER {
            return Err(ProtoError::Network {
                target: host.to_string(),
                detail: "refused: not the loopback fixture's player".to_string(),
            });
        }
        self.lan.soap_post(host, control_path, soap_action, body)
    }
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// An eventing shim over the fixture session whose one allowed callback is `addr` on `/RenderingControl`.
fn serve_at(addr: SocketAddr, events: CallbackLimits) -> FsonosLoopback {
    let session = shim::fixture_session().expect("the fixture session builds");
    let path = format!("/{TAG}");
    let target = CallbackTarget::new(addr, &path).expect("an allowed target");
    let limits = LoopbackLimits::standard();
    FsonosLoopback::start_eventing(session, MEMBER, Policy::LocalLink, limits, target, events)
        .expect("the eventing shim starts")
}

fn serve(sink: &EventSink, events: CallbackLimits) -> FsonosLoopback {
    serve_at(sink.local_addr(), events)
}

fn next(sink: &EventSink) -> Notify {
    sink.recv_timeout(EXPECT).expect("a NOTIFY")
}

fn quiet(sink: &EventSink) -> bool {
    sink.recv_timeout(QUIET).is_none()
}

/// The volume and mute the live session holds for the served member.
fn live(server: &FsonosLoopback) -> (u8, bool) {
    let volume = server.with_session(|s| s.members[MEMBER].volume_0_to_100);
    let muted = server.with_session(|s| s.members[MEMBER].muted);
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
fn settled(server: &FsonosLoopback) -> CallbackReport {
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

#[test]
fn the_real_client_subscribes_and_a_real_listener_receives_ordered_events() {
    let sink = EventSink::start(loopback()).expect("a listener");
    let server = serve(&sink, CallbackLimits::standard());
    let client = Evented::to(&server);
    let callback = sink.callback_url(TAG);

    // Subscribe: the core grants a SID, and the full state follows as SEQ 0, parsed by the client's own GENA parser.
    let sub = client.subscribe(&callback).expect("subscribed");
    assert!(sub.sid.starts_with("uuid:"));
    assert_eq!(sub.timeout_secs, 300);
    let first = next(&sink);
    assert_eq!(first.sid, sub.sid);
    assert_eq!(first.seq, 0);
    assert_eq!(first.path, format!("/{TAG}"));
    let (volume, muted) = live(&server);
    let state = changes(&first);
    assert_eq!(state.volume(), Some(volume));
    assert_eq!(state.mute(), Some(muted));
    let revision = server.with_session(|s| s.state_revision.to_string());
    let property = first.property("FrankenStateRevision");
    assert_eq!(property, Some(revision.as_str()));

    // A volume change reaches the listener as the next event: what changed, the live value, the next SEQ.
    set_volume(&client, PLAYER, 30).expect("a set");
    let second = next(&sink);
    assert_eq!(second.sid, sub.sid);
    assert_eq!(second.seq, 1);
    assert_eq!(changes(&second).volume(), Some(30));
    assert_eq!(changes(&second).mute(), None);
    assert_eq!(live(&server).0, 30);
    set_volume(&client, PLAYER, 31).expect("a set");
    let third = next(&sink);
    assert_eq!(third.seq, 2);
    assert_eq!(changes(&third).volume(), Some(31));
    set_mute(&client, PLAYER, true).expect("a mute");
    let fourth = next(&sink);
    assert_eq!(fourth.seq, 3);
    assert_eq!(changes(&fourth).mute(), Some(true));
    assert_eq!(changes(&fourth).volume(), None);
    assert_eq!(live(&server), (31, true));

    // A renewal keeps the same SID, grants the new time, and sends no event.
    let renewed = client.renew(&sub.sid, 600).expect("renewed");
    assert_eq!(renewed.sid, sub.sid);
    assert_eq!(renewed.timeout_secs, 600);
    assert!(quiet(&sink), "a renewal sends no event");

    // Unsubscribe ends it: a change after it reaches nobody, and the old SID is the core's 412 for a renewal and an unsubscribe.
    client.unsubscribe(&sub.sid).expect("unsubscribed");
    set_volume(&client, PLAYER, 40).expect("a set");
    assert!(quiet(&sink), "nothing is sent after unsubscribe");
    let error = client.renew(&sub.sid, 300).expect_err("an old SID");
    assert_eq!(detail(&error), Some("SUBSCRIBE: HTTP 412"));
    let error = client.unsubscribe(&sub.sid).expect_err("already gone");
    assert_eq!(detail(&error), Some("UNSUBSCRIBE: HTTP 412"));

    // Reconnect: a new SID, and its first event is the CURRENT full state, not a replay of what was missed.
    let again = client.subscribe(&callback).expect("subscribed again");
    assert_ne!(again.sid, sub.sid);
    let fresh = next(&sink);
    assert_eq!(fresh.sid, again.sid);
    assert_eq!(fresh.seq, 0);
    assert_eq!(changes(&fresh).volume(), Some(40));
    assert_eq!(changes(&fresh).mute(), Some(true));
    set_volume(&client, PLAYER, 41).expect("a set");
    let after = next(&sink);
    assert_eq!(after.sid, again.sid);
    assert_eq!(after.seq, 1);
    assert_eq!(changes(&after).volume(), Some(41));
    assert!(quiet(&sink), "the old SID is never heard again");

    // Both sides counted what they did: six events offered, six delivered, none refused, dropped or failed.
    let report = settled(&server);
    assert_eq!(report.offered, 6);
    assert_eq!(report.delivered, 6);
    let lost = report.refused + report.dropped + report.failed + report.unframed;
    assert_eq!(lost, 0);
    let http = server.stop();
    assert_eq!(http.refused + http.dropped, 0);
    assert!(http.reconciled());
}

#[test]
fn a_subscribe_naming_any_other_callback_is_answered_412_and_never_contacted() {
    let sink = EventSink::start(loopback()).expect("a listener");
    let other = TcpListener::bind(loopback()).expect("another listener");
    other.set_nonblocking(true).expect("nonblocking");
    let server = serve(&sink, CallbackLimits::standard());
    let client = Evented::to(&server);

    // Another loopback socket, the allowed socket on another path, and a callback that is not even the peer's own address. The
    // core alone would grant the first two (its rule is that the callback names the peer's address), and nothing could ever be
    // delivered to them; the shim answers the core's own 412 for a bad callback before the core is called.
    let other_addr = other.local_addr().expect("an address");
    let elsewhere = format!("http://{other_addr}/{TAG}");
    let wrong_path = sink.callback_url("AVTransport");
    let lan = "http://192.0.2.9:3400/RenderingControl".to_string();
    for callback in [&elsewhere, &wrong_path, &lan] {
        let error = client.subscribe(callback).expect_err("refused");
        assert_eq!(detail(&error), Some("SUBSCRIBE: HTTP 412"));
    }
    thread::sleep(QUIET);
    let contacted = other.accept().is_ok();
    assert!(!contacted, "the other destination was contacted");
    assert!(quiet(&sink), "wrong path contacted");
    let report = server.callback_report().expect("an eventing shim");
    assert_eq!(report.subscribes_refused, 3);
    assert_eq!(report.offered, 0);

    // The permitted counterpart on the same shim: the allowed callback is subscribed and receives its event.
    let allowed = sink.callback_url(TAG);
    let sub = client.subscribe(&allowed).expect("subscribed");
    let event = next(&sink);
    assert_eq!(event.sid, sub.sid);
    assert_eq!(event.seq, 0);
    let report = settled(&server);
    assert_eq!(report.offered, 1);
    assert_eq!(report.delivered, 1);
    assert_eq!(report.subscribes_refused, 3);

    // The shim's own report: three refusals, each a 412 and none of them reached the endpoint; the one subscribe did.
    let http = server.stop();
    assert_eq!(http.refused_statuses, [412, 412, 412]);
    assert_eq!(http.served, 1);
}

#[test]
fn a_restarted_shim_never_honours_an_old_sid_before_or_after_a_fresh_subscription() {
    let sink = EventSink::start(loopback()).expect("a listener");
    let callback = sink.callback_url(TAG);
    let first = serve(&sink, CallbackLimits::standard());
    let client = Evented::to(&first);
    let old = client.subscribe(&callback).expect("subscribed");
    assert_eq!(next(&sink).sid, old.sid);
    drop(client);
    drop(first);

    // Before any new subscription the restarted endpoint's table is empty: the old SID is the core's 412.
    let second = serve(&sink, CallbackLimits::standard());
    let client = Evented::to(&second);
    let error = client.renew(&old.sid, 300).expect_err("an old SID");
    assert_eq!(detail(&error), Some("SUBSCRIBE: HTTP 412"));
    let error = client.unsubscribe(&old.sid).expect_err("an old SID");
    assert_eq!(detail(&error), Some("UNSUBSCRIBE: HTTP 412"));
    assert!(quiet(&sink), "the old subscription is not heard again");

    // A fresh subscription takes its own SID. The boot's incarnation (ten bytes, 74 bits kept) comes from the host, so the first id
    // of this boot is not the first id of the last (they would be equal under one constant nonce, and then the old SID below would
    // be valid again).
    let fresh = client.subscribe(&callback).expect("subscribed afresh");
    assert_ne!(fresh.sid, old.sid, "two boots handed out the same SID");
    let event = next(&sink);
    assert_eq!(event.sid, fresh.sid);
    assert_eq!(event.seq, 0);

    // The counterexample, AFTER the fresh subscription: the old SID is retried and must change nothing.
    let error = client.unsubscribe(&old.sid).expect_err("an old SID");
    assert_eq!(detail(&error), Some("UNSUBSCRIBE: HTTP 412"));
    let error = client.renew(&old.sid, 600).expect_err("an old SID");
    assert_eq!(detail(&error), Some("SUBSCRIBE: HTTP 412"));

    // The permitted counterpart on the same shim: the fresh subscription is untouched. It still receives its events in order, its
    // own SID renews (the new time is granted) and unsubscribes, and only after that does a change reach nobody.
    set_volume(&client, PLAYER, 44).expect("a set");
    let change = next(&sink);
    assert_eq!(change.sid, fresh.sid);
    assert_eq!(change.seq, 1);
    assert_eq!(changes(&change).volume(), Some(44));
    let renewed = client.renew(&fresh.sid, 600).expect("renewed");
    assert_eq!(renewed.sid, fresh.sid);
    assert_eq!(renewed.timeout_secs, 600);
    client.unsubscribe(&fresh.sid).expect("unsubscribed");
    set_volume(&client, PLAYER, 45).expect("a set");
    assert!(quiet(&sink), "nothing is sent after the fresh unsubscribe");
}

#[test]
fn a_stalled_callback_is_bounded_and_counted_while_control_keeps_answering() {
    let quick = CallbackLimits {
        queue: 2,
        connect_timeout: Duration::from_millis(300),
        io_timeout: Duration::from_millis(150),
        ..CallbackLimits::standard()
    };

    // The permitted counterpart first: the same burst of changes to a healthy listener is delivered in order, with nothing failed.
    let sink = EventSink::start(loopback()).expect("a listener");
    let healthy = serve(&sink, quick);
    let client = Evented::to(&healthy);
    let callback = sink.callback_url(TAG);
    client.subscribe(&callback).expect("subscribed");
    for level in 10_u8..16 {
        set_volume(&client, PLAYER, level).expect("control answers");
    }
    let report = settled(&healthy);
    assert_eq!(report.delivered, report.queued);
    assert_eq!(report.failed, 0);
    let mut last = None;
    while let Some(event) = sink.recv_timeout(QUIET) {
        let in_order = last.is_none_or(|earlier| event.seq > earlier);
        assert!(in_order, "events arrive in SEQ order");
        last = Some(event.seq);
    }
    assert!(last.is_some());
    drop(healthy);

    // A callback that takes connections and never answers: control still answers, promptly, and every loss is counted.
    let stalled = TcpListener::bind(loopback()).expect("a stalled listener");
    let addr = stalled.local_addr().expect("an address");
    let server = serve_at(addr, quick);
    let client = Evented::to(&server);
    let callback = format!("http://{addr}/{TAG}");
    client.subscribe(&callback).expect("subscribed");
    let started = Instant::now();
    for level in 10_u8..22 {
        set_volume(&client, PLAYER, level).expect("control answers");
    }
    let took = started.elapsed();
    assert!(took < Duration::from_millis(1500), "slow: {took:?}");
    assert_eq!(get_volume(&client, PLAYER).expect("a volume"), 21);
    assert_eq!(live(&server).0, 21);

    let sent = server.callback_report().expect("an eventing shim");
    assert_eq!(sent.offered, 13);
    assert!(sent.dropped >= 1, "{sent:?}");
    let report = settled(&server);
    assert_eq!(report.delivered, 0);
    assert_eq!(report.failed, report.queued);
    assert_eq!(report.queued + report.dropped, report.offered);
}

#[test]
fn a_shim_not_started_eventing_still_grants_the_subscription_and_delivers_nothing() {
    let sink = EventSink::start(loopback()).expect("a listener");
    let session = shim::fixture_session().expect("the fixture session builds");
    let limits = LoopbackLimits::standard();
    let plain = FsonosLoopback::start(session, MEMBER, Policy::LocalLink, limits)
        .expect("the plain shim starts");
    assert!(plain.callback_report().is_none());
    let client = Evented::to(&plain);
    let callback = sink.callback_url(TAG);
    let sub = client.subscribe(&callback).expect("the core grants it");
    set_volume(&client, PLAYER, 20).expect("a set");
    assert!(sub.sid.starts_with("uuid:"));
    assert!(quiet(&sink), "a plain shim sends no event");
    drop(plain);

    // The permitted counterpart: the same subscription on an eventing shim is told.
    let server = serve(&sink, CallbackLimits::standard());
    let client = Evented::to(&server);
    let sub = client.subscribe(&callback).expect("subscribed");
    let event = next(&sink);
    assert_eq!(event.sid, sub.sid);
    assert_eq!(event.seq, 0);
}
