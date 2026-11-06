//! GENA eventing: a bounded subscription table and the property-set bodies it sends (G03 / `ffw-xvv`).
//!
//! The controller side (`fsonos-proto` rev `775b08dc`) subscribes with `CALLBACK`, `NT: upnp:event` and
//! `TIMEOUT: Second-N`, reads `SID` and `TIMEOUT` back, renews with `SID` and `TIMEOUT` only, and
//! receives `NOTIFY` bodies shaped `<e:propertyset>` with `SEQ` 0 for the initial full state and +1
//! after. `AVTransport` and `RenderingControl` carry their changes in a `LastChange` document;
//! `GroupRenderingControl` and `ZoneGroupTopology` send plain properties. This module produces exactly
//! those, and nothing is sent anywhere: [`Notification`] values are returned to the owner.
//!
//! # What is bounded, and what is refused
//!
//! * **The table** holds at most `max_subscriptions`; the next subscribe is `TableFull`. An expired
//!   subscription is removed the next time anything touches the table, and frees its place.
//! * **The callback** must be exactly one `http://` URL whose host is an IP literal **equal to the
//!   address the request came from** (no name to resolve, no userinfo, a real port). UPnP lets a
//!   subscriber name another host; this endpoint does not, so it cannot be made to send notifications
//!   to a third party.
//! * **Timeouts** are clamped to `[min, max]`. An unbounded request, `Second-infinite` (the UPnP spelling), the bare word
//!   `infinite`, or a missing header, is granted the default: this endpoint never grants forever.
//! * A renewal that carries `CALLBACK` or `NT` is refused; a renewal of an unknown, expired or
//!   other-service `SID` is `412`, so the controller subscribes afresh.
//!
//! # Events carry the state revision
//!
//! Every body carries `FrankenStateRevision` and `FrankenEpoch` as extra plain properties (a controller
//! that does not know them ignores them), so a controller can tell which committed state an event
//! describes, and notice a revision it missed.
//!
//! # Per-subscriber deltas, SEQ and duplicates
//!
//! Each subscription remembers what it was last told. An event holds only what changed since then, so
//! a subscriber that joined late, or whose earlier events were never produced because nothing called
//! [`SubscriptionTable::publish`], still gets a consistent stream. Publishing an unchanged state sends
//! nothing. `SEQ` is 0 for the initial event and then counts up; after `u32::MAX` it wraps to **1**,
//! never back to 0, which is reserved for the initial full-state event.

use std::net::IpAddr;
use std::str::FromStr;

use sha2::{Digest, Sha256};

use super::soap::{GENA_EVENT_NS, Service};
use super::state::{EventState, TransportState};
use super::xml::{Escape, escape};

/// The `SEQ` after `u32::MAX`.
pub const SEQ_AFTER_WRAP: u32 = 1;

const RCS_NS: &str = "urn:schemas-upnp-org:metadata-1-0/RCS/";
const AVT_NS: &str = "urn:schemas-upnp-org:metadata-1-0/AVT/";

/// Bounds for the table. **Provisional**: the bead names no numbers and none has been measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenaConfig {
    pub max_subscriptions: usize,
    pub min_timeout_secs: u32,
    pub default_timeout_secs: u32,
    pub max_timeout_secs: u32,
    pub max_callback_len: usize,
}

impl GenaConfig {
    #[must_use]
    pub const fn provisional() -> Self {
        Self {
            max_subscriptions: 16,
            min_timeout_secs: 30,
            default_timeout_secs: 300,
            max_timeout_secs: 3_600,
            max_callback_len: 256,
        }
    }
}

/// A subscribe, renew or unsubscribe that was refused. The words are fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GenaError {
    /// HTTP 400: a header combination or value that cannot be what was meant.
    #[error("bad request: {0}")]
    BadRequest(&'static str),
    /// HTTP 412: no usable `CALLBACK` or `NT`, or a `SID` that is unknown, expired or for another
    /// service. The controller subscribes afresh.
    #[error("precondition failed")]
    PreconditionFailed,
    /// HTTP 501: this service has no events here.
    #[error("this service has no events")]
    NotSupported,
    /// HTTP 503: the table is full.
    #[error("the subscription table is full")]
    TableFull,
}

impl GenaError {
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::PreconditionFailed => 412,
            Self::NotSupported => 501,
            Self::TableFull => 503,
        }
    }
}

/// What a successful subscribe or renew tells the controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeGrant {
    pub sid: String,
    pub timeout_secs: u32,
}

impl SubscribeGrant {
    #[must_use]
    pub fn headers(&self) -> Vec<(String, String)> {
        vec![
            ("SID".to_string(), self.sid.clone()),
            (
                "TIMEOUT".to_string(),
                format!("Second-{}", self.timeout_secs),
            ),
        ]
    }
}

/// One `NOTIFY` to send. Nothing here sends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub sid: String,
    pub service: Service,
    pub callback: String,
    pub seq: u32,
    pub body: String,
}

impl Notification {
    #[must_use]
    pub fn headers(&self) -> Vec<(String, String)> {
        vec![
            ("NT".to_string(), "upnp:event".to_string()),
            ("NTS".to_string(), "upnp:propchange".to_string()),
            ("SID".to_string(), self.sid.clone()),
            ("SEQ".to_string(), self.seq.to_string()),
            (
                "CONTENT-TYPE".to_string(),
                "text/xml; charset=\"utf-8\"".to_string(),
            ),
        ]
    }
}

/// What one subscriber was last told, compactly: the topology is kept as a digest, not a copy.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Told {
    volume: Option<u8>,
    mute: Option<bool>,
    group_volume: u8,
    group_mute: bool,
    transport: TransportState,
    topology: [u8; 8],
}

fn digest8(text: &str) -> [u8; 8] {
    let full = Sha256::digest(text.as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&full[..8]);
    out
}

impl Told {
    fn of(state: &EventState) -> Self {
        Self {
            volume: state.volume,
            mute: state.mute,
            group_volume: state.group_volume,
            group_mute: state.group_mute,
            transport: state.transport,
            topology: digest8(&state.zone_group_state),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    sid: String,
    service: Service,
    callback: String,
    expires_at_ns: u64,
    next_seq: u32,
    told: Told,
}

/// The variables an event can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Var {
    Volume(u8),
    Mute(bool),
    GroupVolume(u8),
    GroupMute(bool),
    Transport(TransportState),
    Topology,
}

const NS_PER_SEC: u64 = 1_000_000_000;

/// The bounded table of subscriptions.
#[derive(Debug)]
pub struct SubscriptionTable {
    config: GenaConfig,
    nonce: u32,
    counter: u64,
    entries: Vec<Entry>,
    expired_total: u64,
}

impl SubscriptionTable {
    /// `nonce` makes this table's subscription ids differ from another table's, so a controller that
    /// reconnects to a restarted endpoint cannot renew an old id by accident.
    #[must_use]
    pub fn new(config: GenaConfig, nonce: u32) -> Self {
        Self {
            config,
            nonce,
            counter: 0,
            entries: Vec::new(),
            expired_total: 0,
        }
    }

    #[must_use]
    pub const fn config(&self) -> &GenaConfig {
        &self.config
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many subscriptions have lapsed over the table's life.
    #[must_use]
    pub const fn expired_total(&self) -> u64 {
        self.expired_total
    }

    /// Remove every subscription whose time has come. Returns how many.
    pub fn expire(&mut self, now_ns: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| now_ns < e.expires_at_ns);
        let gone = before - self.entries.len();
        self.expired_total = self.expired_total.saturating_add(gone as u64);
        gone
    }

    /// The timeout to grant for a `TIMEOUT` header: clamped to the bounds; an unbounded request
    /// (`Second-infinite`, or the bare word `infinite`) or no header is the default; anything else that is
    /// not `Second-<n>` is refused.
    fn grant_timeout(&self, header: Option<&str>) -> Result<u32, GenaError> {
        let secs = match header.map(str::trim) {
            None => self.config.default_timeout_secs,
            Some(v) if v.eq_ignore_ascii_case("infinite") || is_second_infinite(v) => {
                self.config.default_timeout_secs
            }
            Some(v) => v
                .strip_prefix("Second-")
                .and_then(|n| n.parse::<u32>().ok())
                .ok_or(GenaError::BadRequest("TIMEOUT is not Second-<n>"))?,
        };
        Ok(secs.clamp(self.config.min_timeout_secs, self.config.max_timeout_secs))
    }

    fn next_sid(&mut self) -> String {
        self.counter += 1;
        format!(
            "uuid:{:08x}-0000-4000-8000-{:012x}",
            self.nonce, self.counter
        )
    }

    /// A new subscription. `peer` is the address the request came from; the callback must name it.
    /// On success: the grant, and the initial full-state event (`SEQ` 0) to send after the response.
    pub fn subscribe(
        &mut self,
        now_ns: u64,
        service: Service,
        peer: IpAddr,
        headers: &SubscribeHeaders<'_>,
        state: &EventState,
    ) -> Result<(SubscribeGrant, Notification), GenaError> {
        if service == Service::ContentDirectory {
            return Err(GenaError::NotSupported);
        }
        self.expire(now_ns);
        if headers.nt != Some("upnp:event") {
            return Err(GenaError::PreconditionFailed);
        }
        let callback = headers
            .callback
            .ok_or(GenaError::PreconditionFailed)
            .and_then(|c| parse_callback(c, peer, self.config.max_callback_len))?;
        let timeout_secs = self.grant_timeout(headers.timeout)?;
        if self.entries.len() >= self.config.max_subscriptions {
            return Err(GenaError::TableFull);
        }
        let sid = self.next_sid();
        let initial = Notification {
            sid: sid.clone(),
            service,
            callback: callback.clone(),
            seq: 0,
            body: event_body(service, &full_vars(service, state), state),
        };
        self.entries.push(Entry {
            sid: sid.clone(),
            service,
            callback,
            expires_at_ns: now_ns.saturating_add(u64::from(timeout_secs) * NS_PER_SEC),
            next_seq: 1,
            told: Told::of(state),
        });
        Ok((SubscribeGrant { sid, timeout_secs }, initial))
    }

    /// Renew `sid`: the new timeout runs from `now`, not from the old expiry.
    pub fn renew(
        &mut self,
        now_ns: u64,
        service: Service,
        sid: &str,
        headers: &SubscribeHeaders<'_>,
    ) -> Result<SubscribeGrant, GenaError> {
        if headers.callback.is_some() || headers.nt.is_some() {
            return Err(GenaError::BadRequest(
                "a renewal carries a SID and no CALLBACK or NT",
            ));
        }
        self.expire(now_ns);
        let timeout_secs = self.grant_timeout(headers.timeout)?;
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.sid == sid && e.service == service)
            .ok_or(GenaError::PreconditionFailed)?;
        entry.expires_at_ns = now_ns.saturating_add(u64::from(timeout_secs) * NS_PER_SEC);
        Ok(SubscribeGrant {
            sid: entry.sid.clone(),
            timeout_secs,
        })
    }

    /// End `sid`. An unknown or already-expired id is `412`, as a renewal would be.
    pub fn unsubscribe(
        &mut self,
        now_ns: u64,
        service: Service,
        sid: &str,
    ) -> Result<(), GenaError> {
        self.expire(now_ns);
        let before = self.entries.len();
        self.entries
            .retain(|e| !(e.sid == sid && e.service == service));
        if self.entries.len() == before {
            Err(GenaError::PreconditionFailed)
        } else {
            Ok(())
        }
    }

    /// Bring every live subscriber up to `state`: for each, an event holding what changed since it
    /// was last told, or nothing if nothing did.
    pub fn publish(&mut self, now_ns: u64, state: &EventState) -> Vec<Notification> {
        self.expire(now_ns);
        let now_told = Told::of(state);
        let mut out = Vec::new();
        for entry in &mut self.entries {
            let vars = changed_vars(entry.service, &entry.told, &now_told, state);
            if vars.is_empty() {
                continue;
            }
            out.push(Notification {
                sid: entry.sid.clone(),
                service: entry.service,
                callback: entry.callback.clone(),
                seq: entry.next_seq,
                body: event_body(entry.service, &vars, state),
            });
            entry.next_seq = if entry.next_seq == u32::MAX {
                SEQ_AFTER_WRAP
            } else {
                entry.next_seq + 1
            };
            entry.told = now_told.clone();
        }
        out
    }

    /// Make the next event of every subscription carry `seq`, to exercise the wrap.
    #[cfg(test)]
    pub(crate) fn set_next_seq(&mut self, seq: u32) {
        for entry in &mut self.entries {
            entry.next_seq = seq;
        }
    }
}

/// `Second-infinite`: how the UPnP device architecture spells an unbounded subscription (`TIMEOUT: Second-`
/// followed by an integer or `infinite`). The unit is spelled as for every other `TIMEOUT` here; the word may
/// be in any case; nothing may follow it.
fn is_second_infinite(value: &str) -> bool {
    value
        .strip_prefix("Second-")
        .is_some_and(|rest| rest.eq_ignore_ascii_case("infinite"))
}

/// The headers of a SUBSCRIBE request, by name, as the transport read them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SubscribeHeaders<'a> {
    pub callback: Option<&'a str>,
    pub nt: Option<&'a str>,
    pub timeout: Option<&'a str>,
}

/// `<http://ip[:port]/path>`: exactly one URL, an IP literal equal to `peer`, a real port.
fn parse_callback(header: &str, peer: IpAddr, max_len: usize) -> Result<String, GenaError> {
    let fail = Err(GenaError::PreconditionFailed);
    let header = header.trim();
    if header.len() > max_len {
        return fail;
    }
    let Some(url) = header.strip_prefix('<').and_then(|h| h.strip_suffix('>')) else {
        return fail;
    };
    if url.contains(['<', '>']) {
        return fail; // more than one URL, or stray brackets
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return fail;
    };
    if !url.bytes().all(|b| b.is_ascii_graphic()) {
        return fail;
    }
    let (authority, _path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    if authority.is_empty() || authority.contains('@') {
        return fail;
    }
    let (host, port) = match authority.strip_prefix('[') {
        Some(v6) => {
            let Some((host, tail)) = v6.split_once(']') else {
                return fail;
            };
            (host, tail.strip_prefix(':'))
        }
        None => match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    if let Some(port) = port {
        match port.parse::<u16>() {
            Ok(p) if p > 0 => {}
            _ => return fail,
        }
    }
    match IpAddr::from_str(host) {
        Ok(address) if address == peer => Ok(url.to_string()),
        _ => fail,
    }
}

fn full_vars(service: Service, state: &EventState) -> Vec<Var> {
    match service {
        Service::RenderingControl => state
            .volume
            .map(Var::Volume)
            .into_iter()
            .chain(state.mute.map(Var::Mute))
            .collect(),
        Service::GroupRenderingControl => vec![
            Var::GroupVolume(state.group_volume),
            Var::GroupMute(state.group_mute),
        ],
        Service::AvTransport => vec![Var::Transport(state.transport)],
        Service::ZoneGroupTopology => vec![Var::Topology],
        Service::ContentDirectory => Vec::new(),
    }
}

fn changed_vars(service: Service, was: &Told, now: &Told, state: &EventState) -> Vec<Var> {
    let mut vars = Vec::new();
    match service {
        Service::RenderingControl => {
            if was.volume != now.volume
                && let Some(v) = state.volume
            {
                vars.push(Var::Volume(v));
            }
            if was.mute != now.mute
                && let Some(m) = state.mute
            {
                vars.push(Var::Mute(m));
            }
        }
        Service::GroupRenderingControl => {
            if was.group_volume != now.group_volume {
                vars.push(Var::GroupVolume(state.group_volume));
            }
            if was.group_mute != now.group_mute {
                vars.push(Var::GroupMute(state.group_mute));
            }
        }
        Service::AvTransport => {
            if was.transport != now.transport {
                vars.push(Var::Transport(state.transport));
            }
        }
        Service::ZoneGroupTopology => {
            if was.topology != now.topology {
                vars.push(Var::Topology);
            }
        }
        Service::ContentDirectory => {}
    }
    vars
}

/// The `LastChange` document for the variables of an RCS or AVT event.
fn last_change(ns: &str, items: &[String]) -> String {
    format!(
        "<Event xmlns=\"{ns}\"><InstanceID val=\"0\">{}</InstanceID></Event>",
        items.concat()
    )
}

fn property(name: &str, value: &str) -> String {
    format!(
        "<e:property><{name}>{}</{name}></e:property>",
        escape(value, Escape::Text)
    )
}

/// The `NOTIFY` body for `vars` of `service`, and the revision it describes.
fn event_body(service: Service, vars: &[Var], state: &EventState) -> String {
    let mut props = String::new();
    match service {
        Service::RenderingControl => {
            let items: Vec<String> = vars
                .iter()
                .filter_map(|v| match v {
                    Var::Volume(n) => Some(format!("<Volume channel=\"Master\" val=\"{n}\"/>")),
                    Var::Mute(m) => Some(format!(
                        "<Mute channel=\"Master\" val=\"{}\"/>",
                        u8::from(*m)
                    )),
                    _ => None,
                })
                .collect();
            props.push_str(&property("LastChange", &last_change(RCS_NS, &items)));
        }
        Service::AvTransport => {
            let items: Vec<String> = vars
                .iter()
                .filter_map(|v| match v {
                    Var::Transport(t) => Some(format!("<TransportState val=\"{}\"/>", t.as_str())),
                    _ => None,
                })
                .collect();
            props.push_str(&property("LastChange", &last_change(AVT_NS, &items)));
        }
        Service::GroupRenderingControl => {
            for var in vars {
                match var {
                    Var::GroupVolume(n) => props.push_str(&property("GroupVolume", &n.to_string())),
                    Var::GroupMute(m) => {
                        props.push_str(&property("GroupMute", &u8::from(*m).to_string()));
                    }
                    _ => {}
                }
            }
        }
        Service::ZoneGroupTopology => {
            if vars.contains(&Var::Topology) {
                props.push_str(&property("ZoneGroupState", &state.zone_group_state));
            }
        }
        Service::ContentDirectory => {}
    }
    props.push_str(&property(
        "FrankenStateRevision",
        &state.revision.to_string(),
    ));
    props.push_str(&property("FrankenEpoch", &state.epoch.to_string()));
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <e:propertyset xmlns:e=\"{GENA_EVENT_NS}\">{props}</e:propertyset>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsonos::xml::{Event, XmlLimits, XmlReader};

    const SEC: u64 = NS_PER_SEC;

    fn state() -> EventState {
        EventState {
            epoch: 10,
            revision: 2,
            volume: Some(50),
            mute: Some(false),
            group_volume: 50,
            group_mute: false,
            transport: TransportState::NoMediaPresent,
            zone_group_state: "<ZoneGroupState><ZoneGroups/></ZoneGroupState>".to_string(),
        }
    }

    fn peer() -> IpAddr {
        "192.0.2.10".parse().unwrap()
    }

    fn table() -> SubscriptionTable {
        SubscriptionTable::new(GenaConfig::provisional(), 0x5a5a_0001)
    }

    fn headers<'a>(callback: &'a str, timeout: Option<&'a str>) -> SubscribeHeaders<'a> {
        SubscribeHeaders {
            callback: Some(callback),
            nt: Some("upnp:event"),
            timeout,
        }
    }

    const CALLBACK: &str = "<http://192.0.2.10:3400/notify>";

    fn subscribe(
        t: &mut SubscriptionTable,
        now: u64,
        service: Service,
    ) -> (SubscribeGrant, Notification) {
        t.subscribe(
            now,
            service,
            peer(),
            &headers(CALLBACK, Some("Second-300")),
            &state(),
        )
        .expect("subscribes")
    }

    /// The text of every element of a body, by name, using the bounded reader.
    fn properties(body: &str) -> Vec<(String, String)> {
        let mut reader = XmlReader::new(
            body.as_bytes(),
            XmlLimits {
                max_bytes: 16 * 1024,
                max_value_len: 8 * 1024,
                ..XmlLimits::soap_request()
            },
        )
        .expect("within bounds");
        let mut out = Vec::new();
        let mut current: Option<String> = None;
        while let Some(event) = reader.next_event().expect("well formed") {
            match event {
                Event::Start { name, .. } if name != "e:propertyset" && name != "e:property" => {
                    current = Some(name);
                }
                Event::Text(text) => {
                    if let Some(name) = current.take() {
                        out.push((name, text));
                    }
                }
                _ => {}
            }
        }
        out
    }

    #[test]
    fn a_subscription_is_granted_with_an_id_a_timeout_and_the_full_initial_state() {
        let mut t = table();
        let (grant, initial) = subscribe(&mut t, 0, Service::RenderingControl);
        assert_eq!(grant.sid, "uuid:5a5a0001-0000-4000-8000-000000000001");
        assert_eq!(grant.timeout_secs, 300);
        assert_eq!(
            grant.headers(),
            vec![
                ("SID".to_string(), grant.sid.clone()),
                ("TIMEOUT".to_string(), "Second-300".to_string())
            ]
        );
        assert_eq!(
            (initial.seq, initial.sid.as_str(), initial.callback.as_str()),
            (0, grant.sid.as_str(), "http://192.0.2.10:3400/notify")
        );
        assert_eq!(
            initial.body,
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
             <e:propertyset xmlns:e=\"urn:schemas-upnp-org:event-1-0\">\
             <e:property><LastChange>&lt;Event xmlns=\"urn:schemas-upnp-org:metadata-1-0/RCS/\"&gt;\
             &lt;InstanceID val=\"0\"&gt;&lt;Volume channel=\"Master\" val=\"50\"/&gt;\
             &lt;Mute channel=\"Master\" val=\"0\"/&gt;&lt;/InstanceID&gt;&lt;/Event&gt;</LastChange></e:property>\
             <e:property><FrankenStateRevision>2</FrankenStateRevision></e:property>\
             <e:property><FrankenEpoch>10</FrankenEpoch></e:property></e:propertyset>"
        );
        assert_eq!(
            initial.headers(),
            vec![
                ("NT".to_string(), "upnp:event".to_string()),
                ("NTS".to_string(), "upnp:propchange".to_string()),
                ("SID".to_string(), grant.sid.clone()),
                ("SEQ".to_string(), "0".to_string()),
                (
                    "CONTENT-TYPE".to_string(),
                    "text/xml; charset=\"utf-8\"".to_string()
                ),
            ]
        );
    }

    #[test]
    fn each_service_sends_the_variables_the_controller_side_reads() {
        let mut t = table();
        let rcs = properties(&subscribe(&mut t, 0, Service::RenderingControl).1.body);
        assert_eq!(rcs[0].0, "LastChange");
        assert!(rcs[0].1.contains("<Volume channel=\"Master\" val=\"50\"/>"));
        let grc = properties(&subscribe(&mut t, 0, Service::GroupRenderingControl).1.body);
        assert_eq!(
            grc.iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("GroupVolume", "50"),
                ("GroupMute", "0"),
                ("FrankenStateRevision", "2"),
                ("FrankenEpoch", "10")
            ]
        );
        let avt = properties(&subscribe(&mut t, 0, Service::AvTransport).1.body);
        assert!(
            avt[0]
                .1
                .contains("<TransportState val=\"NO_MEDIA_PRESENT\"/>")
        );
        assert!(avt[0].1.contains("urn:schemas-upnp-org:metadata-1-0/AVT/"));
        let zgt = properties(&subscribe(&mut t, 0, Service::ZoneGroupTopology).1.body);
        assert_eq!(
            zgt[0],
            ("ZoneGroupState".to_string(), state().zone_group_state)
        );
    }

    #[test]
    fn the_legacy_content_catalog_has_no_events() {
        let mut t = table();
        assert_eq!(
            t.subscribe(
                0,
                Service::ContentDirectory,
                peer(),
                &headers(CALLBACK, None),
                &state()
            )
            .err(),
            Some(GenaError::NotSupported)
        );
        assert!(t.is_empty());
    }

    #[test]
    fn timeouts_are_clamped_and_the_default_stands_in_for_infinite_or_none() {
        let t = table();
        let c = GenaConfig::provisional();
        assert_eq!(t.grant_timeout(Some("Second-300")), Ok(300));
        assert_eq!(t.grant_timeout(Some(" Second-300 ")), Ok(300));
        assert_eq!(t.grant_timeout(None), Ok(c.default_timeout_secs));
        assert_eq!(
            t.grant_timeout(Some("infinite")),
            Ok(c.default_timeout_secs)
        );
        assert_eq!(
            t.grant_timeout(Some("INFINITE")),
            Ok(c.default_timeout_secs)
        );
        assert_eq!(t.grant_timeout(Some("Second-1")), Ok(c.min_timeout_secs));
        assert_eq!(t.grant_timeout(Some("Second-0")), Ok(c.min_timeout_secs));
        assert_eq!(
            t.grant_timeout(Some("Second-99999")),
            Ok(c.max_timeout_secs)
        );
        assert_eq!(
            t.grant_timeout(Some("Second-4294967295")),
            Ok(c.max_timeout_secs)
        );
        for bad in [
            "Second-",
            "Second--1",
            "Second-x",
            "Seconds-30",
            "30",
            "",
            "Second-4294967296",
        ] {
            assert!(
                matches!(t.grant_timeout(Some(bad)), Err(GenaError::BadRequest(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn second_infinite_is_the_upnp_spelling_of_an_unbounded_request_and_gets_the_default() {
        let t = table();
        let default = GenaConfig::provisional().default_timeout_secs;
        for ok in [
            "Second-infinite",
            " Second-infinite ",
            "Second-Infinite",
            "Second-INFINITE",
            "infinite",
        ] {
            assert_eq!(t.grant_timeout(Some(ok)), Ok(default), "{ok:?}");
        }
    }

    #[test]
    fn a_near_miss_of_second_infinite_is_a_400_and_subscribes_nothing() {
        let mut t = table();
        for bad in [
            "Second-infinitely",
            "Second-infinite5",
            "Second-infinit",
            "Second--infinite",
            "Second-infinite-1",
            "Second- infinite",
            "Seconds-infinite",
            "-infinite",
            "Second-infinite Second-5",
            // The word is matched in ASCII case only: dotless i and dotted I are not `i`.
            "Second-\u{131}nfinite",
            "Second-inf\u{131}nite",
            "Second-\u{130}nfinite",
        ] {
            assert!(
                matches!(t.grant_timeout(Some(bad)), Err(GenaError::BadRequest(_))),
                "{bad:?}"
            );
            let refused = t.subscribe(
                0,
                Service::RenderingControl,
                peer(),
                &headers(CALLBACK, Some(bad)),
                &state(),
            );
            assert!(matches!(refused, Err(GenaError::BadRequest(_))), "{bad:?}");
        }
        assert!(t.is_empty());
    }

    #[test]
    fn second_infinite_expires_at_the_default_and_a_renewal_with_it_runs_from_now() {
        let mut t = table();
        let (grant, _) = t
            .subscribe(
                0,
                Service::RenderingControl,
                peer(),
                &headers(CALLBACK, Some("Second-infinite")),
                &state(),
            )
            .expect("the UPnP spelling of an unbounded request subscribes");
        assert_eq!(grant.timeout_secs, 300);
        assert_eq!(
            grant.headers()[1],
            ("TIMEOUT".to_string(), "Second-300".to_string()),
            "the grant is finite and says so"
        );
        let renewed = t
            .renew(
                100 * SEC,
                Service::RenderingControl,
                &grant.sid,
                &SubscribeHeaders {
                    timeout: Some("Second-infinite"),
                    ..SubscribeHeaders::default()
                },
            )
            .expect("a renewal may ask the same way");
        assert_eq!(
            (renewed.sid.as_str(), renewed.timeout_secs),
            (grant.sid.as_str(), 300)
        );
        // The renewal ran from 100 s and not from the first grant: live a nanosecond before 400 s, gone at it.
        assert_eq!(t.expire(400 * SEC - 1), 0);
        assert_eq!(t.expire(400 * SEC), 1);
        assert!(t.is_empty());
    }

    #[test]
    fn a_callback_must_be_one_http_url_naming_the_requester() {
        let ok = |c: &str| parse_callback(c, peer(), 256);
        assert_eq!(
            ok("<http://192.0.2.10:3400/notify>"),
            Ok("http://192.0.2.10:3400/notify".to_string())
        );
        assert_eq!(
            ok("<http://192.0.2.10/>"),
            Ok("http://192.0.2.10/".to_string())
        );
        assert_eq!(
            ok("<http://192.0.2.10>"),
            Ok("http://192.0.2.10".to_string())
        );
        assert_eq!(
            ok("  <http://192.0.2.10:1/x>  "),
            Ok("http://192.0.2.10:1/x".to_string())
        );
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            parse_callback("<http://[2001:db8::1]:3400/n>", v6, 256),
            Ok("http://[2001:db8::1]:3400/n".to_string())
        );
        for bad in [
            "http://192.0.2.10:3400/notify",
            "<https://192.0.2.10:3400/notify>",
            "<http://192.0.2.99:3400/notify>",
            "<http://example.invalid:3400/notify>",
            "<http://user@192.0.2.10:3400/notify>",
            "<http://192.0.2.10:0/notify>",
            "<http://192.0.2.10:65536/notify>",
            "<http://192.0.2.10:port/notify>",
            "<http://192.0.2.10:3400/a b>",
            "<http://192.0.2.10:3400/a><http://192.0.2.10:3400/b>",
            "<http://>",
            "<>",
            "",
            "<ftp://192.0.2.10/x>",
            "<http://192.0.2.10:3400/\u{1F600}>",
            "<http://[2001:db8::1]:3400/n>",
        ] {
            assert_eq!(ok(bad), Err(GenaError::PreconditionFailed), "{bad:?}");
        }
        let long = format!("<http://192.0.2.10:3400/{}>", "x".repeat(300));
        assert_eq!(ok(&long), Err(GenaError::PreconditionFailed));
    }

    #[test]
    fn a_subscribe_without_the_right_nt_or_a_callback_is_a_412() {
        let mut t = table();
        let bad = [
            SubscribeHeaders {
                callback: Some(CALLBACK),
                nt: None,
                timeout: None,
            },
            SubscribeHeaders {
                callback: Some(CALLBACK),
                nt: Some("upnp:other"),
                timeout: None,
            },
            SubscribeHeaders {
                callback: None,
                nt: Some("upnp:event"),
                timeout: None,
            },
        ];
        for h in bad {
            assert_eq!(
                t.subscribe(0, Service::RenderingControl, peer(), &h, &state())
                    .err(),
                Some(GenaError::PreconditionFailed)
            );
        }
        assert!(t.is_empty());
    }

    #[test]
    fn a_callback_for_another_host_is_refused_so_no_third_party_can_be_made_a_target() {
        let mut t = table();
        let elsewhere: IpAddr = "192.0.2.77".parse().unwrap();
        assert_eq!(
            t.subscribe(
                0,
                Service::RenderingControl,
                elsewhere,
                &headers(CALLBACK, None),
                &state()
            )
            .err(),
            Some(GenaError::PreconditionFailed)
        );
    }

    #[test]
    fn a_renewal_runs_from_now_and_keeps_the_id() {
        let mut t = table();
        let (grant, _) = subscribe(&mut t, 0, Service::RenderingControl);
        let renewed = t
            .renew(
                200 * SEC,
                Service::RenderingControl,
                &grant.sid,
                &SubscribeHeaders {
                    callback: None,
                    nt: None,
                    timeout: Some("Second-600"),
                },
            )
            .unwrap();
        assert_eq!(
            renewed,
            SubscribeGrant {
                sid: grant.sid.clone(),
                timeout_secs: 600
            }
        );
        // Live at 200 + 600 - 1 s, gone at 200 + 600 s: the old 300 s expiry no longer applies.
        assert_eq!(t.expire(799 * SEC), 0);
        assert_eq!(t.len(), 1);
        assert_eq!(t.expire(800 * SEC), 1);
        assert!(t.is_empty());
    }

    #[test]
    fn a_renewal_with_a_callback_or_nt_is_a_400_and_changes_nothing() {
        let mut t = table();
        let (grant, _) = subscribe(&mut t, 0, Service::RenderingControl);
        for h in [
            SubscribeHeaders {
                callback: Some(CALLBACK),
                nt: None,
                timeout: None,
            },
            SubscribeHeaders {
                callback: None,
                nt: Some("upnp:event"),
                timeout: None,
            },
        ] {
            assert!(matches!(
                t.renew(10 * SEC, Service::RenderingControl, &grant.sid, &h),
                Err(GenaError::BadRequest(_))
            ));
        }
        assert_eq!(t.expire(299 * SEC), 0, "the original expiry stands");
    }

    #[test]
    fn a_stale_or_unknown_or_other_service_id_is_a_412() {
        let mut t = table();
        let (grant, _) = subscribe(&mut t, 0, Service::RenderingControl);
        let none = SubscribeHeaders::default();
        assert_eq!(
            t.renew(SEC, Service::RenderingControl, "uuid:nope", &none)
                .err(),
            Some(GenaError::PreconditionFailed)
        );
        assert_eq!(
            t.renew(SEC, Service::AvTransport, &grant.sid, &none).err(),
            Some(GenaError::PreconditionFailed)
        );
        // After expiry the id is gone: a late renewal is refused and the controller subscribes afresh.
        assert_eq!(
            t.renew(300 * SEC, Service::RenderingControl, &grant.sid, &none)
                .err(),
            Some(GenaError::PreconditionFailed)
        );
        assert!(t.is_empty());
        assert_eq!(t.expired_total(), 1);
    }

    #[test]
    fn expiry_is_exact_live_a_nanosecond_before_gone_at_the_instant() {
        let mut t = table();
        subscribe(&mut t, 0, Service::RenderingControl);
        assert_eq!(t.expire(300 * SEC - 1), 0);
        assert_eq!(t.expire(300 * SEC), 1);
    }

    #[test]
    fn an_unsubscribe_removes_the_id_and_a_second_one_is_a_412() {
        let mut t = table();
        let (grant, _) = subscribe(&mut t, 0, Service::RenderingControl);
        assert_eq!(
            t.unsubscribe(SEC, Service::AvTransport, &grant.sid),
            Err(GenaError::PreconditionFailed)
        );
        assert_eq!(
            t.unsubscribe(SEC, Service::RenderingControl, &grant.sid),
            Ok(())
        );
        assert_eq!(
            t.unsubscribe(SEC, Service::RenderingControl, &grant.sid),
            Err(GenaError::PreconditionFailed)
        );
        assert!(t.is_empty());
    }

    #[test]
    fn the_table_is_bounded_and_expiry_and_unsubscribe_free_places() {
        let mut t = SubscriptionTable::new(
            GenaConfig {
                max_subscriptions: 3,
                ..GenaConfig::provisional()
            },
            7,
        );
        let mut sids = Vec::new();
        for _ in 0..3 {
            sids.push(subscribe(&mut t, 0, Service::RenderingControl).0.sid);
        }
        assert_eq!(
            t.subscribe(
                0,
                Service::RenderingControl,
                peer(),
                &headers(CALLBACK, None),
                &state()
            )
            .err(),
            Some(GenaError::TableFull)
        );
        assert_eq!(t.len(), 3);
        t.unsubscribe(0, Service::RenderingControl, &sids[0])
            .unwrap();
        assert!(subscribe(&mut t, 0, Service::RenderingControl).0.sid != sids[0]);
        // Everything lapses: the places come back.
        assert!(
            t.subscribe(
                301 * SEC,
                Service::RenderingControl,
                peer(),
                &headers(CALLBACK, None),
                &state()
            )
            .is_ok()
        );
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn ids_are_unique_for_the_life_of_a_table_and_differ_between_tables() {
        let mut a = table();
        let first = subscribe(&mut a, 0, Service::RenderingControl).0.sid;
        a.unsubscribe(0, Service::RenderingControl, &first).unwrap();
        let second = subscribe(&mut a, 0, Service::RenderingControl).0.sid;
        assert_ne!(first, second, "an ended id is never reused");
        let mut b = SubscriptionTable::new(GenaConfig::provisional(), 0x1234_5678);
        assert_ne!(subscribe(&mut b, 0, Service::RenderingControl).0.sid, first);
    }

    #[test]
    fn after_a_restart_an_old_id_is_a_412_and_a_fresh_subscription_works() {
        let mut before = table();
        let old = subscribe(&mut before, 0, Service::RenderingControl).0.sid;
        // The endpoint restarts: a new table, with a new nonce.
        let mut after = SubscriptionTable::new(GenaConfig::provisional(), 0x5a5a_0002);
        assert_eq!(
            after
                .renew(
                    SEC,
                    Service::RenderingControl,
                    &old,
                    &SubscribeHeaders::default()
                )
                .err(),
            Some(GenaError::PreconditionFailed)
        );
        let (fresh, initial) = subscribe(&mut after, SEC, Service::RenderingControl);
        assert_ne!(fresh.sid, old);
        assert_eq!(
            initial.seq, 0,
            "a reconnecting controller gets the full state again"
        );
    }

    #[test]
    fn publishing_sends_only_what_changed_to_the_services_it_changed_for() {
        let mut t = table();
        let (rcs, _) = subscribe(&mut t, 0, Service::RenderingControl);
        let (grc, _) = subscribe(&mut t, 0, Service::GroupRenderingControl);
        let (avt, _) = subscribe(&mut t, 0, Service::AvTransport);
        let mut next = state();
        next.revision = 3;
        next.volume = Some(60);
        let events = t.publish(SEC, &next);
        assert_eq!(events.len(), 1, "only RenderingControl changed");
        assert_eq!(
            (events[0].sid.as_str(), events[0].seq),
            (rcs.sid.as_str(), 1)
        );
        let props = properties(&events[0].body);
        assert!(
            props[0]
                .1
                .contains("<Volume channel=\"Master\" val=\"60\"/>")
        );
        assert!(
            !props[0].1.contains("Mute"),
            "the unchanged variable is not repeated"
        );
        assert_eq!(
            props[1],
            ("FrankenStateRevision".to_string(), "3".to_string())
        );
        let _ = (grc, avt);
    }

    #[test]
    fn publishing_the_same_state_again_sends_nothing() {
        let mut t = table();
        subscribe(&mut t, 0, Service::RenderingControl);
        let mut next = state();
        next.volume = Some(61);
        assert_eq!(t.publish(SEC, &next).len(), 1);
        assert!(
            t.publish(2 * SEC, &next).is_empty(),
            "a duplicate is not re-sent"
        );
        // A revision-only change moves no variable, so there is no event either.
        next.revision = 9;
        assert!(t.publish(3 * SEC, &next).is_empty());
    }

    #[test]
    fn a_change_to_several_variables_arrives_as_one_event() {
        let mut t = table();
        subscribe(&mut t, 0, Service::RenderingControl);
        let mut next = state();
        next.volume = Some(10);
        next.mute = Some(true);
        let events = t.publish(SEC, &next);
        assert_eq!(events.len(), 1);
        let lc = &properties(&events[0].body)[0].1;
        assert!(lc.contains("val=\"10\"") && lc.contains("<Mute channel=\"Master\" val=\"1\"/>"));
    }

    #[test]
    fn a_late_subscriber_gets_the_full_state_and_an_earlier_one_is_unaffected() {
        let mut t = table();
        let (early, _) = subscribe(&mut t, 0, Service::RenderingControl);
        let mut changed = state();
        changed.revision = 3;
        changed.volume = Some(70);
        // Nobody published. A second controller subscribes now and is told the current state.
        let (late, initial) = t
            .subscribe(
                SEC,
                Service::RenderingControl,
                peer(),
                &headers(CALLBACK, None),
                &changed,
            )
            .unwrap();
        assert!(properties(&initial.body)[0].1.contains("val=\"70\""));
        // The early subscriber has still not been told about 70, so the next publish catches it up.
        let mut later = changed.clone();
        later.revision = 4;
        later.mute = Some(true);
        let events = t.publish(2 * SEC, &later);
        assert_eq!(events.len(), 2);
        let for_early = events.iter().find(|e| e.sid == early.sid).unwrap();
        let for_late = events.iter().find(|e| e.sid == late.sid).unwrap();
        let early_lc = &properties(&for_early.body)[0].1;
        let late_lc = &properties(&for_late.body)[0].1;
        assert!(
            early_lc.contains("val=\"70\"") && early_lc.contains("<Mute"),
            "{early_lc}"
        );
        assert!(
            !late_lc.contains("Volume") && late_lc.contains("<Mute"),
            "{late_lc}"
        );
    }

    #[test]
    fn a_stale_subscription_is_not_notified_and_is_removed_by_the_publish() {
        let mut t = table();
        subscribe(&mut t, 0, Service::RenderingControl);
        let mut next = state();
        next.volume = Some(5);
        assert!(t.publish(301 * SEC, &next).is_empty());
        assert!(t.is_empty());
    }

    #[test]
    fn the_sequence_counts_up_from_zero_and_wraps_to_one_never_zero() {
        let mut t = table();
        let (_, initial) = subscribe(&mut t, 0, Service::RenderingControl);
        assert_eq!(initial.seq, 0);
        let mut s = state();
        let mut seqs = Vec::new();
        for v in 51..=53 {
            s.volume = Some(v);
            seqs.push(t.publish(SEC, &s)[0].seq);
        }
        assert_eq!(seqs, vec![1, 2, 3]);

        t.set_next_seq(u32::MAX - 1);
        let mut wrapped = Vec::new();
        for v in 54..=58 {
            s.volume = Some(v);
            wrapped.push(t.publish(SEC, &s)[0].seq);
        }
        assert_eq!(wrapped, vec![u32::MAX - 1, u32::MAX, 1, 2, 3]);
        assert!(!wrapped.contains(&0));
    }

    #[test]
    fn a_topology_event_carries_the_document_and_the_revision() {
        let mut t = table();
        subscribe(&mut t, 0, Service::ZoneGroupTopology);
        let mut next = state();
        next.revision = 5;
        next.epoch = 11;
        next.zone_group_state =
            "<ZoneGroupState><ZoneGroups a=\"x&amp;y\"/></ZoneGroupState>".to_string();
        let events = t.publish(SEC, &next);
        assert_eq!(events.len(), 1);
        let props = properties(&events[0].body);
        assert_eq!(
            props[0],
            ("ZoneGroupState".to_string(), next.zone_group_state.clone())
        );
        assert_eq!(
            props[1],
            ("FrankenStateRevision".to_string(), "5".to_string())
        );
        assert_eq!(props[2], ("FrankenEpoch".to_string(), "11".to_string()));
    }

    #[test]
    fn an_endpoint_that_leaves_the_group_stops_reporting_a_volume_it_no_longer_has() {
        let mut t = table();
        subscribe(&mut t, 0, Service::RenderingControl);
        let mut gone = state();
        gone.volume = None;
        gone.mute = None;
        gone.revision = 6;
        // The variables changed (to nothing), but there is nothing true to say about them.
        let events = t.publish(SEC, &gone);
        assert!(events.is_empty(), "{events:?}");
    }

    #[test]
    fn every_body_is_well_formed_and_within_the_reader_bounds() {
        let mut t = table();
        for service in [
            Service::RenderingControl,
            Service::GroupRenderingControl,
            Service::AvTransport,
            Service::ZoneGroupTopology,
        ] {
            let body = subscribe(&mut t, 0, service).1.body;
            // `properties` panics on a malformed or oversize body.
            assert!(properties(&body).len() >= 3, "{service:?}");
        }
    }
}
