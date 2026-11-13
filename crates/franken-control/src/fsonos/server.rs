//! The request handler: routes an HTTP-shaped request to SOAP control or GENA eventing, and turns every
//! command into an N02 control request (G03 / `ffw-xvv`).
//!
//! Nothing here opens a socket or reads a clock. The transport hands in an [`HttpRequest`] (method,
//! path, headers, body, the address it came from and which [`Ingress`] it arrived on) and a
//! [`Context`] (the control channel, the group session, the time). It gets back a [`Handled`]: the
//! response to write, the `NOTIFY` messages to send, and any other peers' commands the step settled.
//!
//! # Policy: who may do what
//!
//! | ingress | reads (`Get*`) | events | commands | acknowledgements |
//! |---|---|---|---|---|
//! | [`Ingress::LocalLegacy`] | yes | yes | yes, as the local legacy bridge, unless switched off | no (404): it has no command ids |
//! | [`Ingress::Tailnet`] | no (401) | no (401) | only with a valid command authorization | only with a valid acknowledgement authorization |
//!
//! Plain UPnP has no authentication, so the local legacy ingress is for a link the owner has decided to
//! trust as a LAN; the transport must not bind it to the tailnet interface, and a request that arrives
//! on the tailnet is judged as one. The tailnet ingress accepts nothing that is not an authenticated
//! command or the authenticated acknowledgement of one: an unauthenticated tailnet peer gets `401` for a
//! read, an event subscription, a deferred action and an unknown action alike, so it learns nothing about
//! the matrix.
//!
//! # Every command is an N02 command
//!
//! A SOAP action that changes the group is mapped to a [`ControlCommand`] and submitted to the
//! [`ControlChannel`], so N02's guarantees apply to it: authentication, the per-peer rate limit, the
//! bounded queues, the lease check (G01), the epoch and revision checks, and exactly-once application
//! by command number. Nothing in this module writes to the session.
//!
//! * **Tailnet.** The caller's `X-Franken-*` headers are the command id and the authorization: peer,
//!   command number, epoch, observed revision and a proof over [`RequestBody::signing_bytes`]. The
//!   body is rebuilt here from the SOAP call, so the proof covers what the SOAP body asks for and a
//!   changed argument fails authentication. A stop also names `X-Franken-Now-Ns` and
//!   `X-Franken-Dma-Tail-Ns`, which are part of the signed command.
//! * **Local legacy.** The request names no command number, so each is a new command from the
//!   configured bridge peer, signed with the bridge's key, at the current epoch and revision.
//!   Absolute changes are safe to repeat. **Relative changes are accepted, and a retry applies again**:
//!   plain SOAP carries nothing to tell a retry from a new request, so each request is a new step.
//!   The result is clamped to 0..=100 and the resulting volume is returned, as the action specifies.
//!   Only the tailnet route, whose command id is the command number, is deduplicated, and only the
//!   authenticated routes (the tailnet, the panel) have a durable floor written for them: the bridge is
//!   declared to the channel as an identity whose retries carry no stable number
//!   ([`ControlChannel::declare_unstable_retry_ids`]), so a LAN host sending relative changes as fast as the
//!   rate limit allows causes no journal write beyond the group's mark. If the channel holds a floor for the
//!   bridge from before, the bridge's numbers resume above it.
//!
//! # Durable or not is the owner's decision, and it is explicit
//!
//! [`Context`] holds the [`Stepper`] the owner built: a durable one steps through the journal (N02
//! `step_then_store`), and the plain development one stores nothing. There is no request field, header or default
//! that picks between them. A step that cannot be made durable is rolled back. Unsafe changes stay unapplied and
//! their requests receive a fixed-words fault. Local-user stop and mute-on are re-applied to the live session:
//! their actual outcomes are delivered, their live changes are published, and their own requests receive success.
//! No rolled-back effect is reported as committed. The first such failure latches the channel's
//! durable path failed ([`Durability`]); while it is latched the local user's stop and mute-on still work and every
//! other command is refused with another fixed-words fault, until the owner reopens the journal.
//!
//! A command is *queued*, then *stepped*; the response says what happened, and "queued but not applied
//! yet" is a fault that says so, never a success.
//!
//! # Acknowledgements
//!
//! A command's sender can say it saw the outcome (N02 section 7): `POST` [`ACK_PATH`] on the tailnet with
//! `X-Franken-Peer`, `X-Franken-Seq` (the command's number), `X-Franken-Epoch` (the epoch it was issued
//! under) and `X-Franken-Proof`, a hex HMAC over [`AckBody::signing_bytes`], and an empty body. The handler
//! gives the channel exactly that and nothing else: [`ControlChannel::acknowledge`] reads the session and
//! writes one flag on one ledger entry, so an acknowledgement applies nothing, steps nothing and publishes
//! nothing. The answer is the channel's typed outcome as one fixed word in `X-FRANKEN-ACK`: `200` when the
//! entry was completed (`on_time`, `late`, `superseded`) or already was (`duplicate`, so repeating an
//! acknowledgement whose answer was lost is harmless), and `409` when nothing was completed (`not_settled`,
//! `unknown`, `out_of_window`, `mismatch`). An acknowledgement that does not authenticate, and any malformed
//! one, is the same `401` with no body as everywhere else on the tailnet. The local legacy link carries no
//! command ids, so there is nothing on it to acknowledge: the path is `404` there.
//!
//! # Topology events
//!
//! The `ZoneGroupState` document is built from the live session and the [`Directory`] each time it is asked
//! for, and an event carries exactly the document a read would give at that moment. What makes a subscriber
//! hear of a change is the owner telling the endpoint: [`Endpoint::publish`] after it changed the session (a
//! member admitted or removed, the group moved to a new epoch) and also after it changed the [`Directory`] through
//! [`Endpoint::directory_mut`] (where a member is, what its room is called), since the directory is part of the document. Only the topology
//! subscribers are told of a change to the document; the other services hear nothing unless their own variables
//! moved.
//!
//! # Faults say fixed words
//!
//! No fault, header or body carries text the peer sent. A fault is a [`Fault`] with a fixed reason.

use std::net::IpAddr;

use franken_session::UnifiedGroupSession;

use crate::channel::peer::{AuthProof, PeerAuthority, PeerId, compute_proof};
use crate::channel::pipeline::{
    AckOutcome, ControlChannel, Durability, Outcome, Refusal, Rejection, Settlement, Stepper,
    SubmitResult,
};
use crate::channel::request::{
    AckBody, AckRequest, ControlCommand, ControlRequest, RequestBody, RequestError,
};

use super::actions::{self, Cmd, Plan, Read};
use super::gena::{
    GenaConfig, GenaError, INCARNATION_BYTES, Notification, SubscribeHeaders, SubscriptionTable,
    legacy_incarnation,
};
use super::soap::{Fault, Service, SoapCall, fault_envelope, parse_call, response_envelope};
use super::ssdp;
use super::state::{Directory, EventState, TransportState};
use super::xml::XmlLimits;

const CONTENT_TYPE: &str = "text/xml; charset=\"utf-8\"";

/// The route on which a tailnet peer acknowledges the outcome of one of its commands.
pub const ACK_PATH: &str = "/ffw/ack";

/// The response header that carries an acknowledgement's typed outcome, as one fixed word.
const H_ACK: &str = "X-FRANKEN-ACK";

/// Which way a request arrived. The transport decides; this module only obeys it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ingress {
    /// The local link, where plain UPnP is spoken.
    LocalLegacy,
    /// The tailnet: nothing but authenticated commands.
    Tailnet,
}

/// One request, as the transport read it. Header names are matched without regard to case.
#[derive(Debug, Clone, Copy)]
pub struct HttpRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub peer_ip: IpAddr,
    pub ingress: Ingress,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: &'a [u8],
}

/// What to write back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpResponse {
    fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: String::new(),
        }
    }

    fn xml(status: u16, body: String) -> Self {
        Self {
            status,
            headers: vec![("CONTENT-TYPE".to_string(), CONTENT_TYPE.to_string())],
            body,
        }
    }

    fn fault(fault: Fault) -> Self {
        match fault_envelope(fault) {
            Some(body) => Self::xml(fault.http_status(), body),
            None => Self::empty(fault.http_status()),
        }
    }
}

/// What handling a request produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handled {
    pub response: HttpResponse,
    /// Event messages to send, after the response.
    pub notifications: Vec<Notification>,
    /// Commands of other peers that the step this request drove happened to settle. The owner would
    /// otherwise never see their outcomes.
    pub settled_others: Vec<Settlement>,
}

impl Handled {
    fn of(response: HttpResponse) -> Self {
        Self {
            response,
            notifications: Vec::new(),
            settled_others: Vec::new(),
        }
    }
}

/// What a request is handled against. The session is the channel's to change, not this module's.
///
/// `stepper` is how the channel is stepped and whether that is durable. The owner builds it; the caller names it
/// explicitly, with no default, so a production owner cannot get the volatile step by leaving something out.
pub struct Context<'a, A: PeerAuthority> {
    pub channel: &'a mut ControlChannel<A>,
    pub session: &'a mut UnifiedGroupSession,
    pub stepper: &'a mut dyn Stepper<A>,
    pub now_ns: u64,
}

/// The identity local legacy commands are sent under. The peer must be admitted to the channel's
/// directory as a controller with this key; the endpoint signs with it, and nothing else holds it.
pub struct LegacyBridge {
    peer: PeerId,
    key: Vec<u8>,
}

impl LegacyBridge {
    #[must_use]
    pub fn new(peer: PeerId, key: Vec<u8>) -> Self {
        Self { peer, key }
    }
}

impl std::fmt::Debug for LegacyBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegacyBridge")
            .field("peer", &self.peer)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Settings for one endpoint. **Provisional**: the bead names no numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointConfig {
    /// The member this endpoint is: what `RenderingControl` reads and changes.
    pub member_id: String,
    pub limits: XmlLimits,
    pub gena: GenaConfig,
    /// Whether local legacy SOAP may change the group. Reads and events do not depend on it.
    pub legacy_commands: bool,
    /// The `irrevocable_dma_tail_ns` a local legacy stop carries.
    pub stop_dma_tail_ns: u64,
    /// How many times one request may step the channel looking for its own command's outcome.
    pub step_rounds: usize,
}

impl EndpointConfig {
    #[must_use]
    pub fn provisional(member_id: &str) -> Self {
        Self {
            member_id: member_id.to_string(),
            limits: XmlLimits::soap_request(),
            gena: GenaConfig::provisional(),
            legacy_commands: true,
            stop_dma_tail_ns: 20_000_000,
            step_rounds: 4,
        }
    }
}

/// A configuration the endpoint cannot run with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    #[error("the member id is not a valid member id")]
    MemberId,
    #[error("the discovery UUID does not match the endpoint member id")]
    DiscoveryIdentityMismatch,
    #[error("`{0}` must be at least 1")]
    Zero(&'static str),
}

/// Deliberate faults the tests plant in the adapter, to show that the judges notice them. They exist in
/// test builds only; nothing in a normal build can reach them.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Defect {
    /// Ignore the ledger's answer to a retry and apply the command again under a fresh number.
    ReapplyOnRetry,
    /// Answer a command whose outcome the channel no longer knows with a success.
    SuccessAfterRetention,
    /// Answer every well formed acknowledgement `200 on_time` without giving it to the channel.
    AckSwallowed,
    /// Give the channel's refusal of an acknowledgement a success status (the word stays honest).
    AckAlwaysOk,
    /// Call a late acknowledgement `on_time`.
    AckWordCollapsed,
    /// Step the channel and publish after an acknowledgement that completed its entry.
    AckDrivesChannel,
    /// Answer an acknowledgement with a bad proof differently from every other authentication failure.
    AckUnauthenticatedTold,
    /// Serve the acknowledgement route on the local legacy link too.
    AckOnLegacy,
    /// Never send a topology subscriber an event, whatever the document did.
    TopologyNeverEvented,
    /// Send the topology event a document that is not the one a read gives.
    TopologyDocDiffersFromRead,
}

/// The G03 endpoint: GENA state, the directory of room facts, and the legacy bridge.
#[derive(Debug)]
pub struct Endpoint {
    config: EndpointConfig,
    bridge: LegacyBridge,
    gena: SubscriptionTable,
    directory: Directory,
    discovery: Option<Discovery>,
    transport: TransportState,
    legacy_seq: u64,
    #[cfg(test)]
    defect: Option<Defect>,
}

/// Cached bounded description and local metadata from one validated device.
#[derive(Debug)]
struct Discovery {
    device: ssdp::Device,
    location: String,
    description: String,
}

impl Endpoint {
    /// `subscription_nonce` makes this incarnation's subscription ids differ from the last one's, unless the owner hands the same
    /// nonce to every boot. The 32-bit form of [`Endpoint::with_incarnation`]: its ids read exactly
    /// `uuid:<nonce>-0000-4000-8000-<counter>`. `first_legacy_seq` is the first command number the bridge uses; at least 1.
    pub fn new(
        config: EndpointConfig,
        bridge: LegacyBridge,
        subscription_nonce: u32,
        first_legacy_seq: u64,
    ) -> Result<Self, EndpointError> {
        Self::with_incarnation(
            config,
            bridge,
            legacy_incarnation(subscription_nonce),
            first_legacy_seq,
        )
    }

    /// [`Endpoint::new`] with a boot incarnation of [`INCARNATION_BYTES`] bytes in place of the 32-bit nonce: ten bytes the owner draws
    /// afresh for every boot, 74 of whose 80 bits show in every subscription id (see [`SubscriptionTable::with_incarnation`]). A
    /// namespace that tells one boot's ids from another's, not authentication.
    pub fn with_incarnation(
        config: EndpointConfig,
        bridge: LegacyBridge,
        incarnation: [u8; INCARNATION_BYTES],
        first_legacy_seq: u64,
    ) -> Result<Self, EndpointError> {
        let probe = RequestBody::new(
            bridge.peer.clone(),
            1,
            0,
            Some(0),
            ControlCommand::SetMemberMute {
                member_id: config.member_id.clone(),
                muted: false,
            },
        );
        if probe.is_err() {
            return Err(EndpointError::MemberId);
        }
        if first_legacy_seq == 0 {
            return Err(EndpointError::Zero("first_legacy_seq"));
        }
        if config.step_rounds == 0 {
            return Err(EndpointError::Zero("step_rounds"));
        }
        if config.gena.max_subscriptions == 0 {
            return Err(EndpointError::Zero("max_subscriptions"));
        }
        let gena = SubscriptionTable::with_incarnation(config.gena, incarnation);
        Ok(Self {
            config,
            bridge,
            gena,
            directory: Directory::default(),
            discovery: None,
            transport: TransportState::NoMediaPresent,
            legacy_seq: first_legacy_seq,
            #[cfg(test)]
            defect: None,
        })
    }

    /// Plant `defect` in this adapter (tests only).
    #[cfg(test)]
    pub(crate) fn plant(&mut self, defect: Defect) {
        self.defect = Some(defect);
    }

    /// Whether the planted `SuccessAfterRetention` defect is on: a fabricated success where the outcome
    /// is unknown. Always false outside test builds.
    #[cfg(test)]
    fn planted_success_after_retention(&self) -> bool {
        self.defect == Some(Defect::SuccessAfterRetention)
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self)]
    const fn planted_success_after_retention(&self) -> bool {
        false
    }

    /// The planted `ReapplyOnRetry` defect: when the ledger answered a retry, throw the answer away and
    /// apply the command again as a new one from the bridge. Any other request passes through untouched.
    #[cfg(test)]
    fn plant_reapply<A: PeerAuthority>(
        &mut self,
        ctx: &mut Context<'_, A>,
        cmd: Cmd,
        peer: PeerId,
        seq: u64,
        submitted: SubmitResult,
    ) -> (PeerId, u64, SubmitResult) {
        if self.defect != Some(Defect::ReapplyOnRetry)
            || !matches!(submitted, SubmitResult::Settled(_))
        {
            return (peer, seq, submitted);
        }
        let Ok(again) = self.legacy_request(ctx, cmd) else {
            return (peer, seq, submitted);
        };
        let (peer, seq) = (again.body().peer().clone(), again.body().seq());
        self.legacy_seq = seq.saturating_add(1);
        let submitted = ctx.channel.submit(ctx.now_ns, again);
        (peer, seq, submitted)
    }

    /// The acknowledgement route with one of its planted defects, for a well formed request. `None` when no
    /// defect of this route is planted (or the request is not well formed), so the real handler answers.
    #[cfg(test)]
    fn plant_ack<A: PeerAuthority>(
        &mut self,
        ctx: &mut Context<'_, A>,
        request: &HttpRequest<'_>,
    ) -> Option<Handled> {
        let defect = self.defect?;
        if matches!(
            defect,
            Defect::ReapplyOnRetry
                | Defect::SuccessAfterRetention
                | Defect::TopologyNeverEvented
                | Defect::TopologyDocDiffersFromRead
        ) {
            return None;
        }
        if request.ingress != Ingress::Tailnet && defect != Defect::AckOnLegacy {
            return None;
        }
        let ack = tailnet_acknowledgement(request.headers, request.body).ok()?;
        let outcome = if defect == Defect::AckSwallowed {
            AckOutcome::OnTime { age_ns: 0 }
        } else {
            ctx.channel.acknowledge(ctx.now_ns, ctx.session, &ack)
        };
        let mut response = ack_response(outcome);
        match (defect, outcome) {
            (Defect::AckAlwaysOk, _) if response.status == 409 => response.status = 200,
            (Defect::AckWordCollapsed, AckOutcome::Late { .. }) => {
                response.headers = vec![(H_ACK.to_string(), "on_time".to_string())];
            }
            (
                Defect::AckUnauthenticatedTold,
                AckOutcome::Unauthenticated(crate::channel::peer::AuthFailure::BadProof),
            ) => response = HttpResponse::empty(403),
            _ => {}
        }
        let mut handled = Handled::of(response);
        let completed = matches!(
            outcome,
            AckOutcome::OnTime { .. } | AckOutcome::Late { .. } | AckOutcome::Superseded { .. }
        );
        if defect == Defect::AckDrivesChannel && completed {
            handled.settled_others = ctx.channel.step(ctx.now_ns, ctx.session);
            handled.notifications = self.publish(ctx.now_ns, ctx.session);
        }
        Some(handled)
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self)]
    const fn plant_ack<A: PeerAuthority>(
        &mut self,
        _ctx: &mut Context<'_, A>,
        _request: &HttpRequest<'_>,
    ) -> Option<Handled> {
        None
    }

    /// What the transport the owner runs reports as the transport state. The session has no source.
    pub fn set_transport(&mut self, transport: TransportState) {
        self.transport = transport;
    }

    /// Configure discovery for this member, or replace its location and name.
    ///
    /// The owner must stop any old advertiser before replacing its configuration.
    /// Local directory entries are derived from the same validated device. Edits to
    /// those entries through `directory_mut` are corrected before a state read or
    /// event; other members' metadata remains under the caller's control.
    ///
    /// # Errors
    /// Returns `DiscoveryIdentityMismatch` without changing the endpoint if the
    /// device UUID is not this endpoint's configured member id.
    pub fn configure_discovery(&mut self, device: ssdp::Device) -> Result<(), EndpointError> {
        if device.uuid() != self.config.member_id {
            return Err(EndpointError::DiscoveryIdentityMismatch);
        }
        let discovery = Discovery {
            location: device.location(),
            description: device.description_xml(),
            device,
        };
        self.discovery = Some(discovery);
        self.restore_local_discovery_metadata();
        Ok(())
    }

    fn restore_local_discovery_metadata(&mut self) {
        let Some(discovery) = &self.discovery else {
            return;
        };
        let member = &self.config.member_id;
        if self.directory.locations.get(member) != Some(&discovery.location) {
            self.directory
                .locations
                .insert(member.clone(), discovery.location.clone());
        }
        if self.directory.zone_names.get(member).map(String::as_str)
            != Some(discovery.device.name())
        {
            self.directory
                .zone_names
                .insert(member.clone(), discovery.device.name().to_string());
        }
    }

    pub fn directory_mut(&mut self) -> &mut Directory {
        &mut self.directory
    }

    /// Identity reserved for legacy requests with unstable retry numbers. A composition owner
    /// must keep authenticated stable-number traffic under a distinct enrolled identity.
    #[must_use]
    pub fn legacy_peer(&self) -> &PeerId {
        &self.bridge.peer
    }

    #[must_use]
    pub const fn subscriptions(&self) -> &SubscriptionTable {
        &self.gena
    }

    /// Drop lapsed subscriptions. Returns how many.
    pub fn expire_subscriptions(&mut self, now_ns: u64) -> usize {
        self.gena.expire(now_ns)
    }

    /// Retire every subscription before replacing its delivery transport.
    /// Old SIDs cannot be renewed; future subscriptions keep this endpoint's
    /// monotonically allocated SID namespace. No clock or network is touched.
    pub fn invalidate_subscriptions(&mut self) -> usize {
        self.gena.invalidate_all()
    }

    /// Bring every subscriber up to the session as it is now. The owner calls this after anything it
    /// did to the session itself (a local change, a membership change, a move to a new epoch, a change to the
    /// directory made through [`Endpoint::directory_mut`]), and it is called for it after every command this module drives.
    pub fn publish(&mut self, now_ns: u64, session: &UnifiedGroupSession) -> Vec<Notification> {
        let state = self.state(session);
        let state = self.plant_topology_state(state);
        let sent = self.gena.publish(now_ns, &state);
        self.plant_topology_sent(sent)
    }

    /// The event state with the planted `TopologyDocDiffersFromRead` defect applied (tests only): the document an
    /// event carries is not the one a read gives. Unchanged otherwise, and always outside test builds.
    #[cfg(test)]
    fn plant_topology_state(&self, mut state: EventState) -> EventState {
        if self.defect == Some(Defect::TopologyDocDiffersFromRead) {
            state.zone_group_state = state
                .zone_group_state
                .replace("ID=\"grp:", "ID=\"stale:grp:");
        }
        state
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self)]
    const fn plant_topology_state(&self, state: EventState) -> EventState {
        state
    }

    /// The events with the planted `TopologyNeverEvented` defect applied (tests only): the topology subscribers
    /// are never told. Unchanged otherwise, and always outside test builds.
    #[cfg(test)]
    fn plant_topology_sent(&self, mut sent: Vec<Notification>) -> Vec<Notification> {
        if self.defect == Some(Defect::TopologyNeverEvented) {
            sent.retain(|n| n.service != Service::ZoneGroupTopology);
        }
        sent
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self)]
    const fn plant_topology_sent(&self, sent: Vec<Notification>) -> Vec<Notification> {
        sent
    }

    fn state(&mut self, session: &UnifiedGroupSession) -> EventState {
        self.restore_local_discovery_metadata();
        EventState::read(
            session,
            &self.config.member_id,
            self.transport,
            &self.directory,
        )
    }

    /// Handle one request.
    pub fn handle<A: PeerAuthority>(
        &mut self,
        ctx: &mut Context<'_, A>,
        request: &HttpRequest<'_>,
    ) -> Handled {
        match request.method {
            "GET"
                if request.path == ssdp::DESCRIPTION_PATH
                    && (self.discovery.is_some() || request.ingress == Ingress::LocalLegacy) =>
            {
                if request.ingress == Ingress::Tailnet {
                    Handled::of(HttpResponse::empty(401))
                } else if let Some(discovery) = &self.discovery {
                    Handled::of(HttpResponse {
                        status: 200,
                        headers: vec![
                            (
                                "CONTENT-TYPE".to_string(),
                                ssdp::DESCRIPTION_CONTENT_TYPE.to_string(),
                            ),
                            ("CONTENT-LOCATION".to_string(), discovery.location.clone()),
                            (
                                "CACHE-CONTROL".to_string(),
                                format!("max-age={}", discovery.device.max_age()),
                            ),
                        ],
                        body: discovery.description.clone(),
                    })
                } else {
                    Handled::of(HttpResponse::empty(404))
                }
            }
            "POST" if request.path == ACK_PATH => self
                .plant_ack(ctx, request)
                .unwrap_or_else(|| acknowledge(ctx, request)),
            "POST" => self.control(ctx, request),
            "SUBSCRIBE" => self.subscribe(ctx, request),
            "UNSUBSCRIBE" => self.unsubscribe(ctx, request),
            _ => Handled::of(HttpResponse::empty(405)),
        }
    }

    // ---- SOAP control -------------------------------------------------------------------------

    fn control<A: PeerAuthority>(
        &mut self,
        ctx: &mut Context<'_, A>,
        request: &HttpRequest<'_>,
    ) -> Handled {
        let Some(path_service) = Service::from_control_path(request.path) else {
            return Handled::of(HttpResponse::empty(404));
        };
        // Tailnet: without the authorization headers there is nothing to parse for.
        if request.ingress == Ingress::Tailnet && !has_authorization_headers(request.headers) {
            return Handled::of(HttpResponse::fault(Fault::Unauthenticated));
        }
        let soap_action = match unique_header(request.headers, "soapaction") {
            Ok(value) => value,
            Err(Duplicate) => return Handled::of(HttpResponse::fault(Fault::Malformed)),
        };
        let call = match parse_call(soap_action, request.body, self.config.limits) {
            Ok(call) if call.service == path_service => call,
            Ok(_) => return Handled::of(HttpResponse::fault(Fault::Malformed)),
            Err(fault) => return Handled::of(HttpResponse::fault(fault)),
        };
        let plan = actions::plan(&call);

        match (request.ingress, plan) {
            // The tailnet takes authenticated commands and nothing else, and says nothing more.
            (Ingress::Tailnet, Ok(Plan::Command(cmd))) => self.command(ctx, request, &call, cmd),
            (Ingress::Tailnet, _) => Handled::of(HttpResponse::fault(Fault::Unauthenticated)),
            (Ingress::LocalLegacy, Err(fault)) => Handled::of(HttpResponse::fault(fault)),
            (Ingress::LocalLegacy, Ok(Plan::Read(read))) => {
                let state = self.state(ctx.session);
                Handled::of(match read_response(&call, read, &state) {
                    Ok(body) => HttpResponse::xml(200, body),
                    Err(fault) => HttpResponse::fault(fault),
                })
            }
            (Ingress::LocalLegacy, Ok(Plan::Ack)) => Handled::of(HttpResponse::xml(
                200,
                response_envelope(call.service, &call.action, &[]),
            )),
            (Ingress::LocalLegacy, Ok(Plan::Command(cmd))) => {
                if self.config.legacy_commands {
                    self.command(ctx, request, &call, cmd)
                } else {
                    Handled::of(HttpResponse::fault(Fault::Unauthenticated))
                }
            }
        }
    }

    /// Submit one command to the channel, step it, and answer with what became of it.
    fn command<A: PeerAuthority>(
        &mut self,
        ctx: &mut Context<'_, A>,
        request: &HttpRequest<'_>,
        call: &SoapCall,
        cmd: Cmd,
    ) -> Handled {
        let legacy = request.ingress == Ingress::LocalLegacy;
        if legacy && !self.bind_bridge(ctx) {
            return Handled::of(HttpResponse::fault(Fault::ActionFailed(
                "legacy commands are unavailable; use the authenticated route",
            )));
        }
        let built = if legacy {
            self.legacy_request(ctx, cmd)
        } else {
            self.tailnet_request(request, cmd)
        };
        let control_request = match built {
            Ok(r) => r,
            Err(fault) => return Handled::of(HttpResponse::fault(fault)),
        };
        let peer = control_request.body().peer().clone();
        let seq = control_request.body().seq();

        let submitted = ctx.channel.submit(ctx.now_ns, control_request);
        #[cfg(test)]
        let (peer, seq, submitted) = self.plant_reapply(ctx, cmd, peer, seq, submitted);
        if legacy && !matches!(submitted, SubmitResult::Rejected(_)) {
            self.legacy_seq = seq.saturating_add(1);
        }
        let mut settled_others = Vec::new();
        let result = self.drive(ctx, &peer, seq, submitted, legacy, &mut settled_others);

        let notifications = self.publish(ctx.now_ns, ctx.session);
        let response = match result {
            Ok(()) => {
                let state = self.state(ctx.session);
                HttpResponse::xml(200, command_response(call, cmd, &state))
            }
            Err(fault) => HttpResponse::fault(fault),
        };
        Handled {
            response,
            notifications,
            settled_others,
        }
    }

    /// Tell the channel, from the identity this endpoint was configured with, that the bridge's retries carry no stable
    /// number (so no floor is written for it), and start its numbers above any floor the channel already holds for it.
    /// Nothing in a request reaches this. `false` if the channel cannot take one more such identity: the bridge then
    /// does not run, rather than run with floors written for every request.
    fn bind_bridge<A: PeerAuthority>(&mut self, ctx: &mut Context<'_, A>) -> bool {
        if !ctx.channel.declare_unstable_retry_ids(&self.bridge.peer) {
            return false;
        }
        if let Some(floor) = ctx.channel.seq_floor(&self.bridge.peer) {
            self.legacy_seq = self.legacy_seq.max(floor.saturating_add(1));
        }
        true
    }

    fn legacy_request<A: PeerAuthority>(
        &self,
        ctx: &Context<'_, A>,
        cmd: Cmd,
    ) -> Result<ControlRequest, Fault> {
        let command = self.control_command(cmd, ctx.now_ns, self.config.stop_dma_tail_ns);
        // A set names the revision it was composed from; a relative change names it exactly. Both are
        // the current one: the request is composed at the moment it arrives.
        let revision = (command.needs_observed_revision() || command.is_relative())
            .then_some(ctx.session.state_revision);
        let body = RequestBody::new(
            self.bridge.peer.clone(),
            self.legacy_seq,
            ctx.session.current_epoch,
            revision,
            command,
        )
        .map_err(request_fault)?;
        let proof = compute_proof(&self.bridge.key, &body.signing_bytes());
        Ok(ControlRequest::new(body, proof))
    }

    fn tailnet_request(
        &self,
        request: &HttpRequest<'_>,
        cmd: Cmd,
    ) -> Result<ControlRequest, Fault> {
        let auth = tailnet_authorization(request.headers, cmd)?;
        let command = self.control_command(cmd, auth.stop_now_ns, auth.stop_dma_tail_ns);
        let body = RequestBody::new(auth.peer, auth.seq, auth.epoch, auth.revision, command)
            .map_err(request_fault)?;
        Ok(ControlRequest::new(body, auth.proof))
    }

    fn control_command(&self, cmd: Cmd, now_ns: u64, dma_tail_ns: u64) -> ControlCommand {
        let member_id = self.config.member_id.clone();
        match cmd {
            Cmd::SetVolume(volume) => ControlCommand::SetMemberVolume { member_id, volume },
            Cmd::SetMute(muted) => ControlCommand::SetMemberMute { member_id, muted },
            Cmd::SetGroupVolume(volume) => ControlCommand::SetGroupVolume { volume },
            Cmd::RelativeVolume(delta) => ControlCommand::AdjustMemberVolume { member_id, delta },
            Cmd::RelativeGroupVolume(delta) => ControlCommand::AdjustGroupVolume { delta },
            Cmd::Stop => ControlCommand::StopGroupPlayback {
                now_ns,
                irrevocable_dma_tail_ns: dma_tail_ns,
            },
        }
    }

    /// Turn what `submit` said into the command's outcome, stepping the channel until it settles.
    fn drive<A: PeerAuthority>(
        &mut self,
        ctx: &mut Context<'_, A>,
        peer: &PeerId,
        seq: u64,
        submitted: SubmitResult,
        legacy: bool,
        others: &mut Vec<Settlement>,
    ) -> Result<(), Fault> {
        let outcome = match submitted {
            SubmitResult::Settled(outcome) => outcome,
            SubmitResult::Rejected(rejection) => return Err(rejection_fault(&rejection, legacy)),
            SubmitResult::OutOfWindow { floor } => {
                if legacy {
                    self.legacy_seq = self.legacy_seq.max(floor.saturating_add(1));
                }
                if self.planted_success_after_retention() {
                    return Ok(());
                }
                return Err(Fault::OutcomeUnknown);
            }
            SubmitResult::Queued { .. } | SubmitResult::AlreadyQueued { .. } => {
                let mut found = None;
                for _ in 0..self.config.step_rounds {
                    let settled = match ctx.stepper.step(ctx.channel, ctx.now_ns, ctx.session) {
                        Ok(settled) => settled,
                        // The round was rolled back whole. Its outcomes, other peers' included, were never made
                        // durable and are not reported; the rounds before it stand. The one thing that stands from
                        // the failed round is what only silences: the local user's stop and mute-on were applied to the
                        // live session (`StoreFailed::applied`), took effect, and are reported to the owner like any
                        // other peer's settlement. Do not try again: each attempt would stage, write and fail once more.
                        Err(failed) => {
                            // If this request's own command was one of them (a local-user peer's mute-on or stop came by this
                            // route), it did take effect: answer it with its real outcome, and report only the others.
                            for settlement in failed.applied {
                                if settlement.peer == *peer && settlement.seq == seq {
                                    found = Some(settlement.outcome);
                                } else {
                                    others.push(settlement);
                                }
                            }
                            if found.is_none() {
                                return Err(Fault::ActionFailed(
                                    "the change could not be stored; it was not applied",
                                ));
                            }
                            break;
                        }
                    };
                    for settlement in settled {
                        if settlement.peer == *peer && settlement.seq == seq {
                            found = Some(settlement.outcome);
                        } else {
                            others.push(settlement);
                        }
                    }
                    if found.is_some() {
                        break;
                    }
                }
                found.ok_or(Fault::ActionFailed(
                    "queued behind other work; read the state to see whether it applied",
                ))?
            }
        };
        // A command refused because the durable path is latched failed is not an internal fault of the session: say so.
        if matches!(outcome, Outcome::Refused(Refusal::InternalFault))
            && matches!(ctx.channel.durability(), Durability::Failed { .. })
        {
            return Err(Fault::ActionFailed(
                "the change cannot be stored right now; it was not applied; only the device itself can stop or mute",
            ));
        }
        outcome_result(&outcome)
    }

    // ---- GENA ---------------------------------------------------------------------------------

    fn subscribe<A: PeerAuthority>(
        &mut self,
        ctx: &mut Context<'_, A>,
        request: &HttpRequest<'_>,
    ) -> Handled {
        let Some(service) = Service::from_event_path(request.path) else {
            return Handled::of(HttpResponse::empty(404));
        };
        // Events are offered on the local link only: there is no authenticated read to subscribe to.
        if request.ingress == Ingress::Tailnet {
            return Handled::of(HttpResponse::fault(Fault::Unauthenticated));
        }
        let Ok(headers) = gena_headers(request.headers) else {
            return Handled::of(HttpResponse::empty(400));
        };
        let sub = SubscribeHeaders {
            callback: headers.callback,
            nt: headers.nt,
            timeout: headers.timeout,
        };
        let now = ctx.now_ns;
        match headers.sid {
            Some(sid) => match self.gena.renew(now, service, sid, &sub) {
                Ok(grant) => Handled::of(granted(&grant.headers())),
                Err(e) => Handled::of(gena_failure(e)),
            },
            None => {
                let state = self.state(ctx.session);
                match self
                    .gena
                    .subscribe(now, service, request.peer_ip, &sub, &state)
                {
                    Ok((grant, initial)) => Handled {
                        response: granted(&grant.headers()),
                        notifications: vec![initial],
                        settled_others: Vec::new(),
                    },
                    Err(e) => Handled::of(gena_failure(e)),
                }
            }
        }
    }

    fn unsubscribe<A: PeerAuthority>(
        &mut self,
        ctx: &mut Context<'_, A>,
        request: &HttpRequest<'_>,
    ) -> Handled {
        let Some(service) = Service::from_event_path(request.path) else {
            return Handled::of(HttpResponse::empty(404));
        };
        if request.ingress == Ingress::Tailnet {
            return Handled::of(HttpResponse::fault(Fault::Unauthenticated));
        }
        let Ok(headers) = gena_headers(request.headers) else {
            return Handled::of(HttpResponse::empty(400));
        };
        if headers.callback.is_some() || headers.nt.is_some() {
            return Handled::of(HttpResponse::empty(400));
        }
        let Some(sid) = headers.sid else {
            return Handled::of(HttpResponse::empty(412));
        };
        match self.gena.unsubscribe(ctx.now_ns, service, sid) {
            Ok(()) => Handled::of(HttpResponse::empty(200)),
            Err(e) => Handled::of(gena_failure(e)),
        }
    }
}

fn granted(headers: &[(String, String)]) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: headers.to_vec(),
        body: String::new(),
    }
}

fn gena_failure(error: GenaError) -> HttpResponse {
    HttpResponse::empty(error.http_status())
}

/// `POST` [`ACK_PATH`]: a tailnet peer says it saw the outcome of one of its commands. The channel is given
/// the acknowledgement and decides; nothing is stepped, published or written here.
fn acknowledge<A: PeerAuthority>(ctx: &mut Context<'_, A>, request: &HttpRequest<'_>) -> Handled {
    // The local legacy link has no command ids, so there is nothing on it to acknowledge.
    if request.ingress != Ingress::Tailnet {
        return Handled::of(HttpResponse::empty(404));
    }
    let ack = match tailnet_acknowledgement(request.headers, request.body) {
        Ok(ack) => ack,
        Err(fault) => return Handled::of(HttpResponse::fault(fault)),
    };
    let outcome = ctx.channel.acknowledge(ctx.now_ns, ctx.session, &ack);
    Handled::of(ack_response(outcome))
}

/// What the channel made of an acknowledgement, as a status and one fixed word. The numbers in the typed
/// outcome (an age, a floor, an epoch) stay in the channel's log. An acknowledgement that did not
/// authenticate is the same plain `401` as every other tailnet authentication failure.
fn ack_response(outcome: AckOutcome) -> HttpResponse {
    let (status, word) = match outcome {
        AckOutcome::OnTime { .. } => (200, "on_time"),
        AckOutcome::Late { .. } => (200, "late"),
        AckOutcome::Superseded { .. } => (200, "superseded"),
        AckOutcome::Duplicate => (200, "duplicate"),
        AckOutcome::NotSettled => (409, "not_settled"),
        AckOutcome::Unknown => (409, "unknown"),
        AckOutcome::OutOfWindow { .. } => (409, "out_of_window"),
        AckOutcome::Mismatch { .. } => (409, "mismatch"),
        AckOutcome::Unauthenticated(_) => return HttpResponse::fault(Fault::Unauthenticated),
    };
    HttpResponse {
        status,
        headers: vec![(H_ACK.to_string(), word.to_string())],
        body: String::new(),
    }
}

// ---- headers ----------------------------------------------------------------------------------

/// A header that was sent more than once. Which value counts would be a guess, so the request is
/// refused.
struct Duplicate;

fn unique_header<'a>(
    headers: &[(&'a str, &'a str)],
    name: &str,
) -> Result<Option<&'a str>, Duplicate> {
    let mut found = None;
    for (key, value) in headers {
        if key.eq_ignore_ascii_case(name) {
            if found.is_some() {
                return Err(Duplicate);
            }
            found = Some(*value);
        }
    }
    Ok(found)
}

struct GenaHeaders<'a> {
    callback: Option<&'a str>,
    nt: Option<&'a str>,
    timeout: Option<&'a str>,
    sid: Option<&'a str>,
}

fn gena_headers<'a>(headers: &[(&'a str, &'a str)]) -> Result<GenaHeaders<'a>, Duplicate> {
    Ok(GenaHeaders {
        callback: unique_header(headers, "callback")?,
        nt: unique_header(headers, "nt")?,
        timeout: unique_header(headers, "timeout")?,
        sid: unique_header(headers, "sid")?,
    })
}

const H_PEER: &str = "x-franken-peer";
const H_SEQ: &str = "x-franken-seq";
const H_EPOCH: &str = "x-franken-epoch";
const H_REVISION: &str = "x-franken-revision";
const H_PROOF: &str = "x-franken-proof";
const H_STOP_NOW: &str = "x-franken-now-ns";
const H_STOP_TAIL: &str = "x-franken-dma-tail-ns";

fn has_authorization_headers(headers: &[(&str, &str)]) -> bool {
    [H_PEER, H_SEQ, H_EPOCH, H_PROOF].iter().all(|name| {
        headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case(name))
    })
}

struct TailnetAuth {
    peer: PeerId,
    seq: u64,
    epoch: u64,
    revision: Option<u64>,
    proof: AuthProof,
    stop_now_ns: u64,
    stop_dma_tail_ns: u64,
}

fn decimal(raw: &str) -> Option<u64> {
    let ok = !raw.is_empty() && raw.len() <= 20 && raw.bytes().all(|b| b.is_ascii_digit());
    if ok { raw.parse().ok() } else { None }
}

fn hex(raw: &str) -> Option<Vec<u8>> {
    if raw.is_empty() || raw.len() & 1 == 1 || raw.len() > 128 || !raw.is_ascii() {
        return None;
    }
    raw.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(digits, 16).ok()
        })
        .collect()
}

/// One required authorization header, exactly once. Anything else is the same answer.
fn auth_header<'a>(headers: &[(&'a str, &'a str)], name: &str) -> Result<&'a str, Fault> {
    match unique_header(headers, name) {
        Ok(Some(value)) => Ok(value),
        Ok(None) | Err(Duplicate) => Err(Fault::Unauthenticated),
    }
}

fn auth_number(headers: &[(&str, &str)], name: &str) -> Result<u64, Fault> {
    decimal(auth_header(headers, name)?).ok_or(Fault::Unauthenticated)
}

/// The proof header: hex, once, of a length `AuthProof` accepts. Anything else is the same answer.
fn auth_proof(headers: &[(&str, &str)]) -> Result<AuthProof, Fault> {
    hex(auth_header(headers, H_PROOF)?)
        .and_then(|bytes| AuthProof::new(bytes).ok())
        .ok_or(Fault::Unauthenticated)
}

/// Read the authorization. Any problem at all is the same answer, `Unauthenticated`, so a caller who
/// has no valid authorization learns nothing about which part was wrong.
fn tailnet_authorization(headers: &[(&str, &str)], cmd: Cmd) -> Result<TailnetAuth, Fault> {
    let peer = PeerId::parse(auth_header(headers, H_PEER)?).map_err(|_| Fault::Unauthenticated)?;
    let seq = auth_number(headers, H_SEQ)?;
    let epoch = auth_number(headers, H_EPOCH)?;
    let revision = match unique_header(headers, H_REVISION) {
        Ok(Some(raw)) => Some(decimal(raw).ok_or(Fault::Unauthenticated)?),
        Ok(None) => None,
        Err(Duplicate) => return Err(Fault::Unauthenticated),
    };
    let proof = auth_proof(headers)?;
    let (stop_now_ns, stop_dma_tail_ns) = if matches!(cmd, Cmd::Stop) {
        (
            auth_number(headers, H_STOP_NOW)?,
            auth_number(headers, H_STOP_TAIL)?,
        )
    } else {
        (0, 0)
    };
    Ok(TailnetAuth {
        peer,
        seq,
        epoch,
        revision,
        proof,
        stop_now_ns,
        stop_dma_tail_ns,
    })
}

/// Read an acknowledgement: the peer, the command's number, the epoch it was issued under and a proof over
/// those, and an empty body. Any problem at all is the same answer, `Unauthenticated`, so a caller who has no
/// valid authorization learns nothing about which part was wrong.
fn tailnet_acknowledgement(headers: &[(&str, &str)], body: &[u8]) -> Result<AckRequest, Fault> {
    if !body.is_empty() {
        return Err(Fault::Unauthenticated);
    }
    let peer = PeerId::parse(auth_header(headers, H_PEER)?).map_err(|_| Fault::Unauthenticated)?;
    let seq = auth_number(headers, H_SEQ)?;
    let epoch = auth_number(headers, H_EPOCH)?;
    let proof = auth_proof(headers)?;
    let body = AckBody::new(peer, seq, epoch).map_err(|_| Fault::Unauthenticated)?;
    Ok(AckRequest::new(body, proof))
}

// ---- faults -----------------------------------------------------------------------------------

fn request_fault(error: RequestError) -> Fault {
    match error {
        RequestError::ZeroSequence => Fault::InvalidArgs("a command number is at least 1"),
        RequestError::RelativeNeedsExpectedRevision { .. } => {
            Fault::InvalidArgs("a relative change names the revision it was computed from")
        }
        RequestError::InvalidMemberId { .. }
        | RequestError::VolumeOutOfRange { .. }
        | RequestError::DeltaOutOfRange { .. }
        | RequestError::CancelsItself => Fault::InvalidArgs("the command is not valid"),
    }
}

fn rejection_fault(rejection: &Rejection, legacy: bool) -> Fault {
    match rejection {
        // For a legacy request this is the bridge's own credential failing, which is the owner's to
        // fix, not the LAN client's.
        Rejection::Unauthenticated(_) if legacy => {
            Fault::ActionFailed("the local control bridge is not available")
        }
        Rejection::Unauthenticated(_) => Fault::Unauthenticated,
        Rejection::EpochNotBound { .. } => {
            Fault::ActionFailed("the authorization is for another epoch")
        }
        Rejection::RevisionRequired { .. } => {
            Fault::InvalidArgs("a change names the revision it was composed from")
        }
        Rejection::RateLimited { .. } => Fault::ActionFailed("too many commands; retry later"),
        Rejection::QueueFull { .. } => Fault::ActionFailed("busy; retry later"),
        Rejection::IdReuse => {
            Fault::ActionFailed("that command number was used for a different command")
        }
    }
}

fn outcome_result(outcome: &Outcome) -> Result<(), Fault> {
    match outcome {
        Outcome::Committed { .. } | Outcome::AlreadySilent { .. } => Ok(()),
        Outcome::Refused(refusal) => Err(refusal_fault(refusal)),
        Outcome::Withdrawn | Outcome::CancelApplied { .. } => {
            Err(Fault::ActionFailed("the command was withdrawn"))
        }
    }
}

fn refusal_fault(refusal: &Refusal) -> Fault {
    match refusal {
        Refusal::SequenceExhausted => {
            Fault::ActionFailed("session sequence exhausted; read the state")
        }
        Refusal::StaleEpoch { .. } | Refusal::EpochAhead { .. } => {
            Fault::ActionFailed("the group is in another epoch")
        }
        Refusal::RevisionMismatch { .. } => {
            Fault::ActionFailed("the group changed since it was read")
        }
        Refusal::StaleRevision { .. } => {
            Fault::ActionFailed("composed before the last restart; read the state")
        }
        Refusal::UnknownMember { .. } => Fault::ActionFailed("this endpoint is not in the group"),
        Refusal::Session(_) => Fault::ActionFailed("the group refused the command"),
        Refusal::InternalFault => Fault::ActionFailed("internal fault; read the state"),
        Refusal::AuthorityExpired => Fault::Unauthenticated,
        Refusal::NoLease => Fault::ActionFailed("no group lease yet; retry later"),
        Refusal::Lease(_) => Fault::ActionFailed("the group lease is not live; retry later"),
        Refusal::Expired => Fault::ActionFailed("timed out waiting to be applied; read the state"),
        _ => Fault::ActionFailed("the command was not applied"),
    }
}

// ---- responses --------------------------------------------------------------------------------

fn read_response(call: &SoapCall, read: Read, state: &EventState) -> Result<String, Fault> {
    let one = |name: &'static str, value: String| {
        response_envelope(call.service, &call.action, &[(name, value)])
    };
    match read {
        Read::Volume => state
            .volume
            .map(|v| one("CurrentVolume", v.to_string()))
            .ok_or(Fault::ActionFailed("this endpoint is not in the group")),
        Read::Mute => state
            .mute
            .map(|m| one("CurrentMute", u8::from(m).to_string()))
            .ok_or(Fault::ActionFailed("this endpoint is not in the group")),
        Read::GroupVolume => Ok(one("CurrentVolume", state.group_volume.to_string())),
        Read::TransportInfo => Ok(response_envelope(
            call.service,
            &call.action,
            &[
                (
                    "CurrentTransportState",
                    state.transport.as_str().to_string(),
                ),
                ("CurrentTransportStatus", "OK".to_string()),
                ("CurrentSpeed", "1".to_string()),
            ],
        )),
        Read::ZoneGroupState => Ok(one("ZoneGroupState", state.zone_group_state.clone())),
    }
}

/// The success response for a command that was applied. A relative change reports the volume it
/// ended at, read from the session after the change.
fn command_response(call: &SoapCall, cmd: Cmd, state: &EventState) -> String {
    let new_volume = |volume: Option<u8>| -> Vec<(&'static str, String)> {
        volume
            .map(|v| vec![("NewVolume", v.to_string())])
            .unwrap_or_default()
    };
    let out = match cmd {
        Cmd::RelativeVolume(_) => new_volume(state.volume),
        Cmd::RelativeGroupVolume(_) => new_volume(Some(state.group_volume)),
        Cmd::SetVolume(_) | Cmd::SetMute(_) | Cmd::SetGroupVolume(_) | Cmd::Stop => Vec::new(),
    };
    response_envelope(call.service, &call.action, &out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn already_silent_soap_succeeds_but_exhaustion_is_a_fault() {
        use super::{Fault, Outcome, Refusal, outcome_result};
        assert!(outcome_result(&Outcome::AlreadySilent { revision: u64::MAX }).is_ok());
        assert!(matches!(
            outcome_result(&Outcome::Refused(Refusal::SequenceExhausted)),
            Err(Fault::ActionFailed(
                "session sequence exhausted; read the state"
            ))
        ));
    }
    use franken_journal::{Journal, Limits, MemStorage, Namespace};
    use franken_session::{AuthorityToken, ChannelRole, FencedControlCommand, GroupCommandPayload};

    use super::*;
    use crate::channel::limiter::RateLimit;
    use crate::channel::peer::PeerRole;
    use crate::channel::peer::ephemeral::{EphemeralPeers, test_key};
    use crate::channel::pipeline::{
        ChannelConfig, DevelopmentVolatile, Durable, SEQ_FLOORS_KEY, restore_from_open,
        restore_seq_floors_from_open,
    };
    use crate::channel::seqfloor::SeqFloors;
    use crate::fsonos::xml::{Event, XmlReader};

    const EPOCH: u64 = 10;
    const LEASE_EXPIRY_NS: u64 = 1_000_000_000_000;
    const MS: u64 = 1_000_000;
    const LAN: &str = "192.0.2.10";
    const BRIDGE: &str = "legacy-bridge";
    const CTL: &str = "ctl-a";

    fn fixture_session(epoch: u64) -> UnifiedGroupSession {
        let catalog = franken_board_profile::synthetic_test_fixture_catalog();
        let board = |model: &str| {
            catalog
                .iter()
                .find(|p| p.model_number == model)
                .expect("fixture model")
                .clone()
        };
        let mut s = UnifiedGroupSession::new("grp", "coord", epoch);
        for (seq, member, model) in [(1, "kitchen", "S5"), (2, "den", "S12")] {
            s.apply_command(FencedControlCommand {
                epoch,
                command_seq: seq,
                payload: GroupCommandPayload::AdmitMember {
                    member_id: member.to_string(),
                    board: board(model),
                    role: ChannelRole::Stereo,
                },
            })
            .expect("fixture member admits");
        }
        s
    }

    struct Rig {
        endpoint: Endpoint,
        channel: ControlChannel<EphemeralPeers>,
        channel_config: ChannelConfig,
        session: UnifiedGroupSession,
        now: u64,
        /// The journal a durable rig steps through; none for the development rig.
        journal: Option<Journal<MemStorage>>,
    }

    /// The peers every rig admits: the legacy bridge and one tailnet controller, both bound to `EPOCH`.
    fn admitted_peers() -> EphemeralPeers {
        let mut peers = EphemeralPeers::new();
        for name in [BRIDGE, CTL] {
            peers
                .admit(
                    &PeerId::parse(name).unwrap(),
                    PeerRole::Controller,
                    &test_key(name),
                    Some(EPOCH),
                    1,
                )
                .unwrap();
        }
        peers
    }

    fn roomy() -> ChannelConfig {
        let mut c = ChannelConfig::provisional();
        c.ordinary_rate = RateLimit::new(100_000, MS).unwrap();
        c.priority_rate = RateLimit::new(100_000, MS).unwrap();
        c.ordinary_capacity = 64;
        c.ledger_capacity = 128;
        c.session_seq_base = 1_000;
        c
    }

    impl Rig {
        fn new() -> Self {
            Self::with(roomy(), |_| {})
        }

        fn with(channel_config: ChannelConfig, tweak: impl FnOnce(&mut EndpointConfig)) -> Self {
            let session = fixture_session(EPOCH);
            let mut channel = ControlChannel::new(admitted_peers(), channel_config).unwrap();
            let token = AuthorityToken::issue(&session, LEASE_EXPIRY_NS);
            channel.install_lease(&session, token, 0).unwrap();
            let mut config = EndpointConfig::provisional("kitchen");
            tweak(&mut config);
            let bridge = LegacyBridge::new(PeerId::parse(BRIDGE).unwrap(), test_key(BRIDGE));
            let endpoint = Endpoint::new(config, bridge, 0x0a0b_0c0d, 1).unwrap();
            Self {
                endpoint,
                channel,
                channel_config,
                session,
                now: 0,
                journal: None,
            }
        }

        /// A rig whose steps are durable: they go through a journal on an in-memory medium.
        fn durable() -> Self {
            let mut rig = Self::new();
            let limits = Limits::standard();
            let (journal, _) =
                Journal::open(MemStorage::new(limits.segment_bytes), limits).unwrap();
            rig.journal = Some(journal);
            rig
        }

        /// A process restart over the same group: the journal's durable bytes are all that survive of the channel
        /// and the endpoint, and the session (the audible group) carries on.
        fn restart_process(&mut self) {
            let limits = Limits::standard();
            let image = self.journal.as_ref().unwrap().storage().durable().to_vec();
            let opened =
                Journal::open(MemStorage::from_image(limits.segment_bytes, &image), limits);
            let mut channel = ControlChannel::new(admitted_peers(), self.channel_config).unwrap();
            restore_from_open(&mut channel, &opened).unwrap();
            restore_seq_floors_from_open(&mut channel, &opened).unwrap();
            let token = AuthorityToken::issue(&self.session, LEASE_EXPIRY_NS);
            channel
                .install_lease(&self.session, token, self.now)
                .unwrap();
            self.channel = channel;
            self.journal = opened.ok().map(|(journal, _)| journal);
            let bridge = LegacyBridge::new(PeerId::parse(BRIDGE).unwrap(), test_key(BRIDGE));
            self.endpoint = Endpoint::new(
                EndpointConfig::provisional("kitchen"),
                bridge,
                0x0a0b_0c0d,
                1,
            )
            .unwrap();
        }

        /// Cut the medium's power at storage operation `n` (an absolute count), keeping `k` unsynced bytes.
        fn arm_cut(&mut self, n: usize, k: usize) {
            let storage = self.journal.as_mut().unwrap().storage_mut();
            storage.cut_after_ops = Some(n);
            storage.cut_budget = k;
        }

        fn ops_done(&self) -> usize {
            self.journal.as_ref().unwrap().storage().ops_done()
        }

        fn frames(&self) -> u64 {
            self.journal.as_ref().unwrap().frames_written()
        }

        /// A new channel on the same session: an empty ledger, no floors, no lease until the owner obtains
        /// one again. This is a restart of the channel, not of the process or of the session.
        fn restart_channel(&mut self) {
            let mut channel = ControlChannel::new(admitted_peers(), self.channel_config).unwrap();
            let token = AuthorityToken::issue(&self.session, LEASE_EXPIRY_NS);
            channel
                .install_lease(&self.session, token, self.now)
                .unwrap();
            self.channel = channel;
        }

        fn handle(&mut self, request: &HttpRequest<'_>) -> Handled {
            match self.journal.as_mut() {
                Some(journal) => {
                    let mut stepper = Durable::new(journal);
                    let mut ctx = Context {
                        channel: &mut self.channel,
                        session: &mut self.session,
                        stepper: &mut stepper,
                        now_ns: self.now,
                    };
                    self.endpoint.handle(&mut ctx, request)
                }
                None => {
                    let mut stepper = DevelopmentVolatile;
                    let mut ctx = Context {
                        channel: &mut self.channel,
                        session: &mut self.session,
                        stepper: &mut stepper,
                        now_ns: self.now,
                    };
                    self.endpoint.handle(&mut ctx, request)
                }
            }
        }

        fn soap(
            &mut self,
            ingress: Ingress,
            service: Service,
            action: &str,
            args: &[(&str, &str)],
            extra: &[(&str, &str)],
        ) -> Handled {
            let body = envelope(service, action, args);
            let header = format!("\"{}#{action}\"", service.urn());
            let mut headers = vec![("SOAPACTION", header.as_str())];
            headers.extend_from_slice(extra);
            let ip: IpAddr = LAN.parse().unwrap();
            self.handle(&HttpRequest {
                method: "POST",
                path: service.control_path(),
                peer_ip: ip,
                ingress,
                headers: &headers,
                body: body.as_bytes(),
            })
        }

        /// A local POST to the RenderingControl control path with exactly these headers and bytes.
        fn post_raw(&mut self, body: &[u8], headers: &[(&str, &str)]) -> Handled {
            self.handle(&HttpRequest {
                method: "POST",
                path: RC.control_path(),
                peer_ip: LAN.parse().unwrap(),
                ingress: Ingress::LocalLegacy,
                headers,
                body,
            })
        }

        /// A local request with no headers and no body, for routing checks.
        fn bare(&mut self, method: &str, path: &str) -> Handled {
            self.handle(&HttpRequest {
                method,
                path,
                peer_ip: LAN.parse().unwrap(),
                ingress: Ingress::LocalLegacy,
                headers: &[],
                body: b"",
            })
        }

        fn legacy(&mut self, service: Service, action: &str, args: &[(&str, &str)]) -> Handled {
            self.soap(Ingress::LocalLegacy, service, action, args, &[])
        }

        fn event(&mut self, method: &str, service: Service, headers: &[(&str, &str)]) -> Handled {
            self.handle(&HttpRequest {
                method,
                path: service.event_path(),
                peer_ip: LAN.parse().unwrap(),
                ingress: Ingress::LocalLegacy,
                headers,
                body: b"",
            })
        }

        fn member(&self, id: &str) -> (u8, bool) {
            let m = &self.session.members[id];
            (m.volume_0_to_100, m.muted)
        }
    }

    fn envelope(service: Service, action: &str, args: &[(&str, &str)]) -> String {
        let args: String = args
            .iter()
            .map(|(k, v)| format!("<{k}>{v}</{k}>"))
            .collect();
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope \
             xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
             <u:{action} xmlns:u=\"{}\">{args}</u:{action}></s:Body></s:Envelope>",
            service.urn()
        )
    }

    const RC: Service = Service::RenderingControl;
    const GRC: Service = Service::GroupRenderingControl;
    const AVT: Service = Service::AvTransport;
    const ZGT: Service = Service::ZoneGroupTopology;
    const MASTER: [(&str, &str); 2] = [("InstanceID", "0"), ("Channel", "Master")];

    fn set_volume(v: &str) -> [(&str, &str); 3] {
        [MASTER[0], MASTER[1], ("DesiredVolume", v)]
    }

    fn fault_code(h: &Handled) -> Option<String> {
        let marker = "<errorCode>";
        let at = h.response.body.find(marker)? + marker.len();
        let end = h.response.body[at..].find('<')? + at;
        Some(h.response.body[at..end].to_string())
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// What a tailnet client sends for `command`: it knows the key, and signs the bytes the endpoint
    /// will rebuild from the SOAP call.
    fn tailnet_headers(
        peer: &str,
        key_of: &str,
        seq: u64,
        epoch: u64,
        revision: Option<u64>,
        command: ControlCommand,
    ) -> Vec<(String, String)> {
        let body =
            RequestBody::new(PeerId::parse(peer).unwrap(), seq, epoch, revision, command).unwrap();
        let proof = compute_proof(&test_key(key_of), &body.signing_bytes());
        let mut headers = vec![
            ("X-Franken-Peer".to_string(), peer.to_string()),
            ("X-Franken-Seq".to_string(), seq.to_string()),
            ("X-Franken-Epoch".to_string(), epoch.to_string()),
            ("X-Franken-Proof".to_string(), hex_of(proof.as_bytes())),
        ];
        if let Some(r) = revision {
            headers.push(("X-Franken-Revision".to_string(), r.to_string()));
        }
        headers
    }

    fn borrowed(headers: &[(String, String)]) -> Vec<(&str, &str)> {
        headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }

    fn tail(
        rig: &mut Rig,
        action: &str,
        args: &[(&str, &str)],
        headers: &[(String, String)],
    ) -> Handled {
        let service = match action {
            "SetGroupVolume" | "SetRelativeGroupVolume" => GRC,
            "Stop" => AVT,
            _ => RC,
        };
        rig.soap(Ingress::Tailnet, service, action, args, &borrowed(headers))
    }

    // ---- local legacy reads -----------------------------------------------------------------

    #[test]
    fn local_reads_answer_from_the_live_session() {
        let mut rig = Rig::new();
        let h = rig.legacy(RC, "GetVolume", &MASTER);
        assert_eq!(h.response.status, 200);
        assert_eq!(
            h.response.body,
            response_envelope(RC, "GetVolume", &[("CurrentVolume", "50".to_string())])
        );
        assert_eq!(
            h.response.headers,
            vec![("CONTENT-TYPE".to_string(), CONTENT_TYPE.to_string())]
        );
        let h = rig.legacy(RC, "GetMute", &MASTER);
        assert!(h.response.body.contains("<CurrentMute>0</CurrentMute>"));
        let h = rig.legacy(GRC, "GetGroupVolume", &[("InstanceID", "0")]);
        assert!(
            h.response
                .body
                .contains("<CurrentVolume>50</CurrentVolume>")
        );
        let h = rig.legacy(AVT, "GetTransportInfo", &[("InstanceID", "0")]);
        assert!(h.response.body.contains(
            "<CurrentTransportState>NO_MEDIA_PRESENT</CurrentTransportState>\
             <CurrentTransportStatus>OK</CurrentTransportStatus><CurrentSpeed>1</CurrentSpeed>"
        ));
    }

    #[test]
    fn the_topology_read_is_the_escaped_document_and_never_stale() {
        let mut rig = Rig::new();
        let h = rig.legacy(ZGT, "GetZoneGroupState", &[]);
        assert!(
            h.response
                .body
                .contains("&lt;ZoneGroup Coordinator=\"coord\" ID=\"grp:10\"&gt;"),
            "{}",
            h.response.body
        );
        // A change of epoch shows at once: the read is of the session, not of a copy.
        rig.session
            .apply_command(FencedControlCommand {
                epoch: 11,
                command_seq: 3,
                payload: GroupCommandPayload::MarkMemberClockLocked {
                    member_id: "kitchen".to_string(),
                },
            })
            .unwrap();
        let h = rig.legacy(ZGT, "GetZoneGroupState", &[]);
        assert!(h.response.body.contains("grp:11"), "{}", h.response.body);
        assert!(!h.response.body.contains("grp:10"));
    }

    #[test]
    fn an_endpoint_that_left_the_group_says_so_instead_of_a_stale_volume() {
        let mut rig = Rig::new();
        rig.endpoint.config.member_id = "absent".to_string();
        let h = rig.legacy(RC, "GetVolume", &MASTER);
        assert_eq!(h.response.status, 500);
        assert_eq!(fault_code(&h).as_deref(), Some("501"));
    }

    // ---- faults ------------------------------------------------------------------------------

    #[test]
    fn an_unknown_action_is_401_a_deferred_one_is_602_and_neither_is_a_success() {
        let mut rig = Rig::new();
        let h = rig.legacy(RC, "NoSuchAction", &MASTER);
        assert_eq!(
            (h.response.status, fault_code(&h).as_deref()),
            (500, Some("401"))
        );
        let h = rig.legacy(AVT, "Play", &[("InstanceID", "0"), ("Speed", "1")]);
        assert_eq!(
            (h.response.status, fault_code(&h).as_deref()),
            (500, Some("602"))
        );
        let h = rig.legacy(Service::ContentDirectory, "Browse", &[("ObjectID", "0")]);
        assert_eq!(
            (h.response.status, fault_code(&h).as_deref()),
            (500, Some("602"))
        );
        assert_eq!(rig.session.state_revision, 2, "nothing changed");
    }

    #[test]
    fn bad_arguments_are_402_and_change_nothing() {
        let mut rig = Rig::new();
        for v in ["101", "-1", "abc", ""] {
            let h = rig.legacy(RC, "SetVolume", &set_volume(v));
            assert_eq!(fault_code(&h).as_deref(), Some("402"), "{v:?}");
        }
        assert_eq!(rig.member("kitchen"), (50, false));
    }

    #[test]
    fn a_peers_text_is_never_echoed_in_a_fault() {
        let mut rig = Rig::new();
        let secret = "tok-77c1e9a04b";
        let h = rig.legacy(RC, "SetVolume", &set_volume(secret));
        assert!(!h.response.body.contains("77c1e9a04b"));
        let h = rig.legacy(RC, secret, &MASTER);
        assert!(!h.response.body.contains("77c1e9a04b"));
    }

    #[test]
    fn malformed_oversize_and_hostile_bodies_are_refused_without_allocation_or_echo() {
        let mut rig = Rig::new();
        let header = format!("\"{}#SetVolume\"", RC.urn());
        let soap = [("SOAPACTION", header.as_str())];
        let big = vec![b'a'; 1 << 20];
        assert_eq!(rig.post_raw(&big[..], &soap).response.status, 413);
        let dtd = b"<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY a \"aaaa\">]><s:Envelope/>";
        assert_eq!(rig.post_raw(dtd, &soap).response.status, 400);
        assert_eq!(rig.post_raw(b"<not xml", &soap).response.status, 400);
        assert_eq!(rig.post_raw(b"", &soap).response.status, 400);
        // No SOAPACTION, or two of them.
        assert_eq!(rig.post_raw(b"<a/>", &[]).response.status, 400);
        let twice = [
            ("SOAPACTION", header.as_str()),
            ("soapaction", header.as_str()),
        ];
        assert_eq!(rig.post_raw(b"<a/>", &twice).response.status, 400);
        assert_eq!(rig.session.state_revision, 2);
    }

    #[test]
    fn the_path_and_the_soap_action_must_name_the_same_service() {
        let mut rig = Rig::new();
        let body = envelope(RC, "GetVolume", &MASTER);
        let header = format!("\"{}#GetVolume\"", RC.urn());
        let h = rig.handle(&HttpRequest {
            method: "POST",
            path: AVT.control_path(),
            peer_ip: LAN.parse().unwrap(),
            ingress: Ingress::LocalLegacy,
            headers: &[("SOAPACTION", header.as_str())],
            body: body.as_bytes(),
        });
        assert_eq!(h.response.status, 400);
    }

    #[test]
    fn an_unknown_path_is_404_and_an_unknown_method_is_405() {
        let mut rig = Rig::new();
        assert_eq!(rig.bare("POST", "/nope").response.status, 404);
        assert_eq!(rig.bare("SUBSCRIBE", "/nope").response.status, 404);
        assert_eq!(rig.bare("GET", RC.control_path()).response.status, 405);
        assert_eq!(rig.bare("post", RC.control_path()).response.status, 405);
    }

    #[test]
    fn a_local_set_volume_goes_through_n02_and_changes_the_session() {
        let mut rig = Rig::new();
        let h = rig.legacy(RC, "SetVolume", &set_volume("30"));
        assert_eq!(h.response.status, 200, "{}", h.response.body);
        assert_eq!(h.response.body, response_envelope(RC, "SetVolume", &[]));
        assert_eq!(rig.member("kitchen"), (30, false));
        assert_eq!(rig.channel.stats().received, 1);
        assert_eq!(rig.channel.stats().committed, 1);
    }

    #[test]
    fn local_mute_group_volume_and_stop_work_and_each_is_one_n02_command() {
        let mut rig = Rig::new();
        let h = rig.legacy(RC, "SetMute", &[MASTER[0], MASTER[1], ("DesiredMute", "1")]);
        assert_eq!(h.response.status, 200, "{}", h.response.body);
        assert!(rig.member("kitchen").1);
        let h = rig.legacy(
            GRC,
            "SetGroupVolume",
            &[("InstanceID", "0"), ("DesiredVolume", "40")],
        );
        assert_eq!(h.response.status, 200, "{}", h.response.body);
        assert_eq!(rig.session.group_master_volume, 40);
        let h = rig.legacy(AVT, "Stop", &[("InstanceID", "0")]);
        assert_eq!(h.response.status, 200, "{}", h.response.body);
        assert_eq!(rig.channel.stats().committed, 3);
    }

    #[test]
    fn local_legacy_numbers_are_fresh_for_each_command() {
        let mut rig = Rig::new();
        for v in ["10", "20", "30"] {
            assert_eq!(
                rig.legacy(RC, "SetVolume", &set_volume(v)).response.status,
                200
            );
        }
        assert_eq!(rig.member("kitchen").0, 30);
        assert_eq!(rig.endpoint.legacy_seq, 4);
    }

    #[test]
    fn a_relative_change_over_the_local_link_applies_and_reports_the_resulting_volume() {
        let mut rig = Rig::new();
        let args = [MASTER[0], MASTER[1], ("Adjustment", "5")];
        let h = rig.legacy(RC, "SetRelativeVolume", &args);
        assert_eq!(h.response.status, 200, "{}", h.response.body);
        assert_eq!(
            h.response.body,
            response_envelope(RC, "SetRelativeVolume", &[("NewVolume", "55".to_string())])
        );
        assert_eq!(rig.member("kitchen").0, 55);
        let h = rig.legacy(
            GRC,
            "SetRelativeGroupVolume",
            &[("InstanceID", "0"), ("Adjustment", "-10")],
        );
        assert_eq!(h.response.status, 200, "{}", h.response.body);
        assert!(h.response.body.contains("<NewVolume>40</NewVolume>"));
        assert_eq!(rig.session.group_master_volume, 40);
    }

    #[test]
    fn a_plain_soap_retry_of_a_relative_change_applies_twice_and_that_is_pinned() {
        // The hazard is real and stated in the contract: plain SOAP has no command id, so the same
        // request sent twice is two steps. This test fails if that ever quietly changes.
        let mut rig = Rig::new();
        let args = [MASTER[0], MASTER[1], ("Adjustment", "5")];
        rig.legacy(RC, "SetRelativeVolume", &args);
        rig.legacy(RC, "SetRelativeVolume", &args);
        assert_eq!(rig.member("kitchen").0, 60, "applied twice");
        assert_eq!(rig.channel.stats().committed, 2);
    }

    #[test]
    fn a_relative_change_is_clamped_to_the_volume_range() {
        let mut rig = Rig::new();
        let up = [MASTER[0], MASTER[1], ("Adjustment", "100")];
        let h = rig.legacy(RC, "SetRelativeVolume", &up);
        assert!(h.response.body.contains("<NewVolume>100</NewVolume>"));
        assert_eq!(rig.member("kitchen").0, 100);
        let down = [MASTER[0], MASTER[1], ("Adjustment", "-100")];
        let h = rig.legacy(RC, "SetRelativeVolume", &down);
        assert!(h.response.body.contains("<NewVolume>0</NewVolume>"));
        assert_eq!(rig.member("kitchen").0, 0);
    }

    #[test]
    fn legacy_commands_can_be_switched_off_and_reads_and_events_still_work() {
        let mut rig = Rig::with(roomy(), |c| c.legacy_commands = false);
        let h = rig.legacy(RC, "SetVolume", &set_volume("30"));
        assert_eq!(h.response.status, 401);
        assert_eq!(rig.member("kitchen").0, 50);
        assert_eq!(rig.legacy(RC, "GetVolume", &MASTER).response.status, 200);
    }

    #[test]
    fn a_local_command_without_a_live_lease_is_refused_and_can_be_sent_again() {
        let mut rig = Rig::new();
        rig.now = 2 * LEASE_EXPIRY_NS;
        let h = rig.legacy(RC, "SetVolume", &set_volume("30"));
        assert_eq!(
            (h.response.status, fault_code(&h).as_deref()),
            (500, Some("501"))
        );
        assert_eq!(rig.member("kitchen").0, 50);
        // The owner renews the lease; the same request now succeeds.
        let token = AuthorityToken::issue(&rig.session, 4 * LEASE_EXPIRY_NS);
        rig.channel
            .install_lease(&rig.session, token, rig.now)
            .unwrap();
        assert_eq!(
            rig.legacy(RC, "SetVolume", &set_volume("30"))
                .response
                .status,
            200
        );
        assert_eq!(rig.member("kitchen").0, 30);
    }

    #[test]
    fn a_local_flood_is_rate_limited_by_n02_and_cannot_starve_anything_else() {
        let mut config = roomy();
        config.ordinary_rate = RateLimit::new(3, 1_000 * MS).unwrap();
        let mut rig = Rig::with(config, |_| {});
        let statuses: Vec<u16> = (0..6)
            .map(|i| {
                rig.legacy(RC, "SetVolume", &set_volume(&(10 + i).to_string()))
                    .response
                    .status
            })
            .collect();
        assert_eq!(statuses[..3], [200, 200, 200]);
        assert!(statuses[3..].iter().all(|s| *s == 500), "{statuses:?}");
        assert_eq!(rig.channel.stats().rejected_rate_limited, 3);
    }

    #[test]
    fn a_revoked_bridge_fails_closed_with_the_owners_problem_not_the_clients() {
        let mut rig = Rig::new();
        rig.channel
            .authority_mut()
            .revoke(&PeerId::parse(BRIDGE).unwrap());
        let h = rig.legacy(RC, "SetVolume", &set_volume("30"));
        assert_eq!(
            (h.response.status, fault_code(&h).as_deref()),
            (500, Some("501"))
        );
        assert!(h.response.body.contains("local control bridge"));
        assert_eq!(rig.member("kitchen").0, 50);
    }

    #[test]
    fn a_member_id_that_cannot_be_a_member_is_refused_at_construction() {
        let too_long = "x".repeat(65);
        for bad in ["", "Kitchen", "has space", too_long.as_str()] {
            let bridge = LegacyBridge::new(PeerId::parse(BRIDGE).unwrap(), test_key(BRIDGE));
            assert_eq!(
                Endpoint::new(EndpointConfig::provisional(bad), bridge, 1, 1).err(),
                Some(EndpointError::MemberId),
                "{bad:?}"
            );
        }
        let bridge = LegacyBridge::new(PeerId::parse(BRIDGE).unwrap(), test_key(BRIDGE));
        assert_eq!(
            Endpoint::new(EndpointConfig::provisional("kitchen"), bridge, 1, 0).err(),
            Some(EndpointError::Zero("first_legacy_seq"))
        );
    }

    #[test]
    fn the_bridge_key_never_appears_in_debug_output() {
        let bridge = LegacyBridge::new(PeerId::parse(BRIDGE).unwrap(), test_key(BRIDGE));
        let shown = format!("{bridge:?}");
        // A derived Debug would print the key's bytes as a list of numbers; "key" is 107, 101, 121.
        assert!(
            shown.contains("redacted") && !shown.contains("107, 101, 121"),
            "{shown}"
        );
        let endpoint = Endpoint::new(EndpointConfig::provisional("kitchen"), bridge, 1, 1).unwrap();
        assert!(!format!("{endpoint:?}").contains("107, 101, 121"));
    }

    // ---- tailnet ------------------------------------------------------------------------------

    fn set_volume_command(v: u8) -> ControlCommand {
        ControlCommand::SetMemberVolume {
            member_id: "kitchen".to_string(),
            volume: v,
        }
    }

    #[test]
    fn a_tailnet_command_with_a_valid_authorization_is_applied_once() {
        let mut rig = Rig::new();
        let headers = tailnet_headers(CTL, CTL, 1, EPOCH, Some(2), set_volume_command(35));
        let h = tail(&mut rig, "SetVolume", &set_volume("35"), &headers);
        assert_eq!(h.response.status, 200, "{}", h.response.body);
        assert_eq!(rig.member("kitchen").0, 35);
        // The same request again is a retry: answered from the ledger, applied once.
        let revision = rig.session.state_revision;
        let h = tail(&mut rig, "SetVolume", &set_volume("35"), &headers);
        assert_eq!(h.response.status, 200);
        assert_eq!(rig.session.state_revision, revision);
        assert_eq!(rig.channel.stats().committed, 1);
    }

    #[test]
    fn a_tailnet_proof_covers_the_soap_arguments_so_a_changed_value_fails() {
        let mut rig = Rig::new();
        // Signed for 35, sent as 90.
        let headers = tailnet_headers(CTL, CTL, 1, EPOCH, Some(2), set_volume_command(35));
        let h = tail(&mut rig, "SetVolume", &set_volume("90"), &headers);
        assert_eq!(h.response.status, 401);
        assert!(h.response.body.is_empty());
        assert_eq!(rig.member("kitchen").0, 50);
        assert_eq!(rig.channel.stats().rejected_unauthenticated, 1);
    }

    #[test]
    fn a_tailnet_proof_from_the_wrong_key_or_for_another_peer_fails() {
        let mut rig = Rig::new();
        let wrong_key = tailnet_headers(CTL, BRIDGE, 1, EPOCH, Some(2), set_volume_command(35));
        assert_eq!(
            tail(&mut rig, "SetVolume", &set_volume("35"), &wrong_key)
                .response
                .status,
            401
        );
        let stranger = tailnet_headers("ghost", "ghost", 1, EPOCH, Some(2), set_volume_command(35));
        assert_eq!(
            tail(&mut rig, "SetVolume", &set_volume("35"), &stranger)
                .response
                .status,
            401
        );
        assert_eq!(rig.member("kitchen").0, 50);
    }

    #[test]
    fn every_tailnet_header_problem_is_the_same_401_with_no_body() {
        let mut rig = Rig::new();
        let good = tailnet_headers(CTL, CTL, 1, EPOCH, Some(2), set_volume_command(35));
        let without = |name: &str| -> Vec<(String, String)> {
            good.iter()
                .filter(|(k, _)| !k.eq_ignore_ascii_case(name))
                .cloned()
                .collect()
        };
        let replaced = |name: &str, value: &str| -> Vec<(String, String)> {
            good.iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        if k.eq_ignore_ascii_case(name) {
                            value.to_string()
                        } else {
                            v.clone()
                        },
                    )
                })
                .collect()
        };
        let long_proof = "ab".repeat(65);
        let mut duplicate = good.clone();
        duplicate.push(("x-franken-seq".to_string(), "1".to_string()));
        let cases = [
            without("X-Franken-Peer"),
            without("X-Franken-Seq"),
            without("X-Franken-Epoch"),
            without("X-Franken-Proof"),
            replaced("X-Franken-Peer", "Not A Peer"),
            replaced("X-Franken-Seq", "abc"),
            replaced("X-Franken-Seq", "-1"),
            replaced("X-Franken-Epoch", "1e3"),
            replaced("X-Franken-Revision", "x"),
            replaced("X-Franken-Proof", "zz"),
            replaced("X-Franken-Proof", "abc"),
            replaced("X-Franken-Proof", ""),
            replaced("X-Franken-Proof", long_proof.as_str()),
            duplicate,
            Vec::new(),
        ];
        for (i, headers) in cases.iter().enumerate() {
            let h = tail(&mut rig, "SetVolume", &set_volume("35"), headers);
            assert_eq!(
                (h.response.status, h.response.body.as_str()),
                (401, ""),
                "case {i}"
            );
        }
        assert_eq!(rig.member("kitchen").0, 50);
    }

    #[test]
    fn a_tailnet_peer_without_authorization_learns_nothing_about_the_matrix() {
        let mut rig = Rig::new();
        let good = tailnet_headers(CTL, CTL, 1, EPOCH, Some(2), set_volume_command(35));
        // Reads, deferred, unknown and retired actions are all the same 401, even with valid headers.
        for (service, action, args) in [
            (RC, "GetVolume", MASTER.to_vec()),
            (ZGT, "GetZoneGroupState", Vec::new()),
            (AVT, "Play", vec![("InstanceID", "0"), ("Speed", "1")]),
            (RC, "NoSuchAction", MASTER.to_vec()),
            (Service::ContentDirectory, "Browse", vec![("ObjectID", "0")]),
            (GRC, "SnapshotGroupVolume", vec![("InstanceID", "0")]),
        ] {
            let h = rig.soap(Ingress::Tailnet, service, action, &args, &borrowed(&good));
            assert_eq!(
                (h.response.status, h.response.body.as_str()),
                (401, ""),
                "{action}"
            );
        }
        // And with no headers at all.
        let h = rig.soap(Ingress::Tailnet, RC, "GetVolume", &MASTER, &[]);
        assert_eq!((h.response.status, h.response.body.as_str()), (401, ""));
    }

    #[test]
    fn a_tailnet_peer_cannot_subscribe_to_events() {
        let mut rig = Rig::new();
        let h = rig.handle(&HttpRequest {
            method: "SUBSCRIBE",
            path: RC.event_path(),
            peer_ip: LAN.parse().unwrap(),
            ingress: Ingress::Tailnet,
            headers: &[
                ("CALLBACK", "<http://192.0.2.10:3400/n>"),
                ("NT", "upnp:event"),
            ],
            body: b"",
        });
        assert_eq!(h.response.status, 401);
        assert!(rig.endpoint.subscriptions().is_empty());
    }

    #[test]
    fn a_tailnet_stale_revision_epoch_and_reused_number_are_refused_by_n02() {
        let mut rig = Rig::new();
        // A revision from before this incarnation (the floor is the revision at the first step).
        rig.legacy(RC, "SetVolume", &set_volume("51"));
        let stale = tailnet_headers(CTL, CTL, 1, EPOCH, Some(1), set_volume_command(60));
        let h = tail(&mut rig, "SetVolume", &set_volume("60"), &stale);
        assert_eq!(
            (h.response.status, fault_code(&h).as_deref()),
            (500, Some("501"))
        );
        assert_eq!(rig.member("kitchen").0, 51);
        // A key bound to another epoch.
        let other_epoch = tailnet_headers(CTL, CTL, 2, EPOCH + 1, Some(3), set_volume_command(60));
        let h = tail(&mut rig, "SetVolume", &set_volume("60"), &other_epoch);
        assert!(
            h.response.body.contains("another epoch"),
            "{}",
            h.response.body
        );
        // A number used for a different command.
        let first = tailnet_headers(CTL, CTL, 3, EPOCH, Some(3), set_volume_command(60));
        assert_eq!(
            tail(&mut rig, "SetVolume", &set_volume("60"), &first)
                .response
                .status,
            200
        );
        let reused = tailnet_headers(CTL, CTL, 3, EPOCH, Some(3), set_volume_command(70));
        let h = tail(&mut rig, "SetVolume", &set_volume("70"), &reused);
        assert!(
            h.response.body.contains("different command"),
            "{}",
            h.response.body
        );
        assert_eq!(rig.member("kitchen").0, 60);
    }

    #[test]
    fn a_tailnet_set_without_a_revision_is_refused_and_a_relative_one_needs_the_exact_revision() {
        let mut rig = Rig::new();
        let body = RequestBody::new(
            PeerId::parse(CTL).unwrap(),
            1,
            EPOCH,
            None,
            set_volume_command(35),
        )
        .unwrap();
        let proof = compute_proof(&test_key(CTL), &body.signing_bytes());
        let no_revision = vec![
            ("X-Franken-Peer".to_string(), CTL.to_string()),
            ("X-Franken-Seq".to_string(), "1".to_string()),
            ("X-Franken-Epoch".to_string(), EPOCH.to_string()),
            ("X-Franken-Proof".to_string(), hex_of(proof.as_bytes())),
        ];
        let h = tail(&mut rig, "SetVolume", &set_volume("35"), &no_revision);
        assert_eq!(
            (h.response.status, fault_code(&h).as_deref()),
            (500, Some("402"))
        );
        // Relative, with no revision at all: refused before anything is verified.
        let rel_args = [MASTER[0], MASTER[1], ("Adjustment", "5")];
        let h = tail(&mut rig, "SetRelativeVolume", &rel_args, &no_revision);
        assert_eq!(
            fault_code(&h).as_deref(),
            Some("402"),
            "{}",
            h.response.body
        );
        // Relative at the exact revision is applied, and reports where the volume ended.
        let cmd = ControlCommand::AdjustMemberVolume {
            member_id: "kitchen".to_string(),
            delta: 5,
        };
        let exact = tailnet_headers(CTL, CTL, 2, EPOCH, Some(2), cmd.clone());
        let h = tail(&mut rig, "SetRelativeVolume", &rel_args, &exact);
        assert_eq!(h.response.status, 200, "{}", h.response.body);
        assert!(h.response.body.contains("<NewVolume>55</NewVolume>"));
        // The same step at the old revision is now a mismatch.
        let late = tailnet_headers(CTL, CTL, 3, EPOCH, Some(2), cmd);
        let h = tail(&mut rig, "SetRelativeVolume", &rel_args, &late);
        assert!(
            h.response.body.contains("changed since it was read"),
            "{}",
            h.response.body
        );
        assert_eq!(rig.member("kitchen").0, 55);
    }

    #[test]
    fn a_tailnet_relative_group_change_reports_the_new_group_volume() {
        let mut rig = Rig::new();
        let cmd = ControlCommand::AdjustGroupVolume { delta: -10 };
        let headers = tailnet_headers(CTL, CTL, 1, EPOCH, Some(2), cmd);
        let args = [("InstanceID", "0"), ("Adjustment", "-10")];
        let h = tail(&mut rig, "SetRelativeGroupVolume", &args, &headers);
        assert_eq!(h.response.status, 200, "{}", h.response.body);
        assert!(h.response.body.contains("<NewVolume>40</NewVolume>"));
    }

    #[test]
    fn a_retried_relative_step_with_the_same_command_id_applies_once() {
        let mut rig = Rig::new();
        let cmd = ControlCommand::AdjustMemberVolume {
            member_id: "kitchen".to_string(),
            delta: 5,
        };
        let headers = tailnet_headers(CTL, CTL, 1, EPOCH, Some(2), cmd);
        let args = [MASTER[0], MASTER[1], ("Adjustment", "5")];
        let first = tail(&mut rig, "SetRelativeVolume", &args, &headers);
        assert_eq!(first.response.status, 200, "{}", first.response.body);
        assert_eq!(rig.member("kitchen").0, 55);
        // The very same request again, as a client does after a lost response.
        let revision = rig.session.state_revision;
        let retry = tail(&mut rig, "SetRelativeVolume", &args, &headers);
        assert_eq!(retry.response.status, 200, "{}", retry.response.body);
        assert_eq!(rig.member("kitchen").0, 55, "not applied again");
        assert_eq!(rig.session.state_revision, revision);
        assert_eq!(rig.channel.stats().committed, 1);
    }

    #[test]
    fn a_tailnet_stop_names_its_time_and_both_are_signed() {
        let mut rig = Rig::new();
        let cmd = ControlCommand::StopGroupPlayback {
            now_ns: 5,
            irrevocable_dma_tail_ns: 7,
        };
        let mut headers = tailnet_headers(CTL, CTL, 1, EPOCH, None, cmd);
        // Without the two stop headers the authorization is incomplete.
        assert_eq!(
            tail(&mut rig, "Stop", &[("InstanceID", "0")], &headers)
                .response
                .status,
            401
        );
        headers.push(("X-Franken-Now-Ns".to_string(), "5".to_string()));
        headers.push(("X-Franken-Dma-Tail-Ns".to_string(), "7".to_string()));
        let h = tail(&mut rig, "Stop", &[("InstanceID", "0")], &headers);
        assert_eq!(h.response.status, 200, "{}", h.response.body);
        // A different time than the one signed fails authentication.
        let mut tampered = tailnet_headers(
            CTL,
            CTL,
            2,
            EPOCH,
            None,
            ControlCommand::StopGroupPlayback {
                now_ns: 5,
                irrevocable_dma_tail_ns: 7,
            },
        );
        tampered.push(("X-Franken-Now-Ns".to_string(), "6".to_string()));
        tampered.push(("X-Franken-Dma-Tail-Ns".to_string(), "7".to_string()));
        assert_eq!(
            tail(&mut rig, "Stop", &[("InstanceID", "0")], &tampered)
                .response
                .status,
            401
        );
    }

    // ---- N02 integration details -------------------------------------------------------------

    #[test]
    fn another_peers_settled_commands_are_handed_back_not_lost() {
        let mut rig = Rig::new();
        // A tailnet controller's command is queued by the owner and not yet stepped.
        let cmd = set_volume_command(66);
        let body = RequestBody::new(PeerId::parse(CTL).unwrap(), 1, EPOCH, Some(2), cmd).unwrap();
        let proof = compute_proof(&test_key(CTL), &body.signing_bytes());
        rig.channel.submit(0, ControlRequest::new(body, proof));
        // A local request steps the channel and settles both.
        let h = rig.legacy(RC, "SetMute", &[MASTER[0], MASTER[1], ("DesiredMute", "1")]);
        assert_eq!(h.response.status, 200, "{}", h.response.body);
        assert_eq!(h.settled_others.len(), 1);
        assert_eq!(h.settled_others[0].peer.as_str(), CTL);
        assert_eq!(rig.member("kitchen"), (66, true));
    }

    #[test]
    fn work_queued_behind_the_request_is_an_honest_fault_not_a_success() {
        let mut config = roomy();
        config.max_per_step = 1;
        let mut rig = Rig::with(config, |c| c.step_rounds = 1);
        // Three ordinary commands from the controller are already waiting.
        for seq in 1..=3u64 {
            let cmd = set_volume_command(u8::try_from(60 + seq).unwrap());
            let body =
                RequestBody::new(PeerId::parse(CTL).unwrap(), seq, EPOCH, Some(2), cmd).unwrap();
            let proof = compute_proof(&test_key(CTL), &body.signing_bytes());
            rig.channel.submit(0, ControlRequest::new(body, proof));
        }
        let h = rig.legacy(RC, "SetVolume", &set_volume("10"));
        assert_eq!(
            (h.response.status, fault_code(&h).as_deref()),
            (500, Some("501"))
        );
        assert!(
            h.response.body.contains("queued behind other work"),
            "{}",
            h.response.body
        );
    }

    // ---- N02 row 8: drop the ack after commit, retry through the adapter ----------------------------
    //
    // "Dropping the ack" is simply not looking at the response: the request is committed by the first
    // call, and the client, having seen nothing, sends the very same bytes again. The judges below are
    // plain functions over a rig, so the same judge can be shown to pass the real adapter and to fail an
    // adapter with a planted defect.

    /// The first request commits; its response is lost; another controller moves the volume on; the
    /// client sends the first request again. Exactly one effect, and the retry reports the committed
    /// result. Every failure begins with `RETRY-REAPPLIED` or `RETRY-ANSWER` so a test can tell *why*.
    fn judge_one_effect(rig: &mut Rig) -> Result<(), String> {
        let headers = tailnet_headers(CTL, CTL, 1, EPOCH, Some(2), set_volume_command(35));
        let args = set_volume("35");
        let before = rig.session.state_revision;
        let _lost = tail(rig, "SetVolume", &args, &headers);
        let committed = rig.session.state_revision;
        if rig.member("kitchen").0 != 35 || committed != before + 1 {
            return Err(format!(
                "RETRY-ANSWER: the first request did not commit once ({before} -> {committed})"
            ));
        }
        let other = tailnet_headers(CTL, CTL, 2, EPOCH, Some(committed), set_volume_command(60));
        let moved = tail(rig, "SetVolume", &set_volume("60"), &other);
        if moved.response.status != 200 {
            return Err("RETRY-ANSWER: the second controller command was refused".to_string());
        }
        let revision = rig.session.state_revision;
        let retry = tail(rig, "SetVolume", &args, &headers);
        if retry.response.status != 200
            || retry.response.body != response_envelope(RC, "SetVolume", &[])
        {
            return Err(format!(
                "RETRY-ANSWER: the retry did not report the committed result ({})",
                retry.response.status
            ));
        }
        if rig.session.state_revision != revision || rig.member("kitchen").0 != 60 {
            return Err("RETRY-REAPPLIED: the retry changed the group again".to_string());
        }
        if rig.channel.stats().committed != 2 {
            return Err("RETRY-REAPPLIED: more than two commits for two commands".to_string());
        }
        Ok(())
    }

    /// The first request commits and its response is lost. Retention passes. The retry gets a typed
    /// fault that says the outcome is unknown, and nothing is applied. Failures begin with
    /// `NO-TYPED-FAULT` or `RETRY-REAPPLIED`.
    fn judge_unknown_after_retention(rig: &mut Rig) -> Result<(), String> {
        let headers = tailnet_headers(CTL, CTL, 1, EPOCH, Some(2), set_volume_command(35));
        let args = set_volume("35");
        let _lost = tail(rig, "SetVolume", &args, &headers);
        if rig.member("kitchen").0 != 35 {
            return Err("NO-TYPED-FAULT: the first request did not commit".to_string());
        }
        let revision = rig.session.state_revision;
        rig.now = 31_000 * MS; // retention is 30 s in this configuration
        let retry = tail(rig, "SetVolume", &args, &headers);
        if retry.response.status != 500 || fault_code(&retry).as_deref() != Some("801") {
            return Err(format!(
                "NO-TYPED-FAULT: expected fault 801, got status {} code {:?}",
                retry.response.status,
                fault_code(&retry)
            ));
        }
        if !retry.response.body.contains("Command Outcome Unknown") {
            return Err(
                "NO-TYPED-FAULT: the fault does not say the outcome is unknown".to_string(),
            );
        }
        if rig.session.state_revision != revision || rig.channel.stats().out_of_window != 1 {
            return Err("RETRY-REAPPLIED: the forgotten command changed the group".to_string());
        }
        // The sender reads the state and sends a new command: that works.
        let fresh = tailnet_headers(CTL, CTL, 2, EPOCH, Some(revision), set_volume_command(40));
        let sent = tail(rig, "SetVolume", &set_volume("40"), &fresh);
        if sent.response.status != 200 || rig.member("kitchen").0 != 40 {
            return Err(
                "NO-TYPED-FAULT: a fresh command after the unknown outcome failed".to_string(),
            );
        }
        Ok(())
    }

    #[test]
    fn a_dropped_ack_then_a_retry_through_the_adapter_is_one_effect() {
        let mut rig = Rig::new();
        assert_eq!(judge_one_effect(&mut rig), Ok(()));
    }

    #[test]
    fn after_retention_a_retry_through_the_adapter_is_a_typed_out_of_window_fault() {
        let mut rig = Rig::new();
        assert_eq!(judge_unknown_after_retention(&mut rig), Ok(()));
    }

    #[test]
    fn a_relative_step_retried_after_retention_is_unknown_and_never_applied_again() {
        let mut rig = Rig::new();
        let cmd = ControlCommand::AdjustMemberVolume {
            member_id: "kitchen".to_string(),
            delta: 5,
        };
        let headers = tailnet_headers(CTL, CTL, 1, EPOCH, Some(2), cmd);
        let args = [MASTER[0], MASTER[1], ("Adjustment", "5")];
        tail(&mut rig, "SetRelativeVolume", &args, &headers);
        assert_eq!(rig.member("kitchen").0, 55);
        let revision = rig.session.state_revision;
        rig.now = 31_000 * MS;
        let retry = tail(&mut rig, "SetRelativeVolume", &args, &headers);
        assert_eq!(fault_code(&retry).as_deref(), Some("801"));
        assert_eq!(rig.member("kitchen").0, 55, "the step was not taken again");
        assert_eq!(rig.session.state_revision, revision);
    }

    #[test]
    fn a_retry_that_outlives_a_channel_restart_is_refused_not_reapplied() {
        // Not a process restart: the channel is replaced on the same session, so its ledger is empty and
        // it remembers no floors. What stops the old copy is the session's revision.
        let mut rig = Rig::new();
        let headers = tailnet_headers(CTL, CTL, 1, EPOCH, Some(2), set_volume_command(35));
        let args = set_volume("35");
        tail(&mut rig, "SetVolume", &args, &headers);
        rig.legacy(RC, "SetVolume", &set_volume("60"));
        let revision = rig.session.state_revision;
        rig.restart_channel();
        let retry = tail(&mut rig, "SetVolume", &args, &headers);
        assert_eq!(
            (retry.response.status, fault_code(&retry).as_deref()),
            (500, Some("501"))
        );
        assert!(
            retry
                .response
                .body
                .contains("composed before the last restart"),
            "{}",
            retry.response.body
        );
        assert_eq!(rig.session.state_revision, revision);
        assert_eq!(
            rig.member("kitchen").0,
            60,
            "the old copy did not put 35 back"
        );
    }

    #[test]
    fn the_planted_adapter_that_reapplies_on_retry_fails_the_one_effect_judge() {
        let mut broken = Rig::new();
        broken.endpoint.plant(Defect::ReapplyOnRetry);
        let verdict = judge_one_effect(&mut broken);
        assert!(
            verdict
                .as_ref()
                .is_err_and(|e| e.starts_with("RETRY-REAPPLIED")),
            "the planted defect was not caught for the right reason: {verdict:?}"
        );
        // Remove-the-plant control: the plant is what failed it. The same defect does not touch the other
        // judge (a retry after retention never reaches the ledger's answer), and the unplanted adapter
        // passes this one.
        let mut other = Rig::new();
        other.endpoint.plant(Defect::ReapplyOnRetry);
        assert_eq!(judge_unknown_after_retention(&mut other), Ok(()));
        assert_eq!(judge_one_effect(&mut Rig::new()), Ok(()));
    }

    #[test]
    fn the_planted_adapter_that_answers_success_after_retention_fails_the_retention_judge() {
        let mut broken = Rig::new();
        broken.endpoint.plant(Defect::SuccessAfterRetention);
        let verdict = judge_unknown_after_retention(&mut broken);
        assert!(
            verdict
                .as_ref()
                .is_err_and(|e| e.starts_with("NO-TYPED-FAULT")),
            "the planted defect was not caught for the right reason: {verdict:?}"
        );
        let mut other = Rig::new();
        other.endpoint.plant(Defect::SuccessAfterRetention);
        assert_eq!(judge_one_effect(&mut other), Ok(()));
        assert_eq!(judge_unknown_after_retention(&mut Rig::new()), Ok(()));
    }

    // ---- acknowledgements (N02 section 7), through the adapter ---------------------------------
    //
    // An acknowledgement is the sender saying it saw the outcome of one of its commands. As for row 8, each
    // check is a plain function over a rig, so it can be shown to pass the real adapter and to fail an
    // adapter with one planted defect. A failure begins with a tag that says why.

    /// What a tailnet client sends to acknowledge command `seq`, issued under `epoch`: the identity headers
    /// of a command and a proof over the acknowledgement's own bytes, made with `key_of`'s key.
    fn ack_headers(peer: &str, key_of: &str, seq: u64, epoch: u64) -> Vec<(String, String)> {
        let body = AckBody::new(PeerId::parse(peer).unwrap(), seq, epoch).unwrap();
        let proof = compute_proof(&test_key(key_of), &body.signing_bytes());
        vec![
            ("X-Franken-Peer".to_string(), peer.to_string()),
            ("X-Franken-Seq".to_string(), seq.to_string()),
            ("X-Franken-Epoch".to_string(), epoch.to_string()),
            ("X-Franken-Proof".to_string(), hex_of(proof.as_bytes())),
        ]
    }

    /// `POST` [`ACK_PATH`] on `ingress` with exactly these headers and this body.
    fn ack_with(
        rig: &mut Rig,
        ingress: Ingress,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Handled {
        let headers = borrowed(headers);
        rig.handle(&HttpRequest {
            method: "POST",
            path: ACK_PATH,
            peer_ip: LAN.parse().unwrap(),
            ingress,
            headers: &headers,
            body,
        })
    }

    /// A tailnet acknowledgement of `CTL`'s command `seq`, issued under `epoch`, signed by `CTL`.
    fn ack(rig: &mut Rig, seq: u64, epoch: u64) -> Handled {
        ack_with(
            rig,
            Ingress::Tailnet,
            &ack_headers(CTL, CTL, seq, epoch),
            b"",
        )
    }

    fn ack_word(h: &Handled) -> Option<&str> {
        h.response
            .headers
            .iter()
            .find(|(name, _)| name == H_ACK)
            .map(|(_, word)| word.as_str())
    }

    /// The status and the word of an acknowledgement's answer, to compare in one go.
    fn ack_answer(h: &Handled) -> (u16, Option<&str>) {
        (h.response.status, ack_word(h))
    }

    /// `CTL`'s command `seq` sets the kitchen to `volume`, composed from the current revision. It must commit.
    fn commit_volume(rig: &mut Rig, seq: u64, volume: u8) -> Result<(), String> {
        let revision = Some(rig.session.state_revision);
        let headers = tailnet_headers(CTL, CTL, seq, EPOCH, revision, set_volume_command(volume));
        let text = volume.to_string();
        let h = tail(rig, "SetVolume", &set_volume(&text), &headers);
        if h.response.status == 200 && rig.member("kitchen").0 == volume {
            Ok(())
        } else {
            Err(format!(
                "ACK-SETUP: command {seq} was not applied ({})",
                h.response.status
            ))
        }
    }

    /// `CTL`'s command `seq` is accepted by the channel and not stepped: it waits in the queue.
    fn queue_volume(rig: &mut Rig, seq: u64, volume: u8) -> Result<(), String> {
        let body = RequestBody::new(
            PeerId::parse(CTL).unwrap(),
            seq,
            EPOCH,
            Some(rig.session.state_revision),
            set_volume_command(volume),
        )
        .unwrap();
        let proof = compute_proof(&test_key(CTL), &body.signing_bytes());
        match rig
            .channel
            .submit(rig.now, ControlRequest::new(body, proof))
        {
            SubmitResult::Queued { .. } => Ok(()),
            other => Err(format!(
                "ACK-SETUP: command {seq} was not queued: {other:?}"
            )),
        }
    }

    /// The group moves to epoch 11 (a newer issuer is adopted), the owner installs the lease for it, and the
    /// controller's key is rebound, as N02's own acknowledgement tests do.
    fn move_to_epoch_11(rig: &mut Rig) {
        rig.session
            .apply_command(FencedControlCommand {
                epoch: 11,
                command_seq: 5,
                payload: GroupCommandPayload::MarkMemberClockLocked {
                    member_id: "kitchen".to_string(),
                },
            })
            .expect("a newer epoch is adopted");
        let token = AuthorityToken::issue(&rig.session, LEASE_EXPIRY_NS);
        rig.channel
            .install_lease(&rig.session, token, rig.now)
            .unwrap();
        rig.channel
            .authority_mut()
            .rebind(&PeerId::parse(CTL).unwrap(), Some(11));
    }

    fn group_json(rig: &Rig) -> serde_json::Value {
        serde_json::to_value(&rig.session).expect("the session serializes")
    }

    /// A command commits and is acknowledged exactly at the budget (on time, `200`), the same acknowledgement
    /// again is a duplicate (`200`), and each reached the channel. Failures begin `ACK-NOT-CARRIED` (the
    /// channel was never told) or `ACK-WORD` (the adapter said the wrong word).
    fn judge_ack_is_carried(rig: &mut Rig) -> Result<(), String> {
        let headers = tailnet_headers(CTL, CTL, 1, EPOCH, Some(2), set_volume_command(35));
        let committed = tail(rig, "SetVolume", &set_volume("35"), &headers);
        if committed.response.status != 200 || rig.member("kitchen").0 != 35 {
            return Err("ACK-SETUP: the command did not commit".to_string());
        }
        if rig.channel.unacked() != 1 {
            return Err("ACK-SETUP: the outcome is not waiting to be acknowledged".to_string());
        }
        rig.now = 2_000 * MS; // exactly the budget after the outcome: on time
        let first = ack(rig, 1, EPOCH);
        if ack_answer(&first) != (200, Some("on_time")) {
            return Err(format!(
                "ACK-WORD: the first acknowledgement was answered {:?}",
                ack_answer(&first)
            ));
        }
        let stats = *rig.channel.stats();
        if stats.acks_received != 1 || stats.acks_on_time != 1 || rig.channel.unacked() != 0 {
            return Err(format!(
                "ACK-NOT-CARRIED: the channel did not complete the entry ({stats:?})"
            ));
        }
        let again = ack(rig, 1, EPOCH);
        if ack_answer(&again) != (200, Some("duplicate")) || rig.channel.stats().acks_duplicate != 1
        {
            return Err(format!(
                "ACK-WORD: the repeated acknowledgement was answered {:?}",
                ack_answer(&again)
            ));
        }
        Ok(())
    }

    /// A late acknowledgement and one for a command issued under an epoch the group has left both complete
    /// their entries, and each says so by name (`200`). Failures begin `ACK-WORD` or `ACK-NOT-CARRIED`.
    fn judge_ack_late_and_superseded(rig: &mut Rig) -> Result<(), String> {
        commit_volume(rig, 1, 35)?;
        rig.now = 2_001 * MS; // one millisecond over the budget
        let late = ack(rig, 1, EPOCH);
        if ack_answer(&late) != (200, Some("late")) {
            return Err(format!(
                "ACK-WORD: the late acknowledgement was answered {:?}",
                ack_answer(&late)
            ));
        }
        commit_volume(rig, 2, 60)?;
        move_to_epoch_11(rig);
        rig.now = 2_500 * MS;
        let superseded = ack(rig, 2, EPOCH);
        if ack_answer(&superseded) != (200, Some("superseded")) {
            return Err(format!(
                "ACK-WORD: the superseded acknowledgement was answered {:?}",
                ack_answer(&superseded)
            ));
        }
        let stats = *rig.channel.stats();
        if (stats.acks_received, stats.acks_late, stats.acks_superseded) != (2, 1, 1) {
            return Err(format!(
                "ACK-NOT-CARRIED: the channel's counts differ ({stats:?})"
            ));
        }
        Ok(())
    }

    /// An acknowledgement that completes nothing (a number never seen, another epoch, a command still waiting,
    /// a number the channel has forgotten) is a `409` with its word, never a success. Failures begin
    /// `FALSE-ACK-SUCCESS` (a success status), `ACK-WORD` or `ACK-NOT-CARRIED`.
    fn judge_ack_that_completed_nothing_is_never_a_success(rig: &mut Rig) -> Result<(), String> {
        commit_volume(rig, 1, 35)?;
        queue_volume(rig, 2, 60)?;
        let mut answers = vec![
            ("unknown", ack(rig, 9, EPOCH)),
            ("mismatch", ack(rig, 1, EPOCH + 1)),
            ("not_settled", ack(rig, 2, EPOCH)),
        ];
        rig.now = 31_000 * MS; // retention is 30 s in this configuration
        answers.push(("out_of_window", ack(rig, 1, EPOCH)));
        for (word, answer) in &answers {
            if answer.response.status != 409 {
                return Err(format!(
                    "FALSE-ACK-SUCCESS: `{word}` was answered {}",
                    answer.response.status
                ));
            }
            if ack_word(answer) != Some(*word) {
                return Err(format!(
                    "ACK-WORD: `{word}` was answered {:?}",
                    ack_word(answer)
                ));
            }
        }
        let stats = *rig.channel.stats();
        let counts = (
            stats.acks_received,
            stats.acks_unknown,
            stats.acks_mismatch,
            stats.acks_not_settled,
            stats.acks_out_of_window,
        );
        if counts != (4, 1, 1, 1, 1) {
            return Err(format!(
                "ACK-NOT-CARRIED: the channel's counts differ ({stats:?})"
            ));
        }
        Ok(())
    }

    /// With a subscriber and a command waiting in the queue, an acknowledgement that completes its entry
    /// steps nothing, publishes nothing and changes neither the group, the queue nor the ledger. Failures
    /// begin `ACK-DROVE-THE-CHANNEL` (or `ACK-WORD`).
    fn judge_ack_is_inert(rig: &mut Rig) -> Result<(), String> {
        if rig.event("SUBSCRIBE", RC, &SUB).response.status != 200 {
            return Err("ACK-SETUP: the subscription was refused".to_string());
        }
        commit_volume(rig, 1, 35)?;
        queue_volume(rig, 2, 60)?;
        let before = (group_json(rig), rig.channel.diagnostics(&rig.session));
        let answered = ack(rig, 1, EPOCH);
        if ack_answer(&answered) != (200, Some("on_time")) {
            return Err(format!(
                "ACK-WORD: the acknowledgement was answered {:?}",
                ack_answer(&answered)
            ));
        }
        if !answered.notifications.is_empty() || !answered.settled_others.is_empty() {
            return Err(
                "ACK-DROVE-THE-CHANNEL: the acknowledgement stepped or published".to_string(),
            );
        }
        let after = (group_json(rig), rig.channel.diagnostics(&rig.session));
        if before.0 != after.0
            || before.1.ordinary_pending != after.1.ordinary_pending
            || before.1.ledger_len != after.1.ledger_len
            || before.1.stats.committed != after.1.stats.committed
        {
            return Err(
                "ACK-DROVE-THE-CHANNEL: the group, the queue or the ledger moved".to_string(),
            );
        }
        Ok(())
    }

    /// The acknowledgement route is the tailnet's alone and is silent to a caller who cannot prove who it is:
    /// the local link answers `404` and never reaches the channel, and every authentication failure is the
    /// answer a request with no authorization gets. Failures begin `ACK-ON-LEGACY` or `ACK-ORACLE`.
    fn judge_ack_is_tailnet_only_and_silent(rig: &mut Rig) -> Result<(), String> {
        commit_volume(rig, 1, 35)?;
        let good = ack_headers(CTL, CTL, 1, EPOCH);
        let legacy = ack_with(rig, Ingress::LocalLegacy, &good, b"");
        if legacy.response.status != 404 || rig.channel.stats().acks_received != 0 {
            return Err(format!(
                "ACK-ON-LEGACY: the local link answered {}",
                legacy.response.status
            ));
        }
        let silent = ack_with(rig, Ingress::Tailnet, &[], b"");
        if silent.response != HttpResponse::empty(401) {
            return Err("ACK-SETUP: a request with no authorization is not a bare 401".to_string());
        }
        let mut other_number = good.clone();
        for (name, value) in &mut other_number {
            if name.eq_ignore_ascii_case(H_SEQ) {
                *value = "2".to_string();
            }
        }
        if !rig
            .channel
            .authority_mut()
            .revoke(&PeerId::parse(BRIDGE).unwrap())
        {
            return Err("ACK-SETUP: the bridge was not admitted".to_string());
        }
        let strangers = [
            (
                "a proof made with another peer's key",
                ack_headers(CTL, BRIDGE, 1, EPOCH),
            ),
            ("a proof for another number", other_number),
            (
                "a peer the channel never admitted",
                ack_headers("ghost", "ghost", 1, EPOCH),
            ),
            (
                "a peer that was revoked",
                ack_headers(BRIDGE, BRIDGE, 1, EPOCH),
            ),
        ];
        for (why, headers) in &strangers {
            let h = ack_with(rig, Ingress::Tailnet, headers, b"");
            if h.response != silent.response {
                return Err(format!(
                    "ACK-ORACLE: {why} was answered {}, not as a request with no authorization",
                    h.response.status
                ));
            }
        }
        let stats = *rig.channel.stats();
        if stats.acks_received != 4 || stats.acks_rejected_unauthenticated != 4 {
            return Err(format!(
                "ACK-ORACLE: the channel's counts differ ({stats:?})"
            ));
        }
        Ok(())
    }

    #[test]
    fn an_acknowledgement_reaches_the_channel_and_is_answered_with_its_typed_outcome() {
        let mut rig = Rig::new();
        assert_eq!(judge_ack_is_carried(&mut rig), Ok(()));
        // Acknowledging does not make the adapter forget the command: its retry is still one effect.
        let revision = rig.session.state_revision;
        let headers = tailnet_headers(CTL, CTL, 1, EPOCH, Some(2), set_volume_command(35));
        let retry = tail(&mut rig, "SetVolume", &set_volume("35"), &headers);
        assert_eq!(retry.response.status, 200);
        assert_eq!(rig.session.state_revision, revision);
        assert_eq!(rig.channel.stats().committed, 1);
        assert_eq!(
            rig.channel.stats().acks_accounted(),
            rig.channel.stats().acks_received
        );
    }

    #[test]
    fn a_late_or_superseded_acknowledgement_still_completes_its_entry_and_says_which() {
        let mut rig = Rig::new();
        assert_eq!(judge_ack_late_and_superseded(&mut rig), Ok(()));
        assert_eq!(rig.channel.unacked(), 0);
    }

    #[test]
    fn an_acknowledgement_that_completed_nothing_is_a_409_with_its_word_and_changes_nothing() {
        let mut rig = Rig::new();
        assert_eq!(
            judge_ack_that_completed_nothing_is_never_a_success(&mut rig),
            Ok(())
        );
        // The refusals did not touch the command that was waiting: it is still waiting, and its entry
        // for command 1 was never completed by them.
        assert_eq!(rig.channel.diagnostics(&rig.session).ordinary_pending, 1);
        assert_eq!(rig.channel.unacked(), 0, "command 1's entry has aged out");
    }

    #[test]
    fn an_acknowledgement_is_inert_and_a_waiting_command_still_applies_afterwards() {
        let mut rig = Rig::new();
        assert_eq!(judge_ack_is_inert(&mut rig), Ok(()));
        // Positive control: the waiting command was neither lost nor applied early.
        assert_eq!(rig.member("kitchen").0, 35);
        let settled = rig.channel.step(rig.now, &mut rig.session);
        assert!(
            settled.iter().any(|s| s.seq == 2),
            "the waiting command settled at the next step"
        );
        assert_eq!(rig.member("kitchen").0, 60);
    }

    #[test]
    fn acknowledgements_are_tailnet_only_and_every_authentication_failure_is_the_same_401() {
        let mut rig = Rig::new();
        assert_eq!(judge_ack_is_tailnet_only_and_silent(&mut rig), Ok(()));
        // Positive control: none of the failed acknowledgements consumed the entry; the genuine one is
        // still on time.
        let genuine = ack(&mut rig, 1, EPOCH);
        assert_eq!(ack_answer(&genuine), (200, Some("on_time")));
    }

    #[test]
    fn every_acknowledgement_header_problem_is_the_same_401_with_no_body() {
        let mut rig = Rig::new();
        commit_volume(&mut rig, 1, 35).unwrap();
        let good = ack_headers(CTL, CTL, 1, EPOCH);
        let without = |name: &str| -> Vec<(String, String)> {
            good.iter()
                .filter(|(k, _)| !k.eq_ignore_ascii_case(name))
                .cloned()
                .collect()
        };
        let replaced = |name: &str, value: &str| -> Vec<(String, String)> {
            good.iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        if k.eq_ignore_ascii_case(name) {
                            value.to_string()
                        } else {
                            v.clone()
                        },
                    )
                })
                .collect()
        };
        let long_proof = "ab".repeat(65);
        let mut duplicate = good.clone();
        duplicate.push(("x-franken-seq".to_string(), "1".to_string()));
        let cases = [
            without("X-Franken-Peer"),
            without("X-Franken-Seq"),
            without("X-Franken-Epoch"),
            without("X-Franken-Proof"),
            replaced("X-Franken-Peer", "Not A Peer"),
            replaced("X-Franken-Seq", "abc"),
            replaced("X-Franken-Seq", "-1"),
            replaced("X-Franken-Seq", "0"),
            replaced("X-Franken-Epoch", "1e3"),
            replaced("X-Franken-Proof", "zz"),
            replaced("X-Franken-Proof", "abc"),
            replaced("X-Franken-Proof", ""),
            replaced("X-Franken-Proof", long_proof.as_str()),
            duplicate,
            Vec::new(),
        ];
        for (i, headers) in cases.iter().enumerate() {
            let h = ack_with(&mut rig, Ingress::Tailnet, headers, b"");
            assert_eq!(h.response, HttpResponse::empty(401), "case {i}");
        }
        // The acknowledgement is the headers alone: a body makes it something else, and is refused.
        let h = ack_with(&mut rig, Ingress::Tailnet, &good, b"x");
        assert_eq!(h.response, HttpResponse::empty(401));
        assert_eq!(
            rig.channel.stats().acks_received,
            0,
            "none of these reached the channel"
        );
        // Permitted positive: the same headers without the problem are accepted.
        let h = ack_with(&mut rig, Ingress::Tailnet, &good, b"");
        assert_eq!(ack_answer(&h), (200, Some("on_time")));
    }

    #[test]
    fn the_acknowledgement_route_is_a_post_route_of_its_own() {
        let mut rig = Rig::new();
        // It is no SOAP control or event path, so nothing else can reach it by accident.
        assert_eq!(Service::from_control_path(ACK_PATH), None);
        assert_eq!(Service::from_event_path(ACK_PATH), None);
        assert_eq!(rig.bare("GET", ACK_PATH).response.status, 405);
        assert_eq!(rig.bare("SUBSCRIBE", ACK_PATH).response.status, 404);
        assert_eq!(rig.bare("UNSUBSCRIBE", ACK_PATH).response.status, 404);
        // A POST with no headers on the local link is the route's own 404, not a SOAP fault.
        let h = rig.bare("POST", ACK_PATH);
        assert_eq!(h.response, HttpResponse::empty(404));
    }

    #[test]
    fn the_planted_adapter_that_swallows_acknowledgements_fails_the_carried_judge() {
        let mut broken = Rig::new();
        broken.endpoint.plant(Defect::AckSwallowed);
        let verdict = judge_ack_is_carried(&mut broken);
        assert!(
            verdict
                .as_ref()
                .is_err_and(|e| e.starts_with("ACK-NOT-CARRIED")),
            "the planted defect was not caught for the right reason: {verdict:?}"
        );
        // It also answers a refusal with a success, so the refusal judge sees it from its own side.
        let mut other = Rig::new();
        other.endpoint.plant(Defect::AckSwallowed);
        let verdict = judge_ack_that_completed_nothing_is_never_a_success(&mut other);
        assert!(
            verdict
                .as_ref()
                .is_err_and(|e| e.starts_with("FALSE-ACK-SUCCESS")),
            "{verdict:?}"
        );
        // Remove-the-plant control.
        assert_eq!(judge_ack_is_carried(&mut Rig::new()), Ok(()));
    }

    #[test]
    fn the_planted_adapter_that_turns_a_refusal_into_a_success_fails_the_refusal_judge() {
        let mut broken = Rig::new();
        broken.endpoint.plant(Defect::AckAlwaysOk);
        let verdict = judge_ack_that_completed_nothing_is_never_a_success(&mut broken);
        assert!(
            verdict
                .as_ref()
                .is_err_and(|e| e.starts_with("FALSE-ACK-SUCCESS")),
            "the planted defect was not caught for the right reason: {verdict:?}"
        );
        // It leaves a completed acknowledgement alone, so the carried judge is satisfied.
        let mut other = Rig::new();
        other.endpoint.plant(Defect::AckAlwaysOk);
        assert_eq!(judge_ack_is_carried(&mut other), Ok(()));
        assert_eq!(
            judge_ack_that_completed_nothing_is_never_a_success(&mut Rig::new()),
            Ok(())
        );
    }

    #[test]
    fn the_planted_adapter_that_calls_a_late_acknowledgement_on_time_fails_the_word_judge() {
        let mut broken = Rig::new();
        broken.endpoint.plant(Defect::AckWordCollapsed);
        let verdict = judge_ack_late_and_superseded(&mut broken);
        assert!(
            verdict.as_ref().is_err_and(|e| e.starts_with("ACK-WORD")),
            "the planted defect was not caught for the right reason: {verdict:?}"
        );
        // It leaves an on-time acknowledgement alone, so the carried judge is satisfied.
        let mut other = Rig::new();
        other.endpoint.plant(Defect::AckWordCollapsed);
        assert_eq!(judge_ack_is_carried(&mut other), Ok(()));
        assert_eq!(judge_ack_late_and_superseded(&mut Rig::new()), Ok(()));
    }

    #[test]
    fn the_planted_adapter_that_steps_the_channel_after_an_acknowledgement_fails_the_inert_judge() {
        let mut broken = Rig::new();
        broken.endpoint.plant(Defect::AckDrivesChannel);
        let verdict = judge_ack_is_inert(&mut broken);
        assert!(
            verdict
                .as_ref()
                .is_err_and(|e| e.starts_with("ACK-DROVE-THE-CHANNEL")),
            "the planted defect was not caught for the right reason: {verdict:?}"
        );
        // With nothing waiting there is nothing for it to drive, so the other completing judges pass.
        let mut other = Rig::new();
        other.endpoint.plant(Defect::AckDrivesChannel);
        assert_eq!(judge_ack_is_carried(&mut other), Ok(()));
        let mut another = Rig::new();
        another.endpoint.plant(Defect::AckDrivesChannel);
        assert_eq!(judge_ack_late_and_superseded(&mut another), Ok(()));
        assert_eq!(judge_ack_is_inert(&mut Rig::new()), Ok(()));
    }

    #[test]
    fn the_planted_adapter_that_tells_a_bad_proof_apart_fails_the_silence_judge() {
        let mut broken = Rig::new();
        broken.endpoint.plant(Defect::AckUnauthenticatedTold);
        let verdict = judge_ack_is_tailnet_only_and_silent(&mut broken);
        assert!(
            verdict.as_ref().is_err_and(|e| e.starts_with("ACK-ORACLE")),
            "the planted defect was not caught for the right reason: {verdict:?}"
        );
        // It leaves a genuine acknowledgement alone, so the carried judge is satisfied.
        let mut other = Rig::new();
        other.endpoint.plant(Defect::AckUnauthenticatedTold);
        assert_eq!(judge_ack_is_carried(&mut other), Ok(()));
        assert_eq!(
            judge_ack_is_tailnet_only_and_silent(&mut Rig::new()),
            Ok(())
        );
    }

    #[test]
    fn the_planted_adapter_that_serves_acknowledgements_on_the_local_link_fails_the_silence_judge()
    {
        let mut broken = Rig::new();
        broken.endpoint.plant(Defect::AckOnLegacy);
        let verdict = judge_ack_is_tailnet_only_and_silent(&mut broken);
        assert!(
            verdict
                .as_ref()
                .is_err_and(|e| e.starts_with("ACK-ON-LEGACY")),
            "the planted defect was not caught for the right reason: {verdict:?}"
        );
        // It leaves the tailnet route alone, so the carried judge is satisfied.
        let mut other = Rig::new();
        other.endpoint.plant(Defect::AckOnLegacy);
        assert_eq!(judge_ack_is_carried(&mut other), Ok(()));
    }

    const DISCOVERY_UUID: &str = "00000000-0000-4000-8000-00000000a001";
    const OTHER_UUID: &str = "00000000-0000-4000-8000-00000000a002";

    fn discovery_device(uuid: &str, port: u16, name: &str) -> ssdp::Device {
        ssdp::Device::new(uuid, [127, 0, 0, 1], port, name, ssdp::MIN_MAX_AGE).unwrap()
    }

    fn discovery_rig() -> Rig {
        let mut rig = Rig::with(roomy(), |c| c.member_id = DISCOVERY_UUID.to_string());
        admit(&mut rig, DISCOVERY_UUID, 3);
        rig
    }

    #[test]
    fn discovery_get_and_topology_share_owner_device_without_changing_session() {
        let mut rig = discovery_rig();
        let device = discovery_device(DISCOVERY_UUID, 1400, "Kitchen & Den");
        let location = device.location();
        let expected = device.description_xml();
        let revision = rig.session.state_revision;
        let epoch = rig.session.current_epoch;
        let member_count = rig.session.members.len();
        let session_before = format!("{:?}", rig.session);
        let lease_before = rig.channel.lease().cloned();
        rig.endpoint.configure_discovery(device).unwrap();
        let h = rig.bare("GET", ssdp::DESCRIPTION_PATH);
        assert_eq!(h.response.status, 200);
        assert_eq!(h.response.body, expected);
        assert_eq!(
            h.response.headers,
            [
                (
                    "CONTENT-TYPE".to_string(),
                    ssdp::DESCRIPTION_CONTENT_TYPE.to_string()
                ),
                ("CONTENT-LOCATION".to_string(), location.clone()),
                (
                    "CACHE-CONTROL".to_string(),
                    format!("max-age={}", ssdp::MIN_MAX_AGE)
                ),
            ]
        );
        assert!(h.notifications.is_empty());
        assert!(h.settled_others.is_empty());
        assert!(
            h.response
                .body
                .contains(&format!("<UDN>uuid:{DISCOVERY_UUID}</UDN>"))
        );
        let topology = read_topology(&mut rig);
        assert!(topology.contains(&format!(
            "UUID=\"{DISCOVERY_UUID}\" Location=\"{location}\" ZoneName=\"Kitchen &amp; Den\""
        )));
        assert_eq!(rig.session.state_revision, revision);
        assert_eq!(rig.session.current_epoch, epoch);
        assert_eq!(rig.session.members.len(), member_count);
        assert_eq!(format!("{:?}", rig.session), session_before);
        assert_eq!(rig.channel.lease(), lease_before.as_ref());
    }

    #[test]
    fn discovery_refuses_unconfigured_tailnet_and_mismatched_without_partial_mutation() {
        let mut rig = discovery_rig();
        assert_eq!(rig.bare("GET", ssdp::DESCRIPTION_PATH).response.status, 404);
        let denied = |rig: &mut Rig| {
            rig.handle(&HttpRequest {
                method: "GET",
                path: ssdp::DESCRIPTION_PATH,
                peer_ip: LAN.parse().unwrap(),
                ingress: Ingress::Tailnet,
                headers: &[],
                body: b"",
            })
        };
        let legacy = denied(&mut rig);
        assert_eq!(legacy.response.status, 405);
        assert!(legacy.response.body.is_empty());
        assert!(legacy.response.headers.is_empty()); // In particular, no Allow header.
        assert!(legacy.notifications.is_empty());
        assert!(legacy.settled_others.is_empty());
        let before = rig.endpoint.directory.clone();
        assert_eq!(
            rig.endpoint
                .configure_discovery(discovery_device(OTHER_UUID, 1400, "Wrong")),
            Err(EndpointError::DiscoveryIdentityMismatch)
        );
        assert_eq!(rig.endpoint.directory, before);
        assert_eq!(rig.bare("GET", ssdp::DESCRIPTION_PATH).response.status, 404);
        let valid = discovery_device(DISCOVERY_UUID, 1400, "Kitchen");
        rig.endpoint.configure_discovery(valid.clone()).unwrap();
        assert_eq!(denied(&mut rig).response.status, 401);
        assert_eq!(rig.bare("GET", "/other").response.status, 405);
        let before = rig.endpoint.directory.clone();
        assert_eq!(
            rig.endpoint
                .configure_discovery(discovery_device(OTHER_UUID, 1401, "Wrong")),
            Err(EndpointError::DiscoveryIdentityMismatch)
        );
        assert_eq!(rig.endpoint.directory, before);
        assert_eq!(
            rig.bare("GET", ssdp::DESCRIPTION_PATH).response.body,
            valid.description_xml()
        );
    }

    #[test]
    fn discovery_reconfiguration_and_directory_drift_keep_read_and_event_identity_coherent() {
        let mut rig = discovery_rig();
        let first = discovery_device(DISCOVERY_UUID, 1400, "Kitchen");
        rig.endpoint.configure_discovery(first).unwrap();
        let subscription = rig.event("SUBSCRIBE", ZGT, &SUB);
        assert_eq!(subscription.response.status, 200);
        let second = discovery_device(DISCOVERY_UUID, 1500, "New & Room");
        rig.endpoint.configure_discovery(second.clone()).unwrap();
        let directory = rig.endpoint.directory_mut();
        directory
            .locations
            .insert(DISCOVERY_UUID.to_string(), "http://wrong/".to_string());
        directory
            .zone_names
            .insert(DISCOVERY_UUID.to_string(), "Wrong".to_string());
        directory
            .zone_names
            .insert("den".to_string(), "Peer".to_string());
        let sent = rig.endpoint.publish(rig.now, &rig.session);
        let event = sent
            .iter()
            .find(|n| n.service == ZGT)
            .expect("changed topology event");
        let event_topology = text_of(&event.body, "ZoneGroupState").unwrap();
        let topology = read_topology(&mut rig);
        assert_eq!(event_topology, topology);
        assert!(topology.contains(&format!(
            "UUID=\"{DISCOVERY_UUID}\" Location=\"{}\" ZoneName=\"New &amp; Room\"",
            second.location()
        )));
        assert!(topology.contains("ZoneName=\"Peer\""));
        assert!(!topology.contains("http://wrong/"));
        let response = rig.bare("GET", ssdp::DESCRIPTION_PATH).response;
        assert_eq!(response.body, second.description_xml());
        assert_eq!(
            response.headers[1],
            ("CONTENT-LOCATION".to_string(), second.location())
        );
        assert_eq!(
            response.headers[2],
            (
                "CACHE-CONTROL".to_string(),
                format!("max-age={}", second.max_age())
            )
        );
        rig.endpoint.configure_discovery(second.clone()).unwrap();
        assert_eq!(
            rig.bare("GET", ssdp::DESCRIPTION_PATH).response.body,
            second.description_xml()
        );
        let changed_age = ssdp::Device::new(
            DISCOVERY_UUID,
            [127, 0, 0, 1],
            1500,
            "New & Room",
            ssdp::MIN_MAX_AGE + 1,
        )
        .unwrap();
        assert_eq!(changed_age.description_xml(), second.description_xml());
        rig.endpoint
            .configure_discovery(changed_age.clone())
            .unwrap();
        let response = rig.bare("GET", ssdp::DESCRIPTION_PATH).response;
        assert_eq!(response.body, second.description_xml());
        assert_eq!(response.headers[1].1, second.location());
        assert_eq!(
            response.headers[2].1,
            format!("max-age={}", changed_age.max_age())
        );
        assert_ne!(changed_age.max_age(), second.max_age());
    }

    // ---- topology events: the live session and the directory, through the endpoint -------------
    //
    // Until here the topology event was only shown inside the subscription table, against a document written by
    // hand. These go through the endpoint from a real session: the owner changes it and tells the endpoint, and a
    // controller subscribed to the topology hears the document a read would give at that moment. As before, each
    // check is a plain function over a rig, so it can be shown to pass the real endpoint and to fail one with a
    // planted defect, and a failure begins with a tag that says why.

    /// One member of the rig's group as the wire shows it after the owner renamed the kitchen: the document's
    /// attribute is escaped (`&amp; &lt;Den&gt;`) and the whole document is then escaped again as the text of the
    /// `ZoneGroupState` property, so the `&` of the first layer is `&amp;amp;` here. Written by hand; a Python check
    /// recomputes it with an escaper of its own.
    const RENAMED_MEMBER_ON_THE_WIRE: &str = "&lt;ZoneGroupMember UUID=\"kitchen\" Location=\"http://192.0.2.10:1400/xml/device_description.xml\" ZoneName=\"Patio &amp;amp; &amp;lt;Den&amp;gt;\" Invisible=\"0\" SWGen=\"1\"/&gt;";

    /// The decoded text of every element of a body, by name, using the bounded reader (a SOAP response or an
    /// event). The property wrappers carry no text of their own.
    fn texts(body: &str) -> Vec<(String, String)> {
        let mut reader = XmlReader::new(
            body.as_bytes(),
            XmlLimits {
                max_bytes: 32 * 1024,
                max_value_len: 16 * 1024,
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

    fn text_of(body: &str, name: &str) -> Option<String> {
        texts(body)
            .into_iter()
            .find(|(element, _)| element == name)
            .map(|(_, text)| text)
    }

    /// The document a read gives now.
    fn read_topology(rig: &mut Rig) -> String {
        let h = rig.legacy(ZGT, "GetZoneGroupState", &[]);
        text_of(&h.response.body, "ZoneGroupState").expect("the read carries the document")
    }

    /// Subscribe to the four evented services on the local link, in the order RC, GRC, AVT, ZGT, and return
    /// their ids.
    fn subscribe_all(rig: &mut Rig) -> [String; 4] {
        [RC, GRC, AVT, ZGT].map(|service| {
            rig.event("SUBSCRIBE", service, &SUB).response.headers[0]
                .1
                .clone()
        })
    }

    fn fixture_board() -> franken_board_profile::BoardProfile {
        franken_board_profile::synthetic_test_fixture_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .expect("fixture model")
    }

    /// The owner admits `member` to the group (the session only; the endpoint is not told).
    fn admit(rig: &mut Rig, member: &str, command_seq: u64) {
        rig.session
            .apply_command(FencedControlCommand {
                epoch: EPOCH,
                command_seq,
                payload: GroupCommandPayload::AdmitMember {
                    member_id: member.to_string(),
                    board: fixture_board(),
                    role: ChannelRole::Stereo,
                },
            })
            .expect("the member is admitted");
    }

    fn remove(rig: &mut Rig, member: &str, command_seq: u64) {
        rig.session
            .apply_command(FencedControlCommand {
                epoch: EPOCH,
                command_seq,
                payload: GroupCommandPayload::RemoveMember {
                    member_id: member.to_string(),
                },
            })
            .expect("the member is removed");
    }

    /// What the owner records for a member in the directory (two maps it fills): where its description is and what its room
    /// is called. The endpoint is not told; the owner calls `publish` afterwards, as the loopback shim's owner does.
    fn record_in_directory(rig: &mut Rig, member: &str, address: &str, room: &str) {
        let directory = rig.endpoint.directory_mut();
        let location = format!("http://{address}:1400/xml/device_description.xml");
        directory.locations.insert(member.to_string(), location);
        directory
            .zone_names
            .insert(member.to_string(), room.to_string());
    }

    /// The owner admits a member and tells the endpoint. The topology subscriber is told, and the document it is
    /// given is the one a read gives now. Returns the events, so a test can also say who else was and was not
    /// told. Failures begin `TOPOLOGY-NOT-ANNOUNCED` (the subscriber was not told) or `TOPOLOGY-STALE` (the
    /// event's document is not the read's).
    fn judge_membership_change_is_announced(rig: &mut Rig) -> Result<Vec<Notification>, String> {
        let sids = subscribe_all(rig);
        admit(rig, "porch", 5);
        let events = rig.endpoint.publish(rig.now, &rig.session);
        let Some(told) = events.iter().find(|n| n.sid == sids[3]) else {
            return Err("TOPOLOGY-NOT-ANNOUNCED: the topology subscriber was not told".to_string());
        };
        let announced = text_of(&told.body, "ZoneGroupState");
        let read = read_topology(rig);
        if announced.as_deref() != Some(read.as_str()) {
            return Err(
                "TOPOLOGY-STALE: the event's document is not the one a read gives now".to_string(),
            );
        }
        Ok(events)
    }

    /// The owner renames the kitchen in the endpoint's directory and publishes. One event is sent, to the topology subscriber. Returns
    /// the events. Failures begin `TOPOLOGY-NOT-ANNOUNCED`.
    fn judge_rename_is_announced_through_the_endpoint(
        rig: &mut Rig,
    ) -> Result<Vec<Notification>, String> {
        let sids = subscribe_all(rig);
        record_in_directory(rig, "kitchen", "192.0.2.10", "Patio & <Den>");
        let events = rig.endpoint.publish(rig.now, &rig.session);
        if events.len() != 1 || events[0].sid != sids[3] {
            return Err(format!(
                "TOPOLOGY-NOT-ANNOUNCED: {} events for a rename",
                events.len()
            ));
        }
        Ok(events)
    }

    #[test]
    fn a_membership_change_is_announced_to_the_topology_subscriber_with_the_document_a_read_gives_and_to_no_one_else()
     {
        let mut rig = Rig::new();
        let events = judge_membership_change_is_announced(&mut rig).unwrap();
        assert_eq!(events.len(), 1, "no other service had anything to say");
        assert_eq!(events[0].seq, 1);
        let doc = text_of(&events[0].body, "ZoneGroupState").unwrap();
        for member in ["kitchen", "den", "porch"] {
            assert!(doc.contains(&format!("UUID=\"{member}\"")), "{member}");
        }
        assert_eq!(
            text_of(&events[0].body, "FrankenStateRevision"),
            Some(rig.session.state_revision.to_string())
        );
        assert_eq!(
            text_of(&events[0].body, "FrankenEpoch"),
            Some(EPOCH.to_string())
        );
        // Nothing has changed since: a second publish says nothing to anyone.
        assert!(rig.endpoint.publish(rig.now, &rig.session).is_empty());
    }

    #[test]
    fn a_member_leaving_is_announced_and_an_endpoint_that_left_is_told_nothing_false() {
        let mut rig = Rig::new();
        let sids = subscribe_all(&mut rig);
        remove(&mut rig, "den", 5);
        let events = rig.endpoint.publish(rig.now, &rig.session);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sid, sids[3]);
        let doc = text_of(&events[0].body, "ZoneGroupState").unwrap();
        assert!(doc.contains("UUID=\"kitchen\"") && !doc.contains("UUID=\"den\""));
        // The endpoint's own member leaves too: the topology says so, and RenderingControl has no volume to
        // report, so its subscriber is told nothing rather than something false.
        remove(&mut rig, "kitchen", 6);
        let events = rig.endpoint.publish(rig.now, &rig.session);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sid, sids[3]);
        assert!(
            !text_of(&events[0].body, "ZoneGroupState")
                .unwrap()
                .contains("kitchen")
        );
        let read = rig.legacy(RC, "GetVolume", &MASTER);
        assert_eq!(fault_code(&read).as_deref(), Some("501"));
    }

    #[test]
    fn a_group_that_moves_to_a_new_epoch_is_announced_as_a_new_group_and_wakes_no_one_else() {
        let mut rig = Rig::new();
        let sids = subscribe_all(&mut rig);
        rig.session
            .apply_command(FencedControlCommand {
                epoch: 11,
                command_seq: 3,
                payload: GroupCommandPayload::MarkMemberClockLocked {
                    member_id: "kitchen".to_string(),
                },
            })
            .expect("a newer epoch is adopted");
        let events = rig.endpoint.publish(rig.now, &rig.session);
        assert_eq!(events.len(), 1, "the epoch rides along; it wakes nobody");
        assert_eq!(events[0].sid, sids[3]);
        let doc = text_of(&events[0].body, "ZoneGroupState").unwrap();
        assert!(doc.contains("ID=\"grp:11\"") && !doc.contains("grp:10"));
        assert_eq!(
            text_of(&events[0].body, "FrankenEpoch"),
            Some("11".to_string())
        );
    }

    #[test]
    fn a_late_subscriber_is_told_the_new_document_at_once_and_neither_is_told_it_twice() {
        let mut rig = Rig::new();
        let early = rig.event("SUBSCRIBE", ZGT, &SUB);
        let early_sid = early.response.headers[0].1.clone();
        assert_eq!(early.notifications[0].seq, 0);
        admit(&mut rig, "porch", 5);
        let events = rig.endpoint.publish(rig.now, &rig.session);
        assert_eq!(events.len(), 1);
        assert_eq!(
            (events[0].sid.as_str(), events[0].seq),
            (early_sid.as_str(), 1)
        );
        let late = rig.event("SUBSCRIBE", ZGT, &SUB);
        assert_eq!(late.notifications.len(), 1);
        assert_eq!(late.notifications[0].seq, 0);
        let doc = text_of(&late.notifications[0].body, "ZoneGroupState").unwrap();
        assert!(doc.contains("UUID=\"porch\""), "told everything at once");
        assert!(rig.endpoint.publish(rig.now, &rig.session).is_empty());
    }

    #[test]
    fn a_room_renamed_through_the_endpoint_is_announced_with_the_name_escaped_twice_and_no_one_else_hears()
     {
        let mut rig = Rig::new();
        let events = judge_rename_is_announced_through_the_endpoint(&mut rig).unwrap();
        assert_eq!(events[0].seq, 1);
        let wire = &events[0].body;
        assert!(wire.contains(RENAMED_MEMBER_ON_THE_WIRE), "{wire}");
        // Decoded once the controller reads the document, and decoded again the name; markup in the name never
        // becomes markup.
        let doc = text_of(wire, "ZoneGroupState").unwrap();
        assert!(
            doc.contains("ZoneName=\"Patio &amp; &lt;Den&gt;\""),
            "{doc}"
        );
        assert!(!doc.contains("<Den>"));
        assert_eq!(doc, read_topology(&mut rig));
    }

    #[test]
    fn a_directory_change_made_without_publishing_is_carried_by_the_next_publish_and_not_lost() {
        let mut rig = Rig::new();
        let sids = subscribe_all(&mut rig);
        record_in_directory(&mut rig, "kitchen", "192.0.2.10", "Patio");
        // The owner did not call `publish`, so nobody has been told. The next command's publish brings each
        // subscriber up to date, each with what changed for it.
        let h = rig.legacy(RC, "SetVolume", &set_volume("30"));
        assert_eq!(h.notifications.len(), 2);
        let told = |sid: &str| h.notifications.iter().find(|n| n.sid == sid);
        assert!(told(&sids[0]).is_some_and(|n| n.body.contains("val=\"30\"")));
        let doc = text_of(&told(&sids[3]).unwrap().body, "ZoneGroupState").unwrap();
        assert!(doc.contains("ZoneName=\"Patio\""));
        assert!(told(&sids[1]).is_none() && told(&sids[2]).is_none());
    }

    #[test]
    fn the_planted_endpoint_that_never_announces_topology_fails_the_membership_judge() {
        let mut broken = Rig::new();
        broken.endpoint.plant(Defect::TopologyNeverEvented);
        let verdict = judge_membership_change_is_announced(&mut broken);
        assert!(
            verdict
                .as_ref()
                .is_err_and(|e| e.starts_with("TOPOLOGY-NOT-ANNOUNCED")),
            "the planted defect was not caught for the right reason: {verdict:?}"
        );
        // A rename is announced by the same publish, so the rename judge sees it too.
        let mut other = Rig::new();
        other.endpoint.plant(Defect::TopologyNeverEvented);
        let verdict = judge_rename_is_announced_through_the_endpoint(&mut other);
        assert!(
            verdict
                .as_ref()
                .is_err_and(|e| e.starts_with("TOPOLOGY-NOT-ANNOUNCED")),
            "{verdict:?}"
        );
        // Remove-the-plant control.
        assert!(judge_membership_change_is_announced(&mut Rig::new()).is_ok());
    }

    #[test]
    fn the_planted_endpoint_that_announces_another_document_than_a_read_gives_fails_the_membership_judge()
     {
        let mut broken = Rig::new();
        broken.endpoint.plant(Defect::TopologyDocDiffersFromRead);
        let verdict = judge_membership_change_is_announced(&mut broken);
        assert!(
            verdict
                .as_ref()
                .is_err_and(|e| e.starts_with("TOPOLOGY-STALE")),
            "the planted defect was not caught for the right reason: {verdict:?}"
        );
        // It still announces, so the rename judge, which asks only whether the subscriber was told, passes.
        let mut other = Rig::new();
        other.endpoint.plant(Defect::TopologyDocDiffersFromRead);
        assert!(judge_rename_is_announced_through_the_endpoint(&mut other).is_ok());
        assert!(judge_membership_change_is_announced(&mut Rig::new()).is_ok());
    }

    // ---- GENA through the endpoint -----------------------------------------------------------

    const SUB: [(&str, &str); 3] = [
        ("CALLBACK", "<http://192.0.2.10:3400/notify>"),
        ("NT", "upnp:event"),
        ("TIMEOUT", "Second-300"),
    ];

    #[test]
    fn the_endpoint_takes_a_wide_boot_incarnation_and_its_nonce_constructor_keeps_the_old_ids() {
        let bridge = || LegacyBridge::new(PeerId::parse(BRIDGE).unwrap(), test_key(BRIDGE));
        let config = || EndpointConfig::provisional("kitchen");
        let first_id = |rig: &mut Rig| {
            rig.event("SUBSCRIBE", RC, &SUB).response.headers[0]
                .1
                .clone()
        };
        let mut rig = Rig::new();

        // The 32-bit constructor: exactly the id it always gave.
        rig.endpoint = Endpoint::new(config(), bridge(), 0x0a0b_0c0d, 1).unwrap();
        assert_eq!(
            first_id(&mut rig),
            "uuid:0a0b0c0d-0000-4000-8000-000000000001"
        );
        // The wide constructor given that nonce's own mapping: the same id.
        let legacy = legacy_incarnation(0x0a0b_0c0d);
        rig.endpoint = Endpoint::with_incarnation(config(), bridge(), legacy, 1).unwrap();
        assert_eq!(
            first_id(&mut rig),
            "uuid:0a0b0c0d-0000-4000-8000-000000000001"
        );
        // A wide incarnation reaches the id, with the version and variant digits the shape's own.
        let wide = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22];
        rig.endpoint = Endpoint::with_incarnation(config(), bridge(), wide, 1).unwrap();
        assert_eq!(
            first_id(&mut rig),
            "uuid:12345678-9abc-4ef0-9122-000000000001"
        );
        // Two boots with different incarnations do not share their first id.
        rig.endpoint =
            Endpoint::with_incarnation(config(), bridge(), [9; INCARNATION_BYTES], 1).unwrap();
        assert_ne!(
            first_id(&mut rig),
            "uuid:12345678-9abc-4ef0-9122-000000000001"
        );

        // What the constructor always refused, the wide one refuses too.
        assert_eq!(
            Endpoint::with_incarnation(config(), bridge(), wide, 0).err(),
            Some(EndpointError::Zero("first_legacy_seq"))
        );
        assert_eq!(
            Endpoint::with_incarnation(EndpointConfig::provisional("Kitchen"), bridge(), wide, 1)
                .err(),
            Some(EndpointError::MemberId)
        );
    }

    #[test]
    fn a_local_subscribe_answers_with_sid_and_timeout_and_the_full_initial_state() {
        let mut rig = Rig::new();
        let h = rig.event("SUBSCRIBE", RC, &SUB);
        assert_eq!(h.response.status, 200);
        assert_eq!(h.response.headers[0].0, "SID");
        assert!(h.response.headers[0].1.starts_with("uuid:0a0b0c0d-"));
        assert_eq!(
            h.response.headers[1],
            ("TIMEOUT".to_string(), "Second-300".to_string())
        );
        assert_eq!(h.notifications.len(), 1);
        assert_eq!(h.notifications[0].seq, 0);
        assert!(h.notifications[0].body.contains("FrankenStateRevision"));
    }

    #[test]
    fn a_command_publishes_a_delta_with_the_new_revision_to_each_affected_subscriber() {
        let mut rig = Rig::new();
        let rcs = rig.event("SUBSCRIBE", RC, &SUB).response.headers[0]
            .1
            .clone();
        rig.event("SUBSCRIBE", GRC, &SUB);
        let h = rig.legacy(RC, "SetVolume", &set_volume("30"));
        assert_eq!(h.notifications.len(), 1, "only RenderingControl changed");
        assert_eq!(
            (h.notifications[0].sid.as_str(), h.notifications[0].seq),
            (rcs.as_str(), 1)
        );
        assert!(
            h.notifications[0]
                .body
                .contains("<FrankenStateRevision>3</FrankenStateRevision>")
        );
        assert!(h.notifications[0].body.contains("val=\"30\""));
        // The group volume moved with it? No: a member change leaves the master alone.
        let h = rig.legacy(RC, "SetVolume", &set_volume("30"));
        assert!(
            h.notifications.is_empty(),
            "an unchanged state sends nothing"
        );
    }

    #[test]
    fn renew_and_unsubscribe_follow_the_rules() {
        let mut rig = Rig::new();
        let sid = rig.event("SUBSCRIBE", RC, &SUB).response.headers[0]
            .1
            .clone();
        let renew = rig.event(
            "SUBSCRIBE",
            RC,
            &[("SID", sid.as_str()), ("TIMEOUT", "Second-600")],
        );
        assert_eq!(renew.response.status, 200);
        assert_eq!(renew.response.headers[1].1, "Second-600");
        assert!(renew.notifications.is_empty(), "a renewal sends no event");
        let with_callback = rig.event("SUBSCRIBE", RC, &[("SID", sid.as_str()), SUB[0]]);
        assert_eq!(with_callback.response.status, 400);
        let other_service = rig.event("SUBSCRIBE", AVT, &[("SID", sid.as_str())]);
        assert_eq!(other_service.response.status, 412);
        assert_eq!(
            rig.event("UNSUBSCRIBE", RC, &[("SID", sid.as_str())])
                .response
                .status,
            200
        );
        assert_eq!(
            rig.event("UNSUBSCRIBE", RC, &[("SID", sid.as_str())])
                .response
                .status,
            412
        );
        assert_eq!(rig.event("UNSUBSCRIBE", RC, &[]).response.status, 412);
        assert_eq!(
            rig.event("UNSUBSCRIBE", RC, &[("SID", "x"), SUB[1]])
                .response
                .status,
            400
        );
    }

    #[test]
    fn subscription_expiry_is_driven_by_the_clock_the_owner_passes() {
        let mut rig = Rig::new();
        let sid = rig.event("SUBSCRIBE", RC, &SUB).response.headers[0]
            .1
            .clone();
        rig.now = 299 * 1_000_000_000;
        assert_eq!(
            rig.event("SUBSCRIBE", RC, &[("SID", sid.as_str())])
                .response
                .status,
            200
        );
        rig.now = (299 + 300) * 1_000_000_000;
        assert_eq!(
            rig.event("SUBSCRIBE", RC, &[("SID", sid.as_str())])
                .response
                .status,
            412
        );
        assert!(rig.endpoint.subscriptions().is_empty());
    }

    #[test]
    fn a_controller_that_subscribes_with_second_infinite_gets_a_finite_grant_and_hears_the_next_change()
     {
        let mut rig = Rig::new();
        let sub = [SUB[0], SUB[1], ("TIMEOUT", "Second-infinite")];
        let h = rig.event("SUBSCRIBE", RC, &sub);
        assert_eq!(h.response.status, 200);
        assert_eq!(
            h.response.headers[1],
            ("TIMEOUT".to_string(), "Second-300".to_string()),
            "never forever"
        );
        assert_eq!(h.notifications.len(), 1);
        assert_eq!(h.notifications[0].seq, 0);
        let sid = h.response.headers[0].1.clone();
        // The ordinary path works for this subscriber: a volume change reaches it as the next event.
        let changed = rig.legacy(RC, "SetVolume", &set_volume("30"));
        assert_eq!(changed.response.status, 200);
        assert_eq!(changed.notifications.len(), 1);
        assert_eq!(
            (
                changed.notifications[0].sid.as_str(),
                changed.notifications[0].seq
            ),
            (sid.as_str(), 1)
        );
        assert!(changed.notifications[0].body.contains("val=\"30\""));
        // A renewal that asks the same way keeps the id and is granted the same finite time.
        let renewed = rig.event(
            "SUBSCRIBE",
            RC,
            &[("SID", sid.as_str()), ("TIMEOUT", "Second-infinite")],
        );
        assert_eq!(renewed.response.status, 200);
        assert_eq!(renewed.response.headers[0].1, sid);
        assert_eq!(renewed.response.headers[1].1, "Second-300");
        assert!(renewed.notifications.is_empty(), "a renewal sends no event");
        // The renewed subscriber is still live: the next change reaches it under the same id, SEQ counting on.
        let after = rig.legacy(RC, "SetVolume", &set_volume("31"));
        assert_eq!(after.response.status, 200);
        assert_eq!(after.notifications.len(), 1);
        assert_eq!(
            (
                after.notifications[0].sid.as_str(),
                after.notifications[0].seq
            ),
            (sid.as_str(), 2)
        );
        assert!(after.notifications[0].body.contains("val=\"31\""));
    }

    #[test]
    fn a_near_miss_of_second_infinite_is_a_400_from_the_endpoint_and_leaves_no_subscription() {
        let mut rig = Rig::new();
        for bad in [
            "Second-infinitely",
            "Second-infinite5",
            "Second-infinit",
            "Second-\u{131}nfinite",
        ] {
            let h = rig.event("SUBSCRIBE", RC, &[SUB[0], SUB[1], ("TIMEOUT", bad)]);
            assert_eq!(h.response.status, 400, "{bad}");
            assert!(h.response.body.is_empty() && h.notifications.is_empty());
        }
        assert!(rig.endpoint.subscriptions().is_empty());
        // The control: the same request with the right spelling subscribes.
        let ok = rig.event(
            "SUBSCRIBE",
            RC,
            &[SUB[0], SUB[1], ("TIMEOUT", "Second-infinite")],
        );
        assert_eq!(ok.response.status, 200);
        assert_eq!(rig.endpoint.subscriptions().len(), 1);
    }

    #[test]
    fn a_lapsed_second_infinite_grant_is_a_412_on_renewal_and_a_fresh_subscribe_gets_a_new_id() {
        let mut rig = Rig::new();
        let sub = [SUB[0], SUB[1], ("TIMEOUT", "Second-infinite")];
        let first = rig.event("SUBSCRIBE", RC, &sub);
        let sid = first.response.headers[0].1.clone();
        rig.now = 301 * 1_000_000_000;
        let late = rig.event(
            "SUBSCRIBE",
            RC,
            &[("SID", sid.as_str()), ("TIMEOUT", "Second-infinite")],
        );
        assert_eq!(late.response.status, 412, "the 300 s grant lapsed");
        let again = rig.event("SUBSCRIBE", RC, &sub);
        assert_eq!(again.response.status, 200);
        assert_ne!(again.response.headers[0].1, sid);
        assert_eq!(again.notifications[0].seq, 0);
    }

    #[test]
    fn a_renewal_with_a_refused_timeout_is_a_400_and_the_subscription_stands_as_it_was() {
        let sec = 1_000_000_000u64;
        let mut rig = Rig::new();
        let sid = rig.event("SUBSCRIBE", RC, &SUB).response.headers[0]
            .1
            .clone();
        // The permitted positive: a renewal at 10 s runs 300 s from there.
        rig.now = 10 * sec;
        let ok = rig.event(
            "SUBSCRIBE",
            RC,
            &[("SID", sid.as_str()), ("TIMEOUT", "Second-300")],
        );
        assert_eq!(ok.response.status, 200);
        // A renewal whose TIMEOUT is refused is a 400 with nothing in it, and it neither extends the
        // subscription nor drops it.
        rig.now = 20 * sec;
        for bad in ["Second-infinitely", "Seconds-infinite", "Second-infinite5"] {
            let h = rig.event("SUBSCRIBE", RC, &[("SID", sid.as_str()), ("TIMEOUT", bad)]);
            assert_eq!(h.response.status, 400, "{bad}");
            assert!(
                h.response.body.is_empty() && h.notifications.is_empty(),
                "{bad}"
            );
        }
        assert_eq!(rig.endpoint.expire_subscriptions(310 * sec - 1), 0);
        assert_eq!(rig.endpoint.subscriptions().len(), 1);
        assert_eq!(rig.endpoint.expire_subscriptions(310 * sec), 1);
        assert!(rig.endpoint.subscriptions().is_empty());
    }

    #[test]
    fn duplicate_event_headers_and_the_retired_catalog_are_refused() {
        let mut rig = Rig::new();
        let twice = [
            SUB[0],
            SUB[1],
            ("callback", "<http://192.0.2.10:3400/other>"),
        ];
        assert_eq!(rig.event("SUBSCRIBE", RC, &twice).response.status, 400);
        assert_eq!(
            rig.event("SUBSCRIBE", Service::ContentDirectory, &SUB)
                .response
                .status,
            501
        );
        assert!(rig.endpoint.subscriptions().is_empty());
    }

    #[test]
    fn a_callback_for_someone_else_is_a_412_so_the_endpoint_is_no_relay() {
        let mut rig = Rig::new();
        let h = rig.event(
            "SUBSCRIBE",
            RC,
            &[("CALLBACK", "<http://192.0.2.99:3400/notify>"), SUB[1]],
        );
        assert_eq!(h.response.status, 412);
        assert!(rig.endpoint.subscriptions().is_empty());
    }

    #[test]
    fn the_owner_can_publish_after_its_own_change_to_the_session() {
        let mut rig = Rig::new();
        rig.event("SUBSCRIBE", RC, &SUB);
        rig.session
            .apply_command(FencedControlCommand {
                epoch: EPOCH,
                command_seq: 5,
                payload: GroupCommandPayload::SetMemberVolume {
                    member_id: "kitchen".to_string(),
                    volume_0_to_100: 12,
                },
            })
            .unwrap();
        let events = rig.endpoint.publish(rig.now, &rig.session);
        assert_eq!(events.len(), 1);
        assert!(events[0].body.contains("val=\"12\""));
    }

    #[test]
    fn the_transport_state_is_the_owners_to_set_and_is_evented() {
        let mut rig = Rig::new();
        rig.event("SUBSCRIBE", AVT, &SUB);
        rig.endpoint.set_transport(TransportState::Playing);
        let events = rig.endpoint.publish(rig.now, &rig.session);
        assert_eq!(events.len(), 1);
        assert!(events[0].body.contains("PLAYING"));
        let h = rig.legacy(AVT, "GetTransportInfo", &[("InstanceID", "0")]);
        assert!(
            h.response
                .body
                .contains("<CurrentTransportState>PLAYING</CurrentTransportState>")
        );
    }

    // ---- the durable step: what a request can and cannot get from a journal that fails -------------

    const REL5: [(&str, &str); 3] = [MASTER[0], MASTER[1], ("Adjustment", "5")];

    fn relative_command(delta: i8) -> ControlCommand {
        ControlCommand::AdjustMemberVolume {
            member_id: "kitchen".to_string(),
            delta,
        }
    }

    fn signed_request(
        peer: &str,
        seq: u64,
        revision: Option<u64>,
        command: ControlCommand,
    ) -> ControlRequest {
        let body =
            RequestBody::new(PeerId::parse(peer).unwrap(), seq, EPOCH, revision, command).unwrap();
        let proof = compute_proof(&test_key(peer), &body.signing_bytes());
        ControlRequest::new(body, proof)
    }

    fn tailnet_absolute_once(rig: &mut Rig) -> Handled {
        let headers = tailnet_headers(CTL, CTL, 1, EPOCH, Some(2), set_volume_command(35));
        tail(rig, "SetVolume", &set_volume("35"), &headers)
    }

    fn tailnet_relative_once(rig: &mut Rig) -> Handled {
        let headers = tailnet_headers(CTL, CTL, 1, EPOCH, Some(2), relative_command(5));
        tail(rig, "SetRelativeVolume", &REL5, &headers)
    }

    /// Another controller's command is already waiting when the bridge's request drives the step.
    fn two_peers_once(rig: &mut Rig) -> Handled {
        let waiting = signed_request(CTL, 1, Some(2), set_volume_command(35));
        assert!(matches!(
            rig.channel.submit(rig.now, waiting),
            SubmitResult::Queued { .. }
        ));
        rig.legacy(RC, "SetVolume", &set_volume("30"))
    }

    /// Run `call` once, uncut, on an identical durable rig to learn where its last storage operation falls. The same
    /// call on a fresh rig numbers its operations the same way.
    fn last_operation_of(call: fn(&mut Rig) -> Handled) -> usize {
        let mut twin = Rig::durable();
        call(&mut twin);
        twin.ops_done() - 1
    }

    #[test]
    fn a_tailnet_set_that_cannot_be_stored_is_not_applied_publishes_nothing_and_reports_no_ones_outcome()
     {
        let last = last_operation_of(tailnet_absolute_once);
        let mut rig = Rig::durable();
        let initial = rig.event("SUBSCRIBE", RC, &SUB);
        assert_eq!(initial.notifications.len(), 1);
        let revision = rig.session.state_revision;
        rig.arm_cut(last, 0);
        let h = tailnet_absolute_once(&mut rig);
        assert_eq!(
            (h.response.status, fault_code(&h).as_deref()),
            (500, Some("501"))
        );
        assert!(
            h.response.body.contains("could not be stored"),
            "{}",
            h.response.body
        );
        assert!(h.notifications.is_empty() && h.settled_others.is_empty());
        assert_eq!(
            (rig.session.state_revision, rig.member("kitchen").0),
            (revision, 50)
        );
        // The subscriber is up to date with the session as it stands: there is nothing left to tell it.
        assert!(rig.endpoint.publish(rig.now, &rig.session).is_empty());
        assert_eq!(rig.channel.stats().committed, 0);
        assert!(matches!(
            rig.channel.durability(),
            Durability::Failed { .. }
        ));
    }

    #[test]
    fn a_tailnet_relative_step_that_cannot_be_stored_is_not_applied_and_its_retry_is_unknown_never_ok()
     {
        let last = last_operation_of(tailnet_relative_once);
        let mut rig = Rig::durable();
        rig.arm_cut(last, 0);
        let h = tailnet_relative_once(&mut rig);
        assert_eq!(
            (h.response.status, fault_code(&h).as_deref()),
            (500, Some("501"))
        );
        assert!(h.response.body.contains("could not be stored"));
        assert_eq!(rig.member("kitchen").0, 50);
        assert_eq!(rig.channel.stats().committed, 0);
        // Its floor was made durable before the step, so the retry is unknown: never applied, never reported done.
        let retry = tailnet_relative_once(&mut rig);
        assert_eq!(fault_code(&retry).as_deref(), Some("801"));
        assert_eq!(rig.member("kitchen").0, 50);
    }

    #[test]
    fn when_a_round_with_two_peers_commands_cannot_be_stored_neither_peers_retry_is_answered_from_the_ledger()
     {
        let last = last_operation_of(two_peers_once);
        let mut rig = Rig::durable();
        rig.arm_cut(last, 0);
        let h = two_peers_once(&mut rig);
        assert_eq!(
            (h.response.status, fault_code(&h).as_deref()),
            (500, Some("501"))
        );
        assert!(h.response.body.contains("could not be stored"));
        // The other peer's outcome from the failed round is not reported to this request's caller...
        assert!(h.settled_others.is_empty());
        assert_eq!(rig.member("kitchen").0, 50);
        // ...and is not in the ledger, so the other peer's retry is not answered with a result it never got.
        let retry = signed_request(CTL, 1, Some(2), set_volume_command(35));
        assert!(
            !matches!(rig.channel.submit(rig.now, retry), SubmitResult::Settled(_)),
            "a withheld outcome was answered to a retry"
        );
    }

    /// A local-user-role peer reaches the tailnet route with a mute-on.
    fn local_mute_once(rig: &mut Rig) -> Handled {
        let panel = PeerId::parse("panel").unwrap();
        rig.channel
            .authority_mut()
            .admit(&panel, PeerRole::LocalUser, &test_key("panel"), None, 1)
            .unwrap();
        let command = ControlCommand::SetMemberMute {
            member_id: "kitchen".to_string(),
            muted: true,
        };
        let headers = tailnet_headers("panel", "panel", 1, EPOCH, None, command);
        tail(
            rig,
            "SetMute",
            &[MASTER[0], MASTER[1], ("DesiredMute", "1")],
            &headers,
        )
    }

    #[test]
    fn a_request_whose_own_local_mute_on_took_effect_despite_the_failed_store_is_answered_ok() {
        let last = last_operation_of(local_mute_once);
        let mut rig = Rig::durable();
        rig.arm_cut(last, 0);
        let h = local_mute_once(&mut rig);
        // The mark could not be stored, and the mute-on was applied to the live session anyway: the requester is told so.
        assert_eq!(h.response.status, 200, "{}", h.response.body);
        assert!(rig.member("kitchen").1, "the member was not muted");
        assert!(h.settled_others.is_empty());
        assert!(matches!(
            rig.channel.durability(),
            Durability::Failed { .. }
        ));
        // The permitted contrast: a controller's volume set in the same state is refused, in fixed words.
        let refused = rig.legacy(RC, "SetVolume", &set_volume("30"));
        assert_eq!(
            (refused.response.status, fault_code(&refused).as_deref()),
            (500, Some("501"))
        );
        assert_eq!(rig.member("kitchen").0, 50);
    }

    #[test]
    fn once_the_durable_path_is_latched_commands_are_refused_in_fixed_words_and_reads_still_work() {
        let last = last_operation_of(tailnet_absolute_once);
        let mut rig = Rig::durable();
        rig.arm_cut(last, 0);
        let _ = tailnet_absolute_once(&mut rig);
        let (ops, frames) = (rig.ops_done(), rig.frames());
        // Refused, and nothing is staged or written to refuse it.
        let h = rig.legacy(RC, "SetVolume", &set_volume("30"));
        assert_eq!(
            (h.response.status, fault_code(&h).as_deref()),
            (500, Some("501"))
        );
        assert!(
            h.response.body.contains("cannot be stored right now"),
            "{}",
            h.response.body
        );
        assert_eq!((rig.ops_done(), rig.frames()), (ops, frames));
        assert_eq!(rig.member("kitchen").0, 50);
        // Reads are untouched.
        assert_eq!(rig.legacy(RC, "GetVolume", &MASTER).response.status, 200);
    }

    #[test]
    fn after_a_process_restart_a_legacy_relative_applies_once_and_a_tailnet_duplicate_is_unknown() {
        let mut rig = Rig::durable();
        assert_eq!(tailnet_relative_once(&mut rig).response.status, 200);
        assert_eq!(rig.member("kitchen").0, 55);
        assert_eq!(
            rig.legacy(RC, "SetRelativeVolume", &REL5).response.status,
            200
        );
        assert_eq!(rig.member("kitchen").0, 60);
        rig.restart_process();
        // The bridge starts again at number 1 and holds no floor: its relative change is a new command, applied once.
        let h = rig.legacy(RC, "SetRelativeVolume", &REL5);
        assert_eq!(h.response.status, 200, "{}", h.response.body);
        assert_eq!(rig.member("kitchen").0, 65);
        // The tailnet's pre-restart number is unknown. It is never applied again and never reported as done.
        let duplicate = tailnet_relative_once(&mut rig);
        assert_eq!(fault_code(&duplicate).as_deref(), Some("801"));
        assert_eq!(rig.member("kitchen").0, 65);
    }

    #[test]
    fn sixty_legacy_relative_changes_write_no_floor_and_one_tailnet_relative_change_writes_one() {
        let mut rig = Rig::durable();
        let before = rig.frames();
        for i in 0..60 {
            let delta = if i % 2 == 0 { "1" } else { "-1" };
            let args = [MASTER[0], MASTER[1], ("Adjustment", delta)];
            assert_eq!(
                rig.legacy(RC, "SetRelativeVolume", &args).response.status,
                200
            );
        }
        // One frame per step (the group's mark) and none for a floor.
        assert_eq!(rig.frames() - before, 60);
        assert_eq!(
            rig.journal
                .as_ref()
                .unwrap()
                .state()
                .records
                .get(SEQ_FLOORS_KEY),
            None
        );
        let after = rig.frames();
        let revision = rig.session.state_revision;
        let headers = tailnet_headers(CTL, CTL, 1, EPOCH, Some(revision), relative_command(5));
        assert_eq!(
            tail(&mut rig, "SetRelativeVolume", &REL5, &headers)
                .response
                .status,
            200
        );
        // The floor, then the mark.
        assert_eq!(rig.frames() - after, 2);
        assert!(
            rig.journal
                .as_ref()
                .unwrap()
                .state()
                .records
                .contains_key(SEQ_FLOORS_KEY)
        );
    }

    #[test]
    fn the_plain_soap_retry_pin_holds_with_the_journal_on() {
        let mut rig = Rig::durable();
        rig.legacy(RC, "SetRelativeVolume", &REL5);
        rig.legacy(RC, "SetRelativeVolume", &REL5);
        assert_eq!(rig.member("kitchen").0, 60, "applied twice");
        assert_eq!(rig.channel.stats().committed, 2);
    }

    #[test]
    fn a_floor_the_channel_holds_for_the_bridge_from_before_is_resumed_above_and_not_reported_unknown()
     {
        let mut rig = Rig::durable();
        let bridge = PeerId::parse(BRIDGE).unwrap();
        let table = SeqFloors::new().raised(&bridge, 7).unwrap();
        rig.journal
            .as_mut()
            .unwrap()
            .put(Namespace::Records, SEQ_FLOORS_KEY, &table.encode())
            .unwrap();
        rig.restart_process();
        assert_eq!(rig.channel.seq_floor(&bridge), Some(7));
        let h = rig.legacy(RC, "SetRelativeVolume", &REL5);
        assert_eq!(h.response.status, 200, "{}", h.response.body);
        assert_eq!(rig.member("kitchen").0, 55);
        // It used number 8, and the next is 9.
        assert_eq!(rig.endpoint.legacy_seq, 9);
    }

    #[test]
    fn a_bridge_the_channel_cannot_declare_does_not_run_rather_than_run_with_a_floor_per_request() {
        let mut rig = Rig::durable();
        for i in 0..16 {
            let other = PeerId::parse(&format!("other-{i:02}")).unwrap();
            assert!(rig.channel.declare_unstable_retry_ids(&other));
        }
        let before = rig.frames();
        let h = rig.legacy(RC, "SetRelativeVolume", &REL5);
        assert_eq!(
            (h.response.status, fault_code(&h).as_deref()),
            (500, Some("501"))
        );
        assert!(
            h.response.body.contains("unavailable"),
            "{}",
            h.response.body
        );
        assert_eq!((rig.member("kitchen").0, rig.frames()), (50, before));
        // The permitted positive: the authenticated route is not affected.
        assert_eq!(tailnet_relative_once(&mut rig).response.status, 200);
    }
}
