//! A bounded loopback HTTP transport for an ACTUAL `fsonos` client, over the real G03 endpoint (`ffw-xvv`,
//! `docs/contracts/g03.md` section 11 item 1).
//!
//! `franken-control` answers SOAP as a pure function of an [`HttpRequest`] and opens no socket, by design. The acceptance clause it
//! leaves open is a real controller talking to it, and that needs a transport. This module is that transport and nothing more:
//!
//! * **One listener, on `127.0.0.1`, on an ephemeral port.** There is no address parameter, so no other interface can be asked for,
//!   and every accepted peer is checked to be loopback again.
//! * **One request per connection**, read within fixed bounds (head bytes, header count, body bytes, one read, the whole request),
//!   handed unchanged to the REAL [`franken_control::fsonos::Endpoint`] through the speaker's real control plane (the real channel,
//!   peer directory, lease and legacy bridge), and answered with exactly what the endpoint returned, framed with `Content-Length`
//!   and `Connection: close`.
//! * **Bounded for life.** At most [`LoopbackLimits::max_connections`] connections are accepted. The worker stops by itself at
//!   [`LoopbackLimits::lifetime`] or when asked, and stopping joins it within a deadline.
//! * **It never invents an answer.** A request it cannot read it refuses itself with a bare status and no body, counts the refusal
//!   and does not call the endpoint. Nothing the peer sent is echoed or logged: the report holds counts and statuses only.
//!
//! **Discovery is opt in** ([`FsonosLoopback::start_discoverable`], and the `discovery` module): a second loopback-only UDP socket
//! answers `M-SEARCH` with the core's own answers, and the shim serves the core's device description at its path to the local link
//! only. The topology answer then carries the served member's location and room. [`FsonosLoopback::start`] opens neither, as before.
//!
//! **Eventing is opt in** ([`FsonosLoopback::start_eventing`], and the `callback` module): the `NOTIFY` messages a `Handled` asks for
//! are offered, after the answer is written, to a bounded queue and delivered by a separate thread to ONE explicitly allowed
//! loopback callback, and every one is counted. [`FsonosLoopback::start`] and [`FsonosLoopback::start_discoverable`] deliver nothing.
//!
//! What it is not: no outbound announcement of any kind, no delivery to any address but the one allowed, no TLS, no keep-alive and
//! no tailnet. It is evidence for the discovery, description, HTTP, SOAP and event path an actual client
//! takes and says nothing about a speaker, a board or the real LAN. The client side lives outside this
//! workspace (`tests/g03/fsonos-client`) because it needs the sibling `frankensonos` checkout, transferred by RCH's multi-root
//! closure.
//!
//! The control plane is built inside the worker thread and never leaves it: one of its stepper variants holds an `Rc`, so the
//! plane is not `Send`. Only the group session (for inspection) and the report are shared.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use franken_control::channel::owner::{AgreementError, FleetControlOwner};
use franken_control::channel::pipeline::Storage;
use franken_control::contracts::secret_store::SecretStore;
use franken_control::fsonos::gena::INCARNATION_BYTES;
use franken_control::fsonos::ssdp::{DESCRIPTION_CONTENT_TYPE, DESCRIPTION_PATH, Device};
use franken_control::fsonos::{Directory, Handled, HttpRequest, Ingress, Notification};
use franken_session::{
    ChannelRole, FencedControlCommand, GroupCommandPayload, UnifiedGroupSession,
};

use crate::control_adapter::ControlPlane;
use crate::settled_http::{HttpMailboxClient, HttpMailboxError};

mod callback;
mod discovery;
mod incarnation;

pub use callback::{CallbackLimits, CallbackReport, CallbackStop, CallbackTarget};
use discovery::Responder;
pub use discovery::{
    DiscoveryIdentity, DiscoveryLimits, DiscoveryReport, DiscoveryStop, FIXTURE_DEVICE_UUID,
    FIXTURE_OTHER_UUID, FIXTURE_ROOM, PLAYER_PORT,
};
pub use incarnation::{IncarnationError, host_incarnation};

/// The member the fixture session's endpoint is: what `GetVolume` and `GetMute` read and `SetVolume` and `SetMute` change.
pub const FIXTURE_MEMBER: &str = "kitchen";
/// The address a client names for the player: loopback itself. A client is routed from it to [`FsonosLoopback::addr`]; a route that
/// failed to apply would dial this address on the player port (1400), where nothing listens, instead of leaving the host.
pub const FIXTURE_PLAYER_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

const FIXTURE_EPOCH: u64 = 1;
/// The virtual clock the control plane runs on: it starts here and moves one step per request. No wall clock reaches the endpoint.
const START_NS: u64 = 1_000_000_000;
const STEP_NS: u64 = 1_000_000;
/// How long the accept loop sleeps when nobody is connecting.
const POLL: Duration = Duration::from_millis(2);
/// How long `start` waits for the worker to build the control plane.
const STARTUP: Duration = Duration::from_secs(10);
/// Extra time `stop` allows beyond one request's deadline.
const JOIN_SLACK: Duration = Duration::from_secs(1);
const JOIN_CAP: Duration = Duration::from_secs(60);
/// After answering, how long and how much the shim reads and discards before closing, so an unread request tail cannot turn the close
/// into a reset that destroys the answer.
const LINGER: Duration = Duration::from_millis(100);
const LINGER_BYTES: usize = 32 * 1024;
const READ_CHUNK: usize = 2048;
const MAX_METHOD_BYTES: usize = 16;
const MAX_TARGET_BYTES: usize = 512;
const MAX_NAME_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 1024;
const MAX_LENGTH_DIGITS: usize = 9;

/// Which ingress every connection is judged as. Both are confined to loopback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// The local link: plain UPnP, reads and legacy commands, as a LAN controller is treated.
    LocalLink,
    /// Treat each connection as tailnet ingress. Requests without command authorization are refused,
    /// including reads; signed commands are checked by the selected control plane.
    UnauthenticatedTailnet,
}

impl Policy {
    const fn ingress(self) -> Ingress {
        match self {
            Self::LocalLink => Ingress::LocalLegacy,
            Self::UnauthenticatedTailnet => Ingress::Tailnet,
        }
    }
}

/// Every bound of the shim. All of them are enforced; none is a hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopbackLimits {
    /// Connections accepted over the shim's life. After this many it stops accepting and its listener closes.
    pub max_connections: u32,
    /// Request line, headers and the blank line together.
    pub max_head_bytes: usize,
    pub max_headers: usize,
    /// Larger than the endpoint's own SOAP limit (8 KiB), so the endpoint's refusal of an oversize body is reachable.
    pub max_body_bytes: usize,
    /// One read or one write.
    pub io_timeout: Duration,
    /// Reading, handling and answering one request.
    pub request_deadline: Duration,
    /// The shim stops by itself after this long.
    pub lifetime: Duration,
}

impl LoopbackLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            max_connections: 64,
            max_head_bytes: 8 * 1024,
            max_headers: 32,
            max_body_bytes: 16 * 1024,
            io_timeout: Duration::from_secs(2),
            request_deadline: Duration::from_secs(5),
            lifetime: Duration::from_secs(60),
        }
    }

    fn usable(&self) -> bool {
        self.max_connections > 0
            && self.max_head_bytes >= 256
            && self.max_headers > 0
            && !self.io_timeout.is_zero()
            && !self.request_deadline.is_zero()
            && !self.lifetime.is_zero()
    }
}

/// Why the worker is not running.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum StopCause {
    #[default]
    Running,
    Requested,
    ConnectionCap,
    Lifetime,
    ListenerFailed,
    WorkerPanicked,
    /// The worker did not stop within the join deadline and was left to stop by itself at its lifetime.
    WorkerStuck,
}

/// What the shim did. Counts and statuses only: no byte of any request or answer is kept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoopbackReport {
    pub accepted: u32,
    /// Requests the endpoint answered and whose answer was written completely.
    pub served: u32,
    /// Requests for the device description that the shim answered itself, from the core's own document, without calling the endpoint.
    /// Always zero unless the shim was started discoverable.
    pub described: u32,
    /// Requests the shim answered itself with a bare error status, without calling the endpoint (or whose endpoint answer it
    /// refused to forward).
    pub refused: u32,
    /// Connections closed with no complete answer: the client went away or sent nothing, or the answer could not be written.
    pub dropped: u32,
    /// The status of each refusal, in order. At most one per accepted connection.
    pub refused_statuses: Vec<u16>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub stopped_by: StopCause,
}

impl LoopbackReport {
    /// Every accepted connection ended in exactly one of served, described, refused or dropped. True once the worker is idle or
    /// stopped.
    #[must_use]
    pub fn reconciled(&self) -> bool {
        self.accepted
            == self
                .served
                .saturating_add(self.described)
                .saturating_add(self.refused)
                .saturating_add(self.dropped)
    }
}

/// Two members at the default volume 50 and unmuted, in epoch 1: the session the endpoint serves.
///
/// # Errors
/// If a fixture board is missing or a member does not admit.
pub fn fixture_session() -> Result<UnifiedGroupSession, String> {
    fixture_session_for(FIXTURE_MEMBER, "den")
}

/// [`fixture_session`] with the two members' ids chosen by the caller: the first is the endpoint's member and the second its
/// neighbour. The discoverable fixture names them by device id, so the topology's `UUID` is the description's `UDN`.
///
/// # Errors
/// If a fixture board is missing or a member does not admit.
pub fn fixture_session_for(first: &str, second: &str) -> Result<UnifiedGroupSession, String> {
    let catalog = franken_board_profile::synthetic_test_fixture_catalog();
    let board = |model: &str| {
        catalog
            .iter()
            .find(|profile| profile.model_number == model)
            .cloned()
            .ok_or_else(|| format!("no fixture board {model}"))
    };
    let mut session = UnifiedGroupSession::new("grp", "coord", FIXTURE_EPOCH);
    for (seq, member, model) in [(1_u64, first, "S5"), (2, second, "S12")] {
        session
            .apply_command(FencedControlCommand {
                epoch: FIXTURE_EPOCH,
                command_seq: seq,
                payload: GroupCommandPayload::AdmitMember {
                    member_id: member.to_string(),
                    board: board(model)?,
                    role: ChannelRole::Stereo,
                },
            })
            .map_err(|error| format!("admitting {member}: {error:?}"))?;
    }
    Ok(session)
}

// ---- shared state ----------------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Shared {
    session: Arc<Mutex<UnifiedGroupSession>>,
    report: Arc<Mutex<LoopbackReport>>,
    stop: Arc<AtomicBool>,
}

impl Shared {
    fn session(&self) -> MutexGuard<'_, UnifiedGroupSession> {
        self.session.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn report(&self) -> MutexGuard<'_, LoopbackReport> {
        self.report.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn note(&self, change: impl FnOnce(&mut LoopbackReport)) {
        let mut report = self.report();
        change(&mut report);
    }
}

#[derive(Clone, Copy)]
struct Config {
    limits: LoopbackLimits,
    policy: Policy,
}

/// What a discoverable shim serves besides SOAP: the core's device, and the room name its topology entry carries.
#[derive(Clone)]
struct Described {
    device: Device,
    room: String,
}

/// What a shim does beyond SOAP, built before the worker thread starts and moved into it.
struct Extras {
    described: Option<Described>,
    outbox: Option<callback::Outbox>,
    /// This boot's incarnation, ten bytes read from the host before anything was bound.
    incarnation: [u8; INCARNATION_BYTES],
}

/// The control plane used by the bounded HTTP worker. The plane is constructed and used on
/// the worker thread; its journal and key store need not themselves be `Send`.
pub trait HttpControl {
    fn handle_request(
        &mut self,
        session: &mut UnifiedGroupSession,
        now_ns: u64,
        request: &HttpRequest<'_>,
    ) -> Handled;

    fn directory_mut(&mut self) -> &mut Directory;

    /// Whether this worker may configure discovery and event-delivery extras.
    /// A mailbox-owned endpoint must be configured at its actual owner instead.
    fn supports_extras(&self) -> bool {
        true
    }
}

impl HttpControl for ControlPlane {
    fn handle_request(
        &mut self,
        session: &mut UnifiedGroupSession,
        now_ns: u64,
        request: &HttpRequest<'_>,
    ) -> Handled {
        ControlPlane::handle_request(self, session, now_ns, request)
    }

    fn directory_mut(&mut self) -> &mut Directory {
        ControlPlane::directory_mut(self)
    }
}

/// A caller-provided durable fleet owner and its existing G03 endpoint.
/// The caller supplies credentials, storage, admission, lease, and endpoint configuration.
pub struct FleetSoapPlane<K: SecretStore, S: Storage> {
    owner: FleetControlOwner<K, S>,
    endpoint: franken_control::fsonos::Endpoint,
}

impl<K: SecretStore, S: Storage> FleetSoapPlane<K, S> {
    /// Reserve this endpoint's legacy identity before exposing it to either SOAP or raw control.
    /// Additional bridge identities are reserved by the caller on the supplied owner.
    ///
    /// # Errors
    /// Returns an error if the owner's bounded legacy identity set cannot hold this bridge.
    pub fn new(
        mut owner: FleetControlOwner<K, S>,
        endpoint: franken_control::fsonos::Endpoint,
    ) -> Result<Self, AgreementError> {
        owner.reserve_legacy_peer(endpoint.legacy_peer())?;
        Ok(Self { owner, endpoint })
    }
}

impl<K: SecretStore, S: Storage> HttpControl for FleetSoapPlane<K, S> {
    fn handle_request(
        &mut self,
        session: &mut UnifiedGroupSession,
        now_ns: u64,
        request: &HttpRequest<'_>,
    ) -> Handled {
        self.owner
            .handle_soap(&mut self.endpoint, session, now_ns, request)
    }

    fn directory_mut(&mut self) -> &mut Directory {
        self.endpoint.directory_mut()
    }
}

/// Forward this isolated HTTP worker to the actual protected-playback owner.
/// The caller explicitly services the mailbox outside its render callback.
/// No second control plane, fixture identity, or live membership is created.
/// The custom-factory SOAP path is supported; discovery/event-delivery extras
/// must be configured by an owner-aware transport and are refused by this shim.
pub fn mailbox_control(client: HttpMailboxClient) -> Box<dyn HttpControl> {
    Box::new(MailboxControl {
        client,
        directory: Directory::default(),
    })
}

struct MailboxControl {
    client: HttpMailboxClient,
    // The legacy trait exposes transport-local metadata. This adapter never
    // uses it to configure the owned endpoint, and refuses extras at startup.
    directory: Directory,
}

impl HttpControl for MailboxControl {
    fn handle_request(
        &mut self,
        session: &mut UnifiedGroupSession,
        _now_ns: u64,
        request: &HttpRequest<'_>,
    ) -> Handled {
        // This adapter has no event-delivery transport. Refuse before the
        // actual owner can create or remove subscriptions; preserve the
        // tailnet ingress's anonymous 401 policy instead of disclosing it.
        if request.method.eq_ignore_ascii_case("SUBSCRIBE")
            || request.method.eq_ignore_ascii_case("UNSUBSCRIBE")
        {
            let mut refusal = mailbox_fault(
                if request.ingress == Ingress::Tailnet {
                    401
                } else {
                    405
                },
                false,
            );
            if request.ingress == Ingress::LocalLegacy {
                refusal
                    .response
                    .headers
                    .push(("Allow".into(), "POST".into()));
            }
            return refusal;
        }
        let reply = match self
            .client
            .submit(request)
            .and_then(|pending| pending.wait())
        {
            Ok(reply) => reply,
            Err(error) => {
                let (status, unknown) = match error {
                    HttpMailboxError::TooLarge | HttpMailboxError::TooManyHeaders => (413, false),
                    HttpMailboxError::Busy => (503, false),
                    HttpMailboxError::TimeoutOutcomeUnknown => (504, true),
                    HttpMailboxError::Disconnected => (503, true),
                    HttpMailboxError::Unavailable | HttpMailboxError::InvalidLimits => (500, false),
                };
                return mailbox_fault(status, unknown);
            }
        };
        // This is a diagnostic copy from the sole owner, never authority used
        // to reconstruct it. HTTP callers cannot write the renderer's session.
        *session = reply.session;
        match reply.result {
            Ok(result) => {
                // A control may have committed even when policy application
                // failed. Preserve its real response instead of inviting a
                // relative retry by rewriting a committed result as a fault.
                let mut handled = result.control;
                handled.notifications.extend(result.notifications);
                handled
            }
            Err(_) => mailbox_fault(500, false),
        }
    }

    fn directory_mut(&mut self) -> &mut Directory {
        &mut self.directory
    }

    fn supports_extras(&self) -> bool {
        false
    }
}

fn mailbox_fault(status: u16, unknown: bool) -> Handled {
    Handled {
        response: franken_control::fsonos::HttpResponse {
            status,
            headers: if unknown {
                vec![("X-Franken-Outcome".into(), "unknown".into())]
            } else {
                Vec::new()
            },
            body: String::new(),
        },
        notifications: Vec::new(),
        settled_others: Vec::new(),
    }
}

type ControlFactory = Box<
    dyn FnOnce(
            &UnifiedGroupSession,
            &str,
            [u8; INCARNATION_BYTES],
        ) -> Result<Box<dyn HttpControl>, String>
        + Send,
>;

fn legacy_control(
    session: &UnifiedGroupSession,
    member: &str,
    incarnation: [u8; INCARNATION_BYTES],
) -> Result<Box<dyn HttpControl>, String> {
    ControlPlane::with_incarnation(session, member, START_NS, incarnation)
        .map(|plane| Box::new(plane) as Box<dyn HttpControl>)
}

// ---- the public handle -----------------------------------------------------------------------------------------------

/// A running shim. Dropping it stops and joins it.
pub struct FsonosLoopback {
    addr: SocketAddr,
    shared: Shared,
    worker: Option<JoinHandle<()>>,
    join_budget: Duration,
    responder: Option<Responder>,
    deliverer: Option<callback::Deliverer>,
}

impl FsonosLoopback {
    /// Start the bounded loopback worker with an explicitly supplied control plane. The
    /// factory runs inside the worker after host incarnation is obtained and receives the
    /// same session and member the worker serves. A factory error fails startup.
    ///
    /// # Errors
    /// Returns an error if startup or the caller's factory fails; no legacy plane is substituted.
    pub fn start_with_control<F>(
        session: UnifiedGroupSession,
        member_id: &str,
        policy: Policy,
        limits: LoopbackLimits,
        factory: F,
    ) -> Result<Self, String>
    where
        F: FnOnce(
                &UnifiedGroupSession,
                &str,
                [u8; INCARNATION_BYTES],
            ) -> Result<Box<dyn HttpControl>, String>
            + Send
            + 'static,
    {
        Self::start_inner_with(
            session,
            member_id,
            policy,
            limits,
            None,
            None,
            (host_incarnation, Box::new(factory)),
        )
    }

    /// Bind `127.0.0.1:0`, build the real control plane over `session` for `member_id` inside a worker thread, and start serving.
    ///
    /// # Errors
    /// If the limits are unusable, the host cannot give this boot an incarnation (`incarnation: <word>`, from
    /// [`IncarnationError::code`]; checked first, before anything is bound), the listener cannot be bound or is not on loopback,
    /// the worker cannot start, or the control plane cannot be built (the reason names a label or an error kind, never a request).
    ///
    /// Every boot takes ten bytes of host entropy ([`host_incarnation`]) as the first ten bytes of its event subscription ids, so
    /// an id of one boot is not the id of any subscription of another, except with probability 2^-74 (the 74 bits the UUID
    /// version and variant leave). That is a boot namespace for refusing stale ids, not authentication.
    pub fn start(
        session: UnifiedGroupSession,
        member_id: &str,
        policy: Policy,
        limits: LoopbackLimits,
    ) -> Result<Self, String> {
        Self::start_inner(
            session,
            member_id,
            policy,
            limits,
            None,
            None,
            host_incarnation,
        )
    }

    /// [`FsonosLoopback::start`] with eventing: the `NOTIFY` messages the core asks for are delivered to `target`, the one allowed
    /// loopback callback, by a separate bounded thread ([`FsonosLoopback::callback_report`] counts every one). A local-link
    /// `SUBSCRIBE` naming any other callback is answered 412 by the shim before the core is called, and counted; a notification for
    /// any other callback, which that check should keep out of the queue, is refused with no contact as well.
    ///
    /// # Errors
    /// As [`FsonosLoopback::start`], and if the callback limits are unusable or the delivery thread cannot start. Nothing is left
    /// running on an error.
    pub fn start_eventing(
        session: UnifiedGroupSession,
        member_id: &str,
        policy: Policy,
        limits: LoopbackLimits,
        target: CallbackTarget,
        callbacks: CallbackLimits,
    ) -> Result<Self, String> {
        Self::start_inner(
            session,
            member_id,
            policy,
            limits,
            None,
            Some((target, callbacks)),
            host_incarnation,
        )
    }

    /// [`FsonosLoopback::start`] for the device `identity` names, with discovery: a loopback-only UDP responder answering
    /// `M-SEARCH` for it ([`FsonosLoopback::discovery_addr`]), the core's device description served at its path to the local link,
    /// and the served member's location and room in the topology answer. The identity's id is the endpoint's member id, so `session`
    /// must hold a member of that id for the volume and mute actions to have something to read.
    ///
    /// # Errors
    /// As [`FsonosLoopback::start`], and if the discovery limits are unusable, the identity is refused by the core (a malformed id,
    /// an empty or over-long room name) or the UDP socket cannot be bound or started. Nothing is left running on an error.
    pub fn start_discoverable(
        session: UnifiedGroupSession,
        identity: &DiscoveryIdentity,
        policy: Policy,
        limits: LoopbackLimits,
        discovery: DiscoveryLimits,
    ) -> Result<Self, String> {
        let described = Self::describe(identity, discovery)?;
        Self::start_inner(
            session,
            &identity.uuid,
            policy,
            limits,
            Some((described, discovery)),
            None,
            host_incarnation,
        )
    }

    /// [`FsonosLoopback::start_discoverable`] and [`FsonosLoopback::start_eventing`] on ONE shim: the same listener, worker, control
    /// plane and session answer the search, serve the description, take a client's SOAP and `SUBSCRIBE` requests and deliver the
    /// events the core produces to `target`, the one allowed loopback callback. Nothing is duplicated: this is the constructor
    /// behind the other two with both of its options set, so the identity and limits checks, the order they run in, the loopback
    /// confinement of the responder and of the callback, and the cleanup on an error are the ones those constructors run.
    ///
    /// # Errors
    /// As both constructors: the discovery limits, then the identity, are checked first (the one check `start_discoverable` runs),
    /// then the loopback limits, the host's incarnation, the bind and the callback limits, as `start_inner` checks them for both. The
    /// first problem is the one named. Nothing is left running on an error.
    pub fn start_discoverable_eventing(
        session: UnifiedGroupSession,
        identity: &DiscoveryIdentity,
        policy: Policy,
        limits: LoopbackLimits,
        discovery: DiscoveryLimits,
        target: CallbackTarget,
        callbacks: CallbackLimits,
    ) -> Result<Self, String> {
        let described = Self::describe(identity, discovery)?;
        Self::start_inner(
            session,
            &identity.uuid,
            policy,
            limits,
            Some((described, discovery)),
            Some((target, callbacks)),
            host_incarnation,
        )
    }

    /// What a discoverable shim serves, if its limits are usable and the core accepts `identity`. `start_discoverable` and
    /// `start_discoverable_eventing` both ask it, so neither can be laxer than the other.
    fn describe(
        identity: &DiscoveryIdentity,
        discovery: DiscoveryLimits,
    ) -> Result<Described, String> {
        if !discovery.usable() {
            return Err("the discovery limits are unusable".to_string());
        }
        Ok(Described {
            device: identity.device()?,
            room: identity.room.clone(),
        })
    }

    /// `boot` is where this boot's incarnation comes from: the host (`host_incarnation`) in every public constructor. It is asked
    /// once, before anything is bound, and its failure is the startup's.
    fn start_inner(
        session: UnifiedGroupSession,
        member_id: &str,
        policy: Policy,
        limits: LoopbackLimits,
        discovery: Option<(Described, DiscoveryLimits)>,
        events: Option<(CallbackTarget, CallbackLimits)>,
        boot: impl FnOnce() -> Result<[u8; INCARNATION_BYTES], IncarnationError>,
    ) -> Result<Self, String> {
        Self::start_inner_with(
            session,
            member_id,
            policy,
            limits,
            discovery,
            events,
            (boot, Box::new(legacy_control)),
        )
    }

    fn start_inner_with(
        session: UnifiedGroupSession,
        member_id: &str,
        policy: Policy,
        limits: LoopbackLimits,
        discovery: Option<(Described, DiscoveryLimits)>,
        events: Option<(CallbackTarget, CallbackLimits)>,
        startup: (
            impl FnOnce() -> Result<[u8; INCARNATION_BYTES], IncarnationError>,
            ControlFactory,
        ),
    ) -> Result<Self, String> {
        let (boot, factory) = startup;
        if !limits.usable() {
            return Err("the loopback limits are unusable".to_string());
        }
        let incarnation = boot().map_err(|error| format!("incarnation: {}", error.code()))?;
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .map_err(|error| format!("bind: {}", error.kind()))?;
        let addr = listener
            .local_addr()
            .map_err(|error| format!("local address: {}", error.kind()))?;
        if !addr.ip().is_loopback() {
            return Err("the listener is not on loopback".to_string());
        }
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("nonblocking: {}", error.kind()))?;
        let shared = Shared {
            session: Arc::new(Mutex::new(session)),
            report: Arc::new(Mutex::new(LoopbackReport::default())),
            stop: Arc::new(AtomicBool::new(false)),
        };
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let member = member_id.to_string();
        let cfg = Config { limits, policy };
        let for_worker = shared.clone();
        let described = discovery.as_ref().map(|(described, _)| described.clone());
        // On an error below the delivery thread is dropped with this function, which stops and joins it.
        let (deliverer, outbox) = match events {
            Some((target, callbacks)) => {
                let (deliverer, outbox) = callback::Deliverer::start(target, callbacks)?;
                (Some(deliverer), Some(outbox))
            }
            None => (None, None),
        };
        let extras = Extras {
            described,
            outbox,
            incarnation,
        };
        let worker = thread::Builder::new()
            .name("g03-fsonos-loopback".to_string())
            .spawn(move || {
                worker_main(
                    &listener, for_worker, &member, cfg, extras, &ready_tx, factory,
                )
            })
            .map_err(|error| format!("spawn: {}", error.kind()))?;
        match ready_rx.recv_timeout(STARTUP) {
            Ok(Ok(())) => {
                let mut server = Self {
                    addr,
                    shared,
                    worker: Some(worker),
                    join_budget: limits
                        .request_deadline
                        .saturating_add(JOIN_SLACK)
                        .min(JOIN_CAP),
                    responder: None,
                    deliverer,
                };
                if let Some((described, discovery_limits)) = discovery {
                    // On an error `server` is dropped here, which stops and joins its worker: nothing is left running.
                    let responder = Responder::start(described.device, discovery_limits)?;
                    server.responder = Some(responder);
                }
                Ok(server)
            }
            Ok(Err(reason)) => {
                let _ = worker.join();
                Err(reason)
            }
            Err(_) => {
                // The worker is slow or gone; it will see the flag before it serves anything and leave.
                shared.stop.store(true, Ordering::SeqCst);
                Err("the loopback worker did not start".to_string())
            }
        }
    }

    /// Where the shim listens: always `127.0.0.1` and an ephemeral port.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Inspect the transport's diagnostic session. The legacy planes update it
    /// directly. With mailbox_control it is the last owner-response snapshot,
    /// and may be stale before the first response or between owner-side changes.
    /// Requests themselves always query the actual owner, not this copy.
    pub fn with_session<R>(&self, read: impl FnOnce(&UnifiedGroupSession) -> R) -> R {
        let session = self.shared.session();
        read(&session)
    }

    #[must_use]
    pub fn report(&self) -> LoopbackReport {
        self.shared.report().clone()
    }

    /// Where the SSDP responder listens: always `127.0.0.1` and an ephemeral UDP port. `None` unless the shim was started
    /// discoverable. This is the only address a client may be given as its search target.
    #[must_use]
    pub fn discovery_addr(&self) -> Option<SocketAddr> {
        self.responder.as_ref().map(Responder::addr)
    }

    /// What the SSDP responder did so far (it stays readable after the shim is stopped). `None` unless discoverable.
    #[must_use]
    pub fn discovery_report(&self) -> Option<DiscoveryReport> {
        self.responder.as_ref().map(Responder::report)
    }

    /// What the callback delivery did so far (it stays readable after the shim is shut down). `None` unless started eventing.
    #[must_use]
    pub fn callback_report(&self) -> Option<CallbackReport> {
        self.deliverer.as_ref().map(callback::Deliverer::report)
    }

    /// Stop, join within the deadline, and return the final report.
    pub fn stop(mut self) -> LoopbackReport {
        self.shutdown();
        self.report()
    }

    /// Stop everything this handle started: the HTTP worker and the responder first, then the delivery thread, so a notification
    /// the worker offered in its last request is still counted before the thread is told to stop.
    fn shutdown(&mut self) {
        self.stop_serving();
        if let Some(deliverer) = self.deliverer.as_mut() {
            deliverer.stop();
        }
    }

    fn stop_serving(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(responder) = self.responder.as_mut() {
            responder.stop(self.join_budget);
        }
        let Some(worker) = self.worker.take() else {
            return;
        };
        let give_up = Instant::now() + self.join_budget;
        while !worker.is_finished() {
            if Instant::now() >= give_up {
                // Dropping the handle detaches the thread; it stops by itself at its lifetime.
                self.shared
                    .note(|report| report.stopped_by = StopCause::WorkerStuck);
                return;
            }
            thread::sleep(POLL);
        }
        if worker.join().is_err() {
            self.shared
                .note(|report| report.stopped_by = StopCause::WorkerPanicked);
        }
    }
}

impl Drop for FsonosLoopback {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn worker_main(
    listener: &TcpListener,
    shared: Shared,
    member: &str,
    cfg: Config,
    extras: Extras,
    ready: &mpsc::Sender<Result<(), String>>,
    factory: ControlFactory,
) {
    let built = {
        let session = shared.session();
        factory(&session, member, extras.incarnation)
    };
    let mut plane = match built {
        Ok(plane) => plane,
        Err(reason) => {
            let _ = ready.send(Err(reason));
            return;
        }
    };
    if (extras.described.is_some() || extras.outbox.is_some()) && !plane.supports_extras() {
        let _ = ready.send(Err(
            "control owner does not admit transport-local extras".into()
        ));
        return;
    }
    // What the group session does not hold, the topology answer reads from the endpoint's directory: where the served member's
    // description lives, and its room. Only that member is entered; any other member is listed without a location.
    let device = extras.described.map(|described| {
        let directory = plane.directory_mut();
        directory
            .locations
            .insert(member.to_string(), described.device.location());
        directory
            .zone_names
            .insert(member.to_string(), described.room);
        described.device
    });
    let _ = ready.send(Ok(()));
    let mut worker = Worker {
        plane,
        now_ns: START_NS,
        shared,
        cfg,
        device,
        outbox: extras.outbox,
    };
    let cause = worker.run(listener);
    worker.shared.note(|report| report.stopped_by = cause);
}

// ---- the worker ------------------------------------------------------------------------------------------------------

struct Worker {
    plane: Box<dyn HttpControl>,
    now_ns: u64,
    shared: Shared,
    cfg: Config,
    /// The device whose description this worker serves; `None` unless the shim was started discoverable.
    device: Option<Device>,
    /// Where this worker offers the core's notifications; `None` unless the shim was started eventing.
    outbox: Option<callback::Outbox>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Served,
    /// The device description, answered by the shim from the core's document.
    Described,
    Refused(u16),
    Dropped,
}

impl Worker {
    fn run(&mut self, listener: &TcpListener) -> StopCause {
        let started = Instant::now();
        loop {
            if self.shared.stop.load(Ordering::SeqCst) {
                return StopCause::Requested;
            }
            if started.elapsed() >= self.cfg.limits.lifetime {
                return StopCause::Lifetime;
            }
            if self.shared.report().accepted >= self.cfg.limits.max_connections {
                return StopCause::ConnectionCap;
            }
            match listener.accept() {
                Ok((stream, peer)) => {
                    self.shared
                        .note(|report| report.accepted = report.accepted.saturating_add(1));
                    self.serve(stream, peer);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(POLL),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return StopCause::ListenerFailed,
            }
        }
    }

    fn serve(&mut self, mut stream: TcpStream, peer: SocketAddr) {
        // An accepted socket can inherit the listener's non-blocking mode: ask for blocking explicitly.
        let ready = peer.ip().is_loopback() && stream.set_nonblocking(false).is_ok();
        let mut bytes_in = 0_u64;
        let (outcome, bytes_out) = if ready {
            let deadline = deadline_after(self.cfg.limits.request_deadline);
            match read_request(&mut stream, &self.cfg.limits, deadline, &mut bytes_in) {
                Ok(request) => self.answer(&mut stream, peer, &request, deadline),
                Err(Failure::Refuse(status)) => self.refuse(&mut stream, status, deadline),
                Err(Failure::Drop) => (Outcome::Dropped, 0),
            }
        } else {
            (Outcome::Dropped, 0)
        };
        // Recorded BEFORE the half-close in `linger`: the half-close is what tells the client the connection is finished, so a caller
        // that reads the report once the client has returned must already see this connection counted.
        self.shared.note(move |report| {
            report.bytes_in = report.bytes_in.saturating_add(bytes_in);
            report.bytes_out = report.bytes_out.saturating_add(bytes_out);
            match outcome {
                Outcome::Served => report.served = report.served.saturating_add(1),
                Outcome::Described => report.described = report.described.saturating_add(1),
                Outcome::Refused(status) => {
                    report.refused = report.refused.saturating_add(1);
                    report.refused_statuses.push(status);
                }
                Outcome::Dropped => report.dropped = report.dropped.saturating_add(1),
            }
        });
        linger(&mut stream);
    }

    /// Hand the request to the real endpoint and write its answer.
    fn answer(
        &mut self,
        stream: &mut TcpStream,
        peer: SocketAddr,
        request: &Request,
        deadline: Instant,
    ) -> (Outcome, u64) {
        if let Some(bytes) = self.description_for(request) {
            return match send(stream, &bytes, &self.cfg.limits, deadline) {
                Ok(()) => (Outcome::Described, to_u64(bytes.len())),
                Err(_) => (Outcome::Dropped, 0),
            };
        }
        if self.names_another_callback(request) {
            return self.refuse(stream, 412, deadline);
        }
        let headers: Vec<(&str, &str)> = request
            .head
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let http = HttpRequest {
            method: &request.head.method,
            path: &request.head.target,
            peer_ip: peer.ip(),
            ingress: self.cfg.policy.ingress(),
            headers: &headers,
            body: &request.body,
        };
        self.now_ns = self.now_ns.saturating_add(STEP_NS);
        let handled = {
            let mut session = self.shared.session();
            self.plane.handle_request(&mut session, self.now_ns, &http)
        };
        let response = &handled.response;
        let body = response.body.as_bytes();
        let framed = render_response(response.status, &response.headers, body);
        let outcome = match framed {
            Some(bytes) => match send(stream, &bytes, &self.cfg.limits, deadline) {
                Ok(()) => (Outcome::Served, to_u64(bytes.len())),
                Err(_) => (Outcome::Dropped, 0),
            },
            // The endpoint's answer cannot be framed safely (a header with a line break): say so, forward nothing of it.
            None => self.refuse(stream, 500, deadline),
        };
        // Events go out after the answer, never before it: a controller learns its SID from the SUBSCRIBE answer first. They are
        // the core's, so they are offered whatever became of the write; the delivery thread does the sending, off this path.
        self.offer(&handled.notifications);
        outcome
    }

    /// Whether this is a local-link `SUBSCRIBE` on a shim started eventing that names a callback other than the allowed one. The
    /// core would grant it (its only rule is that the callback names the peer's own address) and nothing could ever be delivered, so
    /// the shim answers the core's own 412 for a bad callback without calling it, and counts it. A renewal or an unsubscribe carries
    /// no callback and passes through; so does every request on a shim not started eventing, and every tailnet connection (the
    /// core refuses those itself).
    fn names_another_callback(&self, request: &Request) -> bool {
        let Some(outbox) = &self.outbox else {
            return false;
        };
        if self.cfg.policy != Policy::LocalLink || request.head.method != "SUBSCRIBE" {
            return false;
        }
        let another = request
            .head
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("callback"))
            .any(|(_, value)| !outbox.allows(value));
        if another {
            outbox.note_subscribe_refused();
        }
        another
    }

    /// Hand the notifications the core produced to the delivery queue, if this shim was started eventing. Never blocks. Without
    /// a queue they are dropped, as they always were.
    fn offer(&self, notifications: &[Notification]) {
        if let Some(outbox) = &self.outbox {
            outbox.offer(notifications);
        }
    }

    /// The device description as the core builds it, framed for the wire, when `request` is the one GET for it on the local link.
    /// `None` for everything else: another path or method, a shim not started discoverable, and any connection judged as the
    /// tailnet, all of which go to the endpoint and are answered (or refused) as before.
    fn description_for(&self, request: &Request) -> Option<Vec<u8>> {
        let device = self.device.as_ref()?;
        if self.cfg.policy != Policy::LocalLink
            || request.head.method != "GET"
            || request.head.target != DESCRIPTION_PATH
        {
            return None;
        }
        let name = "Content-Type".to_string();
        let value = DESCRIPTION_CONTENT_TYPE.to_string();
        let body = device.description_xml();
        render_response(200, &[(name, value)], body.as_bytes())
    }

    /// Answer with a bare status and no body, without calling the endpoint.
    fn refuse(&self, stream: &mut TcpStream, status: u16, deadline: Instant) -> (Outcome, u64) {
        let bytes = render_response(status, &[], b"").unwrap_or_default();
        match send(stream, &bytes, &self.cfg.limits, deadline) {
            Ok(()) => (Outcome::Refused(status), to_u64(bytes.len())),
            Err(_) => (Outcome::Refused(status), 0),
        }
    }
}

fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn deadline_after(span: Duration) -> Instant {
    // A span too large to add is no deadline at all, which would be unbounded: treat it as already expired.
    Instant::now()
        .checked_add(span)
        .unwrap_or_else(Instant::now)
}

// ---- reading a request -----------------------------------------------------------------------------------------------

/// How a read failed: answer with a status, or close without answering.
#[derive(Debug, PartialEq, Eq)]
enum Failure {
    Refuse(u16),
    Drop,
}

#[derive(Debug, PartialEq, Eq)]
struct Head {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    content_length: usize,
}

struct Request {
    head: Head,
    body: Vec<u8>,
}

/// A request is silent while nothing at all has arrived: closing it unanswered is right. Once something arrived a stall is a 408.
fn timed_out(silent: bool) -> Failure {
    if silent {
        Failure::Drop
    } else {
        Failure::Refuse(408)
    }
}

fn fill(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    limits: &LoopbackLimits,
    deadline: Instant,
    bytes_in: &mut u64,
) -> Result<(), Failure> {
    let silent = buf.is_empty();
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(timed_out(silent));
    }
    let wait = left.min(limits.io_timeout).max(Duration::from_millis(1));
    if stream.set_read_timeout(Some(wait)).is_err() {
        return Err(Failure::Drop);
    }
    let mut chunk = [0_u8; READ_CHUNK];
    match stream.read(&mut chunk) {
        Ok(0) => Err(Failure::Drop),
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            *bytes_in = bytes_in.saturating_add(to_u64(n));
            Ok(())
        }
        Err(error) => match error.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Err(timed_out(silent)),
            io::ErrorKind::Interrupted => Ok(()),
            _ => Err(Failure::Drop),
        },
    }
}

/// Where the blank line that ends the head starts.
fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn read_request(
    stream: &mut TcpStream,
    limits: &LoopbackLimits,
    deadline: Instant,
    bytes_in: &mut u64,
) -> Result<Request, Failure> {
    let mut buf: Vec<u8> = Vec::new();
    let end = loop {
        if let Some(at) = head_end(&buf) {
            break at;
        }
        if buf.len() > limits.max_head_bytes {
            return Err(Failure::Refuse(431));
        }
        fill(stream, &mut buf, limits, deadline, bytes_in)?;
    };
    if end + 4 > limits.max_head_bytes {
        return Err(Failure::Refuse(431));
    }
    let text = std::str::from_utf8(&buf[..end]).map_err(|_| Failure::Refuse(400))?;
    let head = parse_head(text, limits).map_err(Failure::Refuse)?;
    if head.content_length > limits.max_body_bytes {
        return Err(Failure::Refuse(413));
    }
    let total = end + 4 + head.content_length;
    while buf.len() < total {
        fill(stream, &mut buf, limits, deadline, bytes_in)?;
    }
    let body = buf[end + 4..total].to_vec();
    Ok(Request { head, body })
}

fn valid_method(method: &str) -> bool {
    !method.is_empty()
        && method.len() <= MAX_METHOD_BYTES
        && method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
}

fn valid_target(target: &str) -> bool {
    target.starts_with('/')
        && target.len() <= MAX_TARGET_BYTES
        && target.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

fn valid_header_value(value: &str) -> bool {
    value.len() <= MAX_VALUE_BYTES
        && value
            .bytes()
            .all(|byte| matches!(byte, b'\t' | 0x20..=0x7e))
}

fn parse_length(value: &str) -> Option<usize> {
    if value.is_empty()
        || value.len() > MAX_LENGTH_DIGITS
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse().ok()
}

/// The request line and headers, or the status to refuse with. Strict on purpose: a head that is odd is refused, not repaired.
fn parse_head(text: &str, limits: &LoopbackLimits) -> Result<Head, u16> {
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(400);
    };
    if !valid_method(method) || !valid_target(target) {
        return Err(400);
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(505);
    }
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: Option<usize> = None;
    for line in lines {
        if headers.len() >= limits.max_headers {
            return Err(431);
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(400);
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(400);
        };
        let value = value.trim_matches([' ', '\t']);
        if !valid_header_name(name) || !valid_header_value(value) {
            return Err(400);
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(501);
        }
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = parse_length(value).ok_or(400_u16)?;
            if content_length.is_some_and(|earlier| earlier != parsed) {
                return Err(400);
            }
            content_length = Some(parsed);
        }
        headers.push((name.to_string(), value.to_string()));
    }
    Ok(Head {
        method: method.to_string(),
        target: target.to_string(),
        headers,
        content_length: content_length.unwrap_or(0),
    })
}

// ---- writing an answer -----------------------------------------------------------------------------------------------

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        505 => "HTTP Version Not Supported",
        _ => "Status",
    }
}

/// The bytes of one answer: the endpoint's headers (less the three the shim owns), then `Content-Length` and `Connection: close`.
/// `None` when a header cannot be framed safely, so a value with a line break can never split the answer.
fn render_response(status: u16, headers: &[(String, String)], body: &[u8]) -> Option<Vec<u8>> {
    let mut out = format!("HTTP/1.1 {status} {}\r\n", reason(status)).into_bytes();
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        if !valid_header_name(name) || !valid_header_value(value) {
            return None;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(
        format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(body);
    Some(out)
}

fn send(
    stream: &mut TcpStream,
    bytes: &[u8],
    limits: &LoopbackLimits,
    deadline: Instant,
) -> io::Result<()> {
    let left = deadline.saturating_duration_since(Instant::now());
    let wait = left.min(limits.io_timeout).max(Duration::from_millis(1));
    stream.set_write_timeout(Some(wait))?;
    stream.write_all(bytes)?;
    stream.flush()
}

/// Half-close, then read and discard for a short bounded time before the socket closes. A client that is still sending would
/// otherwise get a reset that can discard the answer it has not read yet.
fn linger(stream: &mut TcpStream) {
    let _ = stream.shutdown(Shutdown::Write);
    if stream.set_read_timeout(Some(LINGER)).is_err() {
        return;
    }
    let started = Instant::now();
    let mut sink = [0_u8; READ_CHUNK];
    let mut left = LINGER_BYTES;
    while left > 0 && started.elapsed() < LINGER {
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(n) => left = left.saturating_sub(n),
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod fleet_tests;

#[cfg(test)]
mod mailbox_tests {
    use super::*;
    use crate::settled_http::{HttpMailboxConfig, HttpService, OwnedHttpReply, http_mailbox};
    use crate::settled_render::{ControlResult, OwnerError};

    fn notice(seq: u32) -> Notification {
        Notification {
            sid: "uuid:synthetic".into(),
            service: franken_control::fsonos::Service::RenderingControl,
            callback: "http://127.0.0.1:9/events".into(),
            seq,
            body: format!("notice-{seq}"),
        }
    }

    #[test]
    fn mailbox_adapter_preserves_committed_response_despite_render_error_and_updates_snapshot() {
        let config = HttpMailboxConfig::new(4096, 8, Duration::from_millis(500)).unwrap();
        let (client, mut owner) = http_mailbox(config).unwrap();
        let service = thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(2);
            loop {
                let result = owner
                    .service_one(|request| {
                        assert_eq!(request.body, b"request");
                        let mut session = UnifiedGroupSession::new("group", "issuer", 1);
                        session.state_revision = 17;
                        OwnedHttpReply {
                            result: Ok(ControlResult {
                                control: Handled {
                                    response: franken_control::fsonos::HttpResponse {
                                        status: 200,
                                        headers: Vec::new(),
                                        body: "committed".into(),
                                    },
                                    notifications: vec![notice(1)],
                                    settled_others: Vec::new(),
                                },
                                render: Err(OwnerError::Clock),
                                notifications: vec![notice(2)],
                            }),
                            session,
                        }
                    })
                    .unwrap();
                if result == HttpService::Replied {
                    break;
                }
                assert_eq!(result, HttpService::Idle);
                assert!(Instant::now() < end);
                thread::sleep(Duration::from_millis(1));
            }
        });
        let mut plane = mailbox_control(client);
        let mut diagnostic = UnifiedGroupSession::new("diagnostic", "old", 1);
        let request = HttpRequest {
            method: "POST",
            path: "/control",
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ingress: Ingress::Tailnet,
            headers: &[],
            body: b"request",
        };
        let response = plane.handle_request(&mut diagnostic, 0, &request);
        assert_eq!(response.response.status, 200);
        assert_eq!(response.response.body, "committed");
        assert_eq!(response.notifications, vec![notice(1), notice(2)]);
        assert_eq!(diagnostic.group_id, "group");
        assert_eq!(diagnostic.state_revision, 17);
        service.join().unwrap();
    }

    #[test]
    fn mailbox_discovery_extras_are_refused_and_plain_factory_start_still_works() {
        let config = HttpMailboxConfig::new(4096, 8, Duration::from_millis(500)).unwrap();
        let (client, _owner) = http_mailbox(config).unwrap();
        let identity = DiscoveryIdentity::fixture();
        let described = FsonosLoopback::describe(&identity, DiscoveryLimits::standard()).unwrap();
        let refused_client = client.clone();
        let refused = FsonosLoopback::start_inner_with(
            UnifiedGroupSession::new("group", "issuer", 1),
            &identity.uuid,
            Policy::LocalLink,
            LoopbackLimits::standard(),
            Some((described, DiscoveryLimits::standard())),
            None,
            (
                || Ok([1; INCARNATION_BYTES]),
                Box::new(move |_, _, _| Ok(mailbox_control(refused_client))),
            ),
        );
        assert_eq!(
            refused.err().as_deref(),
            Some("control owner does not admit transport-local extras")
        );
        let started = FsonosLoopback::start_with_control(
            UnifiedGroupSession::new("group", "issuer", 1),
            &identity.uuid,
            Policy::UnauthenticatedTailnet,
            LoopbackLimits::standard(),
            move |_, _, _| Ok(mailbox_control(client)),
        )
        .unwrap();
        assert!(started.addr().ip().is_loopback());
        assert_eq!(started.stop().stopped_by, StopCause::Requested);
    }
}
