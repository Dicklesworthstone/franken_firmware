//! The retained-network lifecycle (`N07` / `ffw-ybr`, `docs/contracts/n07.md` section 8): what the Rust side owns, what is not
//! established, and the bounded state machine that reacts to link, address and lease events.
//!
//! Nothing here touches an interface. [`LinkManager`] is a pure state machine: the caller passes the time and the event, and
//! gets back the actions to perform. It does not read a clock, open a socket, or know how an event was produced. The
//! carrier's half of each action is `CarrierSender::set_link_up` / `rebind` / `peer_address_changed` and the receiver's
//! `rebind` / `set_sender_control`; the speaker's glue (`franken-speaker`, `net_carrier`) performs them.
//!
//! What is deliberately not claimed.
//! * **No ownership guess.** [`ownership_matrix`] lists every duty the bead names. A duty is `Rust` only where this crate
//!   performs it, with a test. Association, address acquisition, lease renewal, routes, resolvers and the seven E04 radio
//!   duties are [`Owner::Unestablished`]: nobody has shown who performs them in the stock system or whether they survive
//!   replacing the daemon, and this module does not assume either answer. The seven E04 duties carry the E04 record id
//!   and blocker ids verbatim, and a test holds them to the committed `tests/e04/matrix_audiodev_m16.json`.
//! * **No physical qualification.** Every [`LinkProfile`] names the external receipt that would qualify it (`Q03`, `Q06`) and
//!   there is no way to mark one qualified. Wireless profiles are tracked as required; they are not silently dropped and not
//!   claimed. A pass over events produced by a test says nothing about a radio.
//! * **No WAN coupling.** [`LinkEvent::WanReachability`] and [`LinkEvent::ResolverChanged`] are counted and change nothing:
//!   local control and playback never wait on the WAN.

use serde::Serialize;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

// ------------------------------------------------------------------------------------------------------ transport reasons

/// Why transport is down or degraded, in terms the speaker's readiness state can show (UX01). No variant is about WAN
/// reachability: a speaker that cannot reach the internet is not degraded here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportReason {
    InterfaceDown,
    AddressMissing,
    AddressChanged,
    LeaseLapsed,
    RebindFailed,
    ReconnectBudgetSpent,
    UnsupportedAddressFamily,
}

impl TransportReason {
    pub const ALL: [Self; 7] = [
        Self::InterfaceDown,
        Self::AddressMissing,
        Self::AddressChanged,
        Self::LeaseLapsed,
        Self::RebindFailed,
        Self::ReconnectBudgetSpent,
        Self::UnsupportedAddressFamily,
    ];

    /// A stable machine-readable name, used in logs and receipts.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InterfaceDown => "N07_INTERFACE_DOWN",
            Self::AddressMissing => "N07_ADDRESS_MISSING",
            Self::AddressChanged => "N07_ADDRESS_CHANGED",
            Self::LeaseLapsed => "N07_LEASE_LAPSED",
            Self::RebindFailed => "N07_REBIND_FAILED",
            Self::ReconnectBudgetSpent => "N07_RECONNECT_BUDGET_SPENT",
            Self::UnsupportedAddressFamily => "N07_UNSUPPORTED_ADDRESS_FAMILY",
        }
    }

    /// The sentence the readiness state shows. It names the local network condition and never a remote service.
    #[must_use]
    pub const fn ux_text(self) -> &'static str {
        match self {
            Self::InterfaceDown => "the network interface is down",
            Self::AddressMissing => "the speaker has no network address yet",
            Self::AddressChanged => "the network address changed; reconnecting",
            Self::LeaseLapsed => "the network address lease ended without renewal",
            Self::RebindFailed => "reconnecting to the local network failed; retrying",
            Self::ReconnectBudgetSpent => "reconnecting to the local network did not succeed",
            Self::UnsupportedAddressFamily => {
                "the network offered only an address family this speaker does not use"
            }
        }
    }
}

// ----------------------------------------------------------------------------------------------------------------- profiles

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    Wired,
    WifiStation,
    SonosNetMesh,
}

/// One declared link profile. Address families are declared per profile: an address of an undeclared family is refused and
/// never becomes the path. `pending_receipt` names the external physical receipt that would qualify the profile; there is no
/// field that says "qualified", so no code path here can claim it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LinkProfile {
    pub id: &'static str,
    pub kind: LinkKind,
    pub ipv4: bool,
    pub ipv6: bool,
    /// The fleet needs this profile. Wireless stays a tracked requirement wherever it does.
    pub required: bool,
    pub pending_receipt: &'static str,
    /// The path MTU assumed until a peer's own is measured.
    pub default_path_mtu: usize,
}

impl LinkProfile {
    /// Whether this profile declares `ip`'s family.
    #[must_use]
    pub const fn declares(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.ipv4,
            IpAddr::V6(_) => self.ipv6,
        }
    }
}

/// The profiles this slice tracks. IPv4 only: IPv6 operation is neither declared nor exercised for any of them.
pub const PROFILES: [LinkProfile; 3] = [
    LinkProfile {
        id: "wired",
        kind: LinkKind::Wired,
        ipv4: true,
        ipv6: false,
        required: true,
        pending_receipt: "Q03",
        default_path_mtu: 1500,
    },
    LinkProfile {
        id: "wifi_station",
        kind: LinkKind::WifiStation,
        ipv4: true,
        ipv6: false,
        required: true,
        pending_receipt: "Q03+Q06",
        default_path_mtu: 1500,
    },
    LinkProfile {
        id: "sonosnet_mesh",
        kind: LinkKind::SonosNetMesh,
        ipv4: true,
        ipv6: false,
        required: true,
        pending_receipt: "Q03+Q06",
        default_path_mtu: 1500,
    },
];

// --------------------------------------------------------------------------------------------------------- ownership matrix

/// The E04 blocker that says who performs a radio duty, and whether it survives replacing the daemon, is not established.
pub const E04_OWNERSHIP_BLOCKER: &str = "EXT-E04-RADIO-OWNERSHIP";
/// The E04 blocker for the worst-case audio scheduling delay a radio duty can cause (needs the human-lane measurement).
pub const E04_QUAL_BLOCKER: &str = "EXT-E04-LIVE-QUAL";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    /// This crate performs it, and a test shows it.
    Rust,
    /// Nobody has shown who performs it in the stock system or whether it survives replacing the daemon. Nothing here
    /// assumes either answer, and a duty in this state is a missing capability, not a retained one.
    Unestablished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Implementation {
    /// Code and tests exist in this tree.
    Implemented,
    /// The Rust side decides, but the on-device source of its input or effector for its output does not exist yet; the
    /// gap is named in `blocker`.
    PolicyOnly,
    /// Nothing exists. The duty is listed so that it cannot be silently dropped.
    NotStarted,
}

/// One duty of the retained-network matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DutyRecord {
    pub id: &'static str,
    pub text: &'static str,
    pub owner: Owner,
    pub implementation: Implementation,
    /// The duty exists on wireless profiles (and only there, when false it exists on every profile).
    pub wireless_only: bool,
    /// The exact E04 radio-duty record this duty is, if it is one.
    pub e04_record: Option<&'static str>,
    /// Blocker ids that say what would establish or implement it (E04's own where E04 names them).
    pub blockers: &'static [&'static str],
}

const E04_BLOCKERS: &[&str] = &[E04_OWNERSHIP_BLOCKER, E04_QUAL_BLOCKER];
const GAP_EVENT_SOURCE: &[&str] = &["N07-GAP-LINK-EVENT-SOURCE"];
const GAP_P02_SEND: &[&str] = &["N07-GAP-P02-DATAGRAM-SEND"];
const GAP_REPLACEMENT: &[&str] = &["N07-GAP-NO-RUST-REPLACEMENT", E04_OWNERSHIP_BLOCKER];
const NONE: &[&str] = &[];

const fn duty(
    id: &'static str,
    text: &'static str,
    owner: Owner,
    implementation: Implementation,
    wireless_only: bool,
    e04_record: Option<&'static str>,
    blockers: &'static [&'static str],
) -> DutyRecord {
    DutyRecord {
        id,
        text,
        owner,
        implementation,
        wireless_only,
        e04_record,
        blockers,
    }
}

/// The matrix. The first group is what this slice performs or names as its own gap; the second is the E04 radio-duty
/// set, verbatim (record ids and blocker ids), all unestablished.
pub const OWNERSHIP: [DutyRecord; 21] = [
    duty(
        "link.state_events",
        "interface up/down and address-change events reach the link manager",
        Owner::Rust,
        Implementation::PolicyOnly,
        false,
        None,
        GAP_EVENT_SOURCE,
    ),
    duty(
        "link.association",
        "Wi-Fi association and authentication; SonosNet mesh join",
        Owner::Unestablished,
        Implementation::NotStarted,
        true,
        None,
        GAP_REPLACEMENT,
    ),
    duty(
        "addr.acquisition",
        "obtaining an address (DHCP or static)",
        Owner::Unestablished,
        Implementation::NotStarted,
        false,
        None,
        GAP_REPLACEMENT,
    ),
    duty(
        "addr.lease_renewal",
        "renewing the address lease before it ends",
        Owner::Unestablished,
        Implementation::NotStarted,
        false,
        None,
        GAP_REPLACEMENT,
    ),
    duty(
        "addr.lease_watch",
        "stop sending before a lease ends unless it was renewed; never send from an address that lapsed",
        Owner::Rust,
        Implementation::Implemented,
        false,
        None,
        NONE,
    ),
    duty(
        "route.maintenance",
        "default route and on-link route upkeep",
        Owner::Unestablished,
        Implementation::NotStarted,
        false,
        None,
        GAP_REPLACEMENT,
    ),
    duty(
        "resolver.maintenance",
        "resolver configuration and lookups (local playback needs none; recorded so it is not assumed)",
        Owner::Unestablished,
        Implementation::NotStarted,
        false,
        None,
        GAP_REPLACEMENT,
    ),
    duty(
        "socket.rebind",
        "replace the media and control sockets after the local address changed, all or nothing",
        Owner::Rust,
        Implementation::Implemented,
        false,
        None,
        NONE,
    ),
    duty(
        "path.stale_cleanup",
        "drop state tied to an address that is gone; refuse reports from an old path",
        Owner::Rust,
        Implementation::Implemented,
        false,
        None,
        NONE,
    ),
    duty(
        "identity.stable_across_ip_change",
        "a speaker keeps its identity, peer handle and sequence when its address changes",
        Owner::Rust,
        Implementation::Implemented,
        false,
        None,
        NONE,
    ),
    duty(
        "reconnect.backoff",
        "bounded reconnect with backoff; a spent budget is reported, not retried forever",
        Owner::Rust,
        Implementation::Implemented,
        false,
        None,
        NONE,
    ),
    duty(
        "transport.failure_reasons",
        "failure reasons for the readiness state that never mention the WAN",
        Owner::Rust,
        Implementation::Implemented,
        false,
        None,
        NONE,
    ),
    duty(
        "wan.decoupling",
        "WAN reachability and resolver events never change local control or playback state",
        Owner::Rust,
        Implementation::Implemented,
        false,
        None,
        NONE,
    ),
    duty(
        "p02.datagram_send",
        "sending a datagram through the P02 socket seam (the seam has socket, bind, listen, accept4 and recv only)",
        Owner::Rust,
        Implementation::PolicyOnly,
        false,
        None,
        GAP_P02_SEND,
    ),
    duty(
        "radio.multicast_delivery",
        "multicast delivery",
        Owner::Unestablished,
        Implementation::NotStarted,
        true,
        Some("radio.multicast_delivery"),
        E04_BLOCKERS,
    ),
    duty(
        "radio.unicast_delivery",
        "unicast delivery",
        Owner::Unestablished,
        Implementation::NotStarted,
        true,
        Some("radio.unicast_delivery"),
        E04_BLOCKERS,
    ),
    duty(
        "radio.power_save",
        "power save",
        Owner::Unestablished,
        Implementation::NotStarted,
        true,
        Some("radio.power_save"),
        E04_BLOCKERS,
    ),
    duty(
        "radio.roam",
        "roaming between access points",
        Owner::Unestablished,
        Implementation::NotStarted,
        true,
        Some("radio.roam"),
        E04_BLOCKERS,
    ),
    duty(
        "radio.congestion",
        "congestion handling",
        Owner::Unestablished,
        Implementation::NotStarted,
        true,
        Some("radio.congestion"),
        E04_BLOCKERS,
    ),
    duty(
        "radio.mesh_membership",
        "mesh membership",
        Owner::Unestablished,
        Implementation::NotStarted,
        true,
        Some("radio.mesh_membership"),
        E04_BLOCKERS,
    ),
    duty(
        "radio.scheduler_interference",
        "scheduler interference",
        Owner::Unestablished,
        Implementation::NotStarted,
        true,
        Some("radio.scheduler_interference"),
        E04_BLOCKERS,
    ),
];

/// Every duty, in a stable order.
#[must_use]
pub const fn ownership_matrix() -> &'static [DutyRecord] {
    &OWNERSHIP
}

/// Self-consistency of the matrix; empty when it holds. Checked by a unit test, and by the integration test against E04.
///
/// * ids are unique;
/// * an unestablished duty names a blocker, and a policy-only duty names its gap;
/// * a duty that is E04's is unestablished and not started (this crate claims nothing E04 does not know) and names both E04
///   blockers;
/// * a duty that is `Implemented` names no blocker.
#[must_use]
pub fn matrix_problems() -> Vec<String> {
    matrix_problems_of(ownership_matrix())
}

/// [`matrix_problems`] over any table, so that a test can show the check is not blind by feeding it a table that claims more
/// than E04 knows.
#[must_use]
pub fn matrix_problems_of(all: &[DutyRecord]) -> Vec<String> {
    let mut problems = Vec::new();
    for (index, record) in all.iter().enumerate() {
        if all[..index].iter().any(|earlier| earlier.id == record.id) {
            problems.push(format!("{}: duplicate id", record.id));
        }
        if record.owner == Owner::Unestablished && record.blockers.is_empty() {
            problems.push(format!("{}: unestablished without a blocker", record.id));
        }
        if record.implementation == Implementation::PolicyOnly && record.blockers.is_empty() {
            problems.push(format!("{}: policy-only without a named gap", record.id));
        }
        if record.implementation == Implementation::Implemented && !record.blockers.is_empty() {
            problems.push(format!("{}: implemented but names a blocker", record.id));
        }
        if record.e04_record.is_some() {
            if record.owner != Owner::Unestablished
                || record.implementation != Implementation::NotStarted
            {
                problems.push(format!(
                    "{}: claims more than E04 knows (E04 leaves it unestablished)",
                    record.id
                ));
            }
            if record.blockers != E04_BLOCKERS {
                problems.push(format!("{}: E04 blockers not carried verbatim", record.id));
            }
        }
    }
    problems
}

// ------------------------------------------------------------------------------------------------------------ link manager

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    #[error("invalid link configuration: {0}")]
    InvalidConfig(&'static str),
}

/// Every bound of the link manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkConfig {
    pub profile: LinkProfile,
    /// First wait after a failed rebind; doubles per attempt up to `backoff_max_ns`.
    pub backoff_initial_ns: u64,
    pub backoff_max_ns: u64,
    /// Rebind attempts in one outage before the manager gives up (it resumes on the next event).
    pub max_rebind_attempts: u32,
    /// How long to wait for an address once the interface is up before giving up.
    pub address_wait_ns: u64,
    /// Stop sending this long before a lease ends unless it was renewed.
    pub lease_guard_ns: u64,
    /// Seed of the backoff jitter (up to a quarter of the step), so a mixed fleet does not retry in step and a run can be
    /// replayed from the seed.
    pub jitter_seed: u64,
}

impl LinkConfig {
    #[must_use]
    pub const fn baseline(profile: LinkProfile, jitter_seed: u64) -> Self {
        Self {
            profile,
            backoff_initial_ns: 100_000_000,
            backoff_max_ns: 5_000_000_000,
            max_rebind_attempts: 6,
            address_wait_ns: 10_000_000_000,
            lease_guard_ns: 1_000_000_000,
            jitter_seed,
        }
    }

    /// # Errors
    /// [`LinkError::InvalidConfig`] naming the bound.
    pub const fn validate(&self) -> Result<(), LinkError> {
        if self.backoff_initial_ns == 0 || self.backoff_initial_ns > self.backoff_max_ns {
            return Err(LinkError::InvalidConfig("backoff needs 0 < initial <= max"));
        }
        if self.max_rebind_attempts == 0 {
            return Err(LinkError::InvalidConfig("zero rebind attempts"));
        }
        if self.address_wait_ns == 0 {
            return Err(LinkError::InvalidConfig("zero address wait"));
        }
        if !self.profile.ipv4 && !self.profile.ipv6 {
            return Err(LinkError::InvalidConfig(
                "the profile declares no address family",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkState {
    /// The interface is down. Nothing is sent or read.
    Down,
    /// The interface is up and has no usable address (yet). Bounded by `address_wait_ns`.
    WaitingForAddress,
    /// A rebind was requested and its outcome is awaited.
    Binding,
    /// Sockets are bound on the current address and the carrier may run.
    Up,
    /// A rebind failed; the next attempt is at `next_attempt_ns`.
    Backoff,
    /// The budget is spent (or no address ever came). Any later connectivity event starts over.
    Failed,
}

/// What the link manager learned. The caller produces these from whatever it observes; none of them is read from an
/// interface here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkEvent {
    InterfaceUp,
    InterfaceDown,
    /// An address was bound or changed. `lease_ns` is the lease length when there is one (`None`: static or unknown).
    AddressBound {
        ip: IpAddr,
        lease_ns: Option<u64>,
    },
    AddressLost,
    LeaseRenewed {
        lease_ns: u64,
    },
    /// The outcome of a [`LinkAction::Rebind`], naming the address it was for.
    RebindResult {
        ip: IpAddr,
        ok: bool,
    },
    /// The resolver changed or failed. Recorded and nothing else.
    ResolverChanged {
        servers: u8,
        usable: bool,
    },
    /// Upstream reachability changed. Recorded and nothing else.
    WanReachability {
        reachable: bool,
    },
}

/// What the caller must do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkAction {
    /// Stop sending and reading (`set_link_up(false)`); queues stay bounded and age out by their own deadlines.
    Quiesce { reason: TransportReason },
    /// Bind new sockets on `ip` (carrier and receiver `rebind`) and report the outcome as `RebindResult`.
    Rebind { ip: IpAddr, attempt: u32 },
    /// Drop state tied to the address `old_ip` (a stale path).
    ReleaseStale { old_ip: IpAddr },
    /// The sockets are bound on `ip`: resume (`set_link_up(true)`). `generation` identifies the path; audio queued while
    /// the link was down is not replayed, and the receivers catch up muted.
    Resume { ip: IpAddr, generation: u64 },
    /// The budget is spent; the speaker's readiness state shows `reason`. Local control is unaffected.
    GiveUp { reason: TransportReason },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LinkCounters {
    pub events: u64,
    pub ignored_events: u64,
    pub resolver_events: u64,
    pub wan_events: u64,
    pub rebinds_requested: u64,
    pub rebinds_failed: u64,
    pub resumes: u64,
    pub quiesces: u64,
    pub give_ups: u64,
    pub refused_addresses: u64,
    pub stale_releases: u64,
    pub lease_lapses: u64,
}

/// A read-only view for logs and tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkStatus {
    pub state: LinkState,
    pub iface_up: bool,
    pub addr: Option<IpAddr>,
    pub bound: Option<IpAddr>,
    pub generation: u64,
    pub attempt: u32,
    pub reason: Option<TransportReason>,
    pub next_attempt_ns: Option<u64>,
    pub lease_end_ns: Option<u64>,
}

/// One step of `SplitMix64`, the generator the backoff jitter draws from.
const fn splitmix64(mut state: u64) -> u64 {
    state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The bounded lifecycle state machine. See the module documentation.
#[derive(Debug, Clone)]
pub struct LinkManager {
    cfg: LinkConfig,
    state: LinkState,
    iface_up: bool,
    addr: Option<IpAddr>,
    bound: Option<IpAddr>,
    stale: Option<IpAddr>,
    lease_end_ns: Option<u64>,
    attempt: u32,
    next_attempt_ns: Option<u64>,
    wait_deadline_ns: Option<u64>,
    generation: u64,
    reason: Option<TransportReason>,
    counters: LinkCounters,
}

impl LinkManager {
    /// # Errors
    /// [`LinkError::InvalidConfig`].
    pub fn new(cfg: LinkConfig) -> Result<Self, LinkError> {
        cfg.validate()?;
        Ok(Self {
            cfg,
            state: LinkState::Down,
            iface_up: false,
            addr: None,
            bound: None,
            stale: None,
            lease_end_ns: None,
            attempt: 0,
            next_attempt_ns: None,
            wait_deadline_ns: None,
            generation: 0,
            reason: Some(TransportReason::InterfaceDown),
            counters: LinkCounters::default(),
        })
    }

    #[must_use]
    pub const fn counters(&self) -> &LinkCounters {
        &self.counters
    }

    #[must_use]
    pub const fn config(&self) -> &LinkConfig {
        &self.cfg
    }

    #[must_use]
    pub const fn status(&self) -> LinkStatus {
        LinkStatus {
            state: self.state,
            iface_up: self.iface_up,
            addr: self.addr,
            bound: self.bound,
            generation: self.generation,
            attempt: self.attempt,
            reason: self.reason,
            next_attempt_ns: self.next_attempt_ns,
            lease_end_ns: self.lease_end_ns,
        }
    }

    /// The wait before rebind attempt `attempt` (1-based): `initial * 2^(attempt-1)` capped at `max`, plus seeded jitter of
    /// at most a quarter of the step, still capped. It never decreases from one attempt to the next within an outage.
    #[must_use]
    pub fn backoff_ns(&self, attempt: u32) -> u64 {
        let shift = attempt.saturating_sub(1).min(32);
        let base = self
            .cfg
            .backoff_initial_ns
            .saturating_mul(1u64 << shift)
            .min(self.cfg.backoff_max_ns);
        let span = base / 4;
        let jitter = if span == 0 {
            0
        } else {
            splitmix64(self.cfg.jitter_seed ^ u64::from(attempt)) % (span + 1)
        };
        base.saturating_add(jitter).min(self.cfg.backoff_max_ns)
    }

    fn quiesce(&mut self, reason: TransportReason, actions: &mut Vec<LinkAction>) {
        self.counters.quiesces += 1;
        self.reason = Some(reason);
        actions.push(LinkAction::Quiesce { reason });
    }

    fn resume(&mut self, ip: IpAddr, actions: &mut Vec<LinkAction>) {
        self.counters.resumes += 1;
        actions.push(LinkAction::Resume {
            ip,
            generation: self.generation,
        });
    }

    fn begin_rebind(&mut self, actions: &mut Vec<LinkAction>) {
        let Some(ip) = self.addr else {
            return;
        };
        self.attempt += 1;
        self.state = LinkState::Binding;
        self.next_attempt_ns = None;
        self.counters.rebinds_requested += 1;
        actions.push(LinkAction::Rebind {
            ip,
            attempt: self.attempt,
        });
    }

    /// A lease that has reached its guard is no address, wherever the manager is: the interface may be down, a rebind may be
    /// in flight, a backoff may be running. It is checked before any event is acted on and at every tick, so nothing resumes
    /// or rebinds onto an address whose lease has ended. A lease the retained stack renews in time never gets here.
    fn lapse_if_expired(&mut self, now_ns: u64, actions: &mut Vec<LinkAction>) {
        let Some(end) = self.lease_end_ns else {
            return;
        };
        if now_ns < end.saturating_sub(self.cfg.lease_guard_ns) {
            return;
        }
        self.counters.lease_lapses += 1;
        self.lease_end_ns = None;
        self.addr = None;
        self.generation += 1;
        if let Some(old) = self.bound.take() {
            self.stale = Some(old);
        }
        if matches!(
            self.state,
            LinkState::Up | LinkState::Binding | LinkState::Backoff
        ) {
            self.quiesce(TransportReason::LeaseLapsed, actions);
        }
        self.reason = Some(TransportReason::LeaseLapsed);
        self.attempt = 0;
        self.next_attempt_ns = None;
        if self.iface_up {
            self.state = LinkState::WaitingForAddress;
            self.wait_deadline_ns = Some(now_ns.saturating_add(self.cfg.address_wait_ns));
        } else {
            self.state = LinkState::Down;
            self.wait_deadline_ns = None;
        }
    }

    /// Re-decide after the interface, the address or the outage changed. The interface must be up to do anything.
    fn reconsider(&mut self, now_ns: u64, actions: &mut Vec<LinkAction>) {
        if !self.iface_up {
            return;
        }
        let Some(ip) = self.addr else {
            if self.state != LinkState::WaitingForAddress {
                if matches!(
                    self.state,
                    LinkState::Up | LinkState::Binding | LinkState::Backoff
                ) {
                    self.quiesce(TransportReason::AddressMissing, actions);
                }
                self.state = LinkState::WaitingForAddress;
                self.next_attempt_ns = None;
                self.wait_deadline_ns = Some(now_ns.saturating_add(self.cfg.address_wait_ns));
                if self.reason != Some(TransportReason::UnsupportedAddressFamily)
                    && self.reason != Some(TransportReason::LeaseLapsed)
                {
                    self.reason = Some(TransportReason::AddressMissing);
                }
            }
            return;
        };
        self.wait_deadline_ns = None;
        if self.bound == Some(ip) {
            if self.state != LinkState::Up {
                self.state = LinkState::Up;
                self.reason = None;
                self.attempt = 0;
                self.next_attempt_ns = None;
                self.resume(ip, actions);
            }
            return;
        }
        if self.state == LinkState::Up {
            self.quiesce(TransportReason::AddressChanged, actions);
        }
        self.begin_rebind(actions);
    }

    /// Feed one event. Returns the actions to perform, in order.
    pub fn on_event(&mut self, now_ns: u64, event: LinkEvent) -> Vec<LinkAction> {
        self.counters.events += 1;
        let mut actions = Vec::new();
        self.lapse_if_expired(now_ns, &mut actions);
        match event {
            LinkEvent::InterfaceDown => {
                self.iface_up = false;
                if self.state != LinkState::Down {
                    self.quiesce(TransportReason::InterfaceDown, &mut actions);
                    self.state = LinkState::Down;
                }
                self.attempt = 0;
                self.next_attempt_ns = None;
                self.wait_deadline_ns = None;
            }
            LinkEvent::InterfaceUp => {
                if self.iface_up {
                    self.counters.ignored_events += 1;
                } else {
                    self.iface_up = true;
                    self.attempt = 0;
                    self.reconsider(now_ns, &mut actions);
                }
            }
            LinkEvent::AddressBound { ip, lease_ns } => {
                if !self.cfg.profile.declares(ip) {
                    // An address of an undeclared family never becomes the path, and never disturbs the one in use.
                    self.counters.refused_addresses += 1;
                    if self.addr.is_none() {
                        self.reason = Some(TransportReason::UnsupportedAddressFamily);
                    }
                    return actions;
                }
                let changed = self.addr != Some(ip);
                self.addr = Some(ip);
                self.lease_end_ns = lease_ns.map(|lease| now_ns.saturating_add(lease));
                if changed {
                    self.generation += 1;
                    self.attempt = 0;
                    self.reconsider(now_ns, &mut actions);
                } else {
                    self.counters.ignored_events += 1;
                }
            }
            LinkEvent::AddressLost => {
                if self.addr.is_none() {
                    self.counters.ignored_events += 1;
                } else {
                    self.addr = None;
                    self.lease_end_ns = None;
                    self.generation += 1;
                    if let Some(old) = self.bound.take() {
                        self.stale = Some(old);
                    }
                    self.reconsider(now_ns, &mut actions);
                }
            }
            LinkEvent::LeaseRenewed { lease_ns } => {
                if self.addr.is_some() {
                    self.lease_end_ns = Some(now_ns.saturating_add(lease_ns));
                } else {
                    self.counters.ignored_events += 1;
                }
            }
            LinkEvent::RebindResult { ip, ok } => {
                if self.state != LinkState::Binding || self.addr != Some(ip) {
                    // Stale: the address moved on, or nothing was awaited.
                    self.counters.ignored_events += 1;
                } else if ok {
                    let old = self.bound.replace(ip).or_else(|| self.stale.take());
                    self.state = LinkState::Up;
                    self.attempt = 0;
                    self.reason = None;
                    self.next_attempt_ns = None;
                    if let Some(old_ip) = old
                        && old_ip != ip
                    {
                        self.counters.stale_releases += 1;
                        actions.push(LinkAction::ReleaseStale { old_ip });
                    }
                    self.resume(ip, &mut actions);
                } else {
                    self.counters.rebinds_failed += 1;
                    self.reason = Some(TransportReason::RebindFailed);
                    if self.attempt >= self.cfg.max_rebind_attempts {
                        self.state = LinkState::Failed;
                        self.reason = Some(TransportReason::ReconnectBudgetSpent);
                        self.counters.give_ups += 1;
                        actions.push(LinkAction::GiveUp {
                            reason: TransportReason::ReconnectBudgetSpent,
                        });
                    } else {
                        self.state = LinkState::Backoff;
                        self.next_attempt_ns =
                            Some(now_ns.saturating_add(self.backoff_ns(self.attempt)));
                    }
                }
            }
            LinkEvent::ResolverChanged { .. } => self.counters.resolver_events += 1,
            LinkEvent::WanReachability { .. } => self.counters.wan_events += 1,
        }
        actions
    }

    /// Advance time: due backoff attempts, the bounded wait for an address, and the lease guard.
    pub fn on_tick(&mut self, now_ns: u64) -> Vec<LinkAction> {
        let mut actions = Vec::new();
        self.lapse_if_expired(now_ns, &mut actions);
        match self.state {
            LinkState::Backoff => {
                if let Some(at) = self.next_attempt_ns
                    && now_ns >= at
                {
                    self.begin_rebind(&mut actions);
                }
            }
            LinkState::WaitingForAddress => {
                if let Some(deadline) = self.wait_deadline_ns
                    && now_ns >= deadline
                {
                    let reason = self.reason.unwrap_or(TransportReason::AddressMissing);
                    self.wait_deadline_ns = None;
                    self.state = LinkState::Failed;
                    self.counters.give_ups += 1;
                    actions.push(LinkAction::GiveUp { reason });
                }
            }
            LinkState::Up | LinkState::Down | LinkState::Binding | LinkState::Failed => {}
        }
        actions
    }
}

// ----------------------------------------------------------------------------------------------------------- peer directory

/// Where one speaker can be reached, and which generation of its path that is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PeerPath {
    pub media: SocketAddr,
    pub control: SocketAddr,
    pub generation: u64,
}

/// What an announcement did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Announced {
    New,
    Unchanged,
    /// The speaker moved. `old` is the path to clean up (`peer_address_changed` moves the carrier's peer to the new one).
    Moved {
        old: PeerPath,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DirectoryError {
    #[error("the directory already holds its {max} speakers")]
    Full { max: usize },
    #[error("an announcement of generation {got} is older than the current {current}")]
    Stale { got: u64, current: u64 },
    #[error("speaker {with:#x} already holds that address")]
    AddressInUse { with: u64 },
    #[error("peer handle {peer} belongs to speaker {with:#x}")]
    PeerHandleInUse { peer: u32, with: u64 },
    #[error("speaker {speaker:#x} keeps peer handle {held}; it cannot take {asked}")]
    PeerHandleChanged { speaker: u64, held: u32, asked: u32 },
}

#[derive(Debug, Clone, Copy)]
struct DirectoryEntry {
    peer: u32,
    path: PeerPath,
}

/// Stable speaker identities mapped to their current path. The speaker id (from membership) and the carrier's peer handle
/// survive an address change; only the path moves. Bounded, and an older path generation never overwrites a newer one.
#[derive(Debug, Clone)]
pub struct PeerDirectory {
    max: usize,
    entries: BTreeMap<u64, DirectoryEntry>,
}

impl PeerDirectory {
    #[must_use]
    pub const fn new(max: usize) -> Self {
        Self {
            max,
            entries: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn lookup(&self, speaker: u64) -> Option<(u32, PeerPath)> {
        self.entries
            .get(&speaker)
            .map(|entry| (entry.peer, entry.path))
    }

    /// Forget a speaker (it left the group). Returns whether it was known.
    pub fn remove(&mut self, speaker: u64) -> bool {
        self.entries.remove(&speaker).is_some()
    }

    /// Record where `speaker` can be reached. A refusal changes nothing.
    ///
    /// # Errors
    /// [`DirectoryError`]: a full directory, a stale generation, an address or a peer handle another speaker holds, or a
    /// speaker trying to change its handle.
    pub fn announce(
        &mut self,
        speaker: u64,
        peer: u32,
        media: SocketAddr,
        control: SocketAddr,
        generation: u64,
    ) -> Result<Announced, DirectoryError> {
        for (other, entry) in &self.entries {
            if *other == speaker {
                continue;
            }
            if entry.path.media == media
                || entry.path.control == control
                || entry.path.media == control
                || entry.path.control == media
            {
                return Err(DirectoryError::AddressInUse { with: *other });
            }
            if entry.peer == peer {
                return Err(DirectoryError::PeerHandleInUse { peer, with: *other });
            }
        }
        let path = PeerPath {
            media,
            control,
            generation,
        };
        match self.entries.get(&speaker).copied() {
            None => {
                if self.entries.len() >= self.max {
                    return Err(DirectoryError::Full { max: self.max });
                }
                self.entries.insert(speaker, DirectoryEntry { peer, path });
                Ok(Announced::New)
            }
            Some(held) => {
                if held.peer != peer {
                    return Err(DirectoryError::PeerHandleChanged {
                        speaker,
                        held: held.peer,
                        asked: peer,
                    });
                }
                if generation < held.path.generation {
                    return Err(DirectoryError::Stale {
                        got: generation,
                        current: held.path.generation,
                    });
                }
                if held.path.media == media && held.path.control == control {
                    // Same addresses: a newer generation of the same path is recorded, nothing moved.
                    self.entries.insert(speaker, DirectoryEntry { peer, path });
                    return Ok(Announced::Unchanged);
                }
                self.entries.insert(speaker, DirectoryEntry { peer, path });
                Ok(Announced::Moved { old: held.path })
            }
        }
    }
}

#[cfg(test)]
mod tests;
