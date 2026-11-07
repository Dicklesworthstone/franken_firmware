//! The real G03 endpoint and N02 control channel inside the Virtual House (`Q01` / `ffw-gmq`).
//!
//! The harness used to change the group's volume through `handle_fsonos_soap`, the earlier skeleton that calls the session
//! directly with no authentication, lease or ledger (`docs/contracts/g03.md` section 9 calls it superseded); every campaign now
//! ends with a group volume set through the real endpoint instead ([`exercise_group_volume_set`]). The acceptance
//! text asks for relative volume to be *retried through real adapter interfaces*. This module puts the real
//! `franken_control::fsonos::Endpoint`, a real `ControlChannel` and a real `PeerDirectory` in that place, unchanged and unwrapped,
//! and drives the two ingresses a controller really has:
//!
//! * **Local legacy SOAP** (`Ingress::LocalLegacy`): plain UPnP with no command id. The endpoint composes each request itself at the
//!   revision current when it arrives, so a retry is a *new* command and applies again (`g03.md` section 3.1, pinned by that
//!   crate's `a_plain_soap_retry_of_a_relative_change_applies_twice_and_that_is_pinned`).
//! * **Tailnet** (`Ingress::Tailnet`): an authenticated command carrying a command number, the epoch and the revision it was
//!   computed against, and an HMAC proof over exactly those bytes. The same number with the same body is answered from the ledger
//!   and applies once; a relative step composed against an older revision is refused with no effect.
//!
//! **What the oracle is.** [`VolumeModel`] states, from `g03.md` 3.1 / 9.1 and `n02.md`, what each send must do: the volume moves
//! to `clamp(v + delta, 0, 100)`, every applied volume command moves the state revision by exactly one (a clamped step too), a
//! legacy send always applies, a tailnet number applies at most once and its outcome, applied or refused, is remembered. The
//! harness compares the endpoint's answer (status, `NewVolume`, UPnP error code) and the session's state against it after every
//! send. It is a restatement of the contract, not a copy of the endpoint's code.
//!
//! **What it is not.** The ledger's retention (30 s of virtual time) is not modelled: a campaign lasts about a second. The
//! endpoint's own planted defects (`ReapplyOnRetry` and the like) are `cfg(test)` in `franken-control` and cannot be reached from
//! here, so the planted faults below are on the *client* side (a retry that is sent as a new command; a stale revision a client
//! silently refreshes) and show that the oracle notices what the contract forbids. Keys are public fixtures, not secrets. Nothing
//! here opens a socket. The only store of keys is [`HarnessKeys`], a volatile one, because `franken-control`'s own is `cfg(test)`.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use franken_control::channel::limiter::RateLimit;
use franken_control::channel::peer::{PeerDirectory, PeerId, PeerRole, compute_proof};
use franken_control::channel::pipeline::{
    Booted, ChannelConfig, ControlChannel, DevelopmentVolatile, Limits, OwnedDurable, RamMedium,
    Restored, RestoredFloors, boot_durable,
};
use franken_control::channel::request::{ControlCommand, RequestBody};
use franken_control::contracts::secret_store::{
    Generation, SecretError, SecretHandle, SecretMeta, SecretStore, SecretValue,
};
use franken_control::fsonos::{
    Context, Endpoint, EndpointConfig, Handled, HttpRequest, Ingress, LegacyBridge, Service,
};
use franken_session::{
    AuthorityToken, FencedControlCommand, GroupCommandPayload, UnifiedGroupSession,
};
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use crate::file_medium::{FaultingMedium, FileMedium};

/// The device's own panel: a LOCAL-USER peer, admitted only to the faulting durable plane. Synthetic label; its key is a public fixture.
#[cfg(unix)]
const PANEL_PEER: &str = "panel";

/// The identities the two ingresses speak as. Synthetic labels.
const BRIDGE_PEER: &str = "legacy-bridge";
const TAILNET_PEER: &str = "tailnet-controller";
/// Makes this incarnation's event subscription ids differ from another's. Nothing subscribes here.
const SUBSCRIPTION_NONCE: u32 = 0x5151_0001;
/// The reference runs apply their absolute sets under numbers of their own: above the bring-up's small ones and the fencing
/// probe's (`1_000_000..`), below the channel's own base (`1 << 32`). The session remembers which numbers it applied (a set), so
/// the order between these ranges does not matter, only that they do not collide.
const DIRECT_SEQ_BASE: u64 = 2_000_000;
/// A documentation-range address (RFC 5737): never a real host.
const LAN_PEER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
/// UPnP error code for "action failed", which is what the endpoint answers to a refused relative step.
const UPNP_ACTION_FAILED: u16 = 501;
/// UPnP error code for "invalid arguments", which is what the endpoint answers to a volume outside 0..=100.
const UPNP_INVALID_ARGS: u16 = 402;
/// The group volume every campaign ends by setting through the endpoint.
pub(crate) const END_OF_CAMPAIGN_GROUP_VOLUME: u8 = 65;
/// A volume the endpoint must refuse.
const OUT_OF_RANGE_VOLUME: u8 = 101;

/// A public fixture key for `peer`: long enough to be admitted, different for every peer. A fixture, not a secret.
fn fixture_key(peer: &str) -> Vec<u8> {
    format!("fixture-key-{peer}-0123456789abcdef").into_bytes()
}

// ---- the plan ------------------------------------------------------------------------------------------------------

/// Which of the two real ingresses a step goes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum Route {
    /// The local link: plain SOAP, no command id.
    LocalLegacy,
    /// The tailnet: an authenticated command with a command number and the revision it was computed against.
    Tailnet,
}

/// What a relative step changes: the endpoint's own member (`SetRelativeVolume`) or the group master (`SetRelativeGroupVolume`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum Target {
    Member,
    Group,
}

/// The revision a tailnet step names as the one it was computed against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum Observed {
    /// The revision the session has when the step is composed.
    Now,
    /// The revision the session had just before step `n` of the plan ran: a controller that read the group then and has not
    /// read it since. A step between that one and this one makes it stale.
    BeforeStep(usize),
}

/// One relative step and how often it is delivered: `sends` is the original plus its retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct RelativeStep {
    pub(crate) route: Route,
    pub(crate) target: Target,
    pub(crate) delta: i8,
    pub(crate) sends: u8,
    pub(crate) observed: Observed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum VolumeAction {
    /// A relative step through one of the real ingresses.
    Relative(RelativeStep),
    /// The reference: the absolute value, applied directly to the session. A reference run reaches the volumes a race is
    /// expected to reach without going through either ingress, so the two can be compared by what they sound like.
    Set { target: Target, volume: u8 },
}

/// A step at the start of render iteration `block`, before that block's gain is read from the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct VolumeStep {
    pub(crate) block: u64,
    pub(crate) action: VolumeAction,
}

/// A planted client-side defect. Each makes the client do what the contract says a correct client does not, and the oracle,
/// which holds the contract's expectation of the *intended* step, must say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum VolumeDefect {
    /// A tailnet client retries under a new command number (and reads the revision again, as a client composing a new step
    /// does), so the retry is a new command and applies again.
    FreshIdOnRetry,
    /// A tailnet client that composed its step against an older revision names the current one instead, so the step the contract
    /// says is stale applies on top of what another controller did.
    StaleRevisionRefreshed,
}

/// What the volume steps of a campaign did, as receipts. The states are read from the session; the expectations come from the
/// model, and a difference is a campaign error, not a field here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeReport {
    pub steps_run: u64,
    /// Every delivery, the original and its retries.
    pub sends: u64,
    /// Legacy deliveries, each of which applied (a plain-SOAP retry is a new command).
    pub legacy_applied: u64,
    /// Tailnet deliveries that applied: at most once per command number.
    pub tailnet_applied: u64,
    /// Tailnet deliveries answered from the ledger with no effect, applied or refused.
    pub ledger_replays: u64,
    /// Tailnet deliveries refused for composing against an older revision, the first of each.
    pub stale_refused: u64,
    /// Absolute sets of a reference run.
    pub direct_sets: u64,
    /// Failed answers, by UPnP error code.
    pub faults: BTreeMap<String, u64>,
    pub start_revision: u64,
    pub end_revision: u64,
    pub start_member_volume: u8,
    pub end_member_volume: u8,
    pub start_group_volume: u8,
    pub end_group_volume: u8,
}

/// What the end of a campaign asked of the real endpoint, as receipts ([`exercise_group_volume_set`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSetReport {
    /// The group volume the set asked for.
    pub volume: u8,
    /// Requests the endpoint applied: the set and its plain-SOAP repeat.
    pub applied: u64,
    /// Requests it refused (a volume outside 0..=100, UPnP 402), with no effect.
    pub refused: u64,
    pub start_revision: u64,
    pub end_revision: u64,
}

// ---- the keys ------------------------------------------------------------------------------------------------------

struct KeyEntry {
    generation: Generation,
    value: SecretValue,
}

/// A volatile secret store for the harness. `franken-control`'s own in-memory store is `cfg(test)` and cannot be reached from
/// another crate. Nothing is written anywhere; a value is wiped when it is dropped (`SecretValue`).
struct HarnessKeys {
    entries: BTreeMap<SecretHandle, KeyEntry>,
    capacity: usize,
}

impl HarnessKeys {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity: 8,
        }
    }
}

/// Shows how many entries exist and nothing about them.
impl fmt::Debug for HarnessKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HarnessKeys")
            .field("entries", &self.entries.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl SecretStore for HarnessKeys {
    fn insert(
        &mut self,
        handle: &SecretHandle,
        value: SecretValue,
    ) -> Result<Generation, SecretError> {
        if self.entries.contains_key(handle) {
            return Err(SecretError::AlreadyExists {
                handle: handle.clone(),
            });
        }
        if self.entries.len() >= self.capacity {
            return Err(SecretError::StoreFull { max: self.capacity });
        }
        self.entries.insert(
            handle.clone(),
            KeyEntry {
                generation: Generation::FIRST,
                value,
            },
        );
        Ok(Generation::FIRST)
    }

    fn replace(
        &mut self,
        handle: &SecretHandle,
        value: SecretValue,
        expected: Generation,
    ) -> Result<Generation, SecretError> {
        let entry = self
            .entries
            .get_mut(handle)
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })?;
        if entry.generation != expected {
            return Err(SecretError::StaleGeneration {
                handle: handle.clone(),
                expected: expected.get(),
                actual: entry.generation.get(),
            });
        }
        let next =
            entry
                .generation
                .successor()
                .ok_or_else(|| SecretError::GenerationExhausted {
                    handle: handle.clone(),
                })?;
        // The old value is dropped here, which wipes it.
        entry.value = value;
        entry.generation = next;
        Ok(next)
    }

    fn remove(&mut self, handle: &SecretHandle) -> Result<(), SecretError> {
        self.entries
            .remove(handle)
            .map(|_| ())
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })
    }

    fn generation(&self, handle: &SecretHandle) -> Result<Generation, SecretError> {
        self.entries
            .get(handle)
            .map(|entry| entry.generation)
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })
    }

    fn with_secret<R>(
        &self,
        handle: &SecretHandle,
        f: impl FnOnce(Generation, &[u8]) -> R,
    ) -> Result<R, SecretError> {
        let entry = self
            .entries
            .get(handle)
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })?;
        Ok(f(entry.generation, entry.value.expose()))
    }

    fn list(&self) -> Vec<SecretMeta> {
        self.entries
            .iter()
            .map(|(handle, entry)| SecretMeta {
                handle: handle.clone(),
                generation: entry.generation,
                byte_len: entry.value.byte_len(),
            })
            .collect()
    }
}

// ---- the plane: the real endpoint and channel -------------------------------------------------------------------------

/// What one delivery was answered: the HTTP status, the volume the response reports, and the UPnP error code if it is a fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sent {
    pub(crate) status: u16,
    pub(crate) new_volume: Option<u8>,
    pub(crate) fault_code: Option<u16>,
}

impl Sent {
    fn applied(new_volume: u8) -> Self {
        Self {
            status: 200,
            new_volume: Some(new_volume),
            fault_code: None,
        }
    }

    fn refused_as_stale() -> Self {
        Self {
            status: 500,
            new_volume: None,
            fault_code: Some(UPNP_ACTION_FAILED),
        }
    }
}

/// The text of the first `<name>...</name>` in `body`.
fn tag<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find('<')? + start;
    Some(&body[start..end])
}

fn sent_of(handled: &Handled) -> Sent {
    let body = handled.response.body.as_str();
    Sent {
        status: handled.response.status,
        new_volume: tag(body, "NewVolume").and_then(|text| text.parse().ok()),
        fault_code: tag(body, "errorCode").and_then(|text| text.parse().ok()),
    }
}

pub(crate) fn envelope(service: Service, action: &str, args: &[(&str, &str)]) -> String {
    let args: String = args
        .iter()
        .map(|(name, value)| format!("<{name}>{value}</{name}>"))
        .collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope \
         xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
         <u:{action} xmlns:u=\"{}\">{args}</u:{action}></s:Body></s:Envelope>",
        service.urn()
    )
}

/// The service, action and arguments of a relative step on `target`.
fn soap_call(
    target: Target,
    delta_text: &str,
) -> (Service, &'static str, Vec<(&'static str, &str)>) {
    match target {
        Target::Member => (
            Service::RenderingControl,
            "SetRelativeVolume",
            vec![
                ("InstanceID", "0"),
                ("Channel", "Master"),
                ("Adjustment", delta_text),
            ],
        ),
        Target::Group => (
            Service::GroupRenderingControl,
            "SetRelativeGroupVolume",
            vec![("InstanceID", "0"), ("Adjustment", delta_text)],
        ),
    }
}

/// One tailnet request: the key its proof is made under, its command number, the revision it names, and what it asks for.
#[derive(Debug, Clone, Copy)]
struct TailnetRequest<'a> {
    key: &'a [u8],
    seq: u64,
    revision: u64,
    target: Target,
    delta: i8,
}

/// How the plane's channel is stepped. [`ControlPlane::new`] is the campaign fixture and is volatile on purpose, and says so by
/// naming the development stepper; [`ControlPlane::new_durable`] boots a journal and holds the stepper that stores into it.
enum PlaneStepper {
    Volatile(DevelopmentVolatile),
    // Built by `new_durable`, which the campaign does not call (it is the volatile fixture) and the tests do.
    // This retained box allocates size_of::<OwnedDurable<RamMedium>>() during initialization, in addition to
    // the temporary Booted::Durable box. Both may coexist until its fields move and the temporary is freed;
    // neither allocation is inside a measured channel step/datagram window. Nested journal allocations are separate.
    #[cfg_attr(not(test), allow(dead_code))]
    Durable(Box<OwnedDurable<RamMedium>>),
    // Built by `new_durable_file`, which the process-restart driver (`control_restart`, harness builds) calls. The medium is a regular
    // file, so what this stepper stores survives the process; the journal and the boot are the same as for `Durable`.
    #[cfg(unix)]
    #[cfg_attr(not(feature = "harness"), allow(dead_code))]
    DurableFile(Box<OwnedDurable<FileMedium>>),
    // Built by `new_durable_faulting`: the same file medium behind a wrapper that can fail one chosen storage call, so a process test
    // can make the commit of a chosen step fail on a real file.
    #[cfg(unix)]
    #[cfg_attr(not(feature = "harness"), allow(dead_code))]
    DurableFaulting(Box<OwnedDurable<FaultingMedium<FileMedium>>>),
}

/// The real endpoint, channel and peer directory, and the two identities that reach them.
pub(crate) struct ControlPlane {
    endpoint: Endpoint,
    channel: ControlChannel<PeerDirectory<HarnessKeys>>,
    stepper: PlaneStepper,
    member_id: String,
    tailnet_peer: PeerId,
    tailnet_key: Vec<u8>,
    next_tailnet_seq: u64,
}

impl ControlPlane {
    /// An endpoint for `member_id` over `session`: the legacy bridge and one tailnet controller admitted as controllers bound to the
    /// session's epoch, and the group lease installed as the session's own check judges it.
    pub(crate) fn new(
        session: &UnifiedGroupSession,
        member_id: &str,
        now_ns: u64,
    ) -> Result<Self, String> {
        let epoch = session.current_epoch;
        let bridge_peer = PeerId::parse(BRIDGE_PEER).map_err(|e| format!("bridge peer id: {e}"))?;
        let tailnet_peer =
            PeerId::parse(TAILNET_PEER).map_err(|e| format!("tailnet peer id: {e}"))?;
        let mut peers = PeerDirectory::with_store(HarnessKeys::new());
        for peer in [&bridge_peer, &tailnet_peer] {
            peers
                .admit(
                    peer,
                    PeerRole::Controller,
                    &fixture_key(peer.as_str()),
                    Some(epoch),
                    1,
                )
                .map_err(|e| format!("admitting {peer}: {e:?}"))?;
        }
        // Roomy limits: this is not a rate-limit test (N02 has its own), and a plan sends a dozen requests within a second.
        let limit = RateLimit::new(100_000, 1_000_000).map_err(|e| format!("rate limit: {e}"))?;
        let mut config = ChannelConfig::provisional();
        config.ordinary_rate = limit;
        config.priority_rate = limit;
        config.ordinary_capacity = 64;
        config.ledger_capacity = 128;
        let mut channel =
            ControlChannel::new(peers, config).map_err(|e| format!("control channel: {e}"))?;
        channel
            .install_lease(session, AuthorityToken::issue(session, u64::MAX), now_ns)
            .map_err(|e| format!("group lease: {e}"))?;
        let bridge = LegacyBridge::new(bridge_peer, fixture_key(BRIDGE_PEER));
        let endpoint = Endpoint::new(
            EndpointConfig::provisional(member_id),
            bridge,
            SUBSCRIPTION_NONCE,
            1,
        )
        .map_err(|e| format!("endpoint: {e}"))?;
        // The campaign fixture has no journal and fixture keys: it steps with the plain, volatile development step on purpose,
        // and says so here.
        Ok(Self {
            endpoint,
            channel,
            stepper: PlaneStepper::Volatile(DevelopmentVolatile),
            member_id: member_id.to_string(),
            tailnet_peer,
            tailnet_key: fixture_key(TAILNET_PEER),
            next_tailnet_seq: 1,
        })
    }

    /// [`ControlPlane::new`], but durable: the journal on `medium` is opened and the channel is given the revision mark and
    /// the relative-command floors it holds ([`boot_durable`], before the channel's first step), and every step from then on
    /// is made durable before it is reported ([`OwnedDurable`]). Returns what was restored, for the caller's log. The medium
    /// is RAM: no file-backed or flash-backed storage exists in this tree, and the prototype's restart is a plane built over
    /// the same medium ([`ControlPlane::into_medium`]).
    ///
    /// # Errors
    /// If the plane cannot be built, the channel has already stepped, or the medium cannot be opened (a plane that is latched
    /// failed from its first step is not a plane this harness can run).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new_durable(
        session: &UnifiedGroupSession,
        member_id: &str,
        now_ns: u64,
        medium: RamMedium,
    ) -> Result<(Self, Restored, RestoredFloors), String> {
        let mut plane = Self::new(session, member_id, now_ns)?;
        match boot_durable(&mut plane.channel, medium, Limits::standard())
            .map_err(|e| format!("durable boot: {e}"))?
        {
            Booted::Durable(boot) => {
                plane.stepper = PlaneStepper::Durable(Box::new(boot.stepper));
                Ok((plane, boot.mark, boot.floors))
            }
            Booted::Latched { code, .. } => Err(format!(
                "durable boot: the medium could not be opened ({code})"
            )),
        }
    }

    /// [`ControlPlane::new_durable`], over a regular file ([`FileMedium`]) instead of RAM: the same boot ([`boot_durable`], before the
    /// channel's first step), the same stepper, so a plane built over the same file in ANOTHER PROCESS is given the revision mark and
    /// the relative-command floors this one stored. Returns what was restored, for the caller's log. The session (G01) is not stored
    /// anywhere: the caller rebuilds it.
    ///
    /// # Errors
    /// If the plane cannot be built, the channel has already stepped, or the file's journal cannot be opened (a plane that is
    /// latched failed from its first step is not a plane this harness can run).
    #[cfg(unix)]
    #[cfg_attr(not(feature = "harness"), allow(dead_code))]
    pub(crate) fn new_durable_file(
        session: &UnifiedGroupSession,
        member_id: &str,
        now_ns: u64,
        medium: FileMedium,
    ) -> Result<(Self, Restored, RestoredFloors), String> {
        let mut plane = Self::new(session, member_id, now_ns)?;
        match boot_durable(&mut plane.channel, medium, Limits::standard())
            .map_err(|e| format!("durable boot: {e}"))?
        {
            Booted::Durable(boot) => {
                plane.stepper = PlaneStepper::DurableFile(Box::new(boot.stepper));
                Ok((plane, boot.mark, boot.floors))
            }
            Booted::Latched { code, .. } => Err(format!(
                "durable boot: the medium could not be opened ({code})"
            )),
        }
    }

    /// [`ControlPlane::new_durable_file`] over a [`FaultingMedium`] (a plan of `None` makes it the plain file medium), and with the
    /// device's panel admitted as a LOCAL-USER peer so a test can send the one kind of command that still applies to the live session
    /// when the store has failed (a mute-on). The caller arms the medium after this returns, so the journal's own writes while it opens
    /// are not counted.
    ///
    /// # Errors
    /// As [`ControlPlane::new_durable_file`], and if the panel cannot be admitted.
    #[cfg(unix)]
    #[cfg_attr(not(feature = "harness"), allow(dead_code))]
    pub(crate) fn new_durable_faulting(
        session: &UnifiedGroupSession,
        member_id: &str,
        now_ns: u64,
        medium: FaultingMedium<FileMedium>,
    ) -> Result<(Self, Restored, RestoredFloors), String> {
        let mut plane = Self::new(session, member_id, now_ns)?;
        let panel = PeerId::parse(PANEL_PEER).map_err(|e| format!("panel peer id: {e}"))?;
        plane
            .channel
            .authority_mut()
            .admit(
                &panel,
                PeerRole::LocalUser,
                &fixture_key(PANEL_PEER),
                None,
                1,
            )
            .map_err(|e| format!("admitting {panel}: {e:?}"))?;
        match boot_durable(&mut plane.channel, medium, Limits::standard())
            .map_err(|e| format!("durable boot: {e}"))?
        {
            Booted::Durable(boot) => {
                plane.stepper = PlaneStepper::DurableFaulting(Box::new(boot.stepper));
                Ok((plane, boot.mark, boot.floors))
            }
            Booted::Latched { code, .. } => Err(format!(
                "durable boot: the medium could not be opened ({code})"
            )),
        }
    }

    /// The device's panel (a LOCAL-USER peer admitted by [`ControlPlane::new_durable_faulting`]) asks for the member to be muted or
    /// unmuted, signed with its fixture key on the tailnet route, as the endpoint's own tests send it. A local user's mute-on is the
    /// one change that still applies to the live session when the store has failed.
    ///
    /// # Errors
    /// If the request cannot be built.
    #[cfg(unix)]
    #[cfg_attr(not(feature = "harness"), allow(dead_code))]
    pub(crate) fn send_panel_mute(
        &mut self,
        session: &mut UnifiedGroupSession,
        now_ns: u64,
        seq: u64,
        muted: bool,
    ) -> Result<Sent, String> {
        let panel = PeerId::parse(PANEL_PEER).map_err(|e| format!("panel peer id: {e}"))?;
        let command = ControlCommand::SetMemberMute {
            member_id: self.member_id.clone(),
            muted,
        };
        let epoch = session.current_epoch;
        let signed = RequestBody::new(panel, seq, epoch, None, command)
            .map_err(|e| format!("panel request body: {e:?}"))?;
        let proof = compute_proof(&fixture_key(PANEL_PEER), &signed.signing_bytes());
        let proof_hex: String = proof
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let desired = if muted { "1" } else { "0" };
        let args = [
            ("InstanceID", "0"),
            ("Channel", "Master"),
            ("DesiredMute", desired),
        ];
        let service = Service::RenderingControl;
        let body = envelope(service, "SetMute", &args);
        let soap_action = format!("\"{}#SetMute\"", service.urn());
        let seq_text = seq.to_string();
        let epoch_text = epoch.to_string();
        let headers = [
            ("SOAPACTION", soap_action.as_str()),
            ("X-Franken-Peer", PANEL_PEER),
            ("X-Franken-Seq", seq_text.as_str()),
            ("X-Franken-Epoch", epoch_text.as_str()),
            ("X-Franken-Proof", proof_hex.as_str()),
        ];
        Ok(self.dispatch(session, now_ns, Ingress::Tailnet, service, &headers, &body))
    }

    /// Whether the channel has latched its durability failed: a store failed or the journal is poisoned, so only the local user's
    /// stop and mute-on still work and every other command is refused.
    #[cfg(unix)]
    #[cfg_attr(not(feature = "harness"), allow(dead_code))]
    pub(crate) fn durability_failed(&self) -> bool {
        matches!(
            self.channel.durability(),
            franken_control::channel::pipeline::Durability::Failed { .. }
        )
    }

    /// The medium a durable plane stores into, given back when the plane is dropped: what a restart is built over. `None` for
    /// the volatile fixture, which stores nothing, and for a plane over a file (its restart is a new process opening the file).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn into_medium(self) -> Option<RamMedium> {
        match self.stepper {
            PlaneStepper::Durable(stepper) => Some(stepper.into_journal().into_storage()),
            PlaneStepper::Volatile(_) => None,
            #[cfg(unix)]
            PlaneStepper::DurableFile(_) | PlaneStepper::DurableFaulting(_) => None,
        }
    }

    /// The next command number the tailnet controller has not used.
    pub(crate) fn tailnet_seq(&mut self) -> u64 {
        let seq = self.next_tailnet_seq;
        self.next_tailnet_seq += 1;
        seq
    }

    /// The endpoint's directory: what the topology answer reads that the group session does not hold (where a member's device
    /// description lives, and its room name). A transport that serves a description fills it for the member it serves.
    pub(crate) fn directory_mut(&mut self) -> &mut franken_control::fsonos::Directory {
        self.endpoint.directory_mut()
    }

    /// One request exactly as a transport read it, handled by the real endpoint over this plane's channel and stepper, and the
    /// endpoint's answer unchanged. [`Self::dispatch`] builds the harness's own requests and keeps a summary of the answer; a
    /// socket transport ([`crate::fsonos_loopback`]) hands in what it read from the wire and writes the whole answer back.
    pub(crate) fn handle_request(
        &mut self,
        session: &mut UnifiedGroupSession,
        now_ns: u64,
        request: &HttpRequest<'_>,
    ) -> Handled {
        match &mut self.stepper {
            PlaneStepper::Volatile(stepper) => {
                let mut ctx = Context {
                    channel: &mut self.channel,
                    session,
                    stepper,
                    now_ns,
                };
                self.endpoint.handle(&mut ctx, request)
            }
            PlaneStepper::Durable(stepper) => {
                let mut ctx = Context {
                    channel: &mut self.channel,
                    session,
                    stepper: &mut **stepper,
                    now_ns,
                };
                self.endpoint.handle(&mut ctx, request)
            }
            #[cfg(unix)]
            PlaneStepper::DurableFile(stepper) => {
                let mut ctx = Context {
                    channel: &mut self.channel,
                    session,
                    stepper: &mut **stepper,
                    now_ns,
                };
                self.endpoint.handle(&mut ctx, request)
            }
            #[cfg(unix)]
            PlaneStepper::DurableFaulting(stepper) => {
                let mut ctx = Context {
                    channel: &mut self.channel,
                    session,
                    stepper: &mut **stepper,
                    now_ns,
                };
                self.endpoint.handle(&mut ctx, request)
            }
        }
    }

    fn dispatch(
        &mut self,
        session: &mut UnifiedGroupSession,
        now_ns: u64,
        ingress: Ingress,
        service: Service,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Sent {
        let request = HttpRequest {
            method: "POST",
            path: service.control_path(),
            peer_ip: LAN_PEER_IP,
            ingress,
            headers,
            body: body.as_bytes(),
        };
        let handled = self.handle_request(session, now_ns, &request);
        sent_of(&handled)
    }

    /// A relative step over plain SOAP on the local link. It carries no command id, so a second send is a second step.
    pub(crate) fn send_legacy(
        &mut self,
        session: &mut UnifiedGroupSession,
        now_ns: u64,
        target: Target,
        delta: i8,
    ) -> Sent {
        let delta_text = delta.to_string();
        let (service, action, args) = soap_call(target, &delta_text);
        let body = envelope(service, action, &args);
        let soap_action = format!("\"{}#{action}\"", service.urn());
        let headers = [("SOAPACTION", soap_action.as_str())];
        self.dispatch(
            session,
            now_ns,
            Ingress::LocalLegacy,
            service,
            &headers,
            &body,
        )
    }

    /// An ABSOLUTE group volume over plain SOAP on the local link (`SetGroupVolume`). It carries no command id either, so a repeat is a
    /// second command, but an absolute set is safe to repeat: the volume ends where it did (`g03.md` section 3.1).
    pub(crate) fn send_legacy_group_set(
        &mut self,
        session: &mut UnifiedGroupSession,
        now_ns: u64,
        volume: u8,
    ) -> Sent {
        let volume_text = volume.to_string();
        let service = Service::GroupRenderingControl;
        let action = "SetGroupVolume";
        let args = [("InstanceID", "0"), ("DesiredVolume", volume_text.as_str())];
        let body = envelope(service, action, &args);
        let soap_action = format!("\"{}#{action}\"", service.urn());
        let headers = [("SOAPACTION", soap_action.as_str())];
        self.dispatch(
            session,
            now_ns,
            Ingress::LocalLegacy,
            service,
            &headers,
            &body,
        )
    }

    /// A relative step over the tailnet, signed with the controller's key: `seq` is its command number and `revision` the revision
    /// it was computed against.
    pub(crate) fn send_tailnet(
        &mut self,
        session: &mut UnifiedGroupSession,
        now_ns: u64,
        seq: u64,
        revision: u64,
        target: Target,
        delta: i8,
    ) -> Result<Sent, String> {
        let key = self.tailnet_key.clone();
        let request = TailnetRequest {
            key: &key,
            seq,
            revision,
            target,
            delta,
        };
        self.send_tailnet_signed(session, now_ns, &request)
    }

    /// [`ControlPlane::send_tailnet`] with the key the proof is made under named, so a test can sign with one that is not admitted.
    fn send_tailnet_signed(
        &mut self,
        session: &mut UnifiedGroupSession,
        now_ns: u64,
        request: &TailnetRequest<'_>,
    ) -> Result<Sent, String> {
        let TailnetRequest {
            key,
            seq,
            revision,
            target,
            delta,
        } = *request;
        let command = match target {
            Target::Member => ControlCommand::AdjustMemberVolume {
                member_id: self.member_id.clone(),
                delta,
            },
            Target::Group => ControlCommand::AdjustGroupVolume { delta },
        };
        let epoch = session.current_epoch;
        let body_of_request = RequestBody::new(
            self.tailnet_peer.clone(),
            seq,
            epoch,
            Some(revision),
            command,
        )
        .map_err(|e| format!("tailnet request body: {e:?}"))?;
        let proof = compute_proof(key, &body_of_request.signing_bytes());
        let proof_hex: String = proof
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let delta_text = delta.to_string();
        let (service, action, args) = soap_call(target, &delta_text);
        let body = envelope(service, action, &args);
        let soap_action = format!("\"{}#{action}\"", service.urn());
        let peer_text = self.tailnet_peer.as_str().to_string();
        let seq_text = seq.to_string();
        let epoch_text = epoch.to_string();
        let revision_text = revision.to_string();
        let headers = [
            ("SOAPACTION", soap_action.as_str()),
            ("X-Franken-Peer", peer_text.as_str()),
            ("X-Franken-Seq", seq_text.as_str()),
            ("X-Franken-Epoch", epoch_text.as_str()),
            ("X-Franken-Revision", revision_text.as_str()),
            ("X-Franken-Proof", proof_hex.as_str()),
        ];
        Ok(self.dispatch(session, now_ns, Ingress::Tailnet, service, &headers, &body))
    }
}

// ---- the end of a campaign: an absolute group volume through the real endpoint ---------------------------------------------

/// The step every campaign ends with, in place of the superseded `handle_fsonos_soap` call: over the real endpoint and channel, a
/// local legacy SOAP request sets the group volume to `volume`; it must apply (HTTP 200, the volume set, the revision moved by one);
/// a plain-SOAP repeat of the same absolute set must leave the volume where it was and move the revision again (it is a new command
/// and an absolute set is safe to repeat, `g03.md` section 3.1); and a volume outside 0..=100 must be refused with UPnP 402 and change
/// nothing (the group volume, the revision and every member's volume stay). Any other answer fails the campaign by name.
pub(crate) fn exercise_group_volume_set(
    session: &mut UnifiedGroupSession,
    member_id: &str,
    now_ns: u64,
    volume: u8,
) -> Result<GroupSetReport, String> {
    let mut plane = ControlPlane::new(session, member_id, now_ns)?;
    let start_revision = session.state_revision;
    let members_before: Vec<(String, u8)> = session
        .members
        .iter()
        .map(|(id, state)| (id.clone(), state.volume_0_to_100))
        .collect();
    let applied = Sent {
        status: 200,
        new_volume: None,
        fault_code: None,
    };
    for send in 0..2_u64 {
        let sent = plane.send_legacy_group_set(session, now_ns, volume);
        if sent != applied {
            return Err(format!(
                "group_set_response_mismatch: send {send}: the contract says {applied:?}, the endpoint answered {sent:?}"
            ));
        }
        let wanted = (volume, start_revision + send + 1);
        let seen = (session.group_master_volume, session.state_revision);
        if seen != wanted {
            return Err(format!(
                "group_set_state_mismatch: send {send}: the session has (group volume, revision) {seen:?}, the contract says {wanted:?}"
            ));
        }
    }
    let refusal = Sent {
        status: 500,
        new_volume: None,
        fault_code: Some(UPNP_INVALID_ARGS),
    };
    let sent = plane.send_legacy_group_set(session, now_ns, OUT_OF_RANGE_VOLUME);
    if sent != refusal {
        return Err(format!(
            "group_set_refusal_mismatch: the contract says {refusal:?}, the endpoint answered {sent:?}"
        ));
    }
    let members_after: Vec<(String, u8)> = session
        .members
        .iter()
        .map(|(id, state)| (id.clone(), state.volume_0_to_100))
        .collect();
    let seen = (
        session.group_master_volume,
        session.state_revision,
        members_after,
    );
    let wanted = (volume, start_revision + 2, members_before);
    if seen != wanted {
        return Err(format!(
            "group_set_state_mismatch: the refused request changed the group: {seen:?}, the contract says {wanted:?}"
        ));
    }
    Ok(GroupSetReport {
        volume,
        applied: 2,
        refused: 1,
        start_revision,
        end_revision: session.state_revision,
    })
}

// ---- the model: what the contract says each delivery does -------------------------------------------------------------

/// What a delivery did, by the contract's rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    LegacyApplied,
    TailnetApplied,
    /// Answered from the ledger with no effect: the command was applied or refused before.
    Replayed,
    /// A tailnet step composed against an older revision, refused with no effect, and remembered as refused.
    StaleRefused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Remembered {
    Applied(Target),
    Refused,
}

/// The volume after a relative step: the contract's own clamp to 0..=100.
fn stepped(current: u8, delta: i8) -> u8 {
    let moved = i16::from(current) + i16::from(delta);
    u8::try_from(moved.clamp(0, 100)).unwrap_or(100)
}

/// The contract's expectation of the group, from `g03.md` 3.1 and 9.1 and `n02.md`. It starts from the state it is shown and
/// predicts every change after that.
struct VolumeModel {
    member: u8,
    group: u8,
    revision: u64,
    ledger: BTreeMap<u64, Remembered>,
}

impl VolumeModel {
    fn volume(&self, target: Target) -> u8 {
        match target {
            Target::Member => self.member,
            Target::Group => self.group,
        }
    }

    /// An applied volume command: the volume moves, the revision moves by one even when the clamp leaves the volume as it was.
    fn apply(&mut self, target: Target, delta: i8) -> u8 {
        let slot = match target {
            Target::Member => &mut self.member,
            Target::Group => &mut self.group,
        };
        *slot = stepped(*slot, delta);
        self.revision += 1;
        *slot
    }

    /// A plain-SOAP step: composed by the endpoint at the current revision, so it always applies.
    fn legacy(&mut self, target: Target, delta: i8) -> (Sent, Effect) {
        let volume = self.apply(target, delta);
        (Sent::applied(volume), Effect::LegacyApplied)
    }

    /// A tailnet step named `seq`, composed against revision `named`. A number the ledger remembers is answered with what it
    /// remembers, and the response reports the volume as it is *now* (the endpoint builds it from the session after the call). A
    /// number it does not remember applies iff it names the exact current revision; either way the outcome is remembered.
    fn tailnet(&mut self, seq: u64, named: u64, target: Target, delta: i8) -> (Sent, Effect) {
        match self.ledger.get(&seq).copied() {
            Some(Remembered::Applied(first)) => {
                (Sent::applied(self.volume(first)), Effect::Replayed)
            }
            Some(Remembered::Refused) => (Sent::refused_as_stale(), Effect::Replayed),
            None if named == self.revision => {
                let volume = self.apply(target, delta);
                self.ledger.insert(seq, Remembered::Applied(target));
                (Sent::applied(volume), Effect::TailnetApplied)
            }
            None => {
                self.ledger.insert(seq, Remembered::Refused);
                (Sent::refused_as_stale(), Effect::StaleRefused)
            }
        }
    }

    /// The reference: an absolute set, which the session applies as one command.
    fn set(&mut self, target: Target, volume: u8) {
        match target {
            Target::Member => self.member = volume,
            Target::Group => self.group = volume,
        }
        self.revision += 1;
    }
}

// ---- the desk: the plan, the plane and the model ----------------------------------------------------------------------

/// The volume side of a campaign: the plane, the model, the plan and the report.
pub(crate) struct VolumeDesk {
    plane: ControlPlane,
    model: VolumeModel,
    plan: &'static [VolumeStep],
    next: usize,
    /// The session's revision just before each step that has run, for [`Observed::BeforeStep`].
    before: Vec<u64>,
    defect: Option<VolumeDefect>,
    direct_seq: u64,
    member_id: String,
    report: VolumeReport,
}

fn validate(plan: &[VolumeStep], total_blocks: u64) -> Result<(), String> {
    let mut previous = 0;
    for (index, step) in plan.iter().enumerate() {
        if !(previous..total_blocks).contains(&step.block) {
            return Err(format!(
                "volume_plan_invalid: step {index} is at block {}, which is not in {previous}..{total_blocks}",
                step.block
            ));
        }
        previous = step.block;
        match step.action {
            VolumeAction::Relative(relative) => {
                if relative.sends == 0 {
                    return Err(format!("volume_plan_invalid: step {index} sends nothing"));
                }
                if relative.delta == 0 || relative.delta.unsigned_abs() > 100 {
                    return Err(format!(
                        "volume_plan_invalid: step {index} has delta {}, outside -100..=100 and not zero",
                        relative.delta
                    ));
                }
                if let Observed::BeforeStep(before) = relative.observed
                    && (relative.route == Route::LocalLegacy || before >= index)
                {
                    return Err(format!(
                        "volume_plan_invalid: step {index} names the revision before step {before}, which is not an earlier step of a tailnet step"
                    ));
                }
            }
            VolumeAction::Set { volume, .. } => {
                if volume > 100 {
                    return Err(format!(
                        "volume_plan_invalid: step {index} sets volume {volume}"
                    ));
                }
            }
        }
    }
    Ok(())
}

impl VolumeDesk {
    /// The desk starts from the state it is shown, so what it predicts is every change after that.
    pub(crate) fn start(
        session: &UnifiedGroupSession,
        member_id: &str,
        plan: &'static [VolumeStep],
        total_blocks: u64,
        now_ns: u64,
        defect: Option<VolumeDefect>,
    ) -> Result<Self, String> {
        validate(plan, total_blocks)?;
        let member = session
            .members
            .get(member_id)
            .map(|state| state.volume_0_to_100)
            .ok_or_else(|| format!("volume_plan_invalid: {member_id} is not in the group"))?;
        let plane = ControlPlane::new(session, member_id, now_ns)?;
        Ok(Self {
            plane,
            model: VolumeModel {
                member,
                group: session.group_master_volume,
                revision: session.state_revision,
                ledger: BTreeMap::new(),
            },
            plan,
            next: 0,
            before: Vec::new(),
            defect,
            direct_seq: DIRECT_SEQ_BASE,
            member_id: member_id.to_string(),
            report: VolumeReport {
                start_revision: session.state_revision,
                end_revision: session.state_revision,
                start_member_volume: member,
                end_member_volume: member,
                start_group_volume: session.group_master_volume,
                end_group_volume: session.group_master_volume,
                ..VolumeReport::default()
            },
        })
    }

    /// Run every step planned for the start of render iteration `blk`, in plan order.
    pub(crate) fn run_block(
        &mut self,
        blk: u64,
        now_ns: u64,
        session: &mut UnifiedGroupSession,
    ) -> Result<(), String> {
        while let Some(step) = self.plan.get(self.next).copied() {
            if step.block != blk {
                break;
            }
            let index = self.next;
            self.next += 1;
            self.before.push(session.state_revision);
            match step.action {
                VolumeAction::Relative(relative) => {
                    self.run_relative(index, relative, now_ns, session)?;
                }
                VolumeAction::Set { target, volume } => {
                    self.run_set(index, target, volume, session)?;
                }
            }
            self.report.steps_run += 1;
        }
        Ok(())
    }

    fn run_relative(
        &mut self,
        index: usize,
        step: RelativeStep,
        now_ns: u64,
        session: &mut UnifiedGroupSession,
    ) -> Result<(), String> {
        // The command number and the revision the step is *intended* to carry. A legacy step has no number.
        let tailnet_seq = match step.route {
            Route::Tailnet => Some(self.plane.tailnet_seq()),
            Route::LocalLegacy => None,
        };
        let named = match step.observed {
            Observed::Now => session.state_revision,
            Observed::BeforeStep(before) => *self.before.get(before).ok_or_else(|| {
                format!("volume_plan_invalid: step {index} names step {before}, which has not run")
            })?,
        };
        for send in 0..step.sends {
            let (expected, effect) = match tailnet_seq {
                None => self.model.legacy(step.target, step.delta),
                Some(seq) => self.model.tailnet(seq, named, step.target, step.delta),
            };
            let sent = match tailnet_seq {
                None => self
                    .plane
                    .send_legacy(session, now_ns, step.target, step.delta),
                Some(seq) => {
                    // A planted client defect changes what is sent, never what the model expects. A client that retries as a new
                    // command takes a new number and, composing the step afresh, reads the revision again.
                    let fresh_retry = send > 0 && self.defect == Some(VolumeDefect::FreshIdOnRetry);
                    let seq_sent = if fresh_retry {
                        self.plane.tailnet_seq()
                    } else {
                        seq
                    };
                    let refreshed = fresh_retry
                        || (matches!(step.observed, Observed::BeforeStep(_))
                            && self.defect == Some(VolumeDefect::StaleRevisionRefreshed));
                    let named_sent = if refreshed {
                        session.state_revision
                    } else {
                        named
                    };
                    self.plane.send_tailnet(
                        session,
                        now_ns,
                        seq_sent,
                        named_sent,
                        step.target,
                        step.delta,
                    )?
                }
            };
            if sent != expected {
                return Err(format!(
                    "volume_response_mismatch: step {index} send {send}: the contract says {expected:?}, the endpoint answered {sent:?}"
                ));
            }
            self.check_state(&format!("step {index} send {send}"), session)?;
            self.report.sends += 1;
            match effect {
                Effect::LegacyApplied => self.report.legacy_applied += 1,
                Effect::TailnetApplied => self.report.tailnet_applied += 1,
                Effect::Replayed => self.report.ledger_replays += 1,
                Effect::StaleRefused => self.report.stale_refused += 1,
            }
            if let Some(code) = sent.fault_code {
                *self.report.faults.entry(code.to_string()).or_default() += 1;
            }
        }
        Ok(())
    }

    fn run_set(
        &mut self,
        index: usize,
        target: Target,
        volume: u8,
        session: &mut UnifiedGroupSession,
    ) -> Result<(), String> {
        let payload = match target {
            Target::Member => GroupCommandPayload::SetMemberVolume {
                member_id: self.member_id.clone(),
                volume_0_to_100: volume,
            },
            Target::Group => GroupCommandPayload::SetGroupVolume {
                volume_0_to_100: volume,
            },
        };
        session
            .apply_command(FencedControlCommand {
                epoch: session.current_epoch,
                command_seq: self.direct_seq,
                payload,
            })
            .map_err(|e| format!("volume_direct_refused: step {index}: {e}"))?;
        self.direct_seq += 1;
        self.model.set(target, volume);
        self.check_state(&format!("step {index} (direct set)"), session)?;
        self.report.direct_sets += 1;
        Ok(())
    }

    /// The session's revision, the endpoint's member volume and the group volume against the model's.
    fn check_state(&self, label: &str, session: &UnifiedGroupSession) -> Result<(), String> {
        let member = session
            .members
            .get(&self.member_id)
            .map(|state| state.volume_0_to_100);
        let seen = (session.state_revision, member, session.group_master_volume);
        let wanted = (
            self.model.revision,
            Some(self.model.member),
            self.model.group,
        );
        if seen == wanted {
            Ok(())
        } else {
            Err(format!(
                "volume_state_mismatch: {label}: the session has (revision, member volume, group volume) {seen:?}, the contract says {wanted:?}"
            ))
        }
    }

    /// The end of the run: every step ran and the session is where the model says.
    pub(crate) fn finish(&mut self, session: &UnifiedGroupSession) -> Result<VolumeReport, String> {
        if self.next != self.plan.len() {
            return Err(format!(
                "volume_plan_unfinished: {} of {} steps ran",
                self.next,
                self.plan.len()
            ));
        }
        self.check_state("end of run", session)?;
        self.report.end_revision = session.state_revision;
        self.report.end_member_volume = self.model.member;
        self.report.end_group_volume = self.model.group;
        Ok(self.report.clone())
    }
}

/// Plans the tests of this module and the campaign tests in `harness.rs` share. Expected numbers: `predict_volume.py`, which states the
/// contract's rules independently of the Rust; the volumes start at 50 (member) and 50 (group).
#[cfg(test)]
pub(crate) mod plans {
    use super::{Observed, RelativeStep, Route, Target, VolumeAction, VolumeStep};

    // The plans the tests use: two routes, retries, a stale step and a clamp, around a source change at block 100.
    // Expected numbers: `predict_volume.py` (contract rules), start 50/50.
    pub(crate) const fn relative(
        block: u64,
        route: Route,
        target: Target,
        delta: i8,
        sends: u8,
        observed: Observed,
    ) -> VolumeStep {
        VolumeStep {
            block,
            action: VolumeAction::Relative(RelativeStep {
                route,
                target,
                delta,
                sends,
                observed,
            }),
        }
    }

    pub(crate) const fn set(block: u64, target: Target, volume: u8) -> VolumeStep {
        VolumeStep {
            block,
            action: VolumeAction::Set { target, volume },
        }
    }

    pub(crate) const RACE: &[VolumeStep] = &[
        relative(90, Route::Tailnet, Target::Member, 10, 2, Observed::Now),
        relative(95, Route::LocalLegacy, Target::Member, 10, 2, Observed::Now),
        relative(
            100,
            Route::Tailnet,
            Target::Member,
            10,
            2,
            Observed::BeforeStep(1),
        ),
        relative(110, Route::Tailnet, Target::Member, 10, 3, Observed::Now),
        relative(
            120,
            Route::LocalLegacy,
            Target::Group,
            -20,
            1,
            Observed::Now,
        ),
        relative(
            130,
            Route::LocalLegacy,
            Target::Member,
            100,
            1,
            Observed::Now,
        ),
        relative(140, Route::Tailnet, Target::Member, -100, 2, Observed::Now),
        relative(150, Route::Tailnet, Target::Member, 30, 1, Observed::Now),
    ];

    pub(crate) const REFERENCE: &[VolumeStep] = &[
        set(90, Target::Member, 60),
        set(95, Target::Member, 80),
        set(110, Target::Member, 90),
        set(120, Target::Group, 30),
        set(130, Target::Member, 100),
        set(140, Target::Member, 0),
        set(150, Target::Member, 30),
    ];

    /// The reference with one volume wrong (30 where the race reaches 80 at block 95): the negative control that shows the sample
    /// digest can tell two volume trajectories apart.
    pub(crate) const WRONG_REFERENCE: &[VolumeStep] = &[
        set(90, Target::Member, 60),
        set(95, Target::Member, 30),
        set(110, Target::Member, 90),
        set(120, Target::Group, 30),
        set(130, Target::Member, 100),
        set(140, Target::Member, 0),
        set(150, Target::Member, 30),
    ];
}

#[cfg(test)]
mod tests {
    use franken_session::ChannelRole;

    use super::plans::{RACE, REFERENCE, relative, set};
    use super::*;

    const EPOCH: u64 = 1;
    const KITCHEN: &str = "kitchen";
    const NOW_NS: u64 = 1_000_000_000;

    /// Two members at the default volume 50, group volume 50.
    fn fixture_session() -> UnifiedGroupSession {
        let catalog = franken_board_profile::synthetic_test_fixture_catalog();
        let board = |model: &str| {
            catalog
                .iter()
                .find(|profile| profile.model_number == model)
                .expect("fixture model")
                .clone()
        };
        let mut session = UnifiedGroupSession::new("grp", "coord", EPOCH);
        for (seq, member, model) in [(1, KITCHEN, "S5"), (2, "den", "S12")] {
            session
                .apply_command(FencedControlCommand {
                    epoch: EPOCH,
                    command_seq: seq,
                    payload: GroupCommandPayload::AdmitMember {
                        member_id: member.to_string(),
                        board: board(model),
                        role: ChannelRole::Stereo,
                    },
                })
                .expect("a fixture member admits");
        }
        session
    }

    fn plane_and_session() -> (ControlPlane, UnifiedGroupSession) {
        let session = fixture_session();
        let plane = ControlPlane::new(&session, KITCHEN, NOW_NS).expect("plane");
        (plane, session)
    }

    fn member_volume(session: &UnifiedGroupSession) -> u8 {
        session.members[KITCHEN].volume_0_to_100
    }

    fn legacy(plane: &mut ControlPlane, session: &mut UnifiedGroupSession, delta: i8) -> Sent {
        plane.send_legacy(session, NOW_NS, Target::Member, delta)
    }

    fn tailnet(
        plane: &mut ControlPlane,
        session: &mut UnifiedGroupSession,
        seq: u64,
        revision: u64,
        delta: i8,
    ) -> Sent {
        plane
            .send_tailnet(session, NOW_NS, seq, revision, Target::Member, delta)
            .expect("the request builds")
    }

    fn blank_medium() -> RamMedium {
        RamMedium::new(Limits::standard().segment_bytes)
    }

    #[test]
    fn a_durable_plane_boots_restores_and_applies_a_tailnet_step_once_across_a_restart() {
        let mut session = fixture_session();
        let (mut plane, mark, floors) =
            ControlPlane::new_durable(&session, KITCHEN, NOW_NS, blank_medium()).expect("a plane");
        assert_eq!(
            (mark, floors),
            (Restored::FreshMedium, RestoredFloors::Nothing)
        );
        let start = session.state_revision;
        let seq = plane.tailnet_seq();
        assert_eq!(
            tailnet(&mut plane, &mut session, seq, start, 10),
            Sent::applied(60)
        );
        // The bridge's relative step is a new command each time; it applies, and it leaves no floor behind.
        assert_eq!(legacy(&mut plane, &mut session, 5), Sent::applied(65));
        let revision = session.state_revision;
        // The process restarts over the same medium (the session, the audible group, carries on).
        let medium = plane.into_medium().expect("a durable plane has a medium");
        let (mut again, mark, floors) =
            ControlPlane::new_durable(&session, KITCHEN, NOW_NS, medium).expect("a plane");
        assert_eq!(mark, Restored::Mark(revision));
        assert_eq!(floors, RestoredFloors::Table { identities: 1 });
        // The tailnet duplicate of the delivered step is unknown (801) and is not applied again.
        let unknown = tailnet(&mut again, &mut session, seq, start, 10);
        assert_eq!(unknown.new_volume, None);
        assert_eq!(unknown.fault_code, Some(801));
        assert_eq!(member_volume(&session), 65);
        // The bridge restarts at number 1 and holds no floor: its next step is a new command and applies once.
        assert_eq!(legacy(&mut again, &mut session, 5), Sent::applied(70));
        assert_eq!(member_volume(&session), 70);
    }

    #[test]
    fn the_volatile_fixture_is_volatile_and_has_no_medium() {
        let (plane, _session) = plane_and_session();
        assert!(plane.into_medium().is_none());
    }

    #[test]
    fn a_local_legacy_retry_of_a_relative_step_applies_again() {
        let (mut plane, mut session) = plane_and_session();
        let start = session.state_revision;
        assert_eq!(legacy(&mut plane, &mut session, 10), Sent::applied(60));
        // The response was lost; the controller sends the same plain SOAP request again.
        assert_eq!(legacy(&mut plane, &mut session, 10), Sent::applied(70));
        assert_eq!(member_volume(&session), 70);
        assert_eq!(session.state_revision, start + 2);
    }

    #[test]
    fn a_tailnet_retry_with_the_same_command_number_applies_once() {
        let (mut plane, mut session) = plane_and_session();
        let start = session.state_revision;
        let seq = plane.tailnet_seq();
        assert_eq!(
            tailnet(&mut plane, &mut session, seq, start, 10),
            Sent::applied(60)
        );
        assert_eq!(
            tailnet(&mut plane, &mut session, seq, start, 10),
            Sent::applied(60)
        );
        assert_eq!(
            tailnet(&mut plane, &mut session, seq, start, 10),
            Sent::applied(60)
        );
        assert_eq!(member_volume(&session), 60);
        assert_eq!(session.state_revision, start + 1);
    }

    #[test]
    fn a_tailnet_replay_reports_the_volume_as_it_is_now_not_as_it_was_committed() {
        // Another controller moved the volume between the original and its retry. The retry is answered from the ledger, so it is
        // not applied again and the other controller's change is not undone; the response is built from the session as it is.
        let (mut plane, mut session) = plane_and_session();
        let start = session.state_revision;
        let seq = plane.tailnet_seq();
        assert_eq!(
            tailnet(&mut plane, &mut session, seq, start, 10),
            Sent::applied(60)
        );
        assert_eq!(legacy(&mut plane, &mut session, 10), Sent::applied(70));
        let revision = session.state_revision;
        assert_eq!(
            tailnet(&mut plane, &mut session, seq, start, 10),
            Sent::applied(70)
        );
        assert_eq!(member_volume(&session), 70);
        assert_eq!(session.state_revision, revision);
    }

    #[test]
    fn a_tailnet_step_composed_against_an_older_revision_is_refused_and_remembered() {
        let (mut plane, mut session) = plane_and_session();
        let read = session.state_revision;
        assert_eq!(legacy(&mut plane, &mut session, 10), Sent::applied(60));
        let revision = session.state_revision;
        let seq = plane.tailnet_seq();
        assert_eq!(
            tailnet(&mut plane, &mut session, seq, read, 10),
            Sent::refused_as_stale()
        );
        // The refusal is the outcome on record: the same number is refused again, still with no effect.
        assert_eq!(
            tailnet(&mut plane, &mut session, seq, read, 10),
            Sent::refused_as_stale()
        );
        assert_eq!(member_volume(&session), 60);
        assert_eq!(session.state_revision, revision);
        // A fresh number composed against the current revision applies.
        let fresh = plane.tailnet_seq();
        assert_eq!(
            tailnet(&mut plane, &mut session, fresh, revision, 10),
            Sent::applied(70)
        );
        assert_eq!(session.state_revision, revision + 1);
    }

    #[test]
    fn a_tailnet_request_signed_with_a_key_that_is_not_admitted_changes_nothing() {
        let (mut plane, mut session) = plane_and_session();
        let start = session.state_revision;
        let seq = plane.tailnet_seq();
        let other = fixture_key("somebody-else");
        let request = TailnetRequest {
            key: &other,
            seq,
            revision: start,
            target: Target::Member,
            delta: 10,
        };
        let sent = plane
            .send_tailnet_signed(&mut session, NOW_NS, &request)
            .expect("the request builds");
        assert_eq!(
            sent,
            Sent {
                status: 401,
                new_volume: None,
                fault_code: None
            }
        );
        assert_eq!(member_volume(&session), 50);
        assert_eq!(session.state_revision, start);
        // The number was not consumed by the refused request: the properly signed one applies.
        assert_eq!(
            tailnet(&mut plane, &mut session, seq, start, 10),
            Sent::applied(60)
        );
    }

    #[test]
    fn a_relative_step_clamps_and_a_clamped_step_still_moves_the_revision() {
        let (mut plane, mut session) = plane_and_session();
        let start = session.state_revision;
        assert_eq!(legacy(&mut plane, &mut session, 100), Sent::applied(100));
        assert_eq!(legacy(&mut plane, &mut session, 100), Sent::applied(100));
        assert_eq!(session.state_revision, start + 2);
        assert_eq!(legacy(&mut plane, &mut session, -100), Sent::applied(0));
        assert_eq!(legacy(&mut plane, &mut session, -100), Sent::applied(0));
        assert_eq!(session.state_revision, start + 4);
    }

    #[test]
    fn a_group_step_moves_the_group_volume_and_not_the_member() {
        let (mut plane, mut session) = plane_and_session();
        let start = session.state_revision;
        let sent = plane.send_legacy(&mut session, NOW_NS, Target::Group, -20);
        assert_eq!(sent, Sent::applied(30));
        assert_eq!(session.group_master_volume, 30);
        assert_eq!(member_volume(&session), 50);
        let seq = plane.tailnet_seq();
        let sent = plane
            .send_tailnet(&mut session, NOW_NS, seq, start + 1, Target::Group, 5)
            .expect("the request builds");
        assert_eq!(sent, Sent::applied(35));
        assert_eq!(session.state_revision, start + 2);
    }

    const TOTAL_BLOCKS: u64 = 220;

    fn run_plan(
        plan: &'static [VolumeStep],
        defect: Option<VolumeDefect>,
    ) -> Result<VolumeReport, String> {
        let mut session = fixture_session();
        let mut desk = VolumeDesk::start(&session, KITCHEN, plan, TOTAL_BLOCKS, NOW_NS, defect)?;
        for blk in 0..TOTAL_BLOCKS {
            desk.run_block(blk, NOW_NS, &mut session)?;
        }
        desk.finish(&session)
    }

    #[test]
    fn the_race_plan_does_what_the_contract_predicts() {
        let report = run_plan(RACE, None).expect("the plan runs");
        assert_eq!(report.steps_run, 8);
        assert_eq!(report.sends, 14);
        assert_eq!(report.legacy_applied, 4);
        assert_eq!(report.tailnet_applied, 4);
        assert_eq!(report.ledger_replays, 5);
        assert_eq!(report.stale_refused, 1);
        assert_eq!(report.direct_sets, 0);
        assert_eq!(report.faults, BTreeMap::from([("501".to_string(), 2)]));
        assert_eq!(
            (report.start_member_volume, report.start_group_volume),
            (50, 50)
        );
        assert_eq!(
            (report.end_member_volume, report.end_group_volume),
            (30, 30)
        );
        assert_eq!(report.end_revision, report.start_revision + 8);
    }

    #[test]
    fn the_reference_plan_reaches_the_same_volumes_without_either_ingress() {
        let report = run_plan(REFERENCE, None).expect("the plan runs");
        assert_eq!(report.direct_sets, 7);
        assert_eq!(report.sends, 0);
        assert_eq!(
            (report.end_member_volume, report.end_group_volume),
            (30, 30)
        );
        assert_eq!(report.end_revision, report.start_revision + 7);
    }

    #[test]
    fn a_retry_sent_as_a_new_command_is_named_by_the_oracle() {
        run_plan(RACE, None).expect("the control: the same plan without the defect passes");
        // With the defect, the retry of step 0 is a new command and applies again.
        let error = run_plan(RACE, Some(VolumeDefect::FreshIdOnRetry)).expect_err("must fail");
        assert!(
            error.starts_with("volume_response_mismatch: step 0 send 1:"),
            "{error}"
        );
    }

    #[test]
    fn a_stale_revision_a_client_refreshes_is_named_by_the_oracle() {
        run_plan(RACE, None).expect("the control: the same plan without the defect passes");
        let error =
            run_plan(RACE, Some(VolumeDefect::StaleRevisionRefreshed)).expect_err("must fail");
        assert!(
            error.starts_with("volume_response_mismatch: step 2 send 0:"),
            "{error}"
        );
    }

    // Plans a desk must refuse. Constants, so each is the `'static` slice a desk takes.
    const OUTSIDE_THE_CAMPAIGN: &[VolumeStep] = &[set(50, Target::Member, 10)];
    const OUT_OF_ORDER: &[VolumeStep] = &[set(10, Target::Member, 10), set(5, Target::Member, 10)];
    const SENDS_NOTHING: &[VolumeStep] = &[relative(
        1,
        Route::Tailnet,
        Target::Member,
        5,
        0,
        Observed::Now,
    )];
    const ZERO_DELTA: &[VolumeStep] = &[relative(
        1,
        Route::Tailnet,
        Target::Member,
        0,
        1,
        Observed::Now,
    )];
    const BEFORE_ITSELF: &[VolumeStep] = &[relative(
        1,
        Route::Tailnet,
        Target::Member,
        5,
        1,
        Observed::BeforeStep(0),
    )];
    const LEGACY_WITH_A_REVISION: &[VolumeStep] = &[
        set(1, Target::Member, 10),
        relative(
            2,
            Route::LocalLegacy,
            Target::Member,
            5,
            1,
            Observed::BeforeStep(0),
        ),
    ];
    const OVER_100: &[VolumeStep] = &[set(1, Target::Group, 101)];

    #[test]
    fn an_invalid_plan_is_refused_before_anything_is_sent() {
        let session = fixture_session();
        let refusal = |plan: &'static [VolumeStep]| {
            VolumeDesk::start(&session, KITCHEN, plan, 50, NOW_NS, None)
                .err()
                .expect("must be refused")
        };
        assert!(
            refusal(OUTSIDE_THE_CAMPAIGN).starts_with("volume_plan_invalid: step 0 is at block 50")
        );
        assert!(refusal(OUT_OF_ORDER).starts_with("volume_plan_invalid: step 1 is at block 5"));
        assert!(refusal(SENDS_NOTHING).contains("step 0 sends nothing"));
        assert!(refusal(ZERO_DELTA).contains("delta 0"));
        assert!(refusal(BEFORE_ITSELF).contains("not an earlier step"));
        assert!(
            refusal(LEGACY_WITH_A_REVISION).contains("step 1 names the revision before step 0")
        );
        assert!(refusal(OVER_100).contains("sets volume 101"));
        // A member that is not in the group.
        let error = VolumeDesk::start(&session, "nobody", &[], 50, NOW_NS, None)
            .err()
            .expect("must be refused");
        assert!(error.contains("nobody is not in the group"), "{error}");
    }

    #[test]
    fn a_valid_plan_is_not_refused() {
        // The control for the refusals above: the same call accepts the race plan.
        let session = fixture_session();
        assert!(VolumeDesk::start(&session, KITCHEN, RACE, TOTAL_BLOCKS, NOW_NS, None).is_ok());
        assert!(
            VolumeDesk::start(&session, KITCHEN, REFERENCE, TOTAL_BLOCKS, NOW_NS, None).is_ok()
        );
    }

    #[test]
    fn a_plan_that_did_not_finish_is_not_a_clean_run() {
        let mut session = fixture_session();
        let mut desk =
            VolumeDesk::start(&session, KITCHEN, RACE, TOTAL_BLOCKS, NOW_NS, None).expect("desk");
        for blk in 0..100 {
            desk.run_block(blk, NOW_NS, &mut session)
                .expect("blocks run");
        }
        let error = desk.finish(&session).expect_err("must not finish");
        assert!(
            error.starts_with("volume_plan_unfinished: 2 of 8"),
            "{error}"
        );
    }

    #[test]
    fn the_harness_keys_follow_the_secret_store_contract() {
        let handle = SecretHandle::new(
            franken_control::contracts::secret_store::SecretKind::ControlPeerKey,
            "peer-one",
        )
        .expect("handle");
        let value = |text: &str| SecretValue::new(text.as_bytes().to_vec()).expect("value");
        let mut keys = HarnessKeys::new();
        assert_eq!(
            keys.insert(&handle, value("0123456789abcdef")),
            Ok(Generation::FIRST)
        );
        assert!(matches!(
            keys.insert(&handle, value("0123456789abcdef")),
            Err(SecretError::AlreadyExists { .. })
        ));
        // A replacement must name the generation it replaces.
        let second = Generation::FIRST.successor().expect("successor");
        assert!(matches!(
            keys.replace(&handle, value("fedcba9876543210"), second),
            Err(SecretError::StaleGeneration { .. })
        ));
        assert_eq!(
            keys.replace(&handle, value("fedcba9876543210"), Generation::FIRST),
            Ok(second)
        );
        assert_eq!(keys.generation(&handle), Ok(second));
        let seen = keys.with_secret(&handle, |generation, bytes| (generation, bytes.to_vec()));
        assert_eq!(seen, Ok((second, b"fedcba9876543210".to_vec())));
        assert_eq!(keys.list().len(), 1);
        assert_eq!(keys.remove(&handle), Ok(()));
        assert!(matches!(
            keys.remove(&handle),
            Err(SecretError::NotFound { .. })
        ));
        // It is bounded.
        for index in 0..8 {
            let handle = SecretHandle::new(
                franken_control::contracts::secret_store::SecretKind::ControlPeerKey,
                &format!("peer-{index}"),
            )
            .expect("handle");
            keys.insert(&handle, value("0123456789abcdef"))
                .expect("room");
        }
        let full = SecretHandle::new(
            franken_control::contracts::secret_store::SecretKind::ControlPeerKey,
            "peer-extra",
        )
        .expect("handle");
        assert!(matches!(
            keys.insert(&full, value("0123456789abcdef")),
            Err(SecretError::StoreFull { max: 8 })
        ));
    }

    #[test]
    fn an_absolute_group_set_over_plain_soap_applies_and_a_repeat_leaves_the_volume_where_it_was() {
        let (mut plane, mut session) = plane_and_session();
        let start = session.state_revision;
        let applied = Sent {
            status: 200,
            new_volume: None,
            fault_code: None,
        };
        assert_eq!(
            plane.send_legacy_group_set(&mut session, NOW_NS, 65),
            applied
        );
        assert_eq!(
            (session.group_master_volume, session.state_revision),
            (65, start + 1)
        );
        // The response was lost and the controller sends the same plain SOAP request again: an absolute set is safe to repeat, so the
        // volume stays, and the repeat is a second command, so the revision moves again.
        assert_eq!(
            plane.send_legacy_group_set(&mut session, NOW_NS, 65),
            applied
        );
        assert_eq!(
            (session.group_master_volume, session.state_revision),
            (65, start + 2)
        );
        // Only the group moved.
        assert_eq!(member_volume(&session), 50);
    }

    #[test]
    fn an_out_of_range_group_set_is_refused_with_no_effect_and_the_boundary_is_accepted() {
        let (mut plane, mut session) = plane_and_session();
        let start = session.state_revision;
        let refused = Sent {
            status: 500,
            new_volume: None,
            fault_code: Some(UPNP_INVALID_ARGS),
        };
        for volume in [101, 200, 255] {
            assert_eq!(
                plane.send_legacy_group_set(&mut session, NOW_NS, volume),
                refused,
                "{volume}"
            );
        }
        assert_eq!(
            (session.group_master_volume, session.state_revision),
            (50, start)
        );
        // The control: the same call accepts the largest and the smallest valid volume.
        let applied = Sent {
            status: 200,
            new_volume: None,
            fault_code: None,
        };
        assert_eq!(
            plane.send_legacy_group_set(&mut session, NOW_NS, 100),
            applied
        );
        assert_eq!(
            (session.group_master_volume, session.state_revision),
            (100, start + 1)
        );
        assert_eq!(
            plane.send_legacy_group_set(&mut session, NOW_NS, 0),
            applied
        );
        assert_eq!(
            (session.group_master_volume, session.state_revision),
            (0, start + 2)
        );
    }

    #[test]
    fn the_end_of_campaign_step_applies_the_set_and_its_repeat_and_is_refused_nothing_else() {
        let mut session = fixture_session();
        let start = session.state_revision;
        let report =
            exercise_group_volume_set(&mut session, KITCHEN, NOW_NS, END_OF_CAMPAIGN_GROUP_VOLUME)
                .expect("the step passes");
        assert_eq!(
            report,
            GroupSetReport {
                volume: 65,
                applied: 2,
                refused: 1,
                start_revision: start,
                end_revision: start + 2,
            }
        );
        assert_eq!(session.group_master_volume, 65);
        assert_eq!(member_volume(&session), 50);
    }

    #[test]
    fn a_set_the_endpoint_refuses_fails_the_end_of_campaign_step_by_name() {
        // The control: a valid set passes.
        let mut session = fixture_session();
        exercise_group_volume_set(&mut session, KITCHEN, NOW_NS, 65)
            .expect("the control: a valid set passes");
        // The plant: asked to set a volume the endpoint refuses, the step says so by name and changes nothing.
        let mut session = fixture_session();
        let start = session.state_revision;
        let error = exercise_group_volume_set(&mut session, KITCHEN, NOW_NS, 101)
            .expect_err("a refused set must fail the step");
        assert!(
            error.starts_with("group_set_response_mismatch: send 0:"),
            "{error}"
        );
        assert_eq!(
            (session.group_master_volume, session.state_revision),
            (50, start)
        );
    }
}
