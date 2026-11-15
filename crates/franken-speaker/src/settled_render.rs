//! Private draft: one owner for durable control, membership and protected PCM.
//!
//! The provisioned pending binding is not a completed membership transition.
//! Membership tokens and remote readiness retain their existing transport trust
//! boundary. This module does not claim their authenticity or hardware behavior.

use franken_board_profile::BoardProfile;
use franken_control::channel::endpoint::FecHandled;
use franken_control::channel::owner::{
    AgreementError, FleetControlOwner, FreshFleetGroup, PendingFleetStep,
};
use franken_control::channel::pipeline::{PendingStepFailure, Settlement, Storage, StoreFailed};
use franken_control::contracts::secret_store::SecretStore;
use franken_control::fsonos::{Endpoint, Handled, HttpRequest, Notification, TransportState};
use franken_dsp::volume::{MemberVolume, MuteReason, Role, RolePlan, VolumeError};
use franken_hal::backend::DeviceBackend;
use franken_hal::events::ChannelEvent;
use franken_journal::PollStorage;
use franken_platform::ops::KernelOps;
use franken_session::{
    AuthorityToken, ChannelRole, GroupMembership, GroupStopMarker, GroupTime, MemberLifecycleState,
    MembershipChange, MembershipError, ProposalSpec, ProposalStatus, ReadinessReport,
    RenewalWindow, UnifiedGroupSession,
};
use franken_stream::carrier::{DatagramPort, PollReport};

use crate::button_adapter::{
    ButtonAction, ButtonAdapter, ButtonBounds, ButtonMap, ButtonRole, ButtonStats,
};
use crate::network_render::{
    FinalFeedbackConfig, FinalFeedbackOutcome, NetworkRender, NetworkRenderError, OwnerStep,
};
use crate::render::{RenderState, StopReport, TickReport, TimingModel};
use crate::runtime::{ControlRuntime, ControlRuntimeError, ControlRuntimeStats};
use crate::settled_http::{
    HttpMailboxError, HttpMailboxOwner, HttpOwnerIdentity, HttpService, OwnedHttpReply,
};

/// Explicitly provisioned pending identity and local protection ceiling.
#[derive(Debug)]
pub struct PendingMember {
    pub member_id: String,
    pub profile_id: String,
    pub role: ChannelRole,
    pub ceiling: f32,
}

#[derive(Debug)]
pub enum AdmissionError {
    Runtime(ControlRuntimeError),
    Binding,
    Control(AgreementError),
    Membership(MembershipError),
    Render(NetworkRenderError),
    Volume(VolumeError),
}

/// Why the owned physical-button adapter could not be used or configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonInputError {
    NotConfigured,
    AlreadyConfigured,
    ConfigurationClosed,
}

/// The local intent effect and any separate attempt to apply render policy.
#[derive(Debug)]
pub struct ButtonEventResult {
    pub action: ButtonAction,
    pub render: Option<Result<RenderApplication, OwnerError>>,
}

#[derive(Debug)]
pub enum OwnerError {
    ControlPending,
    Runtime(ControlRuntimeError),
    Binding,
    RevisionConflict,
    JoinState,
    LocalReadinessUnproven,
    LeaseExpired,
    RenewalTooLate,
    Clock,
    Membership(MembershipError),
    Render(NetworkRenderError),
}

#[derive(Debug)]
pub enum IngressError {
    Owner(OwnerError),
    Control(AgreementError),
}

/// A control commit is distinct from whether the protected renderer applied it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderApplication {
    WaitingJoin,
    /// The renderer accepted the current target; this is not a DMA, acoustic,
    /// or instantaneous ramped-gain observation.
    PolicyAccepted,
    /// Finite input is exhausted. The current intent was not applied to future
    /// PCM; the already scheduled tail still requires normal finish and drain.
    Finishing,
    /// Cancellation was requested; this does not assert that a drain was ACKed.
    Stopping,
}

#[derive(Debug)]
pub struct ControlResult<T> {
    pub control: T,
    pub render: Result<RenderApplication, OwnerError>,
    /// Produced events for the caller's transport. SOAP keeps its original
    /// events in `Handled`; this vector may contain later transport deltas.
    pub notifications: Vec<Notification>,
}

/// Durable control outcome plus its separately observed render effect.
pub type ControlStep = ControlResult<Result<Vec<Settlement>, StoreFailed>>;

pub type PendingControlStep = ControlResult<Result<Vec<Settlement>, PendingStepFailure>>;

/// Deferred ingress remains unaccepted until the returned datagrams are passed
/// through `receive` with a fresh owner clock. No response is silently dropped.
pub struct PendingControlCompletion {
    pub step: PendingControlStep,
    pub deferred_datagrams: Vec<Vec<u8>>,
}

impl std::fmt::Debug for PendingControlCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingControlCompletion")
            .field("durable_success", &self.step.control.is_ok())
            .field("notification_count", &self.step.notifications.len())
            .field("deferred_datagram_count", &self.deferred_datagrams.len())
            .finish_non_exhaustive()
    }
}

/// Consuming shutdown handoff after the HAL acknowledged stop. The caller
/// retains the complete drained renderer, control storage and event endpoint;
/// a process backend must still be quiesced and its separate worker reaped.
pub struct StoppedOwnerParts<
    K: SecretStore,
    S: Storage,
    P: DatagramPort,
    O: KernelOps,
    B: DeviceBackend,
> {
    pub control: FleetControlOwner<K, S>,
    pub render: NetworkRender<P, O, B>,
    pub soap: Endpoint,
    pub session: UnifiedGroupSession,
}

#[expect(
    clippy::large_enum_variant,
    reason = "reserve inline pending custody without a new allocation at each control transition"
)]
enum ControlSlot<K: SecretStore, S: Storage> {
    Ready(FleetControlOwner<K, S>),
    Pending(PendingFleetStep<K, S>),
    // Present only while a consuming move is synchronously restored.
    Moving,
}

impl<K: SecretStore, S: Storage> ControlSlot<K, S> {
    fn ready_mut(&mut self) -> Result<&mut FleetControlOwner<K, S>, OwnerError> {
        match self {
            Self::Ready(owner) => Ok(owner),
            _ => Err(OwnerError::ControlPending),
        }
    }

    fn fresh_group_is_healthy(&self) -> bool {
        match self {
            Self::Ready(owner) => owner.fresh_group_is_healthy(),
            Self::Pending(owner) => owner.fresh_group_is_healthy(),
            Self::Moving => false,
        }
    }

    fn session_sequence_exhausted(&self, session: &UnifiedGroupSession) -> bool {
        match self {
            Self::Ready(owner) => owner.session_sequence_exhausted(session),
            Self::Pending(owner) => owner.session_sequence_exhausted(session),
            Self::Moving => true,
        }
    }

    fn lease_is_live(&self, session: &UnifiedGroupSession, now_ns: u64) -> bool {
        match self {
            Self::Ready(owner) => owner.lease_is_live(session, now_ns),
            Self::Pending(owner) => owner.lease_is_live(session, now_ns),
            Self::Moving => false,
        }
    }

    fn lease_matches(&self, token: &AuthorityToken) -> bool {
        match self {
            Self::Ready(owner) => owner.lease_matches(token),
            Self::Pending(owner) => owner.lease_matches(token),
            Self::Moving => false,
        }
    }
}

#[derive(Debug)]
pub struct MembershipResult {
    pub settled: Vec<(u64, ProposalStatus)>,
    pub render: Result<RenderApplication, OwnerError>,
    /// Produced events for the caller to deliver after actual activation.
    pub notifications: Vec<Notification>,
}

#[derive(Debug)]
pub enum PlaybackStep {
    WaitingJoin,
    Render(OwnerStep),
    Stopping,
}

#[derive(Debug)]
pub enum DrainProgress {
    /// No active HAL drain is exposed; retained priming custody is unresolved.
    NotStartedUnacknowledged,
    Tick {
        report: TickReport,
        state: RenderState,
    },
    /// Only the existing render stop report may establish an acknowledgement.
    Finished(StopReport),
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct CommittedVolume {
    epoch: u64,
    revision: u64,
    group: u8,
    member: Option<(u8, bool)>,
}

#[derive(Clone, Copy)]
struct ClockBounds {
    earliest_ns: u64,
    latest_ns: u64,
    earliest_frame: u64,
    latest_frame: u64,
}

fn frames_at(ns: u64) -> Option<u64> {
    u64::try_from(u128::from(ns).checked_mul(48_000)? / 1_000_000_000).ok()
}

type PollableHttpService<K, S, P, O, B> = fn(
    &mut SettledRender<K, S, P, O, B>,
    &mut HttpMailboxOwner,
) -> Result<HttpService, HttpMailboxError>;

/// Everything that can change this member's control and render state is owned.
pub struct SettledRender<
    K: SecretStore,
    S: Storage,
    P: DatagramPort,
    O: KernelOps,
    B: DeviceBackend,
> {
    control_runtime: ControlRuntime,
    control: ControlSlot<K, S>,
    stop_generation: u64,
    soap: Endpoint,
    membership: GroupMembership,
    session: UnifiedGroupSession,
    authority: AuthorityToken,
    member: String,
    profile: String,
    role: ChannelRole,
    volume: MemberVolume,
    buttons: Option<ButtonAdapter>,
    button_configuration_closed: bool,
    render: NetworkRender<P, O, B>,
    observed: CommittedVolume,
    observed_stop: Option<GroupStopMarker>,
    last_group_upper_ns: Option<u64>,
    transport: TransportState,
    transport_dirty: bool,
    http_identity: HttpOwnerIdentity,
    pending_http: Option<crate::settled_http::PendingOwnerRequest>,
    pending_soap: Option<franken_control::fsonos::DeferredSoap>,
    pending_http_notifications: Vec<Notification>,
    pollable_http: Option<PollableHttpService<K, S, P, O, B>>,
    active: bool,
    stopping: bool,
    // Natural completion also drains the HAL. It does not grant an explicit
    // stop/revocation a route back into transport feedback.
    final_feedback_revoked: bool,
    output_grants_required: bool,
    join: Option<(u64, AuthorityToken)>,
}

impl<K: SecretStore, S: Storage, P: DatagramPort, O: KernelOps, B: DeviceBackend>
    SettledRender<K, S, P, O, B>
{
    /// Form a new group from trusted provisioning; reconstructed sessions and
    /// existing media require a separate recovery path and are not admitted.
    pub fn admit_fresh_group(
        fresh: FreshFleetGroup<K, S>,
        mut soap: Endpoint,
        mut render: NetworkRender<P, O, B>,
        pending: PendingMember,
        clock_leader: u64,
    ) -> Result<Self, AdmissionError> {
        // Build before acquiring/arming any render policy. Failure cannot leave
        // a partially initialized owner with an unserviced control executor.
        let control_runtime = ControlRuntime::new().map_err(AdmissionError::Runtime)?;
        let (mut control, membership, session, authority) = fresh.into_parts();
        let PendingMember {
            member_id: member,
            profile_id: profile,
            role,
            ceiling,
        } = pending;
        // A stored single-member intent constrains this fresh constructor. It
        // establishes configuration consistency only, not recovery authority.
        if control
            .recovery_binding()
            .map_err(|_| AdmissionError::Binding)?
            .is_some_and(|binding| {
                binding.group_id() != session.group_id.as_str()
                    || binding.configured_issuer().as_str() != session.coordinator_id.as_str()
                    || binding.member_id() != member.as_str()
                    || binding.profile_id() != profile.as_str()
                    || binding.role() != role
            })
        {
            return Err(AdmissionError::Binding);
        }
        if member.is_empty()
            || session.current_epoch != render.bound_epoch()
            || clock_leader != render.bound_clock_leader()
            || !control.fresh_group_is_healthy()
            || profile != render.protection_profile_id()
            || !ceiling.is_finite()
            || !(0.0..=1.0).contains(&ceiling)
        {
            return Err(AdmissionError::Binding);
        }
        if control.session_sequence_exhausted(&session) {
            return Err(AdmissionError::Binding);
        }
        let view = render.join_clock_view().map_err(AdmissionError::Render)?;
        let latest_ns = view
            .group_ns
            .checked_add(view.uncertainty_ns)
            .ok_or(AdmissionError::Binding)?;
        if !membership.lease_is_live(&session, &authority, latest_ns) {
            return Err(AdmissionError::Binding);
        }
        control
            .install_lease(&session, authority.clone(), latest_ns)
            .map_err(AdmissionError::Membership)?;
        let observed = CommittedVolume {
            epoch: session.current_epoch,
            revision: session.state_revision,
            group: session.group_master_volume,
            member: None,
        };
        let observed_stop = session.last_group_stop();
        control
            .reserve_legacy_peer(soap.legacy_peer())
            .map_err(AdmissionError::Control)?;
        render
            .arm_software_silent_start()
            .map_err(AdmissionError::Render)?;
        let mut volume = MemberVolume::new(ceiling);
        volume
            .declare_epoch(session.current_epoch)
            .map_err(AdmissionError::Volume)?;
        volume.observe_board(render.protection_status());
        // A provisioned pending source is not yet rendered or stopped.
        soap.set_transport(TransportState::Transitioning);
        Ok(Self {
            control_runtime,
            control: ControlSlot::Ready(control),
            stop_generation: 0,
            soap,
            membership,
            session,
            authority,
            member,
            profile,
            role,
            volume,
            buttons: None,
            button_configuration_closed: false,
            render,
            observed,
            observed_stop,
            last_group_upper_ns: Some(latest_ns),
            transport: TransportState::Transitioning,
            transport_dirty: true,
            http_identity: HttpOwnerIdentity::new(),
            pending_http: None,
            pending_soap: None,
            pending_http_notifications: Vec::new(),
            pollable_http: None,
            active: false,
            stopping: false,
            final_feedback_revoked: false,
            output_grants_required: false,
            join: None,
        })
    }

    fn bounds(&mut self, require_locked: bool) -> Result<ClockBounds, OwnerError> {
        let clock = if require_locked {
            self.render.join_clock_view()
        } else {
            self.render.usable_clock_view()
        };
        let view = match clock {
            Ok(view) => view,
            Err(error) => {
                let _ = self.request_stop();
                return Err(OwnerError::Render(error));
            }
        };
        let bounds = view
            .group_ns
            .checked_sub(view.uncertainty_ns)
            .zip(view.group_ns.checked_add(view.uncertainty_ns))
            .and_then(|(earliest, latest_ns)| {
                Some(ClockBounds {
                    earliest_ns: earliest,
                    latest_ns,
                    earliest_frame: frames_at(earliest)?,
                    latest_frame: frames_at(latest_ns)?,
                })
            });
        match bounds {
            Some(mut bounds) => {
                // A tighter clock uncertainty can decrease an upper bound even
                // as real time advances. Never move the control time backwards.
                bounds.latest_ns = self
                    .last_group_upper_ns
                    .map_or(bounds.latest_ns, |last| last.max(bounds.latest_ns));
                let Some(latest_frame) = frames_at(bounds.latest_ns) else {
                    let _ = self.request_stop();
                    return Err(OwnerError::Clock);
                };
                bounds.latest_frame = latest_frame;
                self.last_group_upper_ns = Some(bounds.latest_ns);
                Ok(bounds)
            }
            None => {
                let _ = self.request_stop();
                Err(OwnerError::Clock)
            }
        }
    }

    fn join_token(&self, id: u64) -> Result<&AuthorityToken, OwnerError> {
        match self.join.as_ref() {
            Some((current, token)) if *current == id => Ok(token),
            _ => Err(OwnerError::JoinState),
        }
    }

    /// Propose the exact pending identity and profile, not a caller snapshot.
    pub fn propose_join(
        &mut self,
        token: AuthorityToken,
        board: BoardProfile,
        cutover_frame: u64,
        ack_deadline_ns: u64,
    ) -> Result<u64, OwnerError> {
        if self.active
            || self.stopping
            || self.join.is_some()
            || board.profile_id != self.profile
            || token != self.authority
        {
            return Err(OwnerError::JoinState);
        }
        if self.reconcile()? == RenderApplication::Stopping {
            return Err(OwnerError::JoinState);
        }
        let b = self.bounds(true)?;
        if board.verify_integrity().is_err() || !self.render.matches_admitted_profile(&board) {
            return Err(OwnerError::Binding);
        }
        let role = match self.role {
            ChannelRole::Stereo => Role::Stereo,
            ChannelRole::LeftMono => Role::Left,
            ChannelRole::RightMono => Role::Right,
            ChannelRole::SubLfe => Role::Sub,
            ChannelRole::MonoSum => Role::MonoSum,
        };
        let plan = RolePlan::for_profile(&board, role).map_err(|_| OwnerError::Binding)?;
        if !self.render.can_bind_initial_role(plan) {
            return Err(OwnerError::Binding);
        }
        let spec = ProposalSpec {
            change: MembershipChange::Join {
                member_id: self.member.clone(),
                board: Box::new(board),
                role: self.role,
            },
            cutover_frame,
            ack_deadline_ns,
        };
        let id = self
            .membership
            .propose(
                &self.session,
                &token,
                spec,
                GroupTime {
                    ns: b.latest_ns,
                    frame: b.latest_frame,
                },
            )
            .map_err(OwnerError::Membership)?;
        // A successful proposal closes button configuration even if a later
        // role binding or cutover fails; no new adapter can reset its history.
        self.button_configuration_closed = true;
        self.render
            .bind_initial_role(plan)
            .map_err(OwnerError::Render)?;
        self.join = Some((id, token));
        Ok(id)
    }

    /// Existing protocol trust boundary: caller vouches for the remote report.
    /// A local readiness report cannot be supplied through this entry point.
    pub fn ack_remote(
        &mut self,
        id: u64,
        member: &str,
        report: ReadinessReport,
    ) -> Result<(), OwnerError> {
        self.join_token(id)?;
        if member == self.member {
            return Err(OwnerError::JoinState);
        }
        let b = self.bounds(true)?;
        self.membership
            .ack(
                id,
                member,
                report,
                GroupTime {
                    ns: b.latest_ns,
                    frame: b.latest_frame,
                },
            )
            .map_err(OwnerError::Membership)
    }

    /// Derive local readiness from the admitted owned renderer, its explicit
    /// backend capability, and a fresh locked clock. Capability is not an ACK
    /// and does not guarantee that a future stop will succeed.
    pub fn ack_local(&mut self, id: u64) -> Result<(), OwnerError> {
        self.join_token(id)?;
        let b = self.bounds(true)?;
        if !self.render.pending_join_ready() {
            return Err(OwnerError::LocalReadinessUnproven);
        }
        let local = ReadinessReport {
            format_ok: true,
            buffer_ok: true,
            clock_confident: true,
            can_stop_flush: true,
            old_output_tail_complete_frame: 0,
        };
        self.membership
            .ack(
                id,
                &self.member,
                local,
                GroupTime {
                    ns: b.latest_ns,
                    frame: b.latest_frame,
                },
            )
            .map_err(OwnerError::Membership)
    }

    pub fn commit_join(&mut self, id: u64) -> Result<ProposalStatus, OwnerError> {
        if !self.render.pending_join_ready() {
            return Err(OwnerError::LocalReadinessUnproven);
        }
        let token = self.join_token(id)?.clone();
        let b = self.bounds(true)?;
        self.membership
            .commit(
                &self.session,
                &token,
                id,
                GroupTime {
                    ns: b.latest_ns,
                    frame: b.latest_frame,
                },
            )
            .map_err(OwnerError::Membership)
    }

    /// Advance only under the exact original lease, checked again at latest possible
    /// time; activation uses the earliest possible frame so it cannot occur early.
    pub fn tick_membership(&mut self, id: u64) -> Result<MembershipResult, OwnerError> {
        if self.reconcile()? == RenderApplication::Stopping {
            return Err(OwnerError::JoinState);
        }
        let token = self.join_token(id)?.clone();
        if !self.active && !self.render.pending_join_ready() {
            return Err(OwnerError::LocalReadinessUnproven);
        }
        let b = match self.bounds(!self.active) {
            Ok(bounds) => bounds,
            Err(error) => {
                if self.active {
                    let _ = self.request_stop();
                }
                return Err(error);
            }
        };
        if !self
            .membership
            .lease_is_live(&self.session, &token, b.latest_ns)
        {
            if self.active {
                let _ = self.request_stop();
            }
            return Err(OwnerError::LeaseExpired);
        }
        let settled = self.membership.tick(
            &mut self.session,
            GroupTime {
                ns: b.latest_ns,
                frame: b.earliest_frame,
            },
        );
        let activated = settled.iter().any(|(proposal, status)| {
            *proposal == id && matches!(status, ProposalStatus::Activated { .. })
        });
        // Activation has changed the owned session even if a later render or
        // clock check fails. Publish only on this non-real-time control path.
        let notifications = if activated {
            self.transport_dirty = false;
            self.soap.publish(b.latest_ns, &self.session)
        } else {
            Vec::new()
        };
        if activated {
            let valid = self
                .session
                .members
                .get(&self.member)
                .is_some_and(|member| {
                    member.member_id == self.member
                        && member.profile_id == self.profile
                        && member.role == self.role
                        && member.lifecycle == MemberLifecycleState::SynchronizedReady
                        && self.session.current_epoch == self.render.bound_epoch()
                });
            if !valid {
                let _ = self.request_stop();
                return Ok(MembershipResult {
                    settled,
                    render: Err(OwnerError::Binding),
                    notifications,
                });
            }
            // The activation has happened even if a later recheck fails: return
            // its actual outcome separately from the refused renderer effect.
            if !self.render.pending_join_ready() {
                let _ = self.request_stop();
                return Ok(MembershipResult {
                    settled,
                    render: Err(OwnerError::LocalReadinessUnproven),
                    notifications,
                });
            }
            let after = match self.bounds(true) {
                Ok(bounds) => bounds,
                Err(error) => {
                    let _ = self.request_stop();
                    return Ok(MembershipResult {
                        settled,
                        render: Err(error),
                        notifications,
                    });
                }
            };
            if !self
                .membership
                .lease_is_live(&self.session, &token, after.latest_ns)
            {
                let _ = self.request_stop();
                return Ok(MembershipResult {
                    settled,
                    render: Err(OwnerError::LeaseExpired),
                    notifications,
                });
            }
            self.active = true;
            self.volume.complete_join();
        }
        if settled.iter().any(|(proposal, status)| {
            *proposal == id && matches!(status, ProposalStatus::Aborted { .. })
        }) {
            self.join = None;
        }
        let render = self.reconcile();
        Ok(MembershipResult {
            settled,
            render,
            notifications,
        })
    }

    /// Authenticate and enqueue using the same owner's conservative group
    /// time; a datagram caller cannot choose the limiter/TTL timebase.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<FecHandled, IngressError> {
        let now_ns = self.bounds(false).map_err(IngressError::Owner)?.latest_ns;
        self.control
            .ready_mut()
            .map_err(IngressError::Owner)?
            .receive(now_ns, &self.session, bytes)
            .map_err(IngressError::Control)
    }

    pub fn step_control(&mut self) -> Result<ControlStep, OwnerError> {
        if self.pollable_http.is_some() {
            return Err(OwnerError::ControlPending);
        }
        let runtime = self.control_runtime.clone();
        runtime
            .turn(|| self.step_control_owned())
            .map_err(OwnerError::Runtime)?
    }

    fn step_control_owned(&mut self) -> Result<ControlStep, OwnerError> {
        let now_ns = self.bounds(false)?.latest_ns;
        let control = self.control.ready_mut()?.step(now_ns, &mut self.session);
        // On store failure this sees only the live session, including actual
        // reapplied local silence. The endpoint filters unchanged variables.
        let render = self.reconcile();
        let notifications = self.soap.publish(now_ns, &self.session);
        self.transport_dirty = false;
        Ok(ControlResult {
            control,
            render,
            notifications,
        })
    }

    pub fn handle_soap(
        &mut self,
        request: &HttpRequest<'_>,
    ) -> Result<ControlResult<Handled>, OwnerError> {
        if self.pollable_http.is_some() {
            return Err(OwnerError::ControlPending);
        }
        let runtime = self.control_runtime.clone();
        runtime
            .turn(|| self.handle_soap_owned(request))
            .map_err(OwnerError::Runtime)?
    }

    fn handle_soap_owned(
        &mut self,
        request: &HttpRequest<'_>,
    ) -> Result<ControlResult<Handled>, OwnerError> {
        let now_ns = self.bounds(false)?.latest_ns;
        let control = self.control.ready_mut()?.handle_soap(
            &mut self.soap,
            &mut self.session,
            now_ns,
            request,
        );
        let render = self.reconcile();
        let notifications = if self.transport_dirty {
            self.transport_dirty = false;
            self.soap.publish(now_ns, &self.session)
        } else {
            Vec::new()
        };
        Ok(ControlResult {
            control,
            render,
            notifications,
        })
    }

    /// Service at most one admitted HTTP request on the caller's control path.
    /// Synchronous storage uses the compatibility path; explicitly selected
    /// pollable storage drives one cooperative reactor turn and may return
    /// `Pending`, retaining its request and journal. Call outside the render
    /// callback. The copied session is diagnostic state, not physical output.
    /// The first call, even when idle, associates this exact owner instance
    /// with this one mailbox. Other owners, other mailboxes and generic
    /// service cannot replace either side of that association.
    pub fn service_http(
        &mut self,
        mailbox: &mut HttpMailboxOwner,
    ) -> Result<HttpService, HttpMailboxError> {
        if let Some(service) = self.pollable_http {
            return service(self, mailbox);
        }
        let runtime = self.control_runtime.clone();
        runtime
            .turn(|| self.service_http_owned(mailbox))
            .map_err(|error| match error {
                ControlRuntimeError::Busy => HttpMailboxError::Busy,
                _ => HttpMailboxError::Unavailable,
            })?
    }

    fn service_http_owned(
        &mut self,
        mailbox: &mut HttpMailboxOwner,
    ) -> Result<HttpService, HttpMailboxError> {
        let permit = mailbox.associate_owner(&mut self.http_identity)?;
        mailbox.service_owned(&permit, |request| OwnedHttpReply {
            result: self.handle_soap_owned(&request),
            session: self.session.clone(),
        })
    }

    /// Control executor observations only; render/HAL deadline evidence remains
    /// the responsibility of the existing output owner and its timing model.
    pub fn control_runtime_stats(&self) -> ControlRuntimeStats {
        self.control_runtime.stats()
    }

    /// Reopen this owner's mailbox after its exclusive eventing worker exits.
    /// Invalidate the actual owned endpoint's subscriptions before admitting
    /// raw clients or another callback target. Call on the same owner/mailbox
    /// pair used by `service_http`, outside the render callback. Active or
    /// still-executing work returns Busy and does not invalidate anything.
    #[cfg(any(test, feature = "harness"))]
    pub fn release_http_eventing(
        &mut self,
        mailbox: &mut HttpMailboxOwner,
    ) -> Result<usize, HttpMailboxError> {
        let permit = mailbox.owner_permit(&self.http_identity)?;
        mailbox.finish_eventing(&permit, || self.soap.invalidate_subscriptions())
    }

    fn note_transport(&mut self, next: TransportState) {
        if self.transport != next {
            self.transport = next;
            self.soap.set_transport(next);
            self.transport_dirty = true;
        }
    }

    /// Produce pending transport deltas outside the render path. The caller
    /// owns delivery. If no valid clock is available, leave the update dirty
    /// and return the actual failure rather than inventing an event timestamp.
    pub fn publish_transport(&mut self) -> Result<Vec<Notification>, OwnerError> {
        if !self.transport_dirty {
            return Ok(Vec::new());
        }
        let now_ns = self.bounds(false)?.latest_ns;
        let notifications = self.soap.publish(now_ns, &self.session);
        self.transport_dirty = false;
        Ok(notifications)
    }

    /// Configure exactly once, before the first accepted join proposal.
    pub fn configure_buttons(
        &mut self,
        map: ButtonMap,
        bounds: ButtonBounds,
    ) -> Result<(), ButtonInputError> {
        if self.buttons.is_some() {
            return Err(ButtonInputError::AlreadyConfigured);
        }
        if self.button_configuration_closed || self.active || self.stopping || self.join.is_some() {
            return Err(ButtonInputError::ConfigurationClosed);
        }
        self.buttons = Some(ButtonAdapter::new_unknown(map, bounds));
        Ok(())
    }

    /// Apply an admitted HAL event to this owner's local intent. The action is
    /// separate from render policy application and never asserts a HAL ACK.
    pub fn handle_button_event(
        &mut self,
        event: ChannelEvent,
    ) -> Result<ButtonEventResult, ButtonInputError> {
        let adapter = self
            .buttons
            .as_mut()
            .ok_or(ButtonInputError::NotConfigured)?;
        self.volume.observe_board(self.render.protection_status());
        let action = adapter.on_event(event, &mut self.volume);
        // MemberVolume tracks board/local/join mute; this owner also holds the
        // group-member mute in its session. Include both in diagnostics.
        let action = match action {
            ButtonAction::LocalMute { muted, .. } => ButtonAction::LocalMute {
                muted,
                effective_mute: self.effective_mute(),
            },
            ButtonAction::TrimStep { trim_permille, .. } => ButtonAction::TrimStep {
                trim_permille,
                effective_mute: self.effective_mute(),
            },
            other => other,
        };
        let render = if matches!(
            action,
            ButtonAction::LocalMute { .. } | ButtonAction::TrimStep { .. }
        ) {
            Some(self.reconcile())
        } else {
            None
        };
        Ok(ButtonEventResult { action, render })
    }

    /// Report newly stuck buttons without advancing the renderer.
    pub fn poll_buttons(&mut self, now: u64) -> Result<Vec<ButtonRole>, ButtonInputError> {
        Ok(self
            .buttons
            .as_mut()
            .ok_or(ButtonInputError::NotConfigured)?
            .poll(now))
    }

    #[must_use]
    pub fn button_stats(&self) -> Option<ButtonStats> {
        self.buttons.as_ref().map(ButtonAdapter::stats)
    }

    #[must_use]
    pub fn button_is_stuck(&self, role: ButtonRole) -> Option<bool> {
        self.buttons.as_ref().map(|adapter| adapter.is_stuck(role))
    }

    pub fn local_mute(&mut self, muted: bool) -> Result<RenderApplication, OwnerError> {
        self.volume.local_mute(muted);
        self.reconcile()
    }

    pub fn local_trim_step(
        &mut self,
        delta_permille: i16,
    ) -> Result<Result<RenderApplication, OwnerError>, VolumeError> {
        self.volume.local_trim_step(delta_permille)?;
        Ok(self.reconcile())
    }

    /// The current desired mute intent, not a hardware mute or stop ACK.
    pub fn effective_mute(&self) -> Option<MuteReason> {
        self.volume.effective_mute().or_else(|| {
            self.session
                .members
                .get(&self.member)
                .and_then(|member| member.muted.then_some(MuteReason::Group))
        })
    }

    pub fn render_state(&self) -> RenderState {
        self.render.render_state()
    }

    /// Real media frames consumed by the protected source, not proof of output.
    pub fn received_frames_pulled(&self) -> u64 {
        self.render.received_frames_pulled()
    }
    pub fn poll_media(&mut self) -> Result<PollReport, OwnerError> {
        match self.render.poll() {
            Ok(report) => Ok(report),
            Err(error) => {
                let _ = self.request_stop();
                Err(OwnerError::Render(error))
            }
        }
    }
    pub fn report_media(&mut self) -> Result<(), OwnerError> {
        match self.render.report() {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = self.request_stop();
                Err(OwnerError::Render(error))
            }
        }
    }

    /// Opt in once, before rendering, to bounded retransmission of final
    /// authenticated consumption credit. No report is a playback or HAL ACK.
    pub fn enable_final_feedback(&mut self, config: FinalFeedbackConfig) -> Result<(), OwnerError> {
        if self.final_feedback_revoked || self.stopping {
            return Err(OwnerError::Render(NetworkRenderError::Ended));
        }
        self.render
            .enable_final_feedback(config)
            .map_err(OwnerError::Render)
    }

    /// Retry already-consumed final credit after natural EOF, subject to both
    /// the transport's finite budget and the current canonical control lease.
    /// Callers drive this separately from rendering and HAL drain. No ingress,
    /// PCM preparation, policy change or device submission happens here.
    pub fn final_feedback(&mut self) -> Result<FinalFeedbackOutcome, OwnerError> {
        if self.final_feedback_revoked || !self.active {
            return Ok(FinalFeedbackOutcome::Disabled);
        }
        // Borrow disjoint owned state: the transport supplies the *same* fresh
        // conservative bound it uses for the send, not an earlier clock read.
        // This callback performs only in-memory checks and never calls storage,
        // a clock, rendering or arbitrary user work.
        let control = &self.control;
        let session = &self.session;
        let membership = &self.membership;
        let authority = &self.authority;
        let join = &self.join;
        let member = &self.member;
        let profile = &self.profile;
        let role = self.role;
        let observed = &self.observed;
        let observed_stop = &self.observed_stop;
        let epoch = self.render.bound_epoch();
        let last_upper = &mut self.last_group_upper_ns;
        let mut refusal = None;
        let result = self.render.final_feedback_if(|sampled_latest| {
            let latest = last_upper.map_or(sampled_latest, |last| last.max(sampled_latest));
            *last_upper = Some(latest);
            if !control.fresh_group_is_healthy()
                || session.control_sequence_exhausted()
                || control.session_sequence_exhausted(session)
            {
                refusal = Some(OwnerError::Binding);
                return false;
            }
            if !membership.lease_is_live(session, authority, latest)
                || !control.lease_is_live(session, latest)
                || join
                    .as_ref()
                    .is_none_or(|(_, token)| !membership.lease_is_live(session, token, latest))
            {
                refusal = Some(OwnerError::LeaseExpired);
                return false;
            }
            let entry = session.members.get(member);
            let current = CommittedVolume {
                epoch: session.current_epoch,
                revision: session.state_revision,
                group: session.group_master_volume,
                member: entry.map(|m| (m.volume_0_to_100, m.muted)),
            };
            if current.epoch != observed.epoch
                || current.revision < observed.revision
                || (current.revision == observed.revision && current != *observed)
                || session.current_epoch != epoch
                || session.group_master_volume > 100
                || session.last_group_stop().as_ref() != observed_stop.as_ref()
                || entry.is_none_or(|entry| {
                    entry.member_id.as_str() != member.as_str()
                        || entry.profile_id.as_str() != profile.as_str()
                        || entry.role != role
                        || entry.volume_0_to_100 > 100
                        || entry.lifecycle != MemberLifecycleState::SynchronizedReady
                })
            {
                refusal = Some(OwnerError::Binding);
                return false;
            }
            true
        });
        if let Some(error) = refusal {
            let _ = self.request_stop();
            return Err(error);
        }
        match result {
            Ok(outcome) => Ok(outcome),
            Err(error) => {
                let _ = self.request_stop();
                Err(OwnerError::Render(error))
            }
        }
    }

    /// Renew this active configured-issuer owner's lease under trusted local
    /// provisioning. This is not a wire-authenticated request or a quorum win.
    /// `publication_budget_ns` is the caller-admitted worst-case group-time
    /// interval from the final clock sample through the synchronous swaps. It
    /// must be nonzero and fit inside every old lease's conservative lifetime.
    /// A target must qualify that bound; a host fixture does not establish it.
    /// N03 timing/authority, output grants, epoch and protection are unchanged.
    pub fn renew_owned_lease(
        &mut self,
        expected: &AuthorityToken,
        expires_at_ns: u64,
        publication_budget_ns: u64,
    ) -> Result<AuthorityToken, OwnerError> {
        if publication_budget_ns == 0
            || expected != &self.authority
            || !self.active
            || self.stopping
            || self.render.is_terminal()
        {
            return Err(OwnerError::Binding);
        }
        if self.reconcile()? == RenderApplication::Stopping {
            return Err(OwnerError::Binding);
        }
        let (join_id, join_token) = self.join.as_ref().ok_or(OwnerError::JoinState)?;
        if join_token != expected || !self.control.lease_matches(expected) {
            let _ = self.request_stop();
            return Err(OwnerError::Binding);
        }
        // Allocate every replacement before the final clock sample. No I/O,
        // allocation, callback or fallible work follows the control install.
        let candidate = AuthorityToken {
            expires_at_ns,
            ..self.authority.clone()
        };
        let held = candidate.clone();
        let control = candidate.clone();
        let join = (*join_id, candidate.clone());
        let b = self.bounds(false)?;
        if !self
            .membership
            .lease_is_live(&self.session, expected, b.latest_ns)
            || !self.control.lease_is_live(&self.session, b.latest_ns)
            || self.join.as_ref().is_none_or(|(_, token)| {
                !self
                    .membership
                    .lease_is_live(&self.session, token, b.latest_ns)
            })
        {
            let _ = self.request_stop();
            return Err(OwnerError::LeaseExpired);
        }
        let commit_ns = b
            .latest_ns
            .checked_add(publication_budget_ns)
            .ok_or(OwnerError::RenewalTooLate)?;
        if !self
            .membership
            .lease_is_live(&self.session, expected, commit_ns)
            || !self.control.lease_is_live(&self.session, commit_ns)
            || self.join.as_ref().is_none_or(|(_, token)| {
                !self
                    .membership
                    .lease_is_live(&self.session, token, commit_ns)
            })
        {
            return Err(OwnerError::RenewalTooLate);
        }
        self.membership
            .validate_configured_renewal(
                &self.session,
                expected,
                &candidate,
                RenewalWindow {
                    earliest_ns: b.earliest_ns,
                    latest_ns: commit_ns,
                },
            )
            .map_err(OwnerError::Membership)?;
        self.control
            .ready_mut()?
            .install_lease(&self.session, control, commit_ns)
            .map_err(OwnerError::Membership)?;
        self.authority = held;
        self.join = Some(join);
        Ok(candidate)
    }

    /// Opt this fresh owner into explicit whole-block output grants before
    /// joining. This cannot be enabled/disabled after joining or used to reset
    /// authority, an output interval, or retained device custody.
    pub fn require_output_grants(&mut self) -> Result<(), OwnerError> {
        if self.active || self.stopping || self.join.is_some() || self.button_configuration_closed {
            return Err(OwnerError::JoinState);
        }
        self.output_grants_required = true;
        Ok(())
    }

    /// Trusted in-process grant issuance, not a new authenticated wire command.
    /// The owner checks its canonical member/epoch and live control authority;
    /// the requested half-open bound is an absolute 48 kHz group frame.
    /// This may allocate in membership and belongs on the control path.
    /// Existing grants only extend. Expired authority cannot issue a grant and
    /// this mode retains the existing conservative lease-expiry stop policy;
    /// it does not implement post-lease G01 grant drain or takeover.
    pub fn grant_output(
        &mut self,
        token: &AuthorityToken,
        through_frame: u64,
    ) -> Result<u64, OwnerError> {
        if !self.output_grants_required
            || !self.active
            || self.stopping
            || self.render.is_terminal()
            || token != &self.authority
        {
            return Err(OwnerError::Binding);
        }
        if self.reconcile()? == RenderApplication::Stopping {
            return Err(OwnerError::Binding);
        }
        let bounds = self.bounds(false)?;
        if !self
            .membership
            .lease_is_live(&self.session, token, bounds.latest_ns)
            || !self.control.lease_is_live(&self.session, bounds.latest_ns)
            || self.join.as_ref().is_none_or(|(_, join)| {
                !self
                    .membership
                    .lease_is_live(&self.session, join, bounds.latest_ns)
            })
        {
            let _ = self.request_stop();
            return Err(OwnerError::LeaseExpired);
        }
        self.membership
            .grant_output(
                &self.session,
                token,
                &self.member,
                through_frame,
                GroupTime {
                    ns: bounds.latest_ns,
                    frame: bounds.earliest_frame,
                },
            )
            .map_err(OwnerError::Membership)
    }

    pub fn render_step<T: TimingModel>(
        &mut self,
        timing: &mut T,
    ) -> Result<PlaybackStep, OwnerError> {
        match self.reconcile()? {
            RenderApplication::WaitingJoin => Ok(PlaybackStep::WaitingJoin),
            RenderApplication::Stopping => Ok(PlaybackStep::Stopping),
            RenderApplication::PolicyAccepted | RenderApplication::Finishing => {
                let before = self.render.render_counters().frames_submitted;
                let mut grant_refusal = false;
                let result = if self.output_grants_required {
                    let membership = &self.membership;
                    let member = &self.member;
                    let control = &self.control;
                    let session = &self.session;
                    let authority = &self.authority;
                    let join = &self.join;
                    let last_upper = &mut self.last_group_upper_ns;
                    self.render
                        .step_with_output_permission(timing, |through, sampled| {
                            let latest = last_upper.map_or(sampled, |last| last.max(sampled));
                            *last_upper = Some(latest);
                            if !membership.lease_is_live(session, authority, latest)
                                || !control.lease_is_live(session, latest)
                                || join.as_ref().is_none_or(|(_, token)| {
                                    !membership.lease_is_live(session, token, latest)
                                })
                            {
                                grant_refusal = true;
                                return false;
                            }
                            through
                                .checked_sub(1)
                                .is_some_and(|last| membership.output_permitted(member, last))
                        })
                } else {
                    self.render.step(timing)
                };
                if grant_refusal {
                    let _ = self.request_stop();
                    return Err(OwnerError::LeaseExpired);
                }
                match result {
                    Ok(step) => {
                        // Only an actual newly submitted protected frame is
                        // enough to report Playing; admission is not playback.
                        match self.render.render_state() {
                            RenderState::Draining => {
                                self.note_transport(TransportState::Transitioning);
                                // Natural end-of-stream also enters the same
                                // bounded drain path; do not reapply ordinary
                                // playback policy to a draining renderer.
                                self.stopping = true;
                            }
                            RenderState::Stopped if self.render.stop_report().acknowledged => {
                                self.note_transport(TransportState::Stopped);
                            }
                            _ if self.render.render_counters().frames_submitted > before => {
                                self.note_transport(TransportState::Playing);
                            }
                            _ => {}
                        }
                        Ok(PlaybackStep::Render(step))
                    }
                    Err(error) => {
                        let _ = self.request_stop();
                        Err(OwnerError::Render(error))
                    }
                }
            }
        }
    }

    pub fn request_stop(&mut self) -> Result<RenderApplication, OwnerError> {
        self.stop_generation = self.stop_generation.saturating_add(1);
        // Also revoke when a natural EOF has already entered the shared drain
        // path. The existing idempotent HAL-stop behavior is unchanged.
        self.final_feedback_revoked = true;
        self.render.revoke_final_feedback();
        if !self.stopping {
            self.stopping = true;
            self.note_transport(TransportState::Transitioning);
        }
        if !matches!(
            self.render.render_state(),
            RenderState::Draining | RenderState::Stopped
        ) {
            self.render.cancel().map_err(OwnerError::Render)?;
            if self.render.render_state() == RenderState::Stopped
                && self.render.stop_report().acknowledged
            {
                self.note_transport(TransportState::Stopped);
            }
        }
        Ok(RenderApplication::Stopping)
    }

    /// Refuse extraction while a durable operation or hardware stop remains
    /// unresolved. Failure returns this entire owner unchanged, retaining all
    /// storage, rendering and DMA custody for subsequent progress.
    /// The large inline renderer remains subject to target stack qualification.
    #[expect(
        clippy::result_large_err,
        reason = "return full renderer and journal custody without adding a recovery-path allocation"
    )]
    pub fn into_stopped_parts(self) -> Result<StoppedOwnerParts<K, S, P, O, B>, Self> {
        if !self.stopping
            || self.render.render_state() != RenderState::Stopped
            || !self.render.stop_report().acknowledged
            || !matches!(&self.control, ControlSlot::Ready(_))
            || self.pending_http.is_some()
        {
            return Err(self);
        }
        let ControlSlot::Ready(control) = self.control else {
            unreachable!("ready slot checked before consuming owner");
        };
        Ok(StoppedOwnerParts {
            control,
            render: self.render,
            soap: self.soap,
            session: self.session,
        })
    }

    /// No timeout or command receipt is interpreted as a flush ACK.
    pub fn drain_tick<T: TimingModel>(
        &mut self,
        timing: &mut T,
    ) -> Result<DrainProgress, OwnerError> {
        if !self.stopping {
            return Err(OwnerError::JoinState);
        }
        match self.render.render_state() {
            RenderState::Draining => {
                let report = self.render.drain_tick(timing).map_err(OwnerError::Render)?;
                let state = self.render.render_state();
                if state == RenderState::Stopped && self.render.stop_report().acknowledged {
                    self.note_transport(TransportState::Stopped);
                }
                Ok(DrainProgress::Tick { report, state })
            }
            RenderState::Stopped | RenderState::Faulted => {
                Ok(DrainProgress::Finished(self.render.stop_report()))
            }
            _ => Ok(DrainProgress::NotStartedUnacknowledged),
        }
    }

    fn reconcile(&mut self) -> Result<RenderApplication, OwnerError> {
        if self.stopping {
            return Ok(RenderApplication::Stopping);
        }
        if !self.control.fresh_group_is_healthy()
            || self.session.control_sequence_exhausted()
            || self.control.session_sequence_exhausted(&self.session)
        {
            return self.request_stop();
        }
        let b = self.bounds(false)?;
        if !self
            .membership
            .lease_is_live(&self.session, &self.authority, b.latest_ns)
            || !self.control.lease_is_live(&self.session, b.latest_ns)
        {
            let _ = self.request_stop();
            return Err(OwnerError::LeaseExpired);
        }
        let stop = self.session.last_group_stop();
        if stop != self.observed_stop {
            self.observed_stop = stop;
            return self.request_stop();
        }
        if self.session.current_epoch != self.render.bound_epoch()
            || self.session.group_master_volume > 100
        {
            let _ = self.request_stop();
            return Err(OwnerError::Binding);
        }
        if !self.active
            && self.session.members.values().any(|member| {
                matches!(
                    &member.lifecycle,
                    MemberLifecycleState::StoppingDmaTail { .. }
                )
            })
        {
            return self.request_stop();
        }
        let entry = self.session.members.get(&self.member);
        if self.active && entry.is_none() {
            let _ = self.request_stop();
            return Err(OwnerError::Binding);
        }
        if !self.active && entry.is_some() {
            let _ = self.request_stop();
            return Err(OwnerError::Binding);
        }
        let current = CommittedVolume {
            epoch: self.session.current_epoch,
            revision: self.session.state_revision,
            group: self.session.group_master_volume,
            member: entry.map(|m| (m.volume_0_to_100, m.muted)),
        };
        if current.epoch != self.observed.epoch
            || current.revision < self.observed.revision
            || (current.revision == self.observed.revision && current != self.observed)
        {
            let _ = self.request_stop();
            return Err(OwnerError::RevisionConflict);
        }
        self.observed = current;
        let Some(entry) = entry else {
            return Ok(RenderApplication::WaitingJoin);
        };
        if entry.member_id != self.member
            || entry.profile_id != self.profile
            || entry.role != self.role
            || entry.volume_0_to_100 > 100
        {
            let _ = self.request_stop();
            return Err(OwnerError::Binding);
        }
        if entry.lifecycle != MemberLifecycleState::SynchronizedReady {
            return self.request_stop();
        }
        let (member, group_muted) = current.member.ok_or(OwnerError::Binding)?;
        self.volume.observe_board(self.render.protection_status());
        let gain = ((f32::from(current.group) / 100.0)
            * (f32::from(member) / 100.0)
            * (f32::from(self.volume.trim_permille()) / 1000.0))
            .min(self.volume.effective_ceiling())
            .clamp(0.0, 1.0);
        let muted = group_muted || self.volume.effective_mute().is_some();
        if !muted {
            // Borrow the owned token after the clock read: cloning it here would
            // allocate Strings on every protected render step.
            let token = &self.join.as_ref().ok_or(OwnerError::JoinState)?.1;
            if !self
                .membership
                .lease_is_live(&self.session, token, b.latest_ns)
            {
                let _ = self.request_stop();
                return Err(OwnerError::LeaseExpired);
            }
        }
        if let Err(error) = self.render.apply_owned_policy(gain, muted) {
            // A normal finite source can be out of future samples before its
            // scheduled final tail is presented. No policy was applied, but
            // the actual network step must continue to finish that tail.
            if matches!(error, NetworkRenderError::Ended) && !self.render.is_terminal() {
                // A mute intent cannot be applied to already scheduled or
                // retained PCM. Stop rather than silently let that tail play.
                if muted {
                    return self.request_stop();
                }
                return Ok(RenderApplication::Finishing);
            }
            let _ = self.request_stop();
            return Err(OwnerError::Render(error));
        }
        Ok(RenderApplication::PolicyAccepted)
    }
}

impl<K: SecretStore, S: PollStorage, P: DatagramPort, O: KernelOps, B: DeviceBackend>
    SettledRender<K, S, P, O, B>
{
    /// Begin one owned durable step. Rendering and physical local stop remain
    /// available; ordinary mutable control ingress returns `ControlPending`.
    pub fn begin_pending_control(&mut self) -> Result<(), OwnerError> {
        if self.pending_http.is_some() {
            return Err(OwnerError::ControlPending);
        }
        self.begin_pending_control_inner()
    }

    fn begin_pending_control_inner(&mut self) -> Result<(), OwnerError> {
        if self.stopping || self.stop_generation == u64::MAX {
            return Err(OwnerError::JoinState);
        }
        let now_ns = self.bounds(false)?.latest_ns;
        self.begin_pending_control_at(now_ns)
    }

    fn begin_pending_control_at(&mut self, now_ns: u64) -> Result<(), OwnerError> {
        let slot = std::mem::replace(&mut self.control, ControlSlot::Moving);
        match slot {
            ControlSlot::Ready(owner) => {
                self.control = ControlSlot::Pending(owner.into_pending_step(
                    now_ns,
                    &self.session,
                    self.stop_generation,
                ));
                Ok(())
            }
            other => {
                self.control = other;
                Err(OwnerError::ControlPending)
            }
        }
    }

    /// A bounded queue, not an authentication or command-acceptance response.
    pub fn defer_control_datagram(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), franken_control::channel::owner::DeferredIngressError> {
        if self.pending_http.is_some() {
            return Err(franken_control::channel::owner::DeferredIngressError::Full);
        }
        match &mut self.control {
            ControlSlot::Pending(pending) => pending.defer_datagram(bytes),
            _ => Err(franken_control::channel::owner::DeferredIngressError::NotPending),
        }
    }

    /// Poll inside the caller's actively driven Asupersync runtime. There is no
    /// nested block_on, helper thread, or blocking storage in this owner method.
    /// A clock failure cancels publication but still drains the accepted I/O,
    /// retaining journal/worker custody until terminal extraction.
    pub fn poll_pending_control(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<PendingControlCompletion, OwnerError>> {
        if self.pending_http.is_some() {
            return std::task::Poll::Ready(Err(OwnerError::ControlPending));
        }
        self.poll_pending_control_inner(cx)
    }

    fn poll_pending_control_inner(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<PendingControlCompletion, OwnerError>> {
        let sampled = self.bounds(false);
        let now_ns = sampled.as_ref().map_or_else(
            |_| self.last_group_upper_ns.unwrap_or(0),
            |bounds| bounds.latest_ns,
        );
        let ControlSlot::Pending(pending) = &mut self.control else {
            return std::task::Poll::Ready(Err(OwnerError::ControlPending));
        };
        if sampled.is_err() {
            pending.cancel();
        }
        if pending
            .poll_step(cx, now_ns, &mut self.session, self.stop_generation)
            .is_pending()
        {
            return std::task::Poll::Pending;
        }
        let ControlSlot::Pending(pending) =
            std::mem::replace(&mut self.control, ControlSlot::Moving)
        else {
            unreachable!("pending slot retained through poll");
        };
        match pending.finish() {
            Err(pending) => {
                self.control = ControlSlot::Pending(pending);
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
            Ok((owner, control, deferred_datagrams)) => {
                self.control = ControlSlot::Ready(owner);
                let render = self.reconcile();
                let notifications = self.soap.publish(now_ns, &self.session);
                self.transport_dirty = false;
                std::task::Poll::Ready(Ok(PendingControlCompletion {
                    step: ControlResult {
                        control,
                        render,
                        notifications,
                    },
                    deferred_datagrams,
                }))
            }
        }
    }
}

/// One finite production owner turn. Pending storage remains owned across
/// calls; this reports neither hardware deadlines nor successful playback.
#[derive(Debug)]
pub struct ServiceTurn {
    /// Complete owned datagram round, including raw deferred ingress that the
    /// caller must explicitly re-authenticate or return to its sender.
    pub control: Option<Result<PendingControlCompletion, OwnerError>>,
    pub http: Option<Result<HttpService, HttpMailboxError>>,
    pub render: Result<PlaybackStep, OwnerError>,
    pub drain: Option<Result<DrainProgress, OwnerError>>,
    pub stop: Option<Result<RenderApplication, OwnerError>>,
    pub stop_mute_acknowledged: Option<bool>,
}

impl<K: SecretStore, S: PollStorage, P: DatagramPort, O: KernelOps, B: DeviceBackend>
    SettledRender<K, S, P, O, B>
{
    /// Select pollable durability for the existing `service_http` entry point.
    /// This is a one-way mode selection; accepted pending I/O cannot be switched
    /// back to synchronous storage. The caller still owns render/Stop scheduling.
    pub fn use_pollable_control(&mut self) {
        self.pollable_http = Some(Self::service_http_pollable);
    }

    fn service_http_pollable(
        &mut self,
        mailbox: &mut HttpMailboxOwner,
    ) -> Result<HttpService, HttpMailboxError> {
        let runtime = self.control_runtime.clone();
        runtime
            .drive(|| self.service_http_pollable_inner(mailbox))
            .map_err(|error| match error {
                ControlRuntimeError::Busy => HttpMailboxError::Busy,
                _ => HttpMailboxError::Unavailable,
            })?
    }

    async fn service_http_pollable_inner(
        &mut self,
        mailbox: &mut HttpMailboxOwner,
    ) -> Result<HttpService, HttpMailboxError> {
        use std::future::Future;
        let runtime_cx = asupersync::cx::Cx::current().expect("owned control runtime");
        let mut deadline = std::pin::pin!(asupersync::time::sleep(
            runtime_cx.now(),
            std::time::Duration::from_millis(1)
        ));
        std::future::poll_fn(|cx| {
            if let std::task::Poll::Ready(result) = self.poll_service_http(cx, mailbox) {
                return std::task::Poll::Ready(result);
            }
            if deadline.as_mut().poll(cx).is_ready() {
                return std::task::Poll::Ready(Ok(HttpService::Pending));
            }
            std::task::Poll::Pending
        })
        .await
    }

    /// Production caller-driven service route for pollable storage. Each turn
    /// checks the supplied cooperative time budget between polls, services
    /// local Stop and rendering, and retains the one HTTP envelope until a
    /// durable terminal outcome. A poll/HAL call is not preempted: this is not
    /// a hard real-time deadline guarantee. Synchronous storage remains supported.
    pub fn service_turn<T: TimingModel>(
        &mut self,
        mailbox: &mut HttpMailboxOwner,
        timing: &mut T,
        stop: &std::sync::atomic::AtomicBool,
        budget: std::time::Duration,
    ) -> Result<ServiceTurn, OwnerError> {
        if budget.is_zero() || budget > std::time::Duration::from_millis(20) {
            return Err(OwnerError::Binding);
        }
        self.use_pollable_control();
        let runtime = self.control_runtime.clone();
        // The factory captures only borrowed owner inputs; drive separately
        // admits the concrete future layout before constructing/polling it.
        runtime
            .drive(|| self.service_turn_inner(mailbox, timing, stop, budget))
            .map_err(OwnerError::Runtime)
    }

    async fn service_turn_inner<T: TimingModel>(
        &mut self,
        mailbox: &mut HttpMailboxOwner,
        timing: &mut T,
        stop: &std::sync::atomic::AtomicBool,
        budget: std::time::Duration,
    ) -> ServiceTurn {
        use std::future::Future;
        let runtime_cx = asupersync::cx::Cx::current().expect("owned control runtime");
        let mut deadline = std::pin::pin!(asupersync::time::sleep(runtime_cx.now(), budget));
        let mut tick = std::pin::pin!(asupersync::time::sleep(
            runtime_cx.now(),
            std::time::Duration::from_millis(1)
        ));
        let mut render = None;
        let mut drain = None;
        let mut stop_result = None;
        let mut first = true;
        std::future::poll_fn(|cx| {
            if stop.load(std::sync::atomic::Ordering::Acquire)
                && stop_result.is_none()
                && (!self.stopping
                    || !matches!(
                        self.render.render_state(),
                        RenderState::Draining | RenderState::Stopped
                    ))
            {
                stop_result = Some(self.request_stop());
            }
            if first || tick.as_mut().poll(cx).is_ready() {
                first = false;
                render = Some(self.render_step(timing));
                if self.stopping {
                    drain = Some(self.drain_tick(timing));
                }
                tick.set(asupersync::time::sleep(
                    runtime_cx.now(),
                    std::time::Duration::from_millis(1),
                ));
                let _ = tick.as_mut().poll(cx);
            }
            // An already-owned datagram round retains storage before another
            // HTTP envelope can be taken; mailbox admission remains intact.
            // A retained HTTP envelope is its own authority for continuation.
            // Never associate the supplied mailbox before retiring that work.
            let (authorized, mut http) = if self.pending_http.is_some() {
                (true, self.poll_service_http(cx, mailbox))
            } else {
                match mailbox.associate_owner(&mut self.http_identity) {
                    Err(error) => (false, std::task::Poll::Ready(Err(error))),
                    Ok(_) if matches!(self.control, ControlSlot::Pending(_)) => {
                        (true, std::task::Poll::Pending)
                    }
                    Ok(_) => (true, self.poll_service_http(cx, mailbox)),
                }
            };
            let mut control = None;
            // Mailbox identity fences mailbox access, never retirement of
            // independently authenticated, already accepted datagram work.
            if self.pending_http.is_none()
                && (!authorized
                    || matches!(self.control, ControlSlot::Pending(_))
                    || matches!(http, std::task::Poll::Ready(Ok(HttpService::Idle))))
            {
                if matches!(&self.control, ControlSlot::Ready(owner) if owner.has_pending_control())
                {
                    match self
                        .bounds(false)
                        .and_then(|bounds| self.begin_pending_control_at(bounds.latest_ns))
                    {
                        Ok(()) => {}
                        Err(error) => control = Some(Err(error)),
                    }
                }
                if let ControlSlot::Pending(pending) = &mut self.control {
                    if self.stopping {
                        pending.cancel();
                    }
                    if authorized {
                        http = std::task::Poll::Pending;
                    }
                    if let std::task::Poll::Ready(result) = self.poll_pending_control_inner(cx) {
                        control = Some(result);
                    }
                }
            }
            if control.is_some() || http.is_ready() {
                return std::task::Poll::Ready(ServiceTurn {
                    control,
                    http: match http {
                        std::task::Poll::Ready(result) => Some(result),
                        std::task::Poll::Pending => None,
                    },
                    render: render.take().unwrap(),
                    drain: drain.take(),
                    stop: stop_result.take(),
                    stop_mute_acknowledged: self.render.last_mute_acknowledged(),
                });
            }
            if deadline.as_mut().poll(cx).is_ready() {
                return std::task::Poll::Ready(ServiceTurn {
                    control: None,
                    http: None,
                    render: render.take().unwrap(),
                    drain: drain.take(),
                    stop: stop_result.take(),
                    stop_mute_acknowledged: self.render.last_mute_acknowledged(),
                });
            }
            std::task::Poll::Pending
        })
        .await
    }

    fn poll_service_http(
        &mut self,
        cx: &mut std::task::Context<'_>,
        mailbox: &mut HttpMailboxOwner,
    ) -> std::task::Poll<Result<HttpService, HttpMailboxError>> {
        use franken_control::fsonos::PreparedSoap;
        use std::task::Poll;
        // A retained envelope already carries its authorized owner/response
        // custody. Retire that work even when the original mailbox has gone;
        // do not access or consume a replacement mailbox during continuation.
        // Returned HttpService names that retained request. A later intake
        // checks (and rejects) any replacement identity normally.
        if self.pending_http.is_none() {
            let permit = match mailbox.associate_owner(&mut self.http_identity) {
                Ok(p) => p,
                Err(e) => return Poll::Ready(Err(e)),
            };
            if !matches!(self.control, ControlSlot::Ready(_)) {
                return Poll::Ready(Err(HttpMailboxError::Busy));
            }
            let request = match mailbox.take_owned(&permit) {
                Ok(Some(r)) => r,
                Ok(None) => return Poll::Ready(Ok(HttpService::Idle)),
                Err(e) => return Poll::Ready(Err(e)),
            };
            if request.expired() {
                return Poll::Ready(Ok(HttpService::Expired));
            }
            let now = match self.bounds(false) {
                Ok(b) => b.latest_ns,
                Err(e) => {
                    return Poll::Ready(Ok(request.complete(OwnedHttpReply {
                        result: Err(e),
                        session: self.session.clone(),
                    })));
                }
            };
            let prepared = match self.control.ready_mut() {
                Ok(control) => request.with_view(|view| {
                    control.prepare_soap(&mut self.soap, &mut self.session, now, &view)
                }),
                Err(e) => {
                    return Poll::Ready(Ok(request.complete(OwnedHttpReply {
                        result: Err(e),
                        session: self.session.clone(),
                    })));
                }
            };
            match prepared {
                PreparedSoap::Ready(control) => {
                    let render = self.reconcile();
                    let notifications = if self.transport_dirty {
                        self.transport_dirty = false;
                        self.soap.publish(now, &self.session)
                    } else {
                        Vec::new()
                    };
                    return Poll::Ready(Ok(request.complete(OwnedHttpReply {
                        result: Ok(ControlResult {
                            control,
                            render,
                            notifications,
                        }),
                        session: self.session.clone(),
                    })));
                }
                PreparedSoap::Pending(command) => {
                    self.pending_http = Some(request);
                    self.pending_soap = Some(command);
                    if let Err(e) = self.begin_pending_control_at(now) {
                        self.pending_soap = None;
                        let request = self.pending_http.take().unwrap();
                        return Poll::Ready(Ok(request.complete(OwnedHttpReply {
                            result: Err(e),
                            session: self.session.clone(),
                        })));
                    }
                }
            }
        }
        // Once accepted, a disconnected/expired HTTP observer does not cancel
        // the durable command. Finish it and record a lost reply; the client
        // already reports OutcomeUnknown. Only local Stop fences publication.
        if self.stopping
            && let ControlSlot::Pending(pending) = &mut self.control
        {
            pending.cancel();
        }
        let completion = match self.poll_pending_control_inner(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(v)) => v,
            Poll::Ready(Err(_)) => return Poll::Ready(Err(HttpMailboxError::Unavailable)),
        };
        // This route never admits parallel ingress: pending datagrams belong
        // to the explicit manual API, which must not be mixed with this loop.
        let now = self.last_group_upper_ns.unwrap_or(0);
        let command = self.pending_soap.take().unwrap();
        self.pending_http_notifications
            .extend(completion.step.notifications);
        match self
            .soap
            .finish_round(command, completion.step.control, now, &self.session)
        {
            PreparedSoap::Ready(control) => {
                let request = self.pending_http.take().unwrap();
                Poll::Ready(Ok(request.complete(OwnedHttpReply {
                    result: Ok(ControlResult {
                        control,
                        render: completion.step.render,
                        notifications: std::mem::take(&mut self.pending_http_notifications),
                    }),
                    session: self.session.clone(),
                })))
            }
            PreparedSoap::Pending(command) => {
                self.pending_soap = Some(command);
                if self.begin_pending_control_at(now).is_err() {
                    return Poll::Ready(Err(HttpMailboxError::Unavailable));
                }
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}
