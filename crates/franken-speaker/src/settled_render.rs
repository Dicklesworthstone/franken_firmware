//! Private draft: one owner for durable control, membership and protected PCM.
//!
//! The provisioned pending binding is not a completed membership transition.
//! Membership tokens and remote readiness retain their existing transport trust
//! boundary. This module does not claim their authenticity or hardware behavior.

use franken_board_profile::BoardProfile;
use franken_control::channel::endpoint::FecHandled;
use franken_control::channel::owner::{AgreementError, FleetControlOwner, FreshFleetGroup};
use franken_control::channel::pipeline::{Settlement, Storage, StoreFailed};
use franken_control::contracts::secret_store::SecretStore;
use franken_control::fsonos::{Endpoint, Handled, HttpRequest, Notification, TransportState};
use franken_dsp::volume::{MemberVolume, MuteReason, Role, RolePlan, VolumeError};
use franken_hal::backend::DeviceBackend;
use franken_hal::events::ChannelEvent;
use franken_platform::ops::KernelOps;
use franken_session::{
    AuthorityToken, ChannelRole, GroupMembership, GroupStopMarker, GroupTime, MemberLifecycleState,
    MembershipChange, MembershipError, ProposalSpec, ProposalStatus, ReadinessReport,
    UnifiedGroupSession,
};
use franken_stream::carrier::{DatagramPort, PollReport};

use crate::button_adapter::{
    ButtonAction, ButtonAdapter, ButtonBounds, ButtonMap, ButtonRole, ButtonStats,
};
use crate::network_render::{NetworkRender, NetworkRenderError, OwnerStep};
use crate::render::{RenderState, StopReport, TickReport, TimingModel};
use crate::settled_http::{HttpMailboxError, HttpMailboxOwner, HttpService, OwnedHttpReply};

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
    Binding,
    RevisionConflict,
    JoinState,
    LocalReadinessUnproven,
    LeaseExpired,
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
    latest_ns: u64,
    earliest_frame: u64,
    latest_frame: u64,
}

fn frames_at(ns: u64) -> Option<u64> {
    u64::try_from(u128::from(ns).checked_mul(48_000)? / 1_000_000_000).ok()
}

/// Everything that can change this member's control and render state is owned.
pub struct SettledRender<
    K: SecretStore,
    S: Storage,
    P: DatagramPort,
    O: KernelOps,
    B: DeviceBackend,
> {
    control: FleetControlOwner<K, S>,
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
    active: bool,
    stopping: bool,
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
            control,
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
            active: false,
            stopping: false,
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
            .receive(now_ns, &self.session, bytes)
            .map_err(IngressError::Control)
    }

    pub fn step_control(&mut self) -> Result<ControlStep, OwnerError> {
        let now_ns = self.bounds(false)?.latest_ns;
        let control = self.control.step(now_ns, &mut self.session);
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
        let now_ns = self.bounds(false)?.latest_ns;
        let control = self
            .control
            .handle_soap(&mut self.soap, &mut self.session, now_ns, request);
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
    /// No network I/O or waiting is performed by the render loop. The copied
    /// session is diagnostic host state, not evidence of physical output.
    pub fn service_http(
        &mut self,
        mailbox: &mut HttpMailboxOwner,
    ) -> Result<HttpService, HttpMailboxError> {
        mailbox.service_one(|request| OwnedHttpReply {
            result: self.handle_soap(&request),
            session: self.session.clone(),
        })
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

    pub fn render_step<T: TimingModel>(
        &mut self,
        timing: &mut T,
    ) -> Result<PlaybackStep, OwnerError> {
        match self.reconcile()? {
            RenderApplication::WaitingJoin => Ok(PlaybackStep::WaitingJoin),
            RenderApplication::Stopping => Ok(PlaybackStep::Stopping),
            RenderApplication::PolicyAccepted | RenderApplication::Finishing => {
                let before = self.render.render_counters().frames_submitted;
                match self.render.step(timing) {
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
        if !self.stopping {
            self.stopping = true;
            self.note_transport(TransportState::Transitioning);
            self.render.cancel().map_err(OwnerError::Render)?;
            if self.render.render_state() == RenderState::Stopped
                && self.render.stop_report().acknowledged
            {
                self.note_transport(TransportState::Stopped);
            }
        }
        Ok(RenderApplication::Stopping)
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
