//! Bounded ownership of authenticated prepared PCM and the protected renderer.
//!
//! The mapping and final source frame are caller-admitted facts, not discovery,
//! a distributed clock, a hardware deadline measurement, or a DMA completion.

use franken_clock::group::{ClockStatus, GroupClock, Output, StartSchedule};
use franken_dsp::resample::{FrameSource, PRIME_FRAMES, PhaseState};
use franken_hal::backend::DeviceBackend;
use franken_hal::session::StartPreconditions;
use franken_platform::layer::PlatformLayer;
use franken_platform::ops::KernelOps;
use franken_stream::carrier::{DatagramPort, PollReport};
use franken_stream::playout::{BLOCK_FRAMES, BLOCK_PAYLOAD_BYTES, Outcome, Poll, frames_to_ns};

use crate::clock_view::ClockViewBridge;
use crate::media_playout::{Preparation, PreparedBlock, StartRefusal};
use crate::net_carrier::{EngineVerdicts, MediaEndpoint};
use crate::render::{
    BlockOutcome, RenderLoop, RenderSource, RenderState, Starvation, TickReport, TimingModel,
};

/// Maximum retained decoded stereo frames; the caller admits a smaller share.
pub const MAX_QUEUED_FRAMES: usize = 1024;
/// Two full network blocks plus D03's two-frame lookahead.
pub const MIN_QUEUED_FRAMES: usize = 514;

/// Caller-admitted mapping, in group nanoseconds per device tick. This is not
/// clock synchronization or a measurement of an actual device.
#[derive(Debug, Clone, Copy)]
pub struct TickMapping {
    pub anchor_tick: u64,
    pub anchor_group_ns: u64,
    pub ns_numerator: u64,
    pub tick_denominator: u64,
    pub uncertainty_ns: u64,
    pub presentation_tolerance_ns: u64,
}

impl TickMapping {
    fn at(self, tick: u64) -> Option<u64> {
        if self.tick_denominator == 0 {
            return None;
        }
        let delta = i128::from(tick) - i128::from(self.anchor_tick);
        let product = delta.checked_mul(i128::from(self.ns_numerator))?;
        let ns = product.div_euclid(i128::from(self.tick_denominator));
        u64::try_from(i128::from(self.anchor_group_ns).checked_add(ns)?).ok()
    }
}

// D03's input window includes two frames after its interpolation position.
// `pending` is pulled lazily before the next output, so it belongs in the
// projected position even though the input has not yet been consumed.
fn position_q32(anchor: u64, pulled: u64, phase: PhaseState) -> Option<u128> {
    let whole = u128::from(anchor)
        .checked_add(u128::from(pulled))?
        .checked_add(u128::from(phase.pending))?
        .checked_sub(u128::from(PRIME_FRAMES))?;
    whole
        .checked_mul(1_u128 << 32)?
        .checked_add(u128::from(phase.frac))
}

fn position_group_ns(anchor: u64, anchor_ns: u64, pos_q32: u128) -> Option<u64> {
    let absolute = pos_q32.checked_mul(62_500)? / (3_u128 << 32);
    let offset = absolute.checked_sub(u128::from(frames_to_ns(anchor)))?;
    anchor_ns.checked_add(u64::try_from(offset).ok()?)
}

/// Explicit caller-admitted parameters for one bounded source epoch.
#[derive(Debug, Clone, Copy)]
pub struct NetworkRenderAdmission {
    pub schedule: StartSchedule,
    pub anchor_frame: u64,
    pub final_frame: u64,
    pub mapping: TickMapping,
    pub capacity_frames: usize,
    pub start: StartPreconditions,
}

/// Optional host-side retry budget for authenticated final carrier credit.
/// The grace is an upper bound, not an extension of clock or authority life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalFeedbackConfig {
    pub interval_ns: u64,
    pub grace_ns: u64,
    pub max_reports: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalFeedbackOutcome {
    Sent,
    NotDue,
    Expired,
    Disabled,
}

struct FinalFeedbackState {
    config: FinalFeedbackConfig,
    deadline_ns: Option<u64>,
    next_due_ns: Option<u64>,
    stream: u64,
    epoch: u64,
    consumed_next: u64,
    sent: u32,
    expired: bool,
}

/// Terminal faults invalidate the owner; source-end refusals leave the admitted
/// renderer available for its existing completion/drain path.
#[derive(Debug)]
pub enum NetworkRenderError {
    Configuration,
    Mapping,
    Clock,
    Start(StartRefusal),
    Render(crate::render::RenderError),
    Preparation,
    Timeline,
    Capacity,
    Ended,
}

#[derive(Debug)]
pub enum OwnerStep {
    Waiting,
    Tick(TickReport),
    Complete,
}

#[derive(Clone, Copy, Default)]
struct PcmFrame {
    samples: [f32; 2],
    synthetic: bool,
    concealed: bool,
}

/// Fixed ring: pulling is allocation-free and never polls or performs I/O.
struct PreparedPcm {
    frames: [PcmFrame; MAX_QUEUED_FRAMES],
    head: usize,
    len: usize,
    capacity: usize,
    next_frame: u64,
    final_frame: u64,
    anchor_frame: u64,
    anchor_ns: u64,
    real_pulled: u64,
    concealed_pulled: u64,
    padding_pulled: u64,
    timeline_silence_pulled: u64,
    padding_available: usize,
}

impl PreparedPcm {
    fn new(capacity: usize, anchor_frame: u64, final_frame: u64, anchor_ns: u64) -> Self {
        Self {
            frames: [PcmFrame::default(); MAX_QUEUED_FRAMES],
            head: 0,
            len: 0,
            capacity,
            next_frame: anchor_frame,
            final_frame,
            anchor_frame,
            anchor_ns,
            real_pulled: 0,
            concealed_pulled: 0,
            padding_pulled: 0,
            timeline_silence_pulled: 0,
            padding_available: 0,
        }
    }

    fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
        self.padding_available = 0;
    }

    fn offer(
        &mut self,
        block: PreparedBlock,
        bytes: &[u8; BLOCK_PAYLOAD_BYTES],
    ) -> Result<(), NetworkRenderError> {
        let d = block.decision;
        let start = d
            .block
            .checked_mul(BLOCK_FRAMES)
            .ok_or(NetworkRenderError::Timeline)?;
        let frames = usize::from(d.frames);
        let end = start
            .checked_add(u64::try_from(frames).map_err(|_| NetworkRenderError::Timeline)?)
            .ok_or(NetworkRenderError::Timeline)?;
        let offset = frames_to_ns(start)
            .checked_sub(frames_to_ns(self.anchor_frame))
            .ok_or(NetworkRenderError::Timeline)?;
        if !matches!(d.outcome, Outcome::Real | Outcome::Concealed { .. })
            || frames == 0
            || frames > BLOCK_FRAMES as usize
            || start != self.next_frame
            || end > self.final_frame
            || d.gap_before_ns != 0
            || self.anchor_ns.checked_add(offset) != Some(d.presentation_ns)
            || d.submit_deadline_ns > d.presentation_ns
        {
            return Err(NetworkRenderError::Timeline);
        }
        let slot_end = start
            .checked_add(BLOCK_FRAMES)
            .ok_or(NetworkRenderError::Timeline)?
            .min(self.final_frame);
        let slot_frames =
            usize::try_from(slot_end - start).map_err(|_| NetworkRenderError::Timeline)?;
        if self
            .len
            .checked_add(slot_frames)
            .is_none_or(|n| n > self.capacity)
        {
            return Err(NetworkRenderError::Capacity);
        }
        for sample in bytes[..frames * 4].as_chunks::<4>().0 {
            let left = i16::from_be_bytes([sample[0], sample[1]]);
            let right = i16::from_be_bytes([sample[2], sample[3]]);
            let index = (self.head + self.len) % self.capacity;
            self.frames[index] = PcmFrame {
                samples: [f32::from(left) / 32768.0, f32::from(right) / 32768.0],
                synthetic: false,
                concealed: matches!(d.outcome, Outcome::Concealed { .. }),
            };
            self.len += 1;
        }
        for _ in frames..slot_frames {
            let index = (self.head + self.len) % self.capacity;
            self.frames[index] = PcmFrame {
                samples: [0.0; 2],
                synthetic: true,
                concealed: false,
            };
            self.len += 1;
        }
        self.next_frame = slot_end;
        Ok(())
    }
}

impl FrameSource for PreparedPcm {
    fn pull(&mut self) -> Option<[f32; 2]> {
        if self.len != 0 {
            let frame = self.frames[self.head];
            self.head = (self.head + 1) % self.capacity;
            self.len -= 1;
            if frame.synthetic {
                self.timeline_silence_pulled = self.timeline_silence_pulled.saturating_add(1);
            } else if frame.concealed {
                self.concealed_pulled = self.concealed_pulled.saturating_add(1);
            } else {
                self.real_pulled = self.real_pulled.saturating_add(1);
            }
            Some(frame.samples)
        } else if self.padding_available != 0 {
            self.padding_available -= 1;
            self.padding_pulled = self.padding_pulled.saturating_add(1);
            Some([0.0; 2])
        } else {
            None
        }
    }
}

impl RenderSource for PreparedPcm {
    fn starvation(&self) -> Option<Starvation> {
        if self.len == 0 && self.padding_available == 0 {
            Some(Starvation::DecodeDelay)
        } else {
            None
        }
    }

    fn end_of_stream(&self) -> bool {
        self.next_frame == self.final_frame && self.len == 0 && self.padding_pulled == 2
    }
}

/// One owner serializes the endpoint, live clock, prepared queue and render
/// session. It never exposes a mutable renderer or control port.
pub struct NetworkRender<P: DatagramPort, O: KernelOps, B: DeviceBackend> {
    endpoint: MediaEndpoint<P>,
    platform: PlatformLayer<O>,
    clock: GroupClock,
    view: ClockViewBridge,
    render: RenderLoop<B>,
    pcm: PreparedPcm,
    mapping: TickMapping,
    schedule: StartSchedule,
    start: StartPreconditions,
    busy_deadline_ns: Option<u64>,
    last_presentation_end_ns: Option<u64>,
    terminal: bool,
    complete: bool,
    software_silent_start: bool,
    desired_muted: bool,
    final_feedback: Option<FinalFeedbackState>,
    final_feedback_locked: bool,
}

impl<P: DatagramPort, O: KernelOps, B: DeviceBackend> NetworkRender<P, O, B> {
    /// Admit one trusted source epoch and exact finite end. The endpoint and
    /// clock must already be provisioned through their normal trusted path.
    pub fn admit(
        mut endpoint: MediaEndpoint<P>,
        mut platform: PlatformLayer<O>,
        mut clock: GroupClock,
        render: RenderLoop<B>,
        admission: NetworkRenderAdmission,
    ) -> Result<Self, NetworkRenderError> {
        let NetworkRenderAdmission {
            schedule,
            anchor_frame,
            final_frame,
            mapping,
            capacity_frames,
            start,
        } = admission;
        let cfg = render.config();
        if !matches!(render.state(), RenderState::Ready | RenderState::Stopped)
            || !render.control_is_exclusive()
            || !render.presentation_mapping_valid()
            || !(MIN_QUEUED_FRAMES..=MAX_QUEUED_FRAMES).contains(&capacity_frames)
            || !anchor_frame.is_multiple_of(BLOCK_FRAMES)
            || final_frame <= anchor_frame
            || schedule.epoch != clock.epoch()
            || mapping.ns_numerator == 0
            || mapping.tick_denominator == 0
            || cfg.block_frames == 0
            || cfg.period_ticks == 0
            || mapping.presentation_tolerance_ns < mapping.uncertainty_ns
            || mapping.presentation_tolerance_ns > clock.config().lock_uncertainty_ns
        {
            return Err(NetworkRenderError::Configuration);
        }
        // Admit only rates D03 can represent. Per-block phase is checked below;
        // this coarse rate bound alone does not authorize a presentation.
        let lhs = u128::from(cfg.period_ticks)
            .checked_mul(u128::from(mapping.ns_numerator))
            .and_then(|n| n.checked_mul(48_000));
        let rhs = (cfg.block_frames as u128)
            .checked_mul(1_000_000_000)
            .and_then(|n| n.checked_mul(u128::from(mapping.tick_denominator)));
        let (Some(lhs), Some(rhs)) = (lhs, rhs) else {
            return Err(NetworkRenderError::Mapping);
        };
        if lhs
            .abs_diff(rhs)
            .checked_mul(1_000_000)
            .is_none_or(|delta| {
                rhs.checked_mul(u128::from(franken_dsp::resample::HARD_MAX_RATIO_PPM))
                    .is_none_or(|limit| delta > limit)
            })
        {
            return Err(NetworkRenderError::Mapping);
        }
        // Refuse overflow rather than using the stream helper's saturating conversion.
        let end_ns = u128::from(final_frame)
            .checked_mul(62_500)
            .ok_or(NetworkRenderError::Timeline)?
            / 3;
        if end_ns > u128::from(u64::MAX) {
            return Err(NetworkRenderError::Timeline);
        }
        let first = render.next_slot().ok_or(NetworkRenderError::Mapping)?;
        // The phase baseline and the empty queue must describe the same new
        // source; accepting an already-advanced D03 would lose its input count.
        if first.source_phase.pending != PRIME_FRAMES || first.source_phase.frac != 0 {
            return Err(NetworkRenderError::Configuration);
        }
        let first_ns = mapping
            .at(first.presentation_tick)
            .ok_or(NetworkRenderError::Mapping)?;
        if first_ns
            .abs_diff(schedule.start_group_ns)
            .checked_add(mapping.uncertainty_ns)
            .is_none_or(|error| error > mapping.presentation_tolerance_ns)
        {
            return Err(NetworkRenderError::Mapping);
        }
        endpoint
            .admit_start(&mut platform, &mut clock, schedule, anchor_frame)
            .map_err(NetworkRenderError::Start)?;
        Ok(Self {
            endpoint,
            platform,
            clock,
            view: ClockViewBridge::default(),
            render,
            pcm: PreparedPcm::new(
                capacity_frames,
                anchor_frame,
                final_frame,
                schedule.start_group_ns,
            ),
            mapping,
            schedule,
            start,
            busy_deadline_ns: None,
            last_presentation_end_ns: None,
            terminal: false,
            complete: false,
            software_silent_start: false,
            desired_muted: false,
            final_feedback: None,
            final_feedback_locked: false,
        })
    }

    #[must_use]
    pub fn render_state(&self) -> RenderState {
        self.render.state()
    }
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.render.in_flight()
    }
    #[must_use]
    pub fn block_in_progress(&self) -> bool {
        self.render.block_in_progress()
    }
    #[must_use]
    pub fn render_counters(&self) -> crate::render::RenderCounters {
        self.render.counters()
    }
    #[must_use]
    pub fn queued_frames(&self) -> usize {
        self.pcm.len
    }
    #[must_use]
    pub fn verdicts(&self) -> &EngineVerdicts {
        self.endpoint.verdicts()
    }
    #[must_use]
    pub fn received_frames_pulled(&self) -> u64 {
        self.pcm.real_pulled
    }
    #[must_use]
    pub fn concealed_frames_pulled(&self) -> u64 {
        self.pcm.concealed_pulled
    }
    #[must_use]
    pub fn timeline_silence_pulled(&self) -> u64 {
        self.pcm.timeline_silence_pulled
    }
    #[must_use]
    pub fn final_padding_pulled(&self) -> u64 {
        self.pcm.padding_pulled
    }

    fn fresh_clock(&mut self) -> Result<franken_stream::playout::ClockView, NetworkRenderError> {
        if self.clock.epoch() != self.schedule.epoch
            || self.platform.clock_resolution_ns() > self.clock.config().timer_resolution_ns
        {
            return Err(NetworkRenderError::Clock);
        }
        let local = match self.platform.now_ns() {
            Ok(local) => local,
            Err(_) => {
                self.clock.report_clock_fault();
                return Err(NetworkRenderError::Clock);
            }
        };
        if matches!(self.clock.tick(local), Output::Muted(_)) {
            return Err(NetworkRenderError::Clock);
        }
        let view = self.view.at_local(&self.clock, local);
        if !view.usable {
            return Err(NetworkRenderError::Clock);
        }
        Ok(view)
    }

    fn invalidate(&mut self) {
        self.revoke_final_feedback();
        self.pcm.clear();
        self.terminal = true;
        match self.render.state() {
            RenderState::Ready => {
                let _ = self.render.cancel_prepared();
            }
            RenderState::Running | RenderState::Muted => {
                let _ = self.render.cancel();
            }
            _ => {}
        }
    }

    // Controls use the same fresh authority, source phase, mapping and
    // deadline boundary as a subsequent render, without ticking the device.
    fn control_ready(&mut self) -> Result<(), NetworkRenderError> {
        if self.terminal {
            return Err(NetworkRenderError::Ended);
        }
        match self.control_ready_inner() {
            Ok(()) => Ok(()),
            Err(NetworkRenderError::Ended) => Err(NetworkRenderError::Ended),
            Err(error) => {
                self.invalidate();
                Err(error)
            }
        }
    }

    fn control_ready_inner(&mut self) -> Result<(), NetworkRenderError> {
        let view = self.fresh_clock()?;
        if !self.render.presentation_mapping_valid() {
            return Err(NetworkRenderError::Mapping);
        }
        let latest = view
            .group_ns
            .checked_add(view.uncertainty_ns)
            .ok_or(NetworkRenderError::Clock)?;
        if self
            .busy_deadline_ns
            .is_some_and(|deadline| latest > deadline)
        {
            return Err(NetworkRenderError::Timeline);
        }
        let slot = self.render.next_slot().ok_or(NetworkRenderError::Mapping)?;
        let pulled = self
            .pcm
            .real_pulled
            .checked_add(self.pcm.concealed_pulled)
            .and_then(|n| n.checked_add(self.pcm.timeline_silence_pulled))
            .and_then(|n| n.checked_add(self.pcm.padding_pulled))
            .ok_or(NetworkRenderError::Timeline)?;
        let position = position_q32(self.pcm.anchor_frame, pulled, slot.source_phase)
            .ok_or(NetworkRenderError::Timeline)?;
        if self.pcm.next_frame == self.pcm.final_frame {
            let padding = 2_usize.saturating_sub(self.pcm.padding_pulled as usize);
            let available = self
                .pcm
                .len
                .checked_add(padding)
                .ok_or(NetworkRenderError::Capacity)?;
            let first = usize::try_from(slot.first_output_source_frames)
                .map_err(|_| NetworkRenderError::Capacity)?;
            if position >= (u128::from(self.pcm.final_frame) << 32) || first > available {
                return Err(NetworkRenderError::Ended);
            }
        }
        let expected = position_group_ns(
            self.pcm.anchor_frame,
            self.schedule.start_group_ns,
            position,
        )
        .ok_or(NetworkRenderError::Mapping)?;
        let presentation = self
            .mapping
            .at(slot.presentation_tick)
            .ok_or(NetworkRenderError::Mapping)?;
        if presentation
            .abs_diff(expected)
            .checked_add(self.mapping.uncertainty_ns)
            .is_none_or(|error| error > self.mapping.presentation_tolerance_ns)
        {
            return Err(NetworkRenderError::Mapping);
        }
        let deadline = self
            .mapping
            .at(slot.deadline_tick)
            .ok_or(NetworkRenderError::Mapping)?;
        if latest > deadline.saturating_sub(self.mapping.uncertainty_ns) {
            return Err(NetworkRenderError::Timeline);
        }
        Ok(())
    }

    /// Seal this renderer into the composed control owner. This rejects unknown
    /// inherited HAL custody and does not claim a physically muted amplifier.
    pub(crate) fn arm_software_silent_start(&mut self) -> Result<(), NetworkRenderError> {
        if !self.render.silent_start_admissible() {
            return Err(NetworkRenderError::Configuration);
        }
        self.software_silent_start = true;
        self.desired_muted = true;
        Ok(())
    }

    /// The existing admitted clock policy permits bounded usable holdover.
    /// Control remains available after output cancellation while the same owned
    /// clock is valid; this neither reopens PCM nor starts the renderer.
    pub(crate) fn usable_clock_view(
        &mut self,
    ) -> Result<franken_stream::playout::ClockView, NetworkRenderError> {
        self.fresh_clock()
    }

    /// An independently fresh, locked reading from this renderer's owned clock.
    /// Callers still need to account for its uncertainty at all time fences.
    pub(crate) fn join_clock_view(
        &mut self,
    ) -> Result<franken_stream::playout::ClockView, NetworkRenderError> {
        if self.terminal
            || self.clock.epoch() != self.schedule.epoch
            || self.platform.clock_resolution_ns() > self.clock.config().timer_resolution_ns
        {
            return Err(NetworkRenderError::Clock);
        }
        let local = match self.platform.now_ns() {
            Ok(now) => now,
            Err(_) => {
                self.clock.report_clock_fault();
                self.invalidate();
                return Err(NetworkRenderError::Clock);
            }
        };
        let output = self.clock.tick(local);
        if matches!(output, Output::Muted(_)) || self.clock.status(local) != ClockStatus::Locked {
            return Err(NetworkRenderError::Clock);
        }
        let view = self.view.at_local(&self.clock, local);
        if !view.usable {
            return Err(NetworkRenderError::Clock);
        }
        Ok(view)
    }

    pub(crate) fn stop_report(&self) -> crate::render::StopReport {
        self.render.stop_report()
    }

    /// The already-admitted buffer/format path is still prepared and its
    /// owned backend declares bounded stop/flush protocol support.
    pub(crate) fn pending_join_ready(&self) -> bool {
        !self.terminal
            && self.software_silent_start
            && self.render.has_initial_role()
            && self.render.prepared_join_ready()
    }

    pub(crate) fn bound_epoch(&self) -> u64 {
        self.schedule.epoch
    }

    /// A terminal source includes cancellation and faults, not just EOF.
    pub(crate) fn is_terminal(&self) -> bool {
        self.terminal
    }

    /// The leader identity of the owned, provisioned group clock.
    pub(crate) fn bound_clock_leader(&self) -> u64 {
        self.clock.leader()
    }

    pub(crate) fn protection_profile_id(&self) -> &str {
        self.render.dsp().profile_id()
    }

    pub(crate) fn protection_status(&self) -> franken_dsp::protection::BoardStatus {
        self.render.dsp().status()
    }

    /// A member role must describe the exact installed calibrated board, not
    /// a different profile that happens to reuse its public profile ID.
    pub(crate) fn matches_admitted_profile(
        &self,
        profile: &franken_board_profile::BoardProfile,
    ) -> bool {
        let dsp = self.render.dsp();
        !dsp.has_pending_switch()
            && dsp.profile_id() == profile.profile_id
            && dsp.profile_digest() == Some(profile.integrity_sha256.as_bytes())
            && matches!(dsp.status(), franken_dsp::protection::BoardStatus::Active)
    }

    /// Bind the role before the first protected source block is rendered.
    pub(crate) fn can_bind_initial_role(&self, plan: franken_dsp::volume::RolePlan) -> bool {
        !self.terminal && self.render.can_bind_initial_role(plan)
    }

    pub(crate) fn bind_initial_role(
        &mut self,
        plan: franken_dsp::volume::RolePlan,
    ) -> Result<(), NetworkRenderError> {
        if self.terminal {
            return Err(NetworkRenderError::Ended);
        }
        self.render
            .bind_initial_role(plan)
            .map_err(NetworkRenderError::Render)
    }

    /// Apply policy only after the same live clock and mapping gate used by
    /// ordinary controls. A prepared renderer records the request for its first
    /// software-silent start; no audio or hardware transition occurs here.
    pub(crate) fn apply_owned_policy(
        &mut self,
        gain: f32,
        muted: bool,
    ) -> Result<(), NetworkRenderError> {
        self.control_ready()?;
        if !matches!(
            self.render.state(),
            RenderState::Ready | RenderState::Stopped | RenderState::Running | RenderState::Muted
        ) {
            return Err(NetworkRenderError::Configuration);
        }
        self.render.set_gain(gain);
        match self.render.state() {
            RenderState::Ready | RenderState::Stopped => self.desired_muted = muted,
            RenderState::Running | RenderState::Muted => {
                if muted {
                    self.render.mute().map_err(NetworkRenderError::Render)?;
                } else {
                    self.render.unmute().map_err(NetworkRenderError::Render)?;
                }
                self.desired_muted = muted;
            }
            _ => return Err(NetworkRenderError::Configuration),
        }
        Ok(())
    }

    /// Set the renderer's user gain; D02 clamps it and slews the applied gain.
    /// Already-rendered or device-submitted blocks are unaffected.
    pub fn set_gain(&mut self, gain: f32) -> Result<f32, NetworkRenderError> {
        self.control_ready()?;
        Ok(self.render.set_gain(gain))
    }

    /// Request D02's mute ramp on subsequent renders. Submitted device
    /// and already-rendered buffers remain irrevocable; this does not claim
    /// immediate hardware mute.
    pub fn mute(&mut self) -> Result<(), NetworkRenderError> {
        self.control_ready()?;
        self.render.mute().map_err(NetworkRenderError::Render)
    }

    /// Resume protected rendering only while the live authority remains valid.
    pub fn unmute(&mut self) -> Result<(), NetworkRenderError> {
        self.control_ready()?;
        self.render.unmute().map_err(NetworkRenderError::Render)
    }

    /// Poll actual carrier ingress, preserving authentication and replay refusals.
    pub fn poll(&mut self) -> Result<PollReport, NetworkRenderError> {
        if self.terminal {
            return Err(NetworkRenderError::Ended);
        }
        if let Err(error) = self.fresh_clock() {
            self.invalidate();
            return Err(error);
        }
        let report = self.endpoint.poll(&mut self.platform, &mut self.clock);
        if let Err(error) = self.fresh_clock() {
            self.invalidate();
            return Err(error);
        }
        Ok(report)
    }

    /// Report already consumed carrier credit from the actual receiver.
    pub fn report(&mut self) -> Result<(), NetworkRenderError> {
        if self.terminal {
            return Err(NetworkRenderError::Ended);
        }
        if let Err(error) = self.fresh_clock() {
            self.invalidate();
            return Err(error);
        }
        self.endpoint
            .report()
            .map_err(|_| NetworkRenderError::Preparation)
    }

    /// Configure one bounded final-credit retry budget before the renderer runs.
    /// No configuration or revocation can be reset for this owner.
    pub fn enable_final_feedback(
        &mut self,
        config: FinalFeedbackConfig,
    ) -> Result<(), NetworkRenderError> {
        if self.final_feedback_locked
            || self.terminal
            || self.render.state() != RenderState::Ready
            || !(10_000_000..=1_000_000_000).contains(&config.interval_ns)
            || config.grace_ns < config.interval_ns
            || config.grace_ns > 5_000_000_000
            || !(1..=16).contains(&config.max_reports)
        {
            return Err(NetworkRenderError::Configuration);
        }
        self.final_feedback_locked = true;
        self.final_feedback = Some(FinalFeedbackState {
            config,
            deadline_ns: None,
            next_due_ns: None,
            stream: 0,
            epoch: 0,
            consumed_next: 0,
            sent: 0,
            expired: false,
        });
        Ok(())
    }

    /// Permanently revoke this owner's optional final feedback without touching audio.
    pub fn revoke_final_feedback(&mut self) {
        self.final_feedback_locked = true;
        self.final_feedback = None;
    }

    fn arm_final_feedback(&mut self, view: franken_stream::playout::ClockView) {
        let Some(grace) = self
            .final_feedback
            .as_ref()
            .map(|state| state.config.grace_ns)
        else {
            return;
        };
        // The true transition may be as early as the lower bound. A later
        // upper-bound observation must fit strictly inside that grace period.
        let Some(deadline) = view
            .group_ns
            .checked_sub(view.uncertainty_ns)
            .and_then(|earliest| earliest.checked_add(grace))
        else {
            self.revoke_final_feedback();
            return;
        };
        let feedback = self.final_feedback.as_mut().expect("feedback not removed");
        feedback.deadline_ns = Some(deadline);
        feedback.stream = self.endpoint.carrier().stream_id().get();
        feedback.epoch = self.endpoint.carrier().epoch();
        feedback.consumed_next = self.endpoint.carrier().consumed_next();
    }

    /// Re-advertise only the receiver's actual final credit during natural
    /// drain or after stop. This does not ingest media or acknowledge HAL stop.
    pub fn final_feedback(&mut self) -> Result<FinalFeedbackOutcome, NetworkRenderError> {
        self.final_feedback_if(|_| true)
    }

    /// Check the caller's authority against the same freshly sampled upper
    /// group-time bound used by this send. The permit must be bounded and
    /// nonblocking; it is not an atomic real-time or zero-latency guarantee.
    pub fn final_feedback_if(
        &mut self,
        permit: impl FnOnce(u64) -> bool,
    ) -> Result<FinalFeedbackOutcome, NetworkRenderError> {
        let Some(state) = self.final_feedback.as_ref() else {
            return Ok(FinalFeedbackOutcome::Disabled);
        };
        if self.render.state() == RenderState::Faulted || (self.terminal && !self.complete) {
            self.revoke_final_feedback();
            return Ok(FinalFeedbackOutcome::Disabled);
        }
        if state.expired {
            return Ok(FinalFeedbackOutcome::Expired);
        }
        if !self.complete {
            return Ok(FinalFeedbackOutcome::NotDue);
        }
        if !matches!(
            self.render.state(),
            RenderState::Draining | RenderState::Stopped
        ) {
            self.revoke_final_feedback();
            return Ok(FinalFeedbackOutcome::Disabled);
        }
        let view = match self.fresh_clock() {
            Ok(view) => view,
            Err(error) => {
                self.revoke_final_feedback();
                return Err(error);
            }
        };
        let state = self.final_feedback.as_ref().expect("feedback not removed");
        let Some(deadline) = state.deadline_ns else {
            self.revoke_final_feedback();
            return Ok(FinalFeedbackOutcome::Disabled);
        };
        let carrier = self.endpoint.carrier();
        if carrier.stream_id().get() != state.stream
            || carrier.epoch() != state.epoch
            || state.epoch != self.schedule.epoch
            || state.consumed_next == 0
            || carrier.consumed_next() != state.consumed_next
        {
            self.revoke_final_feedback();
            return Ok(FinalFeedbackOutcome::Disabled);
        }
        let Some(latest) = view.group_ns.checked_add(view.uncertainty_ns) else {
            self.revoke_final_feedback();
            return Err(NetworkRenderError::Clock);
        };
        if latest >= deadline || state.sent >= state.config.max_reports {
            self.final_feedback
                .as_mut()
                .expect("feedback not removed")
                .expired = true;
            return Ok(FinalFeedbackOutcome::Expired);
        }
        if state
            .next_due_ns
            .is_some_and(|due| view.group_ns.saturating_sub(view.uncertainty_ns) < due)
        {
            return Ok(FinalFeedbackOutcome::NotDue);
        }
        let Some(next_due) = latest.checked_add(state.config.interval_ns) else {
            self.revoke_final_feedback();
            return Err(NetworkRenderError::Clock);
        };
        if !permit(latest) {
            self.revoke_final_feedback();
            return Ok(FinalFeedbackOutcome::Disabled);
        }
        if self.endpoint.report().is_err() {
            self.revoke_final_feedback();
            return Err(NetworkRenderError::Preparation);
        }
        let state = self.final_feedback.as_mut().expect("feedback not removed");
        state.sent += 1;
        state.next_due_ns = Some(next_due);
        Ok(FinalFeedbackOutcome::Sent)
    }

    /// Prepare at most one network block and advance at most one device tick.
    /// Callers supply the admitted timing model and continue driving this method.
    pub fn step<T: TimingModel>(
        &mut self,
        timing: &mut T,
    ) -> Result<OwnerStep, NetworkRenderError> {
        if self.terminal {
            if self.complete && self.render.state() == RenderState::Stopped {
                return Ok(OwnerStep::Complete);
            }
            if self.complete && self.render.state() == RenderState::Draining {
                let tick = self
                    .render
                    .tick_with_start_permission(&mut self.pcm, timing, false);
                if self.render.state() == RenderState::Faulted {
                    self.revoke_final_feedback();
                    return Err(NetworkRenderError::Preparation);
                }
                return Ok(OwnerStep::Tick(tick));
            }
            return Err(NetworkRenderError::Ended);
        }
        match self.step_inner(timing) {
            Ok(value) => Ok(value),
            Err(error) => {
                self.invalidate();
                Err(error)
            }
        }
    }

    fn step_inner<T: TimingModel>(
        &mut self,
        timing: &mut T,
    ) -> Result<OwnerStep, NetworkRenderError> {
        let mut view = self.fresh_clock()?;
        if !self.render.presentation_mapping_valid() {
            return Err(NetworkRenderError::Mapping);
        }
        // Do not consume an N04 decision unless its entire timeline slot fits.
        if self.pcm.next_frame < self.pcm.final_frame {
            let remaining = self.pcm.final_frame - self.pcm.next_frame;
            let needed = usize::try_from(remaining.min(BLOCK_FRAMES))
                .map_err(|_| NetworkRenderError::Timeline)?;
            if self.pcm.capacity - self.pcm.len >= needed {
                let mut bytes = [0; BLOCK_PAYLOAD_BYTES];
                let prepared = self
                    .endpoint
                    .prepare(&mut self.platform, &mut self.clock, &mut bytes)
                    .map_err(|_| NetworkRenderError::Clock)?;
                view = self.fresh_clock()?;
                match prepared {
                    Preparation::Prepared(block) => {
                        if view
                            .group_ns
                            .checked_add(view.uncertainty_ns)
                            .ok_or(NetworkRenderError::Clock)?
                            > block.decision.submit_deadline_ns
                        {
                            return Err(NetworkRenderError::Timeline);
                        }
                        self.pcm.offer(block, &bytes)?;
                    }
                    Preparation::Quiet {
                        poll: Poll::Pending,
                        ..
                    } => {}
                    Preparation::Quiet { .. } => return Err(NetworkRenderError::Timeline),
                    Preparation::Refused(_)
                    | Preparation::TimingUnavailable
                    | Preparation::Misconfigured(_) => return Err(NetworkRenderError::Clock),
                }
            }
        }

        let slot = self.render.next_slot().ok_or(NetworkRenderError::Mapping)?;
        let pulled = self
            .pcm
            .real_pulled
            .checked_add(self.pcm.concealed_pulled)
            .and_then(|n| n.checked_add(self.pcm.timeline_silence_pulled))
            .and_then(|n| n.checked_add(self.pcm.padding_pulled))
            .ok_or(NetworkRenderError::Timeline)?;
        let position = position_q32(self.pcm.anchor_frame, pulled, slot.source_phase)
            .ok_or(NetworkRenderError::Timeline)?;
        let eof = self.pcm.next_frame == self.pcm.final_frame;
        let padding_left = if eof {
            2_usize.saturating_sub(self.pcm.padding_pulled as usize)
        } else {
            0
        };
        let available_inputs = self
            .pcm
            .len
            .checked_add(padding_left)
            .ok_or(NetworkRenderError::Capacity)?;
        let first_required = usize::try_from(slot.first_output_source_frames)
            .map_err(|_| NetworkRenderError::Capacity)?;
        let history_drained = eof
            && (position >= (u128::from(self.pcm.final_frame) << 32)
                || first_required > available_inputs);
        if !history_drained {
            let expected = position_group_ns(
                self.pcm.anchor_frame,
                self.schedule.start_group_ns,
                position,
            )
            .ok_or(NetworkRenderError::Mapping)?;
            let presentation = self
                .mapping
                .at(slot.presentation_tick)
                .ok_or(NetworkRenderError::Mapping)?;
            if presentation
                .abs_diff(expected)
                .checked_add(self.mapping.uncertainty_ns)
                .is_none_or(|error| error > self.mapping.presentation_tolerance_ns)
            {
                return Err(NetworkRenderError::Mapping);
            }
        }
        let tick_group = self
            .mapping
            .at(slot.now.checked_add(1).ok_or(NetworkRenderError::Mapping)?)
            .ok_or(NetworkRenderError::Mapping)?;
        // The earliest possible group time must have reached this device tick.
        let tick_latest = tick_group
            .checked_add(self.mapping.uncertainty_ns)
            .ok_or(NetworkRenderError::Mapping)?;
        let view_latest = view
            .group_ns
            .checked_add(view.uncertainty_ns)
            .ok_or(NetworkRenderError::Clock)?;
        if view.group_ns.saturating_sub(view.uncertainty_ns) < tick_latest {
            return Ok(OwnerStep::Waiting);
        }
        if self
            .busy_deadline_ns
            .is_some_and(|deadline| view_latest > deadline)
        {
            return Err(NetworkRenderError::Timeline);
        }
        let required = usize::try_from(slot.required_source_frames)
            .map_err(|_| NetworkRenderError::Capacity)?;
        let available = if eof {
            !history_drained
        } else {
            self.pcm.len >= required
        };
        let tail_presented_by_schedule = self.last_presentation_end_ns.is_some_and(|end| {
            end.checked_add(self.mapping.uncertainty_ns)
                .is_some_and(|latest| view.group_ns.saturating_sub(view.uncertainty_ns) >= latest)
        });
        if history_drained && !slot.in_progress && tail_presented_by_schedule {
            self.render.cancel().map_err(NetworkRenderError::Render)?;
            self.terminal = true;
            self.complete = true;
            self.arm_final_feedback(view);
            return Ok(OwnerStep::Waiting);
        }
        let deadline = self
            .mapping
            .at(slot.deadline_tick)
            .ok_or(NetworkRenderError::Mapping)?;
        if !history_drained {
            if view_latest > deadline.saturating_sub(self.mapping.uncertainty_ns) {
                return Err(NetworkRenderError::Timeline);
            }
            if !available && !slot.in_progress {
                return Ok(OwnerStep::Waiting);
            }
        }
        if matches!(
            self.render.state(),
            RenderState::Ready | RenderState::Stopped
        ) {
            if !available || history_drained {
                return Ok(OwnerStep::Waiting);
            }
            if self.software_silent_start {
                self.render
                    .start_silent(self.start)
                    .map_err(NetworkRenderError::Render)?;
                if !self.desired_muted {
                    self.render.unmute().map_err(NetworkRenderError::Render)?;
                }
            } else {
                self.render
                    .start(self.start)
                    .map_err(NetworkRenderError::Render)?;
            }
        }
        self.pcm.padding_available = if eof && !history_drained {
            required.saturating_sub(self.pcm.len).min(padding_left)
        } else {
            0
        };
        let next_presentation_end_ns = if available && !history_drained {
            let end_tick = slot
                .presentation_tick
                .checked_add(self.render.config().period_ticks)
                .ok_or(NetworkRenderError::Mapping)?;
            Some(
                self.mapping
                    .at(end_tick)
                    .ok_or(NetworkRenderError::Mapping)?,
            )
        } else {
            None
        };
        let tick = self.render.tick_with_start_permission(
            &mut self.pcm,
            timing,
            available && !history_drained,
        );
        self.pcm.padding_available = 0;
        if tick.finished.is_some() {
            self.busy_deadline_ns = None;
        }
        if tick.started.is_some() && self.render.block_in_progress() {
            let mapped = deadline.saturating_sub(self.mapping.uncertainty_ns);
            self.busy_deadline_ns = Some(mapped);
        }
        if tick.started.is_some() {
            self.last_presentation_end_ns = next_presentation_end_ns;
        }
        if !self.render.presentation_mapping_valid()
            || self.render.state() == RenderState::Faulted
            || tick
                .finished
                .is_some_and(|(_, outcome)| outcome != BlockOutcome::OnTime)
        {
            return Err(NetworkRenderError::Preparation);
        }
        Ok(OwnerStep::Tick(tick))
    }

    /// Stop immediately: discard only unsubmitted PCM and ask the actual HAL
    /// session to mute/abort. Submitted buffers remain with the session.
    pub fn cancel(&mut self) -> Result<(), NetworkRenderError> {
        self.revoke_final_feedback();
        self.pcm.clear();
        self.terminal = true;
        match self.render.state() {
            RenderState::Ready => self
                .render
                .cancel_prepared()
                .map_err(NetworkRenderError::Render)?,
            RenderState::Running | RenderState::Muted => {
                self.render.cancel().map_err(NetworkRenderError::Render)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Drive only the existing cancel/drain acknowledgment path.
    pub fn drain_tick<T: TimingModel>(
        &mut self,
        timing: &mut T,
    ) -> Result<TickReport, NetworkRenderError> {
        if !self.terminal || self.render.state() != RenderState::Draining {
            return Err(NetworkRenderError::Ended);
        }
        Ok(self.render.tick(&mut self.pcm, timing))
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod mapping_tests {
    use super::{PreparedPcm, TickMapping, position_group_ns, position_q32};
    use crate::media_playout::{PreparedBlock, Release};
    use franken_dsp::resample::{DriftResampler, FrameSource, ResamplerConfig};
    use franken_stream::playout::{BLOCK_PAYLOAD_BYTES, Decision, Outcome, frames_to_ns};

    #[test]
    fn rational_tick_mapping_handles_both_sides_and_rejects_invalid_arithmetic() {
        let map = TickMapping {
            anchor_tick: 9,
            anchor_group_ns: 10_000_000,
            ns_numerator: 1_000_000,
            tick_denominator: 3,
            uncertainty_ns: 0,
            presentation_tolerance_ns: 1,
        };
        assert_eq!(map.at(9), Some(10_000_000));
        assert_eq!(map.at(13), Some(11_333_333));
        assert_eq!(map.at(5), Some(8_666_666));
        assert_eq!(
            TickMapping {
                tick_denominator: 0,
                ..map
            }
            .at(9),
            None
        );
        assert_eq!(
            TickMapping {
                anchor_group_ns: 0,
                ..map
            }
            .at(5),
            None
        );
        assert_eq!(
            TickMapping {
                anchor_tick: 0,
                anchor_group_ns: u64::MAX,
                ..map
            }
            .at(1),
            None
        );
    }

    #[test]
    fn projected_phase_tracks_real_d03_plan_across_both_drift_signs() {
        for ppb in [-500_000, 0, 500_000] {
            let mut d03 =
                DriftResampler::with_initial_ppb(ResamplerConfig::default(), ppb).unwrap();
            let mut pulled = 0;
            let mut previous = position_q32(256, pulled, d03.phase_state()).unwrap();
            assert_eq!(previous, 256_u128 << 32);
            assert_eq!(
                position_group_ns(256, 1_000_000_000, previous),
                Some(1_000_000_000)
            );
            for _ in 0..512 {
                pulled += d03.plan(1);
                let position = position_q32(256, pulled, d03.phase_state()).unwrap();
                assert!(position > previous);
                previous = position;
            }
            assert!(position_group_ns(256, 1_000_000_000, previous).unwrap() > 1_000_000_000);
        }
        assert_eq!(position_group_ns(256, 0, 0), None);
    }

    #[test]
    fn received_and_concealed_frames_remain_distinct_in_the_real_queue() {
        let mut queue = PreparedPcm::new(514, 0, 512, 1_000_000_000);
        let mut bytes = [0_u8; BLOCK_PAYLOAD_BYTES];
        for frame in bytes.as_chunks_mut::<4>().0 {
            frame.copy_from_slice(&[0x40, 0, 0x40, 0]);
        }
        for (block, outcome) in [(0, Outcome::Real), (1, Outcome::Concealed { run: 1 })] {
            let pts = 1_000_000_000 + frames_to_ns(block * 256);
            queue
                .offer(
                    PreparedBlock {
                        decision: Decision {
                            block,
                            outcome,
                            presentation_ns: pts,
                            frames: 256,
                            gap_before_ns: 0,
                            submit_deadline_ns: pts - 1_000_000,
                            late_by_ns: 0,
                        },
                        release: Release::Audible,
                    },
                    &bytes,
                )
                .unwrap();
        }
        for _ in 0..512 {
            assert_eq!(queue.pull(), Some([0.5, 0.5]));
        }
        assert_eq!(
            (
                queue.real_pulled,
                queue.concealed_pulled,
                queue.timeline_silence_pulled
            ),
            (256, 256, 0)
        );
        assert_eq!(queue.pull(), None);
    }
}
