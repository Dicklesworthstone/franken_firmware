//! The default media consumer: authenticated N01 PCM to the N04 playout engine, prepared for a scheduled downstream sink
//! only while the N03 group clock allows it (`N03` / `ffw-u07`).
//!
//! Nothing here is new protocol. It composes, in this order, the pieces that already exist:
//!
//! * ingress: [`StreamReceiver::accept`] (MAC, stream, epoch, replay window) -> [`MediaPacket::from_authenticated`] ->
//!   [`PlayoutEngine::on_packet`], with its [`franken_stream::playout::ClockView`] built by [`ClockViewBridge::at_local`] from the group
//!   clock and the admitted platform's monotonic reading ([`PlatformLayer::now_ns`]). The sender's timestamps reach the
//!   engine exactly as N01 carried them: they are covered by the MAC, so a changed one is an authentication failure and
//!   never an engine input, and one that is authentic but off the agreed timeline is the engine's own `TimelineMismatch`.
//! * preparation: [`GroupClock::tick`] first, then the engine's decision for at most one block. **Preparing a block is not
//!   playing it.** The bytes handed back are PCM for a downstream sink to present at the decision's group-clock
//!   `presentation_ns`; this module emits nothing to a DAC. The engine decides a block at its cutoff, which is *before*
//!   the block's presentation by the admitted work, the submission lead and the clock's uncertainty, so a block of a
//!   start that is still ahead has to be decided while the clock is [`Output::Armed`] or the start's first block is
//!   lost whenever the board's output delay is shorter than that margin (the standard configuration's is zero). The two
//!   states are therefore kept apart in the result: [`Release::Armed`] means "prepared for a start that has not been
//!   reached", [`Release::Audible`] means "the output is audible now". In every other state ([`Output::Muted`]: no
//!   admitted start, an expired authority or clock, a reset, a fault) the buffer is zero and the engine is not asked,
//!   even while the clock's status is Locked.
//!
//! A prepared block is a reservation and never a promise: if `prepare` returns a clock error or
//! [`Preparation::invalidates_prepared`] is true, discard outstanding scheduled blocks. Clock or
//! resolution failures from ingress or start admission likewise invalidate them. Authentication,
//! replay and stale-packet refusals do not: hostile datagrams cannot revoke admitted audio. A
//! rejected replacement schedule also leaves the existing admitted stream intact.
//! The clock must be admitted through [`MediaPlayout::admit_start`], which
//! anchors the engine's timeline at the clock's start; admitting the clock behind its back breaks that agreement.
//!
//! The platform's reported clock resolution is checked at the same boundary, before any call that needs a local time. The
//! group clock's uncertainty arithmetic assumes timestamps no coarser than its configured `timer_resolution_ns`; a platform
//! whose admitted capability matrix reports a coarser monotonic resolution ([`PlatformLayer::clock_resolution_ns`]) is a
//! configuration mismatch, reported as [`ResolutionMismatch`] and never as a clock failure. Nothing is consumed, nothing is
//! prepared, and the group clock is muted once per mismatch (its fit is dropped, never reinterpreted under the coarser
//! tick); sound needs a clock configured for the platform, a new lock and a new start. The resolution is the platform's
//! *reported* capability, not a measurement of the tick.
//!
//! The platform clock is the only local time. If it fails, in any way, [`GroupClock::report_clock_fault`] is called before
//! the error is returned: the fit is dropped, the output is muted, and preparation resumes only after the clock has locked
//! again **and** [`MediaPlayout::admit_start`] has admitted a start again. A datagram is not consumed from the replay
//! window when the clock fails first.
//!
//! What this is not: it does not authenticate clock probes (the caller feeds `GroupClock::on_response` only with responses
//! its own control path authenticated), it never treats a raw probe response as authenticated, and it keeps no schedule of
//! its own: the epoch, the leader, the authority's expiry and the start come from the caller's trusted control path.
//! A passing test here is a statement about this policy over scripted time and a scripted kernel clock; it says nothing
//! about a DAC, a board or acoustic alignment.

use franken_clock::group::{
    GroupClock, GroupClockError, MuteReason, Output, StartPlan, StartReject as ClockStartReject,
    StartSchedule,
};
use franken_platform::clock::ClockError;
use franken_platform::layer::PlatformLayer;
use franken_platform::ops::KernelOps;
use franken_platform::{MemoryBudgetLedger, PlatformAdmissionError};
use franken_stream::playout::{
    Admission, AdmitError, BLOCK_PAYLOAD_BYTES, Decision, LogConfig, MediaPacket, Outcome,
    PlayoutConfig, PlayoutEngine, PlayoutProfile, PlayoutStats, Poll,
    StartReject as EngineStartReject,
};
use franken_stream::{ReceiverCounters, StreamError, StreamId, StreamReceiver};

use crate::clock_view::ClockViewBridge;

/// Why a datagram did not reach the playout engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaRefusal {
    /// Selected experimental N06 framing/repair refused it; baseline N01 is unchanged.
    Fec(franken_stream::fec::Refusal),
    /// The stream receiver refused it (structure, MAC, stream, epoch, replay window, feature). Nothing but its counters
    /// changed, and the engine never saw it.
    Stream(StreamError),
    /// Authenticated, but not a media block. This path has no repair route, so it is not offered to the engine.
    NotMedia,
    /// The platform clock failed first. The group clock was told, the datagram was not consumed from the replay window.
    Clock(ClockError),
    /// The platform's reported resolution is coarser than the group clock is configured for. Not a clock failure; the
    /// datagram was not consumed from the replay window.
    Resolution(ResolutionMismatch),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthenticatedFormat {
    N01Media,
    N06Source,
    N06Retransmit,
    N06RepairSymbol,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedIngress {
    pub stream: u64,
    pub origin_ns: u64,
    pub admission: Option<Admission>,
    pub sequence: u64,
    pub source_epoch: u64,
    pub wire_bytes: usize,
    pub format: AuthenticatedFormat,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IngressIdentity {
    pub stream: u64,
    pub epoch: u64,
    pub origin_ns: u64,
    pub format: AuthenticatedFormat,
    pub sequence: u64,
}
impl AuthenticatedIngress {
    pub fn identity(&self) -> IngressIdentity {
        IngressIdentity {
            stream: self.stream,
            epoch: self.source_epoch,
            origin_ns: self.origin_ns,
            format: self.format,
            sequence: self.sequence,
        }
    }
    pub fn credit_key(&self) -> IngressIdentity {
        self.identity()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostFecAdmitError {
    Profile(franken_stream::fec::Refusal),
    Binding,
    AlreadySelected,
    Memory(MediaAdmitError),
    Capacity { required: usize, available: usize },
    Allocation { requested: usize },
}

/// The platform reports a monotonic resolution coarser than the group clock's configuration assumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolutionMismatch {
    /// [`PlatformLayer::clock_resolution_ns`]: what the admitted capability matrix reports for this platform.
    pub reported_ns: u64,
    /// The group clock's `timer_resolution_ns`. A platform at or below this is permitted.
    pub configured_ns: u64,
}

/// Why no local time was available (kept private; each public path reports it in its own refusal type).
enum LocalTimeRefusal {
    Clock(ClockError),
    Resolution(ResolutionMismatch),
}

impl LocalTimeRefusal {
    fn for_ingest(self) -> MediaRefusal {
        match self {
            Self::Clock(error) => MediaRefusal::Clock(error),
            Self::Resolution(mismatch) => MediaRefusal::Resolution(mismatch),
        }
    }

    fn for_start(self) -> StartRefusal {
        match self {
            Self::Clock(error) => StartRefusal::Clock(error),
            Self::Resolution(mismatch) => StartRefusal::Resolution(mismatch),
        }
    }
}

/// Why a start was not admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartRefusal {
    Fec(franken_stream::fec::Refusal),
    /// The platform clock failed; the group clock was told.
    Clock(ClockError),
    /// The platform's reported resolution is coarser than the group clock is configured for. The engine was not touched.
    Resolution(ResolutionMismatch),
    /// The group clock refused the schedule (stale or future epoch, not locked, too far ahead, too late, ...). The engine
    /// was not touched, so a stream that is playing keeps playing.
    Admission(ClockStartReject),
    /// The engine refused the stream's anchor (stale epoch, misaligned frame, bad anchor). The clock was not armed.
    Stream(EngineStartReject),
}

/// Where the group clock stood when a block was prepared. It is never `Muted`: nothing is prepared then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Release {
    /// An admitted start that has not been reached: the output is not audible yet and this is not sound. The sink holds
    /// the block for its `presentation_ns`, which by the engine's anchoring is at or after the start.
    Armed {
        /// Local nanoseconds until the clock's own audible target, as `Output::Armed` reports it.
        starts_in_ns: u64,
    },
    /// The output is audible now.
    Audible,
}

/// One block of PCM prepared for a scheduled downstream sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedBlock {
    /// The engine's decision: `Real` or `Concealed`. `presentation_ns` is the group time at which the sink is to present
    /// it (possibly well after now), `submit_deadline_ns` the latest group time it may still be handed on, `frames` how
    /// many frames of the buffer are PCM.
    pub decision: Decision,
    /// Armed (a start still ahead) or audible. Preparing is not playing: this module presents nothing.
    pub release: Release,
}

/// What one preparation call produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preparation {
    /// The first `decision.frames * 4` bytes of the caller's buffer are big-endian 16-bit stereo PCM (real, or the
    /// engine's attenuated concealment) and the rest of the buffer is zero.
    Prepared(PreparedBlock),
    /// The group clock allows preparation but this call produced no block: the next block is not due yet, or the engine
    /// decided silence for it (a gap, an overdue block, a skip). The buffer is zero. Drain decisions
    /// until `Poll::Pending`; other non-decision results end this drain attempt.
    Quiet {
        /// Armed or audible, as for a prepared block.
        release: Release,
        /// The engine's answer.
        poll: Poll,
    },
    /// The group clock is muted (no admitted start, an expired authority, clock or buffer, a reset, an epoch change, a
    /// fault) and the reason is the clock's own. The engine was not asked and the buffer is zero.
    Refused(MuteReason),
    /// The clock's fit may still be locked, but its monotonic playout view cannot meet the
    /// uncertainty policy (or the engine refused that view). Invalidate outstanding prepared
    /// reservations and stop this drain attempt. The buffer is zero.
    TimingUnavailable,
    /// The platform's reported resolution is coarser than the group clock is configured for: a configuration refusal,
    /// not a clock failure and not one of the clock's mute reasons. The engine was not asked and the buffer is zero.
    Misconfigured(ResolutionMismatch),
}

impl Preparation {
    /// Whether all previously prepared reservations must be discarded. A returned clock error
    /// has the same invalidating meaning. Quiet or prepared PCM is never proof of presentation.
    #[must_use]
    pub const fn invalidates_prepared(&self) -> bool {
        matches!(
            self,
            Self::Refused(_) | Self::TimingUnavailable | Self::Misconfigured(_)
        )
    }
}

/// Why a media path (or its diagnostics ring) was not admitted. Nothing is built or changed on a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaAdmitError {
    /// The platform ledger fails its own safety floor ([`MemoryBudgetLedger::verify_budget`]): the whole-system commitment leaves too
    /// little headroom, whatever the stream line holds.
    Platform(PlatformAdmissionError),
    /// The engine refused: an invalid configuration (judged first), a footprint beyond the stream-and-jitter line that is left, or an
    /// allocation the allocator could not give.
    Engine(AdmitError),
}

impl MediaAdmitError {
    /// A stable name: `memory_budget` for the platform floor, otherwise the engine's own code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Platform(_) => "memory_budget",
            Self::Engine(error) => error.code(),
        }
    }
}

/// The room the ledger's `stream_and_jitter_bytes` line leaves after `resident_elsewhere_bytes`, once the whole ledger passes its floor.
fn stream_room(
    ledger: &MemoryBudgetLedger,
    resident_elsewhere_bytes: u64,
) -> Result<usize, MediaAdmitError> {
    ledger.verify_budget().map_err(MediaAdmitError::Platform)?;
    let room = ledger
        .stream_and_jitter_bytes
        .saturating_sub(resident_elsewhere_bytes);
    Ok(usize::try_from(room).unwrap_or(usize::MAX))
}

/// Bytes an engine holds: its struct, its slot queue as the allocator kept it, and the diagnostics heap (ring and configuration
/// strings) if diagnostics are on.
#[must_use]
pub fn engine_resident_bytes(engine: &PlayoutEngine) -> u64 {
    let bytes = core::mem::size_of::<PlayoutEngine>().saturating_add(engine.owned_heap_bytes());
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

/// The one admission of a playout engine: the configuration first, then the ledger's floor, then the footprint against the stream line
/// that is left beside `resident_elsewhere_bytes`, then a fallible allocation. [`MediaPlayout::new`] and the virtual-house adapter both
/// build their engines through it.
///
/// # Errors
/// See [`MediaAdmitError`].
pub fn admit_engine(
    profile: PlayoutProfile,
    config: PlayoutConfig,
    ledger: &MemoryBudgetLedger,
    resident_elsewhere_bytes: u64,
) -> Result<PlayoutEngine, MediaAdmitError> {
    config
        .validate()
        .map_err(|e| MediaAdmitError::Engine(AdmitError::Config(e)))?;
    let room = stream_room(ledger, resident_elsewhere_bytes)?;
    PlayoutEngine::new_within(profile, config, room).map_err(MediaAdmitError::Engine)
}

/// A synthetic platform ledger for tests: the nominal 32 MiB board's commitments, with `stream_and_jitter_bytes` set explicitly.
#[cfg(test)]
pub(crate) fn synthetic_ledger(stream_and_jitter_bytes: u64) -> MemoryBudgetLedger {
    MemoryBudgetLedger {
        nominal_ram_bytes: 32 * 1024 * 1024,
        kernel_and_driver_reserved_bytes: 14 * 1024 * 1024,
        dma_ring_reserved_bytes: 512 * 1024,
        core_runtime_peak_bytes: 3 * 1024 * 1024,
        stream_and_jitter_bytes,
        native_integrations_bytes: 4 * 1024 * 1024,
        required_safety_floor_bytes: MemoryBudgetLedger::MIN_SAFETY_FLOOR_BYTES,
    }
}

/// One speaker's media path for one stream: the receiver, the playout engine and the clock view that joins them.
#[derive(Debug)]
pub struct MediaPlayout {
    /// Empty on the baseline path. Capacity is at most one and is budgeted beside this path.
    fec: Vec<franken_stream::fec::Receiver>,
    receiver: StreamReceiver,
    engine: PlayoutEngine,
    bridge: ClockViewBridge,
    clock_faults: u64,
    resolution_refusals: u64,
    /// The group clock was already muted for the current resolution mismatch; reset when a check passes.
    resolution_refused: bool,
}

impl MediaPlayout {
    /// A consumer over `receiver` (built by the caller from the negotiated session), with a fresh engine. The engine is
    /// unbound: nothing is accepted into it until [`Self::admit_start`] succeeds.
    ///
    /// Admission is part of building it. `ledger` is the platform's [`MemoryBudgetLedger`]: its whole-system floor is checked first
    /// ([`MemoryBudgetLedger::verify_budget`]), then the path must fit the ledger's `stream_and_jitter_bytes` line **beside**
    /// `resident_elsewhere_bytes`, the bytes the paths that stay resident while this one is built already hold (during a replacement,
    /// the playing path's [`Self::resident_bytes`], so the old and the new count together at the peak; 0 for the first). This path's
    /// receiver, clock bridge and counters (inline in this struct) are charged with its engine. A refusal builds nothing and touches
    /// no other path; no smaller profile is substituted. The diagnostics ring is charged separately, when it is turned on
    /// ([`Self::enable_diag_log`]).
    ///
    /// # Errors
    /// The configuration is invalid (judged first), the ledger fails its floor, the footprint does not fit the line that is left, or
    /// the allocator could not give the memory.
    pub fn new(
        receiver: StreamReceiver,
        profile: PlayoutProfile,
        config: PlayoutConfig,
        ledger: &MemoryBudgetLedger,
        resident_elsewhere_bytes: u64,
    ) -> Result<Self, MediaAdmitError> {
        let held = resident_elsewhere_bytes.saturating_add(Self::inline_bytes());
        Ok(Self {
            fec: Vec::new(),
            receiver,
            engine: admit_engine(profile, config, ledger, held)?,
            bridge: ClockViewBridge::default(),
            clock_faults: 0,
            resolution_refusals: 0,
            resolution_refused: false,
        })
    }

    /// Bytes of this struct that are not the engine: the receiver, the clock bridge and the counters.
    fn inline_bytes() -> u64 {
        u64::try_from(core::mem::size_of::<Self>() - core::mem::size_of::<PlayoutEngine>())
            .unwrap_or(u64::MAX)
    }

    /// Bytes this path holds: its inline state, the engine and its slot queue, and the diagnostics ring if one is on. This is the
    /// `resident_elsewhere_bytes` a replacement candidate must be admitted beside.
    #[must_use]
    pub fn resident_bytes(&self) -> u64 {
        engine_resident_bytes(&self.engine)
            .saturating_add(Self::inline_bytes())
            .saturating_add(
                (self.fec.capacity() * franken_stream::fec::Receiver::resident_bytes()) as u64,
            )
    }
    /// Explicit HOST-ONLY DEVELOPMENT selection after an admitted MUSIC start.
    /// No packet can select a profile or allocate its backing state. This does
    /// not admit board RAM/WCET or paced N06 transmission. One existing N04 queue.
    pub fn enable_host_fec(
        &mut self,
        config: franken_stream::fec::SessionConfig,
        ledger: &MemoryBudgetLedger,
        resident_elsewhere_bytes: u64,
    ) -> Result<(), HostFecAdmitError> {
        config.metadata(0).map_err(HostFecAdmitError::Profile)?;
        if !self
            .engine
            .matches_fec_timeline(config.epoch, config.presentation_origin_ns)
            || self.engine.snapshot().queued != 0
        {
            return Err(HostFecAdmitError::Binding);
        }
        if !self.fec.is_empty() {
            return Err(HostFecAdmitError::AlreadySelected);
        }
        let required = if self.fec.capacity() == 0 {
            franken_stream::fec::Receiver::resident_bytes()
        } else {
            0
        };
        let available =
            stream_room(ledger, resident_elsewhere_bytes).map_err(HostFecAdmitError::Memory)?;
        let held = usize::try_from(self.resident_bytes()).unwrap_or(usize::MAX);
        let total = held.saturating_add(required);
        if total > available {
            return Err(HostFecAdmitError::Capacity {
                required: total,
                available,
            });
        }
        if self.fec.capacity() == 0 {
            self.fec
                .try_reserve_exact(1)
                .map_err(|_| HostFecAdmitError::Allocation {
                    requested: required,
                })?;
        }
        let origin = config.presentation_origin_ns;
        let mut fec =
            franken_stream::fec::Receiver::new(config).map_err(HostFecAdmitError::Profile)?;
        fec.rebind(&self.engine, origin)
            .map_err(HostFecAdmitError::Profile)?;
        self.fec.push(fec);
        Ok(())
    }
    pub fn host_fec_status(&self) -> Option<franken_stream::fec::Status> {
        self.fec.first().map(|fec| fec.status())
    }
    /// Whether the explicit host-development FEC selection is active (a cheap form of `host_fec_status().is_some()`).
    #[must_use]
    pub fn host_fec_selected(&self) -> bool {
        !self.fec.is_empty()
    }
    /// The presentation origin the selected FEC receiver is bound to, if one is selected.
    #[must_use]
    pub fn host_fec_origin(&self) -> Option<u64> {
        self.fec
            .first()
            .map(franken_stream::fec::Receiver::origin_ns)
    }
    pub fn host_fec_identity(&self) -> Option<(u64, u64, u64)> {
        self.fec
            .first()
            .map(franken_stream::fec::Receiver::identity)
    }
    /// The group time until which a selected FEC receiver would answer the next datagram [`franken_stream::fec::Refusal::Protected`]
    /// (render protection), if it would. A pure query for the carrier, which leaves a datagram in the socket while this is `Some`.
    /// It reports no fault, counts nothing and consumes nothing: `None` when FEC is not selected (no clock is read, so the baseline
    /// is untouched), when the platform clock cannot be read, when the group clock is muted or its view unusable (ingest classifies
    /// and counts those), and when nothing is deferred.
    pub fn host_fec_deferral<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        clock: &mut GroupClock,
    ) -> Option<u64> {
        let fec = self.fec.first()?;
        let local = platform.now_ns().ok()?;
        if matches!(clock.output(local), Output::Muted(_)) {
            return None;
        }
        let view = self.bridge.at_local(clock, local);
        fec.deferral(&self.engine, view)
    }

    /// Turn the engine's diagnostics on (or restart them) under the same ledger line: the ring is charged beside this path's own bytes
    /// and `resident_elsewhere_bytes`, and a restart counts the old ring and the new one together. A refusal leaves the log running as
    /// it was.
    ///
    /// # Errors
    /// The ledger fails its floor, the ring does not fit what is left of the line, or the allocator could not give it.
    pub fn enable_diag_log(
        &mut self,
        log: LogConfig,
        ledger: &MemoryBudgetLedger,
        resident_elsewhere_bytes: u64,
    ) -> Result<(), MediaAdmitError> {
        let room = stream_room(ledger, resident_elsewhere_bytes)?;
        let ring = u64::try_from(self.engine.log_heap_bytes()).unwrap_or(u64::MAX);
        let own = usize::try_from(self.resident_bytes().saturating_sub(ring)).unwrap_or(usize::MAX);
        self.engine
            .enable_log_within(log, room.saturating_sub(own))
            .map_err(MediaAdmitError::Engine)
    }

    /// The one local time every path uses. First the platform's reported resolution against the group clock's configured
    /// one (no kernel call is made for a mismatch, and the group clock is muted once per mismatch, dropping its fit),
    /// then one monotonic reading, where a failure of any kind drops the group clock's fit first.
    fn local_ns<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        clock: &mut GroupClock,
    ) -> Result<u64, LocalTimeRefusal> {
        let mismatch = ResolutionMismatch {
            reported_ns: platform.clock_resolution_ns(),
            configured_ns: clock.config().timer_resolution_ns,
        };
        if mismatch.reported_ns > mismatch.configured_ns {
            for fec in &mut self.fec {
                fec.cancel();
            }
            if !self.resolution_refused {
                clock.report_clock_fault();
                self.resolution_refused = true;
            }
            self.resolution_refusals = self.resolution_refusals.saturating_add(1);
            return Err(LocalTimeRefusal::Resolution(mismatch));
        }
        self.resolution_refused = false;
        platform.now_ns().map_err(|error| {
            for fec in &mut self.fec {
                fec.cancel();
            }
            clock.report_clock_fault();
            self.clock_faults = self.clock_faults.saturating_add(1);
            LocalTimeRefusal::Clock(error)
        })
    }

    /// Take one datagram from the network. The engine buffers an admitted block whether the clock is armed or audible.
    ///
    /// # Errors
    /// [`MediaRefusal`]: the receiver, a non-media packet or the platform clock. An engine verdict that is not
    /// `Admission::Admitted` (late, duplicate, off the timeline, wrong epoch, ...) is `Ok`: the datagram was authentic and
    /// the engine's answer is the result.
    pub fn ingest<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        clock: &mut GroupClock,
        datagram: &[u8],
    ) -> Result<Admission, MediaRefusal> {
        if !self.fec.is_empty() {
            return Err(MediaRefusal::Fec(
                franken_stream::fec::Refusal::TypedIngressRequired,
            ));
        }
        self.ingest_authenticated(platform, clock, datagram)?
            .admission
            .ok_or(MediaRefusal::NotMedia)
    }
    /// One authentication/admission, returning its typed sequence for carrier
    /// credit/report. A selected N06 datagram is never parsed as an N01 header.
    pub fn ingest_authenticated<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        clock: &mut GroupClock,
        datagram: &[u8],
    ) -> Result<AuthenticatedIngress, MediaRefusal> {
        let local_ns = self
            .local_ns(platform, clock)
            .map_err(LocalTimeRefusal::for_ingest)?;
        if let Some(fec) = self.fec.first_mut() {
            if matches!(clock.output(local_ns), Output::Muted(_)) {
                fec.cancel();
                return Err(MediaRefusal::Fec(franken_stream::fec::Refusal::Clock));
            }
            let view = self.bridge.at_local(clock, local_ns);
            let event = fec
                .ingest(&mut self.engine, view, datagram)
                .map_err(MediaRefusal::Fec)?;
            let format = match event.kind {
                franken_stream::fec::IngressKind::Source => AuthenticatedFormat::N06Source,
                franken_stream::fec::IngressKind::Retransmit => AuthenticatedFormat::N06Retransmit,
                franken_stream::fec::IngressKind::RepairSymbol => {
                    AuthenticatedFormat::N06RepairSymbol
                }
            };
            return Ok(AuthenticatedIngress {
                stream: event.stream,
                origin_ns: event.origin_ns,
                admission: event.admission,
                sequence: event.sequence,
                source_epoch: event.epoch,
                wire_bytes: datagram.len(),
                format,
            });
        }
        let packet = self
            .receiver
            .accept(datagram)
            .map_err(MediaRefusal::Stream)?;
        let media = MediaPacket::from_authenticated(&packet).ok_or(MediaRefusal::NotMedia)?;
        let view = self.bridge.at_local(clock, local_ns);
        Ok(AuthenticatedIngress {
            stream: packet.stream_id.get(),
            origin_ns: 0, // N01 sequences do not restart inside an epoch.
            admission: Some(self.engine.on_packet(view, &media)),
            sequence: packet.seq,
            source_epoch: packet.session_epoch,
            wire_bytes: datagram.len(),
            format: AuthenticatedFormat::N01Media,
        })
    }
    pub fn poll_host_fec<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        clock: &mut GroupClock,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<franken_stream::fec::DecodeState, MediaRefusal> {
        let local = self
            .local_ns(platform, clock)
            .map_err(LocalTimeRefusal::for_ingest)?;
        if matches!(clock.output(local), Output::Muted(_)) {
            for fec in &mut self.fec {
                fec.cancel();
            }
            return Err(MediaRefusal::Fec(franken_stream::fec::Refusal::Clock));
        }
        let view = self.bridge.at_local(clock, local);
        let state = self
            .fec
            .first_mut()
            .ok_or(MediaRefusal::NotMedia)?
            .poll(&mut self.engine, view, cancelled)
            .map_err(MediaRefusal::Fec)?;
        if state != franken_stream::fec::DecodeState::Ready {
            return Ok(state);
        }
        // The decode completed AFTER the first reading. Publication must use a
        // new platform/N03 view, not the timestamp captured before its CPU work.
        let finish = self
            .local_ns(platform, clock)
            .map_err(LocalTimeRefusal::for_ingest)?;
        if matches!(clock.output(finish), Output::Muted(_)) {
            for fec in &mut self.fec {
                fec.cancel();
            }
            return Err(MediaRefusal::Fec(franken_stream::fec::Refusal::Clock));
        }
        let finish_view = self.bridge.at_local(clock, finish);
        self.fec
            .first_mut()
            .ok_or(MediaRefusal::NotMedia)?
            .publish(&mut self.engine, finish_view, cancelled)
            .map_err(MediaRefusal::Fec)
    }
    pub fn host_fec_feedback<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        clock: &mut GroupClock,
    ) -> Result<Option<franken_stream::fec::Feedback>, MediaRefusal> {
        let local = self
            .local_ns(platform, clock)
            .map_err(LocalTimeRefusal::for_ingest)?;
        if matches!(clock.output(local), Output::Muted(_)) {
            for fec in &mut self.fec {
                fec.cancel();
            }
            return Err(MediaRefusal::Fec(franken_stream::fec::Refusal::Clock));
        }
        let view = self.bridge.at_local(clock, local);
        self.fec
            .first_mut()
            .ok_or(MediaRefusal::NotMedia)?
            .feedback(&self.engine, view)
            .map_err(MediaRefusal::Fec)
    }

    /// Advance the group clock and, unless it is muted, take at most one block's decision from the engine. The clock's
    /// state is the gate and the engine's own cutoff is the schedule: an admitted start that is still ahead (`Armed`)
    /// prepares blocks as their cutoffs come, so the start's first block is not lost; a muted clock prepares nothing,
    /// even while its status is Locked. `out` is zero on every return except [`Preparation::Prepared`].
    ///
    /// # Errors
    /// The platform clock failed. The group clock was told, `out` is zero, and nothing is prepared until a fresh lock and
    /// a fresh [`Self::admit_start`].
    pub fn prepare<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        clock: &mut GroupClock,
        out: &mut [u8; BLOCK_PAYLOAD_BYTES],
    ) -> Result<Preparation, ClockError> {
        out.fill(0);
        let local_ns = match self.local_ns(platform, clock) {
            Ok(local_ns) => local_ns,
            Err(LocalTimeRefusal::Clock(error)) => return Err(error),
            Err(LocalTimeRefusal::Resolution(mismatch)) => {
                return Ok(Preparation::Misconfigured(mismatch));
            }
        };
        let release = match clock.tick(local_ns) {
            Output::Muted(reason) => {
                for fec in &mut self.fec {
                    fec.cancel();
                }
                return Ok(Preparation::Refused(reason));
            }
            Output::Armed { starts_in_ns } => Release::Armed { starts_in_ns },
            Output::Audible => Release::Audible,
        };
        let view = self.bridge.at_local(clock, local_ns);
        if self
            .fec
            .first_mut()
            .is_some_and(|fec| fec.observe_clock(view).is_err())
        {
            return Ok(Preparation::TimingUnavailable);
        }
        if !view.usable {
            return Ok(Preparation::TimingUnavailable);
        }
        let view = if self.fec.is_empty() {
            view
        } else {
            franken_stream::fec::profile_view(view)
        };
        let result = self.engine.decide(view, out);
        if let Some(fec) = self.fec.first_mut() {
            fec.note_decision(view, &result);
        }
        match result {
            Poll::Decision(decision)
                if matches!(decision.outcome, Outcome::Real | Outcome::Concealed { .. }) =>
            {
                Ok(Preparation::Prepared(PreparedBlock { decision, release }))
            }
            Poll::ClockUnusable | Poll::ClockRegression => {
                out.fill(0);
                Ok(Preparation::TimingUnavailable)
            }
            poll => {
                out.fill(0);
                Ok(Preparation::Quiet { release, poll })
            }
        }
    }

    /// Admit a start the caller's control path scheduled: the engine's timeline becomes `anchor_frame` presented at
    /// `sched.start_group_ns`, and the clock is armed for it. The output is not audible until the group clock reaches the
    /// start (blocks are prepared as `Armed` meanwhile). The checks run so that a refusal changes nothing: the clock's
    /// pure query first, then the engine's bind, then the clock's arming. Calling it again within an epoch is a rebind
    /// (the engine's queue is cleared): this is how preparation resumes after a relock, a reset or an authority renewal.
    ///
    /// # Errors
    /// [`StartRefusal`], naming who refused.
    pub fn admit_start<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        clock: &mut GroupClock,
        sched: StartSchedule,
        anchor_frame: u64,
    ) -> Result<StartPlan, StartRefusal> {
        let local_ns = self
            .local_ns(platform, clock)
            .map_err(LocalTimeRefusal::for_start)?;
        let fec_origin = if let Some(fec) = self.fec.first() {
            if !anchor_frame.is_multiple_of(1024) {
                return Err(StartRefusal::Fec(franken_stream::fec::Refusal::Shape));
            }
            let origin = sched
                .start_group_ns
                .checked_sub(franken_stream::playout::frames_to_ns(anchor_frame))
                .ok_or(StartRefusal::Fec(franken_stream::fec::Refusal::Shape))?;
            fec.validate_rebind(sched.epoch, origin)
                .map_err(StartRefusal::Fec)?;
            Some(origin)
        } else {
            None
        };
        clock
            .plan_start(sched, local_ns)
            .map_err(StartRefusal::Admission)?;
        self.engine
            .begin_stream(sched.epoch, anchor_frame, sched.start_group_ns)
            .map_err(StartRefusal::Stream)?;
        let plan = clock
            .admit(sched, local_ns)
            .map_err(StartRefusal::Admission)?;
        if let Some(fec) = self.fec.first_mut() {
            fec.rebind(
                &self.engine,
                fec_origin.expect("selected FEC origin prevalidated"),
            )
            .map_err(StartRefusal::Fec)?;
        }
        self.bridge.rebind(clock);
        Ok(plan)
    }

    /// Adopt a newer epoch and leader announced by the caller's control path: the clock drops its fit, authority and
    /// admitted start and is muted, and the receiver's replay window moves to the epoch. The engine keeps the old epoch
    /// until [`Self::admit_start`] binds the new one (a lower group timeline is fine: the bind clears the engine's
    /// reading and the clock view restarts for the epoch), so new-epoch packets meanwhile are the engine's `FutureEpoch`.
    ///
    /// # Errors
    /// The clock refused (the epoch does not advance). Nothing changed.
    pub fn begin_epoch(
        &mut self,
        clock: &mut GroupClock,
        epoch: u64,
        leader: u64,
    ) -> Result<(), GroupClockError> {
        clock.begin_epoch(epoch, leader)?;
        for fec in &mut self.fec {
            fec.stop();
        }
        self.fec.clear();
        self.receiver.advance_epoch(epoch);
        Ok(())
    }

    /// Bind the media path to another stream: a source restart under a fresh stream id and a strictly newer epoch, announced by
    /// the caller's trusted control path (the media path invents neither). The receiver's replay window restarts at `epoch` for
    /// the new identity and a packet of the previous stream is refused as a wrong stream; the key is the receiver's own and does
    /// not change. A selected N06 session names the old stream, so it is stopped and cleared (the owner selects it again for the
    /// new stream with [`Self::enable_host_fec`]); the clear is unconditional, so a repeated bind of the same stream also ends the
    /// selection and the owner makes the call once per restart. The group clock and the engine are not touched:
    /// [`Self::begin_epoch`] and [`Self::admit_start`] stay the control path's calls for those.
    pub fn bind_stream(&mut self, stream_id: StreamId, epoch: u64) {
        for fec in &mut self.fec {
            fec.stop();
        }
        self.fec.clear();
        self.receiver.bind_stream(stream_id, epoch);
    }

    /// The receiver's per-reason counters.
    #[must_use]
    pub const fn receiver_counters(&self) -> &ReceiverCounters {
        self.receiver.counters()
    }

    /// The engine's counters.
    #[must_use]
    pub const fn engine_stats(&self) -> &PlayoutStats {
        self.engine.stats()
    }

    /// Platform clock failures reported to the group clock. A resolution mismatch is not one of them.
    #[must_use]
    pub const fn clock_faults(&self) -> u64 {
        self.clock_faults
    }

    /// Calls refused because the platform's reported resolution is coarser than the group clock is configured for.
    #[must_use]
    pub const fn resolution_refusals(&self) -> u64 {
        self.resolution_refusals
    }

    /// Readings the clock view had to raise to the previous usable group time.
    #[must_use]
    pub const fn clamped_readings(&self) -> u64 {
        self.bridge.clamped_readings()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_evidence;
    use franken_clock::group::{ClockStatus, GroupClockConfig, ProbeResponse};
    use franken_platform::abi::Abi;
    use franken_platform::ops::{Provenance, Timespec};
    use franken_stream::playout::{BLOCK_FRAMES, CapacityError, ConfigError, frames_to_ns};
    use franken_stream::{OutboundFrame, StreamId, StreamKey, StreamSender};
    use std::cell::Cell;
    use std::rc::Rc;

    const OLD_TIMELINE_NS: u64 = 100_000_000_000;
    const ENOSYS_PPC: isize = 38;
    /// Offset of the big-endian presentation timestamp in an N01 header; its last byte is the next one less one.
    const OFF_PRESENTATION: usize = 40;

    /// A kernel whose monotonic clock the test moves and can make fail. Everything else the admitted layer never calls
    /// here answers `ENOSYS`, and the one descriptor the wake source needs is handed out.
    struct TestKernel {
        now_ns: Rc<Cell<u64>>,
        errno: Rc<Cell<isize>>,
        reads: Rc<Cell<u64>>,
        fail_read: Rc<Cell<Option<u64>>>,
    }

    impl KernelOps for TestKernel {
        fn provenance(&self) -> Provenance {
            Provenance::Simulated
        }
        fn backend_abi(&self) -> Option<Abi> {
            None
        }
        fn clock_gettime_monotonic(&mut self, out: &mut Timespec) -> isize {
            let read = self.reads.get() + 1;
            self.reads.set(read);
            if self.fail_read.get() == Some(read) {
                return -ENOSYS_PPC;
            }
            let failure = self.errno.get();
            if failure != 0 {
                return failure;
            }
            let now = self.now_ns.get();
            out.secs = i64::try_from(now / 1_000_000_000).unwrap_or(i64::MAX);
            out.nanos = i64::try_from(now % 1_000_000_000).unwrap_or(0);
            0
        }
        fn getrandom(&mut self, _buf: &mut [u8], _flags: u32) -> isize {
            -ENOSYS_PPC
        }
        fn open_dev_random(&mut self, _flags: u32) -> isize {
            -ENOSYS_PPC
        }
        fn eventfd2(&mut self, _initval: u32, _flags: u32) -> isize {
            7
        }
        fn pipe2(&mut self, _fds: &mut [i32; 2], _flags: u32) -> isize {
            -ENOSYS_PPC
        }
        fn write(&mut self, _fd: i32, _buf: &[u8]) -> isize {
            -ENOSYS_PPC
        }
        fn read(&mut self, _fd: i32, _buf: &mut [u8]) -> isize {
            -ENOSYS_PPC
        }
        fn close(&mut self, _fd: i32) -> isize {
            0
        }
    }

    fn stream_id() -> StreamId {
        StreamId::new(0x5EED_5EED_0000_0001).expect("stream id")
    }

    fn key() -> StreamKey {
        StreamKey::from_bytes([0x42; 32])
    }

    /// A real admitted platform layer over the scripted kernel clock, a real group clock, a real engine and receiver, and
    /// a real N01 sender with the same key.
    struct Rig {
        time: Rc<Cell<u64>>,
        errno: Rc<Cell<isize>>,
        reads: Rc<Cell<u64>>,
        fail_read: Rc<Cell<Option<u64>>>,
        platform: PlatformLayer<TestKernel>,
        clock: GroupClock,
        media: MediaPlayout,
        sender: StreamSender,
    }

    impl Rig {
        fn new() -> Self {
            Self::with_resolution(None)
        }

        /// `resolution_ns` overrides the monotonic resolution the admitted capability matrix reports (the evidence's own,
        /// 1 ns, otherwise).
        fn with_resolution(resolution_ns: Option<u64>) -> Self {
            let time = Rc::new(Cell::new(0));
            let errno = Rc::new(Cell::new(0));
            let reads = Rc::new(Cell::new(0));
            let fail_read = Rc::new(Cell::new(None));
            let kernel = TestKernel {
                now_ns: Rc::clone(&time),
                errno: Rc::clone(&errno),
                reads: Rc::clone(&reads),
                fail_read: Rc::clone(&fail_read),
            };
            let mut matrix = guest_evidence::for_abi(Abi::PowerPc32).matrix();
            if let Some(resolution_ns) = resolution_ns {
                matrix.clock_monotonic_res_ns = resolution_ns;
            }
            let platform = crate::platform_start::admit_test_layer(&matrix, kernel)
                .expect("admitted test platform");
            // The standard configuration, unmodified: its output delay is zero, so the output turns audible exactly at the
            // start and every block's engine cutoff falls before that.
            let cfg = GroupClockConfig::standard().expect("config");
            let clock = GroupClock::new(cfg, 1, 7, 100).expect("clock");
            let receiver = StreamReceiver::new(key(), stream_id(), 1);
            let config = PlayoutConfig {
                work_ns: 2_000_000,
                lead_ns: 1_000_000,
                tolerance_ns: 1_000_000,
            };
            let media = MediaPlayout::new(
                receiver,
                PlayoutProfile::MUSIC,
                config,
                &synthetic_ledger(2 * 1024 * 1024),
                0,
            )
            .expect("media path");
            Self {
                time,
                errno,
                reads,
                fail_read,
                platform,
                clock,
                media,
                sender: StreamSender::new(key(), stream_id(), 1),
            }
        }

        /// Four accepted exchanges 10 ms apart; the group clock then reads `group_origin_ns` at `local_origin_ns` and
        /// advances with the local clock.
        fn lock(&mut self, local_origin_ns: u64, group_origin_ns: u64) {
            for k in 1..=4_u64 {
                let offset = k * 10_000_000;
                let t1 = local_origin_ns + offset;
                let req = self.clock.next_probe(t1);
                self.clock
                    .on_response(
                        ProbeResponse {
                            epoch: self.clock.epoch(),
                            leader: self.clock.leader(),
                            seq: req.seq,
                            t1_echo_ns: req.t1_local_ns,
                            t2_group_ns: group_origin_ns + offset + 400_000,
                            t3_group_ns: group_origin_ns + offset + 450_000,
                        },
                        t1 + 850_000,
                    )
                    .expect("accepted exchange");
            }
        }

        fn at(&self, local_ns: u64) {
            self.time.set(local_ns);
        }

        fn group_at(&self, local_ns: u64) -> u64 {
            self.clock.group_ns(local_ns).expect("a fitted clock")
        }

        /// The local instant at which the group clock reads `group_ns`, judged at `now_local_ns`.
        fn local_of(&self, group_ns: u64, now_local_ns: u64) -> u64 {
            self.clock
                .local_for_group(group_ns, now_local_ns)
                .expect("a fitted clock")
        }

        fn admit(
            &mut self,
            start_group_ns: u64,
            anchor_frame: u64,
        ) -> Result<StartPlan, StartRefusal> {
            let sched = StartSchedule {
                epoch: self.clock.epoch(),
                start_group_ns,
            };
            self.media
                .admit_start(&mut self.platform, &mut self.clock, sched, anchor_frame)
        }

        fn ingest(&mut self, datagram: &[u8]) -> Result<Admission, MediaRefusal> {
            self.media
                .ingest(&mut self.platform, &mut self.clock, datagram)
        }

        fn prepare(
            &mut self,
            out: &mut [u8; BLOCK_PAYLOAD_BYTES],
        ) -> Result<Preparation, ClockError> {
            self.media.prepare(&mut self.platform, &mut self.clock, out)
        }

        /// Block `block` of a stream whose first block (`anchor_block`) is presented at `anchor_ns`.
        fn packet(&mut self, block: u64, anchor_block: u64, anchor_ns: u64, seed: u8) -> Vec<u8> {
            let pts = anchor_ns + frames_to_ns((block - anchor_block) * BLOCK_FRAMES);
            self.sender
                .send(OutboundFrame::media(
                    block * BLOCK_FRAMES,
                    pts,
                    pts - 5_333_333,
                    pcm(block, seed),
                ))
                .expect("encoded packet")
        }
    }

    /// A block that is never silent and differs per block and per seed, so a swapped or zeroed buffer is visible.
    fn pcm(block: u64, seed: u8) -> Vec<u8> {
        (0..BLOCK_PAYLOAD_BYTES)
            .map(|i| {
                let mix = (i % 251) as u64 + block * 7 + u64::from(seed);
                0x11 + (mix % 200) as u8
            })
            .collect()
    }

    fn silent(out: &[u8; BLOCK_PAYLOAD_BYTES]) -> bool {
        out.iter().all(|byte| *byte == 0)
    }

    /// A locked rig with a start admitted `ahead_ns` after local 50 ms, the stream's first block at that start. Returns the
    /// rig, the start's group time and the local instant of it.
    fn admitted_rig(ahead_ns: u64) -> (Rig, u64, u64) {
        let mut rig = Rig::new();
        rig.lock(0, OLD_TIMELINE_NS);
        rig.at(50_000_000);
        let start_group = rig.group_at(50_000_000) + ahead_ns;
        rig.admit(start_group, 0).expect("admitted start");
        let start_local = rig.local_of(start_group, 50_000_000);
        (rig, start_group, start_local)
    }

    // This fixture has zero oscillator skew. Find the first clock reading that reaches the
    // engine's uncertainty-adjusted cutoff, rather than preparing at the submission deadline.
    fn cutoff_local(rig: &Rig, presentation_ns: u64, presentation_local_ns: u64) -> u64 {
        let uncertainty = rig
            .clock
            .report(presentation_local_ns)
            .uncertainty_ns
            .expect("fit");
        let group =
            franken_stream::playout::consume_by(presentation_ns, 2_000_000, 1_000_000, uncertainty);
        let mut local = rig.local_of(group, presentation_local_ns);
        for _ in 0..8 {
            let uncertainty = rig.clock.report(local).uncertainty_ns.expect("fit");
            let cutoff = franken_stream::playout::consume_by(
                presentation_ns,
                2_000_000,
                1_000_000,
                uncertainty,
            );
            let now = rig.group_at(local);
            if now >= cutoff {
                return local;
            }
            local += cutoff - now;
        }
        panic!("zero-skew fixture cutoff did not converge");
    }

    #[test]
    fn an_over_budget_refit_invalidates_prepared_blocks_but_a_small_clamp_remains_permitted() {
        for (step_ns, refused) in [
            (3_000_000_u64, true),
            (1_000_000, false),
            (1_000_000_000, true),
        ] {
            let mut rig = Rig::new();
            let mut cfg = rig.clock.config().clone();
            cfg.window = 1;
            cfg.min_probes_for_lock = 1;
            // Admit this explicit fit correction so the consumer, rather than the probe's
            // discontinuity gate, must handle the backwards reading conservatively.
            cfg.prediction_slack_ns = 2_000_000_000;
            rig.clock = GroupClock::new(cfg, 1, 7, 100).expect("clock");
            rig.lock(0, OLD_TIMELINE_NS);
            rig.at(50_000_000);
            let start_group = rig.group_at(50_000_000) + 1_000_000_000;
            rig.admit(start_group, 0).expect("start");
            let start_local = rig.local_of(start_group, 50_000_000);
            let wire = rig.packet(0, 0, start_group, 1);
            assert_eq!(rig.ingest(&wire), Ok(Admission::Admitted));
            let prepared_local = cutoff_local(&rig, start_group, start_local);
            rig.at(prepared_local);
            let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
            let prior = rig.prepare(&mut out).expect("platform time");
            assert!(matches!(prior, Preparation::Prepared(_)));
            assert!(!prior.invalidates_prepared());

            let t1 = prepared_local + 1_000;
            let req = rig.clock.next_probe(t1);
            rig.clock
                .on_response(
                    ProbeResponse {
                        epoch: 1,
                        leader: 7,
                        seq: req.seq,
                        t1_echo_ns: t1,
                        t2_group_ns: OLD_TIMELINE_NS + t1 + 400_000 - step_ns,
                        t3_group_ns: OLD_TIMELINE_NS + t1 + 450_000 - step_ns,
                    },
                    t1 + 850_000,
                )
                .expect("admitted actual refit");
            let now = t1 + 850_000;
            rig.at(now);
            assert_eq!(rig.clock.status(now), ClockStatus::Locked);
            assert!(matches!(rig.clock.output(now), Output::Armed { .. }));
            out.fill(0xFF);
            let result = rig.prepare(&mut out).expect("platform time");
            assert!(silent(&out));
            if refused {
                assert_eq!(result, Preparation::TimingUnavailable);
                assert!(
                    result.invalidates_prepared(),
                    "cancel the earlier prepared reservation"
                );
            } else {
                assert!(matches!(
                    result,
                    Preparation::Quiet {
                        poll: Poll::Pending,
                        ..
                    }
                ));
                assert!(!result.invalidates_prepared());
                assert_eq!(rig.media.clamped_readings(), 1);
            }
            assert_eq!(rig.media.engine_stats().decided_real, 1);
            if refused {
                let new_start = rig.group_at(now) + 200_000_000;
                rig.admit(new_start, BLOCK_FRAMES)
                    .expect("explicit fresh timeline");
                let wire = rig.packet(1, 1, new_start, 2);
                assert_eq!(rig.ingest(&wire), Ok(Admission::Admitted));
                let new_start_local = rig.local_of(new_start, now);
                let next = cutoff_local(&rig, new_start, new_start_local);
                rig.at(next);
                let result = rig.prepare(&mut out).expect("platform time");
                assert!(
                    matches!(result, Preparation::Prepared(_)),
                    "a fresh admission does not inherit the previous stream's time latch"
                );
                assert!(!result.invalidates_prepared());
                assert_eq!(out.as_slice(), pcm(1, 2).as_slice());
            }
        }
    }

    #[test]
    fn preparation_at_the_submission_deadline_is_reported_as_late_not_timely_delivery() {
        let (mut rig, start_group, start_local) = admitted_rig(1_000_000_000);
        let wire = rig.packet(0, 0, start_group, 1);
        assert_eq!(rig.ingest(&wire), Ok(Admission::Admitted));
        let late_local = start_local - 1_000_000;
        rig.at(late_local);
        let mut out = [0; BLOCK_PAYLOAD_BYTES];
        let Preparation::Prepared(block) = rig.prepare(&mut out).expect("platform time") else {
            panic!("engine decision");
        };
        assert!(block.decision.late_by_ns > 0);
        assert!(
            rig.group_at(late_local) + 2_000_000 > block.decision.submit_deadline_ns,
            "the downstream sink cannot assume its declared work budget still fits"
        );
    }

    #[test]
    fn with_the_standard_zero_output_delay_the_first_block_is_prepared_while_armed_and_is_not_lost()
    {
        let (mut rig, start_group, start_local) = admitted_rig(1_000_000_000);
        assert_eq!(rig.clock.config().output_delay_ns, 0, "the ordinary board");
        let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
        // Two authenticated blocks arrive while the clock is armed: the engine buffers both.
        for block in 0..2 {
            let wire = rig.packet(block, 0, start_group, 1);
            assert_eq!(rig.ingest(&wire), Ok(Admission::Admitted), "block {block}");
        }
        assert_eq!(rig.media.receiver_counters().accepted, 2);
        assert_eq!(rig.media.engine_stats().admitted, 2);
        // Armed and far from any cutoff, with the clock Locked: nothing is due, so nothing is prepared.
        rig.at(start_local - 500_000_000);
        let Ok(Preparation::Quiet {
            release: Release::Armed { starts_in_ns },
            poll: Poll::Pending,
        }) = rig.prepare(&mut out)
        else {
            panic!("armed and not due");
        };
        assert!(starts_in_ns > 0);
        assert!(silent(&out));
        assert_eq!(
            rig.clock.status(start_local - 500_000_000),
            ClockStatus::Locked
        );
        assert_eq!(rig.media.engine_stats().decided_real, 0);
        // Still before the first block's cutoff: nothing due yet.
        rig.at(start_local - 8_000_000);
        assert!(matches!(
            rig.prepare(&mut out),
            Ok(Preparation::Quiet {
                release: Release::Armed { .. },
                poll: Poll::Pending
            })
        ));
        // Prepare at the uncertainty-adjusted cutoff, leaving the declared work and submission
        // lead before presentation. Preparing at start minus lead alone would already be late.
        let first_local = cutoff_local(&rig, start_group, start_local);
        rig.at(first_local);
        assert!(rig.group_at(first_local) < start_group);
        let Ok(Preparation::Prepared(first)) = rig.prepare(&mut out) else {
            panic!("the first block is prepared while armed");
        };
        assert!(matches!(first.release, Release::Armed { .. }));
        assert_eq!(
            (
                first.decision.block,
                first.decision.outcome,
                first.decision.frames
            ),
            (0, Outcome::Real, 256)
        );
        assert_eq!(first.decision.presentation_ns, start_group);
        assert!(rig.group_at(first_local) + 2_000_000 <= first.decision.submit_deadline_ns);
        assert!(first.decision.late_by_ns <= 1);
        assert_eq!(out.as_slice(), pcm(0, 1).as_slice());
        // The start is reached: the next block is prepared as audible.
        let second_group = start_group + frames_to_ns(BLOCK_FRAMES);
        let second_local =
            cutoff_local(&rig, second_group, start_local + frames_to_ns(BLOCK_FRAMES));
        rig.at(second_local);
        let Ok(Preparation::Prepared(second)) = rig.prepare(&mut out) else {
            panic!("the second block is prepared");
        };
        assert_eq!(second.release, Release::Audible);
        assert_eq!(
            (second.decision.block, second.decision.outcome),
            (1, Outcome::Real)
        );
        assert!(rig.group_at(second_local) + 2_000_000 <= second.decision.submit_deadline_ns);
        assert!(second.decision.late_by_ns <= 1);
        assert_eq!(out.as_slice(), pcm(1, 1).as_slice());
        let stats = rig.media.engine_stats();
        assert_eq!((stats.decided_real, stats.decided_muted_overdue), (2, 0));
        assert_eq!(rig.media.clock_faults(), 0);
    }

    fn media_config() -> PlayoutConfig {
        PlayoutConfig {
            work_ns: 2_000_000,
            lead_ns: 1_000_000,
            tolerance_ns: 1_000_000,
        }
    }

    fn receiver() -> StreamReceiver {
        StreamReceiver::new(key(), stream_id(), 1)
    }

    #[test]
    fn a_replacement_that_does_not_fit_beside_the_playing_path_is_refused_atomically_and_the_playing_path_is_untouched()
     {
        let rig = Rig::new();
        let before = rig.media.engine.snapshot();
        let old = rig.media.resident_bytes();
        let engine_need = PlayoutEngine::resident_bytes(&PlayoutProfile::MUSIC);
        // The playing path and a candidate of the same profile hold the same bytes, so a line of 2 x old holds exactly both.
        let one_short = synthetic_ledger(2 * old - 1);
        let refused = MediaPlayout::new(
            receiver(),
            PlayoutProfile::MUSIC,
            media_config(),
            &one_short,
            old,
        )
        .expect_err("no room beside the playing path");
        assert_eq!(
            refused,
            MediaAdmitError::Engine(AdmitError::Capacity(CapacityError {
                needed_bytes: engine_need,
                budget_bytes: engine_need - 1,
            }))
        );
        assert_eq!(refused.code(), "capacity");
        assert_eq!(rig.media.engine.snapshot(), before);
        assert_eq!(rig.media.resident_bytes(), old);
        // Exactly enough for both: admitted, and the playing path is still the one it was.
        let both = synthetic_ledger(2 * old);
        let second = MediaPlayout::new(
            receiver(),
            PlayoutProfile::MUSIC,
            media_config(),
            &both,
            old,
        )
        .expect("fits beside the playing path");
        assert_eq!(second.resident_bytes(), old);
        assert_eq!(rig.media.engine.snapshot(), before);
        // Control: the same tight line admits the same profile when nothing else is resident, so the refusal was the overlap.
        assert!(
            MediaPlayout::new(
                receiver(),
                PlayoutProfile::MUSIC,
                media_config(),
                &one_short,
                0
            )
            .is_ok()
        );
    }

    #[test]
    fn a_ledger_that_fails_its_floor_admits_nothing_and_a_bad_configuration_is_judged_before_the_ledger()
     {
        let mut failing = synthetic_ledger(2 * 1024 * 1024);
        failing.nominal_ram_bytes = 20 * 1024 * 1024; // less than what is already committed
        let refused = MediaPlayout::new(
            receiver(),
            PlayoutProfile::MUSIC,
            media_config(),
            &failing,
            0,
        )
        .expect_err("the floor fails");
        assert!(matches!(
            refused,
            MediaAdmitError::Platform(PlatformAdmissionError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(refused.code(), "memory_budget");
        let bad = PlayoutConfig {
            work_ns: 0,
            ..media_config()
        };
        let refused = MediaPlayout::new(receiver(), PlayoutProfile::MUSIC, bad, &failing, 0)
            .expect_err("the configuration is invalid");
        assert_eq!(
            refused,
            MediaAdmitError::Engine(AdmitError::Config(ConfigError::WorkNotPositive))
        );
        // Control: the same ledger with a sound nominal size admits.
        assert!(
            MediaPlayout::new(
                receiver(),
                PlayoutProfile::MUSIC,
                media_config(),
                &synthetic_ledger(2 * 1024 * 1024),
                0
            )
            .is_ok()
        );
    }

    #[test]
    fn the_diagnostic_ring_is_charged_to_the_same_line_and_a_refused_restart_keeps_the_old_ring() {
        let log = |capacity| {
            LogConfig::new(
                "n04-media",
                "unit",
                "p-0123456789abcdef",
                "p-fedcba9876543210",
                capacity,
            )
            .expect("valid log configuration")
        };
        let mut rig = Rig::new();
        let ring = PlayoutEngine::log_heap_bytes_for(&log(4)).expect("fits a usize");
        let base = rig.media.resident_bytes();
        let ring_u64 = u64::try_from(ring).expect("fits");
        // Exactly the path plus one ring: admitted and accounted.
        let exact = synthetic_ledger(base + ring_u64);
        rig.media
            .enable_diag_log(log(4), &exact, 0)
            .expect("the ring fits exactly");
        assert_eq!(rig.media.engine.log_heap_bytes(), ring);
        assert_eq!(rig.media.resident_bytes(), base + ring_u64);
        // A restart holds the old ring and the new one together: the same line cannot take it, and the old ring stays.
        let refused = rig
            .media
            .enable_diag_log(log(4), &exact, 0)
            .expect_err("old plus new do not fit");
        assert!(matches!(
            refused,
            MediaAdmitError::Engine(AdmitError::Capacity(_))
        ));
        assert_eq!(rig.media.engine.log_heap_bytes(), ring);
        assert!(rig.media.engine.log_stats().is_some());
        // Room for both rings: the restart is admitted.
        let both = synthetic_ledger(base + 2 * ring_u64);
        rig.media
            .enable_diag_log(log(4), &both, 0)
            .expect("a restart fits with both rings");
        assert_eq!(rig.media.engine.log_heap_bytes(), ring);
        // One byte short of the first ring: refused, nothing turned on.
        let mut fresh = Rig::new();
        assert!(
            fresh
                .media
                .enable_diag_log(log(4), &synthetic_ledger(base + ring_u64 - 1), 0)
                .is_err()
        );
        assert_eq!(fresh.media.engine.log_heap_bytes(), 0);
        assert!(fresh.media.engine.log_stats().is_none());
    }

    #[test]
    fn before_any_admitted_start_a_locked_clock_stays_silent_and_nothing_is_bound() {
        let mut rig = Rig::new();
        rig.lock(0, OLD_TIMELINE_NS);
        rig.at(50_000_000);
        let mut out = [0xFFu8; BLOCK_PAYLOAD_BYTES];
        assert_eq!(rig.clock.status(50_000_000), ClockStatus::Locked);
        let wire = rig.packet(0, 0, rig.group_at(50_000_000) + 1_000_000_000, 1);
        assert_eq!(rig.ingest(&wire), Ok(Admission::NotBound));
        assert_eq!(
            rig.prepare(&mut out),
            Ok(Preparation::Refused(MuteReason::NotAdmitted))
        );
        assert!(silent(&out), "a locked clock is not permission to sound");
        assert_eq!(rig.media.engine_stats().decided_real, 0);
    }

    #[test]
    fn a_tampered_timestamp_and_a_stale_epoch_cannot_change_playback() {
        let (mut rig, start_group, start_local) = admitted_rig(1_000_000_000);
        let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
        // Change one bit of the presentation time in flight: the MAC covers it, the engine never sees the packet.
        let genuine = rig.packet(0, 0, start_group, 1);
        let mut tampered = genuine.clone();
        tampered[OFF_PRESENTATION + 7] ^= 0x01;
        assert_eq!(
            rig.ingest(&tampered),
            Err(MediaRefusal::Stream(StreamError::AuthenticationFailed))
        );
        assert_eq!(rig.media.engine_stats().packets_seen, 0);
        assert_eq!(rig.media.receiver_counters().rejected_authentication, 1);
        // A failed MAC consumed nothing: the genuine datagram is still admitted.
        assert_eq!(rig.ingest(&genuine), Ok(Admission::Admitted));
        // A correctly keyed packet of an older epoch is refused by the receiver; the engine's count does not move.
        let mut old_sender = StreamSender::new(key(), stream_id(), 0);
        let stale = old_sender
            .send(OutboundFrame::media(
                BLOCK_FRAMES,
                start_group + 5_333_333,
                start_group,
                pcm(1, 9),
            ))
            .expect("old epoch packet");
        assert!(matches!(
            rig.ingest(&stale),
            Err(MediaRefusal::Stream(StreamError::StaleSessionEpoch { .. }))
        ));
        assert_eq!(rig.media.engine_stats().packets_seen, 1);
        // The next block is authentic but its presentation time is 2 ms off the agreed timeline (tolerance 1 ms): the
        // engine refuses it, so that block is never played.
        let off_timeline = rig
            .sender
            .send(OutboundFrame::media(
                BLOCK_FRAMES,
                start_group + frames_to_ns(BLOCK_FRAMES) + 2_000_000,
                start_group,
                pcm(1, 1),
            ))
            .expect("off-timeline packet");
        assert_eq!(rig.ingest(&off_timeline), Ok(Admission::TimelineMismatch));
        rig.at(start_local - 1_000_000);
        let Ok(Preparation::Prepared(first)) = rig.prepare(&mut out) else {
            panic!("the genuine block is prepared");
        };
        assert_eq!(first.decision.block, 0);
        assert_eq!(out.as_slice(), pcm(0, 1).as_slice());
        // Block 1 is due and was never admitted, so the engine conceals it from block 0: the refused bytes are not used.
        rig.at(start_local + 4_000_000);
        let Ok(Preparation::Prepared(second)) = rig.prepare(&mut out) else {
            panic!("the engine conceals the missing block");
        };
        assert_eq!(
            (second.decision.block, second.decision.outcome),
            (1, Outcome::Concealed { run: 1 })
        );
        assert_ne!(out.as_slice(), pcm(1, 1).as_slice());
        assert_eq!(rig.media.engine_stats().timeline_mismatch, 1);
    }

    #[test]
    fn a_future_start_is_never_audible_before_it_and_prepares_nothing_early_while_the_clock_is_locked()
     {
        let (mut rig, start_group, start_local) = admitted_rig(2_000_000_000);
        let mut out = [0xAAu8; BLOCK_PAYLOAD_BYTES];
        let wire = rig.packet(0, 0, start_group, 3);
        assert_eq!(rig.ingest(&wire), Ok(Admission::Admitted));
        // Well before the first block's cutoff: armed, nothing due, the buffer is zero.
        for local in [60_000_000, 500_000_000, start_local - 20_000_000] {
            rig.at(local);
            assert_eq!(rig.clock.status(local), ClockStatus::Locked);
            let Ok(Preparation::Quiet {
                release: Release::Armed { starts_in_ns },
                poll: Poll::Pending,
            }) = rig.prepare(&mut out)
            else {
                panic!("armed and not due at {local}");
            };
            assert!(starts_in_ns > 0);
            assert!(silent(&out), "silent while armed at {local}");
        }
        assert_eq!(rig.media.engine_stats().decided_real, 0);
        // The block is prepared when its cutoff comes, still armed, still ahead of its presentation time, and it is
        // never reported as audible before the start.
        rig.at(start_local - 1_000_000);
        let Ok(Preparation::Prepared(block)) = rig.prepare(&mut out) else {
            panic!("the first block is prepared at its cutoff");
        };
        assert!(matches!(block.release, Release::Armed { .. }));
        assert!(rig.group_at(start_local - 1_000_000) < block.decision.presentation_ns);
        assert_eq!(out.as_slice(), pcm(0, 3).as_slice());
    }

    #[test]
    fn a_fresh_clock_whose_authority_has_expired_is_silent_and_a_renewal_does_not_revive_the_start()
    {
        let mut rig = Rig::new();
        rig.lock(0, OLD_TIMELINE_NS);
        rig.at(50_000_000);
        let start_group = rig.group_at(50_000_000) + 1_000_000_000;
        let start_local = rig.local_of(start_group, 50_000_000);
        let expiry = start_local + 20_000_000;
        rig.clock
            .set_authority(1, expiry, 50_000_000)
            .expect("authority for the epoch");
        rig.admit(start_group, 0)
            .expect("admitted before the expiry");
        for block in 0..6 {
            let wire = rig.packet(block, 0, start_group, 5);
            assert_eq!(rig.ingest(&wire), Ok(Admission::Admitted));
        }
        let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
        rig.at(start_local - 1_000_000);
        assert!(matches!(
            rig.prepare(&mut out),
            Ok(Preparation::Prepared(PreparedBlock {
                release: Release::Armed { .. },
                ..
            }))
        ));
        rig.at(start_local + 4_000_000);
        assert!(matches!(
            rig.prepare(&mut out),
            Ok(Preparation::Prepared(PreparedBlock {
                release: Release::Audible,
                ..
            }))
        ));
        // The clock was fitted 1 s ago, so it is Locked, and later blocks are queued. The authority has run out.
        let after = expiry + 1_000_000;
        rig.at(after);
        assert_eq!(rig.clock.status(after), ClockStatus::Locked);
        assert_eq!(
            rig.prepare(&mut out),
            Ok(Preparation::Refused(MuteReason::AuthorityExpired))
        );
        assert!(silent(&out));
        let decided = rig.media.engine_stats().decided_real;
        assert_eq!(decided, 2);
        // A renewed authority alone prepares nothing: a start has to be admitted again.
        rig.clock
            .set_authority(1, after + 10_000_000_000, after)
            .expect("renewed authority");
        rig.at(after + 1_000_000);
        assert_eq!(
            rig.prepare(&mut out),
            Ok(Preparation::Refused(MuteReason::NotAdmitted))
        );
        assert!(silent(&out));
        assert_eq!(rig.media.engine_stats().decided_real, decided);
    }

    #[test]
    fn an_authority_that_expires_while_armed_keeps_the_queued_first_block_unprepared() {
        let (mut rig, start_group, start_local) = admitted_rig(1_000_000_000);
        let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
        let wire = rig.packet(0, 0, start_group, 5);
        assert_eq!(rig.ingest(&wire), Ok(Admission::Admitted));
        // The control path shortens the authority to end before the start while the start is armed.
        let expiry = start_local - 5_000_000;
        rig.at(start_local - 100_000_000);
        rig.clock
            .set_authority(1, expiry, start_local - 100_000_000)
            .expect("shortened authority");
        // The first block's cutoff has come but the authority is gone: the clock is Locked, the block is queued, and
        // nothing is prepared.
        let at = start_local - 1_000_000;
        rig.at(at);
        assert_eq!(rig.clock.status(at), ClockStatus::Locked);
        assert_eq!(
            rig.prepare(&mut out),
            Ok(Preparation::Refused(MuteReason::AuthorityExpired))
        );
        assert!(silent(&out));
        assert_eq!(rig.media.engine_stats().decided_real, 0);
    }

    #[test]
    fn a_platform_clock_error_refuses_and_stays_silent_until_a_fresh_lock_and_admission() {
        let (mut rig, start_group, start_local) = admitted_rig(1_000_000_000);
        let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
        let wire = rig.packet(0, 0, start_group, 2);
        assert_eq!(rig.ingest(&wire), Ok(Admission::Admitted));
        rig.at(start_local - 1_000_000);
        assert!(matches!(
            rig.prepare(&mut out),
            Ok(Preparation::Prepared(_))
        ));
        // The monotonic call becomes absent. Preparation refuses, the group clock is told, and the buffer is zero.
        rig.errno.set(-ENOSYS_PPC);
        rig.at(start_local + 4_000_000);
        out.fill(0xEE);
        assert_eq!(rig.prepare(&mut out), Err(ClockError::Absent));
        assert!(silent(&out));
        assert_eq!(rig.media.clock_faults(), 1);
        assert_eq!(rig.clock.stats().resets, 1);
        // Ingress refuses too, and the datagram stays unconsumed in the replay window.
        let next = rig.packet(1, 0, start_group, 2);
        let seen = rig.media.receiver_counters().datagrams_seen;
        assert_eq!(
            rig.ingest(&next),
            Err(MediaRefusal::Clock(ClockError::Absent))
        );
        assert_eq!(rig.media.receiver_counters().datagrams_seen, seen);
        assert_eq!(rig.media.clock_faults(), 2);
        assert_eq!(rig.media.resolution_refusals(), 0, "not a mismatch");
        // The call works again, but nothing the old fit said can be believed: muted for the fault.
        rig.errno.set(0);
        rig.at(start_local + 10_000_000);
        assert_eq!(
            rig.prepare(&mut out),
            Ok(Preparation::Refused(MuteReason::ClockFault))
        );
        // A fresh lock alone prepares nothing (and the queued block is not used).
        rig.lock(
            start_local + 10_000_000,
            OLD_TIMELINE_NS + start_local + 10_000_000,
        );
        let relocked = start_local + 60_000_000;
        rig.at(relocked);
        assert_eq!(rig.clock.status(relocked), ClockStatus::Locked);
        assert_eq!(
            rig.prepare(&mut out),
            Ok(Preparation::Refused(MuteReason::NotAdmitted))
        );
        assert!(silent(&out));
        // A fresh admission on a new anchor brings preparation back, with the packets of that timeline.
        let new_start = rig.group_at(relocked) + 1_000_000_000;
        rig.admit(new_start, 100 * BLOCK_FRAMES)
            .expect("fresh admission");
        let wire = rig.packet(100, 100, new_start, 4);
        assert_eq!(rig.ingest(&wire), Ok(Admission::Admitted));
        let new_local = rig.local_of(new_start, relocked);
        rig.at(new_local - 1_000_000);
        let Ok(Preparation::Prepared(resumed)) = rig.prepare(&mut out) else {
            panic!("preparation resumes after a fresh lock and admission");
        };
        assert_eq!(resumed.decision.block, 100);
        assert!(matches!(resumed.release, Release::Armed { .. }));
        assert_eq!(out.as_slice(), pcm(100, 4).as_slice());
    }

    #[test]
    fn a_platform_clock_that_goes_backwards_is_a_fault_and_never_a_rewind() {
        let (mut rig, start_group, start_local) = admitted_rig(1_000_000_000);
        let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
        let wire = rig.packet(0, 0, start_group, 6);
        assert_eq!(rig.ingest(&wire), Ok(Admission::Admitted));
        rig.at(start_local - 1_000_000);
        assert!(matches!(
            rig.prepare(&mut out),
            Ok(Preparation::Prepared(_))
        ));
        rig.at(start_local - 2_000_000);
        assert!(matches!(
            rig.prepare(&mut out),
            Err(ClockError::WentBackwards { .. })
        ));
        assert!(silent(&out));
        assert_eq!(rig.media.clock_faults(), 1);
        rig.at(start_local);
        assert_eq!(
            rig.prepare(&mut out),
            Ok(Preparation::Refused(MuteReason::ClockFault))
        );
    }

    #[test]
    fn a_refused_start_changes_nothing_a_playing_stream_depends_on() {
        let (mut rig, start_group, start_local) = admitted_rig(1_000_000_000);
        let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
        let wire = rig.packet(0, 0, start_group, 8);
        assert_eq!(rig.ingest(&wire), Ok(Admission::Admitted));
        rig.at(start_local - 20_000_000);
        // A schedule for another epoch is the clock's refusal, before the engine is touched.
        let other = StartSchedule {
            epoch: 2,
            start_group_ns: start_group + 1_000_000_000,
        };
        assert_eq!(
            rig.media
                .admit_start(&mut rig.platform, &mut rig.clock, other, 0),
            Err(StartRefusal::Admission(ClockStartReject::FutureEpoch))
        );
        // A misaligned anchor is the engine's refusal, before the clock is armed again.
        assert_eq!(
            rig.admit(start_group + 1_000_000_000, 100),
            Err(StartRefusal::Stream(EngineStartReject::Misaligned))
        );
        rig.at(start_local - 1_000_000);
        let Ok(Preparation::Prepared(first)) = rig.prepare(&mut out) else {
            panic!("the stream that was prepared keeps being prepared");
        };
        assert_eq!(first.decision.block, 0);
        assert_eq!(out.as_slice(), pcm(0, 8).as_slice());
    }

    #[test]
    fn a_new_epoch_on_a_lower_timeline_rebinds_and_does_not_inherit_the_old_leaders_time() {
        let (mut rig, start_group, start_local) = admitted_rig(1_000_000_000);
        let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
        let wire = rig.packet(0, 0, start_group, 1);
        assert_eq!(rig.ingest(&wire), Ok(Admission::Admitted));
        rig.at(start_local - 1_000_000);
        assert!(matches!(
            rig.prepare(&mut out),
            Ok(Preparation::Prepared(_))
        ));
        // The control path announces epoch 2 under another leader, whose timeline is far below the old one.
        rig.media
            .begin_epoch(&mut rig.clock, 2, 8)
            .expect("newer epoch");
        assert_eq!(
            rig.media.begin_epoch(&mut rig.clock, 2, 8),
            Err(GroupClockError::EpochNotAdvanced {
                current: 2,
                requested: 2
            })
        );
        rig.at(start_local + 100_000_000);
        assert_eq!(
            rig.prepare(&mut out),
            Ok(Preparation::Refused(MuteReason::EpochChange))
        );
        assert!(silent(&out));
        // Old-epoch traffic is refused by the receiver; new-epoch traffic waits for the engine's bind.
        let old_epoch = rig.packet(1, 0, start_group, 1);
        assert!(matches!(
            rig.ingest(&old_epoch),
            Err(MediaRefusal::Stream(StreamError::StaleSessionEpoch { .. }))
        ));
        rig.sender.advance_epoch(2).expect("sender epoch");
        let early = rig.packet(0, 0, 1_050_000_000, 7);
        assert_eq!(rig.ingest(&early), Ok(Admission::FutureEpoch));
        // Lock the new timeline (about 1 s of group time against 100 s before), then admit the new epoch's start.
        rig.lock(2_000_000_000, 1_000_000_000);
        rig.at(2_050_000_000);
        let new_start = rig.group_at(2_050_000_000) + 1_000_000_000;
        assert!(
            new_start < 3_000_000_000,
            "the new timeline is far below the old leader's"
        );
        rig.admit(new_start, 0).expect("admitted on the new epoch");
        let wire = rig.packet(1, 0, new_start, 7);
        assert_eq!(rig.ingest(&wire), Ok(Admission::Admitted));
        let first = rig.packet(0, 0, new_start, 7);
        assert_eq!(rig.ingest(&first), Ok(Admission::Admitted));
        let new_local = rig.local_of(new_start, 2_050_000_000);
        rig.at(new_local - 1_000_000);
        let Ok(Preparation::Prepared(resumed)) = rig.prepare(&mut out) else {
            panic!("the new epoch is prepared on its own timeline");
        };
        assert_eq!(resumed.decision.block, 0);
        assert!(matches!(resumed.release, Release::Armed { .. }));
        assert_eq!(resumed.decision.presentation_ns, new_start);
        assert_eq!(out.as_slice(), pcm(0, 7).as_slice());
        assert_eq!(rig.media.clamped_readings(), 0);
    }

    #[test]
    fn a_platform_resolution_equal_to_the_clocks_configured_resolution_is_permitted() {
        let mut rig = Rig::with_resolution(Some(1_000));
        assert_eq!(rig.clock.config().timer_resolution_ns, 1_000);
        rig.lock(0, OLD_TIMELINE_NS);
        rig.at(50_000_000);
        let start_group = rig.group_at(50_000_000) + 1_000_000_000;
        rig.admit(start_group, 0).expect("admitted at the boundary");
        let start_local = rig.local_of(start_group, 50_000_000);
        let wire = rig.packet(0, 0, start_group, 1);
        assert_eq!(rig.ingest(&wire), Ok(Admission::Admitted));
        let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
        rig.at(start_local - 1_000_000);
        let Ok(Preparation::Prepared(first)) = rig.prepare(&mut out) else {
            panic!("a platform exactly as fine as the clock assumes is permitted");
        };
        assert_eq!(first.decision.block, 0);
        assert_eq!(rig.media.resolution_refusals(), 0);
    }

    #[test]
    fn a_platform_coarser_than_the_clock_assumes_refuses_muted_and_consumes_nothing_until_reconfigured()
     {
        let mut rig = Rig::with_resolution(Some(1_001));
        rig.lock(0, OLD_TIMELINE_NS);
        rig.at(50_000_000);
        assert_eq!(rig.clock.status(50_000_000), ClockStatus::Locked);
        let start_group = rig.group_at(50_000_000) + 1_000_000_000;
        let mismatch = ResolutionMismatch {
            reported_ns: 1_001,
            configured_ns: 1_000,
        };
        // Ingress refuses before the receiver sees the datagram, so the replay window consumes nothing.
        let wire = rig.packet(0, 0, start_group, 1);
        assert_eq!(rig.ingest(&wire), Err(MediaRefusal::Resolution(mismatch)));
        assert_eq!(rig.media.receiver_counters().datagrams_seen, 0);
        // The fitted clock is muted, not reinterpreted under the coarser tick: its fit is gone.
        assert_eq!(rig.clock.status(50_000_000), ClockStatus::Unlocked);
        assert_eq!(rig.clock.stats().resets, 1);
        // A start refuses, and preparation is a configuration refusal with a zero buffer.
        assert_eq!(
            rig.admit(start_group, 0),
            Err(StartRefusal::Resolution(mismatch))
        );
        let mut out = [0xEEu8; BLOCK_PAYLOAD_BYTES];
        assert_eq!(
            rig.prepare(&mut out),
            Ok(Preparation::Misconfigured(mismatch))
        );
        assert!(silent(&out));
        // None of it is a platform clock failure, and the clock was muted once for the mismatch.
        assert_eq!(rig.media.resolution_refusals(), 3);
        assert_eq!(rig.media.clock_faults(), 0);
        assert_eq!(rig.clock.stats().resets, 1);
        assert_eq!(rig.media.engine_stats().packets_seen, 0);
        // A fresh lock of the same clock does not help: the configuration is what is wrong.
        rig.lock(60_000_000, OLD_TIMELINE_NS + 60_000_000);
        rig.at(120_000_000);
        assert_eq!(rig.clock.status(120_000_000), ClockStatus::Locked);
        assert_eq!(
            rig.prepare(&mut out),
            Ok(Preparation::Misconfigured(mismatch))
        );
        assert_eq!(
            rig.admit(start_group, 0),
            Err(StartRefusal::Resolution(mismatch))
        );
        // A clock configured for the platform's tick, locked again and started again, works.
        let mut cfg = GroupClockConfig::standard().expect("config");
        cfg.timer_resolution_ns = 2_000;
        rig.clock = GroupClock::new(cfg, 1, 7, 100).expect("clock");
        rig.lock(130_000_000, OLD_TIMELINE_NS + 130_000_000);
        rig.at(200_000_000);
        let new_start = rig.group_at(200_000_000) + 1_000_000_000;
        rig.admit(new_start, 0)
            .expect("admitted on the configured clock");
        let wire = rig.packet(0, 0, new_start, 1);
        assert_eq!(rig.ingest(&wire), Ok(Admission::Admitted));
        assert_eq!(rig.media.receiver_counters().datagrams_seen, 1);
        let new_local = rig.local_of(new_start, 200_000_000);
        rig.at(new_local - 1_000_000);
        assert!(matches!(
            rig.prepare(&mut out),
            Ok(Preparation::Prepared(_))
        ));
        assert_eq!(
            rig.media.resolution_refusals(),
            5,
            "no refusal after the swap"
        );
    }
    fn selected_fec_rig() -> (Rig, franken_stream::fec::SessionConfig) {
        use franken_stream::fec;
        let mut rig = Rig::new();
        rig.media = MediaPlayout::new(
            receiver(),
            PlayoutProfile::MUSIC,
            PlayoutConfig {
                work_ns: 1_000_000,
                lead_ns: 1_000_000,
                tolerance_ns: 0,
            },
            &synthetic_ledger(2 * 1024 * 1024),
            0,
        )
        .unwrap();
        rig.lock(0, OLD_TIMELINE_NS);
        rig.at(50_000_000);
        let start = rig.group_at(50_000_000) + 500_000_000;
        rig.admit(start, 0).unwrap();
        let config = fec::SessionConfig {
            stream: stream_id(),
            epoch: 1,
            presentation_origin_ns: start,
            key: key(),
        };
        let bytes = rig.media.resident_bytes() + fec::Receiver::resident_bytes() as u64;
        rig.media
            .enable_host_fec(config.clone(), &synthetic_ledger(bytes), 0)
            .unwrap();
        (rig, config)
    }

    fn fec_prepare_block(
        rig: &mut Rig,
        cfg: &franken_stream::fec::SessionConfig,
        block: u64,
    ) -> (Outcome, [u8; 1024]) {
        let presentation = cfg.presentation_origin_ns + frames_to_ns(block * 256);
        let mut local = rig.local_of(presentation - 2_500_000, rig.time.get());
        for _ in 0..8 {
            let uncertainty = rig.clock.report(local).uncertainty_ns.unwrap().max(500_000);
            let cutoff = franken_stream::playout::consume_by(
                presentation,
                1_000_000,
                1_000_000,
                uncertainty,
            );
            let group = rig.group_at(local);
            if group >= cutoff {
                break;
            }
            local += cutoff - group;
        }
        rig.at(local);
        let mut out = [0; 1024];
        let outcome = match rig.prepare(&mut out).unwrap() {
            Preparation::Prepared(block) => block.decision.outcome,
            Preparation::Quiet {
                poll: Poll::Decision(decision),
                ..
            } => decision.outcome,
            other => panic!("missing real N04 decision: {other:?}"),
        };
        assert_eq!(rig.media.engine.snapshot().cursor, block + 1);
        (outcome, out)
    }

    #[test]
    fn n06_media_relock_catches_up_absolute_window_without_restarting_the_healthy_group() {
        use franken_stream::fec::{self, BYTES, K, N};
        use std::sync::atomic::AtomicBool;
        let (mut joining, cfg) = selected_fec_rig();
        let (mut healthy, healthy_cfg) = selected_fec_rig();
        assert_eq!(
            joining.media.host_fec_identity(),
            healthy.media.host_fec_identity()
        );
        assert_eq!(
            cfg.presentation_origin_ns,
            healthy_cfg.presentation_origin_ns
        );
        let source: [[u8; BYTES]; K] = std::array::from_fn(|i| [i as u8 + 31; BYTES]);
        let digest = fec::content_digest(&cfg.metadata(0).unwrap(), &source);
        for rig in [&mut joining, &mut healthy] {
            rig.at(70_000_000);
            for (esi, payload) in source.iter().enumerate() {
                let wire = fec::sign_symbol(&cfg, 0, esi, 0, digest, payload).unwrap();
                assert_eq!(
                    rig.media
                        .ingest_authenticated(&mut rig.platform, &mut rig.clock, &wire)
                        .unwrap()
                        .admission,
                    Some(Admission::Admitted)
                );
            }
            assert_eq!(fec_prepare_block(rig, &cfg, 0), (Outcome::Real, source[0]));
        }
        let identity = joining.media.host_fec_identity();
        joining.errno.set(-ENOSYS_PPC);
        joining.at(600_000_000); // The original presentation origin has passed.
        assert_eq!(
            joining.media.poll_host_fec(
                &mut joining.platform,
                &mut joining.clock,
                &AtomicBool::new(false)
            ),
            Err(MediaRefusal::Clock(ClockError::Absent))
        );
        joining.errno.set(0);
        joining.lock(650_000_000, OLD_TIMELINE_NS + 650_000_000);
        joining.at(700_000_000);
        let window = 32_u64;
        let anchor_frame = window * 1024;
        let anchor_presentation = cfg.presentation_origin_ns + frames_to_ns(anchor_frame);
        let healthy_before = healthy.media.engine.snapshot();
        joining.admit(anchor_presentation, anchor_frame).unwrap();
        assert_eq!(joining.media.engine.snapshot().cursor, window * 4);
        assert_eq!(joining.media.host_fec_identity(), identity);
        assert_eq!(healthy.media.engine.snapshot(), healthy_before);
        assert_eq!(healthy.media.host_fec_identity(), identity);
        assert!(
            joining
                .admit(anchor_presentation, anchor_frame + 256)
                .is_err()
        );
        assert_eq!(joining.media.host_fec_identity(), identity);
        for block in 1..40 {
            let _ = fec_prepare_block(&mut healthy, &cfg, block);
        }

        let source: [[u8; BYTES]; K] = std::array::from_fn(|i| [i as u8 + 91; BYTES]);
        let digest = fec::content_digest(&cfg.metadata(window).unwrap(), &source);
        healthy.at(760_000_000);
        joining.at(760_000_000);
        // Healthy members keep ordinary originals. The relocking member receives
        // the SAME original stream's absolute-window equations, never re-signed window0.
        for (esi, payload) in source.iter().enumerate() {
            let wire = fec::sign_symbol(&cfg, window, esi, 0, digest, payload).unwrap();
            assert_eq!(
                healthy
                    .media
                    .ingest_authenticated(&mut healthy.platform, &mut healthy.clock, &wire)
                    .unwrap()
                    .admission,
                Some(Admission::Admitted)
            );
        }
        for esi in 2..N {
            let wire = fec::sign_symbol(
                &cfg,
                window,
                esi,
                if esi < K { 0 } else { 2 },
                digest,
                &fec::encode_symbol(&source, esi).unwrap(),
            )
            .unwrap();
            let event = joining
                .media
                .ingest_authenticated(&mut joining.platform, &mut joining.clock, &wire)
                .unwrap();
            assert_eq!(
                event.credit_key(),
                IngressIdentity {
                    stream: cfg.stream.get(),
                    epoch: cfg.epoch,
                    origin_ns: cfg.presentation_origin_ns,
                    format: if esi < K {
                        AuthenticatedFormat::N06Source
                    } else {
                        AuthenticatedFormat::N06RepairSymbol
                    },
                    sequence: window * 8 + esi as u64
                }
            );
        }
        let mut ready = false;
        for step in 0..1000 {
            joining.at(820_000_000 + step * 30_000);
            match joining
                .media
                .poll_host_fec(
                    &mut joining.platform,
                    &mut joining.clock,
                    &AtomicBool::new(false),
                )
                .unwrap()
            {
                fec::DecodeState::Pending => {}
                fec::DecodeState::Ready => {
                    ready = true;
                    break;
                }
                other => panic!("absolute-window relock state {other:?}"),
            }
        }
        assert!(ready);
        assert_eq!(
            joining.media.host_fec_status().unwrap().counters.recovered,
            2
        );
        for block in 40..window * 4 {
            let _ = fec_prepare_block(&mut healthy, &cfg, block);
        }
        let mut output = Vec::new();
        for slot in 0..2 {
            let block = window * 4 + slot;
            for (member, rig) in [("healthy", &mut healthy), ("relocked", &mut joining)] {
                let (outcome, bytes) = fec_prepare_block(rig, &cfg, block);
                assert_eq!((outcome, bytes), (Outcome::Real, source[slot as usize]));
                // Reuse the existing digest dependency: zero probe metadata and
                // four copies of the ACTUAL output. Python derives it separately.
                let hash: String = fec::content_digest(&[0; 64], &[bytes; K])
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                output.push(serde_json::json!({"member":member,"block":block,"outcome":outcome.code(),"pcm_probe_sha256":hash}));
            }
        }
        assert_eq!(healthy.media.host_fec_identity(), identity);
        assert_eq!(joining.media.host_fec_identity(), identity);
        println!(
            "N06-RELOCK {}",
            serde_json::json!({"schema":"n06.relock.v1","profile":fec::PROFILE,"origin_before":cfg.presentation_origin_ns,"origin_after":joining.media.host_fec_origin(),"healthy_origin":healthy.media.host_fec_origin(),"epoch":cfg.epoch,"window":window,"anchor_frame":anchor_frame,"joined_cursor":joining.media.engine.snapshot().cursor,"healthy_cursor":healthy.media.engine.snapshot().cursor,"output":output})
        );
    }

    #[test]
    fn n06_media_ready_second_platform_read_fault_retires_without_publication() {
        use franken_stream::fec::{self, BYTES, K, N};
        use std::sync::atomic::AtomicBool;
        let (mut rig, cfg) = selected_fec_rig();
        let source: [[u8; BYTES]; K] = std::array::from_fn(|i| [i as u8 + 3; BYTES]);
        let digest = fec::content_digest(&cfg.metadata(0).unwrap(), &source);
        rig.at(70_000_000);
        for esi in 2..N {
            let wire = fec::sign_symbol(
                &cfg,
                0,
                esi,
                if esi < K { 0 } else { 2 },
                digest,
                &fec::encode_symbol(&source, esi).unwrap(),
            )
            .unwrap();
            rig.media
                .ingest_authenticated(&mut rig.platform, &mut rig.clock, &wire)
                .unwrap();
        }
        let mut faulted = false;
        for step in 0..1000 {
            rig.at(130_000_000 + step * 30_000);
            let before = rig.reads.get();
            rig.fail_read.set(Some(before + 2));
            match rig.media.poll_host_fec(
                &mut rig.platform,
                &mut rig.clock,
                &AtomicBool::new(false),
            ) {
                Ok(fec::DecodeState::Pending) => assert_eq!(rig.reads.get(), before + 1),
                Err(MediaRefusal::Clock(ClockError::Absent)) => {
                    assert_eq!(rig.reads.get(), before + 2);
                    faulted = true;
                    break;
                }
                other => panic!("second-read mutation must be observable: {other:?}"),
            }
        }
        assert!(
            faulted,
            "the actual Ready path must request its second platform reading"
        );
        assert_eq!(rig.media.host_fec_status().unwrap().counters.recovered, 0);
        assert_eq!(rig.media.host_fec_status().unwrap().reserved_work, 0);
        assert_eq!(rig.media.engine_stats().repairs_seen, 0);
        assert_eq!(rig.media.engine.snapshot().queued, 2);
        let mut out = [0xee; BYTES];
        assert_eq!(
            rig.prepare(&mut out),
            Ok(Preparation::Refused(MuteReason::ClockFault))
        );
        assert_eq!(out, [0; BYTES]);
        println!(
            "N06-FRESH-CLOCK {}",
            serde_json::json!({"schema":"n06.fresh-clock.v1","profile":fec::PROFILE,"faulted":faulted,"recovered":rig.media.host_fec_status().unwrap().counters.recovered,"queued":rig.media.engine.snapshot().queued,"repairs_seen":rig.media.engine_stats().repairs_seen,"clock_faults":rig.media.clock_faults()})
        );
    }

    #[test]
    fn n06_media_consumer_selects_budgeted_fec_and_returns_authenticated_typed_sequence() {
        use franken_stream::fec::{self, BYTES, K, N};
        use std::sync::atomic::AtomicBool;
        let mut rig = Rig::new();
        rig.media = MediaPlayout::new(
            receiver(),
            PlayoutProfile::MUSIC,
            PlayoutConfig {
                work_ns: 1_000_000,
                lead_ns: 1_000_000,
                tolerance_ns: 0,
            },
            &synthetic_ledger(2 * 1024 * 1024),
            0,
        )
        .unwrap();
        rig.lock(0, OLD_TIMELINE_NS);
        rig.at(50_000_000);
        let start = rig.group_at(50_000_000) + 500_000_000;
        rig.admit(start, 0).unwrap();
        let config = fec::SessionConfig {
            stream: stream_id(),
            epoch: 1,
            presentation_origin_ns: start,
            key: key(),
        };
        let before = rig.media.engine.snapshot();
        let held = rig.media.resident_bytes();
        let need = fec::Receiver::resident_bytes() as u64;
        assert!(matches!(
            rig.media
                .enable_host_fec(config.clone(), &synthetic_ledger(held + need - 1), 0),
            Err(HostFecAdmitError::Capacity { .. })
        ));
        assert_eq!(rig.media.engine.snapshot(), before);
        assert!(rig.media.host_fec_status().is_none());
        rig.media
            .enable_host_fec(config.clone(), &synthetic_ledger(held + need), 0)
            .unwrap();
        assert_eq!(rig.media.resident_bytes(), held + need);
        let source: [[u8; BYTES]; K] = std::array::from_fn(|i| [i as u8 + 1; BYTES]);
        let digest = fec::content_digest(&config.metadata(0).unwrap(), &source);
        rig.at(70_000_000);
        let legacy_wire = fec::sign_symbol(&config, 0, 2, 0, digest, &source[2]).unwrap();
        let before_auth = rig.media.host_fec_status().unwrap().counters.auth_work;
        assert_eq!(
            rig.ingest(&legacy_wire),
            Err(MediaRefusal::Fec(fec::Refusal::TypedIngressRequired))
        );
        assert_eq!(
            rig.media.host_fec_status().unwrap().counters.auth_work,
            before_auth
        );
        let mut last_sequence = 0;
        for esi in 2..N {
            let wire = fec::sign_symbol(
                &config,
                0,
                esi,
                if esi < K { 0 } else { 2 },
                digest,
                &fec::encode_symbol(&source, esi).unwrap(),
            )
            .unwrap();
            let event = rig
                .media
                .ingest_authenticated(&mut rig.platform, &mut rig.clock, &wire)
                .unwrap();
            last_sequence = event.sequence;
            assert_eq!(
                event.admission,
                if esi < K {
                    Some(Admission::Admitted)
                } else {
                    None
                }
            );
            assert_eq!(event.sequence, esi as u64);
            assert_eq!(event.source_epoch, 1);
            assert_eq!(event.wire_bytes, fec::DATAGRAM);
            assert_eq!(
                event.format,
                if esi < K {
                    AuthenticatedFormat::N06Source
                } else {
                    AuthenticatedFormat::N06RepairSymbol
                }
            );
        }
        assert_eq!(
            rig.media.receiver_counters().datagrams_seen,
            0,
            "selected input must not be authenticated twice as N01"
        );
        let mut completed = false;
        for step in 0..1000 {
            rig.at(130_000_000 + step * 30_000);
            let state = rig
                .media
                .poll_host_fec(&mut rig.platform, &mut rig.clock, &AtomicBool::new(false))
                .unwrap();
            if state == fec::DecodeState::Ready {
                completed = true;
                break;
            }
            assert_eq!(state, fec::DecodeState::Pending);
        }
        assert!(completed);
        assert_eq!(rig.media.host_fec_status().unwrap().counters.recovered, 2);
        // The real platform/N03 bridge finds the N04 cutoff, then the existing
        // consumer prepares the authenticated recovered block for downstream.
        let presentation_local = rig.local_of(start, 160_000_000);
        let uncertainty = rig
            .clock
            .report(presentation_local)
            .uncertainty_ns
            .unwrap()
            .max(500_000);
        let target = franken_stream::playout::consume_by(start, 1_000_000, 1_000_000, uncertainty);
        let mut local = rig.local_of(target, presentation_local);
        for _ in 0..8 {
            let uncertainty = rig.clock.report(local).uncertainty_ns.unwrap().max(500_000);
            let cutoff =
                franken_stream::playout::consume_by(start, 1_000_000, 1_000_000, uncertainty);
            let now = rig.group_at(local);
            if now >= cutoff {
                break;
            }
            local += cutoff - now;
        }
        rig.at(local);
        let mut out = [0; BYTES];
        let Preparation::Prepared(block) = rig.prepare(&mut out).unwrap() else {
            panic!("selected N06 did not reach existing prepared consumer")
        };
        assert_eq!(block.decision.outcome, Outcome::Real);
        assert_eq!(out, source[0]);
        assert_eq!(rig.media.engine.snapshot().cursor, 1);
        println!(
            "N06-CONSUMER {}",
            serde_json::json!({"schema":"n06.consumer.v1","profile":fec::PROFILE,"status":rig.media.host_fec_status().unwrap(),"cursor":rig.media.engine.snapshot().cursor,"typed_sequence":last_sequence,"authentication_once":rig.media.receiver_counters().datagrams_seen==0})
        );
    }

    #[test]
    fn n06_media_clock_fault_mute_relock_and_readmission_resume_real_recovery() {
        use franken_stream::fec::{self, BYTES, K, N};
        use std::sync::atomic::AtomicBool;
        let mut rig = Rig::new();
        rig.media = MediaPlayout::new(
            receiver(),
            PlayoutProfile::MUSIC,
            PlayoutConfig {
                work_ns: 1_000_000,
                lead_ns: 1_000_000,
                tolerance_ns: 0,
            },
            &synthetic_ledger(2 * 1024 * 1024),
            0,
        )
        .unwrap();
        rig.lock(0, OLD_TIMELINE_NS);
        rig.at(50_000_000);
        let start = rig.group_at(50_000_000) + 500_000_000;
        rig.admit(start, 0).unwrap();
        let mut config = fec::SessionConfig {
            stream: stream_id(),
            epoch: 1,
            presentation_origin_ns: start,
            key: key(),
        };
        let capacity = rig.media.resident_bytes() + fec::Receiver::resident_bytes() as u64;
        rig.media
            .enable_host_fec(config.clone(), &synthetic_ledger(capacity), 0)
            .unwrap();
        let source: [[u8; BYTES]; K] = std::array::from_fn(|i| [i as u8 + 11; BYTES]);
        rig.at(70_000_000);
        let digest = fec::content_digest(&config.metadata(0).unwrap(), &source);
        for esi in 2..N {
            let wire = fec::sign_symbol(
                &config,
                0,
                esi,
                if esi < K { 0 } else { 2 },
                digest,
                &fec::encode_symbol(&source, esi).unwrap(),
            )
            .unwrap();
            rig.media
                .ingest_authenticated(&mut rig.platform, &mut rig.clock, &wire)
                .unwrap();
        }
        rig.at(130_000_000);
        assert_eq!(
            rig.media
                .poll_host_fec(&mut rig.platform, &mut rig.clock, &AtomicBool::new(false)),
            Ok(fec::DecodeState::Pending)
        );
        let work = rig.media.host_fec_status().unwrap().counters.decode_work;
        let auth = rig.media.host_fec_status().unwrap().counters.auth_work;
        rig.errno.set(-ENOSYS_PPC);
        rig.at(140_000_000);
        assert_eq!(
            rig.media
                .poll_host_fec(&mut rig.platform, &mut rig.clock, &AtomicBool::new(false)),
            Err(MediaRefusal::Clock(ClockError::Absent))
        );
        rig.errno.set(0);
        rig.at(150_000_000);
        let wire = fec::sign_symbol(&config, 0, 0, 0, digest, &source[0]).unwrap();
        assert_eq!(
            rig.media
                .ingest_authenticated(&mut rig.platform, &mut rig.clock, &wire),
            Err(MediaRefusal::Fec(fec::Refusal::Clock))
        );
        assert_eq!(
            rig.media
                .poll_host_fec(&mut rig.platform, &mut rig.clock, &AtomicBool::new(false)),
            Err(MediaRefusal::Fec(fec::Refusal::Clock))
        );
        assert_eq!(
            rig.media.host_fec_status().unwrap().counters.decode_work,
            work
        );
        assert_eq!(
            rig.media.host_fec_status().unwrap().counters.auth_work,
            auth
        );
        assert_eq!(rig.media.host_fec_status().unwrap().counters.recovered, 0);
        assert_eq!(rig.media.host_fec_status().unwrap().reserved_work, 0);
        assert_eq!(rig.media.engine.snapshot().cursor, 0);
        let mut out = [0xee; BYTES];
        assert_eq!(
            rig.prepare(&mut out),
            Ok(Preparation::Refused(MuteReason::ClockFault))
        );
        assert_eq!(out, [0; BYTES]);

        rig.lock(150_000_000, OLD_TIMELINE_NS + 150_000_000);
        rig.at(200_000_000);
        assert_eq!(
            rig.prepare(&mut out),
            Ok(Preparation::Refused(MuteReason::NotAdmitted))
        );
        let new_start = rig.group_at(200_000_000) + 500_000_000;
        rig.admit(new_start, 0).unwrap();
        config.presentation_origin_ns = new_start;
        let digest = fec::content_digest(&config.metadata(0).unwrap(), &source);
        rig.at(220_000_000);
        for esi in 2..N {
            let wire = fec::sign_symbol(
                &config,
                0,
                esi,
                if esi < K { 0 } else { 2 },
                digest,
                &fec::encode_symbol(&source, esi).unwrap(),
            )
            .unwrap();
            rig.media
                .ingest_authenticated(&mut rig.platform, &mut rig.clock, &wire)
                .unwrap();
        }
        let mut ready = false;
        for step in 0..1000 {
            rig.at(280_000_000 + step * 30_000);
            match rig
                .media
                .poll_host_fec(&mut rig.platform, &mut rig.clock, &AtomicBool::new(false))
                .unwrap()
            {
                fec::DecodeState::Pending => {}
                fec::DecodeState::Ready => {
                    ready = true;
                    break;
                }
                other => panic!("unexpected resumed state {other:?}"),
            }
        }
        assert!(ready);
        assert_eq!(rig.media.host_fec_status().unwrap().counters.recovered, 2);
        let mut local = rig.local_of(new_start - 2_500_000, 320_000_000);
        for _ in 0..8 {
            let uncertainty = rig.clock.report(local).uncertainty_ns.unwrap().max(500_000);
            let cutoff =
                franken_stream::playout::consume_by(new_start, 1_000_000, 1_000_000, uncertainty);
            let now = rig.group_at(local);
            if now >= cutoff {
                break;
            }
            local += cutoff - now;
        }
        rig.at(local);
        let Preparation::Prepared(block) = rig.prepare(&mut out).unwrap() else {
            panic!("relocked FEC did not reach N04 output")
        };
        assert_eq!(block.decision.outcome, Outcome::Real);
        assert_eq!(out, source[0]);
        assert_eq!(rig.media.engine.snapshot().cursor, 1);
    }

    #[test]
    fn n06_media_baseline_remains_n01_and_unselected_fec_cannot_change_it() {
        use franken_stream::fec;
        let (mut rig, start, _) = admitted_rig(500_000_000);
        let config = fec::SessionConfig {
            stream: stream_id(),
            epoch: 1,
            presentation_origin_ns: start,
            key: key(),
        };
        let source = [[1; fec::BYTES]; fec::K];
        let wire = fec::sign_symbol(
            &config,
            0,
            2,
            0,
            fec::content_digest(&config.metadata(0).unwrap(), &source),
            &source[2],
        )
        .unwrap();
        let before = rig.media.engine.snapshot();
        assert!(matches!(rig.ingest(&wire), Err(MediaRefusal::Stream(_))));
        assert_eq!(rig.media.engine.snapshot(), before);
        let plain = rig.packet(0, 0, start, 1);
        let event = rig
            .media
            .ingest_authenticated(&mut rig.platform, &mut rig.clock, &plain)
            .unwrap();
        assert_eq!(event.sequence, 0);
        assert_eq!(event.format, AuthenticatedFormat::N01Media);
        assert_eq!(event.admission, Some(Admission::Admitted));
        assert!(rig.media.host_fec_status().is_none());
    }
}
