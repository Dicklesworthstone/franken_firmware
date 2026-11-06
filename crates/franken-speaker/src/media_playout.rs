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
use franken_stream::playout::{
    Admission, BLOCK_PAYLOAD_BYTES, ConfigError, Decision, MediaPacket, Outcome, PlayoutConfig,
    PlayoutEngine, PlayoutProfile, PlayoutStats, Poll, StartReject as EngineStartReject,
};
use franken_stream::{ReceiverCounters, StreamError, StreamReceiver};

use crate::clock_view::ClockViewBridge;

/// Why a datagram did not reach the playout engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaRefusal {
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

/// One speaker's media path for one stream: the receiver, the playout engine and the clock view that joins them.
#[derive(Debug)]
pub struct MediaPlayout {
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
    /// # Errors
    /// The engine's configuration is invalid.
    pub fn new(
        receiver: StreamReceiver,
        profile: PlayoutProfile,
        config: PlayoutConfig,
    ) -> Result<Self, ConfigError> {
        Ok(Self {
            receiver,
            engine: PlayoutEngine::new(profile, config)?,
            bridge: ClockViewBridge::default(),
            clock_faults: 0,
            resolution_refusals: 0,
            resolution_refused: false,
        })
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
            if !self.resolution_refused {
                clock.report_clock_fault();
                self.resolution_refused = true;
            }
            self.resolution_refusals = self.resolution_refusals.saturating_add(1);
            return Err(LocalTimeRefusal::Resolution(mismatch));
        }
        self.resolution_refused = false;
        platform.now_ns().map_err(|error| {
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
        let local_ns = self
            .local_ns(platform, clock)
            .map_err(LocalTimeRefusal::for_ingest)?;
        let packet = self
            .receiver
            .accept(datagram)
            .map_err(MediaRefusal::Stream)?;
        let media = MediaPacket::from_authenticated(&packet).ok_or(MediaRefusal::NotMedia)?;
        let view = self.bridge.at_local(clock, local_ns);
        Ok(self.engine.on_packet(view, &media))
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
            Output::Muted(reason) => return Ok(Preparation::Refused(reason)),
            Output::Armed { starts_in_ns } => Release::Armed { starts_in_ns },
            Output::Audible => Release::Audible,
        };
        let view = self.bridge.at_local(clock, local_ns);
        if !view.usable {
            return Ok(Preparation::TimingUnavailable);
        }
        match self.engine.decide(view, out) {
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
        clock
            .plan_start(sched, local_ns)
            .map_err(StartRefusal::Admission)?;
        self.engine
            .begin_stream(sched.epoch, anchor_frame, sched.start_group_ns)
            .map_err(StartRefusal::Stream)?;
        let plan = clock
            .admit(sched, local_ns)
            .map_err(StartRefusal::Admission)?;
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
        self.receiver.advance_epoch(epoch);
        Ok(())
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
    use franken_stream::playout::{BLOCK_FRAMES, frames_to_ns};
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
    }

    impl KernelOps for TestKernel {
        fn provenance(&self) -> Provenance {
            Provenance::Simulated
        }
        fn backend_abi(&self) -> Option<Abi> {
            None
        }
        fn clock_gettime_monotonic(&mut self, out: &mut Timespec) -> isize {
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
            let kernel = TestKernel {
                now_ns: Rc::clone(&time),
                errno: Rc::clone(&errno),
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
            let media =
                MediaPlayout::new(receiver, PlayoutProfile::MUSIC, config).expect("media path");
            Self {
                time,
                errno,
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
}
