//! The real N04 playout engine inside the Virtual House (`Q01` / `ffw-gmq`).
//!
//! Until now the harness fed each member's blocks to the legacy `BoundedJitterBuffer`, pushing block `k` and pulling it
//! in the same loop iteration. That is a zero-buffer shortcut: nothing was ever held until a cutoff, and no packet could
//! be late, early, reordered or from the wrong epoch in any way the playout code would notice. This module puts
//! `franken_stream::playout::PlayoutEngine` (N04) in that place, unchanged and unwrapped: it only does what the engine
//! cannot do for itself, and each of those is a fact about the simulation, not a model of the engine.
//!
//! * **Time order.** The engine decides block `k` about 496 ms after it was sent (`pts - work - lead`), so the sender runs
//!   ~93 blocks ahead of the renderer. [`NodePlayout::send_until`] is called from the render loop and sends, in block order,
//!   every block whose send instant is not later than the instant the next block is decided. The seeded network schedule,
//!   the N01 sender and `StreamReceiver::accept` are still called exactly once per block, in block order, with the same
//!   arguments as before, so the fault schedule and the N01 behaviour do not change.
//! * **Arrivals.** An authenticated packet is staged at its arrival instant and handed to the engine in arrival order
//!   ([`NodePlayout::deliver_until`]), so jitter really reorders blocks, and a duplicate the schedule produces really
//!   arrives twice (the schedule produced them all along; the legacy path ignored them).
//! * **Views.** Every engine call carries a `ClockView` built from the node's own `GroupClock` (`group_ns`,
//!   `report().uncertainty_ns`, usable while Locked or Holdover) read at the node's own simulated local time, never from
//!   the simulation's true time. The engine refuses a view that goes backwards, and a refreshed clock fit can step a
//!   reading back by a few microseconds; [`MonotoneReading`] never lets the reading fall and **counts** every time it had
//!   to ([`PlayoutMemberReport::clamped_readings`]).
//! * **Oracles that do not trust the engine.** A block the engine plays as `Real` must carry exactly the bytes the sender
//!   sent for that block (an FNV-1a digest taken at send time); a different byte is a campaign error. After the run
//!   every block must have been decided exactly once ([`NodePlayout::finish`]).
//!
//! What this is not: a model of N04 (the engine is the real one), evidence of any device, provider or audio output, or a
//! check of concealment quality. The render costs below are illustrative simulation values (the same ones N04's vectors
//! use), not board numbers.

use std::collections::BTreeMap;

use franken_clock::group::{ClockStatus, GroupClock};
use franken_dsp::{FRAMES_PER_BLOCK, StereoAudioBlock};
use franken_stream::playout::{
    BLOCK_PAYLOAD_BYTES, ClockView, Decision, MediaPacket, Outcome, PlayoutConfig, PlayoutEngine,
    PlayoutProfile, Poll,
};
use franken_stream::{AuthenticatedStreamPacket, OutboundFrame, StreamReceiver, StreamSender};
use franken_test_support::NetworkSchedule;
use serde::{Deserialize, Serialize};

use crate::harness::SimNodeClock;

/// Time the render path spends between the engine's decision and the DMA submission, and the lead it needs to submit
/// before the presentation instant. Illustrative simulation values (N04's vectors use the same), not measurements.
pub(crate) const RENDER_WORK_NS: u64 = 1_500_000;
pub(crate) const RENDER_LEAD_NS: u64 = 2_000_000;
/// How far a packet's own presentation time may differ from the engine's timeline (N04 requires less than half a block).
pub(crate) const TIMELINE_TOLERANCE_NS: u64 = 100_000;

/// The campaign's clocks. In the Virtual House the group clock is true time; `origin_ns` is the true time at which block
/// 0 is sent, `offset_ns(k)` the exact offset of block `k`'s send from it, and a block is presented `horizon_ns` after it
/// is sent.
#[derive(Clone, Copy)]
pub(crate) struct CampaignTimeline {
    pub origin_ns: u64,
    pub horizon_ns: u64,
    pub offset_ns: fn(u64) -> u64,
}

impl CampaignTimeline {
    /// Send instant of block `blk` on the campaign-relative axis the network schedule is evaluated on.
    pub(crate) fn send_rel_ns(&self, blk: u64) -> u64 {
        (self.offset_ns)(blk)
    }

    pub(crate) fn send_true_ns(&self, blk: u64) -> u64 {
        self.origin_ns + self.send_rel_ns(blk)
    }

    /// Group time at which block `blk` is presented; also the presentation time its packet carries.
    pub(crate) fn pts_group_ns(&self, blk: u64) -> u64 {
        self.send_true_ns(blk) + self.horizon_ns
    }

    /// The instant the render loop asks the engine for block `blk`: `work + lead` before its presentation, which is after
    /// the engine's cutoff (`pts - work - lead - uncertainty`) by the clock's uncertainty.
    pub(crate) fn decision_true_ns(&self, blk: u64) -> u64 {
        self.pts_group_ns(blk)
            .saturating_sub(RENDER_WORK_NS + RENDER_LEAD_NS)
    }
}

/// The node's reading of the group clock, never allowed to fall.
#[derive(Debug, Default)]
pub(crate) struct MonotoneReading {
    last_group_ns: u64,
    clamped: u64,
}

impl MonotoneReading {
    /// A group time that is never earlier than the last one handed out; counts the times it had to be raised.
    pub(crate) fn stamp(&mut self, group_ns: u64) -> u64 {
        if group_ns < self.last_group_ns {
            self.clamped += 1;
            return self.last_group_ns;
        }
        self.last_group_ns = group_ns;
        group_ns
    }

    /// The view at true time `true_ns`, from the node's own clock: its local reading of that instant, its group time,
    /// its stated uncertainty, and whether its status lets it be used. With no reading the view is unusable.
    pub(crate) fn view(
        &mut self,
        clock: &GroupClock,
        sim: &SimNodeClock,
        true_ns: u64,
    ) -> ClockView {
        let local = sim.local(true_ns);
        let usable = matches!(
            clock.status(local),
            ClockStatus::Locked | ClockStatus::Holdover
        );
        match (clock.group_ns(local), clock.report(local).uncertainty_ns) {
            (Some(group), Some(uncertainty_ns)) => ClockView {
                group_ns: self.stamp(group),
                uncertainty_ns,
                usable,
            },
            _ => ClockView {
                group_ns: self.last_group_ns,
                uncertainty_ns: 0,
                usable: false,
            },
        }
    }
}

/// FNV-1a over bytes: the digest of what a sender sent, kept to check what the engine plays.
fn digest(bytes: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325_u64;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Why a block that sounds nothing from the engine is silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Silence {
    /// More consecutive blocks missing than the engine conceals.
    Gap,
    /// Nothing had played yet, so there was nothing to conceal with.
    NoHistory,
    /// Decided at or after the block's presentation time.
    Overdue,
    /// Dropped by a coordinated latency decrease.
    Skipped,
}

/// What the engine made of one block position.
pub(crate) enum Played {
    /// The block that arrived in time: exactly the bytes the sender sent.
    Authentic(StereoAudioBlock),
    /// The last played block attenuated by the engine's gain for its run of missing blocks.
    Concealed(StereoAudioBlock),
    Silent(Silence),
    /// The clock could not be used when the block was due: nothing was decided, the engine's cursor did not move, and the
    /// block position is rendered as silence. The engine decides the missed block, as overdue, on a later call.
    NoDecision,
}

/// Counters the report carries for one member's playout: the engine's own, plus what only the adapter can see.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlayoutMemberReport {
    /// Packets handed to the engine, duplicates included.
    pub packets_offered: u64,
    pub admitted: u64,
    pub duplicate: u64,
    /// Arrived at or after the block's cutoff (or after it was decided): never played.
    pub late: u64,
    /// Stale or future stream epoch.
    pub wrong_epoch: u64,
    /// Refused because the clock could not be used or went backwards.
    pub clock_refused: u64,
    /// Bad input, too far ahead, timeline mismatch, or no stream bound.
    pub otherwise_refused: u64,
    pub decided_real: u64,
    pub decided_concealed: u64,
    pub decided_muted_gap: u64,
    pub decided_muted_nohistory: u64,
    pub decided_muted_overdue: u64,
    pub decided_skipped: u64,
    /// Decisions taken for blocks already rendered as silence because the clock was unusable when they were due.
    pub catch_up_decisions: u64,
    /// Block positions rendered as silence because the clock was unusable when the block was due.
    pub blocks_without_a_decision: u64,
    /// Times the node's clock reading had to be raised to keep the engine's views from going backwards.
    pub clamped_readings: u64,
}

/// The sender's end for one member, as the render loop holds it.
pub(crate) struct SendLink<'a> {
    pub member_id: &'a str,
    pub sender: &'a mut StreamSender,
    pub receiver: &'a mut StreamReceiver,
    pub schedule: &'a mut NetworkSchedule,
}

/// One member's playout: the real engine, the packets in flight to it, and the sender's progress.
pub(crate) struct NodePlayout {
    /// `None` exactly when negotiation left the member without a stream.
    engine: Option<PlayoutEngine>,
    mono: MonotoneReading,
    /// Authenticated packets that have been sent and not yet arrived: (arrival true time, block, copy) -> packet.
    in_flight: BTreeMap<(u64, u64, u8), AuthenticatedStreamPacket>,
    /// The next block this member's sender will send.
    next_send: u64,
    /// Digest of the payload sent for each block that has not been decided yet.
    sent_digest: BTreeMap<u64, u64>,
    blocks_without_a_decision: u64,
    catch_up_decisions: u64,
}

impl NodePlayout {
    /// A member with no stream: nothing to send, nothing to decide.
    pub(crate) fn unbound() -> Self {
        Self {
            engine: None,
            mono: MonotoneReading::default(),
            in_flight: BTreeMap::new(),
            next_send: 0,
            sent_digest: BTreeMap::new(),
            blocks_without_a_decision: 0,
            catch_up_decisions: 0,
        }
    }

    /// A member whose stream is bound to `stream_epoch`, block 0 presented at `anchor_group_ns` on the group clock.
    pub(crate) fn bind(stream_epoch: u64, anchor_group_ns: u64) -> Result<Self, String> {
        let cfg = PlayoutConfig {
            work_ns: RENDER_WORK_NS,
            lead_ns: RENDER_LEAD_NS,
            tolerance_ns: TIMELINE_TOLERANCE_NS,
        };
        let mut engine = PlayoutEngine::new(PlayoutProfile::MUSIC, cfg)
            .map_err(|e| format!("playout configuration refused: {}", e.code()))?;
        engine
            .begin_stream(stream_epoch, 0, anchor_group_ns)
            .map_err(|e| format!("playout stream refused: {}", e.code()))?;
        Ok(Self {
            engine: Some(engine),
            ..Self::unbound()
        })
    }

    /// Stage an authenticated packet to arrive at true time `arrival_true_ns` (`copy` 0 is the packet, 1 its duplicate).
    pub(crate) fn stage(
        &mut self,
        arrival_true_ns: u64,
        copy: u8,
        packet: AuthenticatedStreamPacket,
    ) {
        let block = packet.start_frame / (FRAMES_PER_BLOCK as u64);
        self.in_flight
            .insert((arrival_true_ns, block, copy), packet);
    }

    /// Record by hand what the sender sent for `blk` (tests that stage packets themselves; `send_until` records it).
    #[cfg(test)]
    pub(crate) fn note_sent(&mut self, blk: u64, payload: &[u8]) {
        self.sent_digest.insert(blk, digest(payload));
    }

    /// Send, in block order, every block whose send instant is not later than `until_true_ns`. Each block goes through the
    /// member's own N01 sender, the member's seeded network schedule (evaluated on the campaign-relative axis, as it
    /// always was) and, if the schedule delivers it, `StreamReceiver::accept`; a refusal there is a defect in the framing
    /// or the harness, never ordinary loss, so it fails the campaign.
    pub(crate) fn send_until(
        &mut self,
        link: &mut SendLink<'_>,
        until_true_ns: u64,
        total_blocks: u64,
        tl: &CampaignTimeline,
        frame_for: &dyn Fn(u64) -> OutboundFrame,
    ) -> Result<(), String> {
        while self.next_send < total_blocks && tl.send_true_ns(self.next_send) <= until_true_ns {
            let blk = self.next_send;
            self.next_send += 1;
            let frame = frame_for(blk);
            let payload_digest = digest(&frame.payload);
            let wire = link.sender.send(frame).map_err(|e| {
                format!(
                    "member {}: block {blk} could not be encoded: {e}",
                    link.member_id
                )
            })?;
            let decision = link.schedule.evaluate_packet(blk, tl.send_rel_ns(blk));
            if !decision.dropped
                && let Some(deliver_rel_ns) = decision.deliver_time_ns
            {
                let verified = link.receiver.accept(&wire).map_err(|e| {
                    format!(
                        "member {}: block {blk} refused by the receiver: {e}",
                        link.member_id
                    )
                })?;
                self.sent_digest.insert(blk, payload_digest);
                if let Some(dup_rel_ns) = decision.duplicate_deliver_time_ns {
                    self.stage(tl.origin_ns + dup_rel_ns, 1, verified.clone());
                }
                self.stage(tl.origin_ns + deliver_rel_ns, 0, verified);
            }
        }
        Ok(())
    }

    /// Hand the engine every staged packet that arrives at or before `until_true_ns`, in arrival order, each with the
    /// view of the node's own clock at its arrival instant.
    pub(crate) fn deliver_until(
        &mut self,
        clock: &GroupClock,
        sim: &SimNodeClock,
        until_true_ns: u64,
    ) -> Result<(), String> {
        let Some(engine) = self.engine.as_mut() else {
            return Ok(());
        };
        while let Some((&(arrival, _, _), _)) = self.in_flight.first_key_value() {
            if arrival > until_true_ns {
                break;
            }
            let Some((_, packet)) = self.in_flight.pop_first() else {
                break;
            };
            let view = self.mono.view(clock, sim, arrival);
            let media = MediaPacket::from_authenticated(&packet)
                .ok_or_else(|| "a repair packet reached the playout path".to_string())?;
            let _ = engine.on_packet(view, &media);
        }
        Ok(())
    }

    /// Decide block `blk`: deliver what has arrived by the decision instant, then ask the engine. The engine must answer
    /// with this block (or with an earlier one it still owed, which is counted); a block it plays as real must carry the
    /// bytes the sender sent.
    pub(crate) fn decide_block(
        &mut self,
        blk: u64,
        tl: &CampaignTimeline,
        clock: &GroupClock,
        sim: &SimNodeClock,
    ) -> Result<Played, String> {
        self.decide_with_bytes(blk, tl, clock, sim)
            .map(|(played, _)| played)
    }

    /// [`Self::decide_block`] and the bytes the engine left in its buffer for a block it plays as real or concealed
    /// (empty for any other outcome), so the unit tests can hold them to the contract.
    fn decide_with_bytes(
        &mut self,
        blk: u64,
        tl: &CampaignTimeline,
        clock: &GroupClock,
        sim: &SimNodeClock,
    ) -> Result<(Played, Vec<u8>), String> {
        let at = tl.decision_true_ns(blk);
        self.deliver_until(clock, sim, at)?;
        let Some(engine) = self.engine.as_mut() else {
            return Err(format!("block {blk} decided on a member with no stream"));
        };
        let mut bytes = [0u8; BLOCK_PAYLOAD_BYTES];
        loop {
            let view = self.mono.view(clock, sim, at);
            match engine.decide(view, &mut bytes) {
                Poll::Decision(d) if d.block < blk => {
                    // A block already rendered as silence because the clock was unusable when it was due.
                    self.catch_up_decisions += 1;
                    self.sent_digest.remove(&d.block);
                }
                Poll::Decision(d) if d.block == blk => {
                    let sent = self.sent_digest.remove(&d.block);
                    return settle(d, &bytes, sent);
                }
                Poll::Decision(d) => {
                    return Err(format!(
                        "the engine decided block {} while block {blk} was due",
                        d.block
                    ));
                }
                Poll::Pending => {
                    return Err(format!(
                        "the engine was not ready for block {blk} at its own decision instant: view {view:?}"
                    ));
                }
                Poll::ClockUnusable | Poll::ClockRegression => {
                    self.blocks_without_a_decision += 1;
                    return Ok((Played::NoDecision, Vec::new()));
                }
                Poll::NotBound => {
                    return Err(format!("block {blk}: the engine has no stream bound"));
                }
            }
        }
    }

    /// The state oracle for the end of a run of `total_blocks` positions: every position was decided exactly once (unless
    /// the clock was unusable for some), nothing is queued beyond the profile, and the engine's decision counters add up
    /// to its cursor.
    pub(crate) fn finish(&self, total_blocks: u64) -> Result<(), String> {
        let Some(engine) = self.engine.as_ref() else {
            return Ok(());
        };
        let snap = engine.snapshot();
        let s = engine.stats();
        let decided = s.decided_real
            + s.decided_concealed
            + s.decided_muted_gap
            + s.decided_muted_nohistory
            + s.decided_muted_overdue
            + s.decided_skipped;
        if decided != snap.cursor {
            return Err(format!(
                "the engine's decisions ({decided}) do not add up to its cursor ({})",
                snap.cursor
            ));
        }
        if snap.cursor > total_blocks {
            return Err(format!(
                "the engine decided {} blocks of {total_blocks}",
                snap.cursor
            ));
        }
        if self.blocks_without_a_decision == 0 && snap.cursor != total_blocks {
            return Err(format!(
                "{total_blocks} blocks were due and the engine decided {}",
                snap.cursor
            ));
        }
        Ok(())
    }

    /// The member's counters.
    pub(crate) fn report(&self) -> PlayoutMemberReport {
        let mut r = PlayoutMemberReport {
            catch_up_decisions: self.catch_up_decisions,
            blocks_without_a_decision: self.blocks_without_a_decision,
            clamped_readings: self.mono.clamped,
            ..PlayoutMemberReport::default()
        };
        if let Some(engine) = self.engine.as_ref() {
            let s = engine.stats();
            r.packets_offered = s.packets_seen;
            r.admitted = s.admitted;
            r.duplicate = s.duplicate;
            r.late = s.late;
            r.wrong_epoch = s.stale_epoch + s.future_epoch;
            r.clock_refused = s.clock_unusable + s.clock_regressions;
            r.otherwise_refused = s.bad_input + s.too_far_ahead + s.timeline_mismatch + s.not_bound;
            r.decided_real = s.decided_real;
            r.decided_concealed = s.decided_concealed;
            r.decided_muted_gap = s.decided_muted_gap;
            r.decided_muted_nohistory = s.decided_muted_nohistory;
            r.decided_muted_overdue = s.decided_muted_overdue;
            r.decided_skipped = s.decided_skipped;
        }
        r
    }
}

/// Turn the engine's decision for a block, and the bytes it left in the caller's buffer, into what the render path plays.
fn settle(
    d: Decision,
    buffer: &[u8; BLOCK_PAYLOAD_BYTES],
    sent_digest: Option<u64>,
) -> Result<(Played, Vec<u8>), String> {
    let n = usize::from(d.frames) * 4;
    let start_frame = d.block * (FRAMES_PER_BLOCK as u64);
    let decode = || {
        StereoAudioBlock::from_be_i16_bytes(start_frame, &buffer[..n])
            .map_err(|e| format!("block {}: the engine's bytes are not a block: {e}", d.block))
    };
    match d.outcome {
        Outcome::Real => {
            let sent = sent_digest.ok_or_else(|| {
                format!("block {}: played as real but the sender sent none", d.block)
            })?;
            if digest(&buffer[..n]) != sent {
                return Err(format!(
                    "block {}: the engine played bytes the sender did not send",
                    d.block
                ));
            }
            Ok((Played::Authentic(decode()?), buffer[..n].to_vec()))
        }
        Outcome::Concealed { .. } => Ok((Played::Concealed(decode()?), buffer[..n].to_vec())),
        Outcome::MutedGap => Ok((Played::Silent(Silence::Gap), Vec::new())),
        Outcome::MutedNoHistory => Ok((Played::Silent(Silence::NoHistory), Vec::new())),
        Outcome::MutedOverdue => Ok((Played::Silent(Silence::Overdue), Vec::new())),
        Outcome::Skipped => Ok((Played::Silent(Silence::Skipped), Vec::new())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use franken_clock::group::{GroupClockConfig, ProbeResponse};
    use franken_stream::{StreamId, StreamKey};
    use franken_test_support::NetworkScheduleConfig;

    const COORDINATOR: u64 = 0x5EED_C0DE_0000_00AA;
    const ORIGIN: u64 = 250_000_000;
    const HORIZON: u64 = 500_000_000;
    /// N04's concealment gains (`round(0.7^n * 32768)`, n = 1..8), restated here from the contract, not read from the
    /// engine: the expectation must not come from the code under test.
    const GAINS: [i32; 8] = [22938, 16056, 11239, 7868, 5507, 3855, 2699, 1889];

    fn offset(blk: u64) -> u64 {
        (blk * 16_000_000 + 1) / 3
    }

    fn timeline() -> CampaignTimeline {
        CampaignTimeline {
            origin_ns: ORIGIN,
            horizon_ns: HORIZON,
            offset_ns: offset,
        }
    }

    /// A zero-skew node clock, so the node's local readings are the true time plus a constant.
    fn sim() -> SimNodeClock {
        SimNodeClock {
            skew_ppb: 0,
            local0_ns: 5_000_000_000,
        }
    }

    /// A member that took four exchanges (10 ms apart, 400 us each way, 50 us of dwell) with the coordinator.
    fn locked_clock(sim: &SimNodeClock) -> GroupClock {
        let cfg = GroupClockConfig::standard().expect("standard config");
        let mut clock = GroupClock::new(cfg, 1, COORDINATOR, 100).expect("member");
        for k in 1..=4_u64 {
            let t1 = k * 10_000_000;
            let req = clock.next_probe(sim.local(t1));
            let (t2, t3) = (t1 + 400_000, t1 + 450_000);
            let resp = ProbeResponse {
                epoch: 1,
                leader: COORDINATOR,
                seq: req.seq,
                t1_echo_ns: req.t1_local_ns,
                t2_group_ns: t2,
                t3_group_ns: t3,
            };
            clock
                .on_response(resp, sim.local(t3 + 400_000))
                .expect("accepted");
        }
        clock
    }

    /// An N01 sender and receiver for one stream epoch, to make authenticated packets exactly as the campaign does.
    struct Wire {
        sender: StreamSender,
        receiver: StreamReceiver,
    }

    impl Wire {
        fn new(epoch: u64) -> Self {
            let id = StreamId::new(0x5EED_5EED_0000_0001).expect("stream id");
            Self {
                sender: StreamSender::new(StreamKey::from_bytes([0x42; 32]), id, epoch),
                receiver: StreamReceiver::new(StreamKey::from_bytes([0x42; 32]), id, epoch),
            }
        }

        fn frame(tl: &CampaignTimeline, blk: u64, payload: Vec<u8>) -> OutboundFrame {
            let pts = tl.pts_group_ns(blk);
            OutboundFrame::media(
                blk * (FRAMES_PER_BLOCK as u64),
                pts,
                pts - 5_333_333,
                payload,
            )
        }

        fn packet(
            &mut self,
            tl: &CampaignTimeline,
            blk: u64,
            payload: Vec<u8>,
        ) -> AuthenticatedStreamPacket {
            let wire = self
                .sender
                .send(Self::frame(tl, blk, payload))
                .expect("encodes");
            self.receiver.accept(&wire).expect("authentic")
        }
    }

    /// The bytes block `blk` carries, regenerated here from the campaign's source formula.
    fn source_bytes(blk: u64) -> Vec<u8> {
        let amp = ((blk % 32) as f32) * 0.02 + 0.05;
        let mut block = StereoAudioBlock::silence(blk * (FRAMES_PER_BLOCK as u64));
        block.left = [amp; FRAMES_PER_BLOCK];
        block.right = [-amp; FRAMES_PER_BLOCK];
        block.to_be_i16_bytes()
    }

    /// What N04's contract says run `run` of a concealment is: the last played block, each sample scaled by the Q15 gain,
    /// rounded half up.
    fn concealed_expected(last_played: &[u8], run: u8) -> Vec<u8> {
        let gain = GAINS[usize::from(run) - 1];
        last_played
            .as_chunks::<2>()
            .0
            .iter()
            .flat_map(|pair| {
                let s = i32::from(i16::from_be_bytes(*pair));
                i16::try_from((s * gain + 16384) >> 15)
                    .expect("a scaled sample fits")
                    .to_be_bytes()
            })
            .collect()
    }

    struct Scenario {
        play: NodePlayout,
        clock: GroupClock,
        sim: SimNodeClock,
        tl: CampaignTimeline,
        wire: Wire,
    }

    impl Scenario {
        fn new() -> Self {
            Self::with_epochs(1, 1)
        }

        /// The engine is bound to `engine_epoch`; the packets come from a sender of `wire_epoch`.
        fn with_epochs(engine_epoch: u64, wire_epoch: u64) -> Self {
            let (sim, tl) = (sim(), timeline());
            Self {
                play: NodePlayout::bind(engine_epoch, tl.pts_group_ns(0)).expect("binds"),
                clock: locked_clock(&sim),
                sim,
                tl,
                wire: Wire::new(wire_epoch),
            }
        }

        /// Make block `blk`'s packet, note what was sent, and have it arrive `after_send_ns` after its send instant.
        fn arrives(&mut self, blk: u64, after_send_ns: u64) {
            let payload = source_bytes(blk);
            self.play.note_sent(blk, &payload);
            let packet = self.wire.packet(&self.tl, blk, payload);
            let at = self.tl.send_true_ns(blk) + after_send_ns;
            self.play.stage(at, 0, packet);
        }

        fn decide(&mut self, blk: u64) -> (Played, Vec<u8>) {
            self.play
                .decide_with_bytes(blk, &self.tl, &self.clock, &self.sim)
                .expect("decides")
        }

        fn uncertainty_ns(&self, true_ns: u64) -> u64 {
            self.clock
                .report(self.sim.local(true_ns))
                .uncertainty_ns
                .expect("a reading")
        }
    }

    fn authentic((played, bytes): (Played, Vec<u8>), blk: u64) -> Vec<u8> {
        match played {
            Played::Authentic(block) => {
                assert_eq!(block.start_frame, blk * (FRAMES_PER_BLOCK as u64));
                bytes
            }
            Played::Concealed(_) => panic!("block {blk} was concealed"),
            Played::Silent(why) => panic!("block {blk} was silent: {why:?}"),
            Played::NoDecision => panic!("block {blk} had no decision"),
        }
    }

    #[test]
    fn on_time_blocks_play_exactly_the_bytes_that_were_sent() {
        let mut s = Scenario::new();
        for blk in 0..40 {
            s.arrives(blk, 20_000_000 + (blk % 5) * 1_000_000);
        }
        for blk in 0..40 {
            let played = s.decide(blk);
            assert_eq!(authentic(played, blk), source_bytes(blk), "block {blk}");
        }
        let r = s.play.report();
        assert_eq!(
            (
                r.decided_real,
                r.late,
                r.duplicate,
                r.wrong_epoch,
                r.clamped_readings
            ),
            (40, 0, 0, 0, 0)
        );
        s.play.finish(40).expect("every block decided once");
    }

    #[test]
    fn blocks_that_arrive_out_of_order_still_play_in_block_order() {
        let mut s = Scenario::new();
        for blk in 0..20 {
            // Block 4 is held back 40 ms, so it arrives after blocks 5, 6, 7 and 8; none is near its cutoff.
            s.arrives(blk, if blk == 4 { 40_000_000 } else { 5_000_000 });
        }
        for blk in 0..20 {
            let played = s.decide(blk);
            assert_eq!(authentic(played, blk), source_bytes(blk), "block {blk}");
        }
        assert_eq!(s.play.report().late, 0);
    }

    #[test]
    fn a_duplicate_is_refused_and_plays_once() {
        let mut s = Scenario::new();
        for blk in 0..10 {
            s.arrives(blk, 20_000_000);
        }
        let copy = s.wire.packet(&s.tl, 3, source_bytes(3));
        s.play.stage(s.tl.send_true_ns(3) + 21_000_000, 1, copy);
        for blk in 0..10 {
            let played = s.decide(blk);
            assert_eq!(authentic(played, blk), source_bytes(blk), "block {blk}");
        }
        let r = s.play.report();
        assert_eq!((r.duplicate, r.decided_real), (1, 10));
    }

    #[test]
    fn a_missing_block_is_concealed_by_the_contracts_rule_and_the_independent_expectation_agrees() {
        let mut s = Scenario::new();
        let missing = [10_u64, 15, 16];
        for blk in 0..24 {
            if !missing.contains(&blk) {
                s.arrives(blk, 20_000_000);
            }
        }
        let mut last_played: Vec<u8> = Vec::new();
        for blk in 0..24 {
            let (played, bytes) = s.decide(blk);
            match played {
                Played::Authentic(_) => {
                    assert!(!missing.contains(&blk), "block {blk} was missing");
                    assert_eq!(bytes, source_bytes(blk));
                    last_played = bytes;
                }
                Played::Concealed(_) => {
                    assert!(missing.contains(&blk), "block {blk} was not missing");
                    // The run of missing blocks: block 16 is the second in a row, the others the first.
                    let run = if blk == 16 { 2 } else { 1 };
                    assert_eq!(bytes, concealed_expected(&last_played, run), "block {blk}");
                }
                other => panic!(
                    "block {blk}: unexpected {:?}",
                    std::mem::discriminant(&other)
                ),
            }
        }
        let r = s.play.report();
        assert_eq!((r.decided_real, r.decided_concealed), (21, 3));
        s.play.finish(24).expect("every block decided once");
    }

    #[test]
    fn a_long_loss_conceals_a_bounded_number_of_blocks_and_then_mutes() {
        let mut s = Scenario::new();
        for blk in (0..30).filter(|b| !(8..20).contains(b)) {
            s.arrives(blk, 20_000_000);
        }
        let mut kinds = Vec::new();
        for blk in 0..30 {
            kinds.push(match s.decide(blk).0 {
                Played::Authentic(_) => 'r',
                Played::Concealed(_) => 'c',
                Played::Silent(Silence::Gap) => 'g',
                other => panic!("block {blk}: {:?}", std::mem::discriminant(&other)),
            });
        }
        // 12 missing blocks: the profile conceals 8 and then mutes the rest, never extrapolating.
        let line: String = kinds.iter().collect();
        assert_eq!(line, "rrrrrrrrccccccccggggrrrrrrrrrr");
    }

    #[test]
    fn a_block_after_its_cutoff_is_late_and_concealed_even_though_it_arrives_before_presentation() {
        let mut s = Scenario::new();
        let u = s.uncertainty_ns(s.tl.pts_group_ns(8));
        assert!(
            (300_000..1_000_000).contains(&u),
            "the premise: the clock's uncertainty is a few hundred microseconds, got {u}"
        );
        for blk in 0..14 {
            // Block 8 arrives 3.7 ms before it is presented: after its cutoff (3.5 ms plus the uncertainty) and before the
            // render loop asks for it (3.5 ms before presentation).
            let after = if blk == 8 {
                HORIZON - 3_700_000
            } else {
                20_000_000
            };
            s.arrives(blk, after);
        }
        let mut last_played = Vec::new();
        for blk in 0..14 {
            let (played, bytes) = s.decide(blk);
            match played {
                Played::Authentic(_) => {
                    assert_ne!(blk, 8);
                    last_played = bytes;
                }
                Played::Concealed(_) => {
                    assert_eq!(blk, 8);
                    assert_eq!(bytes, concealed_expected(&last_played, 1));
                }
                other => panic!("block {blk}: {:?}", std::mem::discriminant(&other)),
            }
        }
        let r = s.play.report();
        assert_eq!((r.late, r.decided_concealed, r.decided_real), (1, 1, 13));
    }

    #[test]
    fn an_old_block_that_arrives_after_its_decision_is_refused_and_changes_nothing() {
        let mut s = Scenario::new();
        for blk in 0..12 {
            // Block 6 arrives 600 ms after it was sent, 100 ms after the render loop needed it.
            s.arrives(blk, if blk == 6 { 600_000_000 } else { 20_000_000 });
        }
        let mut concealed = Vec::new();
        for blk in 0..12 {
            let (played, bytes) = s.decide(blk);
            match played {
                Played::Authentic(_) => assert_eq!(bytes, source_bytes(blk)),
                Played::Concealed(_) => concealed.push(blk),
                other => panic!("block {blk}: {:?}", std::mem::discriminant(&other)),
            }
        }
        assert_eq!(concealed, [6]);
        // Only now does the old packet reach the engine (it arrives 882 ms into the campaign, after every decision above).
        s.play
            .deliver_until(&s.clock, &s.sim, 900_000_000)
            .expect("delivers");
        let r = s.play.report();
        assert_eq!((r.late, r.decided_real, r.decided_concealed), (1, 11, 1));
        s.play.finish(12).expect("every block decided once");
    }

    #[test]
    fn a_packet_from_another_stream_epoch_is_refused_and_its_block_is_not_played() {
        // Future epoch: the engine is bound to 1, the sender is on 2.
        let mut future = Scenario::with_epochs(1, 2);
        for blk in 0..6 {
            future.arrives(blk, 20_000_000);
        }
        for blk in 0..6 {
            assert!(
                matches!(future.decide(blk).0, Played::Silent(Silence::NoHistory)),
                "block {blk}"
            );
        }
        let r = future.play.report();
        assert_eq!((r.wrong_epoch, r.admitted, r.decided_real), (6, 0, 0));
        // Stale epoch: the engine moved on to 2, the sender is still on 1.
        let mut stale = Scenario::with_epochs(2, 1);
        for blk in 0..6 {
            stale.arrives(blk, 20_000_000);
        }
        for blk in 0..6 {
            assert!(
                matches!(stale.decide(blk).0, Played::Silent(Silence::NoHistory)),
                "block {blk}"
            );
        }
        assert_eq!(stale.play.report().wrong_epoch, 6);
    }

    /// The expectation the oracle holds the integration to, from arithmetic alone: a block that arrives before its cutoff
    /// (`pts - work - lead - uncertainty`) is played, one that arrives at or after it is not.
    fn expected_on_time(
        tl: &CampaignTimeline,
        blk: u64,
        arrival_true_ns: u64,
        uncertainty_ns: u64,
    ) -> bool {
        arrival_true_ns < tl.pts_group_ns(blk) - RENDER_WORK_NS - RENDER_LEAD_NS - uncertainty_ns
    }

    #[test]
    fn the_oracle_trips_on_an_integration_that_stamps_the_send_time_as_the_arrival_time() {
        // Block 12 really arrives 700 ms after it was sent, far past its cutoff. The planted integration gives the engine
        // the send instant instead of the arrival instant, so the block looks on time and is played.
        let run = |stamp_send_time_instead: bool| {
            let mut s = Scenario::new();
            let u = s.uncertainty_ns(s.tl.pts_group_ns(12));
            let true_arrival = s.tl.send_true_ns(12) + 700_000_000;
            for blk in 0..16 {
                if blk == 12 {
                    let at = if stamp_send_time_instead {
                        s.tl.send_true_ns(12)
                    } else {
                        true_arrival
                    };
                    let payload = source_bytes(12);
                    s.play.note_sent(12, &payload);
                    let packet = s.wire.packet(&s.tl, 12, payload);
                    s.play.stage(at, 0, packet);
                } else {
                    s.arrives(blk, 20_000_000);
                }
            }
            let mut played_12 = false;
            for blk in 0..16 {
                let (played, _) = s.decide(blk);
                if blk == 12 {
                    played_12 = matches!(played, Played::Authentic(_));
                }
            }
            (played_12, expected_on_time(&s.tl, 12, true_arrival, u))
        };
        let (observed, expected) = run(false);
        assert!(!expected, "the oracle says block 12 is late");
        assert_eq!(
            observed, expected,
            "the correct integration agrees with the oracle"
        );
        let (planted, expected) = run(true);
        assert!(planted, "the planted integration played the late block");
        assert_ne!(planted, expected, "and the oracle trips on it");
    }

    #[test]
    fn a_real_block_whose_bytes_are_not_the_ones_sent_is_a_campaign_error() {
        let mut s = Scenario::new();
        for blk in 0..2 {
            s.arrives(blk, 20_000_000);
        }
        // Planted: the harness believes block 2 carried block 3's bytes.
        let packet = s.wire.packet(&s.tl, 2, source_bytes(2));
        s.play.note_sent(2, &source_bytes(3));
        s.play.stage(s.tl.send_true_ns(2) + 20_000_000, 0, packet);
        s.decide(0);
        s.decide(1);
        let err = match s.play.decide_block(2, &s.tl, &s.clock, &s.sim) {
            Err(e) => e,
            Ok(_) => panic!("a block with bytes nobody sent was played"),
        };
        assert!(err.contains("did not send"), "{err}");
    }

    #[test]
    fn a_clock_that_cannot_be_used_renders_a_silent_position_and_the_engine_catches_up_as_overdue()
    {
        let mut s = Scenario::new();
        s.clock = GroupClock::new(
            GroupClockConfig::standard().expect("config"),
            1,
            COORDINATOR,
            1,
        )
        .expect("member with no exchange");
        for blk in 0..4 {
            s.arrives(blk, 20_000_000);
        }
        for blk in 0..3 {
            assert!(matches!(s.decide(blk).0, Played::NoDecision), "block {blk}");
        }
        let r = s.play.report();
        assert_eq!((r.blocks_without_a_decision, r.decided_real), (3, 0));
        assert!(
            r.clock_refused > 0,
            "the arrivals were refused for want of a clock"
        );
        // The clock is locked again: the engine decides the three owed blocks, as overdue, and then the due one.
        s.clock = locked_clock(&s.sim);
        assert!(matches!(s.decide(3).0, Played::Silent(Silence::NoHistory)));
        let r = s.play.report();
        assert_eq!((r.catch_up_decisions, r.decided_muted_overdue), (3, 3));
        s.play
            .finish(4)
            .expect("every position was decided once, three of them late");
    }

    #[test]
    fn the_reading_never_falls_and_every_clamp_is_counted() {
        let mut m = MonotoneReading::default();
        assert_eq!(m.stamp(100), 100);
        assert_eq!(m.stamp(100), 100);
        assert_eq!(m.clamped, 0);
        assert_eq!(m.stamp(90), 100, "a reading that stepped back is raised");
        assert_eq!(m.stamp(99), 100);
        assert_eq!(m.clamped, 2);
        assert_eq!(m.stamp(101), 101);
        assert_eq!(m.stamp(100), 101);
        assert_eq!(m.clamped, 3);
    }

    #[test]
    fn finishing_a_run_with_an_undecided_block_is_an_error() {
        let mut s = Scenario::new();
        for blk in 0..5 {
            s.arrives(blk, 20_000_000);
        }
        for blk in 0..5 {
            s.decide(blk);
        }
        s.play.finish(5).expect("five of five");
        let err = s.play.finish(6).expect_err("six were due");
        assert!(err.contains("were due"), "{err}");
        let err = s.play.finish(4).expect_err("only four were due");
        assert!(err.contains("decided 5 blocks of 4"), "{err}");
    }

    #[test]
    fn the_pump_sends_each_block_once_in_order_with_exactly_the_schedules_decisions() {
        let tl = timeline();
        let cfg = NetworkScheduleConfig {
            seed: 7,
            independent_loss_bps: 500,
            duplicate_bps: 500,
            ..NetworkScheduleConfig::default()
        };
        let mut wire = Wire::new(1);
        let mut schedule = NetworkSchedule::new(cfg.clone());
        let mut play = NodePlayout::bind(1, tl.pts_group_ns(0)).expect("binds");
        let frame_for = |blk: u64| Wire::frame(&timeline(), blk, source_bytes(blk));
        let mut link = SendLink {
            member_id: "spk-test",
            sender: &mut wire.sender,
            receiver: &mut wire.receiver,
            schedule: &mut schedule,
        };
        // Everything sent by the first decision instant: 94 blocks (0..=93).
        play.send_until(&mut link, tl.decision_true_ns(0), 1_000, &tl, &frame_for)
            .expect("sends");
        assert_eq!(play.next_send, 94);
        // The expectation: a second schedule with the same seed, asked block by block on the same axis.
        let mut twin = NetworkSchedule::new(cfg);
        let mut expected = BTreeMap::new();
        let mut dropped = 0;
        for blk in 0..94_u64 {
            let d = twin.evaluate_packet(blk, offset(blk));
            if d.dropped {
                dropped += 1;
                continue;
            }
            expected.insert(
                (ORIGIN + d.deliver_time_ns.expect("delivered"), blk, 0_u8),
                (),
            );
            if let Some(dup) = d.duplicate_deliver_time_ns {
                expected.insert((ORIGIN + dup, blk, 1_u8), ());
            }
        }
        assert!(dropped > 0, "the seed drops at least one of 94 at 5%");
        let staged: Vec<_> = play.in_flight.keys().copied().collect();
        let want: Vec<_> = expected.keys().copied().collect();
        assert_eq!(staged, want);
        assert!(play.in_flight.values().all(|p| p.start_frame % 256 == 0));
        // A block is sent once: asking again for the same instant sends nothing.
        play.send_until(&mut link, tl.decision_true_ns(0), 1_000, &tl, &frame_for)
            .expect("sends");
        assert_eq!(play.next_send, 94);
        // And never past the campaign.
        play.send_until(&mut link, u64::MAX, 100, &tl, &frame_for)
            .expect("sends");
        assert_eq!(play.next_send, 100);
    }
}
