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
//!   to ([`PlayoutMemberReport::clamped_readings`]). Each clamp increases the reported uncertainty by the
//!   distance held; exceeding the group clock policy makes the view unusable.
//! * **Oracles that do not trust the engine.** A block the engine plays as `Real` must carry exactly the bytes the sender
//!   sent for that block (an FNV-1a digest taken at send time); a different byte is a campaign error. After the run
//!   every block must have been decided exactly once ([`NodePlayout::finish`]).
//!
//! * **Streams.** A source change is a new stream (N01 §4: a fresh stream id, the receiver told to rebind), and the N04
//!   engine holds exactly one stream (`begin_stream` clears its queue). So each stream generation has its own engine
//!   ([`NodePlayout::open_stream`]): the old one drains the blocks below the cutover frame, the new one is bound when the
//!   change is admitted and already holds the new stream's blocks, which arrive about 490 ms before the old tail has
//!   drained. A packet goes to the engine of its own stream; one for a stream whose last block is decided is refused.
//! * **The publish gate.** Every block the pump sends is first passed through the source arbiter's gate ([`Publish`]), so
//!   a replaced adapter that keeps offering its blocks is refused and its audio never reaches a member.
//! * **Planted faults.** A [`LinkFault`] acts on the packets of one block position (arrives late, swaps arrival order
//!   with its neighbour, or is joined by a previous-epoch datagram), and the harness can leap a node's own clock; the
//!   engine, the sender, the schedule and the receiver are still the real ones.
//!
//! What this is not: a model of N04 (the engine is the real one), evidence of any device, provider or audio output, or a
//! check of concealment quality. The render costs below are illustrative simulation values (the same ones N04's vectors
//! use), not board numbers.

use std::collections::BTreeMap;

use franken_clock::group::GroupClock;
use franken_dsp::{FRAMES_PER_BLOCK, StereoAudioBlock};
use franken_stream::playout::{
    BLOCK_PAYLOAD_BYTES, Decision, MediaPacket, Outcome, PlayoutConfig, PlayoutEngine,
    PlayoutProfile, Poll, frames_to_ns,
};
use franken_stream::{
    AuthenticatedStreamPacket, OutboundFrame, StreamError, StreamReceiver, StreamSender,
};
use franken_test_support::NetworkSchedule;
use serde::{Deserialize, Serialize};

use crate::clock_view::ClockViewBridge as MonotoneReading;
use crate::harness::SimNodeClock;

/// Time the render path spends between the engine's decision and the DMA submission, and the lead it needs to submit
/// before the presentation instant. Illustrative simulation values (N04's vectors use the same), not measurements.
pub(crate) const RENDER_WORK_NS: u64 = 1_500_000;
pub(crate) const RENDER_LEAD_NS: u64 = 2_000_000;
/// How far a packet's own presentation time may differ from the engine's timeline (N04 requires less than half a block).
pub(crate) const TIMELINE_TOLERANCE_NS: u64 = 100_000;
/// How long before its presentation the block of [`LinkFault::Late`] arrives: after the engine decided it (`work + lead` =
/// 3.5 ms before), so it cannot be played, and yet before the block would have sounded, so it is not merely lost.
pub(crate) const LATE_BEFORE_PRESENTATION_NS: u64 = 500_000;
/// How long before the block's own packet the previous-epoch datagram of [`LinkFault::StaleEpoch`] arrives.
pub(crate) const STALE_LEAD_NS: u64 = 1_000_000;

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
    /// Packets handed to the engine whose block was lower than one already handed to it. Jitter makes some; so does a
    /// late packet, and a duplicate of an earlier block counts like any other.
    pub out_of_order_arrivals: u64,
    /// Planted previous-epoch datagrams that the member's own receiver refused as stale (N01's check, the first line; the
    /// engine's `wrong_epoch` is the second).
    pub stale_refused_at_receiver: u64,
    /// Stream generations this member's playout opened: 1 for its negotiated stream, one more for every source change.
    pub streams_opened: u64,
    /// Packets that arrived for a stream whose last block had already been decided (it was retired at its cutover).
    pub retired_stream_refused: u64,
    /// Planted datagrams of the stream a source change replaced that the member's own receiver refused as `WRONG_STREAM`.
    pub wrong_stream_refused_at_receiver: u64,
    /// Blocks the replaced adapter offered after its replacement that the arbiter's publish gate refused, by the gate's
    /// stable refusal code.
    pub replaced_publishes_refused: BTreeMap<String, u64>,
}

/// A defect planted in the link between one member's sender and its engine. It acts on the packets of one block position;
/// the sender, the seeded schedule and the member's receiver are called exactly as they are without it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkFault {
    /// The block's packet arrives [`LATE_BEFORE_PRESENTATION_NS`] before the block is presented: after the engine has
    /// decided the block, and before the block would have sounded.
    Late { block: u64 },
    /// The packets of `block` and `block + 1` swap arrival instants.
    SwapArrivals { block: u64 },
    /// A datagram of the previous epoch, keyed with the member's own media key and carrying other audio, arrives
    /// [`STALE_LEAD_NS`] before the block's own packet.
    StaleEpoch { block: u64 },
    /// A datagram of the stream a source change replaced, keyed with the member's own media key and carrying other audio,
    /// sent by the old sender after the member's receiver rebound to the new stream.
    StaleStream { block: u64 },
}

/// A sender and a receiver one epoch before the member's stream, keyed with the member's own media key: what a datagram of
/// the previous epoch looks like on the wire, and once an old receiver has authenticated it.
pub(crate) struct PreviousEpoch {
    pub sender: StreamSender,
    pub receiver: StreamReceiver,
}

/// The sender's end for one member, as the render loop holds it.
pub(crate) struct SendLink<'a> {
    pub member_id: &'a str,
    pub sender: &'a mut StreamSender,
    pub receiver: &'a mut StreamReceiver,
    pub schedule: &'a mut NetworkSchedule,
    /// The defect planted on this member's link, if any.
    pub fault: Option<LinkFault>,
    /// The previous-epoch endpoints a [`LinkFault::StaleEpoch`] needs.
    pub previous: Option<&'a mut PreviousEpoch>,
    /// The sender of the stream a source change replaced, which a [`LinkFault::StaleStream`] sends with.
    pub replaced: Option<&'a mut StreamSender>,
    /// The source arbiter's publish gate, when the campaign has one.
    pub publish: Option<Publish<'a>>,
}

/// What a block must pass before the pump sends it: the source arbiter's publish gate and, as a planted defect, a replaced
/// adapter that keeps offering its own blocks after it was told to stop.
pub(crate) struct Publish<'a> {
    /// From this block on the replaced adapter offers each block before the owner does. `None`: it stops when replaced.
    pub stale_from: Option<u64>,
    /// The frame the replaced adapter offers for a block.
    pub stale_frame: &'a dyn Fn(u64) -> OutboundFrame,
    /// The arbiter's answer for a block: `Ok` if the adapter asked may publish it, else the refusal's stable code. The flag
    /// says which adapter is asked: `true` the replaced one, `false` the owner.
    pub gate: &'a dyn Fn(bool, u64) -> Result<(), String>,
}

/// One block as the link carries it: when the seeded schedule delivers it (and its duplicate), and the packet the member's
/// receiver authenticated.
struct Sent {
    deliver_rel_ns: u64,
    duplicate_rel_ns: Option<u64>,
    packet: AuthenticatedStreamPacket,
}

/// One stream generation of a member's playout: its id on the wire and its own N04 engine (see the module documentation).
struct StreamEngine {
    stream_id: u64,
    engine: PlayoutEngine,
    /// The first block this stream carries.
    first_block: u64,
    /// The first block of the next stream: this one decides nothing at or after it. `None` while it is the latest.
    until_block: Option<u64>,
}

impl StreamEngine {
    /// Blocks below the cutover that this stream has not decided yet.
    fn owes(&self) -> bool {
        self.until_block
            .is_some_and(|until| self.engine.snapshot().cursor < until)
    }

    /// Every block below the cutover is decided: nothing of this stream is wanted any more.
    fn retired(&self) -> bool {
        self.until_block
            .is_some_and(|until| self.engine.snapshot().cursor >= until)
    }
}

/// One member's playout: its engines (one per stream), the packets in flight to them, and the sender's progress.
pub(crate) struct NodePlayout {
    /// Stream generations in block order; empty exactly when negotiation left the member without a stream.
    engines: Vec<StreamEngine>,
    /// Group time at which block 0 is presented: every later stream continues this timeline.
    origin_group_ns: u64,
    mono: MonotoneReading,
    /// Authenticated packets that have been sent and not yet arrived: (arrival true time, block, copy) -> packet.
    in_flight: BTreeMap<(u64, u64, u8), AuthenticatedStreamPacket>,
    /// The next block this member's sender will send.
    next_send: u64,
    /// Digest of the payload sent for each block that has not been decided yet.
    sent_digest: BTreeMap<u64, u64>,
    blocks_without_a_decision: u64,
    catch_up_decisions: u64,
    /// The highest block handed to an engine so far, and how many packets came after a higher one.
    highest_delivered: Option<u64>,
    out_of_order: u64,
    stale_refused_at_receiver: u64,
    retired_stream_refused: u64,
    wrong_stream_refused_at_receiver: u64,
    replaced_refusals: BTreeMap<String, u64>,
}

/// A fresh N04 engine bound to `stream_epoch`, with `anchor_block` presented at `anchor_group_ns` on the group clock.
fn new_engine(
    stream_epoch: u64,
    anchor_block: u64,
    anchor_group_ns: u64,
) -> Result<PlayoutEngine, String> {
    let cfg = PlayoutConfig {
        work_ns: RENDER_WORK_NS,
        lead_ns: RENDER_LEAD_NS,
        tolerance_ns: TIMELINE_TOLERANCE_NS,
    };
    let mut engine = PlayoutEngine::new(PlayoutProfile::MUSIC, cfg)
        .map_err(|e| format!("playout configuration refused: {}", e.code()))?;
    engine
        .begin_stream(
            stream_epoch,
            anchor_block * (FRAMES_PER_BLOCK as u64),
            anchor_group_ns,
        )
        .map_err(|e| format!("playout stream refused: {}", e.code()))?;
    Ok(engine)
}

impl NodePlayout {
    /// A member with no stream: nothing to send, nothing to decide.
    pub(crate) fn unbound() -> Self {
        Self {
            engines: Vec::new(),
            origin_group_ns: 0,
            mono: MonotoneReading::default(),
            in_flight: BTreeMap::new(),
            next_send: 0,
            sent_digest: BTreeMap::new(),
            blocks_without_a_decision: 0,
            catch_up_decisions: 0,
            highest_delivered: None,
            out_of_order: 0,
            stale_refused_at_receiver: 0,
            retired_stream_refused: 0,
            wrong_stream_refused_at_receiver: 0,
            replaced_refusals: BTreeMap::new(),
        }
    }

    /// A member whose stream `stream_id` is bound to `stream_epoch`, block 0 presented at `anchor_group_ns` on the group
    /// clock.
    pub(crate) fn bind(
        stream_id: u64,
        stream_epoch: u64,
        anchor_group_ns: u64,
    ) -> Result<Self, String> {
        let engine = new_engine(stream_epoch, 0, anchor_group_ns)?;
        Ok(Self {
            engines: vec![StreamEngine {
                stream_id,
                engine,
                first_block: 0,
                until_block: None,
            }],
            origin_group_ns: anchor_group_ns,
            ..Self::unbound()
        })
    }

    /// The first block this member's sender has not sent yet: where a source change admitted now cuts over.
    pub(crate) fn first_unsent(&self) -> u64 {
        self.next_send
    }

    /// A source change was admitted: open stream `stream_id` at `cutover_block`. Its own engine is bound now, so it takes the
    /// new stream's packets as they arrive; the previous stream's engine keeps deciding the blocks below the cutover (drain
    /// to a common future cutover) and is retired once it has. The new stream continues the group's timeline.
    pub(crate) fn open_stream(
        &mut self,
        stream_id: u64,
        stream_epoch: u64,
        cutover_block: u64,
    ) -> Result<(), String> {
        let Some(latest) = self.engines.last() else {
            return Err("a stream was opened on a member that has none".to_string());
        };
        if cutover_block <= latest.first_block {
            return Err(format!(
                "a stream cannot start at block {cutover_block}, the latest one starts at {}",
                latest.first_block
            ));
        }
        if self.engines.iter().any(|e| e.stream_id == stream_id) {
            return Err(format!("stream {stream_id:#x} was already opened"));
        }
        let anchor_group_ns =
            self.origin_group_ns + frames_to_ns(cutover_block * (FRAMES_PER_BLOCK as u64));
        let engine = new_engine(stream_epoch, cutover_block, anchor_group_ns)?;
        if let Some(latest) = self.engines.last_mut() {
            latest.until_block = Some(cutover_block);
        }
        self.engines.push(StreamEngine {
            stream_id,
            engine,
            first_block: cutover_block,
            until_block: None,
        });
        Ok(())
    }

    /// The stream generation that decides block `blk`: the latest one that starts at or before it.
    fn engine_index_for_block(&self, blk: u64) -> Option<usize> {
        self.engines.iter().rposition(|e| e.first_block <= blk)
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
            let mut first = self.send_block(blk, link, tl, frame_for)?;
            // A planted swap needs both packets' arrival instants, so the pair is sent together, still in block order.
            let mut second = None;
            if link.fault == Some(LinkFault::SwapArrivals { block: blk })
                && self.next_send < total_blocks
            {
                let next = self.next_send;
                self.next_send += 1;
                second = self.send_block(next, link, tl, frame_for)?;
                if let (Some(a), Some(b)) = (first.as_mut(), second.as_mut()) {
                    std::mem::swap(&mut a.deliver_rel_ns, &mut b.deliver_rel_ns);
                }
            }
            if link.fault == Some(LinkFault::Late { block: blk })
                && let Some(sent) = first.as_mut()
            {
                sent.deliver_rel_ns = (tl.send_rel_ns(blk) + tl.horizon_ns)
                    .saturating_sub(LATE_BEFORE_PRESENTATION_NS);
            }
            let genuine_rel_ns = first.as_ref().map(|sent| sent.deliver_rel_ns);
            for sent in first.into_iter().chain(second) {
                self.stage_sent(sent, tl);
            }
            if link.fault == Some(LinkFault::StaleEpoch { block: blk }) {
                self.plant_stale(blk, genuine_rel_ns, link, tl, frame_for)?;
            }
            if link.fault == Some(LinkFault::StaleStream { block: blk }) {
                self.plant_stale_stream(blk, link, frame_for)?;
            }
        }
        Ok(())
    }

    /// Send one block: the member's N01 sender, the seeded schedule (asked once, for this block) and, if the schedule
    /// delivers it, the member's receiver. `None` when the schedule drops the block.
    fn send_block(
        &mut self,
        blk: u64,
        link: &mut SendLink<'_>,
        tl: &CampaignTimeline,
        frame_for: &dyn Fn(u64) -> OutboundFrame,
    ) -> Result<Option<Sent>, String> {
        let frame = match link.publish.as_ref() {
            None => frame_for(blk),
            Some(publish) => {
                // The replaced adapter, if it keeps publishing, offers first; the gate decides. A refusal of it is counted by
                // its code. If the gate lets it through, its frame is what is sent, and the harness's bytes oracle finds out.
                let mut offered = None;
                if publish.stale_from.is_some_and(|from| blk >= from) {
                    match (publish.gate)(true, blk) {
                        Ok(()) => offered = Some((publish.stale_frame)(blk)),
                        Err(code) => *self.replaced_refusals.entry(code).or_default() += 1,
                    }
                }
                match offered {
                    Some(frame) => frame,
                    None => {
                        (publish.gate)(false, blk).map_err(|code| {
                            format!(
                                "member {}: the publish gate refused the owner's block {blk}: {code}",
                                link.member_id
                            )
                        })?;
                        frame_for(blk)
                    }
                }
            }
        };
        let payload_digest = digest(&frame.payload);
        let wire = link.sender.send(frame).map_err(|e| {
            format!(
                "member {}: block {blk} could not be encoded: {e}",
                link.member_id
            )
        })?;
        let decision = link.schedule.evaluate_packet(blk, tl.send_rel_ns(blk));
        if decision.dropped {
            return Ok(None);
        }
        let Some(deliver_rel_ns) = decision.deliver_time_ns else {
            return Ok(None);
        };
        let packet = link.receiver.accept(&wire).map_err(|e| {
            format!(
                "member {}: block {blk} refused by the receiver: {e}",
                link.member_id
            )
        })?;
        self.sent_digest.insert(blk, payload_digest);
        Ok(Some(Sent {
            deliver_rel_ns,
            duplicate_rel_ns: decision.duplicate_deliver_time_ns,
            packet,
        }))
    }

    /// Stage a sent block's duplicate (copy 1, if the schedule made one) and the block itself (copy 0).
    fn stage_sent(&mut self, sent: Sent, tl: &CampaignTimeline) {
        if let Some(duplicate_rel_ns) = sent.duplicate_rel_ns {
            self.stage(tl.origin_ns + duplicate_rel_ns, 1, sent.packet.clone());
        }
        self.stage(tl.origin_ns + sent.deliver_rel_ns, 0, sent.packet);
    }

    /// Plant a datagram of the previous epoch for `blk`, other audio than the block's own, arriving [`STALE_LEAD_NS`]
    /// before the block's own packet (`genuine_rel_ns`). The member's own receiver must refuse it as stale: it is keyed
    /// with the member's media key, so only its epoch is wrong. It is then authenticated by the previous epoch's receiver
    /// and handed to the engine, which must refuse it again: the second line, for a node whose engine moved to a new epoch
    /// before its receiver did.
    fn plant_stale(
        &mut self,
        blk: u64,
        genuine_rel_ns: Option<u64>,
        link: &mut SendLink<'_>,
        tl: &CampaignTimeline,
        frame_for: &dyn Fn(u64) -> OutboundFrame,
    ) -> Result<(), String> {
        let member = link.member_id;
        let Some(previous) = link.previous.as_deref_mut() else {
            return Err(format!(
                "member {member}: a previous-epoch datagram was planted on a stream with no earlier epoch"
            ));
        };
        let mut frame = frame_for(blk);
        // Other audio than the block's own: a stale packet that was ever played would fail the bytes check.
        for byte in &mut frame.payload {
            *byte = !*byte;
        }
        let wire = previous.sender.send(frame).map_err(|e| {
            format!("member {member}: the previous-epoch datagram for block {blk} could not be encoded: {e}")
        })?;
        match link.receiver.accept(&wire) {
            Err(StreamError::StaleSessionEpoch { .. }) => self.stale_refused_at_receiver += 1,
            Err(other) => {
                return Err(format!(
                    "member {member}: the previous-epoch datagram for block {blk} was refused for another reason: {other}"
                ));
            }
            Ok(_) => {
                return Err(format!(
                    "member {member}: the receiver accepted a datagram of the previous epoch for block {blk}"
                ));
            }
        }
        let packet = previous.receiver.accept(&wire).map_err(|e| {
            format!("member {member}: the previous epoch's own receiver refused its datagram for block {blk}: {e}")
        })?;
        let genuine = genuine_rel_ns.unwrap_or_else(|| tl.send_rel_ns(blk) + STALE_LEAD_NS);
        self.stage(
            tl.origin_ns + genuine.saturating_sub(STALE_LEAD_NS),
            2,
            packet,
        );
        Ok(())
    }

    /// Send a datagram of the stream a source change replaced for `blk`, with other audio than the block's own. It is the
    /// old sender's, keyed with the member's media key, so only its stream identity is wrong: the member's own receiver
    /// (rebound to the new stream) must refuse it as `WRONG_STREAM` (N01 §3 step 6). The engine never sees it.
    fn plant_stale_stream(
        &mut self,
        blk: u64,
        link: &mut SendLink<'_>,
        frame_for: &dyn Fn(u64) -> OutboundFrame,
    ) -> Result<(), String> {
        let member = link.member_id;
        let Some(replaced) = link.replaced.as_deref_mut() else {
            return Err(format!(
                "member {member}: a previous-stream datagram was planted on a stream that no source change replaced"
            ));
        };
        let mut frame = frame_for(blk);
        for byte in &mut frame.payload {
            *byte = !*byte;
        }
        let wire = replaced.send(frame).map_err(|e| {
            format!("member {member}: the previous-stream datagram for block {blk} could not be encoded: {e}")
        })?;
        match link.receiver.accept(&wire) {
            Err(StreamError::WrongStream { .. }) => self.wrong_stream_refused_at_receiver += 1,
            Err(other) => {
                return Err(format!(
                    "member {member}: the previous-stream datagram for block {blk} was refused for another reason: {other}"
                ));
            }
            Ok(_) => {
                return Err(format!(
                    "member {member}: the receiver accepted a datagram of the replaced stream for block {blk}"
                ));
            }
        }
        Ok(())
    }

    /// Hand each engine the staged packets of its own stream that arrive at or before `until_true_ns`, in arrival order,
    /// each with the view of the node's own clock at its arrival instant.
    pub(crate) fn deliver_until(
        &mut self,
        clock: &GroupClock,
        sim: &SimNodeClock,
        until_true_ns: u64,
    ) -> Result<(), String> {
        if self.engines.is_empty() {
            return Ok(());
        }
        while let Some((&(arrival, _, _), _)) = self.in_flight.first_key_value() {
            if arrival > until_true_ns {
                break;
            }
            let Some((_, packet)) = self.in_flight.pop_first() else {
                break;
            };
            let block = packet.start_frame / (FRAMES_PER_BLOCK as u64);
            if self
                .highest_delivered
                .is_some_and(|highest| block < highest)
            {
                self.out_of_order += 1;
            }
            self.highest_delivered = self.highest_delivered.max(Some(block));
            let stream = packet.stream_id.get();
            let Some(at) = self.engines.iter().position(|e| e.stream_id == stream) else {
                return Err(format!(
                    "a packet of stream {stream:#x} reached a playout path that has no such stream"
                ));
            };
            if self.engines[at].retired() {
                self.retired_stream_refused += 1;
                continue;
            }
            let view = self.mono.at_local(clock, sim.local(arrival));
            let media = MediaPacket::from_authenticated(&packet)
                .ok_or_else(|| "a repair packet reached the playout path".to_string())?;
            let _ = self.engines[at].engine.on_packet(view, &media);
        }
        Ok(())
    }

    /// Decide block `blk`: deliver what has arrived by the decision instant, then ask the engine of the stream that owns
    /// the block. The engine must answer with this block (or with an earlier one it still owed, which is counted); a block
    /// it plays as real must carry the bytes the sender sent.
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
        let Some(idx) = self.engine_index_for_block(blk) else {
            return Err(format!("block {blk} decided on a member with no stream"));
        };
        // A stream whose cutover has passed must have decided everything below it. If the clock was unusable when its last
        // blocks were due, it still owes them; a source change during a clock outage is not supported, and says so.
        if let Some(owing) = self.engines[..idx].iter().position(StreamEngine::owes) {
            return Err(format!(
                "block {blk}: stream {owing} still owes decisions at its cutover (the clock was unusable); a source change during a clock outage is not supported"
            ));
        }
        let mut bytes = [0u8; BLOCK_PAYLOAD_BYTES];
        loop {
            let view = self.mono.at_local(clock, sim.local(at));
            match self.engines[idx].engine.decide(view, &mut bytes) {
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

    /// The state oracle for the end of a run of `total_blocks` positions: for every stream, every position it carries was
    /// decided exactly once (unless the clock was unusable for some), nothing is queued beyond the profile, and the
    /// engine's decision counters add up to its cursor.
    pub(crate) fn finish(&self, total_blocks: u64) -> Result<(), String> {
        for (index, stream) in self.engines.iter().enumerate() {
            let snap = stream.engine.snapshot();
            let s = stream.engine.stats();
            let decided = s.decided_real
                + s.decided_concealed
                + s.decided_muted_gap
                + s.decided_muted_nohistory
                + s.decided_muted_overdue
                + s.decided_skipped;
            let span = snap.cursor.checked_sub(stream.first_block).ok_or_else(|| {
                format!(
                    "stream {index}: the cursor ({}) is before the stream's first block ({})",
                    snap.cursor, stream.first_block
                )
            })?;
            if decided != span {
                return Err(format!(
                    "stream {index}: the engine's decisions ({decided}) do not add up to its cursor ({})",
                    snap.cursor
                ));
            }
            let end = stream.until_block.unwrap_or(total_blocks);
            if snap.cursor > end {
                return Err(format!(
                    "stream {index}: the engine decided {} blocks of {end}",
                    snap.cursor
                ));
            }
            if self.blocks_without_a_decision == 0 && snap.cursor != end {
                return Err(format!(
                    "stream {index}: {end} blocks were due and the engine decided {}",
                    snap.cursor
                ));
            }
        }
        Ok(())
    }

    /// The member's counters, summed over its streams.
    pub(crate) fn report(&self) -> PlayoutMemberReport {
        let mut r = PlayoutMemberReport {
            catch_up_decisions: self.catch_up_decisions,
            blocks_without_a_decision: self.blocks_without_a_decision,
            clamped_readings: self.mono.clamped_readings(),
            out_of_order_arrivals: self.out_of_order,
            stale_refused_at_receiver: self.stale_refused_at_receiver,
            streams_opened: u64::try_from(self.engines.len()).unwrap_or(u64::MAX),
            retired_stream_refused: self.retired_stream_refused,
            wrong_stream_refused_at_receiver: self.wrong_stream_refused_at_receiver,
            replaced_publishes_refused: self.replaced_refusals.clone(),
            ..PlayoutMemberReport::default()
        };
        for stream in &self.engines {
            let s = stream.engine.stats();
            r.packets_offered += s.packets_seen;
            r.admitted += s.admitted;
            r.duplicate += s.duplicate;
            r.late += s.late;
            r.wrong_epoch += s.stale_epoch + s.future_epoch;
            r.clock_refused += s.clock_unusable + s.clock_regressions;
            r.otherwise_refused +=
                s.bad_input + s.too_far_ahead + s.timeline_mismatch + s.not_bound;
            r.decided_real += s.decided_real;
            r.decided_concealed += s.decided_concealed;
            r.decided_muted_gap += s.decided_muted_gap;
            r.decided_muted_nohistory += s.decided_muted_nohistory;
            r.decided_muted_overdue += s.decided_muted_overdue;
            r.decided_skipped += s.decided_skipped;
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
    /// The stream id the unit tests' wires use.
    const STREAM: u64 = 0x5EED_5EED_0000_0001;
    /// A second stream: what a source change opens.
    const STREAM_B: u64 = 0x5EED_5EED_0000_0002;
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
                play: NodePlayout::bind(STREAM, engine_epoch, tl.pts_group_ns(0)).expect("binds"),
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
        assert_eq!(m.clamped_readings(), 0);
        assert_eq!(m.stamp(90), 100, "a reading that stepped back is raised");
        assert_eq!(m.stamp(99), 100);
        assert_eq!(m.clamped_readings(), 2);
        assert_eq!(m.stamp(101), 101);
        assert_eq!(m.stamp(100), 101);
        assert_eq!(m.clamped_readings(), 3);
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
        let mut play = NodePlayout::bind(STREAM, 1, tl.pts_group_ns(0)).expect("binds");
        let frame_for = |blk: u64| Wire::frame(&timeline(), blk, source_bytes(blk));
        let mut link = SendLink {
            member_id: "spk-test",
            sender: &mut wire.sender,
            receiver: &mut wire.receiver,
            schedule: &mut schedule,
            fault: None,
            previous: None,
            replaced: None,
            publish: None,
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

    /// The previous-epoch endpoints for the unit tests' stream: the same key and stream id, one epoch earlier (epoch 0).
    fn previous_epoch() -> PreviousEpoch {
        let id = StreamId::new(0x5EED_5EED_0000_0001).expect("stream id");
        PreviousEpoch {
            sender: StreamSender::new(StreamKey::from_bytes([0x42; 32]), id, 0),
            receiver: StreamReceiver::new(StreamKey::from_bytes([0x42; 32]), id, 0),
        }
    }

    /// A member whose whole run goes through `send_until` over a link with no loss, no duplicates and no jitter, so a packet
    /// arrives at the instant it is sent and the plant is the only thing that is not in block order.
    struct Pumped {
        play: NodePlayout,
        clock: GroupClock,
        sim: SimNodeClock,
        tl: CampaignTimeline,
        wire: Wire,
        total: u64,
    }

    impl Pumped {
        fn new(fault: Option<LinkFault>, total: u64) -> Self {
            let (sim, tl) = (sim(), timeline());
            let mut wire = Wire::new(1);
            let mut previous = previous_epoch();
            let mut schedule = NetworkSchedule::new(NetworkScheduleConfig {
                seed: 7,
                independent_loss_bps: 0,
                burst_loss_interval_ns: 0,
                max_jitter_ns: 0,
                duplicate_bps: 0,
                ..NetworkScheduleConfig::default()
            });
            let mut play = NodePlayout::bind(STREAM, 1, tl.pts_group_ns(0)).expect("binds");
            let frame_for = |blk: u64| Wire::frame(&timeline(), blk, source_bytes(blk));
            play.send_until(
                &mut SendLink {
                    member_id: "spk-test",
                    sender: &mut wire.sender,
                    receiver: &mut wire.receiver,
                    schedule: &mut schedule,
                    fault,
                    previous: Some(&mut previous),
                    replaced: None,
                    publish: None,
                },
                u64::MAX,
                total,
                &tl,
                &frame_for,
            )
            .expect("sends");
            Self {
                play,
                clock: locked_clock(&sim),
                sim,
                tl,
                wire,
                total,
            }
        }

        fn decide_all(&mut self) -> Vec<(Played, Vec<u8>)> {
            (0..self.total)
                .map(|blk| {
                    self.play
                        .decide_with_bytes(blk, &self.tl, &self.clock, &self.sim)
                        .expect("decides")
                })
                .collect()
        }
    }

    /// Every block except `except` was played as real, with exactly the bytes the sender sent for it.
    fn assert_plays_own_bytes(played: &[(Played, Vec<u8>)], except: &[u64]) {
        for (blk, (what, bytes)) in played.iter().enumerate() {
            let blk = blk as u64;
            if except.contains(&blk) {
                continue;
            }
            assert!(matches!(what, Played::Authentic(_)), "block {blk}");
            assert_eq!(*bytes, source_bytes(blk), "block {blk}");
        }
    }

    #[test]
    fn a_planted_late_packet_is_late_its_block_is_concealed_and_the_control_without_the_plant_is_clean()
     {
        // Control: remove the plant and every block is real, nothing is late, nothing arrives out of order.
        let mut control = Pumped::new(None, 60);
        let played = control.decide_all();
        assert_plays_own_bytes(&played, &[]);
        let r = control.play.report();
        assert_eq!(
            (
                r.late,
                r.admitted,
                r.decided_real,
                r.decided_concealed,
                r.out_of_order_arrivals
            ),
            (0, 60, 60, 0, 0)
        );
        control.play.finish(60).expect("every block decided once");

        // Planted: block 20's packet arrives 0.5 ms before its presentation, 3 ms after the engine decided it.
        let mut planted = Pumped::new(Some(LinkFault::Late { block: 20 }), 60);
        let played = planted.decide_all();
        assert_plays_own_bytes(&played, &[20]);
        assert!(matches!(played[20].0, Played::Concealed(_)));
        assert_eq!(played[20].1, concealed_expected(&source_bytes(19), 1));
        let r = planted.play.report();
        assert_eq!(
            (
                r.late,
                r.admitted,
                r.decided_real,
                r.decided_concealed,
                r.out_of_order_arrivals
            ),
            (1, 59, 59, 1, 1)
        );
        planted.play.finish(60).expect("every block decided once");
    }

    #[test]
    fn a_planted_swap_reverses_one_pair_of_arrivals_and_every_block_still_plays_its_own_bytes() {
        let mut control = Pumped::new(None, 60);
        let mut planted = Pumped::new(Some(LinkFault::SwapArrivals { block: 20 }), 60);
        // What was staged: with no jitter a packet arrives when it is sent, so the pair's instants are exactly swapped and
        // every other packet is where it was.
        let key = |blk: u64, other: u64| (ORIGIN + offset(other), blk, 0_u8);
        assert!(planted.play.in_flight.contains_key(&key(20, 21)));
        assert!(planted.play.in_flight.contains_key(&key(21, 20)));
        assert!(!planted.play.in_flight.contains_key(&key(20, 20)));
        assert!(!planted.play.in_flight.contains_key(&key(21, 21)));
        assert_eq!(planted.play.in_flight.len(), control.play.in_flight.len());
        for blk in (0..60).filter(|blk| *blk != 20 && *blk != 21) {
            assert!(planted.play.in_flight.contains_key(&key(blk, blk)));
        }
        // The engine takes block 21 before block 20, and both still play their own bytes, in block order.
        assert_plays_own_bytes(&control.decide_all(), &[]);
        assert_plays_own_bytes(&planted.decide_all(), &[]);
        let (c, p) = (control.play.report(), planted.play.report());
        assert_eq!((c.out_of_order_arrivals, p.out_of_order_arrivals), (0, 1));
        assert_eq!(
            PlayoutMemberReport {
                out_of_order_arrivals: 1,
                ..c
            },
            p,
            "the swap changed the arrival order and nothing else"
        );
    }

    #[test]
    fn a_planted_previous_epoch_datagram_is_refused_by_the_receiver_and_by_the_engine_and_changes_nothing_else()
     {
        let mut control = Pumped::new(None, 60);
        assert_plays_own_bytes(&control.decide_all(), &[]);
        let c = control.play.report();
        assert_eq!(
            (
                c.wrong_epoch,
                c.stale_refused_at_receiver,
                c.packets_offered
            ),
            (0, 0, 60)
        );

        let mut planted = Pumped::new(Some(LinkFault::StaleEpoch { block: 20 }), 60);
        // The planted packet: epoch 0, block 20's position, other audio, 1 ms ahead of the block's own packet.
        let staged = planted
            .play
            .in_flight
            .get(&(ORIGIN + offset(20) - STALE_LEAD_NS, 20, 2))
            .expect("the stale packet is staged");
        assert_eq!(staged.session_epoch, 0);
        assert_eq!(staged.start_frame, 20 * (FRAMES_PER_BLOCK as u64));
        assert_ne!(staged.payload, source_bytes(20));
        // The member's receiver refused it at N01 (its replay window is untouched: the 60 real packets were accepted).
        let counters = planted.wire.receiver.counters();
        assert_eq!((counters.rejected_stale_epoch, counters.accepted), (1, 60));

        let played = planted.decide_all();
        assert_plays_own_bytes(&played, &[]);
        let p = planted.play.report();
        assert_eq!(
            PlayoutMemberReport {
                packets_offered: 61,
                wrong_epoch: 1,
                stale_refused_at_receiver: 1,
                ..c
            },
            p,
            "the engine refused the stale packet as the wrong epoch, and nothing else moved"
        );
        planted.play.finish(60).expect("every block decided once");
    }

    #[test]
    fn a_leaped_node_clock_does_not_latch_a_reading_the_clock_does_not_stand_behind() {
        let sim = sim();
        let clock = locked_clock(&sim);
        let mut latch = MonotoneReading::default();
        let t0 = 700_000_000;
        let before = latch.at_local(&clock, sim.local(t0));
        assert!(before.usable);
        // The node's clock reads 10 000 s more from here on. Its fit is hopelessly stale, but it still extrapolates it, so
        // `group_ns` answers with a time far in the future.
        let leaped = SimNodeClock {
            local0_ns: sim.local0_ns + 10_000_000_000_000,
            ..sim
        };
        let extrapolated = clock.group_ns(leaped.local(t0 + 5_000_000));
        assert!(extrapolated.is_some_and(|g| g > before.group_ns + 9_000_000_000_000));
        let stale = latch.at_local(&clock, leaped.local(t0 + 5_000_000));
        assert!(!stale.usable);
        assert_eq!(
            stale.group_ns, before.group_ns,
            "an unusable reading does not move the latch"
        );
        // The clock is whole again: the next view is the clock's own reading, and nothing was clamped.
        let t1 = t0 + 10_000_000;
        let after = latch.at_local(&clock, sim.local(t1));
        assert!(after.usable);
        assert_eq!(Some(after.group_ns), clock.group_ns(sim.local(t1)));
        assert_eq!(latch.clamped_readings(), 0);
    }

    impl Wire {
        /// A sender and receiver for stream `stream_id` (same media key as [`Wire::new`]), at epoch 1.
        fn on_stream(stream_id: u64) -> Self {
            let id = StreamId::new(stream_id).expect("stream id");
            Self {
                sender: StreamSender::new(StreamKey::from_bytes([0x42; 32]), id, 1),
                receiver: StreamReceiver::new(StreamKey::from_bytes([0x42; 32]), id, 1),
            }
        }
    }

    /// The other program's bytes: every byte of block `blk`'s payload inverted, so no block of one stream can be taken for
    /// the same position of the other.
    fn other_bytes(blk: u64) -> Vec<u8> {
        source_bytes(blk).iter().map(|b| !b).collect()
    }

    /// A member whose first stream carries blocks 0..`cutover` (its audio is [`source_bytes`]) and whose second, opened at
    /// `cutover`, carries the rest to `total` (its audio is [`other_bytes`]). Every packet arrives 5 ms after it was sent.
    struct TwoStreams {
        play: NodePlayout,
        clock: GroupClock,
        sim: SimNodeClock,
        tl: CampaignTimeline,
        old: Wire,
        cutover: u64,
        total: u64,
    }

    impl TwoStreams {
        fn new(cutover: u64, total: u64) -> Self {
            let (sim, tl) = (sim(), timeline());
            let mut play = NodePlayout::bind(STREAM, 1, tl.pts_group_ns(0)).expect("binds");
            let mut old = Wire::on_stream(STREAM);
            let mut new = Wire::on_stream(STREAM_B);
            for blk in 0..cutover {
                let payload = source_bytes(blk);
                play.note_sent(blk, &payload);
                let packet = old.packet(&tl, blk, payload);
                play.stage(tl.send_true_ns(blk) + 5_000_000, 0, packet);
            }
            play.next_send = cutover;
            play.open_stream(STREAM_B, 1, cutover).expect("opens");
            for blk in cutover..total {
                let payload = other_bytes(blk);
                play.note_sent(blk, &payload);
                let packet = new.packet(&tl, blk, payload);
                play.stage(tl.send_true_ns(blk) + 5_000_000, 0, packet);
            }
            Self {
                play,
                clock: locked_clock(&sim),
                sim,
                tl,
                old,
                cutover,
                total,
            }
        }

        fn decide(&mut self, blk: u64) -> (Played, Vec<u8>) {
            self.play
                .decide_with_bytes(blk, &self.tl, &self.clock, &self.sim)
                .expect("decides")
        }
    }

    #[test]
    fn a_new_stream_has_its_own_engine_that_holds_its_blocks_while_the_old_tail_drains() {
        let mut s = TwoStreams::new(20, 40);
        assert_eq!(s.play.first_unsent(), 20);
        // After block 9 is decided, every new-stream block has arrived (5 ms after it was sent, 490 ms before the old tail
        // is drained) and is queued in the new engine: all 20 of them.
        for blk in 0..10 {
            s.decide(blk);
        }
        assert_eq!(s.play.engines[1].engine.snapshot().queued, 20);
        for blk in 10..s.total {
            s.decide(blk);
        }
        let r = s.play.report();
        assert_eq!(
            (r.streams_opened, r.late, r.retired_stream_refused),
            (2, 0, 0)
        );
        s.play
            .finish(40)
            .expect("both streams decided what they carry");
    }

    #[test]
    fn every_block_plays_the_bytes_of_the_stream_that_owns_its_position() {
        let mut s = TwoStreams::new(20, 40);
        for blk in 0..s.total {
            let want = if blk < s.cutover {
                source_bytes(blk)
            } else {
                other_bytes(blk)
            };
            let played = s.decide(blk);
            assert_eq!(authentic(played, blk), want, "block {blk}");
        }
        let r = s.play.report();
        assert_eq!(
            (r.decided_real, r.admitted, r.packets_offered),
            (40, 40, 40)
        );
    }

    #[test]
    fn one_engine_rebound_at_the_cutover_would_discard_the_new_streams_queued_blocks() {
        // Why the new stream gets its own engine: begin_stream clears the engine's queue (N04 §2), so rebinding the one
        // engine at the cutover would throw away every block of the new stream that has already arrived.
        let (sim, tl) = (sim(), timeline());
        let clock = locked_clock(&sim);
        let mut engine = PlayoutEngine::new(
            PlayoutProfile::MUSIC,
            PlayoutConfig {
                work_ns: RENDER_WORK_NS,
                lead_ns: RENDER_LEAD_NS,
                tolerance_ns: TIMELINE_TOLERANCE_NS,
            },
        )
        .expect("engine");
        engine
            .begin_stream(1, 0, tl.pts_group_ns(0))
            .expect("bound");
        let mut wire = Wire::on_stream(STREAM_B);
        let mut mono = MonotoneReading::default();
        for blk in 20..40 {
            let packet = wire.packet(&tl, blk, other_bytes(blk));
            let view = mono.at_local(&clock, sim.local(tl.send_true_ns(blk) + 5_000_000));
            let media = MediaPacket::from_authenticated(&packet).expect("media");
            let _ = engine.on_packet(view, &media);
        }
        assert_eq!(engine.snapshot().queued, 20);
        engine
            .begin_stream(
                1,
                20 * (FRAMES_PER_BLOCK as u64),
                tl.pts_group_ns(0) + frames_to_ns(20 * (FRAMES_PER_BLOCK as u64)),
            )
            .expect("rebound");
        assert_eq!(
            engine.snapshot().queued,
            0,
            "a rebind discards what the new stream had queued"
        );
    }

    #[test]
    fn a_packet_of_a_retired_stream_is_refused_and_a_packet_of_an_unknown_stream_is_an_error() {
        let mut s = TwoStreams::new(20, 40);
        // A late copy of block 5 of the old stream, arriving once the old tail has been decided.
        let late_copy = s.old.packet(&s.tl, 5, source_bytes(5));
        s.play
            .stage(s.tl.decision_true_ns(25) - 1_000_000, 1, late_copy);
        for blk in 0..s.total {
            s.decide(blk);
        }
        let r = s.play.report();
        assert_eq!(
            (
                r.retired_stream_refused,
                r.late,
                r.duplicate,
                r.decided_real
            ),
            (1, 0, 0, 40),
            "the old stream's engine was retired, so the copy never reached it"
        );
        s.play.finish(40).expect("finishes");

        // A stream nobody opened.
        let mut other = Wire::on_stream(0x5EED_5EED_0000_00FF);
        let mut fresh = TwoStreams::new(20, 40);
        let stray = other.packet(&fresh.tl, 3, source_bytes(3));
        fresh.play.stage(fresh.tl.send_true_ns(3), 0, stray);
        let err = match fresh
            .play
            .decide_block(0, &fresh.tl, &fresh.clock, &fresh.sim)
        {
            Err(e) => e,
            Ok(_) => panic!("a packet of an unknown stream was accepted"),
        };
        assert!(err.contains("no such stream"), "{err}");
    }

    #[test]
    fn a_stream_cannot_be_opened_twice_at_the_same_block_or_before_the_latest_one() {
        let tl = timeline();
        let mut play = NodePlayout::bind(STREAM, 1, tl.pts_group_ns(0)).expect("binds");
        assert!(play.open_stream(STREAM_B, 1, 0).is_err());
        play.open_stream(STREAM_B, 1, 10).expect("opens");
        assert!(
            play.open_stream(STREAM, 1, 20).is_err(),
            "a stream id is never reused"
        );
        assert!(
            play.open_stream(0x77, 1, 10).is_err(),
            "not at or before the latest start"
        );
        assert!(NodePlayout::unbound().open_stream(STREAM, 1, 10).is_err());
    }

    /// The pump over a link with no loss, no jitter and no duplicates, with a publish gate and a replaced adapter that keeps
    /// publishing from block 20. The owner's frames are [`source_bytes`], the replaced adapter's [`other_bytes`].
    fn pump_with_gate(
        gate: &dyn Fn(bool, u64) -> Result<(), String>,
    ) -> Result<NodePlayout, String> {
        let tl = timeline();
        let mut wire = Wire::new(1);
        let mut schedule = NetworkSchedule::new(NetworkScheduleConfig {
            seed: 7,
            independent_loss_bps: 0,
            burst_loss_interval_ns: 0,
            max_jitter_ns: 0,
            duplicate_bps: 0,
            ..NetworkScheduleConfig::default()
        });
        let mut play = NodePlayout::bind(STREAM, 1, tl.pts_group_ns(0)).expect("binds");
        let owner = |blk: u64| Wire::frame(&timeline(), blk, source_bytes(blk));
        let stale = |blk: u64| Wire::frame(&timeline(), blk, other_bytes(blk));
        play.send_until(
            &mut SendLink {
                member_id: "spk-test",
                sender: &mut wire.sender,
                receiver: &mut wire.receiver,
                schedule: &mut schedule,
                fault: None,
                previous: None,
                replaced: None,
                publish: Some(Publish {
                    stale_from: Some(20),
                    stale_frame: &stale,
                    gate,
                }),
            },
            u64::MAX,
            40,
            &tl,
            &owner,
        )?;
        Ok(play)
    }

    #[test]
    fn the_publish_gate_decides_whose_frame_is_sent_and_a_refused_adapter_is_counted_by_the_code() {
        let staged = |play: &NodePlayout, blk: u64| {
            play.in_flight
                .get(&(ORIGIN + offset(blk), blk, 0))
                .expect("staged")
                .payload
                .clone()
        };
        // The gate refuses the replaced adapter (as `SOURCE_REPLACED`) and admits the owner.
        let refusing = |replaced: bool, _blk: u64| -> Result<(), String> {
            if replaced {
                Err("SOURCE_REPLACED".to_string())
            } else {
                Ok(())
            }
        };
        let play = pump_with_gate(&refusing).expect("sends");
        for blk in 20..40 {
            assert_eq!(
                staged(&play, blk),
                source_bytes(blk),
                "block {blk}: the owner's audio"
            );
        }
        let r = play.report();
        assert_eq!(
            r.replaced_publishes_refused,
            BTreeMap::from([("SOURCE_REPLACED".to_string(), 20)])
        );

        // Control: with a gate that lets the replaced adapter through, its frames are what goes out.
        let open = |_replaced: bool, _blk: u64| -> Result<(), String> { Ok(()) };
        let play = pump_with_gate(&open).expect("sends");
        for blk in 20..40 {
            assert_eq!(
                staged(&play, blk),
                other_bytes(blk),
                "block {blk}: the replaced adapter's audio"
            );
        }
        assert!(play.report().replaced_publishes_refused.is_empty());
        for blk in 0..20 {
            assert_eq!(
                staged(&play, blk),
                source_bytes(blk),
                "before the replacement"
            );
        }

        // A gate that refuses the owner is a campaign error, not a silent drop.
        let closed = |_replaced: bool, _blk: u64| -> Result<(), String> {
            Err("NOT_SOURCE_OWNER".to_string())
        };
        let err = match pump_with_gate(&closed) {
            Err(e) => e,
            Ok(_) => panic!("a refused owner was sent"),
        };
        assert!(err.contains("refused the owner's block"), "{err}");
    }

    #[test]
    fn a_planted_datagram_of_the_replaced_stream_is_refused_by_the_receiver_and_changes_nothing_else()
     {
        let tl = timeline();
        let run = |fault: Option<LinkFault>| -> Result<(NodePlayout, Wire), String> {
            let mut new = Wire::on_stream(STREAM_B);
            let mut old = StreamSender::new(
                StreamKey::from_bytes([0x42; 32]),
                StreamId::new(STREAM).expect("stream id"),
                1,
            );
            let mut schedule = NetworkSchedule::new(NetworkScheduleConfig {
                seed: 7,
                independent_loss_bps: 0,
                burst_loss_interval_ns: 0,
                max_jitter_ns: 0,
                duplicate_bps: 0,
                ..NetworkScheduleConfig::default()
            });
            let mut play = NodePlayout::bind(STREAM_B, 1, tl.pts_group_ns(0)).expect("binds");
            let owner = |blk: u64| Wire::frame(&timeline(), blk, source_bytes(blk));
            play.send_until(
                &mut SendLink {
                    member_id: "spk-test",
                    sender: &mut new.sender,
                    receiver: &mut new.receiver,
                    schedule: &mut schedule,
                    fault,
                    previous: None,
                    replaced: Some(&mut old),
                    publish: None,
                },
                u64::MAX,
                40,
                &tl,
                &owner,
            )?;
            Ok((play, new))
        };
        let (control, control_wire) = run(None).expect("control");
        let (planted, planted_wire) =
            run(Some(LinkFault::StaleStream { block: 25 })).expect("planted");
        let (c, p) = (control.report(), planted.report());
        assert_eq!(
            (
                c.wrong_stream_refused_at_receiver,
                p.wrong_stream_refused_at_receiver
            ),
            (0, 1)
        );
        assert_eq!(
            PlayoutMemberReport {
                wrong_stream_refused_at_receiver: 1,
                ..c
            },
            p
        );
        // The member's real receiver refused it, by name, and accepted exactly the 40 genuine packets; nothing was staged for it.
        assert_eq!(control_wire.receiver.counters().rejected_wrong_stream, 0);
        assert_eq!(planted_wire.receiver.counters().rejected_wrong_stream, 1);
        assert_eq!(planted_wire.receiver.counters().accepted, 40);
        assert_eq!(planted.in_flight.len(), control.in_flight.len());
        // A fault with no replaced stream to send from is a campaign error.
        let mut wire = Wire::on_stream(STREAM_B);
        let mut schedule = NetworkSchedule::new(NetworkScheduleConfig::default());
        let mut play = NodePlayout::bind(STREAM_B, 1, tl.pts_group_ns(0)).expect("binds");
        let owner = |blk: u64| Wire::frame(&timeline(), blk, source_bytes(blk));
        let err = play
            .send_until(
                &mut SendLink {
                    member_id: "spk-test",
                    sender: &mut wire.sender,
                    receiver: &mut wire.receiver,
                    schedule: &mut schedule,
                    fault: Some(LinkFault::StaleStream { block: 3 }),
                    previous: None,
                    replaced: None,
                    publish: None,
                },
                u64::MAX,
                10,
                &tl,
                &owner,
            )
            .expect_err("nothing to send the stale datagram with");
        assert!(err.contains("no source change replaced"), "{err}");
    }
}
