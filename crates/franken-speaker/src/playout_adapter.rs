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
//!   the N01 sender are still called exactly once per block, in block order, with the same arguments as before, so the fault
//!   schedule does not change; `StreamReceiver::accept` is called when the datagram ARRIVES (next bullet), not when it is sent.
//! * **Arrivals.** The RAW datagram is staged at its arrival instant ([`InFlight::Raw`]); when it arrives the N01 receiver of
//!   the generation its header names authenticates it ([`NodePlayout::deliver_until`]) and only then is it handed to the engine, in arrival
//!   order, so jitter really reorders blocks. The datagram is authenticated on a TRIAL copy of that receiver, which replaces it only when N01
//!   refused the datagram or the generation permits the authenticated block: an authenticated datagram of another interval (the replaced
//!   adapter's post-cutover block) never moves the window of the tail the generation still owes. The copy is valid only inside the trusted
//!   group epoch (`GroupClock::epoch`) under which its generation was prepared: when that moves, EVERY stale generation is FENCED
//!   (copy dropped, queue cleared, later datagrams refused by name), including the newest or initial generation with no copy.
//!   A later source commit cannot relabel queued epoch-1 data as authorized by epoch 2. A duplicate the schedule produces really arrives twice, and N01's replay window refuses
//!   the second copy (`replay_refused_at_receiver`): it is not an engine duplicate and is not counted as one. A datagram is
//!   routed by the hint `franken_stream::untrusted_route_hint` reads from its own header (stream id, epoch, start frame): attacker-controlled,
//!   allocation-free, never an admission and never a replay-window update. The receiver it selects still checks MAC, identity, epoch and replay.
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
//!   ([`NodePlayout::prepare_stream`] then [`NodePlayout::commit_stream`]): the old one drains the blocks below the cutover frame, the new one is bound when the
//!   change is admitted and already holds the new stream's blocks, which arrive about 490 ms before the old tail has
//!   drained. A packet goes to the engine of its own stream; one for a stream whose last block is decided is refused. A source
//!   commit rebinds the node's receiver to the new stream (N01 holds one stream at a time), so the generation being replaced keeps a
//!   COPY of the receiver as it was ([`StreamEngine`]`.ingress`) for as long as its below-cutover tail is owed: old datagrams still
//!   in flight at the commit are authenticated by it when they arrive, and an authenticated block outside the generation's own
//!   interval (at or after its cutover, or before its first block) is refused (`outside_generation_refused`). The copy is dropped
//!   when the generation retires, and is charged to the member's ledger line while it exists.
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
use franken_platform::MemoryBudgetLedger;
use franken_stream::playout::{
    AdmitError, BLOCK_PAYLOAD_BYTES, Decision, MediaPacket, Outcome, PlayoutConfig, PlayoutEngine,
    PlayoutProfile, Poll, frames_to_ns,
};
use franken_stream::{
    AuthenticatedStreamPacket, OutboundFrame, StreamError, StreamReceiver, StreamSender,
    untrusted_route_hint,
};
use franken_test_support::NetworkSchedule;
use serde::{Deserialize, Serialize};

use crate::clock_view::ClockViewBridge as MonotoneReading;
use crate::harness::SimNodeClock;
use crate::media_playout::{MediaAdmitError, admit_engine, engine_resident_bytes};

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
    /// Datagrams N01's replay window refused when they ARRIVED (the second copy of a duplicate): a refusal of the receiver, never an
    /// engine duplicate.
    #[serde(default)]
    pub replay_refused_at_receiver: u64,
    /// Datagrams refused at ingress, before any engine, for any reason other than a replay: a header that cannot be read, a stream this
    /// member never opened, or a refusal by the selected receiver (a failed MAC, a malformed field, a wrong stream or epoch): damaged or
    /// misrouted data, ordinary network behaviour that nothing in the nominal campaign produces.
    #[serde(default)]
    pub refused_at_receiver: u64,
    /// Datagrams a generation's receiver authenticated whose block lies outside that generation's own interval: the replaced
    /// adapter's blocks at or after the cutover, which are never played.
    #[serde(default)]
    pub outside_generation_refused: u64,
    /// Datagrams authenticated at arrival by the COPY of the receiver a draining generation kept across a source commit: the old
    /// stream's tail that was still in flight when the node's receiver was rebound.
    #[serde(default)]
    pub accepted_by_draining_generation: u64,
    /// Generations a trusted group-epoch change invalidated (receiver copy dropped, queue cleared).
    #[serde(default)]
    pub group_epoch_fenced_generations: u64,
    /// Datagrams refused because their generation had been fenced by a trusted group-epoch change.
    #[serde(default)]
    pub group_epoch_fenced_refused: u64,
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

/// One block as the link carries it: when the seeded schedule delivers it (and its duplicate), and what travels.
struct Sent {
    deliver_rel_ns: u64,
    duplicate_rel_ns: Option<u64>,
    packet: InFlight,
}

/// What is in flight to a member's playout.
#[derive(Clone)]
enum InFlight {
    /// The datagram as it was sent. When it ARRIVES, the routing hint read from its own header selects the generation whose receiver
    /// authenticates it; that receiver still verifies the MAC, the stream identity, the epoch and the replay window. `start_frame` is
    /// the staging key's block only (the sender's own value, or the hint's for a datagram staged by hand, 0 if its header cannot be read).
    Raw { start_frame: u64, wire: Vec<u8> },
    /// A packet some receiver already authenticated: a planted defect that models a hole in the first line of defence, or a unit
    /// test staging a packet by hand.
    Admitted(AuthenticatedStreamPacket),
}

impl InFlight {
    fn start_frame(&self) -> u64 {
        match self {
            Self::Raw { start_frame, .. } => *start_frame,
            Self::Admitted(packet) => packet.start_frame,
        }
    }
}

/// One stream generation of a member's playout: its id on the wire and its own N04 engine (see the module documentation).
struct StreamEngine {
    stream_id: u64,
    engine: PlayoutEngine,
    /// The first block this stream carries.
    first_block: u64,
    /// The first block of the next stream: this one decides nothing at or after it. `None` while it is the latest.
    until_block: Option<u64>,
    /// The copy of the node's receiver this generation keeps while its below-cutover tail is owed: the receiver as it was when the next
    /// stream was committed. `None` for the latest generation (the node's own receiver serves it) and once this one is retired.
    ingress: Option<StreamReceiver>,
    /// The trusted group epoch when this generation was admitted. Independent of source-owner revisions and never refreshed by
    /// a later source commit: the newest generation and queued packets are bound just as strictly as a draining receiver copy.
    admitted_group_epoch: u64,
    /// A trusted group-epoch change invalidated this generation: its copy was dropped and its queue cleared, and nothing
    /// routed to it is accepted any more.
    fenced: bool,
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
    /// Datagrams that have been sent and not yet arrived: (arrival true time, block, copy) -> what travels.
    in_flight: BTreeMap<(u64, u64, u8), InFlight>,
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
    replay_refused_at_receiver: u64,
    refused_at_receiver: u64,
    outside_generation_refused: u64,
    accepted_by_draining_generation: u64,
    group_epoch_fenced_generations: u64,
    group_epoch_fenced_refused: u64,
    replaced_refusals: BTreeMap<String, u64>,
}

/// Why a stream generation could not be opened on a member. Every variant is typed and static (numbers and `&'static str` only), so
/// building one allocates nothing: a refusal caused by memory pressure cannot itself fail for want of memory. Text is made from it
/// only by a caller, after the bounded admission path has returned (`Display`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OpenRefusal {
    /// A stream was opened on a member that has none.
    NoStream,
    /// The new stream would not start after the latest one.
    CutoverNotAfter {
        cutover_block: u64,
        latest_first_block: u64,
    },
    /// The stream id was already opened on this member.
    DuplicateStream(u64),
    /// The shared admission (configuration, platform floor, capacity or allocation) refused the engine.
    Admission(MediaAdmitError),
    /// The engine refused to bind to the stream.
    StartRefused(&'static str),
    /// The generation list could not be given room for one more entry.
    GenerationList,
}

impl core::fmt::Display for OpenRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoStream => f.write_str("a stream was opened on a member that has none"),
            Self::CutoverNotAfter {
                cutover_block,
                latest_first_block,
            } => write!(
                f,
                "a stream cannot start at block {cutover_block}, the latest one starts at {latest_first_block}"
            ),
            Self::DuplicateStream(id) => write!(f, "stream {id:#x} was already opened"),
            Self::Admission(MediaAdmitError::Engine(AdmitError::Config(config))) => {
                write!(f, "playout configuration refused: {}", config.code())
            }
            Self::Admission(other) => write!(f, "playout admission refused: {}", other.code()),
            Self::StartRefused(code) => write!(f, "playout stream refused: {code}"),
            Self::GenerationList => f.write_str("playout admission refused: allocation"),
        }
    }
}

/// A stream generation that is built and admitted but not live: its engine, bound to the stream, and the room for it in the
/// generation list. Dropping it releases both and changes nothing; [`NodePlayout::commit_stream`] makes it live and cannot fail.
pub(crate) struct PreparedStream {
    engine: PlayoutEngine,
    cutover_block: u64,
    /// Captured from the trusted clock at preparation, never refreshed when the candidate is committed.
    group_epoch: u64,
}

/// Bytes of the copy of a receiver that a draining generation keeps (the `StreamReceiver` struct: its key, ids, replay window,
/// counters and profile are all inline). A source commit charges one, beside the engines, for the generation it replaces.
///
/// This is a logical count of retained receiver VALUES in the host simulation, not a measurement of process memory: the
/// `Option<StreamReceiver>` slot is inline in every generation entry (Some or None) and the generation list is simulation bookkeeping
/// ([`NodePlayout::resident_bytes`]), so dropping a copy releases its ledger charge but shrinks no allocation. Each arriving datagram's
/// trial copy ([`NodePlayout::deliver_until`]) is one temporary stack value of the same size, bounded to one at a time and not charged.
pub(crate) fn retained_receiver_bytes() -> u64 {
    u64::try_from(core::mem::size_of::<StreamReceiver>()).unwrap_or(u64::MAX)
}

/// A fresh N04 engine bound to `stream_epoch`, with `anchor_block` presented at `anchor_group_ns` on the group clock, admitted
/// through the shared [`admit_engine`] beside `resident_elsewhere_bytes`.
fn new_engine(
    stream_epoch: u64,
    anchor_block: u64,
    anchor_group_ns: u64,
    ledger: &MemoryBudgetLedger,
    resident_elsewhere_bytes: u64,
) -> Result<PlayoutEngine, OpenRefusal> {
    let cfg = PlayoutConfig {
        work_ns: RENDER_WORK_NS,
        lead_ns: RENDER_LEAD_NS,
        tolerance_ns: TIMELINE_TOLERANCE_NS,
    };
    let mut engine = admit_engine(PlayoutProfile::MUSIC, cfg, ledger, resident_elsewhere_bytes)
        .map_err(OpenRefusal::Admission)?;
    engine
        .begin_stream(
            stream_epoch,
            anchor_block * (FRAMES_PER_BLOCK as u64),
            anchor_group_ns,
        )
        .map_err(|e| OpenRefusal::StartRefused(e.code()))?;
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
            replay_refused_at_receiver: 0,
            refused_at_receiver: 0,
            outside_generation_refused: 0,
            accepted_by_draining_generation: 0,
            group_epoch_fenced_generations: 0,
            group_epoch_fenced_refused: 0,
            replaced_refusals: BTreeMap::new(),
        }
    }

    /// A member whose stream `stream_id` is bound to `stream_epoch`, block 0 presented at `anchor_group_ns` on the group
    /// clock.
    pub(crate) fn bind(
        stream_id: u64,
        stream_epoch: u64,
        anchor_group_ns: u64,
        ledger: &MemoryBudgetLedger,
        group_epoch: u64,
    ) -> Result<Self, String> {
        let engine =
            new_engine(stream_epoch, 0, anchor_group_ns, ledger, 0).map_err(|e| e.to_string())?;
        Ok(Self {
            engines: vec![StreamEngine {
                stream_id,
                engine,
                first_block: 0,
                until_block: None,
                ingress: None,
                admitted_group_epoch: group_epoch,
                fenced: false,
            }],
            origin_group_ns: anchor_group_ns,
            ..Self::unbound()
        })
    }

    /// Bytes every engine this member still holds occupies (struct, slots as the allocator kept them, diagnostics heap): what a new
    /// generation must be admitted beside. The generation list itself is simulation bookkeeping, not board memory, and is not counted.
    pub(crate) fn resident_bytes(&self) -> u64 {
        self.engines
            .iter()
            .map(|e| {
                engine_resident_bytes(&e.engine).saturating_add(if e.ingress.is_some() {
                    retained_receiver_bytes()
                } else {
                    0
                })
            })
            .fold(0, u64::saturating_add)
    }

    /// How many stream generations are held.
    #[cfg(test)]
    pub(crate) fn stream_count(&self) -> usize {
        self.engines.len()
    }

    /// The first block this member's sender has not sent yet: where a source change admitted now cuts over.
    pub(crate) fn first_unsent(&self) -> u64 {
        self.next_send
    }

    /// A source change was admitted: open stream `stream_id` at `cutover_block`. Its own engine is bound now, so it takes the
    /// new stream's packets as they arrive; the previous stream's engine keeps deciding the blocks below the cutover (drain
    /// to a common future cutover) and is retired once it has. The new stream continues the group's timeline. This is
    /// [`Self::prepare_stream`] followed by [`Self::commit_stream`]: a refusal changes nothing. Unit tests only: the harness prepares and
    /// commits separately, because the commit also hands the generation a copy of the node's receiver.
    #[cfg(test)]
    pub(crate) fn open_stream(
        &mut self,
        stream_id: u64,
        stream_epoch: u64,
        cutover_block: u64,
        ledger: &MemoryBudgetLedger,
    ) -> Result<(), String> {
        let group_epoch = self
            .engines
            .last()
            .map_or(0, |stream| stream.admitted_group_epoch);
        let prepared = self
            .prepare_stream(stream_id, stream_epoch, cutover_block, ledger, group_epoch)
            .map_err(|e| e.to_string())?;
        self.commit_stream(stream_id, prepared, None);
        Ok(())
    }

    /// Build and admit the next generation without touching anything live: the checks, the shared admission beside every engine
    /// still held (a replaced stream drains to the cutover, so they overlap), the engine itself, and the room for one more entry
    /// in the generation list. Nothing here formats text; every refusal is a typed [`OpenRefusal`].
    pub(crate) fn prepare_stream(
        &mut self,
        stream_id: u64,
        stream_epoch: u64,
        cutover_block: u64,
        ledger: &MemoryBudgetLedger,
        group_epoch: u64,
    ) -> Result<PreparedStream, OpenRefusal> {
        let Some(latest) = self.engines.last() else {
            return Err(OpenRefusal::NoStream);
        };
        if cutover_block <= latest.first_block {
            return Err(OpenRefusal::CutoverNotAfter {
                cutover_block,
                latest_first_block: latest.first_block,
            });
        }
        if self.engines.iter().any(|e| e.stream_id == stream_id) {
            return Err(OpenRefusal::DuplicateStream(stream_id));
        }
        let anchor_group_ns =
            self.origin_group_ns + frames_to_ns(cutover_block * (FRAMES_PER_BLOCK as u64));
        // The commit will keep a copy of the receiver for the generation it replaces: charge it with the candidate's overlap.
        let resident = self
            .resident_bytes()
            .saturating_add(retained_receiver_bytes());
        let engine = new_engine(
            stream_epoch,
            cutover_block,
            anchor_group_ns,
            ledger,
            resident,
        )?;
        self.engines
            .try_reserve(1)
            .map_err(|_| OpenRefusal::GenerationList)?;
        Ok(PreparedStream {
            engine,
            cutover_block,
            group_epoch,
        })
    }

    /// Make a prepared generation live. It cannot fail: the engine exists and the list already has room for it. `retained` is the
    /// copy of the node's receiver, taken BEFORE it is rebound to the new stream, that the generation being replaced keeps to
    /// authenticate its in-flight tail when it arrives (`None` for a caller that stages only packets it has authenticated itself).
    /// The candidate carries the trusted `GroupClock::epoch` captured at preparation. The replaced generation retains its original
    /// admission epoch; committing a new source must never relabel old queued data as authorized by a later group epoch.
    pub(crate) fn commit_stream(
        &mut self,
        stream_id: u64,
        prepared: PreparedStream,
        retained: Option<StreamReceiver>,
    ) {
        if let Some(latest) = self.engines.last_mut() {
            latest.until_block = Some(prepared.cutover_block);
            latest.ingress = if latest.fenced || latest.admitted_group_epoch != prepared.group_epoch
            {
                None
            } else {
                retained
            };
        }
        self.engines.push(StreamEngine {
            stream_id,
            engine: prepared.engine,
            first_block: prepared.cutover_block,
            until_block: None,
            ingress: None,
            admitted_group_epoch: prepared.group_epoch,
            fenced: false,
        });
    }

    /// Test fixture: pretend this member's sender has sent blocks `0..block`.
    #[cfg(test)]
    pub(crate) fn set_first_unsent(&mut self, block: u64) {
        self.next_send = block;
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
        self.stage_entry(arrival_true_ns, copy, InFlight::Admitted(packet));
    }

    /// Stage a datagram as sent, to be routed by its own header and authenticated on arrival (the staging key's block is read from the
    /// same unauthenticated hint; a datagram whose header cannot be read is staged under block 0 and refused when it arrives). Unit tests
    /// only: the campaign stages through `send_block`.
    #[cfg(test)]
    pub(crate) fn stage_raw(&mut self, arrival_true_ns: u64, copy: u8, wire: Vec<u8>) {
        let start_frame = untrusted_route_hint(&wire).map_or(0, |hint| hint.start_frame);
        self.stage_entry(arrival_true_ns, copy, InFlight::Raw { start_frame, wire });
    }

    fn stage_entry(&mut self, arrival_true_ns: u64, copy: u8, entry: InFlight) {
        let block = entry.start_frame() / (FRAMES_PER_BLOCK as u64);
        self.in_flight.insert((arrival_true_ns, block, copy), entry);
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
        let start_frame = frame.start_frame;
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
        // The datagram is NOT authenticated here. It travels as sent, and the receiver of the generation its own header names
        // authenticates it when it arrives. The one exception is the planted `Late` packet, which models the engine's own lateness: it
        // is authenticated now by a scratch copy of the receiver, because the real receiver's replay window must not be pushed
        // ~93 blocks past the arrivals it has yet to see.
        let packet = if link.fault == Some(LinkFault::Late { block: blk }) {
            let mut scratch = link.receiver.clone();
            InFlight::Admitted(scratch.accept(&wire).map_err(|e| {
                format!(
                    "member {}: block {blk} refused by the receiver: {e}",
                    link.member_id
                )
            })?)
        } else {
            InFlight::Raw { start_frame, wire }
        };
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
            self.stage_entry(tl.origin_ns + duplicate_rel_ns, 1, sent.packet.clone());
        }
        self.stage_entry(tl.origin_ns + sent.deliver_rel_ns, 0, sent.packet);
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

    /// Hand each engine the staged datagrams of its own stream that arrive at or before `until_true_ns`, in arrival order, each
    /// with the view of the node's own clock at its arrival instant. A RAW datagram is first authenticated by the N01 receiver of
    /// the generation the header's routing hint names: the node's own receiver (`newest`) for the latest generation, the copy a draining
    /// generation kept for an earlier one. A generation whose tail is all decided keeps no receiver, and its datagrams are refused.
    /// A datagram N01 refuses is counted by why (replay window: `replay_refused_at_receiver`; anything else:
    /// `refused_at_receiver`); one that N01 admits but whose block is outside the generation's own interval is
    /// `outside_generation_refused`, and the receiver is left exactly as it was (the admission was a trial). Only a datagram that passes
    /// all of that reaches the engine.
    pub(crate) fn deliver_until(
        &mut self,
        clock: &GroupClock,
        sim: &SimNodeClock,
        until_true_ns: u64,
        mut newest: Option<&mut StreamReceiver>,
    ) -> Result<(), String> {
        if self.engines.is_empty() {
            return Ok(());
        }
        for stream in &mut self.engines {
            if stream.ingress.is_some() && stream.retired() {
                stream.ingress = None;
            }
        }
        self.fence_stale_generations(clock.epoch())?;
        while let Some((&(arrival, _, _), _)) = self.in_flight.first_key_value() {
            if arrival > until_true_ns {
                break;
            }
            let Some((_, entry)) = self.in_flight.pop_first() else {
                break;
            };
            let admitted = matches!(entry, InFlight::Admitted(_));
            let block = entry.start_frame() / (FRAMES_PER_BLOCK as u64);
            let stream = match &entry {
                InFlight::Admitted(packet) => packet.stream_id.get(),
                InFlight::Raw { wire, .. } => match untrusted_route_hint(wire) {
                    Ok(hint) => hint.stream_id,
                    Err(_) => {
                        // A header that cannot be read names no generation: refused before anything is selected.
                        self.refused_at_receiver += 1;
                        continue;
                    }
                },
            };
            if admitted {
                self.note_arrival(block);
            }
            let Some(at) = self.engines.iter().position(|e| e.stream_id == stream) else {
                if admitted {
                    return Err(format!(
                        "a packet of stream {stream:#x} reached a playout path that has no such stream"
                    ));
                }
                // A raw datagram naming a stream this member never opened is data to refuse, not an error of the simulation.
                self.refused_at_receiver += 1;
                continue;
            };
            if self.engines[at].retired() {
                // A raw datagram of a retired generation is not authenticated (its receiver is gone), so its header says nothing the
                // arrival ledger may record.
                self.retired_stream_refused += 1;
                continue;
            }
            if self.engines[at].fenced {
                // A trusted group-epoch change invalidated this generation: nothing routed to it is accepted, and nothing it
                // kept can reach its engine.
                self.group_epoch_fenced_refused += 1;
                continue;
            }
            let packet = match entry {
                InFlight::Admitted(packet) => packet,
                InFlight::Raw { wire, .. } => {
                    let is_newest = at + 1 == self.engines.len();
                    // The interval is read before the receiver is borrowed: the receiver may be this generation's own copy.
                    let (first, until) =
                        (self.engines[at].first_block, self.engines[at].until_block);
                    let receiver = if is_newest {
                        newest.as_deref_mut()
                    } else {
                        self.engines[at].ingress.as_mut()
                    };
                    let Some(receiver) = receiver else {
                        return Err(format!(
                            "a datagram of stream {stream:#x} arrived at a playout path with no receiver for it"
                        ));
                    };
                    // N01 records a sequence number the moment it admits a datagram. A datagram that authenticates but belongs to another
                    // generation's interval (the replaced adapter's post-cutover block, 64 or more sequence numbers ahead of the tail this
                    // generation still owes) must not have moved this receiver's replay window: the tail would then be a "replay".
                    // So the datagram is authenticated by a TRIAL copy (inline: key, window, counters; no heap), and the trial replaces
                    // the real receiver only when N01 refused the datagram (a refusal changes nothing but the counters, which the
                    // receiver must keep) or when this generation permits the authenticated block.
                    let mut trial = StreamReceiver::clone(receiver);
                    match trial.accept(&wire) {
                        Ok(packet) => {
                            // The block is read from the AUTHENTICATED packet, not from the staging key.
                            let block = packet.start_frame / (FRAMES_PER_BLOCK as u64);
                            if block < first || until.is_some_and(|until| block >= until) {
                                // The trial is dropped: the receiver is exactly as it was, and its own counters do not see this datagram.
                                self.outside_generation_refused += 1;
                                continue;
                            }
                            *receiver = trial;
                            if !is_newest {
                                self.accepted_by_draining_generation += 1;
                            }
                            self.note_arrival(block);
                            packet
                        }
                        Err(StreamError::ReplayOrDuplicatePacket { .. }) => {
                            *receiver = trial;
                            self.replay_refused_at_receiver += 1;
                            continue;
                        }
                        Err(_) => {
                            *receiver = trial;
                            self.refused_at_receiver += 1;
                            continue;
                        }
                    }
                }
            };
            let view = self.mono.at_local(clock, sim.local(arrival));
            let media = MediaPacket::from_authenticated(&packet)
                .ok_or_else(|| "a repair packet reached the playout path".to_string())?;
            let _ = self.engines[at].engine.on_packet(view, &media);
        }
        Ok(())
    }

    /// Every generation and its queued blocks belong to the trusted group epoch under which that generation was admitted.
    /// If `GroupClock::epoch` has moved since, the generation is fenced: its copy is dropped, its engine is re-bound to the
    /// stream epoch it already had, at its own cursor (the engine's way to clear its queue: the blocks it still owes are decided with no
    /// history, never played), and what is routed to it afterwards is refused by name. This includes the latest generation, even before
    /// it has a retained receiver copy. A source change inside the same epoch fences nothing. The epoch comes from the clock the engines
    /// are driven by, never from a datagram.
    fn fence_stale_generations(&mut self, group_epoch: u64) -> Result<(), String> {
        for (index, stream) in self.engines.iter_mut().enumerate() {
            if stream.fenced || stream.retired() || stream.admitted_group_epoch == group_epoch {
                continue;
            }
            stream.ingress = None;
            stream.fenced = true;
            let snap = stream.engine.snapshot();
            if let Some(epoch) = snap.epoch {
                let frame = snap.cursor * (FRAMES_PER_BLOCK as u64);
                stream
                    .engine
                    .begin_stream(epoch, frame, self.origin_group_ns + frames_to_ns(frame))
                    .map_err(|e| {
                        format!(
                            "stream {index}: the engine refused the re-bind that clears its queue: {}",
                            e.code()
                        )
                    })?;
            }
            self.group_epoch_fenced_generations += 1;
        }
        Ok(())
    }

    /// One block handed to an engine's decision path: count it as out of order if a higher block was handed before.
    fn note_arrival(&mut self, block: u64) {
        if self
            .highest_delivered
            .is_some_and(|highest| block < highest)
        {
            self.out_of_order += 1;
        }
        self.highest_delivered = self.highest_delivered.max(Some(block));
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
        newest: Option<&mut StreamReceiver>,
    ) -> Result<Played, String> {
        self.decide_with_bytes(blk, tl, clock, sim, newest)
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
        newest: Option<&mut StreamReceiver>,
    ) -> Result<(Played, Vec<u8>), String> {
        let at = tl.decision_true_ns(blk);
        self.deliver_until(clock, sim, at, newest)?;
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
            replay_refused_at_receiver: self.replay_refused_at_receiver,
            refused_at_receiver: self.refused_at_receiver,
            outside_generation_refused: self.outside_generation_refused,
            accepted_by_draining_generation: self.accepted_by_draining_generation,
            group_epoch_fenced_generations: self.group_epoch_fenced_generations,
            group_epoch_fenced_refused: self.group_epoch_fenced_refused,
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

    /// The harness's explicit synthetic budget: the platform ledger of a nominal board with the standard 2 MiB stream line.
    fn synthetic_ledger() -> MemoryBudgetLedger {
        crate::media_playout::synthetic_ledger(2 * 1024 * 1024)
    }
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
        locked_clock_at(sim, 1)
    }

    /// [`locked_clock`] in group epoch `epoch`: a clock that joined that epoch and locked after the same four exchanges.
    fn locked_clock_at(sim: &SimNodeClock, epoch: u64) -> GroupClock {
        let cfg = GroupClockConfig::standard().expect("standard config");
        let mut clock = GroupClock::new(cfg, epoch, COORDINATOR, 100).expect("member");
        for k in 1..=4_u64 {
            let t1 = k * 10_000_000;
            let req = clock.next_probe(sim.local(t1));
            let (t2, t3) = (t1 + 400_000, t1 + 450_000);
            let resp = ProbeResponse {
                epoch,
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
                play: NodePlayout::bind(
                    STREAM,
                    engine_epoch,
                    tl.pts_group_ns(0),
                    &synthetic_ledger(),
                    1, // This fixture's trusted clock epoch; the wire/engine epochs vary independently.
                )
                .expect("binds"),
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
                .decide_with_bytes(blk, &self.tl, &self.clock, &self.sim, None)
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

    /// The packet a staged entry carries, opened: a pre-authenticated entry as it is, a raw datagram parsed by a throwaway receiver
    /// of the stream its header names, with the test key (so a test can read its payload without touching any real receiver).
    fn opened(entry: &InFlight) -> AuthenticatedStreamPacket {
        match entry {
            InFlight::Admitted(packet) => packet.clone(),
            InFlight::Raw { wire, .. } => {
                let stream = untrusted_route_hint(wire)
                    .expect("a readable header")
                    .stream_id;
                (0..4)
                    .find_map(|epoch| {
                        StreamReceiver::new(
                            StreamKey::from_bytes([0x42; 32]),
                            StreamId::new(stream).expect("stream id"),
                            epoch,
                        )
                        .accept(wire)
                        .ok()
                    })
                    .expect("a raw datagram of the test key")
            }
        }
    }

    /// The cutover of the raw-arrival tests: the old stream carries blocks below it, the next one from it.
    const CUT: u64 = 30;

    fn decide_raw(s: &mut Scenario, blk: u64) -> (Played, Vec<u8>) {
        s.play
            .decide_with_bytes(blk, &s.tl, &s.clock, &s.sim, Some(&mut s.wire.receiver))
            .expect("decides")
    }

    /// The old stream's blocks `0..CUT`, all but the last already delivered to the node's receiver; then the next stream is
    /// committed at `CUT` exactly as the harness's commit does it (the generation being replaced keeps a copy of the receiver as it
    /// was, the node's receiver is rebound to the new stream) and its blocks `CUT..CUT + 10` are in flight. Returns the fixture
    /// and the old stream's last block as a wire datagram, held back: still in flight at the commit.
    fn crossing() -> (Scenario, Vec<u8>) {
        let mut s = Scenario::new();
        let held = s.play.resident_bytes();
        let mut tail = Vec::new();
        for blk in 0..CUT {
            let payload = source_bytes(blk);
            s.play.note_sent(blk, &payload);
            let wire = s
                .wire
                .sender
                .send(Wire::frame(&s.tl, blk, payload))
                .expect("encodes");
            if blk == CUT - 1 {
                tail = wire;
            } else {
                s.play
                    .stage_raw(s.tl.send_true_ns(blk) + 10_000_000, 0, wire);
            }
        }
        s.play
            .deliver_until(
                &s.clock,
                &s.sim,
                s.tl.send_true_ns(CUT - 1) + 10_000_000,
                Some(&mut s.wire.receiver),
            )
            .expect("the early old blocks arrive before the commit");
        let room = crate::media_playout::synthetic_ledger(2 * held + retained_receiver_bytes());
        let prepared = s
            .play
            .prepare_stream(STREAM_B, 1, CUT, &room, s.clock.epoch())
            .unwrap_or_else(|e| panic!("room beside the playing stream: {e}"));
        s.play
            .commit_stream(STREAM_B, prepared, Some(s.wire.receiver.clone()));
        s.wire
            .receiver
            .bind_stream(StreamId::new(STREAM_B).expect("stream id"), 1);
        let mut new = Wire::on_stream(STREAM_B);
        for blk in CUT..CUT + 10 {
            let payload = other_bytes(blk);
            s.play.note_sent(blk, &payload);
            let wire = new
                .sender
                .send(Wire::frame(&s.tl, blk, payload))
                .expect("encodes");
            s.play
                .stage_raw(s.tl.send_true_ns(blk) + 10_000_000, 0, wire);
        }
        (s, tail)
    }

    #[test]
    fn an_old_stream_datagram_still_in_flight_at_the_commit_is_authenticated_on_arrival_by_the_old_generation_and_played()
     {
        let (mut s, tail) = crossing();
        // The delayed tail arrives AFTER the commit, when the node's receiver already speaks the new stream, and before its cutoff.
        s.play
            .stage_raw(s.tl.decision_true_ns(CUT - 1) - 5_000_000, 0, tail);
        for blk in 0..CUT {
            let played = decide_raw(&mut s, blk);
            assert_eq!(authentic(played, blk), source_bytes(blk), "old block {blk}");
        }
        for blk in CUT..CUT + 10 {
            let played = decide_raw(&mut s, blk);
            assert_eq!(authentic(played, blk), other_bytes(blk), "new block {blk}");
        }
        let r = s.play.report();
        assert_eq!(
            r.accepted_by_draining_generation, 1,
            "only the tail crossed the commit"
        );
        assert_eq!(
            (
                r.wrong_stream_refused_at_receiver,
                r.replay_refused_at_receiver,
                r.refused_at_receiver,
                r.outside_generation_refused,
                r.retired_stream_refused
            ),
            (0, 0, 0, 0, 0)
        );
        assert_eq!(r.decided_real, CUT + 10);
        // The node's own receiver spoke the old stream for the first 29 blocks and the new one for ten, and refused nothing.
        let c = s.wire.receiver.counters();
        assert_eq!((c.accepted, c.rejected_wrong_stream), (CUT - 1 + 10, 0));
    }

    #[test]
    fn the_rebound_receiver_alone_would_refuse_the_old_tail_so_the_positive_control_needs_the_old_generations_receiver()
     {
        // The knockout: a single receiver rebound at the commit is N01's one-stream refusal for the old tail (what a composition that
        // routes only to the rebound receiver would do to it).
        let (mut s, tail) = crossing();
        let mut lone = s.wire.receiver.clone();
        assert!(matches!(
            lone.accept(&tail),
            Err(StreamError::WrongStream { .. })
        ));
        // The composed path still plays it, from the very same bytes.
        s.play
            .stage_raw(s.tl.decision_true_ns(CUT - 1) - 5_000_000, 0, tail);
        for blk in 0..CUT {
            let played = decide_raw(&mut s, blk);
            assert_eq!(authentic(played, blk), source_bytes(blk), "old block {blk}");
        }
        assert_eq!(s.play.report().accepted_by_draining_generation, 1);
    }

    /// The replaced adapter's sender goes on past the cutover: it is the old stream's, keyed with the member's media key, so what it
    /// sends AUTHENTICATES. Its sequence number equals its block here (block `b` was the `b`-th send). Returns the datagram of block `through`.
    fn old_sender_runs_ahead(s: &mut Scenario, through: u64) -> Vec<u8> {
        let mut last = Vec::new();
        for blk in CUT..=through {
            last = s
                .wire
                .sender
                .send(Wire::frame(&s.tl, blk, other_bytes(blk)))
                .expect("encodes");
        }
        last
    }

    #[test]
    fn an_authentic_old_stream_datagram_past_the_cutover_that_arrives_first_cannot_poison_the_replay_window_of_the_tail_still_owed()
     {
        let (mut s, tail) = crossing();
        let high = old_sender_runs_ahead(&mut s, 100);
        // The mechanism, on N01 itself (the control that makes the case decisive): a receiver that RECORDS the post-cutover datagram
        // refuses the tail it still owes, because seq 29 is 71 behind seq 100 and the window is 64 packets.
        let mut lone = s.play.engines[0]
            .ingress
            .clone()
            .expect("the replaced generation holds its receiver while its tail is owed");
        assert_eq!(lone.accept(&high).expect("it authenticates").seq, 100);
        assert!(matches!(
            lone.accept(&tail),
            Err(StreamError::ReplayOrDuplicatePacket { .. })
        ));
        // The composed path, the same two datagrams in the same order: the post-cutover one first.
        let at_tail = s.tl.decision_true_ns(CUT - 1) - 5_000_000;
        s.play.stage_raw(at_tail - 1_000_000, 0, high);
        s.play.stage_raw(at_tail, 0, tail);
        s.play
            .deliver_until(&s.clock, &s.sim, at_tail, Some(&mut s.wire.receiver))
            .expect("delivers");
        // The copy was taken after 29 accepted datagrams and the tail is its 30th: the post-cutover datagram authenticated on a trial
        // and left no trace in the receiver, window or counters.
        let kept = s.play.engines[0]
            .ingress
            .as_ref()
            .expect("the tail is decided later, so the copy is still held")
            .counters()
            .clone();
        assert_eq!(
            kept,
            franken_stream::ReceiverCounters {
                datagrams_seen: CUT,
                accepted: CUT,
                mac_verifications: CUT,
                ..franken_stream::ReceiverCounters::default()
            }
        );
        for blk in 0..CUT + 10 {
            let want = if blk < CUT {
                source_bytes(blk)
            } else {
                other_bytes(blk)
            };
            let played = decide_raw(&mut s, blk);
            assert_eq!(authentic(played, blk), want, "block {blk}");
        }
        let r = s.play.report();
        assert_eq!(
            (
                r.outside_generation_refused,
                r.accepted_by_draining_generation,
                r.replay_refused_at_receiver,
                r.refused_at_receiver,
                r.wrong_stream_refused_at_receiver,
                r.retired_stream_refused
            ),
            (1, 1, 0, 0, 0, 0)
        );
        assert_eq!(r.decided_real, CUT + 10);
    }

    #[test]
    fn a_tampered_high_sequence_datagram_fails_its_mac_is_counted_by_n01_and_leaves_the_tail_playable()
     {
        let (mut s, tail) = crossing();
        let mut high = old_sender_runs_ahead(&mut s, 100);
        let last = high.len() - 1;
        high[last] ^= 0x01;
        let at_tail = s.tl.decision_true_ns(CUT - 1) - 5_000_000;
        s.play.stage_raw(at_tail - 1_000_000, 0, high);
        s.play.stage_raw(at_tail, 0, tail);
        s.play
            .deliver_until(&s.clock, &s.sim, at_tail, Some(&mut s.wire.receiver))
            .expect("delivers");
        // A real failure is the receiver's own: counted once, as an authentication failure, with the window untouched.
        let kept = s.play.engines[0]
            .ingress
            .as_ref()
            .expect("the copy is still held")
            .counters()
            .clone();
        assert_eq!(
            kept,
            franken_stream::ReceiverCounters {
                datagrams_seen: CUT + 1,
                accepted: CUT,
                mac_verifications: CUT + 1,
                rejected_authentication: 1,
                ..franken_stream::ReceiverCounters::default()
            }
        );
        for blk in 0..CUT {
            let played = decide_raw(&mut s, blk);
            assert_eq!(authentic(played, blk), source_bytes(blk), "old block {blk}");
        }
        let r = s.play.report();
        assert_eq!(
            (
                r.refused_at_receiver,
                r.outside_generation_refused,
                r.replay_refused_at_receiver,
                r.accepted_by_draining_generation
            ),
            (1, 0, 0, 1)
        );
    }

    #[test]
    fn an_authentic_next_stream_datagram_below_its_first_block_that_arrives_first_cannot_poison_the_node_receivers_replay_window()
     {
        let (mut s, tail) = crossing();
        // The next stream's sender again, from its start: its first ten frames are the blocks `crossing` already has in flight (the same
        // bytes), then it runs ahead to seq 99 with a frame for a block BELOW the stream's first block.
        let mut next = Wire::on_stream(STREAM_B);
        let own_first = next
            .sender
            .send(Wire::frame(&s.tl, CUT, other_bytes(CUT)))
            .expect("encodes");
        for blk in CUT + 1..CUT + 10 {
            next.sender
                .send(Wire::frame(&s.tl, blk, other_bytes(blk)))
                .expect("encodes");
        }
        let mut below = Vec::new();
        for _ in 10..100 {
            below = next
                .sender
                .send(Wire::frame(&s.tl, 5, other_bytes(5)))
                .expect("encodes");
        }
        // The mechanism on N01 itself: recording it makes the stream's own first frame (seq 0) a replay.
        let mut lone = s.wire.receiver.clone();
        assert_eq!(lone.accept(&below).expect("it authenticates").seq, 99);
        assert!(matches!(
            lone.accept(&own_first),
            Err(StreamError::ReplayOrDuplicatePacket { .. })
        ));
        // The composed path: it arrives before any block of the stream, is refused by interval, and every block still plays.
        s.play
            .stage_raw(s.tl.send_true_ns(CUT) + 5_000_000, 0, below);
        s.play
            .stage_raw(s.tl.decision_true_ns(CUT - 1) - 5_000_000, 0, tail);
        for blk in 0..CUT + 10 {
            let want = if blk < CUT {
                source_bytes(blk)
            } else {
                other_bytes(blk)
            };
            let played = decide_raw(&mut s, blk);
            assert_eq!(authentic(played, blk), want, "block {blk}");
        }
        let r = s.play.report();
        assert_eq!(
            (
                r.outside_generation_refused,
                r.replay_refused_at_receiver,
                r.refused_at_receiver,
                r.decided_real
            ),
            (1, 0, 0, CUT + 10)
        );
        // The node's receiver saw 29 old and 10 new datagrams (the tail went to the old generation's copy) and nothing else.
        let c = s.wire.receiver.counters();
        assert_eq!(
            (
                c.datagrams_seen,
                c.accepted,
                c.rejected_replay,
                c.rejected_wrong_stream
            ),
            (CUT - 1 + 10, CUT - 1 + 10, 0, 0)
        );
    }

    #[test]
    fn a_trusted_group_epoch_change_fences_all_queued_generations_and_the_delayed_tail() {
        // Same-epoch source changes still drain their exact bytes in the preceding controls. Here BOTH generations were admitted in
        // epoch 1; being the latest source does not authorize the second generation under a relocked epoch-2 clock.
        let (mut s, tail) = crossing();
        s.play
            .deliver_until(
                &s.clock,
                &s.sim,
                s.tl.send_true_ns(CUT + 9) + 10_000_000,
                Some(&mut s.wire.receiver),
            )
            .expect("queue both generations before the authority changes");
        assert_eq!(
            s.play.engines[0].engine.snapshot().queued,
            u32::try_from(CUT - 1).expect("small")
        );
        assert_eq!(
            s.play.engines[1].engine.snapshot().queued,
            10,
            "newest generation already holds real old-epoch audio"
        );
        assert!(s.play.engines[0].ingress.is_some());
        s.clock = locked_clock_at(&s.sim, 2);
        s.play
            .stage_raw(s.tl.decision_true_ns(CUT - 1) - 5_000_000, 0, tail);
        s.play
            .deliver_until(
                &s.clock,
                &s.sim,
                s.tl.decision_true_ns(0),
                Some(&mut s.wire.receiver),
            )
            .expect("fence old admission epochs");
        assert!(s.play.engines.iter().all(|generation| generation.fenced
            && generation.ingress.is_none()
            && generation.engine.snapshot().queued == 0));
        for blk in 0..CUT + 10 {
            let (played, bytes) = decide_raw(&mut s, blk);
            assert!(
                matches!(played, Played::Silent(_)) && bytes.is_empty(),
                "old-epoch block {blk} sounded"
            );
        }
        let r = s.play.report();
        assert_eq!(
            (
                r.group_epoch_fenced_generations,
                r.group_epoch_fenced_refused,
                r.accepted_by_draining_generation,
                r.decided_real,
                r.decided_muted_nohistory
            ),
            (2, 1, 0, 0, CUT + 10)
        );
        assert_eq!(
            (
                r.replay_refused_at_receiver,
                r.refused_at_receiver,
                r.outside_generation_refused,
                r.retired_stream_refused
            ),
            (0, 0, 0, 0)
        );
    }

    #[test]
    fn a_group_epoch_change_leaves_retired_history_alone_and_fences_the_still_live_generation() {
        let (mut s, tail) = crossing();
        s.play
            .stage_raw(s.tl.decision_true_ns(CUT - 1) - 5_000_000, 0, tail);
        for blk in 0..CUT {
            let played = decide_raw(&mut s, blk);
            assert_eq!(
                authentic(played, blk),
                source_bytes(blk),
                "same-epoch old block {blk}"
            );
        }
        s.clock = locked_clock_at(&s.sim, 2);
        for blk in CUT..CUT + 10 {
            let (played, bytes) = decide_raw(&mut s, blk);
            assert!(
                matches!(played, Played::Silent(_)) && bytes.is_empty(),
                "newest old-epoch block {blk} sounded"
            );
        }
        let r = s.play.report();
        assert_eq!(
            (
                r.group_epoch_fenced_generations,
                r.group_epoch_fenced_refused,
                r.accepted_by_draining_generation,
                r.decided_real,
                r.decided_muted_nohistory
            ),
            (1, 0, 1, CUT, 10)
        );
        assert!(
            !s.play.engines[0].fenced,
            "already-retired history is not a new fence event"
        );
        assert!(s.play.engines[1].fenced);
    }

    #[test]
    fn a_single_initial_generation_is_fenced_without_new_arrivals_and_a_prepared_candidate_cannot_change_its_epoch_at_commit()
     {
        let mut s = Scenario::new();
        for blk in 0..4 {
            s.arrives(blk, 10_000_000);
        }
        s.play
            .deliver_until(&s.clock, &s.sim, s.tl.send_true_ns(3) + 10_000_000, None)
            .expect("queue authenticated test traffic before epoch change");
        assert_eq!(s.play.engines[0].engine.snapshot().queued, 4);
        assert!(s.play.engines[0].ingress.is_none());
        let prepared = s
            .play
            .prepare_stream(STREAM_B, 1, 10, &synthetic_ledger(), s.clock.epoch())
            .unwrap_or_else(|error| panic!("candidate fits: {error}"));
        s.clock = locked_clock_at(&s.sim, 2);
        // No datagram arrives after the change; deciding itself must fence the initial queue.
        let (played, bytes) = s.decide(0);
        assert!(matches!(played, Played::Silent(_)) && bytes.is_empty());
        assert!(s.play.engines[0].fenced);
        assert_eq!(s.play.engines[0].engine.snapshot().queued, 0);
        s.play
            .commit_stream(STREAM_B, prepared, Some(s.wire.receiver.clone()));
        assert!(
            s.play.engines[0].ingress.is_none(),
            "a commit cannot resurrect a fenced receiver"
        );
        assert_eq!(
            s.play.engines[1].admitted_group_epoch, 1,
            "candidate keeps the epoch captured at preparation"
        );
        s.play
            .deliver_until(&s.clock, &s.sim, s.tl.decision_true_ns(1), None)
            .expect("stale candidate fences before any delivery");
        assert!(s.play.engines[1].fenced);
        assert_eq!(s.play.report().group_epoch_fenced_generations, 2);
    }

    #[test]
    fn a_fresh_group_epoch_can_resume_with_a_new_stream_without_relabeling_any_old_queued_generation()
     {
        const STREAM_C: u64 = 0x5EED_5EED_0000_0003;
        const RESTART: u64 = CUT + 10;
        let (mut s, tail) = crossing();
        s.play
            .deliver_until(
                &s.clock,
                &s.sim,
                s.tl.send_true_ns(RESTART - 1) + 10_000_000,
                Some(&mut s.wire.receiver),
            )
            .expect("queue old admission before epoch changes");
        assert_eq!(s.play.engines[1].engine.snapshot().queued, 10);
        s.clock = locked_clock_at(&s.sim, 2);
        // Commit before deliver_until observes the new epoch: retaining B here must not relabel its old queue as epoch 2.
        let room = synthetic_ledger();
        let prepared = s
            .play
            .prepare_stream(STREAM_C, 2, RESTART, &room, s.clock.epoch())
            .unwrap_or_else(|error| panic!("fresh authorized stream must fit: {error}"));
        s.play
            .commit_stream(STREAM_C, prepared, Some(s.wire.receiver.clone()));
        assert_eq!(s.play.engines[1].admitted_group_epoch, 1);
        assert!(
            s.play.engines[1].ingress.is_none(),
            "never retain old authority under a new grant"
        );
        assert_eq!(s.play.engines[2].admitted_group_epoch, 2);
        let id = StreamId::new(STREAM_C).expect("fresh id");
        s.wire.receiver.bind_stream(id, 2);
        let mut sender = StreamSender::new(StreamKey::from_bytes([0x42; 32]), id, 2);
        for blk in RESTART..RESTART + 5 {
            let payload = other_bytes(blk);
            s.play.note_sent(blk, &payload);
            let wire = sender
                .send(Wire::frame(&s.tl, blk, payload))
                .expect("encodes new-epoch bytes");
            s.play
                .stage_raw(s.tl.send_true_ns(blk) + 10_000_000, 0, wire);
        }
        s.play
            .stage_raw(s.tl.decision_true_ns(CUT - 1) - 5_000_000, 0, tail);
        for blk in 0..RESTART {
            let (played, bytes) = decide_raw(&mut s, blk);
            assert!(
                matches!(played, Played::Silent(_)) && bytes.is_empty(),
                "old-epoch block {blk} sounded after fresh grant"
            );
        }
        for blk in RESTART..RESTART + 5 {
            let played = decide_raw(&mut s, blk);
            assert_eq!(
                authentic(played, blk),
                other_bytes(blk),
                "fresh-epoch block {blk}"
            );
        }
        let r = s.play.report();
        assert_eq!(
            (
                r.group_epoch_fenced_generations,
                r.group_epoch_fenced_refused,
                r.decided_real,
                r.decided_muted_nohistory
            ),
            (2, 1, 5, RESTART)
        );
        assert_eq!(s.wire.receiver.active_epoch(), 2);
        assert!(!s.play.engines[2].fenced);
    }

    #[test]
    fn a_duplicate_a_post_cutover_old_datagram_and_damaged_ones_are_refused_by_the_layer_that_owns_the_check()
     {
        let (mut s, tail) = crossing();
        let early = s.tl.decision_true_ns(CUT - 1) - 5_000_000;
        // The tail twice: the second copy reaches N01's replay window of the old generation's receiver, not the engine.
        s.play.stage_raw(early, 0, tail.clone());
        s.play.stage_raw(early + 1_000_000, 1, tail);
        // The replaced adapter keeps publishing: a validly keyed old-stream datagram for a block at the cutover. The old generation's
        // receiver authenticates it, and its own interval refuses it; the next stream's block at that position plays.
        let stale = s
            .wire
            .sender
            .send(Wire::frame(&s.tl, CUT + 1, other_bytes(CUT + 7)))
            .expect("encodes");
        s.play.stage_raw(early, 0, stale);
        // A damaged old datagram (its MAC fails) for a block that is otherwise lost, a datagram whose header cannot be read, and a
        // datagram that names a stream this member never opened.
        let mut damaged = s
            .wire
            .sender
            .send(Wire::frame(&s.tl, CUT - 2, source_bytes(CUT - 2)))
            .expect("encodes");
        let last = damaged.len() - 1;
        damaged[last] ^= 0x01;
        s.play.stage_raw(early, 0, damaged);
        s.play.stage_raw(early + 2_000_000, 0, vec![0; 64]);
        let mut stranger = Wire::on_stream(0x77);
        let unopened = stranger
            .sender
            .send(Wire::frame(&s.tl, CUT - 3, source_bytes(CUT - 3)))
            .expect("encodes");
        s.play.stage_raw(early + 3_000_000, 0, unopened);
        for blk in 0..CUT + 10 {
            let (played, bytes) = decide_raw(&mut s, blk);
            let want = if blk < CUT {
                source_bytes(blk)
            } else {
                other_bytes(blk)
            };
            assert_eq!(authentic((played, bytes), blk), want, "block {blk}");
        }
        let r = s.play.report();
        assert_eq!(
            r.replay_refused_at_receiver, 1,
            "N01's replay window, not an engine duplicate"
        );
        assert_eq!(r.duplicate, 0);
        assert_eq!(r.outside_generation_refused, 1);
        assert_eq!(
            r.refused_at_receiver, 3,
            "a failed MAC, an unreadable header and an unopened stream"
        );
        assert_eq!(r.accepted_by_draining_generation, 1);
        assert_eq!(r.decided_real, CUT + 10);
    }

    #[test]
    fn a_datagram_for_a_retired_generation_is_refused_and_a_generation_keeps_its_receiver_only_while_it_owes_a_tail()
     {
        let (mut s, tail) = crossing();
        s.play
            .stage_raw(s.tl.decision_true_ns(CUT - 1) - 5_000_000, 0, tail);
        assert!(
            s.play.engines[0].ingress.is_some(),
            "the replaced generation holds a copy while its tail is owed"
        );
        for blk in 0..CUT {
            let _ = decide_raw(&mut s, blk);
        }
        // Block CUT-1 is decided, so the old generation is retired: a late datagram of it is refused by name, and its copy is dropped.
        let late = s
            .wire
            .sender
            .send(Wire::frame(&s.tl, CUT - 1, source_bytes(CUT - 1)))
            .expect("encodes");
        s.play
            .stage_raw(s.tl.decision_true_ns(CUT) - 1_000_000, 0, late);
        let _ = decide_raw(&mut s, CUT);
        assert_eq!(s.play.report().retired_stream_refused, 1);
        assert!(
            s.play.engines[0].ingress.is_none(),
            "a retired generation keeps nothing"
        );
        assert_eq!(
            s.play.resident_bytes(),
            s.play
                .engines
                .iter()
                .map(|e| engine_resident_bytes(&e.engine))
                .sum::<u64>()
        );
    }

    #[test]
    fn a_refused_next_stream_leaves_raw_old_traffic_authenticating_on_the_receiver_that_was_never_rebound()
     {
        let mut s = Scenario::new();
        let held = s.play.resident_bytes();
        for blk in 0..20 {
            let payload = source_bytes(blk);
            s.play.note_sent(blk, &payload);
            let wire = s
                .wire
                .sender
                .send(Wire::frame(&s.tl, blk, payload))
                .expect("encodes");
            s.play
                .stage_raw(s.tl.send_true_ns(blk) + 10_000_000, 0, wire);
        }
        // One byte short of the candidate plus the receiver copy a commit would retain: refused, nothing live changed.
        let short =
            crate::media_playout::synthetic_ledger(2 * held + retained_receiver_bytes() - 1);
        let refused = s
            .play
            .prepare_stream(STREAM_B, 1, 30, &short, s.clock.epoch())
            .err()
            .expect("no room");
        assert!(matches!(
            refused,
            OpenRefusal::Admission(MediaAdmitError::Engine(AdmitError::Capacity(_)))
        ));
        for blk in 0..20 {
            let played = decide_raw(&mut s, blk);
            assert_eq!(authentic(played, blk), source_bytes(blk), "block {blk}");
        }
        let c = s.wire.receiver.counters();
        assert_eq!((c.accepted, c.rejected_wrong_stream), (20, 0));
        let r = s.play.report();
        assert_eq!(
            (
                r.accepted_by_draining_generation,
                r.refused_at_receiver,
                r.decided_real
            ),
            (0, 0, 20)
        );
        // Exactly the funded line prepares it.
        let exact = crate::media_playout::synthetic_ledger(2 * held + retained_receiver_bytes());
        assert!(
            s.play
                .prepare_stream(STREAM_B, 1, 30, &exact, s.clock.epoch())
                .is_ok()
        );
    }

    #[test]
    fn rapid_generations_each_keep_their_own_receiver_copy_while_they_owe_a_tail_and_only_the_ledger_caps_them()
     {
        const STREAM_C: u64 = 0x5EED_5EED_0000_0003;
        const CUT2: u64 = CUT + 10;
        let (mut s, tail) = crossing();
        let e = engine_resident_bytes(&s.play.engines[0].engine);
        let r = retained_receiver_bytes();
        // A third stream is committed at CUT2 while the first still owes its tail and every block of the second is in flight:
        // three generations at once, the first two each holding a copy of the receiver as it was when the next one was committed.
        let short = crate::media_playout::synthetic_ledger(3 * e + 2 * r - 1);
        assert!(
            s.play
                .prepare_stream(STREAM_C, 1, CUT2, &short, s.clock.epoch())
                .is_err(),
            "one byte short of the second copy"
        );
        let room = crate::media_playout::synthetic_ledger(3 * e + 2 * r);
        let prepared = s
            .play
            .prepare_stream(STREAM_C, 1, CUT2, &room, s.clock.epoch())
            .unwrap_or_else(|e| panic!("room for three generations and two retained copies: {e}"));
        s.play
            .commit_stream(STREAM_C, prepared, Some(s.wire.receiver.clone()));
        s.wire
            .receiver
            .bind_stream(StreamId::new(STREAM_C).expect("stream id"), 1);
        assert_eq!(s.play.stream_count(), 3);
        assert_eq!(s.play.resident_bytes(), 3 * e + 2 * r);
        let mut third = Wire::on_stream(STREAM_C);
        for blk in CUT2..CUT2 + 5 {
            let payload = other_bytes(blk);
            s.play.note_sent(blk, &payload);
            let wire = third
                .sender
                .send(Wire::frame(&s.tl, blk, payload))
                .expect("encodes");
            s.play
                .stage_raw(s.tl.send_true_ns(blk) + 10_000_000, 0, wire);
        }
        s.play
            .stage_raw(s.tl.decision_true_ns(CUT - 1) - 5_000_000, 0, tail);
        for blk in 0..CUT2 + 5 {
            let want = if blk < CUT {
                source_bytes(blk)
            } else {
                other_bytes(blk)
            };
            let played = decide_raw(&mut s, blk);
            assert_eq!(authentic(played, blk), want, "block {blk}");
        }
        let report = s.play.report();
        // The first stream's tail crossed two rebinds and the second stream's ten blocks crossed one.
        assert_eq!(report.accepted_by_draining_generation, 1 + 10);
        assert_eq!(
            (
                report.refused_at_receiver,
                report.replay_refused_at_receiver,
                report.outside_generation_refused,
                report.wrong_stream_refused_at_receiver
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(report.decided_real, CUT2 + 5);
        // Every copy is dropped when its generation has decided its tail.
        assert!(s.play.engines.iter().all(|e| e.ingress.is_none()));
        assert_eq!(
            s.play.resident_bytes(),
            s.play
                .engines
                .iter()
                .map(|e| engine_resident_bytes(&e.engine))
                .sum::<u64>()
        );
    }

    #[test]
    fn a_refused_next_stream_leaves_the_playing_one_deciding_real_blocks_and_a_funded_one_still_opens()
     {
        let mut s = Scenario::new();
        let held = s.play.resident_bytes();
        for blk in 0..20 {
            s.arrives(blk, 20_000_000);
        }
        for blk in 0..10 {
            let played = s.decide(blk);
            assert_eq!(authentic(played, blk), source_bytes(blk), "block {blk}");
        }
        // The next stream does not fit beside the playing one: a typed refusal, nothing live changed.
        let tight =
            crate::media_playout::synthetic_ledger(2 * held + retained_receiver_bytes() - 1);
        let refused = s
            .play
            .prepare_stream(STREAM_B, 1, 30, &tight, s.clock.epoch())
            .err()
            .expect("no room beside the playing stream");
        assert!(matches!(
            refused,
            OpenRefusal::Admission(MediaAdmitError::Engine(AdmitError::Capacity(_)))
        ));
        assert_eq!(s.play.stream_count(), 1);
        // The stream that was playing goes on deciding REAL blocks, each with exactly the bytes its sender sent.
        for blk in 10..20 {
            let played = s.decide(blk);
            assert_eq!(authentic(played, blk), source_bytes(blk), "block {blk}");
        }
        assert_eq!(s.play.report().decided_real, 20);
        // Control: with room for both, the candidate is prepared (still not live) and then committed.
        let both = crate::media_playout::synthetic_ledger(2 * held + retained_receiver_bytes());
        let prepared = s
            .play
            .prepare_stream(STREAM_B, 1, 30, &both, s.clock.epoch())
            .expect("fits beside the playing stream");
        assert_eq!(s.play.stream_count(), 1);
        s.play.commit_stream(STREAM_B, prepared, None);
        assert_eq!(s.play.stream_count(), 2);
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
            .deliver_until(&s.clock, &s.sim, 900_000_000, None)
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
        let err = match s.play.decide_block(2, &s.tl, &s.clock, &s.sim, None) {
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
        let mut play = NodePlayout::bind(STREAM, 1, tl.pts_group_ns(0), &synthetic_ledger(), 1)
            .expect("binds");
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
        assert!(play.in_flight.values().all(|p| p.start_frame() % 256 == 0));
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
            let mut play = NodePlayout::bind(STREAM, 1, tl.pts_group_ns(0), &synthetic_ledger(), 1)
                .expect("binds");
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
                        .decide_with_bytes(
                            blk,
                            &self.tl,
                            &self.clock,
                            &self.sim,
                            Some(&mut self.wire.receiver),
                        )
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
        let staged = opened(staged);
        assert_eq!(staged.session_epoch, 0);
        assert_eq!(staged.start_frame, 20 * (FRAMES_PER_BLOCK as u64));
        assert_ne!(staged.payload, source_bytes(20));
        // The member's receiver refused it at N01 when it was planted. Its replay window is untouched: the 60 real datagrams are
        // still in flight and are authenticated when they arrive (below).
        let counters = planted.wire.receiver.counters();
        assert_eq!((counters.rejected_stale_epoch, counters.accepted), (1, 0));

        let played = planted.decide_all();
        assert_plays_own_bytes(&played, &[]);
        assert_eq!(planted.wire.receiver.counters().accepted, 60);
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
            let mut play = NodePlayout::bind(STREAM, 1, tl.pts_group_ns(0), &synthetic_ledger(), 1)
                .expect("binds");
            let mut old = Wire::on_stream(STREAM);
            let mut new = Wire::on_stream(STREAM_B);
            for blk in 0..cutover {
                let payload = source_bytes(blk);
                play.note_sent(blk, &payload);
                let packet = old.packet(&tl, blk, payload);
                play.stage(tl.send_true_ns(blk) + 5_000_000, 0, packet);
            }
            play.next_send = cutover;
            play.open_stream(STREAM_B, 1, cutover, &synthetic_ledger())
                .expect("opens");
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
                .decide_with_bytes(blk, &self.tl, &self.clock, &self.sim, None)
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
            .decide_block(0, &fresh.tl, &fresh.clock, &fresh.sim, None)
        {
            Err(e) => e,
            Ok(_) => panic!("a packet of an unknown stream was accepted"),
        };
        assert!(err.contains("no such stream"), "{err}");
    }

    #[test]
    fn a_source_change_that_does_not_fit_beside_the_playing_stream_is_refused_and_the_member_is_unchanged()
     {
        let tl = timeline();
        let ledger = synthetic_ledger();
        let mut play = NodePlayout::bind(STREAM, 1, tl.pts_group_ns(0), &ledger, 1).expect("binds");
        let held = engine_resident_bytes(&play.engines[0].engine);
        // A line that holds the playing engine and a candidate of the same profile, less one byte.
        let tight =
            crate::media_playout::synthetic_ledger(2 * held + retained_receiver_bytes() - 1);
        let err = play
            .open_stream(STREAM_B, 1, 10, &tight)
            .expect_err("no room beside the playing stream");
        assert!(err.contains("admission refused: capacity"), "{err}");
        assert_eq!(play.engines.len(), 1);
        assert_eq!(play.engines[0].stream_id, STREAM);
        assert!(play.engines[0].until_block.is_none());
        // Exactly enough for both: admitted, and the new generation is appended.
        let both = crate::media_playout::synthetic_ledger(2 * held + retained_receiver_bytes());
        play.open_stream(STREAM_B, 1, 10, &both)
            .expect("fits beside it");
        assert_eq!(play.engines.len(), 2);
        // The first stream alone binds in the tight line (the refusal was the overlap).
        assert!(NodePlayout::bind(STREAM, 1, tl.pts_group_ns(0), &tight, 1).is_ok());
    }

    #[test]
    fn a_stream_cannot_be_opened_twice_at_the_same_block_or_before_the_latest_one() {
        let tl = timeline();
        let mut play = NodePlayout::bind(STREAM, 1, tl.pts_group_ns(0), &synthetic_ledger(), 1)
            .expect("binds");
        assert!(
            play.open_stream(STREAM_B, 1, 0, &synthetic_ledger())
                .is_err()
        );
        play.open_stream(STREAM_B, 1, 10, &synthetic_ledger())
            .expect("opens");
        assert!(
            play.open_stream(STREAM, 1, 20, &synthetic_ledger())
                .is_err(),
            "a stream id is never reused"
        );
        assert!(
            play.open_stream(0x77, 1, 10, &synthetic_ledger()).is_err(),
            "not at or before the latest start"
        );
        assert!(
            NodePlayout::unbound()
                .open_stream(STREAM, 1, 10, &synthetic_ledger())
                .is_err()
        );
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
        let mut play = NodePlayout::bind(STREAM, 1, tl.pts_group_ns(0), &synthetic_ledger(), 1)
            .expect("binds");
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
            opened(
                play.in_flight
                    .get(&(ORIGIN + offset(blk), blk, 0))
                    .expect("staged"),
            )
            .payload
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
            let mut play =
                NodePlayout::bind(STREAM_B, 1, tl.pts_group_ns(0), &synthetic_ledger(), 1)
                    .expect("binds");
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
        // The member's real receiver refused it, by name, when it was planted; nothing was staged for it. The 40 genuine datagrams are
        // still in flight: a receiver authenticates them when they arrive, not when they are sent.
        assert_eq!(control_wire.receiver.counters().rejected_wrong_stream, 0);
        assert_eq!(planted_wire.receiver.counters().rejected_wrong_stream, 1);
        assert_eq!(planted_wire.receiver.counters().accepted, 0);
        assert_eq!(planted.in_flight.len(), control.in_flight.len());
        // A fault with no replaced stream to send from is a campaign error.
        let mut wire = Wire::on_stream(STREAM_B);
        let mut schedule = NetworkSchedule::new(NetworkScheduleConfig::default());
        let mut play = NodePlayout::bind(STREAM_B, 1, tl.pts_group_ns(0), &synthetic_ledger(), 1)
            .expect("binds");
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
