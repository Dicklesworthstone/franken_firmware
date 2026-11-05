//! The Virtual House harness (`Q01` / `ffw-gmq`) and the readiness UX simulation (`UX01` / `ffw-389`).
//!
//! Everything here is a test harness: it links `franken-test-support` (network impairment schedules,
//! continuity, fencing and readiness oracles, a redacting diagnostic sink). It is compiled only for unit
//! tests or with the off-by-default `harness` Cargo feature, so a default (device) build of
//! `franken-speaker` carries none of it and has no dependency edge onto `franken-test-support`.

use crate::SpeakerReadinessState;
use crate::clock_log::{ClockLog, ClockLogSummary};
use crate::control_adapter::{VolumeDefect, VolumeDesk, VolumeReport, VolumeStep};
use crate::playout_adapter::{
    CampaignTimeline, LinkFault, NodePlayout, Played, PlayoutMemberReport, PreviousEpoch, Publish,
    SendLink, Silence,
};
use franken_board_profile::{BoardProfile, synthetic_test_fixture_catalog};
use franken_clock::LatencyLedger;
use franken_clock::group::{
    Accepted, ClockStatus, GroupClock, GroupClockConfig, MuteReason, Output, ProbeReject,
    ProbeResponse, StartPlan, StartReject, StartSchedule, group_at,
};
use franken_control::{
    AirPlay2ReceiverState, AlexaDirective, FsonosSoapRequest, FsonosSoapResponse,
    SpotifySessionState, dispatch_alexa_directive, handle_fsonos_soap,
};
use franken_dsp::{BoardProtectionDsp, BoundedDriftResampler, FRAMES_PER_BLOCK, StereoAudioBlock};
use franken_hal::{AudioHalDevice, HalTelemetry, state as hal_state};
use franken_platform::MemoryBudgetLedger;
use franken_session::{
    Admitted, AuthorityToken, ChannelRole, CommandClass, FencedControlCommand, GroupCommandPayload,
    SessionError, SourceArbiter, SourceCommand, SourceConfig, SourceEpoch, SourceError, SourceId,
    SourceKind, UnifiedGroupSession,
};
use franken_stream::{
    Capabilities, Initiator, NegotiationError, OutboundFrame, StreamId, StreamKey, StreamReceiver,
    StreamSender, respond,
};
use franken_test_support::{
    AmplifierObservation, BoardObservation, BoundedDiagnosticSink, ClockObservation,
    CommandObservation, DiagnosticEvent, ExpectedSamples, FencedCommandOracle, NetworkSchedule,
    NetworkScheduleConfig, OracleViolation, ReadinessOracle, ReadinessSpec, SampleContinuityOracle,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Synthetic group key and stream identity for the simulated house (public test values, not secrets).
/// The key is the group's pre-shared key: it authenticates the negotiation, and each member's media
/// key is derived from it and from that member's own negotiation transcript (`N01`), so no two
/// members share a media key.
const CAMPAIGN_STREAM_KEY: [u8; 32] = [0xA5; 32];
const CAMPAIGN_STREAM_ID: u64 = 0x5EED_5EED_0000_0001;

fn campaign_stream_id() -> Result<StreamId, String> {
    StreamId::new(CAMPAIGN_STREAM_ID).map_err(|e| e.to_string())
}

/// SIMULATED stand-in for the stream id a sender draws from admitted entropy at every stream start (`N01` §4): nonzero and
/// different for every member and every source epoch, and **not entropy**. The production source is `P02`; swapping it in
/// changes this one function.
fn simulated_stream_id(member_id: &str, source_epoch: u64) -> u64 {
    let mut h = fnv1a(member_id.as_bytes());
    for part in [source_epoch, 0x57_4EA1_u64] {
        h ^= part;
        h = h.wrapping_mul(0x0100_0000_01b3);
        h ^= h >> 29;
    }
    h | 1
}

// ------------------------------------------------------------------------------------------------
// Stream creation through negotiation (`N01` / `ffw-ey5`).
//
// Before a block flows, the coordinator and each member run the N01 exchange: the coordinator's Offer,
// the member's Answer, and a selection both ends compute from the two capability sets. Each end then
// builds its media endpoint from its own copy of the session, so the wire version, the format and the
// features are the negotiated ones and the media key is bound to that member's transcript. A member
// the coordinator cannot negotiate with gets no stream at all: it is muted, with N01's bounded
// diagnostic on record, and is never put on a quietly degraded stream.
// ------------------------------------------------------------------------------------------------

/// Byte offset of the negotiation message version in an Offer or an Answer (N01 contract, section 9).
/// The decoder checks it before it computes the tag, so a message carrying another version is refused
/// as an unsupported version and not as a forgery. A test pins that the offset is the right one.
const HELLO_VERSION_BYTE: usize = 4;

/// What a simulated member's firmware does in the negotiation. [`PeerFirmware::CURRENT`] is this
/// build's own. Tests plant a different member to show that one the coordinator cannot negotiate
/// with ends up refused, not degraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerFirmware {
    /// The largest media payload the member's firmware accepts, in bytes.
    max_payload_bytes: u16,
    /// A negotiation message version the member's Answer carries instead of this build's (newer
    /// firmware). `None` leaves the Answer as this build made it.
    answer_message_version: Option<u8>,
}

impl PeerFirmware {
    const CURRENT: Self = Self {
        max_payload_bytes: Capabilities::baseline().max_payload_bytes,
        answer_message_version: None,
    };

    fn capabilities(self) -> Capabilities {
        Capabilities {
            max_payload_bytes: self.max_payload_bytes,
            ..Capabilities::baseline()
        }
    }
}

/// What negotiation agreed for one member's stream, copied out of the session for the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamAgreement {
    pub wire_version: u8,
    /// A single N01 format bit.
    pub format: u8,
    pub max_payload_bytes: u16,
    /// Features both ends support and the stream may therefore use.
    pub features: u32,
}

/// Which end of the exchange refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusedBy {
    /// The member, while answering the coordinator's Offer.
    Member,
    /// The coordinator, while checking the member's Answer.
    Coordinator,
}

/// Why a member has no stream: N01's stable code and its bounded text (numbers only, never a key,
/// tag, nonce or digest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamRefusal {
    pub refused_by: RefusedBy,
    pub code: String,
    pub detail: String,
}

/// What negotiation produced for one member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamOutcome {
    Negotiated(StreamAgreement),
    Refused(StreamRefusal),
}

/// The two media endpoints a negotiation produced for one member, or none if it was refused.
struct MemberStream {
    outcome: StreamOutcome,
    receiver: Option<StreamReceiver>,
    sender: Option<StreamSender>,
    /// One epoch earlier, keyed with the same media key: what a planted previous-epoch datagram is made with.
    previous_epoch: Option<PreviousEpoch>,
    /// The media key of the negotiated session, kept so a source change can start a new stream on it (`N01` §4).
    media_key: Option<StreamKey>,
}

fn refused(by: RefusedBy, error: &NegotiationError) -> MemberStream {
    MemberStream {
        outcome: StreamOutcome::Refused(StreamRefusal {
            refused_by: by,
            code: error.code().to_string(),
            detail: error.to_string(),
        }),
        receiver: None,
        sender: None,
        previous_epoch: None,
        media_key: None,
    }
}

/// A member's peer identity in the negotiation: nonzero, and never the coordinator's.
fn member_peer_id(member_id: &str) -> u64 {
    let id = fnv1a(member_id.as_bytes()) | 1;
    if id == COORDINATOR_ID { id ^ 2 } else { id }
}

/// SIMULATED stand-in for the nonce an endpoint draws from admitted entropy for each negotiation
/// message (`N01` requires a fresh nonce per message). It is deterministic and **not entropy**: it is
/// nonzero and differs by role, member, epoch and boot, which is all the simulation needs. The
/// production source is `franken_platform` `PlatformLayer::fill_random` (`P02`); swapping it in
/// changes this one function.
fn simulated_nonce(role: &[u8], member_id: &str, epoch: u64, boot_index: u32) -> [u8; 16] {
    let high = simulated_boot_entropy(member_id, epoch, boot_index) ^ fnv1a(role);
    let low = high.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x5A5A_5A5A_A5A5_A5A5;
    let mut nonce = [0u8; 16];
    nonce[..8].copy_from_slice(&high.to_be_bytes());
    nonce[8..].copy_from_slice(&low.to_be_bytes());
    nonce[15] |= 1;
    nonce
}

/// Run the N01 exchange between the coordinator and one member and build both media endpoints from it.
/// A refusal at either end is an outcome, not an error: the member simply has no stream. `Err` is for
/// a defect (the ends disagree, or this build cannot speak what was agreed).
fn negotiate_member_stream(
    member_id: &str,
    epoch: u64,
    boot_index: u32,
    firmware: PeerFirmware,
) -> Result<MemberStream, String> {
    let psk = StreamKey::from_bytes(CAMPAIGN_STREAM_KEY);
    let (initiator, offer) = Initiator::offer(
        &psk,
        Capabilities::baseline(),
        COORDINATOR_ID,
        campaign_stream_id()?,
        epoch,
        simulated_nonce(b"offer", member_id, epoch, boot_index),
    )
    .map_err(|e| {
        format!(
            "coordinator could not build its offer for {member_id}: {}",
            e.code()
        )
    })?;
    let (member_session, mut answer) = match respond(
        &psk,
        firmware.capabilities(),
        member_peer_id(member_id),
        epoch,
        simulated_nonce(b"answer", member_id, epoch, boot_index),
        &offer,
    ) {
        Ok(pair) => pair,
        Err(error) => return Ok(refused(RefusedBy::Member, &error)),
    };
    if let Some(version) = firmware.answer_message_version {
        // Planted: the member's firmware speaks a newer negotiation message than this build.
        answer[HELLO_VERSION_BYTE] = version;
    }
    let coordinator_session = match initiator.finish(&answer) {
        Ok(session) => session,
        Err(error) => return Ok(refused(RefusedBy::Coordinator, &error)),
    };
    if coordinator_session.selection() != member_session.selection()
        || coordinator_session.transcript_digest() != member_session.transcript_digest()
    {
        return Err(format!(
            "member {member_id}: the two ends of the negotiation disagree"
        ));
    }
    let selection = *coordinator_session.selection();
    // The epoch before this one, with this session's media key (`LinkFault::StaleEpoch`). Epoch 0 has no predecessor.
    let previous_epoch = coordinator_session
        .epoch()
        .checked_sub(1)
        .map(|earlier| PreviousEpoch {
            sender: StreamSender::new(
                coordinator_session.media_key().clone(),
                coordinator_session.stream_id(),
                earlier,
            ),
            receiver: StreamReceiver::new(
                coordinator_session.media_key().clone(),
                coordinator_session.stream_id(),
                earlier,
            ),
        });
    let sender = StreamSender::from_negotiated(&coordinator_session).map_err(|e| {
        format!(
            "member {member_id}: coordinator cannot speak what was agreed: {}",
            e.code()
        )
    })?;
    let receiver = StreamReceiver::from_negotiated(&member_session).map_err(|e| {
        format!(
            "member {member_id}: member cannot speak what was agreed: {}",
            e.code()
        )
    })?;
    Ok(MemberStream {
        outcome: StreamOutcome::Negotiated(StreamAgreement {
            wire_version: selection.wire_version,
            format: selection.format,
            max_payload_bytes: selection.max_payload_bytes,
            features: selection.features,
        }),
        receiver: Some(receiver),
        sender: Some(sender),
        previous_epoch,
        media_key: Some(coordinator_session.media_key().clone()),
    })
}

/// Critical record that a member has no stream, with N01's bounded diagnostic as its cause.
fn stream_refused_event(
    seed: u64,
    member_id: &str,
    session: &UnifiedGroupSession,
    refusal: &StreamRefusal,
) -> DiagnosticEvent {
    DiagnosticEvent {
        schema_version: String::new(),
        timestamp_mono_ns: 0,
        run_id: format!("vh-seed-{seed}"),
        case_id: "Q01-virtual-house".to_string(),
        correlation_id: format!("negotiation-{member_id}"),
        member_id: member_id.to_string(),
        group_id: session.group_id.clone(),
        source_epoch: session.current_epoch,
        state_revision: session.state_revision,
        event_kind: "stream_refused".to_string(),
        message: format!("negotiation refused; {member_id} is muted"),
        queue_depth: 0,
        latency_us: 0,
        fault: None,
        cause: Some(format!("{}: {}", refusal.code, refusal.detail)),
    }
}

/// Per-speaker node in the Virtual House simulator (`Q01` / `ffw-gmq`).
pub struct VirtualSpeakerNode {
    pub member_id: String,
    pub board: BoardProfile,
    pub readiness: SpeakerReadinessState,
    pub readiness_oracle: ReadinessOracle,
    /// One continuity/content oracle per hardware channel, so no channel is judged on another's evidence.
    pub continuity_oracles: Vec<SampleContinuityOracle>,
    /// The member side of the N03 group clock. The node sounds only when this says so (see `gate_block`).
    pub clock: GroupClock,
    /// The node's own simulated monotonic clock; the group clock is true time. Tests may step it.
    pub sim_clock: SimNodeClock,
    /// The start the session controller last admitted for this node, as N03 planned it.
    pub admitted_plan: Option<StartPlan>,
    /// Whether the controller re-admits a start by itself once the clock is locked again after a reset or expiry.
    pub auto_admit: bool,
    /// The only path from datagram bytes to the jitter buffer: structure, MAC, field validation,
    /// stream identity, epoch and replay window, in that order (`N01`). It is built from the
    /// member's own negotiated session, so it is keyed for this member alone and limited to the
    /// negotiated version, format and features. `None` only when negotiation was refused.
    pub receiver: Option<StreamReceiver>,
    /// The coordinator's end of the same session. The simulation owns both ends, so it lives with
    /// the member it sends to. `None` exactly when `receiver` is.
    pub coordinator_sender: Option<StreamSender>,
    /// One epoch earlier, keyed with the member's own media key: what a planted `StaleEpochPacket` sends. `None` when the
    /// stream was refused or its epoch has no predecessor.
    pub(crate) previous_epoch: Option<PreviousEpoch>,
    /// The media key of this member's stream, so a source change can start a new stream on it. `None` when refused.
    pub(crate) stream_key: Option<StreamKey>,
    /// The sender of the stream a source change replaced: what a planted `StaleStreamDatagram` sends with.
    pub(crate) replaced_sender: Option<StreamSender>,
    /// Real blocks played per source epoch, identified from the bytes that sounded.
    pub(crate) source_blocks: BTreeMap<u64, u64>,
    /// FNV-1a over every sample this node rendered, in block, channel and frame order (see [`fnv1a_extend_samples`]).
    pub(crate) output_digest: u64,
    /// Blocks the gate let sound whose audio was the engine's authentic block (not concealed, not silence).
    pub(crate) audible_authentic_blocks: u64,
    /// Blocks in which at least one sample of at least one channel was not zero.
    pub(crate) rendered_nonzero_blocks: u64,
    /// What negotiation produced for this member's stream: the agreement, or the refusal that left it
    /// without one.
    pub stream: StreamOutcome,
    /// Blocks that sounded nothing because there was no stream to play (counted in `muted_blocks` too).
    pub stream_refused_blocks: u64,
    /// The member's playout: the real N04 `PlayoutEngine`, fed through its own clock (`playout_adapter`).
    pub(crate) playout: NodePlayout,
    pub resampler: BoundedDriftResampler,
    pub dsp: BoardProtectionDsp,
    /// A second instance of the same DSP, fed the same input and gain. Its output is the
    /// expectation for the handoff check, so it detects corruption between the DSP and the
    /// output path (and nondeterminism), not errors in the DSP's own arithmetic.
    pub shadow_dsp: BoardProtectionDsp,
    pub hal: AudioHalDevice<hal_state::Running>,
    pub rendered_blocks: u64,
    pub authentic_blocks: u64,
    pub concealed_blocks: u64,
    /// Samples compared against the shadow render, summed over every channel.
    pub handoff_checked_samples: u64,
    pub max_skew_us: u64,
    /// Blocks the gate let sound, and blocks it replaced with silence at the same stream position.
    pub audible_blocks: u64,
    pub muted_blocks: u64,
    /// Clock correction handed to the legacy resampler: the group clock's ratio in ppm while a rate estimate is in
    /// force. That needs a 4 s span of exchanges, longer than any run the harness makes today, so this is always 0
    /// here; the sign convention against the legacy resampler is untested, and nothing claims it works.
    pub drift_ppm: i32,
    /// This member's log of its group clock: the clock's events drained into a bounded sink after bring-up and after
    /// every block's gate (`clock_log.rs`). Whatever the sink does, it cannot change what the clock decides.
    pub(crate) clock_log: ClockLog,
}

/// Silence blocks the virtual HAL must have primed before it may unmute. Stated by the harness,
/// so the readiness gate does not depend on the HAL's own configuration.
const REQUIRED_SILENCE_BLOCKS: u32 = 2;
const HAL_DMA_SLOTS: u16 = 8;
/// What the readiness gate requires of the clock, stated here and not read back from the
/// clock. 4 exchanges and 2 ms are the N03 lock count and admission bound; a test pins both
/// against the production configuration.
const CLOCK_LOCK_MIN_SAMPLES: u32 = 4;
const CLOCK_LOCK_MAX_UNCERTAINTY_US: u64 = 2_000;
const CLOCK_EXCHANGES: u32 = 4;
/// The simulated clock exchange is built from a known truth (the group clock is true time and the node has
/// its own `SimNodeClock`), so the estimate is checked against that truth and not against the clock's own
/// `status()`.
const SIM_ONE_WAY_DELAY_NS: u64 = 400_000;
const SIM_PEER_DWELL_NS: u64 = 50_000;
/// Logical time between bring-up steps; only the order of observations matters.
const BRING_UP_STEP_NS: u64 = 1_000_000;

/// How a node is brought up. `NOMINAL` is the real sequence; the other values exist so tests can
/// plant a defect in the bring-up code itself.
#[derive(Debug, Clone, Copy)]
struct BringUpPlan {
    /// Silence blocks the simulated driver is configured to demand before unmuting.
    hal_required_silence_blocks: u32,
    /// Silence blocks the bring-up primes.
    silence_blocks_primed: u32,
    clock_exchanges: u32,
    /// Skip the node's own clock gate and rely on the independent oracle alone.
    bypass_own_clock_gate: bool,
    /// The node's own simulated clock; `None` derives a member-specific one from the member id.
    sim_clock: Option<SimNodeClock>,
    /// Which boot of this member this is; it changes the first request number of the clock exchanges.
    boot_index: u32,
    /// The block whose presentation is the first admitted start; `None` leaves the node unadmitted.
    first_start_block: Option<u64>,
    /// Whether the controller re-admits a start by itself after a reset or expiry.
    auto_admit: bool,
    /// What the member's firmware does when the coordinator negotiates its stream (`N01`).
    firmware: PeerFirmware,
}

impl BringUpPlan {
    const NOMINAL: Self = Self {
        hal_required_silence_blocks: REQUIRED_SILENCE_BLOCKS,
        silence_blocks_primed: REQUIRED_SILENCE_BLOCKS,
        clock_exchanges: CLOCK_EXCHANGES,
        bypass_own_clock_gate: false,
        sim_clock: None,
        boot_index: 0,
        first_start_block: Some(0),
        auto_admit: true,
        firmware: PeerFirmware::CURRENT,
    };
}

fn amplifier_observation(t_ns: u64, telemetry: &HalTelemetry) -> AmplifierObservation {
    AmplifierObservation {
        t_ns,
        muted: telemetry.hardware_muted,
        primed_silence_blocks: telemetry.primed_silence_blocks,
    }
}

fn readiness_err(violation: OracleViolation) -> String {
    format!("readiness oracle: {violation}")
}

/// Expected samples for one channel of one block: the shadow DSP's output for the same input.
struct ShadowReference<'a> {
    start_frame: u64,
    samples: &'a [i16],
}

impl ExpectedSamples for ShadowReference<'_> {
    fn expected(&self, frame: u64) -> i16 {
        frame
            .checked_sub(self.start_frame)
            .and_then(|offset| usize::try_from(offset).ok())
            .and_then(|offset| self.samples.get(offset).copied())
            .unwrap_or(i16::MIN)
    }
}

/// Coverage of the fencing checks, so a report says what was actually exercised.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencingProbeStats {
    /// Commands handed to the real session and judged by the fencing oracle.
    pub commands_observed: u64,
    pub fresh_applied: u64,
    pub duplicates_suppressed: u64,
    pub stale_rejected: u64,
    pub epoch_advances: u64,
}

type SessionOutcome = Result<u64, SessionError>;

fn fencing_err(violation: OracleViolation) -> String {
    format!("fencing oracle: {violation}")
}

/// Hands commands to the real `UnifiedGroupSession` and has the independent fencing oracle judge
/// each outcome. The authority epoch and the record of what was issued come from this harness,
/// never from the session, so the session cannot vouch for itself.
struct CommandAudit {
    oracle: FencedCommandOracle,
    stats: FencingProbeStats,
    next_id: u64,
}

impl CommandAudit {
    fn new(initial_authority_epoch: u64) -> Self {
        Self {
            oracle: FencedCommandOracle::new(initial_authority_epoch),
            stats: FencingProbeStats::default(),
            next_id: 1,
        }
    }

    /// Issue a new logical command. The outer error means the oracle objected; the inner result
    /// is the session's own answer.
    fn deliver_new(
        &mut self,
        session: &mut UnifiedGroupSession,
        cmd: FencedControlCommand,
    ) -> Result<(u64, SessionOutcome), String> {
        let id = self.next_id;
        self.next_id += 1;
        self.oracle
            .record_issued(id, cmd.epoch, cmd.command_seq)
            .map_err(fencing_err)?;
        let outcome = self.observe(session, id, cmd)?;
        Ok((id, outcome))
    }

    /// Deliver an already issued command again: a duplicate delivery.
    fn redeliver(
        &mut self,
        session: &mut UnifiedGroupSession,
        id: u64,
        cmd: FencedControlCommand,
    ) -> Result<SessionOutcome, String> {
        self.observe(session, id, cmd)
    }

    fn observe(
        &mut self,
        session: &mut UnifiedGroupSession,
        id: u64,
        cmd: FencedControlCommand,
    ) -> Result<SessionOutcome, String> {
        let outcome = session.apply_command(cmd);
        self.stats.commands_observed += 1;
        self.oracle
            .observe_outcome(CommandObservation {
                command_id: id,
                applied: outcome.is_ok(),
                system_epoch_after: session.current_epoch,
            })
            .map_err(fencing_err)?;
        Ok(outcome)
    }
}

/// Far from the small sequence numbers the campaign and the control crate use.
const FENCING_PROBE_SEQ_BASE: u64 = 1_000_000;

/// Drive the real session through the situations the fence exists for and let the oracle judge
/// each outcome: a fresh command, its duplicate delivery, an authority change, a stale command.
fn exercise_fencing(
    session: &mut UnifiedGroupSession,
    audit: &mut CommandAudit,
    epoch: u64,
) -> Result<(), String> {
    let set_volume = |cmd_epoch: u64, command_seq: u64, volume_0_to_100: u8| FencedControlCommand {
        epoch: cmd_epoch,
        command_seq,
        payload: GroupCommandPayload::SetGroupVolume { volume_0_to_100 },
    };
    let mut seq = FENCING_PROBE_SEQ_BASE;

    // A fresh command is applied...
    let fresh = set_volume(epoch, seq, 40);
    let (id, outcome) = audit.deliver_new(session, fresh.clone())?;
    outcome.map_err(|e| format!("fencing probe: a fresh command was refused: {e}"))?;
    audit.stats.fresh_applied += 1;

    // ...and delivering the same command again must not apply it twice.
    if audit.redeliver(session, id, fresh)?.is_err() {
        audit.stats.duplicates_suppressed += 1;
    }

    // The harness elects a new coordinator epoch; a command stamped with it is applied.
    audit
        .oracle
        .declare_authority(epoch + 1)
        .map_err(fencing_err)?;
    seq += 1;
    let (_, outcome) = audit.deliver_new(session, set_volume(epoch + 1, seq, 41))?;
    outcome.map_err(|e| {
        format!("fencing probe: a command from the new authority epoch was refused: {e}")
    })?;
    audit.stats.fresh_applied += 1;
    audit.stats.epoch_advances += 1;

    // A command from the superseded epoch must be fenced out.
    seq += 1;
    let (_, outcome) = audit.deliver_new(session, set_volume(epoch, seq, 99))?;
    if outcome.is_err() {
        audit.stats.stale_rejected += 1;
    }
    Ok(())
}

/// A planted output-path defect, applied after the DSP renders a block and before the oracles see
/// the handoff. Constructed only by tests.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))]
enum OutputFault {
    /// Flip one sample of one member's rendered block, in the first or the last channel.
    CorruptSample {
        member_id: &'static str,
        block: u64,
        last_channel: bool,
        offset: usize,
    },
    /// The member never produces its final block.
    DropFinalBlock { member_id: &'static str },
    /// The controller never schedules a start for any member but this one, so the others stay muted (and the skew
    /// of the one that sounds is trivially 0).
    UnadmittedExcept { member_id: &'static str },
    /// The block's packet reaches the member's engine after the engine has decided the block (`LinkFault::Late`).
    LateBlock { member_id: &'static str, block: u64 },
    /// The packets of `block` and `block + 1` swap arrival instants (`LinkFault::SwapArrivals`).
    ReorderedPair { member_id: &'static str, block: u64 },
    /// A datagram of the previous epoch, keyed with the member's own media key, arrives beside the block's own packet
    /// (`LinkFault::StaleEpoch`).
    StaleEpochPacket { member_id: &'static str, block: u64 },
    /// The member's own monotonic clock reads `delta_ns` more from the start of `block` on (a suspend, or a step).
    ClockLeap {
        member_id: &'static str,
        block: u64,
        delta_ns: u64,
    },
    /// A replaced source adapter keeps offering its own blocks after the arbiter replaced it. The publish gate must refuse
    /// them: only the owner's audio may sound. Needs a source change in the scenario.
    ReplacedSourceKeepsPublishing,
    /// A datagram of the stream a source change replaced reaches `member_id`'s receiver, sent with the old stream's sender
    /// at a block position at or after the cutover: the receiver, rebound to the new stream, must refuse it. Needs a source
    /// change in the scenario.
    StaleStreamDatagram { member_id: &'static str, block: u64 },
    /// A tailnet client retries a relative volume step as a new command (a new command number, the revision read again), so the
    /// retry applies again where the contract says a retry of the same command applies once. Needs a volume plan in the scenario.
    TailnetRetryAsNewCommand,
    /// A tailnet client that composed a relative step against an older revision names the current one, so a step the contract says
    /// is stale applies on top of another controller's change. Needs a volume plan in the scenario.
    TailnetStaleRevisionRefreshed,
    /// The render path hands both DSPs a silent block wherever the member's stream delivered audio and the gate let it sound, and
    /// still counts the block as audible. The live and shadow renders agree (both are silent), so continuity, shadow, fencing and
    /// playout all hold; only the question "did a member that sounded render anything" can see it.
    SilentInput { member_id: &'static str },
}

/// One line describing a planted fault, for the `fault` field of the diagnostic log.
fn describe_fault(fault: OutputFault) -> String {
    match fault {
        OutputFault::CorruptSample {
            member_id,
            block,
            last_channel,
            offset,
        } => format!(
            "corrupt_sample member={member_id} block={block} channel={} offset={offset}",
            if last_channel { "last" } else { "first" }
        ),
        OutputFault::DropFinalBlock { member_id } => {
            format!("drop_final_block member={member_id}")
        }
        OutputFault::UnadmittedExcept { member_id } => {
            format!("unadmitted_except member={member_id}")
        }
        OutputFault::LateBlock { member_id, block } => {
            format!("late_block member={member_id} block={block}")
        }
        OutputFault::ReorderedPair { member_id, block } => {
            format!("reordered_pair member={member_id} block={block}")
        }
        OutputFault::StaleEpochPacket { member_id, block } => {
            format!("stale_epoch_packet member={member_id} block={block}")
        }
        OutputFault::ClockLeap {
            member_id,
            block,
            delta_ns,
        } => format!("clock_leap member={member_id} block={block} delta_ns={delta_ns}"),
        OutputFault::ReplacedSourceKeepsPublishing => {
            "replaced_source_keeps_publishing".to_string()
        }
        OutputFault::StaleStreamDatagram { member_id, block } => {
            format!("stale_stream_datagram member={member_id} block={block}")
        }
        OutputFault::TailnetRetryAsNewCommand => "tailnet_retry_as_new_command".to_string(),
        OutputFault::TailnetStaleRevisionRefreshed => {
            "tailnet_stale_revision_refreshed".to_string()
        }
        OutputFault::SilentInput { member_id } => format!("silent_input member={member_id}"),
    }
}

/// Which of two source adapters that raced from the same view reaches the arbiter first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
enum Racer {
    /// An AirPlay 2 sender that wants the group (`start`, which the policy table lets replace Spotify).
    AirPlay,
    /// The incumbent Spotify session starting its next stream (a new track).
    Spotify,
}

/// A legitimate source change during a campaign (a scenario, not a defect): at the start of render iteration `block` two
/// source adapters, both having last seen the same source epoch, race to start a stream. The arbiter admits exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
struct SourceSwitch {
    block: u64,
    first: Racer,
}

/// What a campaign does beyond streaming the first source to the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Scenario {
    source_switch: Option<SourceSwitch>,
    /// Relative-volume steps driven through the real G03 endpoint and N02 channel (or, for a reference run, absolute sets applied
    /// directly), each at the start of a render iteration. See `control_adapter`.
    volume: Option<&'static [VolumeStep]>,
    /// What the source's two channels are. Under [`SourceSignal::Asymmetric`] the campaign also asks that every member that was
    /// sent audio and sounded it rendered something.
    signal: SourceSignal,
}

impl Scenario {
    const NONE: Self = Self {
        source_switch: None,
        volume: None,
        signal: SourceSignal::Opposed,
    };
}

/// The two racing adapters' identities, as the arbiter sees them. Synthetic labels.
const SPOTIFY_LABEL: &str = "spotify-house";
const AIRPLAY_LABEL: &str = "airplay-living-room";

fn source_id(kind: SourceKind, label: &str) -> Result<SourceId, String> {
    SourceId::new(kind, label).map_err(|e| e.code().to_string())
}

/// The source that owns block positions from `from_block` on, under source epoch `epoch`.
struct ProgramEntry {
    from_block: u64,
    source: SourceId,
    epoch: SourceEpoch,
}

/// Who owns which block positions. A start, a replacement or a restart opens a new stream at its cutover block.
struct Program {
    entries: Vec<ProgramEntry>,
}

impl Program {
    fn starting(source: SourceId, epoch: SourceEpoch) -> Self {
        Self {
            entries: vec![ProgramEntry {
                from_block: 0,
                source,
                epoch,
            }],
        }
    }

    fn index_at(&self, blk: u64) -> usize {
        self.entries
            .iter()
            .rposition(|entry| entry.from_block <= blk)
            .unwrap_or(0)
    }

    /// The program that owns block position `blk`.
    fn owner_at(&self, blk: u64) -> &ProgramEntry {
        &self.entries[self.index_at(blk)]
    }

    /// The program that `blk`'s program replaced, if it replaced one: the adapter that was told to stop.
    fn replaced_at(&self, blk: u64) -> Option<&ProgramEntry> {
        self.index_at(blk)
            .checked_sub(1)
            .map(|index| &self.entries[index])
    }

    fn push(&mut self, from_block: u64, source: SourceId, epoch: SourceEpoch) {
        self.entries.push(ProgramEntry {
            from_block,
            source,
            epoch,
        });
    }
}

/// How the campaign's source relates its two channels (`docs/contracts/q01.md`, limit 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
enum SourceSignal {
    /// The campaign's original signal, `right = -left`. The mono mix `0.5 * (l + r)` is exactly zero, so a member whose every
    /// channel comes from that mix (S12, S1, the sub) renders silence at any volume. Every existing assertion is about this one.
    Opposed,
    /// `right = 0.5 * left`: the mono mix is `0.75 * left`, so every member has something to render. Used by the scenarios that
    /// ask whether a member renders sound.
    Asymmetric,
}

/// The audio source epoch `epoch` publishes for block `blk`. Epoch 1 is the campaign's original signal; every later epoch is
/// a different program, so the bytes of a block name the stream they came from. `signal` only changes the right channel.
fn source_block_in(signal: SourceSignal, blk: u64, epoch: u64) -> StereoAudioBlock {
    let mut block = StereoAudioBlock::silence(blk * (FRAMES_PER_BLOCK as u64));
    let base = ((blk % 32) as f32) * 0.02 + 0.05;
    let amp = if epoch <= 1 {
        base
    } else {
        base * 0.5 + 0.01 * (epoch.min(20) as f32)
    };
    block.left = [amp; FRAMES_PER_BLOCK];
    block.right = match signal {
        SourceSignal::Opposed => [-amp; FRAMES_PER_BLOCK],
        SourceSignal::Asymmetric => [0.5 * amp; FRAMES_PER_BLOCK],
    };
    block
}

/// The campaign's original signal ([`SourceSignal::Opposed`]): what the existing tests state about the source.
#[cfg(test)]
fn source_block(blk: u64, epoch: u64) -> StereoAudioBlock {
    source_block_in(SourceSignal::Opposed, blk, epoch)
}

/// The block a source epoch publishes for `blk`, decoded the way a member's playout decodes what it plays.
fn heard_block(signal: SourceSignal, blk: u64, epoch: u64) -> Result<StereoAudioBlock, String> {
    StereoAudioBlock::from_be_i16_bytes(
        blk * (FRAMES_PER_BLOCK as u64),
        &source_block_in(signal, blk, epoch).to_be_i16_bytes(),
    )
    .map_err(|e| e.to_string())
}

/// Block `blk` of source epoch `epoch` as a media frame. Blocks are coded in groups of four; the sender assigns `seq == blk`
/// within a stream.
fn frame_of(
    timeline: &CampaignTimeline,
    signal: SourceSignal,
    blk: u64,
    epoch: u64,
) -> OutboundFrame {
    let start_frame = blk * (FRAMES_PER_BLOCK as u64);
    let pts_ns = timeline.pts_group_ns(blk);
    let consume_by_ns = pts_ns - BLOCK_PERIOD_NS;
    OutboundFrame {
        fec_group_id: (blk / 4) as u16,
        fec_index: (blk % 4) as u8,
        fec_group_size: 4,
        ..OutboundFrame::media(
            start_frame,
            pts_ns,
            consume_by_ns,
            source_block_in(signal, blk, epoch).to_be_i16_bytes(),
        )
    }
}

/// What the source arbiter did during a campaign (`G01` §10), as receipts: how many commands it admitted, how it refused
/// the rest, who owned the group at the end, and where the program changed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceReport {
    /// Commands the arbiter admitted: the first start, and the winner of a race.
    pub admitted: u64,
    /// Commands it refused, by the refusal's stable code.
    pub refused: BTreeMap<String, u64>,
    /// The source epoch in force at the end and the source that owned the group (`kind:label`).
    pub final_epoch: u64,
    pub final_owner: Option<String>,
    /// The first block of the new program when the owner changed streams: every member cut over here.
    pub cutover_block: Option<u64>,
}

/// The source side of a campaign: the real arbiter, the authority token it judges under, the program it has produced and the
/// report. The simulation owns both the arbiter and the adapters that submit to it; no real transport is involved (`G01` §10).
struct SourceDesk {
    token: AuthorityToken,
    arbiter: SourceArbiter,
    program: Program,
    report: SourceReport,
}

impl SourceDesk {
    /// The first source starts: Spotify, as the Alexa directive that began the campaign asked.
    fn start(session: &UnifiedGroupSession) -> Result<Self, String> {
        let token = AuthorityToken::issue(session, u64::MAX);
        let mut arbiter = SourceArbiter::new(SourceConfig::default());
        let spotify = source_id(SourceKind::Spotify, SPOTIFY_LABEL)?;
        let command = SourceCommand {
            source: spotify.clone(),
            class: CommandClass::Start,
            expected_epoch: arbiter.view(session).epoch,
        };
        let started = arbiter
            .submit(session, &token, CAMPAIGN_ORIGIN_NS, &command)
            .map_err(|e| format!("the first source could not start: {}", e.code()))?;
        Ok(Self {
            token,
            arbiter,
            program: Program::starting(spotify, started.epoch),
            report: SourceReport {
                admitted: 1,
                ..SourceReport::default()
            },
        })
    }
}

/// Two source adapters race to start a stream from the same view, in the order `switch` says. The arbiter admits exactly one
/// (a start that saw the same epoch as another cannot both mint), the other is refused as stale and told the epoch the winner
/// minted. The winner's start begins a new stream: every member that has a stream cuts over at the first block its sender has
/// not sent yet (drain to a common future cutover), with a new stream id, its receiver rebound, a new sender and a new engine.
/// Returns the cutover block.
fn execute_source_switch(
    switch: SourceSwitch,
    total_blocks: u64,
    session: &UnifiedGroupSession,
    desk: &mut SourceDesk,
    nodes: &mut BTreeMap<String, VirtualSpeakerNode>,
) -> Result<u64, String> {
    let view = desk.arbiter.view(session);
    let incumbent = desk
        .program
        .entries
        .last()
        .map(|entry| entry.source.clone())
        .ok_or_else(|| "the program has no owner".to_string())?;
    let challenger = source_id(SourceKind::AirPlay2, AIRPLAY_LABEL)?;
    let order = match switch.first {
        Racer::AirPlay => [challenger, incumbent],
        Racer::Spotify => [incumbent, challenger],
    };
    let now_ns = CAMPAIGN_ORIGIN_NS + block_offset_ns(switch.block);
    let mut winner: Option<Admitted> = None;
    for source in order {
        let command = SourceCommand {
            source: source.clone(),
            class: CommandClass::Start,
            expected_epoch: view.epoch,
        };
        match desk.arbiter.submit(session, &desk.token, now_ns, &command) {
            Ok(admitted) => {
                desk.report.admitted += 1;
                if winner.replace(admitted).is_some() {
                    return Err(format!(
                        "both racing starts were admitted, the second from {source}"
                    ));
                }
            }
            Err(SourceError::SourceEpochStale { expected, current }) => {
                // The loser is told it lost the race: it saw the epoch it presented, and the winner minted the next one.
                let minted = winner.as_ref().map(|won| won.epoch.get());
                if expected != view.epoch.get() || minted != Some(current) {
                    return Err(format!(
                        "{source} was refused as stale with epochs {expected} and {current}, but it saw {} and the winner minted {minted:?}",
                        view.epoch.get()
                    ));
                }
                *desk
                    .report
                    .refused
                    .entry("SOURCE_EPOCH_STALE".to_string())
                    .or_default() += 1;
            }
            Err(other) => {
                return Err(format!(
                    "the racing start of {source} was refused as {}, not as stale",
                    other.code()
                ));
            }
        }
    }
    let admitted = winner.ok_or_else(|| "no racing start was admitted".to_string())?;
    if !admitted.minted || admitted.epoch.get() != view.epoch.get() + 1 {
        return Err(format!(
            "the winning start minted epoch {} from {}",
            admitted.epoch.get(),
            view.epoch.get()
        ));
    }
    let owner = admitted
        .owner
        .clone()
        .ok_or_else(|| "a start left the group with no owner".to_string())?;

    let mut cutover = None;
    for (id, node) in nodes.iter() {
        if node.coordinator_sender.is_none() {
            continue;
        }
        let first_unsent = node.playout.first_unsent();
        match cutover {
            None => cutover = Some(first_unsent),
            Some(agreed) if agreed != first_unsent => {
                return Err(format!(
                    "member {id} would cut over at block {first_unsent}, the others at {agreed}"
                ));
            }
            Some(_) => {}
        }
    }
    let cutover = cutover.ok_or_else(|| "no member has a stream to switch".to_string())?;
    if cutover >= total_blocks {
        return Err(format!(
            "the source change was admitted too late: the new stream would start at block {cutover} of {total_blocks}"
        ));
    }
    for node in nodes.values_mut() {
        node.switch_stream(admitted.epoch.get(), cutover)?;
    }
    desk.program.push(cutover, owner, admitted.epoch);
    desk.report.cutover_block = Some(cutover);
    Ok(cutover)
}

/// The campaign's nominal block period (256 frames at 48 kHz), in nanoseconds, rounded down. It is a DURATION to
/// compare against, never a factor to multiply by a block index: the true period is 16/3 ms, so `index *
/// BLOCK_PERIOD_NS` falls 1/3 ns further behind with every block, one whole frame (20.8 us) after 62 500 blocks and
/// half a frame, enough to round to the wrong frame, after 31 250 (about 2.8 minutes). The instant a block starts is
/// [`block_offset_ns`].
const BLOCK_PERIOD_NS: u64 = 5_333_333;

/// Nanoseconds from the start of the campaign's first block to the start of block `blk`: `blk * 256 / 48 000` seconds,
/// that is `blk * 16 000 000 / 3` ns, rounded to the nearest nanosecond. The error is at most half a nanosecond
/// (0.00002 frame) however long the campaign runs, so the nearest frame to this instant is always `blk * 256`.
const fn block_offset_ns(blk: u64) -> u64 {
    (blk * 16_000_000 + 1) / 3
}

/// Critical record that a planted fault took effect, with the fault schedule entry in force.
fn fault_injected_event(
    seed: u64,
    blk_idx: u64,
    t_ns: u64,
    session: &UnifiedGroupSession,
    fault: Option<OutputFault>,
) -> DiagnosticEvent {
    DiagnosticEvent {
        schema_version: String::new(),
        timestamp_mono_ns: t_ns,
        run_id: format!("vh-seed-{seed}"),
        case_id: "Q01-virtual-house".to_string(),
        correlation_id: format!("blk-{blk_idx}"),
        member_id: "house".to_string(),
        group_id: session.group_id.clone(),
        source_epoch: session.current_epoch,
        state_revision: session.state_revision,
        event_kind: "fault_injected".to_string(),
        message: format!("planted fault took effect at block {blk_idx}"),
        queue_depth: 0,
        latency_us: 0,
        fault: fault.map(describe_fault),
        cause: None,
    }
}

impl VirtualSpeakerNode {
    /// This member's stream after a source change (`N01` §4: "a restarted or rekeyed sender uses a fresh [stream id] and the
    /// receiver is told over the control channel"): a new stream id on the same media key, the member's real receiver rebound
    /// to it, a new sender, and a new playout engine bound at the cutover. The old sender is kept: a replaced adapter's
    /// datagrams are what a planted `StaleStreamDatagram` sends. A member with no stream has nothing to switch.
    fn switch_stream(&mut self, source_epoch: u64, cutover_block: u64) -> Result<(), String> {
        let Some(old_sender) = self.coordinator_sender.take() else {
            return Ok(());
        };
        let (Some(key), Some(receiver)) = (self.stream_key.clone(), self.receiver.as_mut()) else {
            self.coordinator_sender = Some(old_sender);
            return Err(format!(
                "member {}: has a sender but no media key or receiver",
                self.member_id
            ));
        };
        let id = StreamId::new(simulated_stream_id(&self.member_id, source_epoch))
            .map_err(|e| e.to_string())?;
        let epoch = receiver.active_epoch();
        receiver.bind_stream(id, epoch);
        self.coordinator_sender = Some(StreamSender::new(key, id, epoch));
        self.replaced_sender = Some(old_sender);
        self.playout
            .open_stream(id.get(), epoch, cutover_block)
            .map_err(|e| format!("member {}: {e}", self.member_id))
    }

    pub fn bring_up_admitted(
        member_id: &str,
        board: BoardProfile,
        initial_epoch: u64,
    ) -> Result<Self, String> {
        Self::bring_up_with_plan(member_id, board, initial_epoch, BringUpPlan::NOMINAL)
    }

    /// Bring a node up while the readiness oracle watches. Nothing here sets a prerequisite: the
    /// board checks, the HAL's mute pin and prime counter, and the clock's raw output are
    /// recorded as observations as they happen, and `announce_ready` judges the history.
    /// Simulation-only: every observation comes from a simulated component.
    fn bring_up_with_plan(
        member_id: &str,
        board: BoardProfile,
        initial_epoch: u64,
        plan: BringUpPlan,
    ) -> Result<Self, String> {
        let mut readiness_oracle = ReadinessOracle::new(ReadinessSpec {
            required_primed_silence_blocks: REQUIRED_SILENCE_BLOCKS,
            min_clock_samples: CLOCK_LOCK_MIN_SAMPLES,
            max_clock_uncertainty_us: CLOCK_LOCK_MAX_UNCERTAINTY_US,
        });
        let mut t_ns = 0u64;

        board
            .verify_integrity()
            .map_err(|e| format!("board integrity failed: {e:?}"))?;
        let budget = MemoryBudgetLedger::for_board(&board);
        budget
            .verify_budget()
            .map_err(|e| format!("memory budget failed: {e}"))?;
        t_ns += BRING_UP_STEP_NS;
        readiness_oracle
            .record_board(BoardObservation {
                t_ns,
                integrity_ok: true,
                routing_consistent: board.channel_routing.len()
                    == usize::from(board.hardware_channels),
            })
            .map_err(readiness_err)?;

        let closed = AudioHalDevice::open_for_profile(
            board.clone(),
            HAL_DMA_SLOTS,
            plan.hal_required_silence_blocks,
        )
        .map_err(|e| format!("HAL open failed: {e}"))?;
        let mut prepared = closed.prepare();
        t_ns += BRING_UP_STEP_NS;
        readiness_oracle
            .record_amplifier(amplifier_observation(t_ns, &prepared.telemetry()))
            .map_err(readiness_err)?;
        for n in 1..=plan.silence_blocks_primed {
            prepared
                .prime_silence_block()
                .map_err(|e| format!("silence prime {n} failed: {e}"))?;
            t_ns += BRING_UP_STEP_NS;
            readiness_oracle
                .record_amplifier(amplifier_observation(t_ns, &prepared.telemetry()))
                .map_err(readiness_err)?;
        }

        let running = prepared
            .start_unmuted()
            .map_err(|(_, e)| format!("HAL unmute failed: {e}"))?;
        t_ns += BRING_UP_STEP_NS;
        readiness_oracle
            .record_amplifier(amplifier_observation(t_ns, &running.telemetry()))
            .map_err(readiness_err)?;

        let sim_clock = plan
            .sim_clock
            .unwrap_or_else(|| SimNodeClock::for_member(member_id));
        let clock_cfg = GroupClockConfig::for_board(&board).map_err(|e| e.to_string())?;
        let seq_base = simulated_boot_entropy(member_id, initial_epoch, plan.boot_index);
        let mut clock = GroupClock::new(clock_cfg, initial_epoch, COORDINATOR_ID, seq_base)
            .map_err(|e| e.to_string())?;
        let mut last_exchange_true_ns = 0_u64;
        for seq in 1..=u64::from(plan.clock_exchanges) {
            let true_ns = seq * BRING_UP_EXCHANGE_SPACING_NS;
            sim_exchange(&mut clock, &sim_clock, true_ns)
                .map_err(|e| format!("clock exchange {seq} refused: {}", e.code()))?;
            last_exchange_true_ns = true_ns;
        }
        let ready_true_ns = last_exchange_true_ns + BRING_UP_READY_AFTER_NS;
        let ready_local_ns = sim_clock.local(ready_true_ns);
        if !plan.bypass_own_clock_gate && clock.status(ready_local_ns) != ClockStatus::Locked {
            return Err("clock is not locked".to_string());
        }
        t_ns += BRING_UP_STEP_NS;
        let reading = clock.reading(ready_local_ns);
        readiness_oracle
            .record_clock(ClockObservation {
                t_ns,
                ingested_samples: plan.clock_exchanges,
                uncertainty_us: reading.map_or(u64::MAX, |a| a.uncertainty_ns.div_ceil(1_000)),
                // The group clock is true time, so the estimate's error is its reading minus the true instant.
                offset_error_ns: reading.map_or(0, |a| {
                    let error =
                        i128::from(group_at(&a, ready_local_ns)) - i128::from(ready_true_ns);
                    i64::try_from(error).unwrap_or(i64::MAX)
                }),
            })
            .map_err(readiness_err)?;

        t_ns += BRING_UP_STEP_NS;
        readiness_oracle
            .announce_ready(t_ns)
            .map_err(readiness_err)?;

        // The session controller admits the first start: the presentation of the chosen block.
        let admitted_plan = match plan.first_start_block {
            Some(block) => {
                let sched = StartSchedule {
                    epoch: initial_epoch,
                    start_group_ns: Self::block_pts_group_ns(block),
                };
                Some(
                    clock
                        .admit(sched, ready_local_ns)
                        .map_err(|e| format!("start admission refused: {}", e.code()))?,
                )
            }
            None => None,
        };

        // The member's stream exists only through negotiation; a refusal leaves it with none.
        let link =
            negotiate_member_stream(member_id, initial_epoch, plan.boot_index, plan.firmware)?;

        let mut clock_log = ClockLog::new(member_id)?;
        clock_log.drain(&mut clock);
        // The engine is bound to the stream negotiation produced: its epoch, and the presentation time of block 0.
        let playout = if link.sender.is_some() {
            NodePlayout::bind(
                CAMPAIGN_STREAM_ID,
                initial_epoch,
                Self::block_pts_group_ns(0),
            )?
        } else {
            NodePlayout::unbound()
        };

        let dsp = BoardProtectionDsp::new(board.clone()).map_err(|e| e.to_string())?;
        let shadow_dsp = dsp.clone();
        let continuity_oracles: Vec<SampleContinuityOracle> =
            (0..usize::from(board.hardware_channels))
                .map(|_| SampleContinuityOracle::new())
                .collect();

        Ok(Self {
            member_id: member_id.to_string(),
            board,
            readiness: SpeakerReadinessState::ReadySynchronized,
            readiness_oracle,
            continuity_oracles,
            clock,
            sim_clock,
            admitted_plan,
            auto_admit: plan.auto_admit,
            receiver: link.receiver,
            coordinator_sender: link.sender,
            previous_epoch: link.previous_epoch,
            stream_key: link.media_key,
            replaced_sender: None,
            source_blocks: BTreeMap::new(),
            output_digest: OUTPUT_DIGEST_START,
            audible_authentic_blocks: 0,
            rendered_nonzero_blocks: 0,
            stream: link.outcome,
            stream_refused_blocks: 0,
            playout,
            resampler: BoundedDriftResampler::new(),
            dsp,
            shadow_dsp,
            hal: running,
            rendered_blocks: 0,
            authentic_blocks: 0,
            concealed_blocks: 0,
            handoff_checked_samples: 0,
            max_skew_us: 0,
            audible_blocks: 0,
            muted_blocks: 0,
            drift_ppm: 0,
            clock_log,
        })
    }
}

// ------------------------------------------------------------------------------------------------
// The audible gate (`N03`): each node's playout decision rests on `franken_clock::group::GroupClock`.
// ------------------------------------------------------------------------------------------------

/// The coordinator (the group's leader) in the simulated house. A public test value.
const COORDINATOR_ID: u64 = 0x5EED_C0DE_0000_0001;
/// True time at which block 0 of a campaign is sent. The bring-up exchanges happen before it.
const CAMPAIGN_ORIGIN_NS: u64 = 250_000_000;
/// Stream lead: block `k` is presented this long after it is sent.
const PLAYOUT_HORIZON_NS: u64 = 500_000_000;
/// One clock exchange every this many blocks (about 170 ms of stream time).
const PROBE_EVERY_BLOCKS: u64 = 32;
/// The gate decides this long after a block's send instant, so an exchange started at the instant has completed.
const GATE_AFTER_SEND_NS: u64 = 1_000_000;
/// True time of the n-th bring-up exchange is `n` times this.
const BRING_UP_EXCHANGE_SPACING_NS: u64 = 10_000_000;
/// Bring-up considers the clock ready this long after its last exchange was sent.
const BRING_UP_READY_AFTER_NS: u64 = 2_000_000;

/// The digest of nothing: FNV-1a's offset basis. A node that rendered a block has moved off it.
const OUTPUT_DIGEST_START: u64 = 0xcbf2_9ce4_8422_2325;

/// The member the volume plan's endpoint is. It must be one that RENDERS the campaign's source: the source is `left = amp`,
/// `right = -amp`, so the mono mix `0.5 * (l + r)` is exactly zero, and a member whose every channel comes from that mix (S12, S1,
/// the sub) renders silence at any gain, which no sample digest can tell from another volume. S5 has channels fed from the left
/// and the right.
const VOLUME_ENDPOINT_MEMBER: &str = "spk-office-s5";

/// Fold `samples` (as big-endian bytes) into the FNV-1a digest `h`. A dependency-free stand-in for "the same samples": two runs
/// whose digests agree rendered the same samples, in the same order, and a different sample makes them differ.
fn fnv1a_extend_samples(mut h: u64, samples: &[i16]) -> u64 {
    for sample in samples {
        for byte in sample.to_be_bytes() {
            h ^= u64::from(byte);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}

/// FNV-1a over bytes: a stable, dependency-free hash for deriving simulated per-node values.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325_u64;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// SIMULATED stand-in for the platform entropy source, used for the first request number of a node's clock
/// exchanges (`GroupClock::new`'s `seq_base`). It is seeded and deterministic, so it is **not entropy**; it only
/// gives each member and each boot a different, non-constant base so a response recorded before a restart cannot
/// answer a request made after it. The production source is `franken_platform` `PlatformLayer::fill_random`
/// (`P02`), which is not yet declared in that crate's `lib.rs`; swapping it in changes this one function.
fn simulated_boot_entropy(member_id: &str, epoch: u64, boot_index: u32) -> u64 {
    let mut h = fnv1a(member_id.as_bytes());
    for part in [epoch, u64::from(boot_index), 0x5EA1_BA5E_u64] {
        h ^= part;
        h = h.wrapping_mul(0x0100_0000_01b3);
        h ^= h >> 29;
    }
    h
}

/// A node's own monotonic clock in the simulated house. True time `t` (ns) is the campaign timeline; the
/// coordinator's group clock reads `t` exactly, and this clock reads `local0 + t * (1 + skew)`, floored to 1 us.
/// Nothing the node's code sees is true time: it exists so the node's claims can be checked against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimNodeClock {
    pub skew_ppb: i64,
    pub local0_ns: u64,
}

impl SimNodeClock {
    const RESOLUTION_NS: u64 = 1_000;

    /// A clock with a fixed, member-specific offset and a skew within +/-50 ppm.
    #[must_use]
    pub fn for_member(member_id: &str) -> Self {
        let h = fnv1a(member_id.as_bytes());
        let skew_ppb = i64::try_from(h % 100_001).unwrap_or(0) - 50_000;
        let local0 = 1_000_000_000 + (h >> 20) % 4_000_000_000;
        Self {
            skew_ppb,
            local0_ns: local0 - local0 % Self::RESOLUTION_NS,
        }
    }

    /// The node's reading at true time `true_ns`.
    #[must_use]
    pub fn local(&self, true_ns: u64) -> u64 {
        let skew = i128::from(true_ns) * i128::from(self.skew_ppb);
        let v = i128::from(self.local0_ns) + i128::from(true_ns) + skew.div_euclid(1_000_000_000);
        let v = u64::try_from(v).unwrap_or(0);
        v - v % Self::RESOLUTION_NS
    }

    /// The first true time at which this clock reads `local_ns` or more (the clock never runs backwards).
    #[must_use]
    pub fn true_at_local(&self, local_ns: u64) -> u64 {
        let (mut lo, mut hi) = (0_u64, 1_u64 << 50);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.local(mid) < local_ns {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }
}

/// One simulated clock exchange started at true time `true_ns`: the request as the node sends it, the
/// coordinator's answer, and the node's local reading of the arrival. The path is symmetric with the constant
/// one-way delay and dwell above, so the exchange has a known truth.
fn sim_probe(clock: &mut GroupClock, sim: &SimNodeClock, true_ns: u64) -> (ProbeResponse, u64) {
    let req = clock.next_probe(sim.local(true_ns));
    let t2 = true_ns + SIM_ONE_WAY_DELAY_NS;
    let t3 = t2 + SIM_PEER_DWELL_NS;
    let t4 = t3 + SIM_ONE_WAY_DELAY_NS;
    let resp = ProbeResponse {
        epoch: req.epoch,
        leader: COORDINATOR_ID,
        seq: req.seq,
        t1_echo_ns: req.t1_local_ns,
        t2_group_ns: t2,
        t3_group_ns: t3,
    };
    (resp, sim.local(t4))
}

/// A clock exchange the node sends and the coordinator answers.
fn sim_exchange(
    clock: &mut GroupClock,
    sim: &SimNodeClock,
    true_ns: u64,
) -> Result<Accepted, ProbeReject> {
    let (resp, t4_local) = sim_probe(clock, sim, true_ns);
    clock.on_response(resp, t4_local)
}

/// What the audible gate decided for one block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockGate {
    /// What `GroupClock` says about this block's presentation instant.
    pub output: Output,
    /// Where the node's own transform puts the block's presentation, on its local clock.
    pub presented_local_ns: Option<u64>,
}

impl BlockGate {
    #[must_use]
    pub const fn audible(&self) -> bool {
        self.output.is_audible()
    }
}

impl VirtualSpeakerNode {
    /// The true time at which a sounding block is presented: the instant the node's own transform chose, mapped
    /// back through its simulated clock. `None` for a block that does not sound.
    #[must_use]
    pub fn presented_true_ns(&self, gate: &BlockGate) -> Option<u64> {
        match (gate.output, gate.presented_local_ns) {
            (Output::Audible, Some(local)) => Some(self.sim_clock.true_at_local(local)),
            _ => None,
        }
    }

    /// Group time at which block `blk_idx` is presented. The group clock is true time in this house.
    #[must_use]
    pub const fn block_pts_group_ns(blk_idx: u64) -> u64 {
        CAMPAIGN_ORIGIN_NS + block_offset_ns(blk_idx) + PLAYOUT_HORIZON_NS
    }

    /// One clock exchange with the coordinator, started at true time `true_ns`.
    pub fn exchange_at(&mut self, true_ns: u64) -> Result<Accepted, ProbeReject> {
        sim_exchange(&mut self.clock, &self.sim_clock, true_ns)
    }

    /// The session controller schedules a start at block `blk_idx`'s presentation. `now_true_ns` is the time of
    /// the request. The node stays muted, catching up, until the group clock reaches the start.
    pub fn admit_start_at_block(
        &mut self,
        blk_idx: u64,
        now_true_ns: u64,
    ) -> Result<StartPlan, StartReject> {
        let now_local = self.sim_clock.local(now_true_ns);
        let sched = StartSchedule {
            epoch: self.clock.epoch(),
            start_group_ns: Self::block_pts_group_ns(blk_idx),
        };
        let plan = self.clock.admit(sched, now_local)?;
        self.admitted_plan = Some(plan);
        Ok(plan)
    }

    /// The audible gate for block `blk_idx`: its clock exchange if one is due, the controller's re-admission once the
    /// clock is locked again, and then N03's answer for the block's presentation instant. A block sounds only if
    /// `GroupClock` says audible there (locked or in holdover, an admitted start reached, the authority live);
    /// otherwise the caller feeds silence. The exchange's own result is not used here: a rejection that resets the
    /// fit (a clock jump, a clock that went backwards) mutes the node through the clock's state, and any other
    /// rejection changes nothing.
    pub fn gate_block(&mut self, blk_idx: u64) -> BlockGate {
        let send_true = CAMPAIGN_ORIGIN_NS + block_offset_ns(blk_idx);
        if blk_idx > 0 && blk_idx.is_multiple_of(PROBE_EVERY_BLOCKS) {
            let _ = self.exchange_at(send_true);
        }
        let now_local = self.sim_clock.local(send_true + GATE_AFTER_SEND_NS);
        let pts_group = Self::block_pts_group_ns(blk_idx);
        // Settle the clock's state at the real time first: an expiry or a reset clears an admitted start.
        let _ = self.clock.tick(now_local);
        if self.auto_admit
            && self.clock.status(now_local) == ClockStatus::Locked
            && self.clock.output(now_local) == Output::Muted(MuteReason::NotAdmitted)
        {
            let sched = StartSchedule {
                epoch: self.clock.epoch(),
                start_group_ns: pts_group,
            };
            if let Ok(plan) = self.clock.admit(sched, now_local) {
                self.admitted_plan = Some(plan);
            }
        }
        self.drift_ppm = match self.clock.reading(now_local) {
            Some(anchor) if self.clock.rate_in_force() => i32::try_from(anchor.ratio_ppb / 1_000)
                .unwrap_or(0)
                .clamp(-500, 500),
            _ => 0,
        };
        // Would this node be allowed to sound when the block is presented? Ask N03 about that instant.
        let presented_local_ns = self.clock.local_for_group(pts_group, now_local);
        let output = presented_local_ns.map_or(Output::Muted(MuteReason::NotLocked), |l| {
            self.clock.output(l)
        });
        // The clock's events from this block go to its log. The drain only reads the clock's buffer.
        self.clock_log.drain(&mut self.clock);
        BlockGate {
            output,
            presented_local_ns,
        }
    }
}

/// Summary report emitted by a Virtual House multi-room simulation run (`Q01`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualHouseReport {
    /// Always true: every probe, clock exchange and expectation here comes from a simulated
    /// component, so this report is not evidence about real hardware.
    pub simulation_only: bool,
    /// What the fencing oracle observed the real session do with fresh, duplicate and stale commands.
    pub fencing: FencingProbeStats,
    pub group_id: String,
    pub unified_mixed_s1_s2: bool,
    pub total_blocks_streamed: u64,
    pub max_inter_speaker_skew_us: u64,
    /// Blocks in which every participant sounded, so the skew above covers every participant, and blocks in which at
    /// least one did not (it was muted), where there is nothing to compare. A run with an unmeasured block does not
    /// meet the target: a skew measured over fewer members than the group has is not a measurement of the group.
    pub skew_measured_blocks: u64,
    pub skew_unmeasured_blocks: u64,
    /// The members the skew is judged over: those with a media stream. A member N01 refused has none; it is out of the
    /// group by that recorded decision (`members[..].stream`, a critical `stream_refused` event) and is not counted.
    /// A member that has a stream but does not sound IS counted, and makes its blocks unmeasured. With fewer than two
    /// participants there is nothing to compare, so every block is unmeasured.
    pub skew_participants: usize,
    /// Whether the skew target was met: at least one block was compared, none was left unmeasured, and the largest
    /// skew is within 2 ms. A campaign that compared nothing (zero blocks) makes no claim, so this is `false` for it;
    /// `skew_measured_blocks == 0` tells that apart from a measured miss.
    pub within_2ms_skew_target: bool,
    pub video_sync_residual_us: i64,
    pub video_sync_within_40ms_gate: bool,
    pub dropped_log_events: u64,
    /// False when critical evidence (the campaign summary) could not be stored. A report with
    /// `evidence_complete == false` is incomplete and must not be read as a clean pass.
    pub evidence_complete: bool,
    /// What the source arbiter did (`G01` §10).
    #[serde(default)]
    pub source: SourceReport,
    /// What the relative-volume steps did through the real G03 endpoint (`None` for a campaign with no volume plan).
    #[serde(default)]
    pub volume: Option<VolumeReport>,
    pub members: BTreeMap<String, MemberSimulationStats>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberSimulationStats {
    pub profile_id: String,
    pub legacy_sw_gen: u8,
    pub hardware_channels: u8,
    pub rendered_blocks: u64,
    pub authentic_blocks: u64,
    pub concealed_blocks: u64,
    /// Blocks the N03 audible gate let sound, and blocks it muted (replaced with silence at the same position).
    pub audible_blocks: u64,
    pub muted_blocks: u64,
    /// What negotiation produced for this member's stream (`N01`): the agreed version and format, or
    /// the refusal that left it without one.
    pub stream: StreamOutcome,
    /// Blocks muted because there was no stream to play, a subset of `muted_blocks`.
    pub stream_refused_blocks: u64,
    /// Frames verified continuous on every channel (the minimum across channels).
    pub verified_continuous_frames: u64,
    /// Samples compared with the shadow render, summed over every channel. This is a handoff
    /// integrity check, not verification of the DSP's own arithmetic.
    pub handoff_checked_samples: u64,
    pub quarantined_dma_slots: usize,
    pub readiness: SpeakerReadinessState,
    /// What this member's clock log ended with: events offered to its bounded sink, kept and dropped, and whether any
    /// critical clock event was lost (`N03`, `docs/contracts/n03.md` section 13).
    #[serde(default)]
    pub clock_log: ClockLogSummary,
    /// The N04 engine's own account of this member's blocks (`ffw-gmq`): what arrived on time, late, twice or from the
    /// wrong epoch, and what was decided for every block.
    #[serde(default)]
    pub playout: PlayoutMemberReport,
    /// Real blocks played per source epoch, identified from the bytes that sounded (not from the arbiter's view): the
    /// program each block position actually carried.
    #[serde(default)]
    pub source_blocks: BTreeMap<u64, u64>,
    /// FNV-1a over every sample this member rendered (every channel of every block, in order). Two campaigns that reach the same
    /// audible state render the same samples and so have the same digest: that is how a race of relative-volume steps is held to
    /// a reference that sets the same volumes directly.
    #[serde(default)]
    pub output_fnv1a64: u64,
    /// Blocks the gate let sound whose audio was the engine's authentic block.
    #[serde(default)]
    pub audible_authentic_blocks: u64,
    /// Blocks in which at least one rendered sample was not zero. A member whose every channel comes from the mono mix of the
    /// original opposed source has none (`docs/contracts/q01.md`, limit 1).
    #[serde(default)]
    pub rendered_nonzero_blocks: u64,
}

/// Run a complete deterministic Virtual House simulation across 5 mixed-generation Sonos models
/// (`S5` PowerPC S1, `S1` MIPS S1, `S12` MIPS S2, `S3` PowerPC S1, `Sub` PowerPC S1).
pub fn run_virtual_house_campaign(
    seed: u64,
    total_blocks: u64,
) -> Result<VirtualHouseReport, String> {
    run_campaign(seed, total_blocks, None)
}

/// Limits of the diagnostic sink a normal campaign uses: 512 events, 256 KiB, and at most 256
/// ordinary events per virtual second. A healthy campaign emits one event per 5.33 ms block, about
/// 187 per virtual second, so the rate bound only ever limits bursts. Pseudonymous ids are not
/// enabled here: the simulation's ids are synthetic, and a key derived from a public seed would
/// protect nothing.
fn default_diagnostic_sink() -> BoundedDiagnosticSink {
    BoundedDiagnosticSink::new(512, 256 * 1024).with_rate_limit(256, 1_000_000_000)
}

fn run_campaign(
    seed: u64,
    total_blocks: u64,
    fault: Option<OutputFault>,
) -> Result<VirtualHouseReport, String> {
    let mut sink = default_diagnostic_sink();
    run_campaign_with_sink(seed, total_blocks, fault, &mut sink)
}

#[cfg(test)]
fn run_scenario(
    seed: u64,
    total_blocks: u64,
    fault: Option<OutputFault>,
    scenario: Scenario,
) -> Result<VirtualHouseReport, String> {
    let mut sink = default_diagnostic_sink();
    run_scenario_with_sink(seed, total_blocks, fault, scenario, &mut sink)
}

/// The campaign, logging to `sink` (which the caller keeps, so the log can be read afterwards).
/// The render loop emits one bounded `block_rendered` event per block and never waits on the
/// sink: a full, zero-capacity or unavailable sink only increases `dropped_log_events`, and must
/// change nothing else in the report. If the campaign fails, a critical `campaign_failed` event
/// records the causal error chain and the planted fault, if any, so the failure leaves evidence.
fn run_campaign_with_sink(
    seed: u64,
    total_blocks: u64,
    fault: Option<OutputFault>,
    sink: &mut BoundedDiagnosticSink,
) -> Result<VirtualHouseReport, String> {
    run_scenario_with_sink(seed, total_blocks, fault, Scenario::NONE, sink)
}

/// [`run_campaign_with_sink`] for a campaign that also changes its source (see [`Scenario`]).
fn run_scenario_with_sink(
    seed: u64,
    total_blocks: u64,
    fault: Option<OutputFault>,
    scenario: Scenario,
    sink: &mut BoundedDiagnosticSink,
) -> Result<VirtualHouseReport, String> {
    let result = run_campaign_scenario(seed, total_blocks, fault, sink, &[], scenario);
    if let Err(cause) = &result {
        sink.emit_critical(DiagnosticEvent {
            schema_version: String::new(),
            timestamp_mono_ns: block_offset_ns(total_blocks),
            run_id: format!("vh-seed-{seed}"),
            case_id: "Q01-virtual-house".to_string(),
            correlation_id: "corr-vh-failed".to_string(),
            member_id: "house".to_string(),
            group_id: "grp-virtual-house".to_string(),
            source_epoch: 0,
            state_revision: 0,
            event_kind: "campaign_failed".to_string(),
            message: "virtual house campaign failed".to_string(),
            queue_depth: 0,
            latency_us: 0,
            fault: fault.map(describe_fault),
            cause: Some(cause.clone()),
        });
    }
    result
}

/// `firmware` plants members whose negotiation differs from this build's own (see [`PeerFirmware`]);
/// a member not named runs [`PeerFirmware::CURRENT`]. Only the unit tests plant firmware, so only they call this.
#[cfg(test)]
fn run_campaign_inner(
    seed: u64,
    total_blocks: u64,
    fault: Option<OutputFault>,
    sink: &mut BoundedDiagnosticSink,
    firmware: &[(&str, PeerFirmware)],
) -> Result<VirtualHouseReport, String> {
    run_campaign_scenario(seed, total_blocks, fault, sink, firmware, Scenario::NONE)
}

/// The campaign, with its scenario: `run_campaign_inner` (tests only) runs it with none.
fn run_campaign_scenario(
    seed: u64,
    total_blocks: u64,
    fault: Option<OutputFault>,
    sink: &mut BoundedDiagnosticSink,
    firmware: &[(&str, PeerFirmware)],
    scenario: Scenario,
) -> Result<VirtualHouseReport, String> {
    let catalog = synthetic_test_fixture_catalog();
    let find_board = |model: &str| -> BoardProfile {
        catalog
            .iter()
            .find(|p| p.model_number == model)
            .expect("canonical model present")
            .clone()
    };

    let fleet_specs = [
        ("spk-office-s5", find_board("S5"), ChannelRole::Stereo),
        ("spk-bedroom-s1", find_board("S1"), ChannelRole::Stereo),
        ("spk-kitchen-s12", find_board("S12"), ChannelRole::Stereo),
        ("spk-den-s3", find_board("S3"), ChannelRole::Stereo),
        ("spk-living-sub", find_board("Sub"), ChannelRole::SubLfe),
    ];

    let epoch = 1u64;
    let mut session = UnifiedGroupSession::new("grp-virtual-house", "spk-kitchen-s12", epoch);
    let mut nodes: BTreeMap<String, VirtualSpeakerNode> = BTreeMap::new();
    let mut audit = CommandAudit::new(epoch);

    let mut cmd_seq = 1u64;
    for (member_id, board, role) in fleet_specs {
        audit
            .deliver_new(
                &mut session,
                FencedControlCommand {
                    epoch,
                    command_seq: cmd_seq,
                    payload: GroupCommandPayload::AdmitMember {
                        member_id: member_id.to_string(),
                        board: board.clone(),
                        role,
                    },
                },
            )?
            .1
            .map_err(|e| e.to_string())?;
        cmd_seq += 1;

        let mut plan = match fault {
            Some(OutputFault::UnadmittedExcept { member_id: kept }) if kept != member_id => {
                BringUpPlan {
                    first_start_block: None,
                    auto_admit: false,
                    ..BringUpPlan::NOMINAL
                }
            }
            _ => BringUpPlan::NOMINAL,
        };
        plan.firmware = firmware
            .iter()
            .find(|(id, _)| *id == member_id)
            .map_or(PeerFirmware::CURRENT, |(_, planted)| *planted);
        let node = VirtualSpeakerNode::bring_up_with_plan(member_id, board, epoch, plan)?;
        audit
            .deliver_new(
                &mut session,
                FencedControlCommand {
                    epoch,
                    command_seq: cmd_seq,
                    payload: GroupCommandPayload::MarkMemberClockLocked {
                        member_id: member_id.to_string(),
                    },
                },
            )?
            .1
            .map_err(|e| e.to_string())?;
        cmd_seq += 1;
        nodes.insert(member_id.to_string(), node);
    }

    let mut spotify = SpotifySessionState {
        active_device_id: "spk-kitchen-s12".to_string(),
        track_uri: None,
        codec: "ogg-vorbis-320k".to_string(),
        bitrate_kbps: 320,
        playing: false,
        lookahead_compressed_bytes: 512 * 1024,
    };
    dispatch_alexa_directive(
        &mut session,
        &mut spotify,
        AlexaDirective::PlaySpotifyOnGroup {
            track_uri: "spotify:track:franken_test_01".to_string(),
        },
    )
    .map_err(|e| e.to_string())?;

    // Spotify's start goes through the real source arbiter (`G01` §10), which decides who may publish. Planted source faults
    // and a source change need the arbiter's scenario to exist.
    let mut desk = SourceDesk::start(&session)?;
    if matches!(
        fault,
        Some(OutputFault::ReplacedSourceKeepsPublishing | OutputFault::StaleStreamDatagram { .. })
    ) && scenario.source_switch.is_none()
    {
        return Err("a planted source fault needs a source change in the scenario".to_string());
    }
    if let Some(switch) = scenario.source_switch
        && !(1..total_blocks).contains(&switch.block)
    {
        return Err(format!(
            "the source change is at block {}, outside 1..{total_blocks}",
            switch.block
        ));
    }
    let mut stale_publisher_from: Option<u64> = None;

    // Relative volume goes through the real G03 endpoint over the same session (`control_adapter`). A planted volume fault needs a
    // plan to act on.
    let volume_defect = match fault {
        Some(OutputFault::TailnetRetryAsNewCommand) => Some(VolumeDefect::FreshIdOnRetry),
        Some(OutputFault::TailnetStaleRevisionRefreshed) => {
            Some(VolumeDefect::StaleRevisionRefreshed)
        }
        _ => None,
    };
    if volume_defect.is_some() && scenario.volume.is_none() {
        return Err("a planted volume fault needs a volume plan in the scenario".to_string());
    }
    let mut volume_desk = match scenario.volume {
        Some(plan) => Some(VolumeDesk::start(
            &session,
            VOLUME_ENDPOINT_MEMBER,
            plan,
            total_blocks,
            CAMPAIGN_ORIGIN_NS,
            volume_defect,
        )?),
        None => None,
    };
    if volume_defect.is_some() {
        sink.emit_critical(fault_injected_event(
            seed,
            0,
            CAMPAIGN_ORIGIN_NS,
            &session,
            fault,
        ));
    }

    // Each member's stream came out of its own negotiation, so each has its own sender; a sender owns
    // stream identity, epoch and sequence, and sequence 0 is the first block. A member whose
    // negotiation was refused has none and is on record as muted with N01's diagnostic.
    for (member_id, node) in &nodes {
        if let StreamOutcome::Refused(refusal) = &node.stream {
            sink.emit_critical(stream_refused_event(seed, member_id, &session, refusal));
        }
    }
    let playout_horizon_ns: u64 = PLAYOUT_HORIZON_NS; // 500 ms

    // Create deterministic per-member network schedules
    let mut schedules: BTreeMap<String, NetworkSchedule> = nodes
        .keys()
        .enumerate()
        .map(|(idx, id)| {
            let cfg = NetworkScheduleConfig {
                seed: seed.wrapping_add(idx as u64 * 101),
                ..NetworkScheduleConfig::default()
            };
            (id.clone(), NetworkSchedule::new(cfg))
        })
        .collect();

    // Stream & render loop
    let mut max_inter_speaker_skew_us = 0u64;
    let mut skew_measured_blocks = 0u64;
    let mut skew_unmeasured_blocks = 0u64;
    let skew_participants = nodes
        .values()
        .filter(|node| node.coordinator_sender.is_some())
        .count();
    // The N04 engine decides a block `work + lead` before its presentation, about 496 ms after it was sent, so each
    // member's sender runs ahead of the render loop (see `playout_adapter`). A block's frame depends on the block and on
    // the source epoch that owns its position, so it is built when the sender reaches it. The presentation time it carries is on the group clock: the engine's
    // timeline and the node's clock readings share that axis.
    let timeline = CampaignTimeline {
        origin_ns: CAMPAIGN_ORIGIN_NS,
        horizon_ns: playout_horizon_ns,
        offset_ns: block_offset_ns,
    };
    for blk_idx in 0..total_blocks {
        let start_frame = blk_idx * (FRAMES_PER_BLOCK as u64);
        let send_time_ns = block_offset_ns(blk_idx);
        let mut presented_true = Vec::with_capacity(nodes.len());
        // A source change is decided here, at the start of the iteration: the sender is ~93 blocks ahead of this block, and
        // every block it has not sent yet belongs to the new program.
        if let Some(switch) = scenario.source_switch
            && switch.block == blk_idx
        {
            let cutover =
                execute_source_switch(switch, total_blocks, &session, &mut desk, &mut nodes)?;
            if matches!(fault, Some(OutputFault::ReplacedSourceKeepsPublishing)) {
                stale_publisher_from = Some(cutover);
                sink.emit_critical(fault_injected_event(
                    seed,
                    blk_idx,
                    send_time_ns,
                    &session,
                    fault,
                ));
            }
        }
        // Volume steps of this block run before anything reads the session's gain, after any source change, so a step and a
        // source change at the same block meet in that order.
        if let Some(volume) = volume_desk.as_mut() {
            volume.run_block(
                blk_idx,
                CAMPAIGN_ORIGIN_NS + block_offset_ns(blk_idx),
                &mut session,
            )?;
        }
        let frame_for = |blk: u64| {
            frame_of(
                &timeline,
                scenario.signal,
                blk,
                desk.program.owner_at(blk).epoch.get(),
            )
        };
        let stale_frame = |blk: u64| {
            frame_of(
                &timeline,
                scenario.signal,
                blk,
                desk.program
                    .replaced_at(blk)
                    .map_or(0, |entry| entry.epoch.get()),
            )
        };
        // The source arbiter's gate: may the owner (or the replaced adapter, if it kept publishing) publish this block?
        let gate = |replaced: bool, blk: u64| -> Result<(), String> {
            let entry = if replaced {
                desk.program.replaced_at(blk)
            } else {
                Some(desk.program.owner_at(blk))
            };
            let Some(entry) = entry else {
                return Err("NO_REPLACED_ADAPTER".to_string());
            };
            desk.arbiter
                .check_publish(&session, &entry.source, entry.epoch)
                .map_err(|e| e.code().to_string())
        };
        for (member_id, node) in &mut nodes {
            // A fault planted on this member's link, and one on its own clock (which takes effect from this block on).
            let link_fault = match fault {
                Some(OutputFault::LateBlock {
                    member_id: faulty,
                    block,
                }) if faulty == member_id.as_str() => Some(LinkFault::Late { block }),
                Some(OutputFault::ReorderedPair {
                    member_id: faulty,
                    block,
                }) if faulty == member_id.as_str() => Some(LinkFault::SwapArrivals { block }),
                Some(OutputFault::StaleEpochPacket {
                    member_id: faulty,
                    block,
                }) if faulty == member_id.as_str() => Some(LinkFault::StaleEpoch { block }),
                Some(OutputFault::StaleStreamDatagram {
                    member_id: faulty,
                    block,
                }) if faulty == member_id.as_str() => Some(LinkFault::StaleStream { block }),
                _ => None,
            };
            let clock_leap = match fault {
                Some(OutputFault::ClockLeap {
                    member_id: faulty,
                    block,
                    delta_ns,
                }) if faulty == member_id.as_str() && block == blk_idx => Some(delta_ns),
                _ => None,
            };
            if clock_leap.is_some()
                || matches!(
                    link_fault,
                    Some(
                        LinkFault::Late { block }
                            | LinkFault::SwapArrivals { block }
                            | LinkFault::StaleEpoch { block }
                            | LinkFault::StaleStream { block }
                    ) if block == blk_idx
                )
            {
                sink.emit_critical(fault_injected_event(
                    seed,
                    blk_idx,
                    send_time_ns,
                    &session,
                    fault,
                ));
            }
            if let Some(delta_ns) = clock_leap {
                node.sim_clock.local0_ns = node
                    .sim_clock
                    .local0_ns
                    .checked_add(delta_ns)
                    .ok_or_else(|| {
                        "the planted clock leap overflows the node's clock".to_string()
                    })?;
            }
            // Each member is sent the block on its own negotiated session, so the datagram is keyed for
            // that member alone. The sender advances whether or not the network delivers the block, as
            // a real sender does. A member with no stream is sent nothing. The engine decides this block
            // about 496 ms after it was sent, so the sender is ahead of the render loop: it sends, in
            // block order, every block sent before this one is decided (`playout_adapter`). A refusal by
            // the receiver is a defect in the framing or the harness, never ordinary loss: it fails the
            // campaign. A packet that is merely late is a different matter: the engine refuses it and
            // play-out conceals.
            let streaming = node.coordinator_sender.is_some();
            if let (Some(sender), Some(receiver)) =
                (node.coordinator_sender.as_mut(), node.receiver.as_mut())
            {
                let schedule = schedules.get_mut(member_id).unwrap();
                node.playout.send_until(
                    &mut SendLink {
                        member_id,
                        sender,
                        receiver,
                        schedule,
                        fault: link_fault,
                        previous: node.previous_epoch.as_mut(),
                        replaced: node.replaced_sender.as_mut(),
                        publish: Some(Publish {
                            stale_from: stale_publisher_from,
                            stale_frame: &stale_frame,
                            gate: &gate,
                        }),
                    },
                    timeline.decision_true_ns(blk_idx),
                    total_blocks,
                    &timeline,
                    &frame_for,
                )?;
            }

            let gain = session
                .effective_member_gain(member_id)
                .map_err(|e| e.to_string())?;
            node.dsp.set_volume_gain(gain);
            node.shadow_dsp.set_volume_gain(gain);

            // The audible gate: N03's answer for this block's presentation instant.
            let gate = node.gate_block(blk_idx);
            // A member with no stream has nothing to play and nothing to conceal. Otherwise the N04 engine
            // decides this block from what has arrived by now, on the node's own clock.
            let played = if streaming {
                Some(
                    node.playout
                        .decide_block(blk_idx, &timeline, &node.clock, &node.sim_clock)
                        .map_err(|e| format!("member {member_id}: {e}"))?,
                )
            } else {
                None
            };
            let authentic = matches!(played, Some(Played::Authentic(_)));
            let stereo_in = match played {
                None => StereoAudioBlock::silence(start_frame),
                Some(Played::Authentic(block)) => {
                    // Which program's audio sounded, read from the bytes, and whose position it is: they must agree. The
                    // engine has already shown that these are the bytes the sender sent; this shows they are the owner's.
                    let owner = desk.program.owner_at(blk_idx).epoch.get();
                    let heard = desk
                        .program
                        .entries
                        .iter()
                        .map(|entry| entry.epoch.get())
                        .find(|&epoch| {
                            heard_block(scenario.signal, blk_idx, epoch).is_ok_and(|b| b == block)
                        });
                    if heard != Some(owner) {
                        return Err(format!(
                            "member {member_id}: block {blk_idx} played the audio of source epoch {heard:?}, but source epoch {owner} owns that position"
                        ));
                    }
                    *node.source_blocks.entry(owner).or_default() += 1;
                    node.authentic_blocks += 1;
                    block
                }
                Some(Played::Concealed(block)) => {
                    node.concealed_blocks += 1;
                    block
                }
                // Missing blocks beyond what the engine conceals are silence; the legacy buffer counted those as
                // concealed too, and so does this.
                Some(Played::Silent(Silence::Gap)) => {
                    node.concealed_blocks += 1;
                    StereoAudioBlock::silence(start_frame)
                }
                // Silence the engine decided for another reason, and a position whose block the clock could not
                // decide: both are in the member's playout report, and neither is a block that sounds.
                Some(Played::Silent(_) | Played::NoDecision) => {
                    StereoAudioBlock::silence(start_frame)
                }
            };
            // A block the gate does not let sound is replaced by silence at the same stream position, so the
            // continuity and shadow oracles still judge contiguous frames. So is every block of a member
            // whose negotiation was refused.
            let stereo_in = if gate.audible() && streaming {
                node.audible_blocks += 1;
                if authentic {
                    node.audible_authentic_blocks += 1;
                }
                stereo_in
            } else {
                node.muted_blocks += 1;
                if !streaming {
                    node.stream_refused_blocks += 1;
                }
                StereoAudioBlock::silence(start_frame)
            };

            // Planted defect: the member's audio never reaches either DSP, but the block is still counted as having sounded.
            let stereo_in = if let Some(OutputFault::SilentInput { member_id: faulty }) = fault
                && faulty == member_id.as_str()
                && gate.audible()
                && streaming
            {
                if blk_idx == 0 {
                    sink.emit_critical(fault_injected_event(
                        seed,
                        blk_idx,
                        send_time_ns,
                        &session,
                        fault,
                    ));
                }
                StereoAudioBlock::silence(start_frame)
            } else {
                stereo_in
            };

            let resampled = node
                .resampler
                .process_stereo(&stereo_in, node.drift_ppm)
                .map_err(|e| e.to_string())?;
            let mut hw_out = node.dsp.render_block(&resampled);
            let shadow_out = node.shadow_dsp.render_block(&resampled);

            if let Some(OutputFault::DropFinalBlock { member_id: faulty }) = fault
                && faulty == member_id.as_str()
                && blk_idx + 1 == total_blocks
            {
                // Planted defect: this member's final block never reaches the output.
                sink.emit_critical(fault_injected_event(
                    seed,
                    blk_idx,
                    send_time_ns,
                    &session,
                    fault,
                ));
                continue;
            }
            if let Some(OutputFault::CorruptSample {
                member_id: faulty,
                block,
                last_channel,
                offset,
            }) = fault
                && faulty == member_id.as_str()
                && block == blk_idx
            {
                sink.emit_critical(fault_injected_event(
                    seed,
                    blk_idx,
                    send_time_ns,
                    &session,
                    fault,
                ));
                let channel = if last_channel {
                    hw_out.channel_samples.len().saturating_sub(1)
                } else {
                    0
                };
                let sample = hw_out
                    .channel_samples
                    .get_mut(channel)
                    .and_then(|samples| samples.get_mut(offset))
                    .ok_or_else(|| "planted output fault is out of range".to_string())?;
                *sample = sample.wrapping_add(1);
            }

            // Every channel is judged against the shadow render of the same input: continuity,
            // block shape and per-sample content. A fault in any channel is therefore visible.
            if node.continuity_oracles.len() != hw_out.channel_samples.len()
                || shadow_out.channel_samples.len() != hw_out.channel_samples.len()
            {
                return Err(format!(
                    "member {member_id}: {} oracle channels, {} rendered channels, {} shadow channels",
                    node.continuity_oracles.len(),
                    hw_out.channel_samples.len(),
                    shadow_out.channel_samples.len()
                ));
            }
            for (channel, oracle) in node.continuity_oracles.iter_mut().enumerate() {
                let live = &hw_out.channel_samples[channel][..hw_out.frames];
                let reference = ShadowReference {
                    start_frame: hw_out.start_frame,
                    samples: &shadow_out.channel_samples[channel][..hw_out.frames],
                };
                oracle
                    .observe_block_against(
                        hw_out.start_frame,
                        hw_out.frames as u64,
                        live,
                        &reference,
                        0,
                    )
                    .map_err(|e| format!("member {member_id} channel {channel}: {e}"))?;
                node.handoff_checked_samples += live.len() as u64;
            }
            for samples in &hw_out.channel_samples {
                node.output_digest =
                    fnv1a_extend_samples(node.output_digest, &samples[..hw_out.frames]);
            }
            if hw_out
                .channel_samples
                .iter()
                .any(|samples| samples[..hw_out.frames].iter().any(|&sample| sample != 0))
            {
                node.rendered_nonzero_blocks += 1;
            }

            let lease = node.hal.submit_dma_block().map_err(|e| e.to_string())?;
            lease.complete();
            node.rendered_blocks += 1;

            // Where this node really presents the block: its own transform's local instant, mapped back to true time.
            if streaming && let Some(true_ns) = node.presented_true_ns(&gate) {
                presented_true.push(true_ns);
            }
        }

        if skew_participants >= 2 && presented_true.len() == skew_participants {
            skew_measured_blocks += 1;
        } else {
            skew_unmeasured_blocks += 1;
        }
        if let (Some(&min_ns), Some(&max_ns)) =
            (presented_true.iter().min(), presented_true.iter().max())
        {
            let skew_us = (max_ns - min_ns) / 1_000;
            max_inter_speaker_skew_us = max_inter_speaker_skew_us.max(skew_us);
        }

        // Bounded, non-blocking diagnostics from the render path: one small event per block. The
        // result is deliberately ignored; a dropped event is counted by the sink and nothing in
        // the render path depends on whether it was stored.
        sink.try_emit(DiagnosticEvent {
            schema_version: String::new(),
            timestamp_mono_ns: send_time_ns,
            run_id: format!("vh-seed-{seed}"),
            case_id: "Q01-virtual-house".to_string(),
            correlation_id: format!("blk-{blk_idx}"),
            member_id: "house".to_string(),
            group_id: session.group_id.clone(),
            source_epoch: session.current_epoch,
            state_revision: session.state_revision,
            event_kind: "block_rendered".to_string(),
            message: format!("block {blk_idx} rendered"),
            queue_depth: nodes.len(),
            latency_us: max_inter_speaker_skew_us,
            fault: None,
            cause: None,
        });
    }

    // What the arbiter ended with, before the fencing probe moves the group to a newer epoch.
    let end_view = desk.arbiter.view(&session);
    desk.report.final_epoch = end_view.epoch.get();
    desk.report.final_owner = end_view.owner.map(|owner| owner.to_string());
    if let Some(OutputFault::StaleStreamDatagram { member_id, block }) = fault {
        // A planted datagram that was never refused proves nothing: it was not sent (is the block at or after the cutover?).
        let refused = nodes
            .get(member_id)
            .map(|node| node.playout.report().wrong_stream_refused_at_receiver);
        if refused != Some(1) {
            return Err(format!(
                "the planted previous-stream datagram for {member_id} block {block} was refused {refused:?} times by its receiver, not once"
            ));
        }
    }

    // Tail check: the harness streamed `total_blocks` blocks, so every channel of every member must
    // have produced exactly that many frames. A dropped final block shows up here and nowhere
    // earlier. (A zero-block campaign makes no claim, so there is nothing to finalize.)
    if total_blocks > 0 {
        let expected_total_frames = total_blocks * (FRAMES_PER_BLOCK as u64);
        for (id, node) in &nodes {
            for (channel, oracle) in node.continuity_oracles.iter().enumerate() {
                oracle
                    .finalize(expected_total_frames)
                    .map_err(|e| format!("member {id} channel {channel}: {e}"))?;
            }
        }
    }

    // Each member's engine decided every block position exactly once (a position the clock could not decide is
    // counted, and decided as overdue later), and its decision counters add up to its cursor.
    for (id, node) in &nodes {
        node.playout
            .finish(total_blocks)
            .map_err(|e| format!("member {id}: {e}"))?;
    }

    // With a source whose channels do not cancel, a member that sounded audio it was sent and rendered only zeros has lost its
    // output somewhere the other oracles cannot see (both DSPs are handed the same input). Under the original opposed source this is
    // not asked: a member whose every channel comes from the mono mix legitimately renders zeros (`docs/contracts/q01.md`, limit 1).
    // A member the gate never let sound is not asked either.
    if scenario.signal == SourceSignal::Asymmetric {
        for (id, node) in &nodes {
            if node.audible_authentic_blocks > 0 && node.rendered_nonzero_blocks == 0 {
                return Err(format!(
                    "member_rendered_silence: {id}: {} authentic blocks sounded and every sample it rendered is zero",
                    node.audible_authentic_blocks
                ));
            }
        }
    }

    // The volume plan is judged here, before the skeleton SOAP call and the fencing probe below change the group volume.
    let volume_report = match volume_desk.as_mut() {
        Some(volume) => Some(volume.finish(&session)?),
        None => None,
    };

    // Exercise fsonos SOAP group volume update
    match handle_fsonos_soap(
        &mut session,
        FsonosSoapRequest::SetGroupVolume {
            epoch,
            command_seq: cmd_seq,
            desired_volume: 65,
        },
    )
    .map_err(|e| e.to_string())?
    {
        FsonosSoapResponse::StateUpdated { .. } => {}
        other => return Err(format!("unexpected SOAP response: {other:?}")),
    }

    // Exercise cooperative AirPlay 2 / YouTube video lip-sync evaluation
    let mut airplay = AirPlay2ReceiverState {
        receiver_name: "Kitchen S12".to_string(),
        paired: true,
        active_stream_kind: None,
        last_video_sync: None,
    };
    let video_eval = airplay
        .evaluate_youtube_video_sync(
            &LatencyLedger {
                network_ingress_us: 2_500,
                jitter_buffer_target_us: 45_000,
                dsp_block_period_us: 5_333,
                dma_queue_us: 5_333,
                calibrated_dac_delay_us: 1_400,
                calibration_uncertainty_us: 200,
            },
            58_000,
        )
        .map_err(|e| e.to_string())?;

    // The campaign summary is critical evidence: if it cannot be stored the report must say so
    // (`evidence_complete`), not quietly look like a clean run.
    sink.emit_critical(DiagnosticEvent {
        schema_version: String::new(),
        timestamp_mono_ns: block_offset_ns(total_blocks),
        run_id: format!("vh-seed-{seed}"),
        case_id: "Q01-virtual-house".to_string(),
        correlation_id: "corr-vh-1".to_string(),
        member_id: "spk-kitchen-s12".to_string(),
        group_id: session.group_id.clone(),
        source_epoch: session.current_epoch,
        state_revision: session.state_revision,
        event_kind: "campaign_complete".to_string(),
        message: "virtual house multi-room simulation finished".to_string(),
        queue_depth: 0,
        latency_us: max_inter_speaker_skew_us,
        fault: fault.map(describe_fault),
        cause: None,
    });

    // Fencing probe last: it advances the session to a newer epoch, which the steps above must
    // not see.
    exercise_fencing(&mut session, &mut audit, epoch)?;

    let mut member_stats = BTreeMap::new();
    for (id, node) in &nodes {
        let hal_t = node.hal.telemetry();
        member_stats.insert(
            id.clone(),
            MemberSimulationStats {
                profile_id: node.board.profile_id.clone(),
                legacy_sw_gen: node.board.legacy_sw_gen_hint,
                hardware_channels: node.board.hardware_channels,
                rendered_blocks: node.rendered_blocks,
                authentic_blocks: node.authentic_blocks,
                concealed_blocks: node.concealed_blocks,
                audible_blocks: node.audible_blocks,
                muted_blocks: node.muted_blocks,
                stream: node.stream.clone(),
                stream_refused_blocks: node.stream_refused_blocks,
                verified_continuous_frames: node
                    .continuity_oracles
                    .iter()
                    .map(SampleContinuityOracle::verified_frames)
                    .min()
                    .unwrap_or(0),
                handoff_checked_samples: node.handoff_checked_samples,
                quarantined_dma_slots: hal_t.quarantined_dma_slots,
                readiness: node.readiness.clone(),
                clock_log: node.clock_log.summary(&node.clock),
                playout: node.playout.report(),
                source_blocks: node.source_blocks.clone(),
                output_fnv1a64: node.output_digest,
                audible_authentic_blocks: node.audible_authentic_blocks,
                rendered_nonzero_blocks: node.rendered_nonzero_blocks,
            },
        );
    }

    Ok(VirtualHouseReport {
        simulation_only: true,
        fencing: audit.stats,
        group_id: session.group_id.clone(),
        unified_mixed_s1_s2: session.is_unified_mixed_generation_group(),
        total_blocks_streamed: total_blocks,
        max_inter_speaker_skew_us,
        skew_measured_blocks,
        skew_unmeasured_blocks,
        skew_participants,
        within_2ms_skew_target: skew_measured_blocks > 0
            && skew_unmeasured_blocks == 0
            && max_inter_speaker_skew_us <= 2_000,
        video_sync_residual_us: video_eval.residual_av_skew_us,
        video_sync_within_40ms_gate: video_eval.within_40ms_p99_gate,
        dropped_log_events: sink.dropped_event_count(),
        evidence_complete: sink.is_evidence_complete(),
        source: desk.report,
        volume: volume_report,
        members: member_stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use franken_stream::StreamError;

    #[test]
    fn virtual_house_streams_mixed_s1_s2_fleet_with_zero_output_discontinuities() {
        let report = run_virtual_house_campaign(0x2026_1104, 200).unwrap();
        assert!(report.unified_mixed_s1_s2);
        assert!(report.within_2ms_skew_target);
        assert!(report.video_sync_within_40ms_gate);
        assert_eq!(report.members.len(), 5);
        for (id, stats) in &report.members {
            assert_eq!(stats.rendered_blocks, 200, "member {id} missed blocks");
            assert_eq!(
                stats.verified_continuous_frames,
                200 * (FRAMES_PER_BLOCK as u64),
                "member {id} had frame discontinuity"
            );
            assert_eq!(stats.quarantined_dma_slots, 0);
            assert_eq!(stats.readiness, SpeakerReadinessState::ReadySynchronized);
        }
    }

    const SEED: u64 = 0x2026_1104;

    fn fixture_board(model: &str) -> BoardProfile {
        synthetic_test_fixture_catalog()
            .iter()
            .find(|p| p.model_number == model)
            .expect("fixture model present")
            .clone()
    }

    fn bring_up(plan: BringUpPlan) -> Result<VirtualSpeakerNode, String> {
        VirtualSpeakerNode::bring_up_with_plan("spk-test", fixture_board("S5"), 1, plan)
    }

    fn refusal(plan: BringUpPlan) -> String {
        match bring_up(plan) {
            Ok(_) => panic!("bring-up must have been refused"),
            Err(e) => e,
        }
    }

    #[test]
    fn nominal_bring_up_is_observed_and_reaches_ready() {
        let node = bring_up(BringUpPlan::NOMINAL).expect("nominal bring-up is permitted");
        assert_eq!(node.readiness, SpeakerReadinessState::ReadySynchronized);
        assert!(node.readiness_oracle.is_announced());
        let hal = node.hal.telemetry();
        assert!(!hal.hardware_muted);
        assert_eq!(hal.primed_silence_blocks, REQUIRED_SILENCE_BLOCKS);
        assert_eq!(
            node.continuity_oracles.len(),
            usize::from(node.board.hardware_channels)
        );
    }

    #[test]
    fn canary_premature_unmute_through_a_weakened_driver_threshold_is_refused() {
        // The simulated driver is configured to unmute after one silence block; the harness
        // requires two. The HAL's own guard cannot object, so only the oracle can.
        let weakened = BringUpPlan {
            hal_required_silence_blocks: 1,
            silence_blocks_primed: 1,
            ..BringUpPlan::NOMINAL
        };
        let err = refusal(weakened);
        assert!(err.contains("premature unmute"), "{err}");
        // Paired positive: the same sequence at the required threshold is accepted.
        assert!(bring_up(BringUpPlan::NOMINAL).is_ok());
    }

    #[test]
    fn the_hal_still_refuses_an_unmute_before_priming_on_its_own() {
        let unprimed = BringUpPlan {
            silence_blocks_primed: 0,
            ..BringUpPlan::NOMINAL
        };
        let err = refusal(unprimed);
        assert!(err.contains("HAL unmute failed"), "{err}");
    }

    #[test]
    fn canary_false_ready_on_an_unlocked_clock_is_refused_even_when_the_node_skips_its_own_gate() {
        // N03 locks on its fourth accepted exchange, so 0..=3 exchanges are an unlocked clock.
        for exchanges in [0u32, 1, 2, 3] {
            let gated = BringUpPlan {
                clock_exchanges: exchanges,
                ..BringUpPlan::NOMINAL
            };
            let err = refusal(gated);
            assert!(err.contains("clock is not locked"), "{err}");

            let ungated = BringUpPlan {
                clock_exchanges: exchanges,
                bypass_own_clock_gate: true,
                ..BringUpPlan::NOMINAL
            };
            let err = refusal(ungated);
            assert!(err.contains("clock_locked"), "{err}");
        }
        // Paired positive at the boundary: four exchanges lock the clock.
        let four = BringUpPlan {
            clock_exchanges: 4,
            ..BringUpPlan::NOMINAL
        };
        assert!(bring_up(four).is_ok());
    }

    #[test]
    fn harness_oracle_spec_for_the_clock_is_pinned_to_the_n03_configuration() {
        let cfg = GroupClockConfig::standard().expect("standard configuration");
        assert_eq!(CLOCK_LOCK_MIN_SAMPLES, cfg.min_probes_for_lock);
        assert_eq!(
            CLOCK_LOCK_MAX_UNCERTAINTY_US * 1_000,
            cfg.lock_uncertainty_ns
        );
        assert_eq!(
            CLOCK_EXCHANGES, cfg.min_probes_for_lock,
            "nominal bring-up sends exactly the lock count"
        );
    }

    /// A clock with no skew and an offset of whole microseconds: every timestamp of the bring-up exchanges is
    /// exact, so N03's arithmetic can be checked against values the independent reference produced.
    const EXACT_CLOCK: SimNodeClock = SimNodeClock {
        skew_ppb: 0,
        local0_ns: 7_000_000_000,
    };

    fn exact_plan() -> BringUpPlan {
        BringUpPlan {
            sim_clock: Some(EXACT_CLOCK),
            ..BringUpPlan::NOMINAL
        }
    }

    /// The frame nearest to an offset from the stream's first sample, at 48 kHz.
    fn nearest_frame(offset_ns: u64) -> u64 {
        u64::try_from((u128::from(offset_ns) * 48_000 + 500_000_000) / 1_000_000_000)
            .expect("a frame count fits")
    }

    #[test]
    fn a_blocks_start_maps_back_to_its_scheduled_frame_however_long_the_campaign_runs() {
        let first = VirtualSpeakerNode::block_pts_group_ns(0);
        let check = |blk: u64| {
            let offset = VirtualSpeakerNode::block_pts_group_ns(blk) - first;
            assert_eq!(offset, block_offset_ns(blk), "block {blk}");
            assert_eq!(
                nearest_frame(offset),
                blk * (FRAMES_PER_BLOCK as u64),
                "block {blk}"
            );
        };
        // every block of a 5.5 minute campaign and the stretch after it, then a thinner walk out to about 15 hours
        for blk in 0..=70_000_u64 {
            check(blk);
        }
        for blk in (70_000..10_000_000_u64).step_by(4_999) {
            check(blk);
        }
        for blk in [10_000_001, 123_456_789, 1_000_000_007] {
            check(blk);
        }
        // consecutive blocks are 5 333 333 or 5 333 334 ns apart: the period is not a whole number of nanoseconds
        for blk in 0..1_000_u64 {
            let step = block_offset_ns(blk + 1) - block_offset_ns(blk);
            assert!(
                (5_333_333..=5_333_334).contains(&step),
                "block {blk}: {step}"
            );
        }
    }

    #[test]
    fn the_old_mapping_a_block_index_times_the_rounded_period_misses_its_frame_and_the_exact_one_does_not()
     {
        // The plant: multiplying the index by the rounded period. It is off by one frame at block 62 500 and already
        // rounds to the wrong frame at 31 251; the floor of the same product is wrong from block 1.
        let planted = |blk: u64| nearest_frame(blk * BLOCK_PERIOD_NS);
        for blk in [31_251_u64, 62_500, 62_501, 200_000] {
            let scheduled = blk * (FRAMES_PER_BLOCK as u64);
            assert_ne!(planted(blk), scheduled, "the planted mapping, block {blk}");
            assert_eq!(
                nearest_frame(block_offset_ns(blk)),
                scheduled,
                "the exact mapping, block {blk}"
            );
        }
        assert_eq!(
            blk_floor_frame(1),
            255,
            "the floor of the planted product is wrong from block 1"
        );
        // the planted mapping is right while the error is under half a frame, which is why short runs never saw it
        for blk in [0_u64, 1, 100, 31_250] {
            assert_eq!(planted(blk), blk * (FRAMES_PER_BLOCK as u64), "block {blk}");
        }

        fn blk_floor_frame(blk: u64) -> u64 {
            blk * BLOCK_PERIOD_NS * 48_000 / 1_000_000_000
        }
    }

    #[test]
    fn a_locked_node_keeps_presenting_the_scheduled_frame_past_62_500_blocks() {
        let mut node = bring_up(exact_plan()).expect("bring-up");
        let first_pts = VirtualSpeakerNode::block_pts_group_ns(0);
        let (mut audible, mut audible_after) = (0_u64, 0_u64);
        for blk in 0..=66_000_u64 {
            let gate = node.gate_block(blk);
            let Some(true_ns) = node.presented_true_ns(&gate) else {
                continue;
            };
            audible += 1;
            if blk > 62_500 {
                audible_after += 1;
            }
            // The instant the node presents the block is within the 1 us clock's resolution of the stream's own
            // presentation time, which is a twentieth of a frame: the nearest frame is the scheduled one.
            assert_eq!(
                nearest_frame(true_ns - first_pts),
                blk * (FRAMES_PER_BLOCK as u64),
                "block {blk}"
            );
        }
        assert!(
            audible > 0 && audible_after >= 1_000,
            "{audible} audible, {audible_after} after block 62 500"
        );
    }

    #[test]
    fn a_locked_node_sounds_at_the_admitted_start_and_presents_the_scheduled_frame_at_the_reference_instant()
     {
        let mut node = bring_up(exact_plan()).expect("bring-up");
        // Reference values: tests/n03/reference.py `run_script` on this exact script (board S5: output delay 1.85 ms,
        // calibration uncertainty 150 us; four 800 us exchanges at true 10, 20, 30 and 40 ms on a clock that reads
        // true time + 7 s; an admit at local 7.042 s of a start at group 750 ms).
        let plan = node.admitted_plan.expect("admitted at bring-up");
        assert_eq!(plan.start_group_ns, 750_000_000);
        assert_eq!(plan.start_local_ns, 7_748_150_000);
        assert_eq!(plan.deadline_local_ns, 7_648_150_000);
        assert_eq!(plan.uncertainty_at_start_ns, 621_773);
        assert_eq!(plan.valid_until_local_ns, 21_530_425_001);
        assert_eq!(plan.binding.code(), "Uncertainty");

        let first_pts = VirtualSpeakerNode::block_pts_group_ns(0);
        assert_eq!(first_pts, plan.start_group_ns);
        for blk in 0..100_u64 {
            let gate = node.gate_block(blk);
            assert_eq!(gate.output, Output::Audible, "block {blk}");
            let pts = VirtualSpeakerNode::block_pts_group_ns(blk);
            let true_ns = node
                .presented_true_ns(&gate)
                .expect("a sounding block has a presentation instant");
            if blk < PROBE_EVERY_BLOCKS {
                // Before the first in-campaign exchange the transform is the bring-up one: local = group + 7 s
                // exactly, so the presentation instant is exact, and in true time it falls within one tick of the
                // 1 us clock after the stream's own presentation time.
                assert_eq!(
                    gate.presented_local_ns,
                    Some(pts + 7_000_000_000),
                    "block {blk}"
                );
                assert!(
                    (pts..pts + 1_000).contains(&true_ns),
                    "block {blk}: {true_ns} vs {pts}"
                );
            } else {
                // Later exchanges start at times that are not whole microseconds, so the anchor carries the 1 us
                // clock's floor: the instant is right to within that.
                assert!(
                    true_ns.abs_diff(pts) < 2_000,
                    "block {blk}: {true_ns} vs {pts}"
                );
            }
            // The presented sample position: the nearest frame to that group time is the block's first frame, exactly
            // (a block's start is rounded to the nearest nanosecond, which is 0.00002 frame).
            let frame_at = nearest_frame(pts - first_pts);
            let block_frame = blk * (FRAMES_PER_BLOCK as u64);
            assert_eq!(frame_at, block_frame, "block {blk}");
        }
    }

    #[test]
    fn nothing_sounds_before_the_admitted_start_and_the_first_sounding_block_is_the_scheduled_one()
    {
        let plan = BringUpPlan {
            first_start_block: Some(10),
            ..exact_plan()
        };
        let mut node = bring_up(plan).expect("bring-up");
        let mut first_audible = None;
        for blk in 0..30_u64 {
            let gate = node.gate_block(blk);
            if gate.audible() {
                first_audible.get_or_insert(blk);
            } else {
                assert!(
                    matches!(gate.output, Output::Armed { .. }),
                    "block {blk}: {:?}",
                    gate.output
                );
                assert!(node.presented_true_ns(&gate).is_none(), "block {blk}");
            }
            if blk == 9 {
                // Exactly one block period (5 333 333 ns) before the start, less the S5 board's 1.85 ms output delay.
                assert_eq!(
                    gate.output,
                    Output::Armed {
                        starts_in_ns: 5_333_333 - 1_850_000
                    }
                );
            }
        }
        assert_eq!(first_audible, Some(10));
        assert_eq!(
            10 * (FRAMES_PER_BLOCK as u64),
            2_560,
            "the first sounding frame"
        );
    }

    /// Step the node's own clock at block 40 by `delta_ns` and run 260 blocks.
    fn run_with_clock_step(delta_ns: i64) -> (VirtualSpeakerNode, Vec<BlockGate>) {
        let clock = SimNodeClock {
            skew_ppb: 0,
            local0_ns: 40_000_000_000,
        };
        let plan = BringUpPlan {
            sim_clock: Some(clock),
            ..BringUpPlan::NOMINAL
        };
        let mut node = bring_up(plan).expect("bring-up");
        let mut gates = Vec::new();
        for blk in 0..260_u64 {
            if blk == 40 {
                node.sim_clock.local0_ns = node
                    .sim_clock
                    .local0_ns
                    .checked_add_signed(delta_ns)
                    .expect("the clock stays positive");
            }
            gates.push(node.gate_block(blk));
        }
        (node, gates)
    }

    /// The shared shape of both clock-step cases: sounding until the step, muted from `first_muted` until a relock
    /// (the reset needs `min_probes_for_lock` accepted exchanges, one per probe interval, after the probe that found
    /// it) and a fresh admission, then sounding again to the end at a block boundary of the stream.
    fn assert_mutes_and_resumes(
        node: &VirtualSpeakerNode,
        gates: &[BlockGate],
        first_muted: usize,
    ) {
        let every = PROBE_EVERY_BLOCKS as usize;
        assert!(
            gates[..40].iter().all(BlockGate::audible),
            "sounding until the step"
        );
        assert_eq!(gates.iter().position(|g| !g.audible()), Some(first_muted));
        let probe_after_step = (40 / every + 1) * every;
        let resume = probe_after_step + (CLOCK_LOCK_MIN_SAMPLES as usize) * every;
        assert!(
            gates[first_muted..resume].iter().all(|g| !g.audible()),
            "muted from {first_muted} until the relock at {resume}"
        );
        assert!(
            gates[resume..].iter().all(BlockGate::audible),
            "sounding again from the new admitted start"
        );
        let plan = node.admitted_plan.expect("re-admitted");
        assert_eq!(
            plan.start_group_ns,
            VirtualSpeakerNode::block_pts_group_ns(resume as u64),
            "the new start is the first block presented after the relock"
        );
        for (blk, gate) in gates.iter().enumerate().skip(resume) {
            let ideal = VirtualSpeakerNode::block_pts_group_ns(blk as u64);
            let true_ns = node.presented_true_ns(gate).expect("sounding");
            assert!(
                true_ns.abs_diff(ideal) < 2_000,
                "block {blk}: {true_ns} vs {ideal}"
            );
        }
        assert_eq!(node.clock.stats().resets, 1, "exactly one reset");
    }

    #[test]
    fn a_suspend_mid_stream_mutes_within_one_probe_and_a_relock_resumes_at_a_new_admitted_start() {
        // The monotonic clock loses 30 s at block 40 (a suspend): the node cannot see it until its next exchange
        // (block 64), where the local clock is found to have gone backwards.
        let (node, gates) = run_with_clock_step(-30_000_000_000);
        assert_mutes_and_resumes(&node, &gates, 64);
        assert_eq!(
            node.clock
                .stats()
                .rejected(ProbeReject::LocalClockRegression),
            1
        );
    }

    #[test]
    fn a_leap_forward_mid_stream_mutes_at_once_and_a_relock_resumes_at_a_new_admitted_start() {
        // The clock reads 30 s more at block 40: the last exchange is now far older than the freshness window, so
        // the node mutes without waiting for a probe; the next exchange (block 64) then finds the offset step.
        let (node, gates) = run_with_clock_step(30_000_000_000);
        assert_mutes_and_resumes(&node, &gates, 40);
        assert_eq!(node.clock.stats().rejected(ProbeReject::Discontinuity), 1);
    }

    #[test]
    fn an_unadmitted_node_never_sounds_and_admitting_it_makes_it_sound_at_the_start() {
        let plan = BringUpPlan {
            first_start_block: None,
            auto_admit: false,
            ..exact_plan()
        };
        let mut node = bring_up(plan).expect("bring-up");
        assert!(node.admitted_plan.is_none());
        for blk in 0..40_u64 {
            let gate = node.gate_block(blk);
            assert_eq!(
                gate.output,
                Output::Muted(MuteReason::NotAdmitted),
                "block {blk}"
            );
            assert!(node.presented_true_ns(&gate).is_none(), "block {blk}");
        }
        // Paired positive: the same node, admitted at block 45, is armed until then and sounds from there on.
        let asked_at = CAMPAIGN_ORIGIN_NS + 40 * BLOCK_PERIOD_NS;
        node.admit_start_at_block(45, asked_at).expect("admitted");
        for blk in 40..60_u64 {
            let gate = node.gate_block(blk);
            assert_eq!(gate.audible(), blk >= 45, "block {blk}: {:?}", gate.output);
        }
    }

    #[test]
    fn unsolicited_replayed_stale_and_wrong_leader_probes_change_nothing_and_never_produce_audio() {
        let mut node = bring_up(exact_plan()).expect("bring-up");
        // A genuine exchange, recorded and delivered once.
        let (resp, t4_local) = sim_probe(&mut node.clock, &node.sim_clock, 150_000_000);
        node.clock
            .on_response(resp, t4_local)
            .expect("genuine exchange");
        let accepted = node.clock.stats().accepted;
        let attacks = [
            (resp, ProbeReject::UnsolicitedOrReplayed),
            (
                ProbeResponse {
                    epoch: resp.epoch - 1,
                    ..resp
                },
                ProbeReject::StaleEpoch,
            ),
            (
                ProbeResponse {
                    epoch: resp.epoch + 1,
                    ..resp
                },
                ProbeReject::FutureEpoch,
            ),
            (
                ProbeResponse {
                    leader: COORDINATOR_ID + 1,
                    ..resp
                },
                ProbeReject::UnadmittedLeader,
            ),
            (
                ProbeResponse {
                    seq: resp.seq.wrapping_add(1_000),
                    ..resp
                },
                ProbeReject::UnsolicitedOrReplayed,
            ),
        ];
        for (bad, why) in attacks {
            assert_eq!(node.clock.on_response(bad, t4_local + 1_000), Err(why));
        }
        assert_eq!(
            node.clock.stats().accepted,
            accepted,
            "no attack was accepted"
        );
        assert_eq!(node.clock.stats().rejected_total(), 5);
        // The locked, admitted node is unaffected: it sounds at the admitted start.
        assert_eq!(node.gate_block(0).output, Output::Audible);

        // A member that is not yet locked, given the same bad probes, stays silent and cannot be admitted.
        let cfg = GroupClockConfig::for_board(&node.board).expect("configuration");
        let mut lone = GroupClock::new(cfg, 1, COORDINATOR_ID, 77).expect("member");
        let start = StartSchedule {
            epoch: 1,
            start_group_ns: 750_000_000,
        };
        for (bad, _) in attacks {
            assert!(lone.on_response(bad, t4_local).is_err());
        }
        assert_eq!(lone.tick(t4_local), Output::Muted(MuteReason::NotLocked));
        assert_eq!(lone.admit(start, t4_local), Err(StartReject::NotLocked));
        // Paired positive: four genuine exchanges lock it, the start is admitted, and it sounds at the start.
        for seq in 1..=4_u64 {
            sim_exchange(&mut lone, &EXACT_CLOCK, seq * BRING_UP_EXCHANGE_SPACING_NS)
                .expect("genuine exchange");
        }
        let ready_local = EXACT_CLOCK.local(42_000_000);
        assert_eq!(lone.status(ready_local), ClockStatus::Locked);
        lone.admit(start, ready_local)
            .expect("admitted once locked");
        assert_eq!(lone.tick(EXACT_CLOCK.local(750_000_000)), Output::Audible);
    }

    #[test]
    fn each_member_and_each_boot_gets_a_different_request_base_and_a_recorded_answer_cannot_cross_a_reboot()
     {
        let ids = [
            "spk-office-s5",
            "spk-bedroom-s1",
            "spk-kitchen-s12",
            "spk-den-s3",
            "spk-living-sub",
        ];
        let mut bases = std::collections::BTreeSet::new();
        for id in ids {
            for boot in 0..2 {
                assert!(
                    bases.insert(simulated_boot_entropy(id, 1, boot)),
                    "{id} boot {boot}"
                );
            }
        }
        // The same member, the same simulated clock and the same send time on both boots: only the request base
        // differs, and that alone makes the answer recorded on the first boot useless on the second.
        let mut first = bring_up(BringUpPlan {
            boot_index: 0,
            ..exact_plan()
        })
        .expect("boot 0");
        let mut second = bring_up(BringUpPlan {
            boot_index: 1,
            ..exact_plan()
        })
        .expect("boot 1");
        let (recorded, t4_local) = sim_probe(&mut first.clock, &first.sim_clock, 150_000_000);
        let request = second.clock.next_probe(second.sim_clock.local(150_000_000));
        assert_eq!(
            request.t1_local_ns, recorded.t1_echo_ns,
            "same send time on both boots"
        );
        assert_ne!(request.seq, recorded.seq);
        assert_eq!(
            second.clock.on_response(recorded, t4_local),
            Err(ProbeReject::UnsolicitedOrReplayed)
        );
        // Paired positive: the second boot's own exchange is accepted.
        assert!(second.exchange_at(160_000_000).is_ok());
    }

    #[test]
    fn the_campaign_sounds_every_block_of_every_member_and_measures_a_skew_from_independent_clocks()
    {
        let report = run_campaign(SEED, 200, None).expect("campaign");
        for (id, stats) in &report.members {
            assert_eq!(stats.audible_blocks, 200, "member {id}");
            assert_eq!(stats.muted_blocks, 0, "member {id}");
        }
        assert!(report.within_2ms_skew_target);
        // The figure is no longer the trivial zero of five nodes that all read true time: the members' clocks differ.
        let clocks: Vec<SimNodeClock> = [
            "spk-office-s5",
            "spk-bedroom-s1",
            "spk-kitchen-s12",
            "spk-den-s3",
            "spk-living-sub",
        ]
        .iter()
        .map(|id| SimNodeClock::for_member(id))
        .collect();
        assert!(clocks.windows(2).all(|w| w[0] != w[1]));
        assert!(clocks.iter().all(|c| c.skew_ppb.abs() <= 50_000));
        assert!(report.max_inter_speaker_skew_us > 0);
    }

    #[test]
    fn campaign_checks_every_channel_against_the_shadow_render_and_is_simulation_only() {
        let report = run_campaign(SEED, 20, None).expect("clean campaign");
        assert!(report.simulation_only);
        assert_eq!(report.members.len(), 5);
        for (id, stats) in &report.members {
            assert!(stats.verified_continuous_frames > 0, "member {id}");
            assert_eq!(
                stats.handoff_checked_samples,
                stats.verified_continuous_frames * u64::from(stats.hardware_channels),
                "member {id}: every channel must have been compared"
            );
        }
    }

    #[test]
    fn canary_sample_corruption_in_any_channel_of_the_real_campaign_is_caught() {
        let clean = run_campaign(SEED, 20, None).expect("clean campaign");
        let channels = clean.members["spk-office-s5"].hardware_channels;
        assert!(
            channels > 1,
            "the fixture board must have a non-first channel"
        );
        for (last_channel, expected_channel) in [(false, 0usize), (true, usize::from(channels) - 1)]
        {
            let fault = OutputFault::CorruptSample {
                member_id: "spk-office-s5",
                block: 7,
                last_channel,
                offset: 5,
            };
            let err = run_campaign(SEED, 20, Some(fault)).expect_err("corruption must be caught");
            assert!(err.contains("spk-office-s5"), "{err}");
            assert!(
                err.contains(&format!("channel {expected_channel}:")),
                "{err}"
            );
            // Block 7 starts at frame 7 * 256; the flipped sample is 5 frames in.
            assert!(err.contains("wrong sample at frame 1797"), "{err}");
        }
    }

    #[test]
    fn canary_a_missing_final_block_is_caught_as_a_truncated_stream() {
        let fault = OutputFault::DropFinalBlock {
            member_id: "spk-bedroom-s1",
        };
        let err = run_campaign(SEED, 20, Some(fault)).expect_err("a dropped tail must be caught");
        assert!(err.contains("spk-bedroom-s1"), "{err}");
        assert!(err.contains("truncated stream"), "{err}");
        assert!(err.contains("4864 of 5120"), "{err}");
    }

    #[test]
    fn campaign_fencing_probe_drives_the_real_session_and_the_oracle_accepts_it() {
        let report = run_campaign(SEED, 20, None).expect("clean campaign");
        // 5 members x (admit + clock-locked) = 10 observed in the admit loop, then the probe:
        // a fresh command, its duplicate delivery, a new-epoch command, and a stale command.
        assert_eq!(
            report.fencing,
            FencingProbeStats {
                commands_observed: 14,
                fresh_applied: 2,
                duplicates_suppressed: 1,
                stale_rejected: 1,
                epoch_advances: 1,
            }
        );
    }

    /// Regression test for a `franken-session` defect that is now fixed. `apply_command` used to
    /// adopt a command's epoch before validating its payload, so a *rejected* command at a
    /// far-future epoch moved `current_epoch` and fenced out the legitimate coordinator. The
    /// session now adopts a newer epoch only once the command has been applied. This began life
    /// as `known_session_defect_a_rejected_command_still_adopts_its_epoch`, asserting the defect,
    /// and was inverted when the fix landed.
    #[test]
    fn a_rejected_command_does_not_adopt_its_epoch_and_cannot_fence_out_the_coordinator() {
        let mut session = UnifiedGroupSession::new("grp-regression", "coord", 1);
        let mut audit = CommandAudit::new(1);
        let ghost = |epoch: u64, command_seq: u64| FencedControlCommand {
            epoch,
            command_seq,
            payload: GroupCommandPayload::RemoveMember {
                member_id: "ghost".to_string(),
            },
        };

        // Paired positive: a rejected command at the current epoch leaves the epoch alone.
        let (_, outcome) = audit
            .deliver_new(&mut session, ghost(1, 1))
            .expect("a rejection that keeps the epoch is permitted");
        assert!(matches!(outcome, Err(SessionError::UnknownMember { .. })));
        assert_eq!(session.current_epoch, 1);

        // The formerly defective case: the same rejection at epoch 999 must not move the epoch,
        // and the oracle (which declared no such epoch) accepts the session's behaviour.
        let (_, outcome) = audit
            .deliver_new(&mut session, ghost(999, 2))
            .expect("a rejection must not move the system epoch");
        assert!(matches!(outcome, Err(SessionError::UnknownMember { .. })));
        assert_eq!(session.current_epoch, 1);

        // The real coordinator, still at epoch 1, is still obeyed.
        let legitimate = FencedControlCommand {
            epoch: 1,
            command_seq: 3,
            payload: GroupCommandPayload::SetGroupVolume {
                volume_0_to_100: 30,
            },
        };
        let (_, outcome) = audit
            .deliver_new(&mut session, legitimate)
            .expect("the coordinator's command is permitted");
        assert!(outcome.is_ok());
    }

    /// KNOWN LIMIT, owned by bead ffw-kh0 (G01). Kept as a passing characterization so it stays in
    /// the test counts. It is deliberately not `#[ignore]`d: the intended-behavior form needs an
    /// authenticated-epoch or election API that does not exist yet, and none is invented here.
    ///
    /// The session still adopts the epoch of any *valid* command and has no way to tell whether
    /// the sender was elected, so an unauthenticated command at a far-future epoch applies and
    /// fences out the real coordinator. The oracle objects because the harness never declared
    /// epoch 999.
    ///
    /// When G01 lands authenticated epoch adoption, or elections are declared to the session,
    /// invert the assertions marked FLIP so the test asserts all of:
    /// - the command is rejected with a specific `SessionError` variant, not merely some error;
    /// - the oracle accepts that rejection, so `deliver_new` returns `Ok`;
    /// - `current_epoch` is still 1, and `group_master_volume` and `state_revision` are unchanged;
    /// - a following epoch-1 command from the real coordinator is still applied.
    #[test]
    fn known_limit_a_valid_command_at_an_undeclared_epoch_is_still_applied() {
        let mut session = UnifiedGroupSession::new("grp-limit", "coord", 1);
        let mut audit = CommandAudit::new(1);
        let unelected = FencedControlCommand {
            epoch: 999,
            command_seq: 1,
            payload: GroupCommandPayload::SetGroupVolume { volume_0_to_100: 1 },
        };
        let err = audit
            .deliver_new(&mut session, unelected)
            .expect_err("the oracle must flag an epoch nobody declared"); // FLIP: expect Ok, and assert the specific rejection inside it
        assert!(err.contains("future epoch accepted"), "{err}"); // FLIP: drop
        assert_eq!(session.current_epoch, 999); // FLIP: expect 1; volume and state_revision unchanged; then an epoch-1 command still applies
    }

    fn event_kinds(sink: &BoundedDiagnosticSink) -> Vec<&str> {
        sink.events()
            .iter()
            .map(|e| e.event_kind.as_str())
            .collect()
    }

    #[test]
    fn a_planted_fault_leaves_the_fault_and_its_causal_chain_in_the_log() {
        // A corrupted sample in block 7 is caught during block 7, so exactly 7 block events
        // (blocks 0 to 6) precede the fault record and the failure record.
        let mut sink = default_diagnostic_sink();
        let corrupt = OutputFault::CorruptSample {
            member_id: "spk-office-s5",
            block: 7,
            last_channel: true,
            offset: 5,
        };
        let err = run_campaign_with_sink(SEED, 20, Some(corrupt), &mut sink)
            .expect_err("corruption must be caught");
        let kinds = event_kinds(&sink);
        assert_eq!(kinds.iter().filter(|k| **k == "block_rendered").count(), 7);
        assert_eq!(
            &kinds[kinds.len() - 2..],
            ["fault_injected", "campaign_failed"]
        );
        let injected = &sink.events()[kinds.len() - 2];
        assert!(injected.fault.as_deref().is_some_and(|f| {
            f.contains("corrupt_sample")
                && f.contains("member=spk-office-s5")
                && f.contains("block=7")
        }));
        let failed = &sink.events()[kinds.len() - 1];
        assert_eq!(failed.fault, injected.fault);
        let chain = failed
            .cause
            .as_deref()
            .expect("a failure record carries its cause");
        assert!(chain.contains("wrong sample at frame 1797"), "{chain}");
        assert!(err.contains("wrong sample at frame 1797"), "{err}");
        assert!(sink.is_evidence_complete());

        // A dropped final block is only noticed after the loop, so all 20 block events exist.
        let mut tail_sink = default_diagnostic_sink();
        let dropped = OutputFault::DropFinalBlock {
            member_id: "spk-bedroom-s1",
        };
        run_campaign_with_sink(SEED, 20, Some(dropped), &mut tail_sink)
            .expect_err("a dropped tail must be caught");
        let tail_kinds = event_kinds(&tail_sink);
        assert_eq!(
            tail_kinds
                .iter()
                .filter(|k| **k == "block_rendered")
                .count(),
            20
        );
        let tail_failed = tail_sink.events().last().expect("a failure record");
        assert_eq!(tail_failed.event_kind, "campaign_failed");
        assert!(
            tail_failed
                .cause
                .as_deref()
                .is_some_and(|c| c.contains("truncated stream"))
        );
        assert!(tail_kinds.contains(&"fault_injected"));

        // Paired positive: a clean campaign leaves neither record, and its summary names no fault.
        let mut clean = default_diagnostic_sink();
        run_campaign_with_sink(SEED, 20, None, &mut clean).expect("clean campaign");
        let clean_kinds = event_kinds(&clean);
        assert!(!clean_kinds.contains(&"fault_injected"));
        assert!(!clean_kinds.contains(&"campaign_failed"));
        let summary = clean.events().last().expect("a summary record");
        assert_eq!(summary.event_kind, "campaign_complete");
        assert_eq!(summary.fault, None);
        assert_eq!(summary.cause, None);
    }

    #[test]
    fn the_default_campaign_sink_bounds_a_burst_but_never_limits_a_healthy_stream() {
        // A burst of 300 ordinary events in one instant: 256 pass, 44 are rate limited and
        // counted. Capacity (512) is not the limit being exercised here.
        let mut burst = default_diagnostic_sink();
        for n in 0..300u64 {
            assert_eq!(
                burst.try_emit(DiagnosticEvent {
                    schema_version: String::new(),
                    timestamp_mono_ns: 0,
                    run_id: "burst".to_string(),
                    case_id: "Q01-virtual-house".to_string(),
                    correlation_id: format!("burst-{n}"),
                    member_id: "house".to_string(),
                    group_id: "grp-burst".to_string(),
                    source_epoch: 1,
                    state_revision: 0,
                    event_kind: "burst".to_string(),
                    message: "burst".to_string(),
                    queue_depth: 0,
                    latency_us: 0,
                    fault: None,
                    cause: None,
                }),
                n < 256
            );
        }
        assert_eq!(burst.events().len(), 256);
        assert_eq!(burst.rate_limited_event_count(), 44);
        assert_eq!(burst.dropped_event_count(), 44);
        assert_eq!(burst.emitted_event_count(), 300);

        // Paired positive: a normal campaign emits one event per block and is never limited.
        let mut healthy = default_diagnostic_sink();
        run_campaign_with_sink(SEED, 200, None, &mut healthy).expect("clean campaign");
        assert_eq!(healthy.rate_limited_event_count(), 0);
        assert_eq!(healthy.dropped_event_count(), 0);
        assert!(healthy.is_evidence_complete());
    }

    /// What each member's engine must decide for every block, from the seeded schedule alone. These are the rules N04's
    /// contract states, restated here and not read from the engine: a delivered block is real; a missing one is concealed
    /// up to 8 in a row and then muted; before anything has played it is muted for want of history. Returns (real,
    /// concealed, muted for a long gap, muted for want of history, duplicates delivered).
    fn expected_playout(
        seed: u64,
        member_index: u64,
        total_blocks: u64,
    ) -> (u64, u64, u64, u64, u64) {
        let cfg = NetworkScheduleConfig {
            seed: seed.wrapping_add(member_index * 101),
            ..NetworkScheduleConfig::default()
        };
        let mut schedule = NetworkSchedule::new(cfg);
        let (mut real, mut concealed, mut gap, mut nohistory, mut duplicates) = (0, 0, 0, 0, 0);
        let (mut have_played, mut run) = (false, 0_u32);
        for blk in 0..total_blocks {
            let decision = schedule.evaluate_packet(blk, block_offset_ns(blk));
            if !decision.dropped {
                real += 1;
                have_played = true;
                run = 0;
                duplicates += u64::from(decision.duplicate_deliver_time_ns.is_some());
            } else if !have_played {
                nohistory += 1;
                run += 1;
            } else if run >= 8 {
                gap += 1;
                run += 1;
            } else {
                concealed += 1;
                run += 1;
            }
        }
        (real, concealed, gap, nohistory, duplicates)
    }

    #[test]
    fn the_real_playout_engine_decides_every_block_as_the_seeded_schedule_says_it_must() {
        // 1 200 blocks is 6.4 s: long enough to contain the schedule's first 100 ms burst outage (it starts at 5 s) and
        // the muting after the engine has concealed 8 blocks of it.
        let total = 1_200;
        let report = run_virtual_house_campaign(SEED, total).unwrap();
        assert_eq!(report.members.len(), 5);
        assert!(report.unified_mixed_s1_s2 && report.within_2ms_skew_target);
        let mut muted_after_a_long_gap = false;
        for (idx, (id, stats)) in report.members.iter().enumerate() {
            let (real, concealed, gap, nohistory, duplicates) =
                expected_playout(SEED, idx as u64, total);
            let p = &stats.playout;
            assert_eq!(
                (
                    p.decided_real,
                    p.decided_concealed,
                    p.decided_muted_gap,
                    p.decided_muted_nohistory
                ),
                (real, concealed, gap, nohistory),
                "member {id}"
            );
            assert_eq!(real + concealed + gap + nohistory, total, "member {id}");
            // Jitter is at most 50 ms against a 500 ms horizon: nothing is late, from another epoch, refused for want of
            // a clock, or left undecided; every delivered block is admitted once and each duplicate is refused once.
            assert_eq!(
                (
                    p.late,
                    p.wrong_epoch,
                    p.clock_refused,
                    p.otherwise_refused,
                    p.blocks_without_a_decision,
                    p.catch_up_decisions,
                    p.decided_muted_overdue,
                    p.decided_skipped
                ),
                (0, 0, 0, 0, 0, 0, 0, 0),
                "member {id}"
            );
            assert_eq!((p.admitted, p.duplicate), (real, duplicates), "member {id}");
            // The legacy counters keep their meaning: real blocks, and blocks that were missing.
            assert_eq!(stats.authentic_blocks, real, "member {id}");
            assert_eq!(stats.concealed_blocks, concealed + gap, "member {id}");
            muted_after_a_long_gap |= gap > 0;
        }
        assert!(
            muted_after_a_long_gap,
            "the burst outage reached the engine"
        );
    }

    // ---- planted link and clock faults (Q01, second slice) -----------------------------------------------------------

    /// Where a plant acts on one member, in the terms the independent model understands.
    #[derive(Clone, Copy, Default)]
    struct Plant {
        late: Option<u64>,
        swap: Option<u64>,
        stale: Option<u64>,
        leap: Option<u64>,
        /// The first block of the second stream when a source change cuts the house over (the scenario, not a defect).
        cutover: Option<u64>,
        /// A datagram of the replaced stream was sent at this block.
        stale_stream: Option<u64>,
        /// The replaced adapter kept publishing after the cutover, and the gate refused it with this code.
        replaced_publishes: Option<&'static str>,
    }

    /// What one member's playout must come to, and the legacy counters that follow from it.
    struct ModelMember {
        playout: PlayoutMemberReport,
        authentic: u64,
        concealed: u64,
        /// Real blocks per source epoch: 1 before the cutover, 2 from it.
        source_blocks: BTreeMap<u64, u64>,
    }

    /// The seeded schedule's verdict for each block of a member, asked block by block on the campaign-relative axis, as the
    /// sender does: `None` if the block is dropped, else (arrival, arrival of its duplicate).
    fn schedule_link(seed: u64, member_index: u64, total: u64) -> Vec<Option<(u64, Option<u64>)>> {
        let cfg = NetworkScheduleConfig {
            seed: seed.wrapping_add(member_index * 101),
            ..NetworkScheduleConfig::default()
        };
        let mut schedule = NetworkSchedule::new(cfg);
        (0..total)
            .map(|blk| {
                let d = schedule.evaluate_packet(blk, block_offset_ns(blk));
                if d.dropped {
                    None
                } else {
                    d.deliver_time_ns
                        .map(|arrival| (arrival, d.duplicate_deliver_time_ns))
                }
            })
            .collect()
    }

    /// The interval in which a member's clock cannot be used after its own clock leaps forward at block `k`, as the
    /// node-level tests pin it (`a_leap_forward_mid_stream_mutes_at_once...`): from `k`, when the last exchange is stale,
    /// until the relock, which needs the lock count of accepted exchanges, one per probe interval, after the probe that
    /// finds the step.
    fn leap_outage(k: u64) -> (u64, u64) {
        let probe_after_step = (k / PROBE_EVERY_BLOCKS + 1) * PROBE_EVERY_BLOCKS;
        (
            k,
            probe_after_step + u64::from(CLOCK_LOCK_MIN_SAMPLES) * PROBE_EVERY_BLOCKS,
        )
    }

    /// What a member's engines must do with a campaign of `total` blocks, from the seeded schedule and N04's contract alone.
    /// The rules are restated here, not read from the engine: the order of checks on an arriving packet (stream, epoch,
    /// clock, already decided, beyond the horizon, already held), the decision for the next block (overdue if the clock is
    /// past its presentation, real if held, then muted without history, muted after eight concealed, else concealed) and the
    /// render loop's timing (a block is decided 3.5 ms before its presentation; everything that has arrived by then is
    /// handed over first, in arrival order, and handed over refused if the clock cannot be used). A source change adds a
    /// second engine that starts empty at the cutover block, so nothing it was told before, no concealment history either,
    /// carries across; a packet for a stream whose last block is decided is refused before the engine sees it. Nothing here
    /// models an arrival between a block's cutoff and its decision: the schedule's 50 ms of jitter against a 500 ms horizon
    /// never makes one.
    fn model_member(seed: u64, member_index: u64, total: u64, plant: Plant) -> ModelMember {
        use std::collections::BTreeSet;
        const WORK_PLUS_LEAD_NS: u64 = 1_500_000 + 2_000_000;
        const HORIZON_BLOCKS: u64 = 94;
        const MAX_CONCEAL: u32 = 8;
        const HISTORY_BLOCKS: u64 = 128;
        const LATE_BEFORE_PRESENTATION_NS: u64 = 500_000;
        const STALE_LEAD_NS: u64 = 1_000_000;

        /// One stream generation's engine as N04's contract states it.
        struct Engine {
            until: Option<u64>,
            cursor: u64,
            gap_run: u32,
            have_last_real: bool,
            slots: BTreeSet<u64>,
            decided_real: BTreeSet<u64>,
        }

        impl Engine {
            fn new(first: u64, until: Option<u64>) -> Self {
                Self {
                    until,
                    cursor: first,
                    gap_run: 0,
                    have_last_real: false,
                    slots: BTreeSet::new(),
                    decided_real: BTreeSet::new(),
                }
            }

            fn retired(&self) -> bool {
                self.until.is_some_and(|until| self.cursor >= until)
            }
        }

        let index = |blk: u64| usize::try_from(blk).expect("a block index");
        let decision_ns = |blk: u64| {
            CAMPAIGN_ORIGIN_NS + block_offset_ns(blk) + PLAYOUT_HORIZON_NS - WORK_PLUS_LEAD_NS
        };
        // The stream generation that owns a block position.
        let engine_of = |blk: u64| usize::from(plant.cutover.is_some_and(|cutover| blk >= cutover));

        let mut link = schedule_link(seed, member_index, total);
        if let Some(k) = plant.swap
            && let (Some(a), Some(b)) = (link[index(k)], link[index(k + 1)])
        {
            link[index(k)] = Some((b.0, a.1));
            link[index(k + 1)] = Some((a.0, b.1));
        }
        // Everything that reaches the engine: (arrival, block, copy, from the previous epoch).
        let mut arrivals: Vec<(u64, u64, u8, bool)> = Vec::new();
        for blk in 0..total {
            let slot = link[index(blk)];
            let genuine = slot.map(|(arrival, _)| {
                if plant.late == Some(blk) {
                    block_offset_ns(blk) + PLAYOUT_HORIZON_NS - LATE_BEFORE_PRESENTATION_NS
                } else {
                    arrival
                }
            });
            if let (Some(arrival), Some((_, duplicate))) = (genuine, slot) {
                arrivals.push((CAMPAIGN_ORIGIN_NS + arrival, blk, 0, false));
                if let Some(duplicate) = duplicate {
                    arrivals.push((CAMPAIGN_ORIGIN_NS + duplicate, blk, 1, false));
                }
            }
            if plant.stale == Some(blk) {
                let at = genuine
                    .unwrap_or(block_offset_ns(blk) + STALE_LEAD_NS)
                    .saturating_sub(STALE_LEAD_NS);
                arrivals.push((CAMPAIGN_ORIGIN_NS + at, blk, 2, true));
            }
        }
        arrivals.sort_unstable();

        let mut engines = vec![Engine::new(0, plant.cutover)];
        if let Some(cutover) = plant.cutover {
            engines.push(Engine::new(cutover, None));
        }
        let outage = plant.leap.map(leap_outage);
        let mut report = PlayoutMemberReport {
            stale_refused_at_receiver: u64::from(plant.stale.is_some()),
            streams_opened: engines.len() as u64,
            wrong_stream_refused_at_receiver: u64::from(plant.stale_stream.is_some()),
            replaced_publishes_refused: match (plant.replaced_publishes, plant.cutover) {
                (Some(code), Some(cutover)) => {
                    BTreeMap::from([(code.to_string(), total - cutover)])
                }
                _ => BTreeMap::new(),
            },
            ..PlayoutMemberReport::default()
        };
        let (mut authentic, mut concealed_legacy) = (0, 0);
        let mut source_blocks = BTreeMap::new();
        let (mut highest, mut next) = (None, 0);
        for j in 0..total {
            let usable = outage.is_none_or(|(from, until)| !(from..until).contains(&j));
            while next < arrivals.len() && arrivals[next].0 <= decision_ns(j) {
                let (_, blk, _, previous_epoch) = arrivals[next];
                next += 1;
                if highest.is_some_and(|h| blk < h) {
                    report.out_of_order_arrivals += 1;
                }
                highest = highest.max(Some(blk));
                let engine = &mut engines[engine_of(blk)];
                if engine.retired() {
                    report.retired_stream_refused += 1;
                    continue;
                }
                report.packets_offered += 1;
                if previous_epoch {
                    report.wrong_epoch += 1;
                } else if !usable {
                    report.clock_refused += 1;
                } else if blk < engine.cursor {
                    if engine.cursor - blk <= HISTORY_BLOCKS && engine.decided_real.contains(&blk) {
                        report.duplicate += 1;
                    } else {
                        report.late += 1;
                    }
                } else if blk >= engine.cursor + HORIZON_BLOCKS {
                    report.otherwise_refused += 1;
                } else if engine.slots.insert(blk) {
                    report.admitted += 1;
                } else {
                    report.duplicate += 1;
                }
            }
            if !usable {
                report.blocks_without_a_decision += 1;
                continue;
            }
            let engine = &mut engines[engine_of(j)];
            while engine.cursor <= j {
                let blk = engine.cursor;
                if blk < j {
                    // Decided after its presentation: overdue, whatever it held.
                    engine.slots.remove(&blk);
                    engine.gap_run = (engine.gap_run + 1).min(255);
                    report.decided_muted_overdue += 1;
                    report.catch_up_decisions += 1;
                } else if engine.slots.remove(&blk) {
                    engine.have_last_real = true;
                    engine.gap_run = 0;
                    engine.decided_real.insert(blk);
                    report.decided_real += 1;
                    authentic += 1;
                    *source_blocks
                        .entry(if plant.cutover.is_some_and(|cutover| blk >= cutover) {
                            2
                        } else {
                            1
                        })
                        .or_default() += 1;
                } else if !engine.have_last_real {
                    engine.gap_run = (engine.gap_run + 1).min(255);
                    report.decided_muted_nohistory += 1;
                } else if engine.gap_run >= MAX_CONCEAL {
                    engine.gap_run = (engine.gap_run + 1).min(255);
                    report.decided_muted_gap += 1;
                    concealed_legacy += 1;
                } else {
                    engine.gap_run += 1;
                    report.decided_concealed += 1;
                    concealed_legacy += 1;
                }
                engine.cursor = blk + 1;
            }
        }
        ModelMember {
            playout: report,
            authentic,
            concealed: concealed_legacy,
            source_blocks,
        }
    }

    /// Run the campaign without the plant and with `fault`, and hold both to the independent model member by member:
    /// the control (no plant) must come out as the model says nominal is, every planted member as the model says the plant
    /// makes it (and the model must see a difference, so the plant is not a no-op), every other member must be exactly as
    /// without the plant, and every member's continuity and shadow oracles must have held to the last frame. The control
    /// keeps the scenario, so a plant on a source change is judged against the same source change without it.
    fn run_planted_in(
        scenario: Scenario,
        fault: OutputFault,
        planted_members: &[&str],
        plant: Plant,
        control_plant: Plant,
        total: u64,
    ) -> (VirtualHouseReport, VirtualHouseReport) {
        let nominal = run_scenario(SEED, total, None, scenario)
            .expect("the control campaign: the same scenario without the plant");
        let mut sink = default_diagnostic_sink();
        let planted = run_scenario_with_sink(SEED, total, Some(fault), scenario, &mut sink)
            .expect("the planted campaign still runs: every oracle holds");
        for (index, ((id, base), (planted_id, stats))) in nominal
            .members
            .iter()
            .zip(planted.members.iter())
            .enumerate()
        {
            assert_eq!(id, planted_id);
            let control = model_member(SEED, index as u64, total, control_plant);
            assert_eq!(base.playout, control.playout, "nominal {id}");
            assert_eq!(
                (base.authentic_blocks, base.concealed_blocks),
                (control.authentic, control.concealed),
                "nominal {id}"
            );
            assert_eq!(base.source_blocks, control.source_blocks, "nominal {id}");
            if planted_members.contains(&id.as_str()) {
                let expected = model_member(SEED, index as u64, total, plant);
                assert_ne!(
                    expected.playout, control.playout,
                    "the plant must change something the model can see"
                );
                assert_eq!(stats.playout, expected.playout, "planted {id}");
                assert_eq!(
                    (stats.authentic_blocks, stats.concealed_blocks),
                    (expected.authentic, expected.concealed),
                    "planted {id}"
                );
                assert_eq!(stats.source_blocks, expected.source_blocks, "planted {id}");
            } else {
                assert_eq!(
                    stats, base,
                    "{id} is untouched by a plant on {planted_members:?}"
                );
            }
            assert_eq!(
                stats.verified_continuous_frames,
                total * (FRAMES_PER_BLOCK as u64),
                "{id}"
            );
            assert_eq!(stats.rendered_blocks, total, "{id}");
            assert_eq!(stats.quarantined_dma_slots, 0, "{id}");
        }
        let injected: Vec<_> = sink
            .events()
            .iter()
            .filter(|e| e.event_kind == "fault_injected")
            .collect();
        assert_eq!(injected.len(), 1, "the plant is on record once");
        assert_eq!(
            injected[0].fault.as_deref(),
            Some(describe_fault(fault).as_str())
        );
        (nominal, planted)
    }

    /// [`run_planted_in`] for a plant on one member of a campaign with no source change.
    fn run_planted(
        fault: OutputFault,
        member: &str,
        plant: Plant,
        total: u64,
    ) -> (VirtualHouseReport, VirtualHouseReport) {
        run_planted_in(
            Scenario::NONE,
            fault,
            &[member],
            plant,
            Plant::default(),
            total,
        )
    }

    const FAULT_BLOCKS: u64 = 400;

    #[test]
    fn a_late_block_in_the_whole_campaign_is_refused_as_late_and_concealed_and_nothing_else_moves()
    {
        let (member, index) = ("spk-bedroom-s1", 0);
        let nominal = model_member(SEED, index, FAULT_BLOCKS, Plant::default());
        // A block the schedule delivers alone, whose loss the engine would conceal at the first step.
        let block = (120..300)
            .find(|&k| {
                let m = model_member(
                    SEED,
                    index,
                    FAULT_BLOCKS,
                    Plant {
                        late: Some(k),
                        ..Plant::default()
                    },
                );
                m.playout.late == 1
                    && m.playout.decided_real + 1 == nominal.playout.decided_real
                    && m.playout.decided_concealed == nominal.playout.decided_concealed + 1
            })
            .expect("a block the schedule delivers alone");
        let plant = Plant {
            late: Some(block),
            ..Plant::default()
        };
        let fault = OutputFault::LateBlock {
            member_id: member,
            block,
        };
        let (base, planted) = run_planted(fault, member, plant, FAULT_BLOCKS);
        let (b, p) = (&base.members[member], &planted.members[member]);
        // The control has nothing late; the plant makes exactly one block late, plays one block fewer and conceals one more.
        assert_eq!((b.playout.late, p.playout.late), (0, 1));
        assert_eq!(p.playout.decided_real + 1, b.playout.decided_real);
        assert_eq!(p.playout.decided_concealed, b.playout.decided_concealed + 1);
        assert_eq!(p.authentic_blocks + 1, b.authentic_blocks);
        assert_eq!(p.concealed_blocks, b.concealed_blocks + 1);
        assert_eq!(p.playout.admitted + 1, b.playout.admitted);
    }

    #[test]
    fn a_reordered_pair_in_the_whole_campaign_changes_the_arrival_order_and_nothing_else() {
        let (member, index) = ("spk-den-s3", 1);
        let nominal = model_member(SEED, index, FAULT_BLOCKS, Plant::default());
        // A pair the schedule delivers in order, so the swap puts the later block first.
        let block = (120..300)
            .find(|&k| {
                let m = model_member(
                    SEED,
                    index,
                    FAULT_BLOCKS,
                    Plant {
                        swap: Some(k),
                        ..Plant::default()
                    },
                );
                m.playout.out_of_order_arrivals > nominal.playout.out_of_order_arrivals
            })
            .expect("a pair the schedule delivers in order");
        let plant = Plant {
            swap: Some(block),
            ..Plant::default()
        };
        let fault = OutputFault::ReorderedPair {
            member_id: member,
            block,
        };
        let (base, planted) = run_planted(fault, member, plant, FAULT_BLOCKS);
        let (b, p) = (&base.members[member], &planted.members[member]);
        assert!(p.playout.out_of_order_arrivals > b.playout.out_of_order_arrivals);
        // Every block still plays its own bytes (the engine's bytes oracle ran in the campaign), and the decision counts and
        // the legacy counters are the control's.
        assert_eq!(
            PlayoutMemberReport {
                out_of_order_arrivals: p.playout.out_of_order_arrivals,
                ..b.playout.clone()
            },
            p.playout
        );
        assert_eq!(
            (p.authentic_blocks, p.concealed_blocks),
            (b.authentic_blocks, b.concealed_blocks)
        );
    }

    #[test]
    fn a_previous_epoch_datagram_in_the_whole_campaign_is_refused_twice_and_nothing_else_moves() {
        let (member, index) = ("spk-kitchen-s12", 2);
        let link = schedule_link(SEED, index, FAULT_BLOCKS);
        let block = (120..300)
            .find(|&k| link[k as usize].is_some())
            .expect("a delivered block");
        let plant = Plant {
            stale: Some(block),
            ..Plant::default()
        };
        let fault = OutputFault::StaleEpochPacket {
            member_id: member,
            block,
        };
        let (base, planted) = run_planted(fault, member, plant, FAULT_BLOCKS);
        let (b, p) = (&base.members[member], &planted.members[member]);
        // The control saw no stale datagram. The plant is refused by the member's own receiver (N01's epoch check, with the
        // member's key) and, handed on as an old receiver would have authenticated it, by the engine as the wrong epoch;
        // the bytes it carried never sounded, and no other counter moved.
        assert_eq!(
            (b.playout.wrong_epoch, b.playout.stale_refused_at_receiver),
            (0, 0)
        );
        assert_eq!(
            (p.playout.wrong_epoch, p.playout.stale_refused_at_receiver),
            (1, 1)
        );
        assert_eq!(
            PlayoutMemberReport {
                packets_offered: b.playout.packets_offered + 1,
                wrong_epoch: 1,
                stale_refused_at_receiver: 1,
                ..b.playout.clone()
            },
            p.playout
        );
        assert_eq!(
            (p.authentic_blocks, p.concealed_blocks),
            (b.authentic_blocks, b.concealed_blocks)
        );
    }

    #[test]
    fn a_clock_leap_in_the_whole_campaign_blinds_the_engine_until_the_relock_and_it_catches_up_as_overdue()
     {
        let member = "spk-office-s5";
        // The node-level tests pin this timeline for a 30 s leap forward at block 40: muted from 40, relocked and sounding
        // from 192.
        assert_eq!(leap_outage(40), (40, 192));
        let (from, until) = (40, 192);
        let plant = Plant {
            leap: Some(from),
            ..Plant::default()
        };
        let fault = OutputFault::ClockLeap {
            member_id: member,
            block: from,
            delta_ns: 30_000_000_000,
        };
        let (base, planted) = run_planted(fault, member, plant, FAULT_BLOCKS);
        let (b, p) = (&base.members[member], &planted.members[member]);
        let outage = until - from;
        // The control decided every position at once. With the leap, the positions in the outage had no decision, the engine
        // decided each of them as overdue after the relock, and the monotone latch never moved on a reading the clock did
        // not stand behind.
        assert_eq!(
            (
                b.playout.blocks_without_a_decision,
                b.playout.catch_up_decisions
            ),
            (0, 0)
        );
        assert_eq!(
            (
                p.playout.blocks_without_a_decision,
                p.playout.catch_up_decisions,
                p.playout.decided_muted_overdue,
                p.playout.clamped_readings
            ),
            (outage, outage, outage, 0)
        );
        // The packets that arrived while the clock could not be used were refused for that, and are gone.
        assert!(p.playout.clock_refused > 0);
        // The node's own gate muted the same positions: the one fault reached both consumers of the clock.
        assert_eq!(planted.skew_unmeasured_blocks, outage);
        assert!(base.within_2ms_skew_target && !planted.within_2ms_skew_target);
        assert_eq!(p.muted_blocks, b.muted_blocks + outage);
        assert_eq!(p.audible_blocks + outage, b.audible_blocks);
    }

    // ---- a source change through the real arbiter (Q01, third slice) -----------------------------------------------------

    const HOUSE: [&str; 5] = [
        "spk-bedroom-s1",
        "spk-den-s3",
        "spk-kitchen-s12",
        "spk-living-sub",
        "spk-office-s5",
    ];

    /// The first block a member's sender has not sent when a source change is admitted at the start of render iteration `r`:
    /// every block whose send instant is not later than the instant block `r - 1` is decided. Restated from the timeline.
    fn cutover_for(r: u64) -> u64 {
        let until = CAMPAIGN_ORIGIN_NS + block_offset_ns(r - 1) + PLAYOUT_HORIZON_NS
            - (1_500_000 + 2_000_000);
        (0_u64..)
            .take_while(|&k| CAMPAIGN_ORIGIN_NS + block_offset_ns(k) <= until)
            .count() as u64
    }

    fn scenario_at(r: u64, first: Racer) -> Scenario {
        Scenario {
            source_switch: Some(SourceSwitch { block: r, first }),
            ..Scenario::NONE
        }
    }

    fn switch_plant(r: u64) -> Plant {
        Plant {
            cutover: Some(cutover_for(r)),
            ..Plant::default()
        }
    }

    /// A switch point at which a member loses the first block of the new stream, found with the independent model: the lost
    /// block is muted for want of history (the new stream's engine has none), where the one engine that carried history
    /// across would have concealed it. Returns the render iteration and the member's index.
    fn a_switch_where_history_does_not_cross() -> (u64, usize) {
        for r in 100..300 {
            for index in 0..HOUSE.len() {
                let with = model_member(SEED, index as u64, FAULT_BLOCKS, switch_plant(r));
                let without = model_member(SEED, index as u64, FAULT_BLOCKS, Plant::default());
                if with.playout.decided_muted_nohistory
                    == without.playout.decided_muted_nohistory + 1
                {
                    return (r, index);
                }
            }
        }
        panic!("no switch point in 100..300 loses a block of the new stream");
    }

    #[test]
    fn each_source_epoch_publishes_its_own_audio_and_epoch_one_is_the_campaigns_original_signal() {
        let bytes = |blk: u64, epoch: u64| source_block(blk, epoch).to_be_i16_bytes();
        for blk in 0..64 {
            let amp = ((blk % 32) as f32) * 0.02 + 0.05;
            let one = source_block(blk, 1);
            assert_eq!(one.left, [amp; FRAMES_PER_BLOCK], "block {blk}");
            assert_eq!(one.right, [-amp; FRAMES_PER_BLOCK], "block {blk}");
            assert_ne!(bytes(blk, 1), bytes(blk, 2), "block {blk}");
            assert_ne!(bytes(blk, 2), bytes(blk, 3), "block {blk}");
            assert_ne!(bytes(blk, 1), bytes(blk, 3), "block {blk}");
        }
    }

    #[test]
    fn the_cutover_the_model_restates_is_where_the_pump_stands_93_blocks_ahead() {
        for r in [1, 2, 50, 150, 299] {
            assert_eq!(cutover_for(r), r + 93, "iteration {r}");
        }
    }

    #[test]
    fn a_campaign_with_no_source_change_has_one_program_and_the_nominal_counts() {
        let report = run_scenario(SEED, FAULT_BLOCKS, None, Scenario::NONE).expect("campaign");
        let spotify = source_id(SourceKind::Spotify, SPOTIFY_LABEL).expect("id");
        assert_eq!(
            report.source,
            SourceReport {
                admitted: 1,
                refused: BTreeMap::new(),
                final_epoch: 1,
                final_owner: Some(spotify.to_string()),
                cutover_block: None,
            }
        );
        for (index, (id, stats)) in report.members.iter().enumerate() {
            let want = model_member(SEED, index as u64, FAULT_BLOCKS, Plant::default());
            assert_eq!(stats.playout, want.playout, "{id}");
            assert_eq!(stats.playout.streams_opened, 1, "{id}");
            assert_eq!(stats.source_blocks, want.source_blocks, "{id}");
            assert_eq!(
                stats.source_blocks.get(&1),
                Some(&stats.authentic_blocks),
                "{id}"
            );
        }
    }

    #[test]
    fn two_adapters_racing_to_replace_the_source_admit_exactly_one_in_either_order_and_the_house_cuts_over_at_one_frame()
     {
        let (r, lossy) = a_switch_where_history_does_not_cross();
        let cutover = cutover_for(r);
        let airplay = source_id(SourceKind::AirPlay2, AIRPLAY_LABEL).expect("id");
        let spotify = source_id(SourceKind::Spotify, SPOTIFY_LABEL).expect("id");
        for (first, winner) in [(Racer::AirPlay, &airplay), (Racer::Spotify, &spotify)] {
            let report = run_scenario(SEED, FAULT_BLOCKS, None, scenario_at(r, first))
                .unwrap_or_else(|e| panic!("{first:?} first: the campaign failed: {e}"));
            // State: the first start and the race's one winner were admitted; the loser was told it was stale; one epoch was
            // minted by the race; every member cut over at the same, restated frame.
            assert_eq!(
                report.source,
                SourceReport {
                    admitted: 2,
                    refused: BTreeMap::from([("SOURCE_EPOCH_STALE".to_string(), 1)]),
                    final_epoch: 2,
                    final_owner: Some(winner.to_string()),
                    cutover_block: Some(cutover),
                },
                "{first:?} first"
            );
            // Samples: each member's engines decided what the model says, every block that sounded is the owner's audio (the
            // campaign checks that from the bytes), and the audio is continuous across the cutover on every channel.
            for (index, (id, stats)) in report.members.iter().enumerate() {
                let want = model_member(SEED, index as u64, FAULT_BLOCKS, switch_plant(r));
                assert_eq!(stats.playout, want.playout, "{first:?} first, {id}");
                assert_eq!(
                    stats.source_blocks, want.source_blocks,
                    "{first:?} first, {id}"
                );
                assert_eq!(
                    (stats.authentic_blocks, stats.concealed_blocks),
                    (want.authentic, want.concealed),
                    "{first:?} first, {id}"
                );
                assert_eq!(stats.playout.streams_opened, 2, "{id}");
                assert_eq!(
                    stats.source_blocks.values().sum::<u64>(),
                    stats.authentic_blocks,
                    "{id}: every real block is attributed to exactly one program"
                );
                assert_eq!(
                    stats.verified_continuous_frames,
                    FAULT_BLOCKS * (FRAMES_PER_BLOCK as u64),
                    "{id}"
                );
            }
            // History does not cross a stream: the member that lost a block right at the cutover muted it for want of
            // history, which the one-engine alternative would have concealed.
            let with = &report.members[HOUSE[lossy]].playout;
            let without = model_member(SEED, lossy as u64, FAULT_BLOCKS, Plant::default()).playout;
            assert_eq!(
                (with.decided_muted_nohistory, with.decided_concealed + 1),
                (
                    without.decided_muted_nohistory + 1,
                    without.decided_concealed
                ),
                "{first:?} first"
            );
        }
    }

    #[test]
    fn a_replaced_adapter_that_keeps_publishing_is_refused_by_the_gate_and_its_audio_never_sounds()
    {
        let (r, _) = a_switch_where_history_does_not_cross();
        let cutover = cutover_for(r);
        // The code names why: another source replaced it, or it is the same source's own earlier stream.
        for (first, code) in [
            (Racer::AirPlay, "SOURCE_REPLACED"),
            (Racer::Spotify, "SOURCE_EPOCH_STALE"),
        ] {
            let plant = Plant {
                replaced_publishes: Some(code),
                ..switch_plant(r)
            };
            let (control, planted) = run_planted_in(
                scenario_at(r, first),
                OutputFault::ReplacedSourceKeepsPublishing,
                &HOUSE,
                plant,
                switch_plant(r),
                FAULT_BLOCKS,
            );
            for (id, stats) in &planted.members {
                // Every block position from the cutover on was offered by the replaced adapter first and refused; the audio
                // that sounded is the control's, block for block.
                assert_eq!(
                    stats.playout.replaced_publishes_refused,
                    BTreeMap::from([(code.to_string(), FAULT_BLOCKS - cutover)]),
                    "{first:?} first, {id}"
                );
                let base = &control.members[id];
                assert_eq!(stats.source_blocks, base.source_blocks, "{id}");
                assert_eq!(
                    (stats.authentic_blocks, stats.concealed_blocks),
                    (base.authentic_blocks, base.concealed_blocks),
                    "{id}"
                );
                assert!(base.playout.replaced_publishes_refused.is_empty(), "{id}");
            }
            assert_eq!(
                planted.source, control.source,
                "the gate does not change the arbiter's state"
            );
        }
    }

    #[test]
    fn a_datagram_of_the_replaced_stream_after_the_rebind_is_refused_by_the_receiver_and_changes_nothing_else()
     {
        let (r, _) = a_switch_where_history_does_not_cross();
        let block = cutover_for(r) + 10;
        let member = "spk-kitchen-s12";
        let plant = Plant {
            stale_stream: Some(block),
            ..switch_plant(r)
        };
        let (control, planted) = run_planted_in(
            scenario_at(r, Racer::AirPlay),
            OutputFault::StaleStreamDatagram {
                member_id: member,
                block,
            },
            &[member],
            plant,
            switch_plant(r),
            FAULT_BLOCKS,
        );
        let (b, p) = (
            &control.members[member].playout,
            &planted.members[member].playout,
        );
        // The member's own receiver, rebound to the new stream, refused the old stream's datagram by name; the engines never
        // saw it, so no other counter moved.
        assert_eq!(
            (
                b.wrong_stream_refused_at_receiver,
                p.wrong_stream_refused_at_receiver
            ),
            (0, 1)
        );
        assert_eq!(
            PlayoutMemberReport {
                wrong_stream_refused_at_receiver: 1,
                ..b.clone()
            },
            *p
        );
    }

    #[test]
    fn a_planted_source_fault_without_a_source_change_and_a_change_outside_the_campaign_are_errors()
    {
        let err = run_scenario(
            SEED,
            40,
            Some(OutputFault::ReplacedSourceKeepsPublishing),
            Scenario::NONE,
        )
        .expect_err("nothing was replaced");
        assert!(err.contains("needs a source change"), "{err}");
        for block in [0, 40, 41] {
            let err = run_scenario(SEED, 40, None, scenario_at(block, Racer::AirPlay))
                .expect_err("outside the campaign");
            assert!(err.contains("outside 1..40"), "{block}: {err}");
        }
        // Admitted so late that no block of the new stream is left: the stream would start at block 94 of 94.
        let err =
            run_scenario(SEED, 94, None, scenario_at(1, Racer::Spotify)).expect_err("too late");
        assert!(err.contains("too late"), "{err}");
        // Paired positive: the same switch one block earlier still has a block to carry.
        run_scenario(SEED, 95, None, scenario_at(1, Racer::Spotify))
            .expect("one block of the new stream");
    }

    #[test]
    fn the_campaign_is_deterministic() {
        let first = run_campaign(SEED, 20, None).expect("first run");
        let second = run_campaign(SEED, 20, None).expect("second run");
        assert_eq!(first, second);
    }

    #[test]
    fn unavailable_full_zero_capacity_and_tiny_log_sinks_do_not_change_the_campaign() {
        const BLOCKS: u64 = 20;
        // One `block_rendered` event per block, plus the final `campaign_complete`. The exact
        // counts below only come out right if the render loop really emits one event per block.
        const EVENTS: u64 = BLOCKS + 1;

        let baseline = run_campaign(SEED, BLOCKS, None).expect("baseline campaign");
        assert_eq!(
            baseline.dropped_log_events, 0,
            "the default sink holds a campaign this size"
        );
        assert!(baseline.evidence_complete);

        let mut unavailable = default_diagnostic_sink();
        unavailable.set_unavailable(true);
        // (label, sink, events that must be counted as dropped, whether the critical summary
        // survives). A full sink evicts one ordinary event to keep the summary; a sink that
        // cannot store anything loses it, and the report says so.
        for (label, mut sink, expected_dropped, expected_complete) in [
            ("unavailable", unavailable, EVENTS, false),
            (
                "zero capacity",
                BoundedDiagnosticSink::new(0, 0),
                EVENTS,
                false,
            ),
            (
                "full after 5 events",
                BoundedDiagnosticSink::new(5, 256 * 1024),
                EVENTS - 5,
                true,
            ),
        ] {
            let report = run_campaign_with_sink(SEED, BLOCKS, None, &mut sink)
                .unwrap_or_else(|e| panic!("{label}: the campaign failed: {e}"));
            // The loss is counted exactly, never silent...
            assert_eq!(report.dropped_log_events, expected_dropped, "{label}");
            // ...a lost summary marks the result incomplete instead of looking like a clean run...
            assert_eq!(report.evidence_complete, expected_complete, "{label}");
            // ...and nothing else differs: every timing field, every member's stats, the fencing
            // probe and the readiness outcome are the same as with a healthy sink.
            let mut comparable = report.clone();
            comparable.dropped_log_events = baseline.dropped_log_events;
            comparable.evidence_complete = baseline.evidence_complete;
            assert_eq!(
                comparable, baseline,
                "{label}: the sink changed the campaign"
            );
        }

        // A byte budget too small for the stream drops some events, and still changes nothing else.
        let mut tiny_sink = BoundedDiagnosticSink::new(512, 400);
        let tiny =
            run_campaign_with_sink(SEED, BLOCKS, None, &mut tiny_sink).expect("tiny sink campaign");
        assert!(
            tiny.dropped_log_events > 0 && tiny.dropped_log_events <= EVENTS,
            "dropped {} of {EVENTS}",
            tiny.dropped_log_events
        );
        let mut comparable = tiny.clone();
        comparable.dropped_log_events = baseline.dropped_log_events;
        // Whether the summary fits in such a small budget depends on its serialized size, which
        // is not asserted here; the field is excluded from the comparison, not from the report.
        comparable.evidence_complete = baseline.evidence_complete;
        assert_eq!(comparable, baseline, "tiny sink changed the campaign");
    }

    #[test]
    fn a_run_in_which_all_but_one_member_is_muted_does_not_pass_the_skew_gate() {
        // Planted defect: the controller never schedules a start for four of the five members, so they stay muted.
        // One node sounds, so the measured skew is trivially 0, which must not read as "within 2 ms".
        let planted = OutputFault::UnadmittedExcept {
            member_id: "spk-kitchen-s12",
        };
        let report = run_campaign(SEED, 40, Some(planted)).expect("the campaign itself runs");
        assert_eq!(report.max_inter_speaker_skew_us, 0);
        assert_eq!(report.skew_unmeasured_blocks, 40);
        assert_eq!(report.skew_measured_blocks, 0);
        assert!(
            !report.within_2ms_skew_target,
            "an unmeasured skew is not a pass"
        );
        for (id, stats) in &report.members {
            let expected = if id == "spk-kitchen-s12" {
                (40, 0)
            } else {
                (0, 40)
            };
            assert_eq!((stats.audible_blocks, stats.muted_blocks), expected, "{id}");
        }
        // Paired positive: the same campaign without the planted defect measures every block and passes.
        let clean = run_campaign(SEED, 40, None).expect("clean campaign");
        assert_eq!(
            (clean.skew_measured_blocks, clean.skew_unmeasured_blocks),
            (40, 0)
        );
        assert!(clean.within_2ms_skew_target);
        assert!(clean.max_inter_speaker_skew_us > 0);
    }

    #[test]
    fn a_refused_member_is_out_of_the_skew_gate_but_a_silently_muted_one_is_not() {
        let newer = PeerFirmware {
            answer_message_version: Some(2),
            ..PeerFirmware::CURRENT
        };
        // A member N01 refused is out of the group by a recorded decision; the other four are judged among themselves.
        let mut sink = default_diagnostic_sink();
        let refused_only = run_campaign_inner(SEED, 40, None, &mut sink, &[("spk-den-s3", newer)])
            .expect("a refused member is an outcome, not a failed campaign");
        assert_eq!(refused_only.skew_participants, 4);
        assert_eq!(
            (
                refused_only.skew_measured_blocks,
                refused_only.skew_unmeasured_blocks
            ),
            (40, 0)
        );
        assert!(refused_only.within_2ms_skew_target);
        // The same refusal plus the planted defect (the controller never schedules a start for any other member but
        // one): the refusal does not excuse that mute. Three participants never sound, so nothing is measured.
        let planted = OutputFault::UnadmittedExcept {
            member_id: "spk-kitchen-s12",
        };
        let mut sink = default_diagnostic_sink();
        let both = run_campaign_inner(SEED, 40, Some(planted), &mut sink, &[("spk-den-s3", newer)])
            .expect("the campaign itself runs");
        assert_eq!(both.skew_participants, 4);
        assert_eq!(
            (both.skew_measured_blocks, both.skew_unmeasured_blocks),
            (0, 40)
        );
        assert!(
            !both.within_2ms_skew_target,
            "a refusal does not excuse a silent mute"
        );
    }

    #[test]
    fn a_campaign_that_compared_nothing_does_not_report_the_skew_target_as_met() {
        // Planted: no blocks at all. Nothing is measured and nothing is left unmeasured, so both terms of the gate
        // as it stood (skew within 2 ms, no unmeasured block) hold trivially.
        let mut sink = default_diagnostic_sink();
        let report = run_campaign_inner(SEED, 0, None, &mut sink, &[])
            .expect("a zero-block campaign runs; it just makes no claim");
        assert_eq!(report.total_blocks_streamed, 0);
        assert_eq!(report.skew_participants, 5);
        assert_eq!(
            (report.skew_measured_blocks, report.skew_unmeasured_blocks),
            (0, 0)
        );
        assert_eq!(report.max_inter_speaker_skew_us, 0);
        assert!(
            report.max_inter_speaker_skew_us <= 2_000 && report.skew_unmeasured_blocks == 0,
            "the old formula would have called this met"
        );
        assert!(
            !report.within_2ms_skew_target,
            "a run that compared nothing met nothing"
        );
        // Paired positive: a normal campaign compares every block and still meets the target.
        let nominal = run_campaign(SEED, 200, None).expect("campaign");
        assert_eq!(
            (nominal.skew_measured_blocks, nominal.skew_unmeasured_blocks),
            (200, 0)
        );
        assert!(nominal.max_inter_speaker_skew_us > 0);
        assert!(nominal.within_2ms_skew_target);
    }

    #[test]
    fn a_house_with_one_participant_left_makes_no_synchronisation_claim() {
        let newer = PeerFirmware {
            answer_message_version: Some(2),
            ..PeerFirmware::CURRENT
        };
        let mut sink = default_diagnostic_sink();
        let report = run_campaign_inner(
            SEED,
            40,
            None,
            &mut sink,
            &[
                ("spk-bedroom-s1", newer),
                ("spk-kitchen-s12", newer),
                ("spk-den-s3", newer),
                ("spk-living-sub", newer),
            ],
        )
        .expect("refused members are outcomes, not a failed campaign");
        assert_eq!(report.skew_participants, 1);
        assert_eq!(report.members["spk-office-s5"].audible_blocks, 40);
        assert_eq!(
            (report.skew_measured_blocks, report.skew_unmeasured_blocks),
            (0, 40)
        );
        assert!(
            !report.within_2ms_skew_target,
            "one speaker has nothing to be in sync with"
        );
    }

    #[test]
    fn the_simulated_member_clocks_are_pinned_so_a_change_to_them_is_deliberate() {
        // `within_2ms_skew_target` is now a measured gate on the `--virtual-house` exit code, so the simulated
        // offsets and skews it rests on must not drift unnoticed. Values are the FNV-1a derivation of
        // `SimNodeClock::for_member`, checked independently in Python.
        let pinned = [
            ("spk-office-s5", -44_166, 3_311_185_000),
            ("spk-bedroom-s1", -44_711, 2_980_954_000),
            ("spk-kitchen-s12", -38_850, 2_182_976_000),
            ("spk-den-s3", -17_100, 2_032_073_000),
            ("spk-living-sub", 863, 1_085_400_000),
        ];
        for (id, skew_ppb, local0_ns) in pinned {
            assert_eq!(
                SimNodeClock::for_member(id),
                SimNodeClock {
                    skew_ppb,
                    local0_ns
                },
                "{id}"
            );
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Streams are created through negotiation (`N01` / `ffw-ey5`).
    // ---------------------------------------------------------------------------------------------

    const FLEET: [&str; 5] = [
        "spk-office-s5",
        "spk-bedroom-s1",
        "spk-kitchen-s12",
        "spk-den-s3",
        "spk-living-sub",
    ];

    /// One full media block, as the campaign sends it.
    fn media_frame(blk: u64) -> OutboundFrame {
        let start_frame = blk * (FRAMES_PER_BLOCK as u64);
        let pts_ns = 500_000_000 + blk * BLOCK_PERIOD_NS;
        OutboundFrame::media(
            start_frame,
            pts_ns,
            pts_ns - BLOCK_PERIOD_NS,
            StereoAudioBlock::silence(start_frame).to_be_i16_bytes(),
        )
    }

    #[test]
    fn every_member_stream_is_created_through_negotiation_with_the_agreed_version_and_format() {
        let report = run_campaign(SEED, 20, None).expect("campaign");
        assert_eq!(report.members.len(), 5);
        // Stated here, not read back from the stream crate: wire version 1; the one format bit (16-bit
        // big-endian stereo PCM at 48 kHz); one full 256-frame stereo block of payload; and both
        // optional features, because every member's firmware here supports both.
        let agreed = StreamAgreement {
            wire_version: 1,
            format: 0b01,
            max_payload_bytes: u16::try_from(FRAMES_PER_BLOCK * 4).expect("a block fits"),
            features: 0b11,
        };
        for id in FLEET {
            let stats = &report.members[id];
            assert_eq!(
                stats.stream,
                StreamOutcome::Negotiated(agreed),
                "member {id}"
            );
            assert_eq!(stats.stream_refused_blocks, 0, "member {id}");
        }
        // A node brought up on its own is the same, and holds both ends of its session.
        let node = bring_up(BringUpPlan::NOMINAL).expect("nominal bring-up");
        assert_eq!(node.stream, StreamOutcome::Negotiated(agreed));
        assert!(node.receiver.is_some() && node.coordinator_sender.is_some());
    }

    #[test]
    fn a_datagram_made_for_one_member_is_refused_by_another_because_each_session_has_its_own_key() {
        let mut office =
            negotiate_member_stream("spk-office-s5", 1, 0, PeerFirmware::CURRENT).expect("office");
        let mut den =
            negotiate_member_stream("spk-den-s3", 1, 0, PeerFirmware::CURRENT).expect("den");
        let wire = office
            .sender
            .as_mut()
            .expect("office sender")
            .send(media_frame(0))
            .expect("encode");
        assert!(
            office
                .receiver
                .as_mut()
                .expect("office receiver")
                .accept(&wire)
                .is_ok(),
            "the member it was made for accepts it"
        );
        assert_eq!(
            den.receiver
                .as_mut()
                .expect("den receiver")
                .accept(&wire)
                .err(),
            Some(StreamError::AuthenticationFailed),
            "another member's media key is a different key"
        );

        // The contrast, and the reason this matters: the baseline constructors keyed every member
        // alike, so any member accepted any member's stream.
        let key = || StreamKey::from_bytes(CAMPAIGN_STREAM_KEY);
        let id = campaign_stream_id().expect("stream id");
        let shared = StreamSender::new(key(), id, 1)
            .send(media_frame(0))
            .expect("encode");
        assert!(StreamReceiver::new(key(), id, 1).accept(&shared).is_ok());
        assert!(StreamReceiver::new(key(), id, 1).accept(&shared).is_ok());
    }

    #[test]
    fn a_member_whose_answer_carries_an_unsupported_message_version_is_refused_and_muted_with_its_cause()
     {
        let newer = PeerFirmware {
            answer_message_version: Some(2),
            ..PeerFirmware::CURRENT
        };
        let mut sink = default_diagnostic_sink();
        let report = run_campaign_inner(SEED, 200, None, &mut sink, &[("spk-den-s3", newer)])
            .expect("a member without a stream is an outcome, not a failed campaign");

        // The planted member: refused by the coordinator with N01's bounded diagnostic, and muted for
        // every block with nothing played and nothing concealed.
        let den = &report.members["spk-den-s3"];
        assert_eq!(
            den.stream,
            StreamOutcome::Refused(StreamRefusal {
                refused_by: RefusedBy::Coordinator,
                code: "HELLO_UNSUPPORTED_VERSION".to_string(),
                detail: "unsupported negotiation message version 2 (this build speaks 1)"
                    .to_string(),
            })
        );
        assert_eq!(
            (
                den.audible_blocks,
                den.muted_blocks,
                den.stream_refused_blocks
            ),
            (0, 200, 200)
        );
        assert_eq!((den.authentic_blocks, den.concealed_blocks), (0, 0));
        assert_eq!(den.rendered_blocks, 200);
        assert_eq!(
            den.verified_continuous_frames,
            200 * (FRAMES_PER_BLOCK as u64),
            "silence at the right stream positions, so the oracles still judge contiguous frames"
        );
        // Paired positive: the four members that negotiated are exactly as in a normal campaign.
        for id in FLEET.into_iter().filter(|id| *id != "spk-den-s3") {
            let stats = &report.members[id];
            assert!(
                matches!(stats.stream, StreamOutcome::Negotiated(_)),
                "member {id}"
            );
            assert_eq!(
                (
                    stats.audible_blocks,
                    stats.muted_blocks,
                    stats.stream_refused_blocks
                ),
                (200, 0, 0),
                "member {id}"
            );
        }
        assert!(report.within_2ms_skew_target && report.unified_mixed_s1_s2);
        // The gate was judged over the four members that have a stream, on every block: the refused member is out of
        // the group by N01's recorded decision, and nothing about the others was left unmeasured.
        assert_eq!(
            (
                report.skew_participants,
                report.skew_measured_blocks,
                report.skew_unmeasured_blocks
            ),
            (4, 200, 0)
        );

        // The cause is on record exactly once, for that member, and nowhere else.
        let refusals: Vec<_> = sink
            .events()
            .iter()
            .filter(|e| e.event_kind == "stream_refused")
            .collect();
        assert_eq!(refusals.len(), 1);
        assert_eq!(refusals[0].member_id, "spk-den-s3");
        assert!(
            refusals[0]
                .cause
                .as_deref()
                .is_some_and(|c| c.starts_with("HELLO_UNSUPPORTED_VERSION: "))
        );
        assert!(sink.is_evidence_complete());

        // Not degraded: the member holds neither end of any stream, so there was nothing for the
        // baseline path to serve it with.
        let link =
            negotiate_member_stream("spk-den-s3", 1, 0, newer).expect("a refusal is an outcome");
        assert!(link.receiver.is_none() && link.sender.is_none());
        // And the diagnostic is bounded: numbers and words only, no key material.
        if let StreamOutcome::Refused(r) = &link.outcome {
            assert!(r.detail.len() <= 120, "{}", r.detail);
            assert!(!r.detail.to_lowercase().contains("a5a5"), "{}", r.detail);
        } else {
            panic!("the planted member was not refused");
        }
    }

    #[test]
    fn a_member_that_cannot_take_a_full_block_is_refused_by_the_member_and_both_refusals_are_independent()
     {
        let newer = PeerFirmware {
            answer_message_version: Some(2),
            ..PeerFirmware::CURRENT
        };
        let small = PeerFirmware {
            max_payload_bytes: 4,
            ..PeerFirmware::CURRENT
        };
        let mut sink = default_diagnostic_sink();
        let report = run_campaign_inner(
            SEED,
            40,
            None,
            &mut sink,
            &[("spk-living-sub", small), ("spk-den-s3", newer)],
        )
        .expect("campaign");

        assert_eq!(
            report.members["spk-living-sub"].stream,
            StreamOutcome::Refused(StreamRefusal {
                refused_by: RefusedBy::Member,
                code: "LIMITS_INCOMPATIBLE".to_string(),
                detail: "common payload limit 4 is below one full block (1024)".to_string(),
            })
        );
        assert!(matches!(
            report.members["spk-den-s3"].stream,
            StreamOutcome::Refused(StreamRefusal {
                refused_by: RefusedBy::Coordinator,
                ..
            })
        ));
        for id in ["spk-living-sub", "spk-den-s3"] {
            let stats = &report.members[id];
            assert_eq!(
                (
                    stats.audible_blocks,
                    stats.muted_blocks,
                    stats.stream_refused_blocks
                ),
                (0, 40, 40),
                "member {id}"
            );
        }
        for id in ["spk-office-s5", "spk-bedroom-s1", "spk-kitchen-s12"] {
            let stats = &report.members[id];
            assert_eq!(
                (
                    stats.audible_blocks,
                    stats.muted_blocks,
                    stats.stream_refused_blocks
                ),
                (40, 0, 0),
                "member {id}"
            );
        }
        let recorded: Vec<&str> = sink
            .events()
            .iter()
            .filter(|e| e.event_kind == "stream_refused")
            .map(|e| e.member_id.as_str())
            .collect();
        assert_eq!(recorded, ["spk-den-s3", "spk-living-sub"]);
    }

    #[test]
    fn simulated_peer_identities_and_nonces_are_valid_distinct_and_deterministic() {
        let ids: Vec<u64> = FLEET.into_iter().map(member_peer_id).collect();
        assert!(ids.iter().all(|id| *id != 0 && *id != COORDINATOR_ID));
        let mut distinct_ids = ids.clone();
        distinct_ids.sort_unstable();
        distinct_ids.dedup();
        assert_eq!(distinct_ids.len(), FLEET.len());

        let mut nonces = Vec::new();
        for member in FLEET {
            for role in [&b"offer"[..], &b"answer"[..]] {
                nonces.push(simulated_nonce(role, member, 1, 0));
            }
        }
        assert!(nonces.iter().all(|n| *n != [0u8; 16]));
        let mut distinct = nonces.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), nonces.len(), "a nonce repeats");

        let base = simulated_nonce(b"offer", FLEET[0], 1, 0);
        assert_eq!(base, simulated_nonce(b"offer", FLEET[0], 1, 0));
        assert_ne!(base, simulated_nonce(b"offer", FLEET[0], 2, 0));
        assert_ne!(base, simulated_nonce(b"offer", FLEET[0], 1, 1));
    }

    #[test]
    fn the_planted_version_refusal_is_about_the_version_and_not_a_broken_tag() {
        let psk = StreamKey::from_bytes(CAMPAIGN_STREAM_KEY);
        let exchange = || {
            let (initiator, offer) = Initiator::offer(
                &psk,
                Capabilities::baseline(),
                COORDINATOR_ID,
                campaign_stream_id().expect("stream id"),
                1,
                simulated_nonce(b"offer", "spk-test", 1, 0),
            )
            .expect("offer");
            let (_, answer) = respond(
                &psk,
                Capabilities::baseline(),
                member_peer_id("spk-test"),
                1,
                simulated_nonce(b"answer", "spk-test", 1, 0),
                &offer,
            )
            .expect("answer");
            (initiator, answer)
        };
        // Unaltered, the exchange completes.
        let (initiator, answer) = exchange();
        assert!(initiator.finish(&answer).is_ok());
        // The byte the harness patches is the message version, and the refusal says so.
        let (initiator, mut answer) = exchange();
        answer[HELLO_VERSION_BYTE] = 2;
        assert_eq!(
            initiator.finish(&answer).err(),
            Some(NegotiationError::HelloUnsupportedVersion { version: 2 })
        );
        // Any other byte of the same message is a forgery, refused as one: the version refusal above
        // is not a tag failure in disguise.
        let (initiator, mut answer) = exchange();
        answer[20] ^= 0xFF;
        assert_eq!(
            initiator.finish(&answer).err(),
            Some(NegotiationError::HelloAuthenticationFailed)
        );
    }

    // ---- Q01 slice 4: relative volume retried through the real G03 endpoint, around a source change ------------------------------
    //
    // The expected numbers come from `predict_volume.py`, which restates the contract's rules (g03.md 3.1 and 9.1, n02.md) and is not
    // derived from the Rust. The campaign runs the real `Endpoint`, `ControlChannel` and `PeerDirectory` (`control_adapter`) over the
    // campaign's own session, with the AirPlay sender replacing Spotify at block 100 (cutover at block 193).

    use crate::control_adapter::plans;

    const VOLUME_SWITCH_AT: u64 = 100;

    /// The digest of `blocks` blocks of silence on `channels` channels: what a member renders when nothing reaches its output.
    fn silent_digest(blocks: u64, channels: u8) -> u64 {
        let silence = [0i16; FRAMES_PER_BLOCK];
        let mut digest = OUTPUT_DIGEST_START;
        for _ in 0..blocks * u64::from(channels) {
            digest = fnv1a_extend_samples(digest, &silence);
        }
        digest
    }

    #[test]
    fn the_digest_of_silence_is_the_value_computed_independently() {
        // FNV-1a over N zero bytes is `basis * prime^N mod 2^64` (every step xors 0, then multiplies by the prime). For 400 blocks of
        // 2 channels of 256 frames of 2 bytes, N is 409_600, and Python's `pow` gives this number without any of the Rust.
        assert_eq!(silent_digest(400, 2), 5_755_000_421_370_241_829);
    }

    #[test]
    fn a_member_whose_channels_all_come_from_the_mono_mix_renders_silence_and_the_endpoint_member_does_not()
     {
        // The campaign's source is `left = amp`, `right = -amp`, so the mono mix is exactly zero. S12 routes both its channels from
        // that mix, so it renders only zeros whatever its volume: the first central run of the sensitivity test below found its digest
        // to be exactly `silent_digest(400, 2)`. The volume plan's endpoint must therefore be a member that renders the signal.
        let report = run_scenario(SEED, FAULT_BLOCKS, None, Scenario::NONE).expect("campaign");
        let silent = &report.members["spk-kitchen-s12"];
        assert_eq!(
            silent.output_fnv1a64,
            silent_digest(FAULT_BLOCKS, silent.hardware_channels)
        );
        let endpoint = &report.members[VOLUME_ENDPOINT_MEMBER];
        assert_ne!(
            endpoint.output_fnv1a64,
            silent_digest(FAULT_BLOCKS, endpoint.hardware_channels),
            "the endpoint member renders silence: its digest cannot see its volume"
        );
    }

    fn volume_scenario(plan: &'static [VolumeStep]) -> Scenario {
        Scenario {
            volume: Some(plan),
            ..scenario_at(VOLUME_SWITCH_AT, Racer::AirPlay)
        }
    }

    #[test]
    fn the_volume_race_around_a_source_change_does_what_the_contract_predicts() {
        let race = run_scenario(SEED, FAULT_BLOCKS, None, volume_scenario(plans::RACE))
            .expect("the race campaign: every response and every state matched the contract");
        let volume = race.volume.clone().expect("the volume plan ran");
        // 14 deliveries over 8 steps. Legacy: 4 applications (a plain-SOAP retry is a new command). Tailnet: 4 applications, one per
        // command number, and 5 answers from the ledger, one of them the remembered refusal of the stale step.
        assert_eq!(volume.steps_run, 8);
        assert_eq!(volume.sends, 14);
        assert_eq!(volume.legacy_applied, 4);
        assert_eq!(volume.tailnet_applied, 4);
        assert_eq!(volume.ledger_replays, 5);
        assert_eq!(volume.stale_refused, 1);
        assert_eq!(volume.direct_sets, 0);
        assert_eq!(volume.faults, BTreeMap::from([("501".to_string(), 2)]));
        assert_eq!(
            (volume.start_member_volume, volume.start_group_volume),
            (50, 50)
        );
        assert_eq!(
            (volume.end_member_volume, volume.end_group_volume),
            (30, 30)
        );
        // Eight applied commands, not fourteen deliveries and not twelve unrefused ones.
        assert_eq!(volume.end_revision, volume.start_revision + 8);
        // The source change happened as it does in the same campaign with no volume step at all: the same program, the same
        // blocks from each source, and the fencing probe (which runs after the plan) saw what it always sees.
        let quiet = run_scenario(
            SEED,
            FAULT_BLOCKS,
            None,
            scenario_at(VOLUME_SWITCH_AT, Racer::AirPlay),
        )
        .expect("the campaign with the same source change and no volume step");
        assert!(quiet.volume.is_none());
        assert_eq!(race.source, quiet.source);
        assert_eq!(
            race.source.cutover_block,
            Some(cutover_for(VOLUME_SWITCH_AT))
        );
        assert_eq!(race.fencing, quiet.fencing);
        for (id, stats) in &race.members {
            assert_eq!(stats.source_blocks, quiet.members[id].source_blocks, "{id}");
        }
    }

    #[test]
    fn the_volume_race_sounds_exactly_like_a_reference_that_sets_the_same_volumes_directly() {
        let race = run_scenario(SEED, FAULT_BLOCKS, None, volume_scenario(plans::RACE))
            .expect("the race campaign");
        let reference = run_scenario(SEED, FAULT_BLOCKS, None, volume_scenario(plans::REFERENCE))
            .expect("the reference campaign");
        let direct = reference.volume.clone().expect("the reference plan ran");
        assert_eq!((direct.direct_sets, direct.sends), (7, 0));
        assert_eq!(direct.end_revision, direct.start_revision + 7);
        assert_eq!(race.source, reference.source);
        // The endpoint member must render something, or equal digests would prove nothing about its volume.
        let endpoint = &race.members[VOLUME_ENDPOINT_MEMBER];
        assert_ne!(
            endpoint.output_fnv1a64,
            silent_digest(FAULT_BLOCKS, endpoint.hardware_channels),
            "the endpoint member renders silence"
        );
        for (id, stats) in &race.members {
            assert_ne!(
                stats.output_fnv1a64, OUTPUT_DIGEST_START,
                "{id} rendered nothing"
            );
            assert_eq!(
                stats.output_fnv1a64, reference.members[id].output_fnv1a64,
                "{id} does not sound like the reference"
            );
            assert_eq!(
                stats.audible_blocks, reference.members[id].audible_blocks,
                "{id}"
            );
        }
    }

    #[test]
    fn a_reference_that_reaches_a_different_volume_sounds_different_in_that_member_only() {
        // The negative control for the comparison above: a reference that disagrees with the race at one volume for 15 blocks must
        // not have the same digest, so "the same digest" means something. Every other member renders the same samples in both.
        let race = run_scenario(SEED, FAULT_BLOCKS, None, volume_scenario(plans::RACE))
            .expect("the race campaign");
        let wrong = run_scenario(
            SEED,
            FAULT_BLOCKS,
            None,
            volume_scenario(plans::WRONG_REFERENCE),
        )
        .expect("the wrong reference campaign");
        for (id, stats) in &race.members {
            if id.as_str() == VOLUME_ENDPOINT_MEMBER {
                assert_ne!(
                    stats.output_fnv1a64, wrong.members[id].output_fnv1a64,
                    "the digest cannot tell two volume trajectories apart, so agreeing with the reference proves nothing"
                );
            } else {
                assert_eq!(
                    stats.output_fnv1a64, wrong.members[id].output_fnv1a64,
                    "{id}"
                );
            }
        }
    }

    /// The control (the same plan with no plant) must pass; then the plant must fail the campaign with a message that names it.
    fn assert_a_volume_plant_is_named(fault: OutputFault, expected_prefix: &str) {
        run_scenario(SEED, FAULT_BLOCKS, None, volume_scenario(plans::RACE))
            .expect("the control: the same plan without the plant passes");
        let error = run_scenario(
            SEED,
            FAULT_BLOCKS,
            Some(fault),
            volume_scenario(plans::RACE),
        )
        .expect_err("the plant must be caught");
        assert!(error.starts_with(expected_prefix), "{error}");
    }

    #[test]
    fn a_tailnet_retry_sent_as_a_new_command_fails_the_campaign_by_name() {
        // Step 0 is a tailnet +10 sent twice: the retry applies again (70, not 60) when it is sent as a new command.
        assert_a_volume_plant_is_named(
            OutputFault::TailnetRetryAsNewCommand,
            "volume_response_mismatch: step 0 send 1:",
        );
    }

    #[test]
    fn a_stale_tailnet_revision_a_client_refreshes_fails_the_campaign_by_name() {
        // Step 2 names the revision before step 1; the contract refuses it. A client that names the current one is applied instead.
        assert_a_volume_plant_is_named(
            OutputFault::TailnetStaleRevisionRefreshed,
            "volume_response_mismatch: step 2 send 0:",
        );
    }

    #[test]
    fn a_planted_volume_fault_needs_a_volume_plan() {
        for fault in [
            OutputFault::TailnetRetryAsNewCommand,
            OutputFault::TailnetStaleRevisionRefreshed,
        ] {
            let error = run_scenario(SEED, FAULT_BLOCKS, Some(fault), Scenario::NONE)
                .expect_err("a plant with nothing to act on is refused");
            assert_eq!(
                error,
                "a planted volume fault needs a volume plan in the scenario"
            );
        }
    }

    #[test]
    fn a_campaign_with_no_volume_plan_reports_none_and_sounds_the_same_every_time() {
        let first = run_scenario(SEED, 200, None, Scenario::NONE).expect("campaign");
        let second = run_scenario(SEED, 200, None, Scenario::NONE).expect("campaign");
        assert!(first.volume.is_none());
        let mut digests = std::collections::BTreeSet::new();
        for (id, stats) in &first.members {
            assert_ne!(
                stats.output_fnv1a64, OUTPUT_DIGEST_START,
                "{id} rendered nothing"
            );
            assert_eq!(
                stats.output_fnv1a64, second.members[id].output_fnv1a64,
                "{id}"
            );
            digests.insert(stats.output_fnv1a64);
        }
        // Five different boards render different samples: the digest is not one constant.
        assert!(digests.len() > 1);
    }

    // ---- Q01: a source whose channels do not cancel, and the question "did a member that sounded render anything" ---------------
    //
    // The default source has `right = -left`, so the mono mix is exactly zero and a member whose every channel comes from it
    // (S12, S1, the sub) renders silence at any volume. Every assertion above is about that source and is unchanged. These
    // scenarios use `SourceSignal::Asymmetric` and add one question the other oracles cannot answer, because the live and the
    // shadow DSP are handed the same input: did a member that sounded audio it was sent render a single non-zero sample?

    fn asymmetric() -> Scenario {
        Scenario {
            signal: SourceSignal::Asymmetric,
            ..Scenario::NONE
        }
    }

    #[test]
    fn the_asymmetric_source_keeps_the_left_channel_and_its_mono_mix_never_cancels() {
        for blk in 0..64 {
            for epoch in 1..=3 {
                let opposed = source_block_in(SourceSignal::Opposed, blk, epoch);
                let asym = source_block_in(SourceSignal::Asymmetric, blk, epoch);
                assert_eq!(asym.left, opposed.left, "block {blk} epoch {epoch}");
                assert_eq!(asym.right, [0.5 * asym.left[0]; FRAMES_PER_BLOCK]);
                // The original cancels exactly; the new one never does: the mix is 0.75 of the left channel, whose smallest amplitude
                // over these blocks and epochs is 0.045 (epoch 2, block 0), so the mix is at least 0.03375.
                assert_eq!(0.5 * (opposed.left[0] + opposed.right[0]), 0.0);
                assert!(0.5 * (asym.left[0] + asym.right[0]) > 0.03);
                assert_ne!(asym.to_be_i16_bytes(), opposed.to_be_i16_bytes());
            }
        }
    }

    #[test]
    fn with_a_source_whose_channels_do_not_cancel_every_member_renders_sound() {
        let report = run_scenario(SEED, FAULT_BLOCKS, None, asymmetric())
            .expect("the campaign: every oracle, and every member that sounded rendered something");
        for (id, stats) in &report.members {
            assert!(stats.audible_authentic_blocks > 0, "{id} never sounded");
            assert!(
                stats.rendered_nonzero_blocks > 0,
                "{id} rendered only zeros"
            );
            assert!(
                stats.rendered_nonzero_blocks <= stats.rendered_blocks,
                "{id}"
            );
            assert_ne!(
                stats.output_fnv1a64,
                silent_digest(FAULT_BLOCKS, stats.hardware_channels),
                "{id} rendered silence"
            );
        }
    }

    #[test]
    fn under_the_original_source_the_mono_routed_member_renders_only_zeros_and_that_is_not_a_failure()
     {
        // The limit, measured: the same campaign with the original source. S12 sounded (the gate let its authentic blocks through)
        // and rendered not one non-zero sample, and the campaign is still a pass: the other oracles cannot tell, and this question is
        // not asked of the original source.
        let report = run_scenario(SEED, FAULT_BLOCKS, None, Scenario::NONE).expect("campaign");
        let s12 = &report.members["spk-kitchen-s12"];
        assert!(s12.audible_authentic_blocks > 0);
        assert_eq!(s12.rendered_nonzero_blocks, 0);
        assert_eq!(
            s12.output_fnv1a64,
            silent_digest(FAULT_BLOCKS, s12.hardware_channels)
        );
        // A member with channels fed from the left and the right renders in the same campaign.
        let s5 = &report.members["spk-office-s5"];
        assert!(s5.rendered_nonzero_blocks > 0);
    }

    /// The control (the same scenario with no plant) must pass; then the plant must fail the campaign with a message that names it.
    fn assert_silence_is_named(member: &'static str) {
        run_scenario(SEED, FAULT_BLOCKS, None, asymmetric())
            .expect("the control: the same scenario without the plant passes");
        let error = run_scenario(
            SEED,
            FAULT_BLOCKS,
            Some(OutputFault::SilentInput { member_id: member }),
            asymmetric(),
        )
        .expect_err("a member that renders silence must fail the campaign");
        assert!(
            error.starts_with(&format!("member_rendered_silence: {member}:")),
            "{error}"
        );
    }

    #[test]
    fn a_member_that_renders_silence_fails_the_campaign_by_name() {
        // A member with L/R channels (S5) and one that only a non-cancelling source gives anything to (S12).
        assert_silence_is_named("spk-office-s5");
        assert_silence_is_named("spk-kitchen-s12");
    }

    #[test]
    fn without_the_new_question_a_member_handed_silence_passes_every_other_oracle() {
        // Why the question is needed: the same plant under the original source, where it is not asked. Continuity, shadow, fencing,
        // playout and the skew all hold, and the member's output is exactly the digest of silence.
        let plant = OutputFault::SilentInput {
            member_id: "spk-office-s5",
        };
        let report = run_scenario(SEED, FAULT_BLOCKS, Some(plant), Scenario::NONE)
            .expect("every other oracle holds: both DSPs were handed the same silence");
        let s5 = &report.members["spk-office-s5"];
        assert!(s5.audible_authentic_blocks > 0);
        assert_eq!(s5.rendered_nonzero_blocks, 0);
        assert_eq!(
            s5.output_fnv1a64,
            silent_digest(FAULT_BLOCKS, s5.hardware_channels)
        );
    }

    #[test]
    fn a_member_that_never_sounded_may_render_only_zeros_under_the_new_source() {
        // The permitted positive: members the controller never admitted stay muted, render zeros, and are not asked to have
        // rendered anything. Only the member that sounded is.
        let plant = OutputFault::UnadmittedExcept {
            member_id: "spk-office-s5",
        };
        let report = run_scenario(SEED, 200, Some(plant), asymmetric())
            .expect("a member that never sounded is not a silent member");
        for (id, stats) in &report.members {
            if id == "spk-office-s5" {
                assert!(stats.rendered_nonzero_blocks > 0, "{id}");
            } else {
                assert_eq!(stats.audible_authentic_blocks, 0, "{id}");
                assert_eq!(stats.rendered_nonzero_blocks, 0, "{id}");
            }
        }
    }

    // ---- Q01 measurement: what every member renders under each source, for the e2e judge (`tests/q01`, `scripts/e2e/q01`) ------
    //
    // These two tests print one JSON record per line (`Q01-MEMBER`, `Q01-PLANT`) into the `cargo test -- --nocapture` output. The
    // judge re-derives every record independently (it recomputes the digest of silence itself and cross-checks it against the
    // counter) and holds `docs/contracts/q01.md` limit 1 to what the records show. The tests assert the same things, so a pass by
    // name means something on its own. The campaign is the one `franken-speaker --virtual-house` runs: seed `SEED`, 250 blocks.

    const MEASURE_BLOCKS: u64 = 250;

    fn signal_name(signal: SourceSignal) -> &'static str {
        match signal {
            SourceSignal::Opposed => "opposed",
            SourceSignal::Asymmetric => "asymmetric",
        }
    }

    #[test]
    fn q01_measure_what_every_member_renders_under_each_source() {
        for signal in [SourceSignal::Opposed, SourceSignal::Asymmetric] {
            let scenario = Scenario {
                signal,
                ..Scenario::NONE
            };
            let report = run_scenario(SEED, MEASURE_BLOCKS, None, scenario)
                .expect("the campaign passes under this source");
            assert_eq!(report.members.len(), 5);
            for (id, stats) in &report.members {
                println!(
                    "Q01-MEMBER {}",
                    serde_json::json!({
                        "signal": signal_name(signal),
                        "member": id,
                        "seed": SEED,
                        "blocks": MEASURE_BLOCKS,
                        "channels": stats.hardware_channels,
                        "rendered_blocks": stats.rendered_blocks,
                        "audible_authentic_blocks": stats.audible_authentic_blocks,
                        "rendered_nonzero_blocks": stats.rendered_nonzero_blocks,
                        "digest": stats.output_fnv1a64,
                    })
                );
                // The two independent measurements of "rendered only zeros" agree: no non-zero block exactly when the digest is
                // the digest of that many blocks of silence.
                assert_eq!(
                    stats.rendered_nonzero_blocks == 0,
                    stats.output_fnv1a64 == silent_digest(MEASURE_BLOCKS, stats.hardware_channels),
                    "{id}: the counter and the digest disagree about silence"
                );
                if signal == SourceSignal::Asymmetric {
                    assert!(stats.audible_authentic_blocks > 0, "{id} never sounded");
                    assert!(
                        stats.rendered_nonzero_blocks > 0,
                        "{id} rendered only zeros"
                    );
                }
            }
        }
    }

    #[test]
    fn q01_measure_planted_silence_is_named_for_every_member() {
        let scenario = Scenario {
            signal: SourceSignal::Asymmetric,
            ..Scenario::NONE
        };
        // The remove-the-plant control: the same campaign with no plant passes.
        run_scenario(SEED, MEASURE_BLOCKS, None, scenario)
            .expect("the control: the unplanted campaign passes");
        println!(
            "Q01-PLANT {}",
            serde_json::json!({ "member": null, "planted": false, "outcome": "ok", "message": null })
        );
        for member in [
            "spk-office-s5",
            "spk-bedroom-s1",
            "spk-kitchen-s12",
            "spk-den-s3",
            "spk-living-sub",
        ] {
            let error = run_scenario(
                SEED,
                MEASURE_BLOCKS,
                Some(OutputFault::SilentInput { member_id: member }),
                scenario,
            )
            .expect_err("a member that renders silence must fail the campaign");
            println!(
                "Q01-PLANT {}",
                serde_json::json!({ "member": member, "planted": true, "outcome": "error", "message": error })
            );
            assert!(
                error.starts_with(&format!("member_rendered_silence: {member}:")),
                "{error}"
            );
        }
    }
}
