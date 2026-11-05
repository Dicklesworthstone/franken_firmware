//! The Virtual House harness (`Q01` / `ffw-gmq`) and the readiness UX simulation (`UX01` / `ffw-389`).
//!
//! Everything here is a test harness: it links `franken-test-support` (network impairment schedules,
//! continuity, fencing and readiness oracles, a redacting diagnostic sink). It is compiled only for unit
//! tests or with the off-by-default `harness` Cargo feature, so a default (device) build of
//! `franken-speaker` carries none of it and has no dependency edge onto `franken-test-support`.

use crate::SpeakerReadinessState;
use franken_board_profile::{BoardProfile, synthetic_test_fixture_catalog};
use franken_clock::{
    ClockExchangeSample, DEFAULT_MAX_ADMITTED_UNCERTAINTY_US, GroupClockEstimator, LatencyLedger,
};
use franken_control::{
    AirPlay2ReceiverState, AlexaDirective, FsonosSoapRequest, FsonosSoapResponse,
    SpotifySessionState, dispatch_alexa_directive, handle_fsonos_soap,
};
use franken_dsp::{BoardProtectionDsp, BoundedDriftResampler, FRAMES_PER_BLOCK, StereoAudioBlock};
use franken_hal::{AudioHalDevice, HalTelemetry, state as hal_state};
use franken_platform::MemoryBudgetLedger;
use franken_session::{
    ChannelRole, FencedControlCommand, GroupCommandPayload, SessionError, UnifiedGroupSession,
};
use franken_stream::{
    BoundedJitterBuffer, OutboundFrame, PlayoutMode, PlayoutPullDecision, StreamId, StreamKey,
    StreamReceiver, StreamSender,
};
use franken_test_support::{
    AmplifierObservation, BoardObservation, BoundedDiagnosticSink, ClockObservation,
    CommandObservation, DiagnosticEvent, ExpectedSamples, FencedCommandOracle, NetworkSchedule,
    NetworkScheduleConfig, OracleViolation, ReadinessOracle, ReadinessSpec, SampleContinuityOracle,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Synthetic stream key and identity for the simulated house (public test values, not secrets).
/// Every simulated sender and receiver shares them, as a real group shares one stream key and one
/// per-start stream identity.
const CAMPAIGN_STREAM_KEY: [u8; 32] = [0xA5; 32];
const CAMPAIGN_STREAM_ID: u64 = 0x5EED_5EED_0000_0001;

fn campaign_stream_id() -> Result<StreamId, String> {
    StreamId::new(CAMPAIGN_STREAM_ID).map_err(|e| e.to_string())
}

/// Per-speaker node in the Virtual House simulator (`Q01` / `ffw-gmq`).
pub struct VirtualSpeakerNode {
    pub member_id: String,
    pub board: BoardProfile,
    pub readiness: SpeakerReadinessState,
    pub readiness_oracle: ReadinessOracle,
    /// One continuity/content oracle per hardware channel, so no channel is judged on another's evidence.
    pub continuity_oracles: Vec<SampleContinuityOracle>,
    pub clock: GroupClockEstimator,
    /// The only path from datagram bytes to the jitter buffer: structure, MAC, field validation,
    /// stream identity, epoch and replay window, in that order (`N01`).
    pub receiver: StreamReceiver,
    pub jitter_buffer: BoundedJitterBuffer,
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
}

/// Silence blocks the virtual HAL must have primed before it may unmute. Stated by the harness,
/// so the readiness gate does not depend on the HAL's own configuration.
const REQUIRED_SILENCE_BLOCKS: u32 = 2;
const HAL_DMA_SLOTS: u16 = 8;
/// What the readiness gate requires of the clock, stated here and not read back from the
/// estimator. 2 ms is the N03 admission bound; a test pins it against the production constant.
const CLOCK_LOCK_MIN_SAMPLES: u32 = 3;
const CLOCK_LOCK_MAX_UNCERTAINTY_US: u64 = 2_000;
const CLOCK_EXCHANGES: u32 = 4;
/// The simulated clock exchange is built from a known truth, so the estimate can be checked
/// against it instead of against the estimator's own `is_locked()`.
const SIM_TRUE_OFFSET_NS: i64 = 0;
const SIM_ONE_WAY_DELAY_NS: i64 = 400_000;
const SIM_PEER_DWELL_NS: i64 = 50_000;
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
}

impl BringUpPlan {
    const NOMINAL: Self = Self {
        hal_required_silence_blocks: REQUIRED_SILENCE_BLOCKS,
        silence_blocks_primed: REQUIRED_SILENCE_BLOCKS,
        clock_exchanges: CLOCK_EXCHANGES,
        bypass_own_clock_gate: false,
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
    }
}

/// The campaign's fixed block period (256 frames at 48 kHz), in nanoseconds.
const BLOCK_PERIOD_NS: u64 = 5_333_333;

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

        let mut clock = GroupClockEstimator::new(8, DEFAULT_MAX_ADMITTED_UNCERTAINTY_US);
        for seq in 1..=u64::from(plan.clock_exchanges) {
            let t1 = (seq as i64) * 10_000_000;
            let t2 = t1 + SIM_TRUE_OFFSET_NS + SIM_ONE_WAY_DELAY_NS;
            let t3 = t2 + SIM_PEER_DWELL_NS;
            let t4 = t3 - SIM_TRUE_OFFSET_NS + SIM_ONE_WAY_DELAY_NS;
            let sample = ClockExchangeSample::from_four_timestamps(seq, t1, t2, t3, t4)
                .map_err(|e| e.to_string())?;
            clock.ingest_sample(sample);
        }
        if !plan.bypass_own_clock_gate && !clock.is_locked() {
            return Err("clock is not locked".to_string());
        }
        t_ns += BRING_UP_STEP_NS;
        readiness_oracle
            .record_clock(ClockObservation {
                t_ns,
                ingested_samples: plan.clock_exchanges,
                uncertainty_us: clock.uncertainty_us(),
                offset_error_ns: clock
                    .estimated_offset_ns()
                    .saturating_sub(SIM_TRUE_OFFSET_NS),
            })
            .map_err(readiness_err)?;

        t_ns += BRING_UP_STEP_NS;
        readiness_oracle
            .announce_ready(t_ns)
            .map_err(readiness_err)?;

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
            receiver: StreamReceiver::new(
                StreamKey::from_bytes(CAMPAIGN_STREAM_KEY),
                campaign_stream_id()?,
                initial_epoch,
            ),
            jitter_buffer: BoundedJitterBuffer::new(PlayoutMode::Music500ms, 128),
            resampler: BoundedDriftResampler::new(),
            dsp,
            shadow_dsp,
            hal: running,
            rendered_blocks: 0,
            authentic_blocks: 0,
            concealed_blocks: 0,
            handoff_checked_samples: 0,
            max_skew_us: 0,
        })
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
    pub within_2ms_skew_target: bool,
    pub video_sync_residual_us: i64,
    pub video_sync_within_40ms_gate: bool,
    pub dropped_log_events: u64,
    /// False when critical evidence (the campaign summary) could not be stored. A report with
    /// `evidence_complete == false` is incomplete and must not be read as a clean pass.
    pub evidence_complete: bool,
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
    /// Frames verified continuous on every channel (the minimum across channels).
    pub verified_continuous_frames: u64,
    /// Samples compared with the shadow render, summed over every channel. This is a handoff
    /// integrity check, not verification of the DSP's own arithmetic.
    pub handoff_checked_samples: u64,
    pub quarantined_dma_slots: usize,
    pub readiness: SpeakerReadinessState,
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
    let result = run_campaign_inner(seed, total_blocks, fault, sink);
    if let Err(cause) = &result {
        sink.emit_critical(DiagnosticEvent {
            schema_version: String::new(),
            timestamp_mono_ns: total_blocks * BLOCK_PERIOD_NS,
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

fn run_campaign_inner(
    seed: u64,
    total_blocks: u64,
    fault: Option<OutputFault>,
    sink: &mut BoundedDiagnosticSink,
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

        let node = VirtualSpeakerNode::bring_up_admitted(member_id, board, epoch)?;
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

    // The sender owns stream identity, epoch and sequence; sequence 0 is the first block.
    let mut sender = StreamSender::new(
        StreamKey::from_bytes(CAMPAIGN_STREAM_KEY),
        campaign_stream_id()?,
        epoch,
    );
    let block_period_ns: u64 = BLOCK_PERIOD_NS; // 256 / 48_000 s
    let playout_horizon_ns: u64 = 500_000_000; // 500 ms

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
    for blk_idx in 0..total_blocks {
        let start_frame = blk_idx * (FRAMES_PER_BLOCK as u64);
        let send_time_ns = blk_idx * block_period_ns;
        let pts_ns = send_time_ns + playout_horizon_ns;
        let consume_by_ns = pts_ns - block_period_ns;

        let mut src_block = StereoAudioBlock::silence(start_frame);
        let amp = ((blk_idx % 32) as f32) * 0.02 + 0.05;
        src_block.left = [amp; FRAMES_PER_BLOCK];
        src_block.right = [-amp; FRAMES_PER_BLOCK];

        // Blocks are coded in groups of four; the sender assigns `seq == blk_idx`.
        let frame = OutboundFrame {
            fec_group_id: (blk_idx / 4) as u16,
            fec_index: (blk_idx % 4) as u8,
            fec_group_size: 4,
            ..OutboundFrame::media(
                start_frame,
                pts_ns,
                consume_by_ns,
                src_block.to_be_i16_bytes(),
            )
        };
        let wire = sender.send(frame).map_err(|e| e.to_string())?;

        let mut member_dac_cursor_ns = Vec::with_capacity(nodes.len());
        for (member_id, node) in &mut nodes {
            let sched = schedules.get_mut(member_id).unwrap();
            let decision = sched.evaluate_packet(blk_idx, send_time_ns);
            if !decision.dropped
                && let Some(deliver_ns) = decision.deliver_time_ns
            {
                // Each block is delivered to each member at most once, in order, on the member's
                // own stream, so a refusal here is a defect in the framing or the harness, never
                // ordinary loss. Fail the campaign rather than skip it silently. A packet that is
                // merely late is a different matter: `push_packet` counts it and play-out conceals.
                let verified = node.receiver.accept(&wire).map_err(|e| {
                    format!("member {member_id}: block {blk_idx} refused by the receiver: {e}")
                })?;
                let _ = node.jitter_buffer.push_packet(&verified, deliver_ns);
            }

            let gain = session
                .effective_member_gain(member_id)
                .map_err(|e| e.to_string())?;
            node.dsp.set_volume_gain(gain);
            node.shadow_dsp.set_volume_gain(gain);

            let pull = node.jitter_buffer.pull_for_frame(start_frame);
            let stereo_in = match pull {
                PlayoutPullDecision::AuthenticBlock(b)
                | PlayoutPullDecision::FecRecoveredBlock(b) => {
                    node.authentic_blocks += 1;
                    b
                }
                PlayoutPullDecision::PlcConcealedBlock { block, .. } => {
                    node.concealed_blocks += 1;
                    block
                }
            };

            let resampled = node
                .resampler
                .process_stereo(&stereo_in, node.clock.estimated_drift_ppm())
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

            let lease = node.hal.submit_dma_block().map_err(|e| e.to_string())?;
            lease.complete();
            node.rendered_blocks += 1;

            let local_dac_ns = node
                .clock
                .map_presentation_to_local_dac_ns(pts_ns, &node.board)
                .map_err(|e| e.to_string())?;
            // Effective electrical output time adds back the board's calibrated delay
            let electrical_out_ns =
                local_dac_ns + u64::from(node.board.calibrated_output_delay_us) * 1_000;
            member_dac_cursor_ns.push(electrical_out_ns);
        }

        if let (Some(&min_ns), Some(&max_ns)) = (
            member_dac_cursor_ns.iter().min(),
            member_dac_cursor_ns.iter().max(),
        ) {
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
        timestamp_mono_ns: total_blocks * block_period_ns,
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
                verified_continuous_frames: node
                    .continuity_oracles
                    .iter()
                    .map(SampleContinuityOracle::verified_frames)
                    .min()
                    .unwrap_or(0),
                handoff_checked_samples: node.handoff_checked_samples,
                quarantined_dma_slots: hal_t.quarantined_dma_slots,
                readiness: node.readiness.clone(),
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
        within_2ms_skew_target: max_inter_speaker_skew_us <= 2_000,
        video_sync_residual_us: video_eval.residual_av_skew_us,
        video_sync_within_40ms_gate: video_eval.within_40ms_p99_gate,
        dropped_log_events: sink.dropped_event_count(),
        evidence_complete: sink.is_evidence_complete(),
        members: member_stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn harness_clock_bound_matches_the_n03_admission_bound() {
        assert_eq!(
            CLOCK_LOCK_MAX_UNCERTAINTY_US,
            DEFAULT_MAX_ADMITTED_UNCERTAINTY_US
        );
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
        for exchanges in [0u32, 1, 2] {
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
        // Paired positive at the boundary: three exchanges lock the clock.
        let three = BringUpPlan {
            clock_exchanges: 3,
            ..BringUpPlan::NOMINAL
        };
        assert!(bring_up(three).is_ok());
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
}
