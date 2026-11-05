//! The Virtual House harness (`Q01` / `ffw-gmq`) and the readiness UX simulation (`UX01` / `ffw-389`).
//!
//! Everything here is a test harness: it links `franken-test-support` (network impairment schedules,
//! continuity, fencing and readiness oracles, a redacting diagnostic sink). It is compiled only for unit
//! tests or with the off-by-default `harness` Cargo feature, so a default (device) build of
//! `franken-speaker` carries none of it and has no dependency edge onto `franken-test-support`.

use crate::SpeakerReadinessState;
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
    /// The member side of the N03 group clock. The node sounds only when this says so (see `gate_block`).
    pub clock: GroupClock,
    /// The node's own simulated monotonic clock; the group clock is true time. Tests may step it.
    pub sim_clock: SimNodeClock,
    /// The start the session controller last admitted for this node, as N03 planned it.
    pub admitted_plan: Option<StartPlan>,
    /// Whether the controller re-admits a start by itself once the clock is locked again after a reset or expiry.
    pub auto_admit: bool,
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
    /// Blocks the gate let sound, and blocks it replaced with silence at the same stream position.
    pub audible_blocks: u64,
    pub muted_blocks: u64,
    /// Clock correction handed to the legacy resampler: the group clock's ratio in ppm while a rate estimate is in
    /// force. That needs a 4 s span of exchanges, longer than any run the harness makes today, so this is always 0
    /// here; the sign convention against the legacy resampler is untested, and nothing claims it works.
    pub drift_ppm: i32,
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
            audible_blocks: 0,
            muted_blocks: 0,
            drift_ppm: 0,
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
        CAMPAIGN_ORIGIN_NS + blk_idx * BLOCK_PERIOD_NS + PLAYOUT_HORIZON_NS
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
        let send_true = CAMPAIGN_ORIGIN_NS + blk_idx * BLOCK_PERIOD_NS;
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
    /// Blocks in which every member sounded, so the skew above covers every member, and blocks in which at least
    /// one did not (it was muted), where there is nothing to compare. A run with an unmeasured block does not
    /// meet the target: a skew measured over fewer members than the group has is not a measurement of the group.
    pub skew_measured_blocks: u64,
    pub skew_unmeasured_blocks: u64,
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
    /// Blocks the N03 audible gate let sound, and blocks it muted (replaced with silence at the same position).
    pub audible_blocks: u64,
    pub muted_blocks: u64,
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

        let plan = match fault {
            Some(OutputFault::UnadmittedExcept { member_id: kept }) if kept != member_id => {
                BringUpPlan {
                    first_start_block: None,
                    auto_admit: false,
                    ..BringUpPlan::NOMINAL
                }
            }
            _ => BringUpPlan::NOMINAL,
        };
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

    // The sender owns stream identity, epoch and sequence; sequence 0 is the first block.
    let mut sender = StreamSender::new(
        StreamKey::from_bytes(CAMPAIGN_STREAM_KEY),
        campaign_stream_id()?,
        epoch,
    );
    let block_period_ns: u64 = BLOCK_PERIOD_NS; // 256 / 48_000 s
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

        let mut presented_true = Vec::with_capacity(nodes.len());
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

            // The audible gate: N03's answer for this block's presentation instant.
            let gate = node.gate_block(blk_idx);
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
            // A block the gate does not let sound is replaced by silence at the same stream position, so the
            // continuity and shadow oracles still judge contiguous frames.
            let stereo_in = if gate.audible() {
                node.audible_blocks += 1;
                stereo_in
            } else {
                node.muted_blocks += 1;
                StereoAudioBlock::silence(start_frame)
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

            let lease = node.hal.submit_dma_block().map_err(|e| e.to_string())?;
            lease.complete();
            node.rendered_blocks += 1;

            // Where this node really presents the block: its own transform's local instant, mapped back to true time.
            if let Some(true_ns) = node.presented_true_ns(&gate) {
                presented_true.push(true_ns);
            }
        }

        if presented_true.len() == nodes.len() {
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
                audible_blocks: node.audible_blocks,
                muted_blocks: node.muted_blocks,
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
        skew_measured_blocks,
        skew_unmeasured_blocks,
        within_2ms_skew_target: max_inter_speaker_skew_us <= 2_000 && skew_unmeasured_blocks == 0,
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
            // The presented sample position: the frame at that group time is the block's first frame, to within one
            // frame (the block period is rounded to a whole number of nanoseconds).
            let frame_at = (pts - first_pts) * 48_000 / 1_000_000_000;
            let block_frame = blk * (FRAMES_PER_BLOCK as u64);
            assert!(
                frame_at.abs_diff(block_frame) <= 1,
                "block {blk}: frame {frame_at} vs {block_frame}"
            );
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
}
