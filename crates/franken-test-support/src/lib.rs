//! Early deterministic test, receipt, oracle, and bounded logging infrastructure (`Q00` / `ffw-2qz`).
//!
//! Bootstraps independently without importing any production speaker crates so that
//! foundational harnesses (`Q00`, `E07`, `E01`, `E03`, `P01`, `P05`) and later
//! subsystem crates share a single deterministic oracle and receipt contract.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const LOG_SCHEMA_VERSION: &str = "ffw.log.v1";
pub const RECEIPT_SCHEMA_VERSION: &str = "ffw.suite_receipt.v1";

/// Execution tier selected by CI or developer runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestTier {
    Smoke,
    Full,
    Soak,
}

/// Evidence class distinguishing simulation from guest or external receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    HostSimulation,
    FullSystemGuestExecution,
    CpuUserModeEmulation,
    ExternalAuthorizedReceipt,
}

/// Outcome of an individual registered test case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseOutcome {
    Passed,
    Failed,
    Blocked,
    NotRun,
}

/// Deterministic virtual monotonic clock in nanoseconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualClock {
    now_ns: u64,
    resolution_ns: u64,
}

impl VirtualClock {
    #[must_use]
    pub const fn new(start_ns: u64, resolution_ns: u64) -> Self {
        Self {
            now_ns: start_ns,
            resolution_ns: if resolution_ns == 0 { 1 } else { resolution_ns },
        }
    }

    #[must_use]
    pub const fn now_ns(&self) -> u64 {
        self.now_ns
    }

    #[must_use]
    pub const fn resolution_ns(&self) -> u64 {
        self.resolution_ns
    }

    pub fn advance_ns(&mut self, delta_ns: u64) -> u64 {
        self.now_ns = self.now_ns.saturating_add(delta_ns);
        self.now_ns
    }
}

/// Deterministic SplitMix64 PRNG for reproducible fault and network schedules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn next_permille(&mut self) -> u32 {
        (self.next_u64() % 1000) as u32
    }
}

/// Frozen network schedule parameters matching the provisional qualification profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkScheduleConfig {
    pub seed: u64,
    /// Independent packet loss in parts per 10,000 (100 = 1.0%).
    pub independent_loss_bps: u32,
    /// Burst loss duration in nanoseconds (e.g. 100_000_000 = 100 ms).
    pub burst_loss_duration_ns: u64,
    /// Minimum interval between burst losses in nanoseconds (e.g. 10_000_000_000 = 10 s).
    pub burst_loss_interval_ns: u64,
    /// Maximum added jitter in nanoseconds (e.g. 50_000_000 = 50 ms).
    pub max_jitter_ns: u64,
    /// Duplicate packet rate in parts per 10,000.
    pub duplicate_bps: u32,
}

impl Default for NetworkScheduleConfig {
    fn default() -> Self {
        Self {
            seed: 0xFF00_2026_0001_u64,
            independent_loss_bps: 100,              // 1%
            burst_loss_duration_ns: 100_000_000,    // 100 ms
            burst_loss_interval_ns: 10_000_000_000, // 10 s
            max_jitter_ns: 50_000_000,              // 50 ms
            duplicate_bps: 25,                      // 0.25%
        }
    }
}

/// Resulting delivery action for a scheduled packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketDeliveryDecision {
    pub seq: u64,
    pub send_time_ns: u64,
    pub dropped: bool,
    pub in_burst_outage: bool,
    pub deliver_time_ns: Option<u64>,
    pub duplicate_deliver_time_ns: Option<u64>,
}

/// Deterministic network schedule evaluator.
#[derive(Debug, Clone)]
pub struct NetworkSchedule {
    cfg: NetworkScheduleConfig,
    rng: DeterministicRng,
}

impl NetworkSchedule {
    #[must_use]
    pub const fn new(cfg: NetworkScheduleConfig) -> Self {
        let rng = DeterministicRng::new(cfg.seed);
        Self { cfg, rng }
    }

    pub fn evaluate_packet(&mut self, seq: u64, send_time_ns: u64) -> PacketDeliveryDecision {
        let in_burst = if self.cfg.burst_loss_interval_ns > 0 && self.cfg.burst_loss_duration_ns > 0
        {
            let phase = send_time_ns % self.cfg.burst_loss_interval_ns;
            let burst_start = self.cfg.burst_loss_interval_ns / 2;
            phase >= burst_start
                && phase < burst_start.saturating_add(self.cfg.burst_loss_duration_ns)
        } else {
            false
        };

        let loss_roll = (self.rng.next_u64() % 10_000) as u32;
        let jitter_roll = if self.cfg.max_jitter_ns > 0 {
            self.rng.next_u64() % (self.cfg.max_jitter_ns + 1)
        } else {
            0
        };
        let dup_roll = (self.rng.next_u64() % 10_000) as u32;

        if in_burst || loss_roll < self.cfg.independent_loss_bps {
            return PacketDeliveryDecision {
                seq,
                send_time_ns,
                dropped: true,
                in_burst_outage: in_burst,
                deliver_time_ns: None,
                duplicate_deliver_time_ns: None,
            };
        }

        let deliver_ns = send_time_ns.saturating_add(jitter_roll);
        let dup_ns = if dup_roll < self.cfg.duplicate_bps {
            Some(deliver_ns.saturating_add(1_000_000))
        } else {
            None
        };

        PacketDeliveryDecision {
            seq,
            send_time_ns,
            dropped: false,
            in_burst_outage: false,
            deliver_time_ns: Some(deliver_ns),
            duplicate_deliver_time_ns: dup_ns,
        }
    }
}

/// Oracle violation errors. Every canary defect must trigger its specific variant.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum OracleViolation {
    #[error(
        "sample continuity violation at frame {expected_frame}: got {observed_frame} ({reason})"
    )]
    SampleDiscontinuity {
        expected_frame: u64,
        observed_frame: u64,
        reason: String,
    },
    #[error(
        "stale epoch violation: current epoch is {current_epoch}, rejected command from epoch {candidate_epoch}"
    )]
    StaleEpochAccepted {
        current_epoch: u64,
        candidate_epoch: u64,
    },
    #[error(
        "double-applied command violation: epoch {epoch} command_seq {command_seq} applied more than once"
    )]
    DoubleAppliedCommand { epoch: u64, command_seq: u64 },
    #[error(
        "false-ready state violation: entered Ready while prerequisite `{missing_prerequisite}` was unsatisfied"
    )]
    FalseReadyState { missing_prerequisite: String },
    #[error(
        "block length mismatch: frame_count {frame_count} but {observed_samples} samples were supplied"
    )]
    BlockLengthMismatch {
        frame_count: u64,
        observed_samples: u64,
    },
    #[error(
        "wrong sample at frame {frame}: expected {expected}, observed {observed} (tolerance {tolerance})"
    )]
    WrongSample {
        frame: u64,
        expected: i16,
        observed: i16,
        tolerance: u16,
    },
    #[error(
        "truncated stream: {verified_frames} of {expected_total_frames} expected frames were verified"
    )]
    TruncatedStream {
        expected_total_frames: u64,
        verified_frames: u64,
    },
    #[error(
        "overrun stream: {verified_frames} frames were verified but only {expected_total_frames} were expected"
    )]
    OverrunStream {
        expected_total_frames: u64,
        verified_frames: u64,
    },
    #[error(
        "premature unmute: amplifier observed unmuted with {primed_blocks} primed silence blocks, {required_blocks} required"
    )]
    PrematureUnmute {
        primed_blocks: u32,
        required_blocks: u32,
    },
    #[error("probe out of order: observed t={observed_ns} ns after t={previous_ns} ns")]
    ProbeOutOfOrder { previous_ns: u64, observed_ns: u64 },
    #[error(
        "future epoch accepted: authority epoch is {authority_epoch} but a command from epoch {command_epoch} was applied"
    )]
    FutureEpochAccepted {
        authority_epoch: u64,
        command_epoch: u64,
    },
    #[error(
        "future epoch adopted: authority epoch is {authority_epoch} but the system now reports epoch {system_epoch}"
    )]
    FutureEpochAdopted {
        authority_epoch: u64,
        system_epoch: u64,
    },
    #[error("phantom command {command_id}: reported by the system but never issued")]
    PhantomCommand { command_id: u64 },
    #[error("authority epoch regressed: declared {declared_epoch} after {current_epoch}")]
    AuthorityRegressed {
        current_epoch: u64,
        declared_epoch: u64,
    },
    #[error("command tracking overflow: more than {limit} commands tracked")]
    CommandTrackingOverflow { limit: usize },
}

/// Independent source of the samples a single output channel must carry, one value per frame.
///
/// An implementation must be derived from the programme that was injected, never from the
/// device-under-test's own output, or the oracle would only be agreeing with itself.
pub trait ExpectedSamples {
    fn expected(&self, frame: u64) -> i16;
}

/// Stateless random-access synthetic reference signal (test programme, never real audio).
///
/// `expected(frame)` is the `(frame + 1)`-th output of a SplitMix64 stream started at `key`
/// (top 16 bits, two's complement), so any block can be verified in any order without trusting
/// the device's frame counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeededReferenceSignal {
    key: u64,
}

impl SeededReferenceSignal {
    #[must_use]
    pub const fn new(key: u64) -> Self {
        Self { key }
    }
}

impl ExpectedSamples for SeededReferenceSignal {
    fn expected(&self, frame: u64) -> i16 {
        let state = self
            .key
            .wrapping_add(frame.wrapping_add(1).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        (z >> 48) as u16 as i16
    }
}

/// Oracle 1: Sample continuity, block-shape and content verifier for one output channel.
///
/// `observe_block` checks frame continuity and that exactly `frame_count` samples were supplied.
/// It cannot know what the values should be. `observe_block_against` additionally compares every
/// sample with an independent [`ExpectedSamples`] reference. `finalize` rejects a stream that
/// ended early, ran long, or was never observed at all. A rejected block leaves the oracle's
/// position unchanged, so the first fault stays the reported one.
#[derive(Debug, Clone, Default)]
pub struct SampleContinuityOracle {
    next_expected_frame: Option<u64>,
    verified_frames: u64,
}

impl SampleContinuityOracle {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_expected_frame: None,
            verified_frames: 0,
        }
    }

    fn check_block(
        &self,
        start_frame: u64,
        frame_count: u64,
        samples_i16: &[i16],
    ) -> Result<(), OracleViolation> {
        if frame_count == 0 || samples_i16.is_empty() {
            return Err(OracleViolation::SampleDiscontinuity {
                expected_frame: self.next_expected_frame.unwrap_or(start_frame),
                observed_frame: start_frame,
                reason: "empty audio block submitted to output oracle".to_string(),
            });
        }
        if samples_i16.len() as u64 != frame_count {
            return Err(OracleViolation::BlockLengthMismatch {
                frame_count,
                observed_samples: samples_i16.len() as u64,
            });
        }
        if let Some(expected) = self.next_expected_frame
            && start_frame != expected
        {
            return Err(OracleViolation::SampleDiscontinuity {
                expected_frame: expected,
                observed_frame: start_frame,
                reason: "unannounced frame gap or overlap".to_string(),
            });
        }
        Ok(())
    }

    fn commit_block(&mut self, start_frame: u64, frame_count: u64) {
        self.next_expected_frame = Some(start_frame.saturating_add(frame_count));
        self.verified_frames = self.verified_frames.saturating_add(frame_count);
    }

    /// Continuity and shape only: the block must be non-empty, carry exactly `frame_count`
    /// samples, and start where the previous block ended.
    pub fn observe_block(
        &mut self,
        start_frame: u64,
        frame_count: u64,
        samples_i16: &[i16],
    ) -> Result<(), OracleViolation> {
        self.check_block(start_frame, frame_count, samples_i16)?;
        self.commit_block(start_frame, frame_count);
        Ok(())
    }

    /// Everything `observe_block` checks, plus every sample must be within `max_abs_error` of the
    /// independent `reference` at its frame. Use `0` for bit-exact paths.
    pub fn observe_block_against(
        &mut self,
        start_frame: u64,
        frame_count: u64,
        samples_i16: &[i16],
        reference: &dyn ExpectedSamples,
        max_abs_error: u16,
    ) -> Result<(), OracleViolation> {
        self.check_block(start_frame, frame_count, samples_i16)?;
        for (offset, &observed) in samples_i16.iter().enumerate() {
            let frame = start_frame.saturating_add(offset as u64);
            let expected = reference.expected(frame);
            let diff = (i32::from(observed) - i32::from(expected)).unsigned_abs();
            if diff > u32::from(max_abs_error) {
                return Err(OracleViolation::WrongSample {
                    frame,
                    expected,
                    observed,
                    tolerance: max_abs_error,
                });
            }
        }
        self.commit_block(start_frame, frame_count);
        Ok(())
    }

    /// Declare the stream finished. Exactly `expected_total_frames` frames must have been
    /// verified; a stream that was never observed fails even when zero frames were expected.
    pub fn finalize(&self, expected_total_frames: u64) -> Result<(), OracleViolation> {
        if self.verified_frames == 0 || self.verified_frames < expected_total_frames {
            return Err(OracleViolation::TruncatedStream {
                expected_total_frames,
                verified_frames: self.verified_frames,
            });
        }
        if self.verified_frames > expected_total_frames {
            return Err(OracleViolation::OverrunStream {
                expected_total_frames,
                verified_frames: self.verified_frames,
            });
        }
        Ok(())
    }

    #[must_use]
    pub const fn verified_frames(&self) -> u64 {
        self.verified_frames
    }
}

/// What the harness saw when it handed one command to the system under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandObservation {
    /// Harness-assigned identity of the logical command (not the system's own key).
    pub command_id: u64,
    /// Whether the system reported the command as applied.
    pub applied: bool,
    /// The epoch the system reports as current after handling the command, read back from the
    /// system and not from the command.
    pub system_epoch_after: u64,
}

/// Oracles 2 and 3: epoch fencing and single application, judged against harness truth.
///
/// The harness declares which coordinator epoch is authoritative (`declare_authority`) and
/// records every command it issues (`record_issued`). `observe_outcome` then judges what the
/// system did. The system's own epoch bookkeeping is never the source of truth: the previous
/// oracle learned epochs only from commands the system had already accepted, so a fence that
/// never advanced, or advanced on the wrong evidence, went unnoticed. A system epoch that moves
/// past the declared authority is a violation even when the command that moved it was rejected.
/// Tracking is bounded; overflow is reported, not ignored.
#[derive(Debug, Clone)]
pub struct FencedCommandOracle {
    authority_epoch: u64,
    issued: BTreeMap<u64, (u64, u64)>,
    applied: BTreeSet<u64>,
    max_tracked: usize,
}

impl FencedCommandOracle {
    pub const DEFAULT_MAX_TRACKED: usize = 10_000;

    #[must_use]
    pub fn new(initial_authority_epoch: u64) -> Self {
        Self::with_capacity(initial_authority_epoch, Self::DEFAULT_MAX_TRACKED)
    }

    #[must_use]
    pub fn with_capacity(initial_authority_epoch: u64, max_tracked: usize) -> Self {
        Self {
            authority_epoch: initial_authority_epoch,
            issued: BTreeMap::new(),
            applied: BTreeSet::new(),
            max_tracked,
        }
    }

    #[must_use]
    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    /// Truth: the harness elected a new coordinator epoch. It can only move forward.
    pub fn declare_authority(&mut self, epoch: u64) -> Result<(), OracleViolation> {
        if epoch < self.authority_epoch {
            return Err(OracleViolation::AuthorityRegressed {
                current_epoch: self.authority_epoch,
                declared_epoch: epoch,
            });
        }
        self.authority_epoch = epoch;
        Ok(())
    }

    /// Truth: the harness issued this command. Call once per logical command, then
    /// `observe_outcome` for every delivery of it (a duplicate delivery is a second outcome).
    pub fn record_issued(
        &mut self,
        command_id: u64,
        epoch: u64,
        command_seq: u64,
    ) -> Result<(), OracleViolation> {
        if !self.issued.contains_key(&command_id) && self.issued.len() >= self.max_tracked {
            return Err(OracleViolation::CommandTrackingOverflow {
                limit: self.max_tracked,
            });
        }
        self.issued.insert(command_id, (epoch, command_seq));
        Ok(())
    }

    /// Judge one delivery. Rejecting a stale or duplicate command is permitted behaviour.
    pub fn observe_outcome(&mut self, obs: CommandObservation) -> Result<(), OracleViolation> {
        let Some(&(epoch, command_seq)) = self.issued.get(&obs.command_id) else {
            return Err(OracleViolation::PhantomCommand {
                command_id: obs.command_id,
            });
        };
        if obs.applied {
            if epoch < self.authority_epoch {
                return Err(OracleViolation::StaleEpochAccepted {
                    current_epoch: self.authority_epoch,
                    candidate_epoch: epoch,
                });
            }
            if epoch > self.authority_epoch {
                return Err(OracleViolation::FutureEpochAccepted {
                    authority_epoch: self.authority_epoch,
                    command_epoch: epoch,
                });
            }
            if !self.applied.insert(obs.command_id) {
                return Err(OracleViolation::DoubleAppliedCommand { epoch, command_seq });
            }
        }
        if obs.system_epoch_after > self.authority_epoch {
            return Err(OracleViolation::FutureEpochAdopted {
                authority_epoch: self.authority_epoch,
                system_epoch: obs.system_epoch_after,
            });
        }
        Ok(())
    }
}

/// What "ready" requires, stated by the harness. These numbers are never read back from the
/// device under test, or the oracle would only be agreeing with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadinessSpec {
    /// Silence blocks that must be primed before the amplifier may be unmuted.
    pub required_primed_silence_blocks: u32,
    /// Clock exchanges that must have been ingested before the clock may count as locked.
    pub min_clock_samples: u32,
    /// Largest clock uncertainty, in microseconds, that still counts as locked.
    pub max_clock_uncertainty_us: u64,
}

/// Board-profile evidence at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoardObservation {
    pub t_ns: u64,
    pub integrity_ok: bool,
    pub routing_consistent: bool,
}

/// Amplifier read-back at one instant: the hardware mute pin and the prime counter as the
/// hardware layer reports them (for example HAL telemetry), not the bring-up code's own flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmplifierObservation {
    pub t_ns: u64,
    pub muted: bool,
    pub primed_silence_blocks: u32,
}

/// Clock evidence at one instant as raw facts. `offset_error_ns` is the estimator's offset minus
/// the offset the harness injected, so a clock cannot vouch for itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockObservation {
    pub t_ns: u64,
    pub ingested_samples: u32,
    pub uncertainty_us: u64,
    pub offset_error_ns: i64,
}

/// Oracle 4: Speaker readiness gate verifier, driven by an observed probe history.
///
/// Prerequisites are never set by the code under test. The harness records observations as the
/// bring-up proceeds, then `announce_ready` checks the history against the independent
/// [`ReadinessSpec`]. A premature unmute is reported the moment it is observed and is not
/// forgiven by priming afterwards. Simulation-only: the observations come from simulated
/// components, which says nothing about real hardware.
#[derive(Debug, Clone)]
pub struct ReadinessOracle {
    spec: ReadinessSpec,
    last_t_ns: u64,
    board: Option<BoardObservation>,
    clock: Option<ClockObservation>,
    amplifier_seen_muted: bool,
    amplifier_premature_unmute: bool,
    amplifier_last: Option<AmplifierObservation>,
    announced: bool,
}

impl ReadinessOracle {
    #[must_use]
    pub const fn new(spec: ReadinessSpec) -> Self {
        Self {
            spec,
            last_t_ns: 0,
            board: None,
            clock: None,
            amplifier_seen_muted: false,
            amplifier_premature_unmute: false,
            amplifier_last: None,
            announced: false,
        }
    }

    fn advance(&mut self, t_ns: u64) -> Result<(), OracleViolation> {
        if t_ns < self.last_t_ns {
            return Err(OracleViolation::ProbeOutOfOrder {
                previous_ns: self.last_t_ns,
                observed_ns: t_ns,
            });
        }
        self.last_t_ns = t_ns;
        Ok(())
    }

    pub fn record_board(&mut self, obs: BoardObservation) -> Result<(), OracleViolation> {
        self.advance(obs.t_ns)?;
        self.board = Some(obs);
        Ok(())
    }

    /// Record an amplifier read-back. An unmuted observation with fewer primed silence blocks
    /// than the spec requires is a violation at once and stays recorded.
    pub fn record_amplifier(&mut self, obs: AmplifierObservation) -> Result<(), OracleViolation> {
        self.advance(obs.t_ns)?;
        self.amplifier_last = Some(obs);
        if obs.muted {
            self.amplifier_seen_muted = true;
            return Ok(());
        }
        if obs.primed_silence_blocks < self.spec.required_primed_silence_blocks {
            self.amplifier_premature_unmute = true;
            return Err(OracleViolation::PrematureUnmute {
                primed_blocks: obs.primed_silence_blocks,
                required_blocks: self.spec.required_primed_silence_blocks,
            });
        }
        Ok(())
    }

    pub fn record_clock(&mut self, obs: ClockObservation) -> Result<(), OracleViolation> {
        self.advance(obs.t_ns)?;
        self.clock = Some(obs);
        Ok(())
    }

    /// The device claims to be ready: check the observed history, not the device's word.
    pub fn announce_ready(&mut self, t_ns: u64) -> Result<(), OracleViolation> {
        self.advance(t_ns)?;
        if let Some(missing) = self.first_missing_prerequisite() {
            return Err(OracleViolation::FalseReadyState {
                missing_prerequisite: missing.to_string(),
            });
        }
        self.announced = true;
        Ok(())
    }

    fn first_missing_prerequisite(&self) -> Option<&'static str> {
        let board_ok = self
            .board
            .is_some_and(|b| b.integrity_ok && b.routing_consistent);
        if !board_ok {
            return Some("board_profile_verified");
        }
        let amplifier_ok = self.amplifier_seen_muted
            && !self.amplifier_premature_unmute
            && self.amplifier_last.is_some_and(|a| {
                !a.muted && a.primed_silence_blocks >= self.spec.required_primed_silence_blocks
            });
        if !amplifier_ok {
            return Some("amplifier_muted_until_primed");
        }
        let clock_ok = self.clock.is_some_and(|c| {
            c.ingested_samples >= self.spec.min_clock_samples
                && c.uncertainty_us <= self.spec.max_clock_uncertainty_us
                && c.offset_error_ns.unsigned_abs() <= c.uncertainty_us.saturating_mul(1_000)
        });
        if !clock_ok {
            return Some("clock_locked");
        }
        None
    }

    #[must_use]
    pub const fn is_announced(&self) -> bool {
        self.announced
    }
}

const REDACTED_SECRET: &str = "[REDACTED_SECRET]";
const REDACTED_ID: &str = "[REDACTED_ID]";
const REDACTED_LAN_IP: &str = "[REDACTED_LAN_IP]";
const REDACTED_MAC: &str = "[REDACTED_MAC]";
const REDACTED_AUDIO: &str = "[REDACTED_AUDIO]";
/// Every complete marker this module writes, and the only values treated as already redacted.
const REDACTION_MARKERS: [&str; 5] = [
    REDACTED_SECRET,
    REDACTED_ID,
    REDACTED_LAN_IP,
    REDACTED_MAC,
    REDACTED_AUDIO,
];

/// Key names, matched as a lowercase suffix, whose values are secrets.
const SECRET_KEY_SUFFIXES: &[&str] = &[
    "token",
    "secret",
    "key",
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "credential",
    "credentials",
    "cookie",
    "auth",
];

/// Key names, matched exactly with `-` folded to `_`, whose values identify a device, a
/// household or a person.
const IDENTIFIER_KEYS: &[&str] = &[
    "serial",
    "serial_number",
    "serialnumber",
    "sn",
    "hhid",
    "household",
    "household_id",
    "householdid",
    "udn",
    "uuid",
    "mac",
    "mac_address",
    "macaddress",
];

/// Key names, matched exactly with `-` folded to `_`, whose values are audio payloads. Matched
/// exactly so counters such as `num_samples=480` or `payload_len=1024` are left alone.
const AUDIO_KEYS: &[&str] = &[
    "payload",
    "samples",
    "pcm",
    "audio",
    "audio_payload",
    "audio_data",
    "audio_samples",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Secret,
    Identifier,
    Authorization,
    Audio,
}

fn classify_key(name: &str) -> Option<KeyKind> {
    let folded: String = name
        .chars()
        .map(|c| {
            if c == '-' {
                '_'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    if folded == "authorization" || folded == "proxy_authorization" {
        return Some(KeyKind::Authorization);
    }
    if AUDIO_KEYS.contains(&folded.as_str()) {
        return Some(KeyKind::Audio);
    }
    if IDENTIFIER_KEYS.contains(&folded.as_str()) {
        return Some(KeyKind::Identifier);
    }
    if SECRET_KEY_SUFFIXES
        .iter()
        .any(|suffix| folded.ends_with(*suffix))
    {
        return Some(KeyKind::Secret);
    }
    None
}

fn is_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_credential_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'+' | b'/' | b'=')
}

fn is_hex_byte(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn is_alnum_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn is_ipv6_byte(b: u8) -> bool {
    b.is_ascii_hexdigit() || b == b':'
}

/// Shorter words after "bearer" are prose ("the bearer of news"), not credentials.
const MIN_BEARER_CREDENTIAL_LEN: usize = 8;

/// `Bearer <credential>` anywhere in the text. (`Basic` is not matched: it is an ordinary word.)
fn redact_bearer_credentials(input: &str) -> String {
    const SCHEME: &[u8] = b"bearer";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let at_word_start = i == 0 || !is_word_byte(bytes[i - 1]);
        if at_word_start
            && bytes.len() - i >= SCHEME.len()
            && bytes[i..i + SCHEME.len()].eq_ignore_ascii_case(SCHEME)
        {
            let mut j = i + SCHEME.len();
            let gap_start = j;
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
                j += 1;
            }
            let credential_start = j;
            while j < bytes.len() && is_credential_byte(bytes[j]) {
                j += 1;
            }
            if credential_start > gap_start && j - credential_start >= MIN_BEARER_CREDENTIAL_LEN {
                out.push_str(&input[last..credential_start]);
                out.push_str(REDACTED_SECRET);
                last = j;
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&input[last..]);
    out
}

/// `name=value`, `name: value`, `"name":"value"` and URL-query pairs. Only the value is replaced.
fn redact_key_values(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let sep = bytes[i];
        if sep != b'=' && sep != b':' {
            i += 1;
            continue;
        }
        let mut name_end = i;
        if name_end > 0 && matches!(bytes[name_end - 1], b'"' | b'\'') {
            name_end -= 1;
        }
        let mut name_start = name_end;
        while name_start > 0 && is_key_byte(bytes[name_start - 1]) {
            name_start -= 1;
        }
        let kind = if name_start < name_end && name_start >= last {
            classify_key(&input[name_start..name_end])
        } else {
            None
        };
        let Some(kind) = kind else {
            i += 1;
            continue;
        };
        let mut value_start = i + 1;
        if sep == b':' {
            while value_start < bytes.len() && matches!(bytes[value_start], b' ' | b'\t') {
                value_start += 1;
            }
        }
        let quote = match bytes.get(value_start) {
            Some(&q) if q == b'"' || q == b'\'' => Some(q),
            _ => None,
        };
        if quote.is_some() {
            value_start += 1;
        }
        // An unquoted array of samples runs through its closing bracket, not just to the first
        // space or comma.
        let audio_array =
            kind == KeyKind::Audio && quote.is_none() && bytes.get(value_start) == Some(&b'[');
        let mut value_end = value_start;
        // A bracket opened inside an unquoted value is closed inside it. `]`, `)` and `}` are
        // delimiters only when nothing in the value opened them. Without this, a value such as
        // `Bearer [REDACTED_SECRET]` (the bearer pass has already run) or `[x]glued-secret` ended
        // at its first `]`, which left a stray `]` and the text after it, secret included, in
        // the output. A closer is only ever consumed here, never searched for, so the scan stays
        // linear and cannot run past the delimiters below (whitespace, `\n`, `&`, ...).
        let mut depth = 0usize;
        while value_end < bytes.len() {
            let b = bytes[value_end];
            if quote.is_none() && !audio_array {
                match b {
                    b'[' | b'(' | b'{' => depth += 1,
                    b']' | b')' | b'}' if depth > 0 => {
                        depth -= 1;
                        value_end += 1;
                        continue;
                    }
                    _ => {}
                }
            }
            let stop = match quote {
                Some(q) => b == q || b == b'\n',
                None if audio_array => b == b']',
                None if kind == KeyKind::Authorization => matches!(
                    b,
                    b'\n' | b'"' | b'\'' | b',' | b'}' | b']' | b')' | b'&' | b';'
                ),
                None => {
                    b.is_ascii_whitespace()
                        || matches!(b, b'&' | b';' | b',' | b'"' | b'\'' | b')' | b']' | b'}')
                }
            };
            if stop {
                break;
            }
            value_end += 1;
        }
        if audio_array && value_end < bytes.len() {
            value_end += 1; // include the closing bracket
        }
        // Already redacted means the value is exactly one finished marker. A value that merely
        // starts like one (`[REDACTED_]secret`, `[REDACTED_SECRET]secret`) still holds a secret.
        let value = &input[value_start..value_end];
        if value.is_empty() || REDACTION_MARKERS.contains(&value) {
            i += 1;
            continue;
        }
        let marker = match kind {
            KeyKind::Identifier => REDACTED_ID,
            KeyKind::Audio => REDACTED_AUDIO,
            KeyKind::Secret | KeyKind::Authorization => REDACTED_SECRET,
        };
        out.push_str(&input[last..value_start]);
        out.push_str(marker);
        last = value_end;
        i = value_end;
    }
    out.push_str(&input[last..]);
    out
}

/// Six hex pairs joined by `:` or `-` (the same separator throughout) starting at `bytes[0]`.
fn is_mac_at(bytes: &[u8]) -> bool {
    if bytes.len() < 17 {
        return false;
    }
    let sep = bytes[2];
    if sep != b':' && sep != b'-' {
        return false;
    }
    for group in 0..6 {
        let at = group * 3;
        if !(bytes[at].is_ascii_hexdigit() && bytes[at + 1].is_ascii_hexdigit()) {
            return false;
        }
        if group < 5 && bytes[at + 2] != sep {
            return false;
        }
    }
    true
}

/// Colon- and dash-separated MACs, including when glued to a key (`mac=00:0E:...`).
fn redact_mac_addresses(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let boundary_before = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if boundary_before && is_mac_at(&bytes[i..]) {
            let end = i + 17;
            if end == bytes.len() || !bytes[end].is_ascii_alphanumeric() {
                out.push_str(&input[last..i]);
                out.push_str(REDACTED_MAC);
                last = end;
                i = end;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&input[last..]);
    out
}

fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = text.split('.');
    for slot in &mut octets {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 {
            return None;
        }
        *slot = part.parse::<u8>().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(octets)
}

/// RFC 1918, link-local, and the `100.64.0.0/10` shared range that Tailscale tailnets use.
fn is_sensitive_ipv4(octets: [u8; 4]) -> bool {
    let [a, b, _, _] = octets;
    a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 169 && b == 254)
        || (a == 100 && (64..=127).contains(&b))
}

fn redact_private_ipv4(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let starts_numeric_run =
            bytes[i].is_ascii_digit() && (i == 0 || !matches!(bytes[i - 1], b'0'..=b'9' | b'.'));
        if starts_numeric_run {
            let mut j = i;
            while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b'.') {
                j += 1;
            }
            let mut end = j;
            while end > i && bytes[end - 1] == b'.' {
                end -= 1;
            }
            if let Some(octets) = parse_ipv4(&input[i..end])
                && is_sensitive_ipv4(octets)
            {
                out.push_str(&input[last..i]);
                out.push_str(REDACTED_LAN_IP);
                last = end;
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out.push_str(&input[last..]);
    out
}

/// IPv6 unique-local (`fc00::/7`, which includes Tailscale's `fd7a:115c:a1e0::/48`) and link-local.
fn redact_private_ipv6(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if is_ipv6_byte(bytes[i]) && (i == 0 || !is_ipv6_byte(bytes[i - 1])) {
            let mut j = i;
            while j < bytes.len() && is_ipv6_byte(bytes[j]) {
                j += 1;
            }
            let run = &input[i..j];
            let lower = run.to_ascii_lowercase();
            let colons = run.bytes().filter(|&b| b == b':').count();
            if colons >= 2
                && (lower.starts_with("fc") || lower.starts_with("fd") || lower.starts_with("fe80"))
            {
                out.push_str(&input[last..i]);
                out.push_str(REDACTED_LAN_IP);
                last = j;
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out.push_str(&input[last..]);
    out
}

/// `prefix` followed by at least `min_tail` tail characters, at a word start. The prefix is kept.
fn redact_prefixed_ids(
    input: &str,
    prefix: &str,
    min_tail: usize,
    is_tail: fn(u8) -> bool,
) -> String {
    let bytes = input.as_bytes();
    let prefix_bytes = prefix.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i..].starts_with(prefix_bytes) && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
        {
            let tail_start = i + prefix_bytes.len();
            let mut j = tail_start;
            while j < bytes.len() && is_tail(bytes[j]) {
                j += 1;
            }
            if j - tail_start >= min_tail {
                out.push_str(&input[last..tail_start]);
                out.push_str(REDACTED_ID);
                last = j;
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&input[last..]);
    out
}

/// Redact secrets and site identifiers in diagnostic text, in place, preserving everything else
/// (including whitespace) exactly.
///
/// Covered: `Bearer` credentials; values of secret-named keys (`token`, `secret`, `key`,
/// `password`, `cookie`, `auth`, ... matched case-insensitively as a suffix) and of identifier keys
/// (`serial`, `sn`, `hhid`, `household`, `udn`, `uuid`, `mac`, ...) in `name=value`, `name: value`,
/// JSON and URL-query form; the `Authorization` header (unquoted, up to the next delimiter or the
/// end of its line, so the words after it on that line are redacted too); colon- and
/// dash-separated MACs; RFC 1918, link-local and `100.64.0.0/10` IPv4 addresses; IPv6 unique-local
/// and link-local addresses; and `RINCON_`, `Sonos_` and `HHID_` identifiers.
///
/// A bracket opened inside an unquoted value closes inside it, so `[x]y` is one value. A value that
/// is exactly one finished `[REDACTED_*]` marker is already redacted and is left alone; a value
/// that merely starts like one (`[REDACTED_]secret`) is redacted like any other.
///
/// Not covered, deliberately or for now: unseparated 12-hex MACs (too many false positives against
/// hashes), public IP addresses, global IPv6, credentials embedded in URLs (`user:pass@host`), and
/// secrets that appear with no key. Over-redaction is intentional: `key: ready` is redacted too.
#[must_use]
pub fn redact_sensitive_text(input: &str) -> String {
    let text = redact_bearer_credentials(input);
    let text = redact_key_values(&text);
    let text = redact_mac_addresses(&text);
    let text = redact_private_ipv4(&text);
    let text = redact_private_ipv6(&text);
    let text = redact_prefixed_ids(&text, "RINCON_", 12, is_hex_byte);
    let text = redact_prefixed_ids(&text, "Sonos_", 12, is_alnum_byte);
    redact_prefixed_ids(&text, "HHID_", 1, is_alnum_byte)
}

/// Structured versioned diagnostic event (`ffw.log.v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticEvent {
    pub schema_version: String,
    pub timestamp_mono_ns: u64,
    pub run_id: String,
    pub case_id: String,
    pub correlation_id: String,
    pub member_id: String,
    pub group_id: String,
    pub source_epoch: u64,
    pub state_revision: u64,
    pub event_kind: String,
    pub message: String,
    pub queue_depth: usize,
    pub latency_us: u64,
    /// The injected fault (or fault-schedule entry) in force when this event was emitted.
    /// Omitted from the JSON when absent, so existing logs keep their shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault: Option<String>,
    /// The causal error chain behind this event, outermost first. Omitted when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
}

/// Non-blocking diagnostic sink with event-count and byte caps and exact loss accounting. (There
/// is no events-per-second limit: the caps bound memory and size, not rate.)
///
/// `try_emit` stores an ordinary event while there is room and otherwise drops it, counted.
/// `emit_critical` is for evidence a result cannot be trusted without: when the sink is full it
/// evicts the oldest ordinary event to make room, and when it cannot store the event at all it
/// records `critical_evidence_lost`, which makes `is_evidence_complete` false. Nothing here blocks
/// or waits. Every event handed to the sink ends either stored or counted as dropped (an evicted
/// event counts as dropped), so `emitted_event_count == events().len() + dropped_event_count`.
#[derive(Debug, Clone)]
pub struct BoundedDiagnosticSink {
    max_events: usize,
    max_bytes: usize,
    sink_unavailable: bool,
    events: Vec<DiagnosticEvent>,
    /// Serialized size of each stored event; parallel to `events`.
    event_bytes: Vec<usize>,
    /// Whether each stored event is critical, and so never evicted; parallel to `events`.
    critical: Vec<bool>,
    used_bytes: usize,
    emitted_event_count: u64,
    dropped_event_count: u64,
    evicted_event_count: u64,
    critical_evidence_lost: u64,
    /// `(max ordinary events per window, window length in ns)`, measured on event timestamps.
    rate_limit: Option<(usize, u64)>,
    rate_window_start_ns: Option<u64>,
    rate_window_count: usize,
    rate_limited_event_count: u64,
    last_timestamp_ns: Option<u64>,
    non_monotonic_event_count: u64,
    pseudonym_key: Option<PseudonymKey>,
}

/// Secret that keys member/group pseudonyms. `Debug` never prints it.
#[derive(Clone)]
struct PseudonymKey([u8; 32]);

impl std::fmt::Debug for PseudonymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PseudonymKey([REDACTED])")
    }
}

/// Stable, keyed, one-way stand-in for an identifier: `p-` plus 16 hex characters. The same id
/// and key always give the same pseudonym; without the key the id cannot be recovered.
fn pseudonym(key: &PseudonymKey, id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ffw.pseudonym.v1");
    hasher.update(key.0);
    hasher.update((id.len() as u64).to_be_bytes());
    hasher.update(id.as_bytes());
    let full = hex::encode(hasher.finalize());
    format!("p-{}", &full[..16])
}

impl BoundedDiagnosticSink {
    #[must_use]
    pub const fn new(max_events: usize, max_bytes: usize) -> Self {
        Self {
            max_events,
            max_bytes,
            sink_unavailable: false,
            events: Vec::new(),
            event_bytes: Vec::new(),
            critical: Vec::new(),
            used_bytes: 0,
            emitted_event_count: 0,
            dropped_event_count: 0,
            evicted_event_count: 0,
            critical_evidence_lost: 0,
            rate_limit: None,
            rate_window_start_ns: None,
            rate_window_count: 0,
            rate_limited_event_count: 0,
            last_timestamp_ns: None,
            non_monotonic_event_count: 0,
            pseudonym_key: None,
        }
    }

    /// Bound the event rate: at most `max_events_per_window` ordinary events per window of
    /// `window_ns`, measured on the events' own timestamps (so it is deterministic in virtual
    /// time). Excess ordinary events are dropped and counted. Critical events are not rate
    /// limited; they are bounded by capacity alone.
    #[must_use]
    pub fn with_rate_limit(mut self, max_events_per_window: usize, window_ns: u64) -> Self {
        self.rate_limit = Some((max_events_per_window, window_ns));
        self
    }

    /// Replace `member_id` and `group_id` with keyed pseudonyms before anything is stored, so the
    /// raw identifiers never reach the log.
    #[must_use]
    pub fn with_pseudonym_key(mut self, key: [u8; 32]) -> Self {
        self.pseudonym_key = Some(PseudonymKey(key));
        self
    }

    pub fn set_unavailable(&mut self, unavailable: bool) {
        self.sink_unavailable = unavailable;
    }

    /// Redact every free-text field, not only `message` (an identifier placed in any of them
    /// would otherwise reach the log), pseudonymize member/group ids if a key is set, and
    /// measure the serialized event.
    fn prepare(
        mut event: DiagnosticEvent,
        pseudonym_key: Option<&PseudonymKey>,
    ) -> (DiagnosticEvent, usize) {
        event.schema_version = LOG_SCHEMA_VERSION.to_string();
        for field in [
            &mut event.run_id,
            &mut event.case_id,
            &mut event.correlation_id,
            &mut event.member_id,
            &mut event.group_id,
            &mut event.event_kind,
            &mut event.message,
        ] {
            *field = redact_sensitive_text(field);
        }
        for text in [&mut event.fault, &mut event.cause].into_iter().flatten() {
            *text = redact_sensitive_text(text);
        }
        if let Some(key) = pseudonym_key {
            event.member_id = pseudonym(key, &event.member_id);
            event.group_id = pseudonym(key, &event.group_id);
        }
        let serialized = serde_json::to_string(&event).unwrap_or_default();
        let bytes = serialized.len() + 1;
        (event, bytes)
    }

    /// Track that timestamps never go backwards. An event that does is still processed, but
    /// counted, so a log with an unreliable timebase says so.
    fn note_timestamp(&mut self, t_ns: u64) {
        match self.last_timestamp_ns {
            Some(previous) if t_ns < previous => {
                self.non_monotonic_event_count = self.non_monotonic_event_count.saturating_add(1);
            }
            _ => self.last_timestamp_ns = Some(t_ns),
        }
    }

    /// Whether the rate limit, if any, lets an ordinary event at `t_ns` through. Consumes a slot
    /// in the current window when it does.
    fn admit_within_rate(&mut self, t_ns: u64) -> bool {
        let Some((max_in_window, window_ns)) = self.rate_limit else {
            return true;
        };
        let window_ns = window_ns.max(1);
        let in_window = self
            .rate_window_start_ns
            .is_some_and(|start| t_ns < start.saturating_add(window_ns));
        if !in_window {
            self.rate_window_start_ns = Some(t_ns);
            self.rate_window_count = 0;
        }
        if self.rate_window_count >= max_in_window {
            return false;
        }
        self.rate_window_count += 1;
        true
    }

    fn store(&mut self, event: DiagnosticEvent, bytes: usize, critical: bool) {
        self.used_bytes += bytes;
        self.event_bytes.push(bytes);
        self.critical.push(critical);
        self.events.push(event);
    }

    fn count_dropped(&mut self) {
        self.dropped_event_count = self.dropped_event_count.saturating_add(1);
    }

    fn lose_critical(&mut self) -> bool {
        self.critical_evidence_lost = self.critical_evidence_lost.saturating_add(1);
        self.count_dropped();
        false
    }

    fn evict(&mut self, index: usize) {
        let bytes = self.event_bytes.remove(index);
        self.critical.remove(index);
        self.events.remove(index);
        self.used_bytes = self.used_bytes.saturating_sub(bytes);
        self.count_dropped();
        self.evicted_event_count = self.evicted_event_count.saturating_add(1);
    }

    /// Non-blocking emit of an ordinary event. Never panics or blocks even when full or
    /// unavailable; a dropped event is counted.
    pub fn try_emit(&mut self, event: DiagnosticEvent) -> bool {
        self.emitted_event_count = self.emitted_event_count.saturating_add(1);
        let t_ns = event.timestamp_mono_ns;
        self.note_timestamp(t_ns);
        if self.sink_unavailable || self.events.len() >= self.max_events {
            self.count_dropped();
            return false;
        }
        let (event, bytes) = Self::prepare(event, self.pseudonym_key.as_ref());
        if self.used_bytes.saturating_add(bytes) > self.max_bytes {
            self.count_dropped();
            return false;
        }
        // Last, so an event refused for another reason does not use up a slot in the window.
        if !self.admit_within_rate(t_ns) {
            self.count_dropped();
            self.rate_limited_event_count = self.rate_limited_event_count.saturating_add(1);
            return false;
        }
        self.store(event, bytes, false);
        true
    }

    /// Non-blocking emit of evidence that must not be lost. Critical events are never evicted.
    /// If there is no room, the oldest ordinary events are evicted (each counted as dropped) until
    /// there is; if that cannot make room, nothing is evicted, the event is dropped, and
    /// `critical_evidence_lost` is incremented.
    pub fn emit_critical(&mut self, event: DiagnosticEvent) -> bool {
        self.emitted_event_count = self.emitted_event_count.saturating_add(1);
        self.note_timestamp(event.timestamp_mono_ns);
        if self.sink_unavailable {
            return self.lose_critical();
        }
        let (event, bytes) = Self::prepare(event, self.pseudonym_key.as_ref());

        // Decide first whether evicting could possibly make room, so that good events are never
        // thrown away for nothing.
        let mut evictable_count = 0usize;
        let mut evictable_bytes = 0usize;
        for (index, is_critical) in self.critical.iter().enumerate() {
            if !*is_critical {
                evictable_count += 1;
                evictable_bytes += self.event_bytes[index];
            }
        }
        let kept_count = self.events.len() - evictable_count;
        let kept_bytes = self.used_bytes.saturating_sub(evictable_bytes);
        if kept_count >= self.max_events || kept_bytes.saturating_add(bytes) > self.max_bytes {
            return self.lose_critical();
        }

        while self.events.len() >= self.max_events
            || self.used_bytes.saturating_add(bytes) > self.max_bytes
        {
            let Some(index) = self.critical.iter().position(|is_critical| !*is_critical) else {
                return self.lose_critical();
            };
            self.evict(index);
        }
        self.store(event, bytes, true);
        true
    }

    #[must_use]
    pub fn events(&self) -> &[DiagnosticEvent] {
        &self.events
    }

    /// Every event ever handed to the sink, stored or not.
    #[must_use]
    pub const fn emitted_event_count(&self) -> u64 {
        self.emitted_event_count
    }

    /// Events not in the log: refused at emit time, or evicted to make room for a critical one.
    #[must_use]
    pub const fn dropped_event_count(&self) -> u64 {
        self.dropped_event_count
    }

    /// The part of `dropped_event_count` that was stored first and then evicted.
    #[must_use]
    pub const fn evicted_event_count(&self) -> u64 {
        self.evicted_event_count
    }

    /// Critical events that could not be stored.
    #[must_use]
    pub const fn critical_evidence_lost(&self) -> u64 {
        self.critical_evidence_lost
    }

    /// False once any critical event has been lost: the evidence behind a result is then
    /// incomplete and the result must not be reported as a clean pass.
    #[must_use]
    pub const fn is_evidence_complete(&self) -> bool {
        self.critical_evidence_lost == 0
    }

    /// The part of `dropped_event_count` refused only because of the rate limit.
    #[must_use]
    pub const fn rate_limited_event_count(&self) -> u64 {
        self.rate_limited_event_count
    }

    /// Events whose timestamp was earlier than one already seen.
    #[must_use]
    pub const fn non_monotonic_event_count(&self) -> u64 {
        self.non_monotonic_event_count
    }

    /// One concise line for a human reading a run's output.
    #[must_use]
    pub fn human_summary(&self) -> String {
        format!(
            "diagnostics: emitted={} stored={}/{} dropped={} (evicted={} rate_limited={}) critical_lost={} out_of_order={} bytes={}/{} evidence={}",
            self.emitted_event_count,
            self.events.len(),
            self.max_events,
            self.dropped_event_count,
            self.evicted_event_count,
            self.rate_limited_event_count,
            self.critical_evidence_lost,
            self.non_monotonic_event_count,
            self.used_bytes,
            self.max_bytes,
            if self.is_evidence_complete() {
                "complete"
            } else {
                "INCOMPLETE"
            }
        )
    }

    #[must_use]
    pub const fn used_bytes(&self) -> usize {
        self.used_bytes
    }

    #[must_use]
    pub fn to_jsonl(&self) -> String {
        let mut lines = Vec::with_capacity(self.events.len());
        for ev in &self.events {
            if let Ok(line) = serde_json::to_string(ev) {
                lines.push(line);
            }
        }
        lines.join("\n")
    }
}

/// Registered test case record and result receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestCaseReceipt {
    pub case_id: String,
    pub requirement_id: String,
    pub tier: TestTier,
    pub evidence_class: EvidenceClass,
    pub seed: u64,
    pub outcome: CaseOutcome,
    pub duration_ns: u64,
    pub replay_command: String,
    pub expected_oracle: String,
    pub observed_oracle: String,
    pub first_causal_error: Option<String>,
}

/// Complete suite execution receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiteExecutionReceipt {
    pub schema_version: String,
    pub suite_id: String,
    pub run_id: String,
    pub selected_tier: TestTier,
    pub denominator: usize,
    pub passed: usize,
    pub failed: usize,
    pub blocked: usize,
    pub not_run: usize,
    pub dropped_log_events: u64,
    pub overall_pass: bool,
    pub cases: Vec<TestCaseReceipt>,
    pub artifact_digests: BTreeMap<String, String>,
}

impl SuiteExecutionReceipt {
    #[must_use]
    pub fn from_cases(
        suite_id: &str,
        run_id: &str,
        selected_tier: TestTier,
        cases: Vec<TestCaseReceipt>,
        dropped_log_events: u64,
        artifact_digests: BTreeMap<String, String>,
    ) -> Self {
        let denominator = cases.len();
        let passed = cases
            .iter()
            .filter(|c| c.outcome == CaseOutcome::Passed)
            .count();
        let failed = cases
            .iter()
            .filter(|c| c.outcome == CaseOutcome::Failed)
            .count();
        let blocked = cases
            .iter()
            .filter(|c| c.outcome == CaseOutcome::Blocked)
            .count();
        let not_run = cases
            .iter()
            .filter(|c| c.outcome == CaseOutcome::NotRun)
            .count();
        // Mandatory rule: failed, blocked, or not-run cases prevent overall suite green!
        let overall_pass =
            denominator > 0 && passed == denominator && failed == 0 && blocked == 0 && not_run == 0;
        Self {
            schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
            suite_id: suite_id.to_string(),
            run_id: run_id.to_string(),
            selected_tier,
            denominator,
            passed,
            failed,
            blocked,
            not_run,
            dropped_log_events,
            overall_pass,
            cases,
            artifact_digests,
        }
    }

    #[must_use]
    pub fn human_summary(&self) -> String {
        format!(
            "suite={} run_id={} tier={:?} status={} total={} passed={} failed={} blocked={} not_run={} dropped_logs={}",
            self.suite_id,
            self.run_id,
            self.selected_tier,
            if self.overall_pass { "PASS" } else { "FAIL" },
            self.denominator,
            self.passed,
            self.failed,
            self.blocked,
            self.not_run,
            self.dropped_log_events
        )
    }

    #[must_use]
    pub fn digest_hex(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        hex::encode(Sha256::digest(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canary_1_sample_loss_fails_continuity_oracle() {
        let mut oracle = SampleContinuityOracle::new();
        let block = [100i16; 256];
        assert!(oracle.observe_block(0, 256, &block).is_ok());
        // Inject intentional 256-frame sample loss defect (frame 512 instead of 256)
        let res = oracle.observe_block(512, 256, &block);
        assert_eq!(
            res,
            Err(OracleViolation::SampleDiscontinuity {
                expected_frame: 256,
                observed_frame: 512,
                reason: "unannounced frame gap or overlap".to_string(),
            })
        );
    }

    fn reference_block(reference: &SeededReferenceSignal, start: u64, frames: u64) -> Vec<i16> {
        (0..frames).map(|i| reference.expected(start + i)).collect()
    }

    #[test]
    fn splitmix64_matches_published_known_answer_vectors() {
        // Reference splitmix64.c, seed 0.
        let mut rng = DeterministicRng::new(0);
        assert_eq!(rng.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(rng.next_u64(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(rng.next_u64(), 0x06C4_5D18_8009_454F);
        assert_eq!(rng.next_u64(), 0xF88B_B8A8_724C_81EC);
        // rand_xoshiro SplitMix64::seed_from_u64(1234567).
        let mut rng = DeterministicRng::new(1_234_567);
        for expected in [
            6_457_827_717_110_365_317_u64,
            3_203_168_211_198_807_973,
            9_817_491_932_198_370_423,
            4_593_380_528_125_082_431,
            16_408_922_859_458_223_821,
        ] {
            assert_eq!(rng.next_u64(), expected);
        }
    }

    #[test]
    fn seeded_reference_matches_the_sequential_generator() {
        // Second code path: random access must agree with walking the generator.
        let key = 0xDEAD_BEEF_u64;
        let reference = SeededReferenceSignal::new(key);
        let mut rng = DeterministicRng::new(key);
        for frame in 0..64u64 {
            let sequential = (rng.next_u64() >> 48) as u16 as i16;
            assert_eq!(reference.expected(frame), sequential, "frame {frame}");
        }
    }

    #[test]
    fn seeded_reference_is_not_degenerate() {
        let reference = SeededReferenceSignal::new(1);
        let distinct: std::collections::BTreeSet<i16> =
            (0..256u64).map(|f| reference.expected(f)).collect();
        assert!(
            distinct.len() > 200,
            "only {} distinct values",
            distinct.len()
        );
        let other = SeededReferenceSignal::new(2);
        assert_ne!(
            reference_block(&reference, 0, 16),
            reference_block(&other, 0, 16)
        );
    }

    #[test]
    fn blocks_matching_the_reference_pass_and_the_stream_finalizes() {
        let reference = SeededReferenceSignal::new(7);
        let mut oracle = SampleContinuityOracle::new();
        for b in 0..4u64 {
            let block = reference_block(&reference, b * 8, 8);
            assert_eq!(
                oracle.observe_block_against(b * 8, 8, &block, &reference, 0),
                Ok(())
            );
        }
        assert_eq!(oracle.verified_frames(), 32);
        assert_eq!(oracle.finalize(32), Ok(()));
    }

    #[test]
    fn canary_wrong_sample_value_fails_content_oracle() {
        let reference = SeededReferenceSignal::new(7);
        let mut oracle = SampleContinuityOracle::new();
        let good = reference_block(&reference, 0, 8);
        assert_eq!(
            oracle.observe_block_against(0, 8, &good, &reference, 0),
            Ok(())
        );
        // Frame numbers are perfectly continuous; one sample value is off by one.
        let mut bad = reference_block(&reference, 8, 8);
        let original = bad[3];
        bad[3] = original.wrapping_add(1);
        assert_eq!(
            oracle.observe_block_against(8, 8, &bad, &reference, 0),
            Err(OracleViolation::WrongSample {
                frame: 11,
                expected: original,
                observed: original.wrapping_add(1),
                tolerance: 0,
            })
        );
        // The rejected block did not advance the oracle: the correct block is still accepted there.
        let fixed = reference_block(&reference, 8, 8);
        assert_eq!(
            oracle.observe_block_against(8, 8, &fixed, &reference, 0),
            Ok(())
        );
        assert_eq!(oracle.verified_frames(), 16);
    }

    #[test]
    fn right_frame_numbers_with_values_from_the_wrong_frames_fail() {
        let reference = SeededReferenceSignal::new(7);
        // Frames 1..9 presented as frames 0..8.
        let shifted = reference_block(&reference, 1, 8);
        let mut oracle = SampleContinuityOracle::new();
        assert!(matches!(
            oracle.observe_block_against(0, 8, &shifted, &reference, 0),
            Err(OracleViolation::WrongSample { .. })
        ));
        assert_eq!(oracle.verified_frames(), 0);
        // Continuity-only observation cannot see this: that blind spot is why the content API exists.
        assert_eq!(
            SampleContinuityOracle::new().observe_block(0, 8, &shifted),
            Ok(())
        );
    }

    #[test]
    fn tolerance_accepts_small_error_and_rejects_larger_error() {
        let reference = SeededReferenceSignal::new(11);
        let drifted: Vec<i16> = reference_block(&reference, 0, 16)
            .iter()
            .map(|s| s.saturating_add(3))
            .collect();
        let mut within = SampleContinuityOracle::new();
        assert_eq!(
            within.observe_block_against(0, 16, &drifted, &reference, 3),
            Ok(())
        );
        let mut beyond = SampleContinuityOracle::new();
        assert!(matches!(
            beyond.observe_block_against(0, 16, &drifted, &reference, 2),
            Err(OracleViolation::WrongSample { tolerance: 2, .. })
        ));
    }

    #[test]
    fn block_length_must_equal_frame_count() {
        let mut oracle = SampleContinuityOracle::new();
        assert_eq!(
            oracle.observe_block(0, 4, &[1, 2, 3]),
            Err(OracleViolation::BlockLengthMismatch {
                frame_count: 4,
                observed_samples: 3,
            })
        );
        assert_eq!(
            oracle.observe_block(0, 4, &[1, 2, 3, 4, 5]),
            Err(OracleViolation::BlockLengthMismatch {
                frame_count: 4,
                observed_samples: 5,
            })
        );
        let reference = SeededReferenceSignal::new(1);
        assert_eq!(
            oracle.observe_block_against(0, 4, &[0, 0], &reference, u16::MAX),
            Err(OracleViolation::BlockLengthMismatch {
                frame_count: 4,
                observed_samples: 2,
            })
        );
        assert_eq!(oracle.verified_frames(), 0);
        assert_eq!(oracle.observe_block(0, 4, &[1, 2, 3, 4]), Ok(()));
    }

    #[test]
    fn a_fixed_capacity_array_is_only_valid_when_sliced_to_the_frame_count() {
        // How the speaker hands over a block: a 256-slot array of which only `frames` are live.
        let capacity = [5i16; 256];
        let mut oracle = SampleContinuityOracle::new();
        assert_eq!(
            oracle.observe_block(0, 100, &capacity),
            Err(OracleViolation::BlockLengthMismatch {
                frame_count: 100,
                observed_samples: 256,
            })
        );
        assert_eq!(oracle.observe_block(0, 100, &capacity[..100]), Ok(()));
        assert_eq!(oracle.verified_frames(), 100);
    }

    #[test]
    fn finalize_rejects_a_truncated_tail_an_overrun_and_an_unobserved_stream() {
        let reference = SeededReferenceSignal::new(3);
        let mut oracle = SampleContinuityOracle::new();
        for b in 0..3u64 {
            let block = reference_block(&reference, b * 8, 8);
            assert_eq!(
                oracle.observe_block_against(b * 8, 8, &block, &reference, 0),
                Ok(())
            );
        }
        assert_eq!(oracle.finalize(24), Ok(()));
        // The final block of a 4-block stream never arrived.
        assert_eq!(
            oracle.finalize(32),
            Err(OracleViolation::TruncatedStream {
                expected_total_frames: 32,
                verified_frames: 24,
            })
        );
        assert_eq!(
            oracle.finalize(16),
            Err(OracleViolation::OverrunStream {
                expected_total_frames: 16,
                verified_frames: 24,
            })
        );
        // Observing nothing is never a pass, even when nothing was expected.
        assert_eq!(
            SampleContinuityOracle::new().finalize(0),
            Err(OracleViolation::TruncatedStream {
                expected_total_frames: 0,
                verified_frames: 0,
            })
        );
        assert_eq!(
            SampleContinuityOracle::new().finalize(8),
            Err(OracleViolation::TruncatedStream {
                expected_total_frames: 8,
                verified_frames: 0,
            })
        );
    }

    fn outcome(command_id: u64, applied: bool, system_epoch_after: u64) -> CommandObservation {
        CommandObservation {
            command_id,
            applied,
            system_epoch_after,
        }
    }

    #[test]
    fn a_fresh_command_is_applied_and_its_duplicate_delivery_may_be_rejected() {
        let mut oracle = FencedCommandOracle::new(1);
        assert_eq!(oracle.record_issued(1, 1, 1), Ok(()));
        assert_eq!(oracle.observe_outcome(outcome(1, true, 1)), Ok(()));
        // The duplicate delivery is rejected: permitted, and not a second application.
        assert_eq!(oracle.observe_outcome(outcome(1, false, 1)), Ok(()));
    }

    #[test]
    fn canary_2_stale_epoch_fails_fencing_oracle() {
        let mut oracle = FencedCommandOracle::new(10);
        assert_eq!(oracle.declare_authority(11), Ok(()));
        assert_eq!(oracle.record_issued(7, 9, 1), Ok(()));
        // Paired positive: rejecting the stale command is exactly what the fence is for.
        assert_eq!(oracle.observe_outcome(outcome(7, false, 11)), Ok(()));
        // Inject intentional stale epoch 9 command acceptance.
        assert_eq!(
            oracle.observe_outcome(outcome(7, true, 11)),
            Err(OracleViolation::StaleEpochAccepted {
                current_epoch: 11,
                candidate_epoch: 9,
            })
        );
    }

    #[test]
    fn canary_3_double_applied_command_fails_idempotency_oracle() {
        let mut oracle = FencedCommandOracle::new(4);
        assert_eq!(oracle.record_issued(1, 4, 101), Ok(()));
        assert_eq!(oracle.observe_outcome(outcome(1, true, 4)), Ok(()));
        // Inject intentional duplicate command application.
        assert_eq!(
            oracle.observe_outcome(outcome(1, true, 4)),
            Err(OracleViolation::DoubleAppliedCommand {
                epoch: 4,
                command_seq: 101,
            })
        );
    }

    #[test]
    fn a_command_from_an_epoch_nobody_declared_must_not_be_applied() {
        let mut oracle = FencedCommandOracle::new(1);
        assert_eq!(oracle.record_issued(1, 3, 1), Ok(()));
        // Paired positive: rejecting it is fine.
        assert_eq!(oracle.observe_outcome(outcome(1, false, 1)), Ok(()));
        assert_eq!(
            oracle.observe_outcome(outcome(1, true, 3)),
            Err(OracleViolation::FutureEpochAccepted {
                authority_epoch: 1,
                command_epoch: 3,
            })
        );
    }

    #[test]
    fn canary_a_rejected_command_must_not_move_the_system_epoch_past_the_authority() {
        let mut oracle = FencedCommandOracle::new(1);
        assert_eq!(oracle.record_issued(1, 999, 1), Ok(()));
        // The command was rejected, yet the system now reports epoch 999.
        assert_eq!(
            oracle.observe_outcome(outcome(1, false, 999)),
            Err(OracleViolation::FutureEpochAdopted {
                authority_epoch: 1,
                system_epoch: 999,
            })
        );
        // Paired positive: a rejection that leaves the epoch alone is fine.
        assert_eq!(oracle.record_issued(2, 999, 2), Ok(()));
        assert_eq!(oracle.observe_outcome(outcome(2, false, 1)), Ok(()));
    }

    #[test]
    fn adopting_a_newer_epoch_is_legitimate_once_the_harness_declared_it() {
        let mut oracle = FencedCommandOracle::new(1);
        assert_eq!(oracle.declare_authority(2), Ok(()));
        assert_eq!(oracle.record_issued(1, 2, 1), Ok(()));
        assert_eq!(oracle.observe_outcome(outcome(1, true, 2)), Ok(()));
        assert_eq!(oracle.authority_epoch(), 2);
    }

    #[test]
    fn a_system_that_has_not_yet_learned_the_new_epoch_is_not_a_violation() {
        let mut oracle = FencedCommandOracle::new(1);
        assert_eq!(oracle.declare_authority(2), Ok(()));
        assert_eq!(oracle.record_issued(1, 1, 5), Ok(()));
        // Lagging behind the declared authority is not the oracle's concern; running ahead is.
        assert_eq!(oracle.observe_outcome(outcome(1, false, 1)), Ok(()));
    }

    #[test]
    fn an_outcome_for_a_command_never_issued_is_a_phantom() {
        let mut oracle = FencedCommandOracle::new(1);
        assert_eq!(
            oracle.observe_outcome(outcome(42, true, 1)),
            Err(OracleViolation::PhantomCommand { command_id: 42 })
        );
        assert_eq!(
            oracle.observe_outcome(outcome(42, false, 1)),
            Err(OracleViolation::PhantomCommand { command_id: 42 })
        );
    }

    #[test]
    fn the_declared_authority_can_only_move_forward() {
        let mut oracle = FencedCommandOracle::new(3);
        assert_eq!(oracle.declare_authority(3), Ok(()));
        assert_eq!(
            oracle.declare_authority(2),
            Err(OracleViolation::AuthorityRegressed {
                current_epoch: 3,
                declared_epoch: 2,
            })
        );
        assert_eq!(oracle.authority_epoch(), 3);
    }

    #[test]
    fn command_tracking_is_bounded_and_overflow_is_reported() {
        let mut oracle = FencedCommandOracle::with_capacity(1, 2);
        assert_eq!(oracle.record_issued(1, 1, 1), Ok(()));
        assert_eq!(oracle.record_issued(2, 1, 2), Ok(()));
        assert_eq!(
            oracle.record_issued(3, 1, 3),
            Err(OracleViolation::CommandTrackingOverflow { limit: 2 })
        );
        // Re-recording an already tracked command does not count against the bound.
        assert_eq!(oracle.record_issued(2, 1, 2), Ok(()));
    }

    fn readiness_spec() -> ReadinessSpec {
        ReadinessSpec {
            required_primed_silence_blocks: 2,
            min_clock_samples: 3,
            max_clock_uncertainty_us: 2_000,
        }
    }

    fn board_ok(t_ns: u64) -> BoardObservation {
        BoardObservation {
            t_ns,
            integrity_ok: true,
            routing_consistent: true,
        }
    }

    fn amp(t_ns: u64, muted: bool, primed_silence_blocks: u32) -> AmplifierObservation {
        AmplifierObservation {
            t_ns,
            muted,
            primed_silence_blocks,
        }
    }

    fn clock_obs(
        t_ns: u64,
        ingested_samples: u32,
        uncertainty_us: u64,
        offset_error_ns: i64,
    ) -> ClockObservation {
        ClockObservation {
            t_ns,
            ingested_samples,
            uncertainty_us,
            offset_error_ns,
        }
    }

    /// The permitted bring-up order: muted, prime two silence blocks, then unmute.
    fn observe_nominal_amplifier(oracle: &mut ReadinessOracle) {
        assert_eq!(oracle.record_amplifier(amp(2, true, 0)), Ok(()));
        assert_eq!(oracle.record_amplifier(amp(3, true, 1)), Ok(()));
        assert_eq!(oracle.record_amplifier(amp(4, true, 2)), Ok(()));
        assert_eq!(oracle.record_amplifier(amp(5, false, 2)), Ok(()));
    }

    fn missing_after_clock(clock: ClockObservation) -> Result<(), OracleViolation> {
        let mut oracle = ReadinessOracle::new(readiness_spec());
        assert_eq!(oracle.record_board(board_ok(1)), Ok(()));
        observe_nominal_amplifier(&mut oracle);
        assert_eq!(oracle.record_clock(clock), Ok(()));
        oracle.announce_ready(10)
    }

    #[test]
    fn permitted_startup_reaches_ready() {
        let mut oracle = ReadinessOracle::new(readiness_spec());
        assert_eq!(oracle.record_board(board_ok(1)), Ok(()));
        observe_nominal_amplifier(&mut oracle);
        assert_eq!(oracle.record_clock(clock_obs(6, 4, 400, 0)), Ok(()));
        assert!(!oracle.is_announced());
        assert_eq!(oracle.announce_ready(7), Ok(()));
        assert!(oracle.is_announced());
    }

    #[test]
    fn canary_4_false_ready_state_fails_readiness_oracle() {
        let mut oracle = ReadinessOracle::new(readiness_spec());
        assert_eq!(oracle.record_board(board_ok(1)), Ok(()));
        observe_nominal_amplifier(&mut oracle);
        // Only one clock exchange was ingested: the clock is not locked, whatever the device says.
        assert_eq!(oracle.record_clock(clock_obs(6, 1, 400, 0)), Ok(()));
        assert_eq!(
            oracle.announce_ready(7),
            Err(OracleViolation::FalseReadyState {
                missing_prerequisite: "clock_locked".to_string(),
            })
        );
        assert!(!oracle.is_announced());
    }

    #[test]
    fn ready_with_no_observed_evidence_is_false_ready() {
        let mut oracle = ReadinessOracle::new(readiness_spec());
        assert_eq!(
            oracle.announce_ready(1),
            Err(OracleViolation::FalseReadyState {
                missing_prerequisite: "board_profile_verified".to_string(),
            })
        );
    }

    #[test]
    fn board_failure_or_inconsistent_routing_is_not_ready() {
        for (integrity_ok, routing_consistent) in [(false, true), (true, false), (false, false)] {
            let mut oracle = ReadinessOracle::new(readiness_spec());
            let board = BoardObservation {
                t_ns: 1,
                integrity_ok,
                routing_consistent,
            };
            assert_eq!(oracle.record_board(board), Ok(()));
            observe_nominal_amplifier(&mut oracle);
            assert_eq!(oracle.record_clock(clock_obs(6, 4, 400, 0)), Ok(()));
            assert_eq!(
                oracle.announce_ready(7),
                Err(OracleViolation::FalseReadyState {
                    missing_prerequisite: "board_profile_verified".to_string(),
                })
            );
        }
    }

    #[test]
    fn canary_premature_unmute_is_refused_when_observed_and_not_forgiven_later() {
        let mut oracle = ReadinessOracle::new(readiness_spec());
        assert_eq!(oracle.record_board(board_ok(1)), Ok(()));
        assert_eq!(oracle.record_amplifier(amp(2, true, 0)), Ok(()));
        assert_eq!(oracle.record_amplifier(amp(3, true, 1)), Ok(()));
        // The driver unmuted after one silence block when two are required.
        assert_eq!(
            oracle.record_amplifier(amp(4, false, 1)),
            Err(OracleViolation::PrematureUnmute {
                primed_blocks: 1,
                required_blocks: 2,
            })
        );
        // Priming more afterwards does not undo the unsafe unmute.
        assert_eq!(oracle.record_amplifier(amp(5, false, 2)), Ok(()));
        assert_eq!(oracle.record_clock(clock_obs(6, 4, 400, 0)), Ok(()));
        assert_eq!(
            oracle.announce_ready(7),
            Err(OracleViolation::FalseReadyState {
                missing_prerequisite: "amplifier_muted_until_primed".to_string(),
            })
        );
    }

    #[test]
    fn an_amplifier_never_observed_muted_is_not_ready() {
        let mut oracle = ReadinessOracle::new(readiness_spec());
        assert_eq!(oracle.record_board(board_ok(1)), Ok(()));
        assert_eq!(oracle.record_amplifier(amp(2, false, 2)), Ok(()));
        assert_eq!(oracle.record_clock(clock_obs(6, 4, 400, 0)), Ok(()));
        assert_eq!(
            oracle.announce_ready(7),
            Err(OracleViolation::FalseReadyState {
                missing_prerequisite: "amplifier_muted_until_primed".to_string(),
            })
        );
    }

    #[test]
    fn an_amplifier_left_muted_is_not_ready() {
        let mut oracle = ReadinessOracle::new(readiness_spec());
        assert_eq!(oracle.record_board(board_ok(1)), Ok(()));
        assert_eq!(oracle.record_amplifier(amp(2, true, 0)), Ok(()));
        assert_eq!(oracle.record_amplifier(amp(3, true, 2)), Ok(()));
        assert_eq!(oracle.record_clock(clock_obs(6, 4, 400, 0)), Ok(()));
        assert_eq!(
            oracle.announce_ready(7),
            Err(OracleViolation::FalseReadyState {
                missing_prerequisite: "amplifier_muted_until_primed".to_string(),
            })
        );
    }

    #[test]
    fn clock_lock_is_judged_from_raw_facts_at_their_exact_boundaries() {
        let clock_missing = Err(OracleViolation::FalseReadyState {
            missing_prerequisite: "clock_locked".to_string(),
        });
        // Samples: 3 is enough, 2 is not.
        assert_eq!(missing_after_clock(clock_obs(6, 3, 400, 0)), Ok(()));
        assert_eq!(missing_after_clock(clock_obs(6, 2, 400, 0)), clock_missing);
        // Uncertainty: 2000 us is allowed, 2001 us is not.
        assert_eq!(missing_after_clock(clock_obs(6, 4, 2_000, 0)), Ok(()));
        assert_eq!(
            missing_after_clock(clock_obs(6, 4, 2_001, 0)),
            clock_missing
        );
        // Offset error must lie within the stated uncertainty (400 us = 400_000 ns), either sign.
        assert_eq!(missing_after_clock(clock_obs(6, 4, 400, 400_000)), Ok(()));
        assert_eq!(missing_after_clock(clock_obs(6, 4, 400, -400_000)), Ok(()));
        assert_eq!(
            missing_after_clock(clock_obs(6, 4, 400, 400_001)),
            clock_missing
        );
        assert_eq!(
            missing_after_clock(clock_obs(6, 4, 400, -400_001)),
            clock_missing
        );
        // A clock that has ingested nothing reports maximal uncertainty and can never lock.
        assert_eq!(
            missing_after_clock(clock_obs(6, 0, u64::MAX, 0)),
            clock_missing
        );
    }

    #[test]
    fn probes_must_not_go_back_in_time() {
        let mut oracle = ReadinessOracle::new(readiness_spec());
        assert_eq!(oracle.record_board(board_ok(5)), Ok(()));
        assert_eq!(
            oracle.record_amplifier(amp(4, true, 0)),
            Err(OracleViolation::ProbeOutOfOrder {
                previous_ns: 5,
                observed_ns: 4,
            })
        );
        assert_eq!(oracle.record_amplifier(amp(5, true, 0)), Ok(()));
    }

    #[test]
    fn bounded_sink_redacts_secrets_and_never_blocks_when_full_or_unavailable() {
        let mut sink = BoundedDiagnosticSink::new(2, 4096);
        let mk_ev = |seq: u64, msg: &str| DiagnosticEvent {
            schema_version: String::new(),
            timestamp_mono_ns: seq * 1_000_000,
            run_id: "run-01".to_string(),
            case_id: "Q00-sink".to_string(),
            correlation_id: format!("corr-{seq}"),
            member_id: "spk-a".to_string(),
            group_id: "grp-1".to_string(),
            source_epoch: 1,
            state_revision: seq,
            event_kind: "test".to_string(),
            message: msg.to_string(),
            queue_depth: 4,
            latency_us: 120,
            fault: None,
            cause: None,
        };

        assert!(sink.try_emit(mk_ev(
            1,
            "connected to 192.168.4.49 mac 00:0E:58:AA:BB:CC token=secret123"
        )));
        assert!(sink.try_emit(mk_ev(2, "normal event")));
        // 3rd event exceeds max_events=2 -> dropped without blocking
        assert!(!sink.try_emit(mk_ev(3, "overflow event")));
        assert_eq!(sink.dropped_event_count(), 1);

        sink.set_unavailable(true);
        assert!(!sink.try_emit(mk_ev(4, "unavailable sink event")));
        assert_eq!(sink.dropped_event_count(), 2);

        let first_msg = &sink.events()[0].message;
        assert!(!first_msg.contains("192.168.4.49"));
        assert!(!first_msg.contains("00:0E:58:AA:BB:CC"));
        assert!(!first_msg.contains("secret123"));
        assert!(first_msg.contains("[REDACTED_LAN_IP]"));
        assert!(first_msg.contains("[REDACTED_MAC]"));
        assert!(first_msg.contains("[REDACTED_SECRET]"));
    }

    fn diag(correlation_id: &str, message: &str) -> DiagnosticEvent {
        DiagnosticEvent {
            schema_version: String::new(),
            timestamp_mono_ns: 1,
            run_id: "run-01".to_string(),
            case_id: "Q00-sink".to_string(),
            correlation_id: correlation_id.to_string(),
            member_id: "spk-a".to_string(),
            group_id: "grp-1".to_string(),
            source_epoch: 1,
            state_revision: 1,
            event_kind: "test".to_string(),
            message: message.to_string(),
            queue_depth: 0,
            latency_us: 0,
            fault: None,
            cause: None,
        }
    }

    /// Serialized size of a `diag` event. Every event in the sink tests below uses a 6-character
    /// correlation id and an 8-character message, so they all have exactly this size.
    fn one_event_bytes() -> usize {
        let mut probe = BoundedDiagnosticSink::new(1, 1 << 20);
        assert!(probe.try_emit(diag("corr-1", "ordinary")));
        probe.used_bytes()
    }

    fn kept_ids(sink: &BoundedDiagnosticSink) -> Vec<&str> {
        sink.events()
            .iter()
            .map(|e| e.correlation_id.as_str())
            .collect()
    }

    /// Every event handed to the sink is either stored or counted as dropped.
    fn assert_accounting_holds(sink: &BoundedDiagnosticSink) {
        assert_eq!(
            sink.emitted_event_count(),
            sink.events().len() as u64 + sink.dropped_event_count()
        );
    }

    #[test]
    fn a_critical_event_evicts_the_oldest_ordinary_event_when_the_sink_is_full() {
        let one = one_event_bytes();
        let mut sink = BoundedDiagnosticSink::new(100, one * 2);
        assert!(sink.try_emit(diag("corr-1", "ordinary")));
        assert!(sink.try_emit(diag("corr-2", "ordinary")));
        // No room for a third ordinary event: it is dropped, and counted.
        assert!(!sink.try_emit(diag("corr-3", "ordinary")));
        assert!(sink.emit_critical(diag("corr-C", "critical")));
        assert_eq!(kept_ids(&sink), ["corr-2", "corr-C"]);
        assert_eq!(
            (sink.dropped_event_count(), sink.evicted_event_count()),
            (2, 1)
        );
        assert!(sink.is_evidence_complete());
        assert_accounting_holds(&sink);
    }

    #[test]
    fn eviction_skips_older_critical_events_and_takes_the_oldest_ordinary_one() {
        let one = one_event_bytes();
        let mut sink = BoundedDiagnosticSink::new(100, one * 3);
        assert!(sink.emit_critical(diag("corr-1", "critical")));
        assert!(sink.try_emit(diag("corr-2", "ordinary")));
        assert!(sink.try_emit(diag("corr-3", "ordinary")));
        assert!(sink.emit_critical(diag("corr-C", "critical")));
        assert_eq!(kept_ids(&sink), ["corr-1", "corr-3", "corr-C"]);
        assert_eq!(sink.evicted_event_count(), 1);
        assert!(sink.is_evidence_complete());
        assert_accounting_holds(&sink);
    }

    #[test]
    fn critical_events_are_never_evicted_and_losing_one_marks_the_evidence_incomplete() {
        let mut sink = BoundedDiagnosticSink::new(2, 1 << 20);
        assert!(sink.emit_critical(diag("corr-1", "critical")));
        assert!(sink.emit_critical(diag("corr-2", "critical")));
        assert!(sink.is_evidence_complete());
        // The sink is full of critical events: there is nothing to evict.
        assert!(!sink.emit_critical(diag("corr-3", "critical")));
        assert!(!sink.is_evidence_complete());
        assert_eq!(sink.critical_evidence_lost(), 1);
        assert!(!sink.try_emit(diag("corr-4", "ordinary")));
        assert_eq!(kept_ids(&sink), ["corr-1", "corr-2"]);
        assert_eq!(
            (sink.dropped_event_count(), sink.evicted_event_count()),
            (2, 0)
        );
        assert_eq!(sink.critical_evidence_lost(), 1);
        assert_accounting_holds(&sink);
    }

    #[test]
    fn an_unavailable_or_zero_capacity_sink_loses_critical_evidence_without_blocking() {
        let mut unavailable = BoundedDiagnosticSink::new(10, 1 << 20);
        unavailable.set_unavailable(true);
        assert!(!unavailable.emit_critical(diag("corr-1", "critical")));
        assert_eq!(unavailable.critical_evidence_lost(), 1);
        assert_eq!(unavailable.dropped_event_count(), 1);
        assert!(!unavailable.is_evidence_complete());
        // Storing the next critical event once the sink is back does not forgive the loss.
        unavailable.set_unavailable(false);
        assert!(unavailable.emit_critical(diag("corr-2", "critical")));
        assert!(!unavailable.is_evidence_complete());
        assert_accounting_holds(&unavailable);

        let mut zero = BoundedDiagnosticSink::new(0, 0);
        assert!(!zero.emit_critical(diag("corr-1", "critical")));
        assert!(!zero.is_evidence_complete());
        assert_accounting_holds(&zero);
    }

    #[test]
    fn a_critical_event_that_cannot_fit_evicts_nothing() {
        let one = one_event_bytes();
        let mut sink = BoundedDiagnosticSink::new(10, one + 10);
        assert!(sink.try_emit(diag("corr-1", "ordinary")));
        // Larger than the whole byte budget: evicting the ordinary event would not help.
        let too_big = "x".repeat(300);
        assert!(!sink.emit_critical(diag("corr-C", &too_big)));
        assert_eq!(kept_ids(&sink), ["corr-1"]);
        assert_eq!(sink.evicted_event_count(), 0);
        assert_eq!(sink.critical_evidence_lost(), 1);
        assert_accounting_holds(&sink);
    }

    #[test]
    fn a_healthy_sink_keeps_critical_evidence_complete_and_still_redacts_it() {
        let mut sink = BoundedDiagnosticSink::new(10, 1 << 20);
        assert!(sink.emit_critical(diag("corr-1", "token=abc123 ok")));
        assert!(sink.try_emit(diag("corr-2", "ordinary")));
        assert!(sink.is_evidence_complete());
        assert_eq!(sink.events()[0].message, "token=[REDACTED_SECRET] ok");
        assert!(!sink.to_jsonl().contains("abc123"));
        assert_eq!(sink.dropped_event_count(), 0);
        assert_accounting_holds(&sink);
    }

    fn diag_at(t_ns: u64, correlation_id: &str) -> DiagnosticEvent {
        let mut event = diag(correlation_id, "ordinary");
        event.timestamp_mono_ns = t_ns;
        event
    }

    #[test]
    fn the_event_rate_is_bounded_per_window_and_critical_events_are_not_rate_limited() {
        let mut sink = BoundedDiagnosticSink::new(100, 1 << 20).with_rate_limit(3, 1_000);
        // Window 1 (t = 0..999): three events pass, the rest are rate limited and counted.
        for (t, id) in [(0, "corr-0"), (100, "corr-1"), (200, "corr-2")] {
            assert!(sink.try_emit(diag_at(t, id)));
        }
        assert!(!sink.try_emit(diag_at(300, "corr-3")));
        assert!(!sink.try_emit(diag_at(400, "corr-4")));
        // Window 2 starts at t = 1000: the budget is renewed.
        for (t, id) in [(1_000, "corr-5"), (1_100, "corr-6"), (1_200, "corr-7")] {
            assert!(sink.try_emit(diag_at(t, id)));
        }
        assert!(!sink.try_emit(diag_at(1_300, "corr-8")));
        // A critical event is not rate limited even though the window is spent.
        let mut critical = diag_at(1_400, "corr-C");
        critical.message = "critical".to_string();
        assert!(sink.emit_critical(critical));
        assert_eq!(
            kept_ids(&sink),
            [
                "corr-0", "corr-1", "corr-2", "corr-5", "corr-6", "corr-7", "corr-C"
            ]
        );
        assert_eq!(sink.rate_limited_event_count(), 3);
        assert_eq!(sink.dropped_event_count(), 3);
        assert!(sink.is_evidence_complete());
        assert_accounting_holds(&sink);
    }

    #[test]
    fn without_a_rate_limit_a_burst_is_stored_in_full() {
        // Paired positive for the rate limit above.
        let mut sink = BoundedDiagnosticSink::new(100, 1 << 20);
        for t in 0..10u64 {
            assert!(sink.try_emit(diag_at(t, "corr-1")));
        }
        assert_eq!(sink.rate_limited_event_count(), 0);
        assert_eq!(sink.dropped_event_count(), 0);
    }

    #[test]
    fn timestamps_that_go_backwards_are_counted_but_still_logged() {
        let mut sink = BoundedDiagnosticSink::new(10, 1 << 20);
        assert!(sink.try_emit(diag_at(100, "corr-1")));
        assert!(sink.try_emit(diag_at(200, "corr-2")));
        assert!(sink.try_emit(diag_at(150, "corr-3"))); // earlier than 200
        assert!(sink.try_emit(diag_at(200, "corr-4"))); // equal is fine
        assert!(sink.try_emit(diag_at(250, "corr-5")));
        assert_eq!(sink.non_monotonic_event_count(), 1);
        assert_eq!(sink.events().len(), 5);

        let mut clean = BoundedDiagnosticSink::new(10, 1 << 20);
        for t in [10, 10, 20, 30] {
            assert!(clean.try_emit(diag_at(t, "corr-1")));
        }
        assert_eq!(clean.non_monotonic_event_count(), 0);
    }

    #[test]
    fn fault_and_cause_are_stored_redacted_and_omitted_from_json_when_absent() {
        let mut sink = BoundedDiagnosticSink::new(10, 1 << 20);
        let mut event = diag("corr-1", "ordinary");
        event.fault = Some("drop_final_block member=spk-a".to_string());
        event.cause = Some("oracle: bad <- token=s3cr3tCauseTok <- 10.0.0.9".to_string());
        assert!(sink.try_emit(event));
        assert!(sink.try_emit(diag("corr-2", "ordinary")));

        let jsonl = sink.to_jsonl();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains(r#""fault":"drop_final_block member=spk-a""#));
        assert!(lines[0].contains(r#""cause":"#));
        // Redacted like every other free-text field.
        assert!(!jsonl.contains("s3cr3tCauseTok"), "{jsonl}");
        assert!(!jsonl.contains("10.0.0.9"), "{jsonl}");
        // Absent fields are omitted entirely, so the log keeps its existing shape...
        assert!(!lines[1].contains("fault") && !lines[1].contains("cause"));
        // ...and a line in that older shape still parses, with both fields defaulting to None.
        let back: DiagnosticEvent = serde_json::from_str(lines[1]).expect("old-shape line parses");
        assert_eq!((back.fault, back.cause), (None, None));
    }

    #[test]
    fn the_human_summary_is_one_concise_line_that_flags_incomplete_evidence() {
        let mut sink = BoundedDiagnosticSink::new(5, 100);
        assert_eq!(
            sink.human_summary(),
            "diagnostics: emitted=0 stored=0/5 dropped=0 (evicted=0 rate_limited=0) critical_lost=0 out_of_order=0 bytes=0/100 evidence=complete"
        );
        sink.set_unavailable(true);
        assert!(!sink.emit_critical(diag("corr-1", "critical")));
        let summary = sink.human_summary();
        assert!(summary.contains("critical_lost=1"), "{summary}");
        assert!(summary.ends_with("evidence=INCOMPLETE"), "{summary}");
        assert!(!summary.contains('\n'));
    }

    #[test]
    fn member_and_group_ids_become_keyed_stable_pseudonyms_and_the_key_is_never_printed() {
        let mut sink = BoundedDiagnosticSink::new(10, 1 << 20).with_pseudonym_key([7u8; 32]);
        let with_ids = |correlation_id: &str, member: &str, group: &str| {
            let mut event = diag(correlation_id, "ordinary");
            event.member_id = member.to_string();
            event.group_id = group.to_string();
            event
        };
        assert!(sink.try_emit(with_ids("corr-1", "spk-office-s5", "grp-house")));
        assert!(sink.try_emit(with_ids("corr-2", "spk-office-s5", "grp-other")));
        assert!(sink.try_emit(with_ids("corr-3", "spk-den-s3", "grp-house")));

        let events = sink.events();
        // Stable: the same id gives the same pseudonym, and distinct ids give distinct ones.
        assert_eq!(events[0].member_id, events[1].member_id);
        assert_ne!(events[0].member_id, events[2].member_id);
        assert_eq!(events[0].group_id, events[2].group_id);
        assert_ne!(events[0].group_id, events[1].group_id);
        for id in [&events[0].member_id, &events[0].group_id] {
            assert!(id.starts_with("p-") && id.len() == 18, "{id}");
        }
        // The raw ids never reach the log.
        let jsonl = sink.to_jsonl();
        for raw in ["spk-office-s5", "spk-den-s3", "grp-house", "grp-other"] {
            assert!(!jsonl.contains(raw), "{raw} leaked: {jsonl}");
        }

        // A different key gives different pseudonyms for the same id.
        let mut other = BoundedDiagnosticSink::new(10, 1 << 20).with_pseudonym_key([8u8; 32]);
        assert!(other.try_emit(with_ids("corr-1", "spk-office-s5", "grp-house")));
        assert_ne!(other.events()[0].member_id, sink.events()[0].member_id);

        // The key itself is never printed.
        let debug = format!("{sink:?}");
        assert!(debug.contains("PseudonymKey([REDACTED])"), "{debug}");
        assert!(!debug.contains("7, 7, 7"), "{debug}");

        // Paired positive: without a key, ids pass through unchanged (they are still redacted
        // for secret shapes, but a plain id is not a secret).
        let mut plain = BoundedDiagnosticSink::new(10, 1 << 20);
        assert!(plain.try_emit(with_ids("corr-1", "spk-office-s5", "grp-house")));
        assert_eq!(plain.events()[0].member_id, "spk-office-s5");
    }

    #[test]
    fn audio_payloads_are_redacted_but_counters_with_similar_names_are_not() {
        assert_eq!(
            redact_sensitive_text("samples=[1, -2, 3000] rate=48000"),
            "samples=[REDACTED_AUDIO] rate=48000"
        );
        assert_eq!(
            redact_sensitive_text(r#"{"payload":"AAECAwQF","n":2}"#),
            r#"{"payload":"[REDACTED_AUDIO]","n":2}"#
        );
        assert_eq!(
            redact_sensitive_text("pcm=deadbeef00 ok"),
            "pcm=[REDACTED_AUDIO] ok"
        );
        let benign = "num_samples=480 payload_len=1024 audio_state=ready";
        assert_eq!(redact_sensitive_text(benign), benign);
        let once = redact_sensitive_text("samples=[1, 2, 3] pcm=abc");
        assert_eq!(redact_sensitive_text(&once), once);
    }

    #[test]
    fn redaction_leaves_benign_text_and_whitespace_unchanged() {
        for benign in [
            "retry=3 latency_us=40 member spk-office-s5 state ready",
            "version 1.2.3 build 10.0.0 ok",
            "public 8.8.8.8 loopback 127.0.0.1 global 2001:db8::1",
            "the bearer of news",
            "Sonos_short RINCON_xyz HHID_",
            "line one\n\tline  two   three",
            "naïve café ünï",
        ] {
            assert_eq!(redact_sensitive_text(benign), benign);
        }
    }

    #[test]
    fn a_secret_is_redacted_without_destroying_the_text_after_it() {
        // Previously everything after the first key was replaced.
        assert_eq!(
            redact_sensitive_text("auth failed token=abc123 retry=3 latency_us=40"),
            "auth failed token=[REDACTED_SECRET] retry=3 latency_us=40"
        );
        assert_eq!(
            redact_sensitive_text("line1\n  token=abc\tend"),
            "line1\n  token=[REDACTED_SECRET]\tend"
        );
    }

    #[test]
    fn secret_keys_are_matched_case_insensitively_and_in_every_form() {
        assert_eq!(
            redact_sensitive_text("TOKEN=aaa Password=bbb api_key=ccc"),
            "TOKEN=[REDACTED_SECRET] Password=[REDACTED_SECRET] api_key=[REDACTED_SECRET]"
        );
        assert_eq!(
            redact_sensitive_text("GET /x?id=7&token=abc&user=bob"),
            "GET /x?id=7&token=[REDACTED_SECRET]&user=bob"
        );
        assert_eq!(
            redact_sensitive_text(r#"{"token":"abc","ok":true}"#),
            r#"{"token":"[REDACTED_SECRET]","ok":true}"#
        );
        assert_eq!(
            redact_sensitive_text("token: abc def"),
            "token: [REDACTED_SECRET] def"
        );
    }

    #[test]
    fn bearer_credentials_and_authorization_headers_are_redacted() {
        assert_eq!(
            redact_sensitive_text("using Bearer abcDEF123 now"),
            "using Bearer [REDACTED_SECRET] now"
        );
        assert_eq!(
            redact_sensitive_text("Authorization: Bearer abc.def.ghi end"),
            "Authorization: [REDACTED_SECRET]"
        );
        assert_eq!(
            redact_sensitive_text("authorization: bearer xyz"),
            "authorization: [REDACTED_SECRET]"
        );
        // The marker the bearer pass writes must not end the header value early (a stray `]`
        // used to survive), yet a real delimiter after it still does, so later text is kept.
        assert_eq!(
            redact_sensitive_text("(Authorization: Bearer abc.def.ghi) next"),
            "(Authorization: [REDACTED_SECRET]) next"
        );
        // The quoted and `=` forms end the value where they always did.
        assert_eq!(
            redact_sensitive_text(r#"{"Authorization":"Bearer abc.def.ghi"}"#),
            r#"{"Authorization":"[REDACTED_SECRET]"}"#
        );
        assert_eq!(
            redact_sensitive_text("Authorization=Bearer abc.def.ghi&x=1"),
            "Authorization=[REDACTED_SECRET]&x=1"
        );
        // A header value never runs onto the next line, with a finished marker or an unfinished one.
        assert_eq!(
            redact_sensitive_text("Authorization: Bearer abc.def.ghi\nnext line"),
            "Authorization: [REDACTED_SECRET]\nnext line"
        );
        assert_eq!(
            redact_sensitive_text("Authorization: [REDACTED_\nrest"),
            "Authorization: [REDACTED_SECRET]\nrest"
        );
        // Idempotent for real: the first pass must reach exactly this string, then change nothing.
        let once = redact_sensitive_text("Authorization: Bearer abc.def.ghi end");
        assert_eq!(once, "Authorization: [REDACTED_SECRET]");
        assert_eq!(redact_sensitive_text(&once), once);
    }

    #[test]
    fn text_that_only_looks_like_a_finished_marker_does_not_shield_a_secret() {
        // Each of these was skipped as "already redacted" because the value merely started with
        // `[REDACTED_`. The secret must be gone, and the result must be stable.
        for (raw, secret, want) in [
            (
                "Authorization: [REDACTED_ID] sk-live-abcdef123",
                "sk-live-abcdef123",
                "Authorization: [REDACTED_SECRET]",
            ),
            (
                "password=[REDACTED_X]hunter2",
                "hunter2",
                "password=[REDACTED_SECRET]",
            ),
            (
                "token=[REDACTED_]realsecret",
                "realsecret",
                "token=[REDACTED_SECRET]",
            ),
            (
                "token=[REDACTED_SECRET]hunter2",
                "hunter2",
                "token=[REDACTED_SECRET]",
            ),
            (
                r#"{"password":"[REDACTED_X]hunter2"}"#,
                "hunter2",
                r#"{"password":"[REDACTED_SECRET]"}"#,
            ),
        ] {
            let out = redact_sensitive_text(raw);
            assert!(!out.contains(secret), "{raw} leaked: {out}");
            assert_eq!(out, want, "{raw}");
            assert_eq!(
                redact_sensitive_text(&out),
                out,
                "{raw}: second pass differs"
            );
        }

        // Paired positive: a value that IS exactly one of the five finished markers is left
        // alone, and the text after it survives.
        for already in [
            "token=[REDACTED_SECRET] next",
            "serial=[REDACTED_ID] next",
            "Authorization: [REDACTED_SECRET]",
            "mac=[REDACTED_MAC] next",
            "samples=[REDACTED_AUDIO] next",
            r#"{"token":"[REDACTED_SECRET]","ok":true}"#,
        ] {
            assert_eq!(redact_sensitive_text(already), already);
        }

        // Brackets that wrap a key=value pair from outside still end its value.
        assert_eq!(
            redact_sensitive_text("[token=abc] next"),
            "[token=[REDACTED_SECRET]] next"
        );
    }

    #[test]
    fn every_sensitive_ipv4_range_is_redacted_and_the_rest_is_not() {
        assert_eq!(
            redact_sensitive_text(
                "a 10.1.2.3 b 172.16.0.9 c 172.31.255.1 d 192.168.1.20. e 169.254.1.1 f 100.64.0.5 g 100.127.9.9"
            ),
            "a [REDACTED_LAN_IP] b [REDACTED_LAN_IP] c [REDACTED_LAN_IP] d [REDACTED_LAN_IP]. e [REDACTED_LAN_IP] f [REDACTED_LAN_IP] g [REDACTED_LAN_IP]"
        );
        // Just outside each range, public, loopback, and malformed addresses stay as they are.
        let outside = "8.8.8.8 172.15.0.1 172.32.0.1 100.63.0.1 100.128.0.1 11.0.0.1 192.169.0.1 127.0.0.1 10.1.2.300 10.1.2";
        assert_eq!(redact_sensitive_text(outside), outside);
    }

    #[test]
    fn tailnet_and_link_local_ipv6_are_redacted_and_global_ipv6_is_not() {
        assert_eq!(
            redact_sensitive_text("peer fd7a:115c:a1e0::1 and fe80::1ff:fe23:4567:890a ok"),
            "peer [REDACTED_LAN_IP] and [REDACTED_LAN_IP] ok"
        );
        assert_eq!(
            redact_sensitive_text("global 2001:db8::1 ok"),
            "global 2001:db8::1 ok"
        );
    }

    #[test]
    fn macs_are_redacted_in_every_separator_form_including_when_glued_to_a_key() {
        assert_eq!(
            redact_sensitive_text(
                "mac=00:0E:58:AA:BB:CC peer 00-0E-58-aa-bb-cc serial B8-E9-37-AA-BB-CC:5 src_mac=00:0E:58:AA:BB:CC end"
            ),
            "mac=[REDACTED_ID] peer [REDACTED_MAC] serial [REDACTED_MAC]:5 src_mac=[REDACTED_MAC] end"
        );
    }

    #[test]
    fn household_serial_and_udn_identifiers_are_redacted() {
        assert_eq!(
            redact_sensitive_text("device RINCON_000E58AABBCC01400 ok"),
            "device RINCON_[REDACTED_ID] ok"
        );
        assert_eq!(
            redact_sensitive_text("house Sonos_abcdef0123456789 x"),
            "house Sonos_[REDACTED_ID] x"
        );
        assert_eq!(
            redact_sensitive_text("HHID_x9 done"),
            "HHID_[REDACTED_ID] done"
        );
        assert_eq!(
            redact_sensitive_text("serial_number=SN12345 sn:XY9"),
            "serial_number=[REDACTED_ID] sn:[REDACTED_ID]"
        );
    }

    #[test]
    fn every_category_the_doc_names_is_actually_redacted() {
        for (raw, needle) in [
            ("token=aaa111", "aaa111"),
            ("00:0E:58:AA:BB:CC", "00:0E:58"),
            ("00-0E-58-AA-BB-CC", "00-0E-58"),
            ("10.9.8.7", "10.9.8.7"),
            ("100.101.102.103", "100.101.102.103"),
            ("fd7a:115c:a1e0::5", "fd7a:115c"),
            ("HHID_zz9", "zz9"),
            ("serial_number=SNX77", "SNX77"),
            ("Sonos_0123456789abcdef", "0123456789abcdef"),
            ("RINCON_000E58AABBCC01400", "000E58AABBCC"),
        ] {
            let out = redact_sensitive_text(&format!("event {raw} end"));
            assert!(!out.contains(needle), "{raw} leaked: {out}");
            assert!(out.starts_with("event "), "{raw}: prefix lost: {out}");
            assert!(out.ends_with(" end"), "{raw}: suffix lost: {out}");
        }
    }

    #[test]
    fn redaction_is_idempotent_and_byte_safe_on_non_ascii_text() {
        let sample = "mac=00:0E:58:AA:BB:CC ip 10.1.2.3 fd7a::1 token=xyz RINCON_000E58AABBCC01400 HHID_a1 Authorization: Bearer abcDEF12345";
        let once = redact_sensitive_text(sample);
        assert!(!once.contains("abcDEF12345") && !once.contains("10.1.2.3"));
        assert_eq!(redact_sensitive_text(&once), once);

        assert_eq!(
            redact_sensitive_text("naïve café token=abc ünï\n\tline  two"),
            "naïve café token=[REDACTED_SECRET] ünï\n\tline  two"
        );
        assert_eq!(redact_sensitive_text("é10.0.0.1é"), "é[REDACTED_LAN_IP]é");
    }

    #[test]
    fn the_bounded_sink_never_lets_a_planted_secret_reach_the_log_from_any_field() {
        let mut sink = BoundedDiagnosticSink::new(4, 8192);
        let event = |run_id: &str,
                     case_id: &str,
                     correlation_id: &str,
                     member_id: &str,
                     group_id: &str,
                     event_kind: &str,
                     message: &str| DiagnosticEvent {
            schema_version: String::new(),
            timestamp_mono_ns: 1,
            run_id: run_id.to_string(),
            case_id: case_id.to_string(),
            correlation_id: correlation_id.to_string(),
            member_id: member_id.to_string(),
            group_id: group_id.to_string(),
            source_epoch: 1,
            state_revision: 1,
            event_kind: event_kind.to_string(),
            message: message.to_string(),
            queue_depth: 0,
            latency_us: 0,
            fault: None,
            cause: None,
        };

        // A different planted identifier in every field.
        assert!(sink.try_emit(event(
            "Bearer s3cr3tRunTok9",
            "RINCON_000E58AABBCC01400",
            "10.20.30.40",
            "00:0E:58:AA:BB:CC",
            "token=s3cr3tGroupTok",
            "serial_number=SNPLANTED77",
            "peer fd7a:115c:a1e0::9 ok",
        )));
        let jsonl = sink.to_jsonl();
        for leaked in [
            "s3cr3tRunTok9",
            "000E58AABBCC",
            "10.20.30.40",
            "00:0E:58",
            "s3cr3tGroupTok",
            "SNPLANTED77",
            "fd7a:115c",
        ] {
            assert!(!jsonl.contains(leaked), "{leaked} reached the log: {jsonl}");
        }

        // Paired positive: benign identifiers pass through untouched.
        assert!(sink.try_emit(event(
            "run-01",
            "Q00-sink",
            "corr-1",
            "spk-a",
            "grp-1",
            "test",
            "normal event",
        )));
        let benign = &sink.events()[1];
        assert_eq!(benign.run_id, "run-01");
        assert_eq!(benign.member_id, "spk-a");
        assert_eq!(benign.group_id, "grp-1");
        assert_eq!(benign.message, "normal event");
    }

    #[test]
    fn deterministic_network_schedule_replays_identically() {
        let cfg = NetworkScheduleConfig::default();
        let mut s1 = NetworkSchedule::new(cfg.clone());
        let mut s2 = NetworkSchedule::new(cfg);

        for seq in 0..500 {
            let t = seq * 5_333_333;
            assert_eq!(s1.evaluate_packet(seq, t), s2.evaluate_packet(seq, t));
        }
    }

    #[test]
    fn suite_receipt_fails_when_any_case_is_blocked_or_not_run() {
        let c1 = TestCaseReceipt {
            case_id: "c1".to_string(),
            requirement_id: "REQ-1".to_string(),
            tier: TestTier::Smoke,
            evidence_class: EvidenceClass::HostSimulation,
            seed: 1,
            outcome: CaseOutcome::Passed,
            duration_ns: 100,
            replay_command: "cargo test".to_string(),
            expected_oracle: "pass".to_string(),
            observed_oracle: "pass".to_string(),
            first_causal_error: None,
        };
        let c2 = TestCaseReceipt {
            outcome: CaseOutcome::Blocked,
            ..c1.clone()
        };
        let receipt = SuiteExecutionReceipt::from_cases(
            "q00",
            "run-1",
            TestTier::Smoke,
            vec![c1, c2],
            0,
            BTreeMap::new(),
        );
        assert!(!receipt.overall_pass);
        assert_eq!(receipt.passed, 1);
        assert_eq!(receipt.blocked, 1);
    }
}
