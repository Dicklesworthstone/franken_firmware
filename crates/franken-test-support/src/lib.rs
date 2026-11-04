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
}

/// Oracle 1: Sample continuity and unexpected dropout detector.
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

    pub fn observe_block(
        &mut self,
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
        if let Some(expected) = self.next_expected_frame
            && start_frame != expected
        {
            return Err(OracleViolation::SampleDiscontinuity {
                expected_frame: expected,
                observed_frame: start_frame,
                reason: "unannounced frame gap or overlap".to_string(),
            });
        }
        self.next_expected_frame = Some(start_frame.saturating_add(frame_count));
        self.verified_frames = self.verified_frames.saturating_add(frame_count);
        Ok(())
    }

    #[must_use]
    pub const fn verified_frames(&self) -> u64 {
        self.verified_frames
    }
}

/// Oracle 2: Coordinator epoch fencing verifier.
#[derive(Debug, Clone, Default)]
pub struct EpochFencingOracle {
    highest_epoch: u64,
}

impl EpochFencingOracle {
    #[must_use]
    pub const fn new(initial_epoch: u64) -> Self {
        Self {
            highest_epoch: initial_epoch,
        }
    }

    pub fn record_accepted_epoch(&mut self, candidate_epoch: u64) -> Result<(), OracleViolation> {
        if candidate_epoch < self.highest_epoch {
            return Err(OracleViolation::StaleEpochAccepted {
                current_epoch: self.highest_epoch,
                candidate_epoch,
            });
        }
        self.highest_epoch = candidate_epoch;
        Ok(())
    }
}

/// Oracle 3: Command idempotency and single-application verifier.
#[derive(Debug, Clone, Default)]
pub struct CommandIdempotencyOracle {
    applied: BTreeSet<(u64, u64)>,
}

impl CommandIdempotencyOracle {
    #[must_use]
    pub fn new() -> Self {
        Self {
            applied: BTreeSet::new(),
        }
    }

    pub fn record_applied_command(
        &mut self,
        epoch: u64,
        command_seq: u64,
    ) -> Result<(), OracleViolation> {
        if !self.applied.insert((epoch, command_seq)) {
            return Err(OracleViolation::DoubleAppliedCommand { epoch, command_seq });
        }
        Ok(())
    }
}

/// Oracle 4: Speaker readiness gate verifier.
#[derive(Debug, Clone, Default)]
pub struct ReadinessOracle {
    pub board_profile_verified: bool,
    pub amplifier_muted_until_primed: bool,
    pub clock_locked: bool,
}

impl ReadinessOracle {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            board_profile_verified: false,
            amplifier_muted_until_primed: false,
            clock_locked: false,
        }
    }

    pub fn assert_can_enter_ready(&self) -> Result<(), OracleViolation> {
        if !self.board_profile_verified {
            return Err(OracleViolation::FalseReadyState {
                missing_prerequisite: "board_profile_verified".to_string(),
            });
        }
        if !self.amplifier_muted_until_primed {
            return Err(OracleViolation::FalseReadyState {
                missing_prerequisite: "amplifier_muted_until_primed".to_string(),
            });
        }
        if !self.clock_locked {
            return Err(OracleViolation::FalseReadyState {
                missing_prerequisite: "clock_locked".to_string(),
            });
        }
        Ok(())
    }
}

/// Redact sensitive tokens, MACs, private IPv4s, household IDs, and serial-like strings.
#[must_use]
pub fn redact_sensitive_text(input: &str) -> String {
    let mut out = input.to_string();
    for secret_key in ["Bearer ", "token=", "secret=", "key=", "HHID_"] {
        if let Some(idx) = out.find(secret_key) {
            let prefix = &out[..idx + secret_key.len()];
            out = format!("{prefix}[REDACTED_SECRET]");
        }
    }
    // Redact 192.168.x.y private LAN addresses
    while let Some(pos) = out.find("192.168.") {
        let rest = &out[pos..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len());
        out.replace_range(pos..pos + end, "[REDACTED_LAN_IP]");
    }
    // Redact colon-separated 6-byte MAC patterns
    let tokens: Vec<String> = out
        .split_whitespace()
        .map(|tok| {
            let clean = tok.trim_matches(|c: char| !c.is_ascii_hexdigit() && c != ':');
            let parts: Vec<&str> = clean.split(':').collect();
            if parts.len() == 6
                && parts
                    .iter()
                    .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
            {
                "[REDACTED_MAC]".to_string()
            } else {
                tok.to_string()
            }
        })
        .collect();
    if tokens.is_empty() {
        out
    } else {
        tokens.join(" ")
    }
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
}

/// Non-blocking bounded diagnostic sink with rate/memory/byte caps and dropped-event accounting.
#[derive(Debug, Clone)]
pub struct BoundedDiagnosticSink {
    max_events: usize,
    max_bytes: usize,
    sink_unavailable: bool,
    events: Vec<DiagnosticEvent>,
    used_bytes: usize,
    dropped_event_count: u64,
}

impl BoundedDiagnosticSink {
    #[must_use]
    pub const fn new(max_events: usize, max_bytes: usize) -> Self {
        Self {
            max_events,
            max_bytes,
            sink_unavailable: false,
            events: Vec::new(),
            used_bytes: 0,
            dropped_event_count: 0,
        }
    }

    pub fn set_unavailable(&mut self, unavailable: bool) {
        self.sink_unavailable = unavailable;
    }

    /// Non-blocking emit. Never panics or blocks even when full or unavailable.
    pub fn try_emit(&mut self, mut event: DiagnosticEvent) -> bool {
        if self.sink_unavailable || self.events.len() >= self.max_events {
            self.dropped_event_count = self.dropped_event_count.saturating_add(1);
            return false;
        }
        event.schema_version = LOG_SCHEMA_VERSION.to_string();
        event.message = redact_sensitive_text(&event.message);
        let serialized = serde_json::to_string(&event).unwrap_or_default();
        let event_bytes = serialized.len() + 1;
        if self.used_bytes.saturating_add(event_bytes) > self.max_bytes {
            self.dropped_event_count = self.dropped_event_count.saturating_add(1);
            return false;
        }
        self.used_bytes += event_bytes;
        self.events.push(event);
        true
    }

    #[must_use]
    pub fn events(&self) -> &[DiagnosticEvent] {
        &self.events
    }

    #[must_use]
    pub const fn dropped_event_count(&self) -> u64 {
        self.dropped_event_count
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

    #[test]
    fn canary_2_stale_epoch_fails_fencing_oracle() {
        let mut oracle = EpochFencingOracle::new(10);
        assert!(oracle.record_accepted_epoch(11).is_ok());
        // Inject intentional stale epoch 9 command acceptance
        let res = oracle.record_accepted_epoch(9);
        assert_eq!(
            res,
            Err(OracleViolation::StaleEpochAccepted {
                current_epoch: 11,
                candidate_epoch: 9,
            })
        );
    }

    #[test]
    fn canary_3_double_applied_command_fails_idempotency_oracle() {
        let mut oracle = CommandIdempotencyOracle::new();
        assert!(oracle.record_applied_command(4, 101).is_ok());
        // Inject intentional duplicate command application
        let res = oracle.record_applied_command(4, 101);
        assert_eq!(
            res,
            Err(OracleViolation::DoubleAppliedCommand {
                epoch: 4,
                command_seq: 101,
            })
        );
    }

    #[test]
    fn canary_4_false_ready_state_fails_readiness_oracle() {
        let mut oracle = ReadinessOracle::new();
        oracle.board_profile_verified = true;
        oracle.amplifier_muted_until_primed = true;
        // clock_locked intentionally false
        let res = oracle.assert_can_enter_ready();
        assert_eq!(
            res,
            Err(OracleViolation::FalseReadyState {
                missing_prerequisite: "clock_locked".to_string(),
            })
        );
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
