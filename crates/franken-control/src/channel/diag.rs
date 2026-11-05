//! Structured JSONL diagnostics for the control channel (N02 / `ffw-ugf`).
//!
//! One record is written for every command that reaches a terminal outcome in a
//! [`step`](super::pipeline::ControlChannel::step): committed, refused (with the reason), withdrawn,
//! expired, or a cancel that was applied. A record is one line of JSON in the shared `ffw.log.v1`
//! shape, so a log reader built for the other diagnostics reads these too:
//!
//! ```text
//! {"schema_version":"ffw.log.v1","timestamp_mono_ns":..,"run_id":..,"case_id":..,
//!  "correlation_id":"p-<peer pseudonym>#<seq>","member_id":"p-.."|"","group_id":"p-..",
//!  "source_epoch":..,"state_revision":..,"event_kind":"n02.step.<outcome>","message":..,
//!  "queue_depth":..,"latency_us":..,"cause":..?}
//! ```
//!
//! # What reaches a record, and what never does
//!
//! Nothing a peer supplied is ever copied into a record. Peer, member and group identifiers are
//! replaced by keyed one-way **pseudonyms** (`p-` and sixteen hex characters), computed exactly as the
//! shared diagnostics sink computes them, so the same identifier gives the same pseudonym in both. The
//! free-text fields (`event_kind`, `message`, `cause`) are built only from a fixed vocabulary and from
//! numbers (revisions, epochs, command numbers, microseconds). `run_id` and `case_id` are labels the
//! harness chooses, validated to the label alphabet. Key material, proofs and the pseudonym key never
//! appear: the key type prints as `[REDACTED]`, and the channel never gives the log a secret.
//!
//! This is stronger than redacting after the fact: there is no path by which a refusal's input string
//! (a member id shaped like a token, say) can reach the text, so there is nothing to miss.
//!
//! # Bounds
//!
//! The log keeps at most `max_records` records and `max_bytes` bytes, and no line is longer than
//! [`MAX_LINE_BYTES`]. Nothing blocks. When the log is full an ordinary record is dropped and counted;
//! an internal fault (evidence the run cannot be trusted without) evicts the oldest ordinary record to
//! make room, and if even that cannot make room it is counted as `critical_lost`, which makes
//! [`ChannelLog::is_evidence_complete`] false. Every record handed to the log ends stored or counted:
//! `emitted == len + dropped`.
//!
//! Timestamps are the `now_ns` the owner gives `step`, clamped never to go backwards.
//!
//! # Acknowledgement records
//!
//! [`ControlChannel::acknowledge`](super::pipeline::ControlChannel::acknowledge) writes one more kind of
//! record, in the same shape: `n02.ack.on_time`, `n02.ack.late` or `n02.ack.superseded` for an
//! acknowledgement that completed its entry, and `n02.ack.rejected.<why>` for one that did not
//! (`duplicate`, `not_settled`, `unknown`, `out_of_window`, `mismatch`, `unauthenticated`). Its
//! `correlation_id` is the command's own (`p-<peer pseudonym>#<seq>`), so the two records join; its
//! `latency_us` is how long after the outcome was recorded the acknowledgement came (zero where that is
//! not meaningful); a rejected-for-authentication record carries the failure word as its `cause`. Nothing
//! the peer sent is copied: an unauthenticated acknowledgement's claimed identifier appears only as a
//! pseudonym.
//!
//! Acknowledgements are cheap for anyone to send, so their records are held to a **share** of the log:
//! at most half of `max_records` and half of `max_bytes`. Past it an acknowledgement record is dropped and
//! counted (`ack_dropped`, which is also in `dropped`), and can never push a command-outcome record out.
//! When an internal-fault record needs room, acknowledgement records are evicted before command records.
//! The log never blocks, never fails the call that wrote to it, and has no effect on any result.

use std::collections::VecDeque;
use std::fmt::{self, Write as _};

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::peer::{AuthFailure, PeerId};
use super::pipeline::{AckOutcome, Outcome, Refusal};
use franken_session::SessionError;

/// The shared diagnostics schema these records follow.
pub const LOG_SCHEMA_VERSION: &str = "ffw.log.v1";
/// Longest run or case label, in bytes.
pub const MAX_LABEL_LEN: usize = 64;
/// No record line is longer than this; a longer one is dropped and counted, never truncated.
pub const MAX_LINE_BYTES: usize = 1024;
/// Acknowledgement records may hold `1 / ACK_SHARE_DIVISOR` of the log's records and of its bytes.
const ACK_SHARE_DIVISOR: usize = 2;

/// A log that cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LogError {
    #[error(
        "`{field}` must be 1 to 64 bytes of a-z, 0-9, '.', '_' and '-', starting with a letter or digit"
    )]
    InvalidLabel { field: &'static str },
    #[error("`{field}` must be at least 1")]
    Zero { field: &'static str },
}

/// The secret that keys the pseudonyms. It is random per run and kept nowhere. It has no `Display`,
/// `Clone` or `PartialEq`, and its `Debug` prints nothing of it.
pub struct LogKey([u8; 32]);

impl LogKey {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for LogKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LogKey([REDACTED])")
    }
}

/// What a log is told about its run, and how much it may hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogConfig {
    run_id: String,
    case_id: String,
    max_records: usize,
    max_bytes: usize,
}

fn valid_label(raw: &str) -> bool {
    let starts_ok = raw
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    starts_ok
        && raw.len() <= MAX_LABEL_LEN
        && raw.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

impl LogConfig {
    /// `run_id` and `case_id` are labels chosen by the harness (not data from peers).
    pub fn new(
        run_id: &str,
        case_id: &str,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<Self, LogError> {
        if !valid_label(run_id) {
            return Err(LogError::InvalidLabel { field: "run_id" });
        }
        if !valid_label(case_id) {
            return Err(LogError::InvalidLabel { field: "case_id" });
        }
        if max_records == 0 {
            return Err(LogError::Zero {
                field: "max_records",
            });
        }
        if max_bytes == 0 {
            return Err(LogError::Zero { field: "max_bytes" });
        }
        Ok(Self {
            run_id: run_id.to_string(),
            case_id: case_id.to_string(),
            max_records,
            max_bytes,
        })
    }
}

/// Counters for the log itself.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LogStats {
    /// Records handed to the log.
    pub emitted: u64,
    /// Records currently held.
    pub stored: usize,
    /// Records not held: refused for want of room, too long, or evicted. `emitted == stored + dropped`.
    pub dropped: u64,
    /// Internal-fault records that could not be held even after evicting every ordinary record.
    pub critical_lost: u64,
    /// Bytes currently held.
    pub bytes: usize,
    /// Acknowledgement records currently held (a share of `stored`).
    pub ack_stored: usize,
    /// Acknowledgement records not held (a share of `dropped`).
    pub ack_dropped: u64,
}

/// What the channel knows about one settled command, gathered while the step runs and turned into a
/// record once the session is at hand. It holds peer-supplied strings only until then.
pub(crate) struct Fact {
    pub peer: PeerId,
    pub seq: u64,
    /// The member the command named, if any. Pseudonymized on its way out; never written as is.
    pub member: Option<String>,
    pub outcome: Outcome,
    /// The underlying reason, as a vocabulary word (never a session error's text).
    pub cause: Option<String>,
    /// The session's committed revision when the command settled.
    pub revision: u64,
    pub queue_depth: usize,
    pub waited_ns: u64,
    /// Evidence the run cannot be trusted without: an internal fault, or an outcome the ledger could
    /// not record.
    pub critical: bool,
}

/// The fields of one JSONL record, in the order the shared `ffw.log.v1` event writes them.
#[derive(Serialize)]
struct Record<'a> {
    schema_version: &'a str,
    timestamp_mono_ns: u64,
    run_id: &'a str,
    case_id: &'a str,
    correlation_id: String,
    member_id: String,
    group_id: String,
    source_epoch: u64,
    state_revision: u64,
    event_kind: String,
    message: String,
    queue_depth: usize,
    latency_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    cause: Option<String>,
}

/// What a held line is, for eviction and for the acknowledgement share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// A command-outcome record.
    Step,
    /// An internal-fault record: never evicted to make room for another.
    Critical,
    /// An acknowledgement record.
    Ack,
}

/// What the channel knows about one acknowledgement, turned into a record by [`ChannelLog::emit_ack`].
pub(crate) struct AckFact {
    pub peer: PeerId,
    pub seq: u64,
    pub outcome: AckOutcome,
    /// The session's committed revision when the acknowledgement arrived.
    pub revision: u64,
    pub queue_depth: usize,
}

/// The bounded JSONL log of one control channel.
pub struct ChannelLog {
    run_id: String,
    case_id: String,
    key: LogKey,
    max_records: usize,
    max_bytes: usize,
    /// Each held line, and what it is (a critical line is never evicted to make room for another).
    lines: VecDeque<(String, Class)>,
    used_bytes: usize,
    emitted: u64,
    dropped: u64,
    critical_lost: u64,
    last_ns: u64,
    /// The acknowledgement records held, their bytes, and how many were not held.
    ack_lines: usize,
    ack_bytes: usize,
    ack_dropped: u64,
    /// The share, as a divisor. Always [`ACK_SHARE_DIVISOR`] outside the tests that plant a wrong one.
    ack_share_divisor: usize,
}

impl fmt::Debug for ChannelLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelLog")
            .field("run_id", &self.run_id)
            .field("case_id", &self.case_id)
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl ChannelLog {
    #[must_use]
    pub fn new(config: LogConfig, key: LogKey) -> Self {
        Self {
            run_id: config.run_id,
            case_id: config.case_id,
            key,
            max_records: config.max_records,
            max_bytes: config.max_bytes,
            lines: VecDeque::new(),
            used_bytes: 0,
            emitted: 0,
            dropped: 0,
            critical_lost: 0,
            last_ns: 0,
            ack_lines: 0,
            ack_bytes: 0,
            ack_dropped: 0,
            ack_share_divisor: ACK_SHARE_DIVISOR,
        }
    }

    /// The stable, keyed, one-way stand-in for `id` used throughout the log: `p-` and sixteen hex
    /// characters. The same id and key give the same pseudonym as the shared diagnostics sink.
    #[must_use]
    pub fn pseudonym_of(&self, id: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"ffw.pseudonym.v1");
        hasher.update(self.key.0);
        hasher.update((id.len() as u64).to_be_bytes());
        hasher.update(id.as_bytes());
        let full = hasher.finalize();
        let mut out = String::from("p-");
        for byte in &full[..8] {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// The held lines, oldest first.
    pub fn lines(&self) -> impl Iterator<Item = &str> {
        self.lines.iter().map(|(line, _)| line.as_str())
    }

    /// Take every held line out, oldest first, leaving the log empty (its counters are kept).
    pub fn drain(&mut self) -> Vec<String> {
        self.used_bytes = 0;
        self.ack_lines = 0;
        self.ack_bytes = 0;
        self.lines.drain(..).map(|(line, _)| line).collect()
    }

    #[must_use]
    pub fn stats(&self) -> LogStats {
        LogStats {
            emitted: self.emitted,
            stored: self.lines.len(),
            dropped: self.dropped,
            critical_lost: self.critical_lost,
            bytes: self.used_bytes,
            ack_stored: self.ack_lines,
            ack_dropped: self.ack_dropped,
        }
    }

    /// False once an internal-fault record was lost: a run that ends so cannot be trusted as complete.
    #[must_use]
    pub const fn is_evidence_complete(&self) -> bool {
        self.critical_lost == 0
    }

    /// A concise human summary, free of anything a peer supplied.
    #[must_use]
    pub fn summary_line(&self) -> String {
        let s = self.stats();
        format!(
            "n02 log run={} case={} emitted={} stored={} dropped={} critical_lost={}",
            self.run_id, self.case_id, s.emitted, s.stored, s.dropped, s.critical_lost
        )
    }

    fn lose(&mut self, critical: bool) {
        self.dropped = self.dropped.saturating_add(1);
        if critical {
            self.critical_lost = self.critical_lost.saturating_add(1);
        }
    }

    fn evict_oldest_ordinary(&mut self) -> bool {
        // Acknowledgement records go first: they are the cheaper evidence.
        let position = self
            .lines
            .iter()
            .position(|(_, class)| *class == Class::Ack)
            .or_else(|| {
                self.lines
                    .iter()
                    .position(|(_, class)| *class == Class::Step)
            });
        let Some(position) = position else {
            return false;
        };
        if let Some((line, class)) = self.lines.remove(position) {
            self.used_bytes = self.used_bytes.saturating_sub(line.len());
            self.dropped = self.dropped.saturating_add(1);
            if class == Class::Ack {
                self.ack_lines = self.ack_lines.saturating_sub(1);
                self.ack_bytes = self.ack_bytes.saturating_sub(line.len());
                self.ack_dropped = self.ack_dropped.saturating_add(1);
            }
        }
        true
    }

    fn full_for(&self, bytes: usize) -> bool {
        self.lines.len() >= self.max_records
            || self.used_bytes.saturating_add(bytes) > self.max_bytes
    }

    fn push(&mut self, line: String, critical: bool) {
        self.emitted = self.emitted.saturating_add(1);
        let bytes = line.len();
        if bytes > MAX_LINE_BYTES || bytes > self.max_bytes {
            self.lose(critical);
            return;
        }
        if critical {
            while self.full_for(bytes) && self.evict_oldest_ordinary() {}
        }
        if self.full_for(bytes) {
            self.lose(critical);
            return;
        }
        self.used_bytes += bytes;
        let class = if critical {
            Class::Critical
        } else {
            Class::Step
        };
        self.lines.push_back((line, class));
    }

    /// Hold an acknowledgement record if it fits its share of the log and the log has room; otherwise
    /// drop it and count it. An acknowledgement record is never critical and never evicts anything.
    fn push_ack(&mut self, line: String) {
        self.emitted = self.emitted.saturating_add(1);
        let bytes = line.len();
        let in_share = self.ack_lines < self.max_records / self.ack_share_divisor
            && self.ack_bytes.saturating_add(bytes) <= self.max_bytes / self.ack_share_divisor;
        if bytes > MAX_LINE_BYTES || !in_share || self.full_for(bytes) {
            self.lose(false);
            self.ack_dropped = self.ack_dropped.saturating_add(1);
            return;
        }
        self.used_bytes += bytes;
        self.ack_lines += 1;
        self.ack_bytes += bytes;
        self.lines.push_back((line, Class::Ack));
    }

    /// Give acknowledgement records the whole budget instead of half of it. Tests only: it is the fault
    /// the flood judge in `pipeline/ack.rs` exists to catch.
    #[cfg(test)]
    pub(crate) fn plant_whole_budget_for_acks(&mut self) {
        self.ack_share_divisor = 1;
    }

    /// Write the record for one settled command.
    pub(crate) fn emit(&mut self, fact: &Fact, now_ns: u64, epoch: u64, group_id: &str) {
        let timestamp = now_ns.max(self.last_ns);
        self.last_ns = timestamp;
        let (kind, message) = describe(&fact.outcome);
        let line = {
            let record = Record {
                schema_version: LOG_SCHEMA_VERSION,
                timestamp_mono_ns: timestamp,
                run_id: &self.run_id,
                case_id: &self.case_id,
                correlation_id: format!("{}#{}", self.pseudonym_of(fact.peer.as_str()), fact.seq),
                member_id: fact
                    .member
                    .as_deref()
                    .map(|member| self.pseudonym_of(member))
                    .unwrap_or_default(),
                group_id: self.pseudonym_of(group_id),
                source_epoch: epoch,
                state_revision: fact.revision,
                event_kind: format!("n02.step.{kind}"),
                message,
                queue_depth: fact.queue_depth,
                latency_us: fact.waited_ns / 1_000,
                cause: fact.cause.clone(),
            };
            serde_json::to_string(&record)
        };
        match line {
            Ok(line) => self.push(line, fact.critical),
            Err(_) => {
                self.emitted = self.emitted.saturating_add(1);
                self.lose(fact.critical);
            }
        }
    }
}

impl ChannelLog {
    /// Write the record for one acknowledgement (see the module documentation).
    pub(crate) fn emit_ack(&mut self, fact: &AckFact, now_ns: u64, epoch: u64, group_id: &str) {
        let timestamp = now_ns.max(self.last_ns);
        self.last_ns = timestamp;
        let (kind, message, cause, age_ns) = describe_ack(&fact.outcome);
        let line = {
            let record = Record {
                schema_version: LOG_SCHEMA_VERSION,
                timestamp_mono_ns: timestamp,
                run_id: &self.run_id,
                case_id: &self.case_id,
                correlation_id: format!("{}#{}", self.pseudonym_of(fact.peer.as_str()), fact.seq),
                member_id: String::new(),
                group_id: self.pseudonym_of(group_id),
                source_epoch: epoch,
                state_revision: fact.revision,
                event_kind: format!("n02.ack.{kind}"),
                message,
                queue_depth: fact.queue_depth,
                latency_us: age_ns / 1_000,
                cause: cause.map(str::to_string),
            };
            serde_json::to_string(&record)
        };
        match line {
            Ok(line) => self.push_ack(line),
            Err(_) => {
                self.emitted = self.emitted.saturating_add(1);
                self.lose(false);
                self.ack_dropped = self.ack_dropped.saturating_add(1);
            }
        }
    }
}

/// `(event kind suffix, message, cause, age in ns)` for an acknowledgement outcome, from the fixed
/// vocabulary and numbers only. The age is how long after the outcome was recorded the acknowledgement
/// came, where the outcome says; zero otherwise.
fn describe_ack(outcome: &AckOutcome) -> (&'static str, String, Option<&'static str>, u64) {
    match outcome {
        AckOutcome::OnTime { age_ns } => (
            "on_time",
            format!("acknowledged {} us after the outcome", age_ns / 1_000),
            None,
            *age_ns,
        ),
        AckOutcome::Late { age_ns, over_by_ns } => (
            "late",
            format!("acknowledged {} us over the budget", over_by_ns / 1_000),
            None,
            *age_ns,
        ),
        AckOutcome::Superseded { epoch, current } => (
            "superseded",
            format!("command issued under epoch {epoch}, the group is at {current}"),
            None,
            0,
        ),
        AckOutcome::Duplicate => (
            "rejected.duplicate",
            "already acknowledged".to_string(),
            None,
            0,
        ),
        AckOutcome::NotSettled => (
            "rejected.not_settled",
            "the command is still waiting".to_string(),
            None,
            0,
        ),
        AckOutcome::Unknown => (
            "rejected.unknown",
            "the channel never recorded this command".to_string(),
            None,
            0,
        ),
        AckOutcome::OutOfWindow { floor } => (
            "rejected.out_of_window",
            format!("forgotten: at or below the remembered floor {floor}"),
            None,
            0,
        ),
        AckOutcome::Mismatch { recorded_epoch } => (
            "rejected.mismatch",
            format!("the command was issued under epoch {recorded_epoch}"),
            None,
            0,
        ),
        AckOutcome::Unauthenticated(failure) => (
            "rejected.unauthenticated",
            "did not authenticate".to_string(),
            Some(match failure {
                AuthFailure::UnknownPeer => "unknown_peer",
                AuthFailure::Revoked => "revoked",
                AuthFailure::BadProof => "bad_proof",
            }),
            0,
        ),
    }
}

/// The vocabulary word for a refusal. Nothing here depends on what a peer sent.
pub(crate) fn refusal_kind(refusal: &Refusal) -> &'static str {
    match refusal {
        Refusal::StaleEpoch { .. } => "stale_epoch",
        Refusal::EpochAhead { .. } => "epoch_ahead",
        Refusal::RevisionMismatch { .. } => "revision_mismatch",
        Refusal::StaleRevision { .. } => "stale_revision",
        Refusal::UnknownMember { .. } => "unknown_member",
        Refusal::Session(_) => "session",
        Refusal::InternalFault => "internal_fault",
        Refusal::NoLease => "no_lease",
        Refusal::Lease(_) => "lease",
        Refusal::AuthorityExpired => "authority_expired",
        Refusal::Expired => "expired",
        Refusal::TooLateToCancel => "too_late_to_cancel",
        Refusal::NothingToCancel => "nothing_to_cancel",
        Refusal::TargetOutOfWindow { .. } => "target_out_of_window",
        Refusal::NotCancellable => "not_cancellable",
    }
}

/// The vocabulary word for a session error: its variant, never its text (which carries member ids).
pub(crate) fn session_error_kind(error: &SessionError) -> &'static str {
    match error {
        SessionError::StaleEpoch { .. } => "stale_epoch",
        SessionError::DuplicateCommand { .. } => "duplicate_command",
        SessionError::IneligibleAudioBoard { .. } => "ineligible_audio_board",
        SessionError::UnknownMember { .. } => "unknown_member",
        SessionError::CommandBelowWindow { .. } => "command_below_window",
    }
}

/// `(event kind suffix, message)` for an outcome, from the fixed vocabulary and numbers only.
fn describe(outcome: &Outcome) -> (String, String) {
    match outcome {
        Outcome::Committed { revision } => (
            "committed".to_string(),
            format!("committed at revision {revision}"),
        ),
        Outcome::Withdrawn => (
            "withdrawn".to_string(),
            "withdrawn before it was applied".to_string(),
        ),
        Outcome::CancelApplied { target_seq } => (
            "cancel_applied".to_string(),
            format!("cancel withdrew command {target_seq}"),
        ),
        Outcome::Refused(refusal) => {
            let kind = refusal_kind(refusal);
            let message = match refusal {
                Refusal::StaleEpoch { request, current }
                | Refusal::EpochAhead { request, current } => {
                    format!("epoch {request} against current {current}")
                }
                Refusal::RevisionMismatch { expected, actual } => {
                    format!("revision {expected} named, current is {actual}")
                }
                Refusal::StaleRevision { observed, floor } => {
                    format!("revision {observed} predates this incarnation, which began at {floor}")
                }
                Refusal::TargetOutOfWindow { floor } => {
                    format!("target is at or below the remembered floor {floor}")
                }
                other => refusal_text(other).to_string(),
            };
            (format!("refused.{kind}"), message)
        }
    }
}

/// The words for the refusals that carry no numbers.
fn refusal_text(refusal: &Refusal) -> &'static str {
    match refusal {
        Refusal::UnknownMember { .. } => "the group has no such member",
        Refusal::Session(_) => "the session refused the command",
        Refusal::InternalFault => {
            "internal fault: the session refused for a reason that was not the sender's"
        }
        Refusal::NoLease => "no group lease is held",
        Refusal::Lease(_) => "the group lease is not live",
        Refusal::AuthorityExpired => "the peer's authority ended after the command was accepted",
        Refusal::Expired => "expired in the queue",
        Refusal::TooLateToCancel => "the target had already settled",
        Refusal::NothingToCancel => "no such command to cancel",
        Refusal::NotCancellable => "a stop or a mute is not withdrawn",
        // The numeric refusals are described by the caller; a word here keeps the match total.
        Refusal::StaleEpoch { .. }
        | Refusal::EpochAhead { .. }
        | Refusal::RevisionMismatch { .. }
        | Refusal::StaleRevision { .. }
        | Refusal::TargetOutOfWindow { .. } => "refused",
    }
}

#[cfg(test)]
mod tests {
    use franken_test_support::{BoundedDiagnosticSink, DiagnosticEvent, redact_sensitive_text};

    use super::*;

    const KEY: [u8; 32] = [7; 32];

    fn log(max_records: usize, max_bytes: usize) -> ChannelLog {
        ChannelLog::new(
            LogConfig::new("run-1", "case-1", max_records, max_bytes).unwrap(),
            LogKey::new(KEY),
        )
    }

    fn fact(seq: u64, outcome: Outcome, critical: bool) -> Fact {
        Fact {
            peer: PeerId::parse("ctl-a").unwrap(),
            seq,
            member: Some("kitchen".to_string()),
            outcome,
            cause: None,
            revision: 3,
            queue_depth: 2,
            waited_ns: 2_500_000,
            critical,
        }
    }

    fn committed(seq: u64) -> Fact {
        fact(seq, Outcome::Committed { revision: 3 }, false)
    }

    #[test]
    fn labels_and_bounds_are_validated() {
        for ok in ["run-1", "a", "0", "a.b_c-d"] {
            assert!(LogConfig::new(ok, "case", 1, 1).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "Run",
            "has space",
            "-lead",
            "a\"b",
            "line\nbreak",
            &"x".repeat(65),
        ] {
            assert_eq!(
                LogConfig::new(bad, "case", 1, 1),
                Err(LogError::InvalidLabel { field: "run_id" }),
                "{bad:?}"
            );
            assert_eq!(
                LogConfig::new("run", bad, 1, 1),
                Err(LogError::InvalidLabel { field: "case_id" }),
                "{bad:?}"
            );
        }
        assert_eq!(
            LogConfig::new("run", "case", 0, 1),
            Err(LogError::Zero {
                field: "max_records"
            })
        );
        assert_eq!(
            LogConfig::new("run", "case", 1, 0),
            Err(LogError::Zero { field: "max_bytes" })
        );
    }

    #[test]
    fn the_key_never_prints() {
        let key = LogKey::new([0xAB; 32]);
        assert_eq!(format!("{key:?}"), "LogKey([REDACTED])");
        let log = ChannelLog::new(LogConfig::new("run", "case", 1, 1).unwrap(), key);
        let shown = format!("{log:?}");
        assert!(!shown.contains("171") && !shown.contains("0xab"), "{shown}");
    }

    #[test]
    fn pseudonyms_are_stable_keyed_and_agree_with_the_shared_sink() {
        let a = log(4, 4096);
        let p = a.pseudonym_of("kitchen");
        assert_eq!(p, a.pseudonym_of("kitchen"));
        assert_ne!(p, a.pseudonym_of("den"));
        assert_ne!(
            p,
            ChannelLog::new(
                LogConfig::new("r", "c", 1, 1).unwrap(),
                LogKey::new([8; 32])
            )
            .pseudonym_of("kitchen")
        );
        assert!(
            p.starts_with("p-") && p.len() == 18 && p[2..].bytes().all(|b| b.is_ascii_hexdigit()),
            "{p}"
        );

        // The shared sink, given the same key, pseudonymizes the same identifier the same way.
        let mut sink = BoundedDiagnosticSink::new(4, 4096).with_pseudonym_key(KEY);
        assert!(sink.try_emit(DiagnosticEvent {
            schema_version: String::new(),
            timestamp_mono_ns: 1,
            run_id: "run-1".into(),
            case_id: "case-1".into(),
            correlation_id: "c".into(),
            member_id: "kitchen".into(),
            group_id: "grp".into(),
            source_epoch: 1,
            state_revision: 1,
            event_kind: "k".into(),
            message: "m".into(),
            queue_depth: 0,
            latency_us: 0,
            fault: None,
            cause: None,
        }));
        let event = &sink.events()[0];
        assert_eq!(event.member_id, p);
        assert_eq!(event.group_id, a.pseudonym_of("grp"));
    }

    #[test]
    fn a_record_is_a_valid_ffw_log_v1_event_and_round_trips_exactly() {
        let mut l = log(8, 8192);
        l.emit(&committed(1), 10_000_000, 10, "grp");
        let mut with_cause = fact(2, Outcome::Refused(Refusal::NoLease), false);
        with_cause.cause = Some("no_lease".to_string());
        l.emit(&with_cause, 11_000_000, 10, "grp");
        let lines: Vec<&str> = l.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let event: DiagnosticEvent = serde_json::from_str(line).expect("a shared-schema event");
            assert_eq!(
                event.schema_version,
                franken_test_support::LOG_SCHEMA_VERSION
            );
            assert_eq!(event.schema_version, LOG_SCHEMA_VERSION);
            assert_eq!(
                serde_json::to_string(&event).unwrap(),
                line,
                "byte-identical round trip"
            );
            assert!(line.len() <= MAX_LINE_BYTES);
            assert_eq!(
                redact_sensitive_text(line),
                line,
                "nothing sensitive-looking in {line}"
            );
        }
    }

    #[test]
    fn a_record_has_the_documented_fields() {
        let mut l = log(8, 8192);
        l.emit(&committed(1), 10_000_000, 10, "grp");
        let line = l.lines().next().unwrap().to_string();
        let event: DiagnosticEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(event.timestamp_mono_ns, 10_000_000);
        assert_eq!(
            (event.run_id.as_str(), event.case_id.as_str()),
            ("run-1", "case-1")
        );
        assert_eq!(
            event.correlation_id,
            format!("{}#1", l.pseudonym_of("ctl-a"))
        );
        assert_eq!(event.member_id, l.pseudonym_of("kitchen"));
        assert_eq!(event.group_id, l.pseudonym_of("grp"));
        assert_eq!((event.source_epoch, event.state_revision), (10, 3));
        assert_eq!(event.event_kind, "n02.step.committed");
        assert_eq!(event.message, "committed at revision 3");
        assert_eq!((event.queue_depth, event.latency_us), (2, 2_500));
        assert_eq!(event.cause, None);
        assert!(
            !line.contains("ctl-a") && !line.contains("kitchen") && !line.contains("grp"),
            "{line}"
        );
    }

    #[test]
    fn a_command_with_no_member_has_an_empty_member_id() {
        let mut l = log(8, 8192);
        let mut f = committed(1);
        f.member = None;
        l.emit(&f, 1, 10, "grp");
        let event: DiagnosticEvent = serde_json::from_str(l.lines().next().unwrap()).unwrap();
        assert_eq!(event.member_id, "");
    }

    #[test]
    fn the_log_is_bounded_by_records_and_every_record_is_accounted() {
        let mut l = log(5, 1_000_000);
        for seq in 1..=100 {
            l.emit(&committed(seq), seq, 10, "grp");
        }
        let s = l.stats();
        assert_eq!(s.stored, 5);
        assert_eq!((s.emitted, s.dropped), (100, 95));
        assert_eq!(s.emitted, s.stored as u64 + s.dropped);
        assert!(
            l.is_evidence_complete(),
            "ordinary drops are not lost evidence"
        );
        // The oldest records were kept, the newest dropped: a full log never blocks the channel.
        let first: DiagnosticEvent = serde_json::from_str(l.lines().next().unwrap()).unwrap();
        assert!(first.correlation_id.ends_with("#1"));
    }

    #[test]
    fn the_log_is_bounded_by_bytes() {
        let mut probe = log(1, 1_000_000);
        probe.emit(&committed(1), 1, 10, "grp");
        let one = probe.stats().bytes;
        let mut l = log(1_000, one * 3 + one / 2);
        for seq in 1..=50 {
            l.emit(&committed(seq), seq, 10, "grp");
        }
        let s = l.stats();
        assert_eq!(
            s.stored, 3,
            "three lines fit in three and a half lines of bytes"
        );
        assert!(s.bytes <= one * 3 + one / 2);
        assert_eq!(s.emitted, s.stored as u64 + s.dropped);
    }

    #[test]
    fn an_internal_fault_evicts_ordinary_records_and_lost_evidence_is_counted() {
        let mut l = log(3, 1_000_000);
        for seq in 1..=3 {
            l.emit(&committed(seq), seq, 10, "grp");
        }
        let fault = |seq| fact(seq, Outcome::Refused(Refusal::InternalFault), true);
        l.emit(&fault(10), 4, 10, "grp");
        l.emit(&fault(11), 5, 10, "grp");
        l.emit(&fault(12), 6, 10, "grp");
        let kinds: Vec<String> = l
            .lines()
            .map(|line| {
                serde_json::from_str::<DiagnosticEvent>(line)
                    .unwrap()
                    .event_kind
            })
            .collect();
        assert_eq!(kinds, vec!["n02.step.refused.internal_fault"; 3]);
        assert!(l.is_evidence_complete());
        // Nothing ordinary is left to evict: the fourth fault cannot be held.
        l.emit(&fault(13), 7, 10, "grp");
        let s = l.stats();
        assert_eq!((s.stored, s.critical_lost), (3, 1));
        assert!(!l.is_evidence_complete());
        assert_eq!(s.emitted, s.stored as u64 + s.dropped);
    }

    #[test]
    fn a_line_longer_than_the_bound_is_dropped_not_truncated() {
        let mut l = log(8, 1_000_000);
        let mut f = committed(1);
        f.cause = Some("x".repeat(MAX_LINE_BYTES));
        l.emit(&f, 1, 10, "grp");
        assert_eq!(l.stats().stored, 0);
        assert_eq!((l.stats().emitted, l.stats().dropped), (1, 1));
    }

    #[test]
    fn timestamps_never_go_backwards() {
        let mut l = log(8, 8192);
        l.emit(&committed(1), 5_000, 10, "grp");
        l.emit(&committed(2), 3_000, 10, "grp");
        l.emit(&committed(3), 9_000, 10, "grp");
        let times: Vec<u64> = l
            .lines()
            .map(|line| {
                serde_json::from_str::<DiagnosticEvent>(line)
                    .unwrap()
                    .timestamp_mono_ns
            })
            .collect();
        assert_eq!(times, vec![5_000, 5_000, 9_000]);
    }

    #[test]
    fn drain_empties_the_log_and_keeps_its_counters() {
        let mut l = log(8, 8192);
        l.emit(&committed(1), 1, 10, "grp");
        l.emit(&committed(2), 2, 10, "grp");
        let taken = l.drain();
        assert_eq!(taken.len(), 2);
        assert_eq!((l.stats().stored, l.stats().bytes), (0, 0));
        assert_eq!(l.stats().emitted, 2);
        l.emit(&committed(3), 3, 10, "grp");
        assert_eq!(l.stats().stored, 1);
    }

    #[test]
    fn the_summary_names_the_run_and_the_counts_and_nothing_else() {
        let mut l = log(1, 8192);
        l.emit(&committed(1), 1, 10, "grp");
        l.emit(&committed(2), 2, 10, "grp");
        assert_eq!(
            l.summary_line(),
            "n02 log run=run-1 case=case-1 emitted=2 stored=1 dropped=1 critical_lost=0"
        );
    }

    #[test]
    fn every_refusal_has_a_distinct_vocabulary_word_and_no_text_from_a_peer() {
        let m = || "tok-9f3a1c77e0b2".to_string();
        let refusals = [
            Refusal::StaleEpoch {
                request: 1,
                current: 2,
            },
            Refusal::EpochAhead {
                request: 3,
                current: 2,
            },
            Refusal::RevisionMismatch {
                expected: 1,
                actual: 2,
            },
            Refusal::StaleRevision {
                observed: 1,
                floor: 2,
            },
            Refusal::UnknownMember { member_id: m() },
            Refusal::Session(SessionError::UnknownMember { member_id: m() }),
            Refusal::InternalFault,
            Refusal::NoLease,
            Refusal::Lease(franken_session::MembershipError::WrongGroup),
            Refusal::AuthorityExpired,
            Refusal::Expired,
            Refusal::TooLateToCancel,
            Refusal::NothingToCancel,
            Refusal::TargetOutOfWindow { floor: 4 },
            Refusal::NotCancellable,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for refusal in refusals {
            let (kind, message) = describe(&Outcome::Refused(refusal.clone()));
            assert!(seen.insert(kind.clone()), "duplicate kind {kind}");
            assert!(
                !message.contains("tok-") && !message.contains("9f3a1c77e0b2"),
                "{kind}: {message}"
            );
            assert!(!kind.contains("tok-"), "{kind}");
        }
        assert_eq!(seen.len(), 15);
    }

    #[test]
    fn session_errors_are_named_by_variant_never_by_text() {
        let e = SessionError::UnknownMember {
            member_id: "tok-9f3a1c77e0b2".to_string(),
        };
        assert_eq!(session_error_kind(&e), "unknown_member");
        assert!(
            format!("{e}").contains("tok-9f3a1c77e0b2"),
            "the text does carry it; the kind must not"
        );
    }

    const VECTORS_JSON: &str = include_str!("../../tests/vectors/n02_log_vectors.json");

    fn outcome_for(name: &str, revision: u64) -> Outcome {
        match name {
            "committed" => Outcome::Committed { revision },
            "refused_session" => Outcome::Refused(Refusal::Session(SessionError::UnknownMember {
                member_id: "nowhere".to_string(),
            })),
            "refused_lease" => Outcome::Refused(Refusal::Lease(
                franken_session::MembershipError::StaleAuthority {
                    token_epoch: 10,
                    current_epoch: 11,
                },
            )),
            "expired" => Outcome::Refused(Refusal::Expired),
            other => panic!("unknown outcome `{other}` in the vectors"),
        }
    }

    /// The pseudonyms and the four lines were computed with Python's `hashlib` and `json`, not with
    /// this code, so the keyed construction and the exact bytes (field order, separators) are pinned by
    /// an independent implementation.
    #[test]
    fn pseudonyms_and_golden_lines_match_the_independent_vectors() {
        let doc: serde_json::Value = serde_json::from_str(VECTORS_JSON).expect("vectors parse");
        let text = |v: &serde_json::Value, key: &str| v[key].as_str().expect(key).to_string();
        let num = |v: &serde_json::Value, key: &str| v[key].as_u64().expect(key);
        let key_hex = text(&doc, "pseudonym_key_hex");
        let key: [u8; 32] = (0..key_hex.len() / 2)
            .map(|i| u8::from_str_radix(&key_hex[2 * i..2 * i + 2], 16).expect("hex"))
            .collect::<Vec<u8>>()
            .try_into()
            .expect("a 32-byte key");
        let (run, case) = (text(&doc, "run_id"), text(&doc, "case_id"));
        let make = || {
            ChannelLog::new(
                LogConfig::new(&run, &case, 16, 65_536).unwrap(),
                LogKey::new(key),
            )
        };

        let l = make();
        let pseudonyms = doc["pseudonyms"].as_array().expect("pseudonyms");
        assert!(pseudonyms.len() >= 5);
        for p in pseudonyms {
            assert_eq!(
                l.pseudonym_of(&text(p, "id")),
                text(p, "pseudonym"),
                "{}",
                text(p, "id")
            );
        }

        let lines = doc["golden_lines"].as_array().expect("golden_lines");
        assert!(lines.len() >= 4);
        for g in lines {
            let f = &g["fact"];
            let fact = Fact {
                peer: PeerId::parse(&text(f, "peer")).unwrap(),
                seq: num(f, "seq"),
                member: f["member"].as_str().map(str::to_string),
                outcome: outcome_for(&text(f, "outcome"), num(f, "revision")),
                cause: f["cause"].as_str().map(str::to_string),
                revision: num(f, "revision"),
                queue_depth: usize::try_from(num(f, "queue_depth")).unwrap(),
                waited_ns: num(f, "waited_ns"),
                critical: false,
            };
            let mut log = make();
            log.emit(&fact, num(f, "now_ns"), num(f, "epoch"), &text(f, "group"));
            assert_eq!(
                log.lines().next().unwrap(),
                text(g, "line"),
                "{}",
                text(g, "id")
            );
        }
    }

    fn ack_fact(seq: u64) -> AckFact {
        AckFact {
            peer: PeerId::parse("ctl-a").unwrap(),
            seq,
            outcome: AckOutcome::Duplicate,
            revision: 3,
            queue_depth: 0,
        }
    }

    fn ack_outcome_for(o: &serde_json::Value) -> AckOutcome {
        let n = |key: &str| o[key].as_u64().expect(key);
        match o["kind"].as_str().expect("kind") {
            "on_time" => AckOutcome::OnTime {
                age_ns: n("age_ns"),
            },
            "late" => AckOutcome::Late {
                age_ns: n("age_ns"),
                over_by_ns: n("over_by_ns"),
            },
            "superseded" => AckOutcome::Superseded {
                epoch: n("epoch"),
                current: n("current"),
            },
            "out_of_window" => AckOutcome::OutOfWindow { floor: n("floor") },
            "mismatch" => AckOutcome::Mismatch {
                recorded_epoch: n("recorded_epoch"),
            },
            "unauthenticated" => AckOutcome::Unauthenticated(match o["failure"].as_str() {
                Some("unknown_peer") => AuthFailure::UnknownPeer,
                Some("revoked") => AuthFailure::Revoked,
                Some("bad_proof") => AuthFailure::BadProof,
                other => panic!("unknown failure {other:?} in the vectors"),
            }),
            other => panic!("unknown acknowledgement outcome `{other}` in the vectors"),
        }
    }

    /// The acknowledgement lines were computed with Python's `hashlib` and `json`; the Rust builds each from
    /// the outcome named in the fact, so the vocabulary, the arithmetic and the bytes are all pinned.
    #[test]
    fn acknowledgement_lines_match_the_independent_vectors() {
        let doc: serde_json::Value = serde_json::from_str(VECTORS_JSON).expect("vectors parse");
        let text = |v: &serde_json::Value, key: &str| v[key].as_str().expect(key).to_string();
        let num = |v: &serde_json::Value, key: &str| v[key].as_u64().expect(key);
        let key_hex = text(&doc, "pseudonym_key_hex");
        let key: [u8; 32] = (0..key_hex.len() / 2)
            .map(|i| u8::from_str_radix(&key_hex[2 * i..2 * i + 2], 16).expect("hex"))
            .collect::<Vec<u8>>()
            .try_into()
            .expect("a 32-byte key");
        let lines = doc["ack_golden_lines"]
            .as_array()
            .expect("ack_golden_lines");
        assert!(lines.len() >= 6);
        for g in lines {
            let f = &g["fact"];
            let fact = AckFact {
                peer: PeerId::parse(&text(f, "peer")).unwrap(),
                seq: num(f, "seq"),
                outcome: ack_outcome_for(&f["outcome"]),
                revision: num(f, "revision"),
                queue_depth: usize::try_from(num(f, "queue_depth")).unwrap(),
            };
            let mut l = ChannelLog::new(
                LogConfig::new(&text(&doc, "run_id"), &text(&doc, "case_id"), 16, 65_536).unwrap(),
                LogKey::new(key),
            );
            l.emit_ack(&fact, num(f, "now_ns"), num(f, "epoch"), &text(f, "group"));
            assert_eq!(
                l.lines().next().unwrap(),
                text(g, "line"),
                "{}",
                text(g, "id")
            );
        }
    }

    #[test]
    fn acknowledgement_records_hold_to_half_the_log_and_every_drop_is_counted() {
        let mut l = log(8, 65_536);
        for seq in 1..=10 {
            l.emit_ack(&ack_fact(seq), seq, 10, "grp");
        }
        let s = l.stats();
        assert_eq!(
            (s.emitted, s.stored, s.dropped, s.ack_stored, s.ack_dropped),
            (10, 4, 6, 4, 6)
        );
        assert_eq!(s.emitted, s.stored as u64 + s.dropped);
        // Command records still have the other half, and the next one finds the log full: counted.
        for seq in 1..=4 {
            l.emit(&committed(seq), 20, 10, "grp");
        }
        let s = l.stats();
        assert_eq!((s.stored, s.dropped), (8, 6));
        l.emit(&committed(5), 21, 10, "grp");
        let s = l.stats();
        assert_eq!((s.dropped, s.emitted), (7, 15));
        assert_eq!(s.emitted, s.stored as u64 + s.dropped);
    }

    #[test]
    fn the_acknowledgement_share_is_held_in_bytes_as_well_as_records() {
        let mut probe = log(64, 65_536);
        probe.emit_ack(&ack_fact(1), 1, 10, "grp");
        let one = probe.stats().bytes;
        // Room for four lines in all, so two for acknowledgements.
        let mut l = log(64, one * 4);
        for seq in 1..=5 {
            l.emit_ack(&ack_fact(seq), 1, 10, "grp");
        }
        let s = l.stats();
        assert_eq!((s.ack_stored, s.ack_dropped, s.dropped), (2, 3, 3));
        assert!(s.bytes <= one * 4);
    }

    #[test]
    fn a_record_too_big_for_any_log_is_dropped_and_counted_never_truncated() {
        let mut l = log(8, 10);
        l.emit_ack(&ack_fact(1), 1, 10, "grp");
        l.emit(&committed(1), 1, 10, "grp");
        let s = l.stats();
        assert_eq!(
            (s.emitted, s.stored, s.dropped, s.ack_dropped),
            (2, 0, 2, 1)
        );
        assert_eq!(l.lines().count(), 0);
    }

    #[test]
    fn a_critical_record_makes_room_by_evicting_acknowledgement_records_before_command_records() {
        let mut l = log(4, 65_536);
        l.emit(&committed(1), 1, 10, "grp");
        l.emit(&committed(2), 2, 10, "grp");
        l.emit_ack(&ack_fact(3), 3, 10, "grp");
        l.emit_ack(&ack_fact(4), 4, 10, "grp");
        assert_eq!(l.stats().stored, 4);
        let critical = fact(5, Outcome::Refused(Refusal::InternalFault), true);
        l.emit(&critical, 5, 10, "grp");
        let s = l.stats();
        assert_eq!(
            (
                s.stored,
                s.ack_stored,
                s.ack_dropped,
                s.dropped,
                s.critical_lost
            ),
            (4, 1, 1, 1, 0)
        );
        let kinds: Vec<String> = l
            .lines()
            .map(|line| {
                let record: serde_json::Value = serde_json::from_str(line).unwrap();
                record["event_kind"].as_str().unwrap().to_string()
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "n02.step.committed",
                "n02.step.committed",
                "n02.ack.rejected.duplicate",
                "n02.step.refused.internal_fault"
            ]
        );
        // Draining empties the log, including the acknowledgement share.
        assert_eq!(l.drain().len(), 4);
        assert_eq!((l.stats().stored, l.stats().ack_stored), (0, 0));
    }
}
