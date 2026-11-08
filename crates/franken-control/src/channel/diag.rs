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
//!  "queue_depth":..,"latency_us":..,"fault":..?,"cause":..?}
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
//! # The injected fault label
//!
//! The shared schema has a `fault` field: the injected fault (or fault-schedule entry) in force when the event was
//! emitted. A harness that runs the channel under one names it with [`LogConfig::with_fault`], and then **every** record
//! the log writes carries it, between `latency_us` and `cause`: the record of a settled command, an acknowledgement, a
//! request turned away at `submit`, and the closing record. It is a label the harness chooses, validated to the same
//! alphabet and length as `run_id` and `case_id`, so nothing a peer supplied can reach it. A log that is told no fault
//! writes records with no `fault` key, byte for byte as before. The channel injects no fault and never decides that one
//! is in force: the label only says what the run was under.
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
//!
//! # Records for requests turned away at `submit`
//!
//! A request that is turned away before it is queued is counted in `ChannelStats` and, since a controller
//! that is refused needs to know why, also written as a record: `n02.submit.rejected.<why>` for
//! `unauthenticated` (its `cause` is the failure word), `epoch_not_bound`, `revision_required`, `rate_limited`,
//! `queue_full` and `id_reuse`, and `n02.submit.out_of_window` for a retry of a number the ledger has
//! forgotten. A request that was queued, found already waiting, or answered from the ledger writes none.
//! Its `correlation_id` is the claimed peer's pseudonym and the number it named; nothing the sender put in
//! the request is copied, so an unauthenticated sender's claimed identifier appears only as a pseudonym.
//!
//! Anyone can send a request that does not authenticate, so these records are held to a **quarter** of the
//! log's records and of its bytes (the acknowledgements' half and this quarter leave command records at least
//! a quarter). Past it a record is dropped and counted (`reject_dropped`, also in `dropped`). When an
//! internal-fault record needs room, acknowledgement records are evicted first, then these, then command
//! records. The channel gathers the facts at `submit` and writes the records when the session is at hand
//! (the next `step`, or `flush_log`); the facts waiting are bounded, and a request that does not fit is
//! counted as a dropped record.
//!
//! # Handing records to a sink
//!
//! The channel never writes a record anywhere: `submit`, `step` and `acknowledge` only push a line into the bounded ring
//! in this module and return. Getting lines out is the owner's, in its diagnostic drain, between those calls:
//! [`ChannelLog::drain`] takes everything, and [`ChannelLog::drain_to`] offers lines to a [`LineSink`], oldest first, at most
//! `budget` offers per call. A sink answers [`SinkReply::Taken`] (the line leaves the ring), or `Full` or `Unavailable` (the
//! line stays queued and this drain stops). So a slow, full, short-writing or absent sink can stall only the drain, never a
//! decision, and whatever it does the channel takes the decisions it takes with no log at all. Nothing is lost silently:
//! every record handed to the log is held, delivered, or counted as dropped, `emitted == stored + dropped + drained`, and a
//! critical record is offered as critical so a sink can keep room for it. A run whose critical records were lost, or are
//! still waiting when the run ends, is not complete ([`LogStats::critical_held`], [`ChannelLog::is_evidence_complete`]).
//! The real file sink is `crate::logfile`; it is the only code in this crate that touches a filesystem.

use std::collections::VecDeque;
use std::fmt::{self, Write as _};

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::peer::{AuthFailure, PeerId};
use super::pipeline::{AckOutcome, Outcome, Refusal, Rejection, SubmitResult};
use super::request::Lane;
use franken_session::SessionError;

/// The shared diagnostics schema these records follow.
pub const LOG_SCHEMA_VERSION: &str = "ffw.log.v1";
/// Longest run or case label, in bytes.
pub const MAX_LABEL_LEN: usize = 64;
/// No record line is longer than this; a longer one is dropped and counted, never truncated.
pub const MAX_LINE_BYTES: usize = 1024;
/// Acknowledgement records may hold `1 / ACK_SHARE_DIVISOR` of the log's records and of its bytes.
const ACK_SHARE_DIVISOR: usize = 2;
/// Records of requests turned away at `submit` may hold `1 / REJECT_SHARE_DIVISOR` of the log's records and of
/// its bytes.
const REJECT_SHARE_DIVISOR: usize = 4;

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
    /// The injected fault schedule entry the run is under, if the harness named one (see the module documentation).
    fault: Option<String>,
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
            fault: None,
        })
    }

    /// Say that the run is under the injected fault `fault`: every record the log writes then carries it as its `fault`.
    /// A label chosen by the harness, held to the alphabet and length of `run_id` and `case_id`.
    ///
    /// # Errors
    /// [`LogError::InvalidLabel`] naming the field `fault`.
    pub fn with_fault(mut self, fault: &str) -> Result<Self, LogError> {
        if !valid_label(fault) {
            return Err(LogError::InvalidLabel { field: "fault" });
        }
        self.fault = Some(fault.to_string());
        Ok(self)
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
    /// Records of requests turned away at `submit` currently held (a share of `stored`).
    pub reject_stored: usize,
    /// Such records not held (a share of `dropped`).
    pub reject_dropped: u64,
    /// Records that left the ring for a sink (`drain`, or a line a sink took in `drain_to`). `emitted == stored +
    /// dropped + drained`.
    pub drained: u64,
    /// Lines offered to a sink by `drain_to`, and how many of those offers were answered `Full` and `Unavailable`.
    pub offers: u64,
    pub sink_full_polls: u64,
    pub sink_unavailable_polls: u64,
    /// Critical records held now: evidence that has not reached a sink yet. A run that ends with any is incomplete.
    pub critical_held: usize,
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
    /// Between `latency_us` and `cause`, where the shared `DiagnosticEvent` writes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    fault: Option<&'a str>,
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
    /// The record of a request turned away at `submit`.
    Reject,
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

/// What the channel knows about one request it turned away at `submit`, turned into a record by
/// [`ChannelLog::emit_reject`] once the session is at hand. The vocabulary is fixed when the fact is made, so
/// nothing the sender supplied is held beyond the claimed identifier, which only a pseudonym ever leaves.
pub(crate) struct RejectFact {
    peer: PeerId,
    seq: u64,
    now_ns: u64,
    queue_depth: usize,
    kind: &'static str,
    message: String,
    cause: Option<&'static str>,
}

impl RejectFact {
    /// The fact for what `submit` returned for a request claiming to be `peer` and naming number `seq`, or `None` if
    /// it was not turned away (queued, already waiting, or answered from the ledger).
    pub(crate) fn new(
        peer: PeerId,
        seq: u64,
        now_ns: u64,
        queue_depth: usize,
        result: &SubmitResult,
    ) -> Option<Self> {
        let (kind, message, cause) = describe_submit(result)?;
        Some(Self {
            peer,
            seq,
            now_ns,
            queue_depth,
            kind,
            message,
            cause,
        })
    }
}

/// What a sink said to one offered line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkReply {
    /// The sink has the line; it leaves the ring.
    Taken,
    /// The sink cannot take it right now (its file or its budget is full, or it would block); it stays queued and this
    /// drain stops.
    Full,
    /// The sink is down; it stays queued and this drain stops.
    Unavailable,
}

/// A consumer of log lines. `offer` is called only from [`ChannelLog::drain_to`], never from `submit`, `step` or
/// `acknowledge`, and should return promptly: a drain makes at most `budget` offers.
pub trait LineSink {
    /// One complete line, without a trailing newline. `critical` is true for a record a run cannot be trusted
    /// without (an internal fault), which a sink may keep room for.
    fn offer(&mut self, line: &str, critical: bool) -> SinkReply;
}

/// Why a drain stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainStop {
    /// Nothing is queued.
    Empty,
    /// The offer budget was used up with lines still queued.
    Budget,
    SinkFull,
    SinkUnavailable,
}

/// What one `drain_to` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainReport {
    pub offered: usize,
    pub taken: usize,
    pub stop: DrainStop,
}

/// What a sink counts of its own, for the closing record: lines it wrote, lines it took and dropped (over its caps, or not
/// one line), and how many of those were critical.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SinkCounts {
    pub written: u64,
    pub dropped: u64,
    pub critical_dropped: u64,
}

/// The bounded JSONL log of one control channel.
pub struct ChannelLog {
    run_id: String,
    case_id: String,
    /// The injected fault the run is under, carried by every record.
    fault: Option<String>,
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
    /// The same for the records of requests turned away at `submit`.
    reject_lines: usize,
    reject_bytes: usize,
    reject_dropped: u64,
    reject_share_divisor: usize,
    /// Lines that left the ring for a sink, offers made, and the offers that were refused.
    drained: u64,
    offers: u64,
    sink_full_polls: u64,
    sink_unavailable_polls: u64,
    /// Critical lines held now.
    critical_lines: usize,
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
            fault: config.fault,
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
            reject_lines: 0,
            reject_bytes: 0,
            reject_dropped: 0,
            reject_share_divisor: REJECT_SHARE_DIVISOR,
            drained: 0,
            offers: 0,
            sink_full_polls: 0,
            sink_unavailable_polls: 0,
            critical_lines: 0,
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
        self.reject_lines = 0;
        self.reject_bytes = 0;
        self.critical_lines = 0;
        self.drained = self
            .drained
            .saturating_add(u64::try_from(self.lines.len()).unwrap_or(u64::MAX));
        self.lines.drain(..).map(|(line, _)| line).collect()
    }

    /// Offer the held lines to `sink`, oldest first, at most `budget` offers. A line leaves the ring only when the sink
    /// answers [`SinkReply::Taken`]; on `Full` or `Unavailable` it stays and the drain stops (see the module documentation).
    /// This is the only call that gives a sink anything, and nothing the channel does on its own paths calls it.
    pub fn drain_to(&mut self, sink: &mut dyn LineSink, budget: usize) -> DrainReport {
        let mut report = DrainReport {
            offered: 0,
            taken: 0,
            stop: DrainStop::Empty,
        };
        while report.offered < budget {
            let Some((line, class)) = self.lines.front() else {
                return report;
            };
            let critical = *class == Class::Critical;
            self.offers = self.offers.saturating_add(1);
            report.offered += 1;
            match sink.offer(line, critical) {
                SinkReply::Taken => {
                    if let Some((line, class)) = self.lines.pop_front() {
                        self.release(line.len(), class);
                    }
                    self.drained = self.drained.saturating_add(1);
                    report.taken += 1;
                }
                SinkReply::Full => {
                    self.sink_full_polls = self.sink_full_polls.saturating_add(1);
                    report.stop = DrainStop::SinkFull;
                    return report;
                }
                SinkReply::Unavailable => {
                    self.sink_unavailable_polls = self.sink_unavailable_polls.saturating_add(1);
                    report.stop = DrainStop::SinkUnavailable;
                    return report;
                }
            }
        }
        if !self.lines.is_empty() {
            report.stop = DrainStop::Budget;
        }
        report
    }

    /// A held line of `len` bytes and `class` has left the ring: give back its bytes and its share.
    fn release(&mut self, len: usize, class: Class) {
        self.used_bytes = self.used_bytes.saturating_sub(len);
        match class {
            Class::Step => {}
            Class::Critical => self.critical_lines = self.critical_lines.saturating_sub(1),
            Class::Ack => {
                self.ack_lines = self.ack_lines.saturating_sub(1);
                self.ack_bytes = self.ack_bytes.saturating_sub(len);
            }
            Class::Reject => {
                self.reject_lines = self.reject_lines.saturating_sub(1);
                self.reject_bytes = self.reject_bytes.saturating_sub(len);
            }
        }
    }

    /// The record that closes a run's file: the log's own counts and the sink's as numbers in the shared `ffw.log.v1` shape
    /// (`n02.log.summary`), so a reader that has only the file can check the counts against the lines it holds. It carries
    /// the cause `evidence_incomplete` when a critical record was lost, is still waiting, or was dropped by the sink.
    /// `None` only if it cannot be serialized, which the record's fields do not allow.
    pub(crate) fn closing_line_for(
        &self,
        stats: &LogStats,
        sink: &SinkCounts,
        now_ns: u64,
    ) -> Option<String> {
        let incomplete =
            stats.critical_lost > 0 || stats.critical_held > 0 || sink.critical_dropped > 0;
        let record = Record {
            schema_version: LOG_SCHEMA_VERSION,
            timestamp_mono_ns: now_ns.max(self.last_ns),
            run_id: &self.run_id,
            case_id: &self.case_id,
            correlation_id: "n02.log".to_string(),
            member_id: String::new(),
            group_id: String::new(),
            source_epoch: 0,
            state_revision: 0,
            event_kind: "n02.log.summary".to_string(),
            message: format!(
                "emitted={} stored={} dropped={} drained={} written={} sink_dropped={} critical_lost={} critical_held={} critical_sink_dropped={}",
                stats.emitted,
                stats.stored,
                stats.dropped,
                stats.drained,
                sink.written,
                sink.dropped,
                stats.critical_lost,
                stats.critical_held,
                sink.critical_dropped
            ),
            queue_depth: stats.stored,
            latency_us: 0,
            fault: self.fault.as_deref(),
            cause: incomplete.then(|| "evidence_incomplete".to_string()),
        };
        serde_json::to_string(&record).ok()
    }

    /// The closing record for the log as it stands now.
    pub(crate) fn closing_line(&self, sink: &SinkCounts, now_ns: u64) -> Option<String> {
        self.closing_line_for(&self.stats(), sink, now_ns)
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
            reject_stored: self.reject_lines,
            reject_dropped: self.reject_dropped,
            drained: self.drained,
            offers: self.offers,
            sink_full_polls: self.sink_full_polls,
            sink_unavailable_polls: self.sink_unavailable_polls,
            critical_held: self.critical_lines,
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
        // Acknowledgement records go first, then the records of requests turned away: they are the cheaper evidence.
        let position = self
            .lines
            .iter()
            .position(|(_, class)| *class == Class::Ack)
            .or_else(|| {
                self.lines
                    .iter()
                    .position(|(_, class)| *class == Class::Reject)
            })
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
            if class == Class::Reject {
                self.reject_lines = self.reject_lines.saturating_sub(1);
                self.reject_bytes = self.reject_bytes.saturating_sub(line.len());
                self.reject_dropped = self.reject_dropped.saturating_add(1);
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
            self.critical_lines += 1;
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

    /// Hold the record of a request turned away if it fits its share of the log and the log has room;
    /// otherwise drop it and count it. Such a record is never critical and never evicts anything.
    fn push_reject(&mut self, line: String) {
        self.emitted = self.emitted.saturating_add(1);
        let bytes = line.len();
        let in_share = self.reject_lines < self.max_records / self.reject_share_divisor
            && self.reject_bytes.saturating_add(bytes)
                <= self.max_bytes / self.reject_share_divisor;
        if bytes > MAX_LINE_BYTES || !in_share || self.full_for(bytes) {
            self.lose(false);
            self.reject_dropped = self.reject_dropped.saturating_add(1);
            return;
        }
        self.used_bytes += bytes;
        self.reject_lines += 1;
        self.reject_bytes += bytes;
        self.lines.push_back((line, Class::Reject));
    }

    /// Count a record that was never written because the facts waiting for the session were already at their
    /// bound. It is handed to the log and not held, like any other record that does not fit.
    pub(crate) fn note_reject_overflow(&mut self) {
        self.emitted = self.emitted.saturating_add(1);
        self.lose(false);
        self.reject_dropped = self.reject_dropped.saturating_add(1);
    }

    /// Give acknowledgement records the whole budget instead of half of it. Tests only: it is the fault
    /// the flood judge in `pipeline/ack.rs` exists to catch.
    #[cfg(test)]
    pub(crate) fn plant_whole_budget_for_acks(&mut self) {
        self.ack_share_divisor = 1;
    }

    /// Give the records of requests turned away the whole budget instead of a quarter of it. Tests only: it is
    /// the fault the flood judge in `pipeline/submit_log.rs` exists to catch.
    #[cfg(test)]
    pub(crate) fn plant_whole_budget_for_rejects(&mut self) {
        self.reject_share_divisor = 1;
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
                fault: self.fault.as_deref(),
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
                fault: self.fault.as_deref(),
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

impl ChannelLog {
    /// Write the record for one request turned away at `submit`, made under the epoch and revision the session is at
    /// now (see the module documentation).
    pub(crate) fn emit_reject(
        &mut self,
        fact: &RejectFact,
        epoch: u64,
        revision: u64,
        group_id: &str,
    ) {
        let timestamp = fact.now_ns.max(self.last_ns);
        self.last_ns = timestamp;
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
                state_revision: revision,
                event_kind: format!("n02.submit.{}", fact.kind),
                message: fact.message.clone(),
                queue_depth: fact.queue_depth,
                latency_us: 0,
                fault: self.fault.as_deref(),
                cause: fact.cause.map(str::to_string),
            };
            serde_json::to_string(&record)
        };
        match line {
            Ok(line) => self.push_reject(line),
            Err(_) => self.note_reject_overflow(),
        }
    }
}

/// The word for a lane, for a message.
const fn lane_word(lane: Lane) -> &'static str {
    match lane {
        Lane::Ordinary => "ordinary",
        Lane::Priority => "priority",
    }
}

/// `(event kind suffix, message, cause)` for a `submit` result that turned the request away, from the fixed
/// vocabulary and numbers only; `None` for a request that was queued, already waiting, or answered from the ledger.
/// No result is matched by a wildcard, so a new one does not compile until it has a word.
fn describe_submit(result: &SubmitResult) -> Option<(&'static str, String, Option<&'static str>)> {
    match result {
        SubmitResult::Queued { .. }
        | SubmitResult::AlreadyQueued { .. }
        | SubmitResult::Settled(_) => None,
        SubmitResult::OutOfWindow { floor } => Some((
            "out_of_window",
            format!("forgotten: at or below the remembered floor {floor}"),
            None,
        )),
        SubmitResult::Rejected(rejection) => Some(match rejection {
            Rejection::Unauthenticated(failure) => (
                "rejected.unauthenticated",
                "did not authenticate".to_string(),
                Some(match failure {
                    AuthFailure::UnknownPeer => "unknown_peer",
                    AuthFailure::Revoked => "revoked",
                    AuthFailure::BadProof => "bad_proof",
                }),
            ),
            Rejection::EpochNotBound { bound, request } => (
                "rejected.epoch_not_bound",
                format!("key bound to epoch {bound}, request named {request}"),
                None,
            ),
            Rejection::RevisionRequired { command } => (
                "rejected.revision_required",
                format!("{command} must name the revision it last read"),
                None,
            ),
            Rejection::RateLimited {
                lane,
                retry_after_ns,
            } => (
                "rejected.rate_limited",
                format!(
                    "rate limited on the {} lane, retry in {} us",
                    lane_word(*lane),
                    retry_after_ns / 1_000
                ),
                None,
            ),
            Rejection::QueueFull { lane } => (
                "rejected.queue_full",
                format!("the {} queue is full", lane_word(*lane)),
                None,
            ),
            Rejection::IdReuse => (
                "rejected.id_reuse",
                "the number was used for a different request".to_string(),
                None,
            ),
        }),
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

    /// A sink the test controls: the replies it gives in order (then `Taken`), and what it was offered.
    struct Scripted {
        replies: Vec<SinkReply>,
        seen: Vec<(String, bool)>,
    }

    impl Scripted {
        fn new(replies: &[SinkReply]) -> Self {
            Self {
                replies: replies.to_vec(),
                seen: Vec::new(),
            }
        }
    }

    impl LineSink for Scripted {
        fn offer(&mut self, line: &str, critical: bool) -> SinkReply {
            self.seen.push((line.to_string(), critical));
            if self.replies.is_empty() {
                SinkReply::Taken
            } else {
                self.replies.remove(0)
            }
        }
    }

    fn accounted(s: &LogStats) -> bool {
        s.emitted == s.stored as u64 + s.dropped + s.drained
    }

    #[test]
    fn a_drain_offers_oldest_first_and_removes_only_what_the_sink_took() {
        let mut l = log(8, 65_536);
        for seq in 1..=3 {
            l.emit(&committed(seq), seq, 10, "grp");
        }
        let held: Vec<String> = l.lines().map(str::to_string).collect();
        let mut sink = Scripted::new(&[SinkReply::Taken, SinkReply::Taken, SinkReply::Full]);
        let report = l.drain_to(&mut sink, 10);
        assert_eq!(
            report,
            DrainReport {
                offered: 3,
                taken: 2,
                stop: DrainStop::SinkFull
            }
        );
        // The sink saw the lines in the order they were written, and the one it refused is still the oldest held.
        let offered: Vec<&str> = sink.seen.iter().map(|(line, _)| line.as_str()).collect();
        assert_eq!(
            offered,
            [held[0].as_str(), held[1].as_str(), held[2].as_str()]
        );
        assert_eq!(l.lines().collect::<Vec<_>>(), [held[2].as_str()]);
        let s = l.stats();
        assert_eq!(
            (
                s.stored,
                s.drained,
                s.offers,
                s.sink_full_polls,
                s.sink_unavailable_polls
            ),
            (1, 2, 3, 1, 0)
        );
        assert!(accounted(&s));
        // A sink that takes it empties the log, and an empty drain says so.
        let mut open = Scripted::new(&[]);
        assert_eq!(l.drain_to(&mut open, 10).stop, DrainStop::Empty);
        assert_eq!(l.stats().stored, 0);
        assert_eq!(l.drain_to(&mut open, 10).offered, 0);
        assert!(accounted(&l.stats()));
    }

    #[test]
    fn an_unavailable_sink_stops_the_drain_and_keeps_the_line() {
        let mut l = log(8, 65_536);
        l.emit(&committed(1), 1, 10, "grp");
        let mut sink = Scripted::new(&[SinkReply::Unavailable]);
        let report = l.drain_to(&mut sink, 10);
        assert_eq!(
            (report.offered, report.taken, report.stop),
            (1, 0, DrainStop::SinkUnavailable)
        );
        let s = l.stats();
        assert_eq!(
            (
                s.stored,
                s.drained,
                s.sink_unavailable_polls,
                s.sink_full_polls
            ),
            (1, 0, 1, 0)
        );
    }

    #[test]
    fn the_budget_bounds_the_offers_of_one_drain() {
        let mut l = log(8, 65_536);
        for seq in 1..=5 {
            l.emit(&committed(seq), seq, 10, "grp");
        }
        let mut sink = Scripted::new(&[]);
        let report = l.drain_to(&mut sink, 2);
        assert_eq!(
            (report.offered, report.taken, report.stop),
            (2, 2, DrainStop::Budget)
        );
        // No budget at all offers nothing, and a log with lines still says it stopped for the budget.
        let none = l.drain_to(&mut sink, 0);
        assert_eq!((none.offered, none.stop), (0, DrainStop::Budget));
        assert_eq!(l.stats().stored, 3);
        assert_eq!(l.drain_to(&mut sink, 3).stop, DrainStop::Empty);
        assert!(accounted(&l.stats()));
    }

    #[test]
    fn a_drain_gives_back_the_shares_of_the_records_it_removed() {
        let mut l = log(8, 65_536);
        for seq in 1..=4 {
            l.emit_ack(&ack_fact(seq), seq, 10, "grp");
        }
        for seq in 1..=2 {
            l.emit_reject(&reject_fact(seq), 10, 3, "grp");
        }
        let s = l.stats();
        assert_eq!((s.ack_stored, s.reject_stored, s.stored), (4, 2, 6));
        // The acknowledgement share is full: the next one is dropped. A drain frees it.
        l.emit_ack(&ack_fact(5), 5, 10, "grp");
        assert_eq!(l.stats().ack_dropped, 1);
        let mut sink = Scripted::new(&[]);
        assert_eq!(l.drain_to(&mut sink, 100).taken, 6);
        let s = l.stats();
        assert_eq!(
            (s.stored, s.bytes, s.ack_stored, s.reject_stored),
            (0, 0, 0, 0)
        );
        for seq in 6..=9 {
            l.emit_ack(&ack_fact(seq), seq, 10, "grp");
        }
        assert_eq!(l.stats().ack_stored, 4, "the share is whole again");
        assert!(accounted(&l.stats()));
    }

    #[test]
    fn a_critical_line_is_offered_as_critical_and_counted_until_it_is_taken() {
        let mut l = log(8, 65_536);
        l.emit(&committed(1), 1, 10, "grp");
        let critical = fact(2, Outcome::Refused(Refusal::InternalFault), true);
        l.emit(&critical, 2, 10, "grp");
        assert_eq!(l.stats().critical_held, 1);
        let mut sink = Scripted::new(&[SinkReply::Taken, SinkReply::Full]);
        l.drain_to(&mut sink, 10);
        let flags: Vec<bool> = sink.seen.iter().map(|(_, critical)| *critical).collect();
        assert_eq!(flags, [false, true]);
        // Refused, it is still held, and the run is not complete until it is delivered.
        assert_eq!(l.stats().critical_held, 1);
        assert!(
            l.is_evidence_complete(),
            "nothing is lost yet, only waiting"
        );
        let mut open = Scripted::new(&[]);
        l.drain_to(&mut open, 10);
        assert_eq!(l.stats().critical_held, 0);
        // drain() takes everything and counts it too.
        l.emit(&critical, 3, 10, "grp");
        assert_eq!(l.stats().critical_held, 1);
        assert_eq!(l.drain().len(), 1);
        let s = l.stats();
        assert_eq!((s.critical_held, s.stored), (0, 0));
        assert!(accounted(&s));
    }

    #[test]
    fn the_closing_record_is_a_valid_ffw_log_v1_event_and_matches_the_independent_vectors() {
        let doc: serde_json::Value = serde_json::from_str(VECTORS_JSON).expect("vectors parse");
        let text = |v: &serde_json::Value, key: &str| v[key].as_str().expect(key).to_string();
        let num = |v: &serde_json::Value, key: &str| v[key].as_u64().expect(key);
        let key_hex = text(&doc, "pseudonym_key_hex");
        let key: [u8; 32] = (0..key_hex.len() / 2)
            .map(|i| u8::from_str_radix(&key_hex[2 * i..2 * i + 2], 16).expect("hex"))
            .collect::<Vec<u8>>()
            .try_into()
            .expect("a 32-byte key");
        let lines = doc["summary_golden_lines"]
            .as_array()
            .expect("summary_golden_lines");
        assert_eq!(lines.len(), 3);
        for g in lines {
            let f = &g["fact"];
            let s = &f["stats"];
            let stats = LogStats {
                emitted: num(s, "emitted"),
                stored: usize::try_from(num(s, "stored")).unwrap(),
                dropped: num(s, "dropped"),
                drained: num(s, "drained"),
                critical_lost: num(s, "critical_lost"),
                critical_held: usize::try_from(num(s, "critical_held")).unwrap(),
                ..LogStats::default()
            };
            let l = ChannelLog::new(
                LogConfig::new(&text(&doc, "run_id"), &text(&doc, "case_id"), 16, 65_536).unwrap(),
                LogKey::new(key),
            );
            let sink = SinkCounts {
                written: num(&f["sink"], "written"),
                dropped: num(&f["sink"], "dropped"),
                critical_dropped: num(&f["sink"], "critical_dropped"),
            };
            let line = l
                .closing_line_for(&stats, &sink, num(f, "now_ns"))
                .expect("the record serializes");
            assert_eq!(line, text(g, "line"), "{}", text(g, "id"));
            // It is an ordinary event of the shared schema, and it round-trips exactly.
            let event: DiagnosticEvent = serde_json::from_str(&line).expect("a valid event");
            assert_eq!(event.event_kind, "n02.log.summary");
            assert_eq!(serde_json::to_string(&event).unwrap(), line);
            assert_eq!(redact_sensitive_text(&line), line);
        }
    }

    fn reject_fact(seq: u64) -> RejectFact {
        RejectFact::new(
            PeerId::parse("ctl-a").unwrap(),
            seq,
            seq,
            1,
            &SubmitResult::Rejected(Rejection::QueueFull {
                lane: Lane::Ordinary,
            }),
        )
        .unwrap()
    }

    fn submit_result_for(o: &serde_json::Value) -> SubmitResult {
        let n = |key: &str| o[key].as_u64().expect(key);
        let lane = || match o["lane"].as_str() {
            Some("ordinary") => Lane::Ordinary,
            Some("priority") => Lane::Priority,
            other => panic!("unknown lane {other:?} in the vectors"),
        };
        match o["kind"].as_str().expect("kind") {
            "unauthenticated" => {
                SubmitResult::Rejected(Rejection::Unauthenticated(match o["failure"].as_str() {
                    Some("unknown_peer") => AuthFailure::UnknownPeer,
                    Some("revoked") => AuthFailure::Revoked,
                    Some("bad_proof") => AuthFailure::BadProof,
                    other => panic!("unknown failure {other:?} in the vectors"),
                }))
            }
            "epoch_not_bound" => SubmitResult::Rejected(Rejection::EpochNotBound {
                bound: n("bound"),
                request: n("request"),
            }),
            "revision_required" => SubmitResult::Rejected(Rejection::RevisionRequired {
                command: match o["command"].as_str() {
                    Some("set-group-volume") => "set-group-volume",
                    Some("set-member-mute") => "set-member-mute",
                    other => panic!("unknown command {other:?} in the vectors"),
                },
            }),
            "rate_limited" => SubmitResult::Rejected(Rejection::RateLimited {
                lane: lane(),
                retry_after_ns: n("retry_after_ns"),
            }),
            "queue_full" => SubmitResult::Rejected(Rejection::QueueFull { lane: lane() }),
            "id_reuse" => SubmitResult::Rejected(Rejection::IdReuse),
            "out_of_window" => SubmitResult::OutOfWindow { floor: n("floor") },
            other => panic!("unknown submit result `{other}` in the vectors"),
        }
    }

    /// The lines of requests turned away were computed with Python's `hashlib` and `json`; the Rust builds each
    /// from the result named in the fact, so the vocabulary, the arithmetic and the bytes are all pinned.
    #[test]
    fn submit_lines_match_the_independent_vectors() {
        let doc: serde_json::Value = serde_json::from_str(VECTORS_JSON).expect("vectors parse");
        let text = |v: &serde_json::Value, key: &str| v[key].as_str().expect(key).to_string();
        let num = |v: &serde_json::Value, key: &str| v[key].as_u64().expect(key);
        let key_hex = text(&doc, "pseudonym_key_hex");
        let key: [u8; 32] = (0..key_hex.len() / 2)
            .map(|i| u8::from_str_radix(&key_hex[2 * i..2 * i + 2], 16).expect("hex"))
            .collect::<Vec<u8>>()
            .try_into()
            .expect("a 32-byte key");
        let lines = doc["submit_golden_lines"]
            .as_array()
            .expect("submit_golden_lines");
        assert_eq!(lines.len(), 9);
        for g in lines {
            let f = &g["fact"];
            let fact = RejectFact::new(
                PeerId::parse(&text(f, "peer")).unwrap(),
                num(f, "seq"),
                num(f, "now_ns"),
                usize::try_from(num(f, "queue_depth")).unwrap(),
                &submit_result_for(&f["result"]),
            )
            .expect("the vector names a request that was turned away");
            let mut l = ChannelLog::new(
                LogConfig::new(&text(&doc, "run_id"), &text(&doc, "case_id"), 16, 65_536).unwrap(),
                LogKey::new(key),
            );
            l.emit_reject(
                &fact,
                num(f, "epoch"),
                num(f, "revision"),
                &text(f, "group"),
            );
            assert_eq!(
                l.lines().next().unwrap(),
                text(g, "line"),
                "{}",
                text(g, "id")
            );
        }
    }

    #[test]
    fn a_request_that_was_not_turned_away_has_no_fact() {
        let peer = || PeerId::parse("ctl-a").unwrap();
        for (how, result) in [
            (
                "queued",
                SubmitResult::Queued {
                    lane: Lane::Ordinary,
                },
            ),
            (
                "already waiting",
                SubmitResult::AlreadyQueued {
                    lane: Lane::Priority,
                },
            ),
            (
                "answered from the ledger",
                SubmitResult::Settled(Outcome::Committed { revision: 3 }),
            ),
        ] {
            assert!(
                RejectFact::new(peer(), 1, 1, 0, &result).is_none(),
                "{how} must write no record"
            );
        }
    }

    #[test]
    fn every_way_a_request_is_turned_away_has_its_own_word_and_no_text_from_the_sender() {
        let results = [
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::UnknownPeer)),
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::Revoked)),
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::BadProof)),
            SubmitResult::Rejected(Rejection::EpochNotBound {
                bound: 10,
                request: 9,
            }),
            SubmitResult::Rejected(Rejection::RevisionRequired {
                command: "set-group-volume",
            }),
            SubmitResult::Rejected(Rejection::RateLimited {
                lane: Lane::Ordinary,
                retry_after_ns: 5_000,
            }),
            SubmitResult::Rejected(Rejection::QueueFull {
                lane: Lane::Priority,
            }),
            SubmitResult::Rejected(Rejection::IdReuse),
            SubmitResult::OutOfWindow { floor: 2 },
        ];
        let mut seen = std::collections::BTreeSet::new();
        for result in &results {
            let (kind, message, cause) = describe_submit(result).expect("a word");
            assert!(!kind.is_empty() && !message.is_empty());
            // Only the vocabulary and numbers: lower-case words, digits and the few separators the messages use.
            assert!(
                message.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b' ' | b'-' | b',' | b':')),
                "{message}"
            );
            seen.insert((kind, cause));
        }
        assert_eq!(seen.len(), results.len(), "two results share a word");
    }

    #[test]
    fn records_of_requests_turned_away_hold_to_a_quarter_of_the_log_and_every_drop_is_counted() {
        let mut l = log(8, 65_536);
        for seq in 1..=10 {
            l.emit_reject(&reject_fact(seq), 10, 3, "grp");
        }
        let s = l.stats();
        assert_eq!(
            (
                s.emitted,
                s.stored,
                s.dropped,
                s.reject_stored,
                s.reject_dropped
            ),
            (10, 2, 8, 2, 8)
        );
        assert_eq!(s.emitted, s.stored as u64 + s.dropped);
        // Acknowledgements keep their half and command records keep what is left: at least a quarter.
        for seq in 1..=4 {
            l.emit_ack(&ack_fact(seq), 20, 10, "grp");
        }
        for seq in 1..=4 {
            l.emit(&committed(seq), 20, 10, "grp");
        }
        let s = l.stats();
        assert_eq!((s.stored, s.ack_stored, s.reject_stored), (8, 4, 2));
        assert_eq!(s.emitted, s.stored as u64 + s.dropped);
        // Two command records are held beside the two records of requests turned away.
        let steps = l
            .lines()
            .filter(|line| line.contains("\"event_kind\":\"n02.step."))
            .count();
        assert_eq!(steps, 2);
    }

    #[test]
    fn the_share_of_requests_turned_away_is_held_in_bytes_as_well_as_records() {
        let mut probe = log(64, 65_536);
        probe.emit_reject(&reject_fact(1), 10, 3, "grp");
        let one = probe.stats().bytes;
        // Room for eight lines in all, so two for requests turned away.
        let mut l = log(64, one * 8);
        for seq in 1..=5 {
            l.emit_reject(&reject_fact(seq), 10, 3, "grp");
        }
        let s = l.stats();
        assert_eq!((s.reject_stored, s.reject_dropped, s.dropped), (2, 3, 3));
        assert!(s.bytes <= one * 8);
    }

    #[test]
    fn a_critical_record_evicts_the_records_of_requests_turned_away_after_acknowledgements_and_before_command_records()
     {
        let mut l = log(8, 65_536);
        l.emit(&committed(1), 1, 10, "grp");
        l.emit(&committed(2), 2, 10, "grp");
        l.emit_ack(&ack_fact(3), 3, 10, "grp");
        l.emit_reject(&reject_fact(4), 4, 3, "grp");
        l.emit_reject(&reject_fact(5), 5, 3, "grp");
        l.emit(&committed(6), 6, 10, "grp");
        l.emit(&committed(7), 7, 10, "grp");
        l.emit(&committed(8), 8, 10, "grp");
        assert_eq!(l.stats().stored, 8);
        let critical = |seq| fact(seq, Outcome::Refused(Refusal::InternalFault), true);
        // The first critical record takes the acknowledgement's place.
        l.emit(&critical(9), 9, 10, "grp");
        let s = l.stats();
        assert_eq!((s.stored, s.ack_stored, s.reject_stored), (8, 0, 2));
        // The next two take the places of the two records of requests turned away.
        l.emit(&critical(10), 10, 10, "grp");
        l.emit(&critical(11), 11, 10, "grp");
        let s = l.stats();
        assert_eq!(
            (
                s.stored,
                s.ack_stored,
                s.reject_stored,
                s.reject_dropped,
                s.critical_lost
            ),
            (8, 0, 0, 2, 0)
        );
        // Only then does a command record go.
        l.emit(&critical(12), 12, 10, "grp");
        let s = l.stats();
        assert_eq!((s.stored, s.critical_lost), (8, 0));
        assert_eq!(s.emitted, s.stored as u64 + s.dropped);
    }

    #[test]
    fn a_pending_overflow_is_counted_as_a_dropped_record() {
        let mut l = log(8, 65_536);
        l.note_reject_overflow();
        l.note_reject_overflow();
        let s = l.stats();
        assert_eq!(
            (s.emitted, s.stored, s.dropped, s.reject_dropped),
            (2, 0, 2, 2)
        );
        assert!(l.is_evidence_complete());
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

    // ------------------------------------------------------------------------------------------- the injected fault label

    const FAULT: &str = "drop-ack-after-commit";

    fn fault_log(fault: Option<&str>) -> ChannelLog {
        let mut config = LogConfig::new("run-1", "case-1", 32, 65_536).unwrap();
        if let Some(label) = fault {
            config = config.with_fault(label).unwrap();
        }
        ChannelLog::new(config, LogKey::new(KEY))
    }

    /// One record of every kind the log writes, in a fixed order: a settled command, an acknowledgement, a request turned
    /// away at `submit`, and the closing record.
    fn one_of_each(log: &mut ChannelLog) -> Vec<String> {
        log.emit(&committed(1), 1_000_000, 10, "grp");
        log.emit_ack(&ack_fact(1), 2_000_000, 10, "grp");
        log.emit_reject(&reject_fact(1), 10, 3, "grp");
        let closing = log
            .closing_line(&SinkCounts::default(), 3_000_000)
            .expect("the closing record serializes");
        let mut lines: Vec<String> = log.lines().map(str::to_string).collect();
        lines.push(closing);
        lines
    }

    /// `Ok` when every line carries exactly `expected` as its `fault` (and none carries one when `expected` is `None`);
    /// otherwise a verdict that starts `MISSING-FAULT`, `WRONG-FAULT` or `UNEXPECTED-FAULT` and names the record.
    fn judge_fault_labels(lines: &[String], expected: Option<&str>) -> Result<(), String> {
        for (index, line) in lines.iter().enumerate() {
            let event: DiagnosticEvent = serde_json::from_str(line)
                .map_err(|e| format!("setup: record {index} is not a shared event: {e}"))?;
            match (event.fault.as_deref(), expected) {
                (None, Some(want)) => {
                    return Err(format!(
                        "MISSING-FAULT: record {index} has no fault, the run is under `{want}`"
                    ));
                }
                (Some(got), Some(want)) if got != want => {
                    return Err(format!(
                        "WRONG-FAULT: record {index} names `{got}`, the run is under `{want}`"
                    ));
                }
                (Some(got), None) => {
                    return Err(format!(
                        "UNEXPECTED-FAULT: record {index} names `{got}` in a run under no fault"
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[test]
    fn a_fault_label_is_held_to_the_label_alphabet_and_length() {
        let base = LogConfig::new("run", "case", 1, 1).unwrap();
        for ok in [
            "drop-ack-after-commit",
            "a",
            "0",
            "a.b_c-d",
            &"x".repeat(MAX_LABEL_LEN),
        ] {
            assert!(base.clone().with_fault(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "Fault",
            "has space",
            "-lead",
            "a\"b",
            "line\nbreak",
            &"x".repeat(MAX_LABEL_LEN + 1),
        ] {
            assert_eq!(
                base.clone().with_fault(bad),
                Err(LogError::InvalidLabel { field: "fault" }),
                "{bad:?}"
            );
        }
        // A log told no fault has none.
        assert_eq!(base.fault, None);
    }

    #[test]
    fn every_kind_of_record_carries_the_fault_when_one_is_set_and_none_carries_it_when_not() {
        let mut faulted = fault_log(Some(FAULT));
        let lines = one_of_each(&mut faulted);
        assert_eq!(lines.len(), 4);
        assert_eq!(judge_fault_labels(&lines, Some(FAULT)), Ok(()));
        for line in &lines {
            let event: DiagnosticEvent = serde_json::from_str(line).expect("a shared-schema event");
            assert_eq!(
                serde_json::to_string(&event).unwrap(),
                *line,
                "byte-identical round trip"
            );
            assert!(line.len() <= MAX_LINE_BYTES);
            assert_eq!(
                redact_sensitive_text(line),
                *line,
                "nothing sensitive-looking in {line}"
            );
        }
        // Told no fault, the same four records carry no key, and each is the faulted one with the pair removed.
        let mut plain = fault_log(None);
        let plain_lines = one_of_each(&mut plain);
        assert_eq!(judge_fault_labels(&plain_lines, None), Ok(()));
        let pair = format!(",\"fault\":\"{FAULT}\"");
        for (with, without) in lines.iter().zip(&plain_lines) {
            assert!(!without.contains("\"fault\""), "{without}");
            assert_eq!(&with.replacen(&pair, "", 1), without);
        }
    }

    #[test]
    fn the_fault_judge_names_a_missing_a_wrong_and_an_unexpected_label() {
        let mut faulted = fault_log(Some(FAULT));
        let lines = one_of_each(&mut faulted);
        let mut plain = fault_log(None);
        let plain_lines = one_of_each(&mut plain);
        // The faithful logs pass first, so each verdict below is the judge seeing the plant.
        assert_eq!(judge_fault_labels(&lines, Some(FAULT)), Ok(()));
        assert_eq!(judge_fault_labels(&plain_lines, None), Ok(()));
        // A log that was never told the fault, judged as if the run were under it.
        let verdict = judge_fault_labels(&plain_lines, Some(FAULT));
        assert!(
            verdict
                .as_ref()
                .is_err_and(|e| e.starts_with("MISSING-FAULT: record 0")),
            "{verdict:?}"
        );
        // A log under another fault.
        let mut other = fault_log(Some("another-fault"));
        let other_lines = one_of_each(&mut other);
        let verdict = judge_fault_labels(&other_lines, Some(FAULT));
        assert!(
            verdict
                .as_ref()
                .is_err_and(|e| e.starts_with("WRONG-FAULT: record 0")),
            "{verdict:?}"
        );
        // One kind of record that forgets the label: the request turned away at `submit` (record 2) loses it.
        let pair = format!(",\"fault\":\"{FAULT}\"");
        let mut forgetful = lines.clone();
        forgetful[2] = forgetful[2].replacen(&pair, "", 1);
        let verdict = judge_fault_labels(&forgetful, Some(FAULT));
        assert!(
            verdict
                .as_ref()
                .is_err_and(|e| e.starts_with("MISSING-FAULT: record 2")),
            "{verdict:?}"
        );
        // A run under no fault whose records name one.
        let verdict = judge_fault_labels(&lines, None);
        assert!(
            verdict
                .as_ref()
                .is_err_and(|e| e.starts_with("UNEXPECTED-FAULT: record 0")),
            "{verdict:?}"
        );
    }

    #[test]
    fn a_fault_label_at_its_limit_does_not_push_any_record_past_the_line_cap() {
        let long = "x".repeat(MAX_LABEL_LEN);
        let config = LogConfig::new(&long, &long, 32, 65_536)
            .unwrap()
            .with_fault(&long)
            .unwrap();
        let mut l = ChannelLog::new(config, LogKey::new(KEY));
        let mut worst = fact(
            u64::MAX,
            Outcome::Refused(Refusal::Session(SessionError::UnknownMember {
                member_id: "nowhere".to_string(),
            })),
            false,
        );
        worst.cause = Some("unknown_member".to_string());
        worst.revision = u64::MAX;
        worst.queue_depth = usize::MAX;
        worst.waited_ns = u64::MAX;
        l.emit(&worst, u64::MAX, u64::MAX, "grp");
        l.emit_ack(
            &AckFact {
                peer: PeerId::parse("ctl-a").unwrap(),
                seq: u64::MAX,
                outcome: AckOutcome::Unauthenticated(AuthFailure::UnknownPeer),
                revision: u64::MAX,
                queue_depth: usize::MAX,
            },
            u64::MAX,
            u64::MAX,
            "grp",
        );
        let turned_away = RejectFact::new(
            PeerId::parse("ctl-a").unwrap(),
            u64::MAX,
            u64::MAX,
            usize::MAX,
            &SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::UnknownPeer)),
        )
        .unwrap();
        l.emit_reject(&turned_away, u64::MAX, u64::MAX, "grp");
        let closing = l
            .closing_line(
                &SinkCounts {
                    written: u64::MAX,
                    dropped: u64::MAX,
                    critical_dropped: u64::MAX,
                },
                u64::MAX,
            )
            .expect("the closing record serializes");
        let stats = l.stats();
        assert_eq!(
            (stats.emitted, stats.stored, stats.dropped),
            (3, 3, 0),
            "no record was dropped for length"
        );
        for line in l.lines().chain(std::iter::once(closing.as_str())) {
            assert!(line.len() <= MAX_LINE_BYTES, "{} bytes: {line}", line.len());
            assert!(line.contains(&format!("\"fault\":\"{long}\"")), "{line}");
        }
    }

    #[test]
    fn fault_lines_match_the_independent_vectors() {
        fn family_key(family: &str) -> &'static str {
            match family {
                "step" => "golden_lines",
                "ack" => "ack_golden_lines",
                "submit" => "submit_golden_lines",
                "summary" => "summary_golden_lines",
                other => panic!("unknown record family `{other}` in the vectors"),
            }
        }
        let doc: serde_json::Value = serde_json::from_str(VECTORS_JSON).expect("vectors parse");
        let text = |v: &serde_json::Value, key: &str| v[key].as_str().expect(key).to_string();
        let num = |v: &serde_json::Value, key: &str| v[key].as_u64().expect(key);
        let key_hex = text(&doc, "pseudonym_key_hex");
        let key: [u8; 32] = (0..key_hex.len() / 2)
            .map(|i| u8::from_str_radix(&key_hex[2 * i..2 * i + 2], 16).expect("hex"))
            .collect::<Vec<u8>>()
            .try_into()
            .expect("a 32-byte key");
        let entries = doc["fault_golden_lines"]
            .as_array()
            .expect("fault_golden_lines");
        assert_eq!(entries.len(), 8);
        for entry in entries {
            let (id, family, fault) = (
                text(entry, "id"),
                text(entry, "family"),
                text(entry, "fault"),
            );
            let base = doc[family_key(&family)]
                .as_array()
                .expect("an array of base facts")
                .iter()
                .find(|g| g["id"] == entry["base"])
                .unwrap_or_else(|| panic!("{id}: its base fact is not in the vectors"));
            let f = &base["fact"];
            let mut l = ChannelLog::new(
                LogConfig::new(&text(&doc, "run_id"), &text(&doc, "case_id"), 16, 65_536)
                    .unwrap()
                    .with_fault(&fault)
                    .unwrap(),
                LogKey::new(key),
            );
            let line = match family.as_str() {
                "step" => {
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
                    l.emit(&fact, num(f, "now_ns"), num(f, "epoch"), &text(f, "group"));
                    l.lines().next().unwrap().to_string()
                }
                "ack" => {
                    let fact = AckFact {
                        peer: PeerId::parse(&text(f, "peer")).unwrap(),
                        seq: num(f, "seq"),
                        outcome: ack_outcome_for(&f["outcome"]),
                        revision: num(f, "revision"),
                        queue_depth: usize::try_from(num(f, "queue_depth")).unwrap(),
                    };
                    l.emit_ack(&fact, num(f, "now_ns"), num(f, "epoch"), &text(f, "group"));
                    l.lines().next().unwrap().to_string()
                }
                "submit" => {
                    let fact = RejectFact::new(
                        PeerId::parse(&text(f, "peer")).unwrap(),
                        num(f, "seq"),
                        num(f, "now_ns"),
                        usize::try_from(num(f, "queue_depth")).unwrap(),
                        &submit_result_for(&f["result"]),
                    )
                    .expect("the vector names a request that was turned away");
                    l.emit_reject(
                        &fact,
                        num(f, "epoch"),
                        num(f, "revision"),
                        &text(f, "group"),
                    );
                    l.lines().next().unwrap().to_string()
                }
                "summary" => {
                    let s = &f["stats"];
                    let stats = LogStats {
                        emitted: num(s, "emitted"),
                        stored: usize::try_from(num(s, "stored")).unwrap(),
                        dropped: num(s, "dropped"),
                        drained: num(s, "drained"),
                        critical_lost: num(s, "critical_lost"),
                        critical_held: usize::try_from(num(s, "critical_held")).unwrap(),
                        ..LogStats::default()
                    };
                    let sink = SinkCounts {
                        written: num(&f["sink"], "written"),
                        dropped: num(&f["sink"], "dropped"),
                        critical_dropped: num(&f["sink"], "critical_dropped"),
                    };
                    l.closing_line_for(&stats, &sink, num(f, "now_ns"))
                        .expect("the record serializes")
                }
                other => panic!("unknown record family `{other}` in the vectors"),
            };
            assert_eq!(line, text(entry, "line"), "{id}");
            // It is an ordinary event of the shared schema, it names the fault, and it round-trips exactly.
            let event: DiagnosticEvent = serde_json::from_str(&line).expect("a valid event");
            assert_eq!(event.fault.as_deref(), Some(fault.as_str()), "{id}");
            assert_eq!(serde_json::to_string(&event).unwrap(), line, "{id}");
        }
    }
}
