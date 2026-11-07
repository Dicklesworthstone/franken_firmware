//! Diagnostics for the playout engine (`N04` / `ffw-nx0`, contract section 15): one bounded `ffw.log.v1` JSON line
//! per decision and per refusal, written here, and a nonblocking path from the engine to whatever consumes them.
//!
//! The decision path never touches a sink. It formats a line into a preallocated ring and returns; a separate
//! [`PlayoutEngine::drain_log`] offers queued lines to a [`LogSink`], oldest first, at most `budget` offers per call.
//! So a slow, full, unavailable or even blocking sink can stall only the thread that drains, never `decide`, and
//! whatever the sink does, the engine's decisions are the ones it takes with no log at all.
//!
//! Nothing is lost silently. Every record is delivered, still queued, or counted as dropped:
//! `emitted == delivered + queued + dropped_full + dropped_oversize` ([`LogStats::accounted`]). A line longer than
//! the bound is dropped whole, never cut. Ordinary records (a real block, a refused packet, a delivered block) may use
//! all but a quarter of the ring; critical ones (everything that changes what is heard or the timeline) may use all of
//! it, so a flood of ordinary records cannot crowd out the evidence a run cannot be trusted without. When a critical
//! record is lost, [`LogStats::evidence_complete`] is false.
//!
//! A record carries only fixed vocabulary and numbers: nothing a peer supplied (payload bytes, strings) is copied into
//! it, and the member and group appear only as the caller's keyed pseudonyms (`p-` and 16 hex characters), which this
//! module will not accept in any other form. The key never enters the engine.

use core::fmt::{self, Display, Write as _};

use serde::Serialize;

use super::{
    Admission, BLOCK_FRAMES, ChangeReject, ClockView, Decision, Delivery, LatencyChange, Outcome,
    PlayoutEngine, Poll, StartReject,
};

/// The schema every line declares; the shared diagnostics type (`franken-test-support`) checks lines against it.
pub const LOG_SCHEMA: &str = "ffw.log.v1";
/// Longest line the ring can hold; a longer record is dropped and counted.
pub const MAX_LINE_BYTES: usize = 1024;
/// Longest run, case or fault label.
pub const MAX_LABEL_LEN: usize = 64;

/// Why a [`LogConfig`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogConfigError {
    /// A label is empty, over 64 bytes, or not `[a-z0-9][a-z0-9._-]*`.
    InvalidLabel { field: &'static str },
    /// A member or group identifier is not `p-` followed by 16 lowercase hex characters.
    NotAPseudonym { field: &'static str },
    /// The ring needs at least one slot.
    ZeroCapacity,
    /// The line bound is zero or above [`MAX_LINE_BYTES`].
    BadMaxLine,
}

impl LogConfigError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidLabel { .. } => "invalid_label",
            Self::NotAPseudonym { .. } => "not_a_pseudonym",
            Self::ZeroCapacity => "zero_capacity",
            Self::BadMaxLine => "bad_max_line",
        }
    }
}

fn valid_label(text: &str) -> bool {
    let b = text.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_LABEL_LEN
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|&c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'_' || c == b'-'
        })
}

fn valid_pseudonym(text: &str) -> bool {
    text.len() == 18
        && text.starts_with("p-")
        && text.as_bytes()[2..]
            .iter()
            .all(|&c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Validated ASCII text retained inline, including its exact logical length.
/// Only the checked LogConfig constructors create these values.
#[derive(Clone, PartialEq, Eq)]
struct InlineText<const CAPACITY: usize> {
    bytes: [u8; CAPACITY],
    len: usize,
}

impl<const CAPACITY: usize> InlineText<CAPACITY> {
    fn from_validated(text: &str) -> Self {
        debug_assert!(text.is_ascii() && text.len() <= CAPACITY);
        let mut bytes = [0; CAPACITY];
        bytes[..text.len()].copy_from_slice(text.as_bytes());
        Self {
            bytes,
            len: text.len(),
        }
    }

    fn as_str(&self) -> Result<&str, fmt::Error> {
        core::str::from_utf8(&self.bytes[..self.len]).map_err(|_| fmt::Error)
    }
}

impl<const CAPACITY: usize> Display for InlineText<CAPACITY> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str()?)
    }
}

impl<const CAPACITY: usize> fmt::Debug for InlineText<CAPACITY> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str()?, f)
    }
}

/// Where the diagnostics go and how much memory they may use: `capacity` lines of up to [`MAX_LINE_BYTES`] each,
/// allocated once when logging is enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogConfig {
    run_id: InlineText<MAX_LABEL_LEN>,
    case_id: InlineText<MAX_LABEL_LEN>,
    member_id: InlineText<18>,
    group_id: InlineText<18>,
    fault: Option<InlineText<MAX_LABEL_LEN>>,
    capacity: usize,
    max_line: usize,
}

impl LogConfig {
    /// `member_id` and `group_id` must already be pseudonyms (`ffw.pseudonym.v1`: `p-` and 16 hex characters of the
    /// keyed SHA-256 of the identifier); a raw identifier is refused, so one cannot reach a record by mistake.
    ///
    /// # Errors
    /// A label or pseudonym of the wrong form, or a zero `capacity`.
    pub fn new(
        run_id: &str,
        case_id: &str,
        member_id: &str,
        group_id: &str,
        capacity: usize,
    ) -> Result<Self, LogConfigError> {
        if !valid_label(run_id) {
            return Err(LogConfigError::InvalidLabel { field: "run_id" });
        }
        if !valid_label(case_id) {
            return Err(LogConfigError::InvalidLabel { field: "case_id" });
        }
        if !valid_pseudonym(member_id) {
            return Err(LogConfigError::NotAPseudonym { field: "member_id" });
        }
        if !valid_pseudonym(group_id) {
            return Err(LogConfigError::NotAPseudonym { field: "group_id" });
        }
        if capacity == 0 {
            return Err(LogConfigError::ZeroCapacity);
        }
        Ok(Self {
            run_id: InlineText::from_validated(run_id),
            case_id: InlineText::from_validated(case_id),
            member_id: InlineText::from_validated(member_id),
            group_id: InlineText::from_validated(group_id),
            fault: None,
            capacity,
            max_line: MAX_LINE_BYTES,
        })
    }

    /// Name the injected fault schedule this run is under; every record then carries it.
    ///
    /// # Errors
    /// `fault` is not a valid label.
    pub fn with_fault(mut self, fault: &str) -> Result<Self, LogConfigError> {
        if !valid_label(fault) {
            return Err(LogConfigError::InvalidLabel { field: "fault" });
        }
        self.fault = Some(InlineText::from_validated(fault));
        Ok(self)
    }

    /// Lower the line bound (1 to [`MAX_LINE_BYTES`]).
    ///
    /// # Errors
    /// `max_line` is zero or above [`MAX_LINE_BYTES`].
    pub fn with_max_line(mut self, max_line: usize) -> Result<Self, LogConfigError> {
        if max_line == 0 || max_line > MAX_LINE_BYTES {
            return Err(LogConfigError::BadMaxLine);
        }
        self.max_line = max_line;
        Ok(self)
    }
}

/// What a sink said to one offered line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkReply {
    /// The sink has the line; it leaves the ring.
    Taken,
    /// The sink cannot take it right now; it stays queued and this drain stops.
    Full,
    /// The sink is down; it stays queued and this drain stops.
    Unavailable,
}

/// A consumer of log lines. `offer` is called only from [`PlayoutEngine::drain_log`], never from the decision path,
/// and should still return promptly: a drain makes at most `budget` offers.
pub trait LogSink {
    /// One complete line, without a trailing newline.
    fn offer(&mut self, line: &str) -> SinkReply;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainReport {
    pub offered: usize,
    pub taken: usize,
    pub stop: DrainStop,
}

/// Cumulative counts. `queued` is the number of lines waiting now; the rest only grow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct LogStats {
    /// Records the engine produced, kept or not.
    pub emitted: u64,
    pub delivered: u64,
    pub queued: u64,
    /// Not stored because the ring had no room for its kind of record.
    pub dropped_full: u64,
    /// Not stored because the line was longer than the bound.
    pub dropped_oversize: u64,
    /// Critical records among the dropped.
    pub critical_lost: u64,
    /// Lines offered to a sink.
    pub offers: u64,
    pub sink_full_polls: u64,
    pub sink_unavailable_polls: u64,
}

impl LogStats {
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped_full + self.dropped_oversize
    }

    /// Every record is delivered, queued or counted as dropped.
    #[must_use]
    pub const fn accounted(&self) -> bool {
        self.emitted == self.delivered + self.queued + self.dropped()
    }

    /// False once a critical record has been lost: the run's log can no longer be trusted as complete.
    #[must_use]
    pub const fn evidence_complete(&self) -> bool {
        self.critical_lost == 0
    }
}

impl Display for LogStats {
    /// The concise human summary line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "n04 log: emitted={} delivered={} queued={} dropped={} (full={} oversize={}) critical_lost={} evidence={}",
            self.emitted,
            self.delivered,
            self.queued,
            self.dropped(),
            self.dropped_full,
            self.dropped_oversize,
            self.critical_lost,
            if self.evidence_complete() {
                "complete"
            } else {
                "INCOMPLETE"
            },
        )
    }
}

#[derive(Clone, Copy)]
struct Line {
    len: usize,
    bytes: [u8; MAX_LINE_BYTES],
}

impl Line {
    const EMPTY: Self = Self {
        len: 0,
        bytes: [0; MAX_LINE_BYTES],
    };
}

/// `fmt::Write` into a [`Line`] that fails, writing nothing of the offending piece, once `limit` would be exceeded.
struct LineWriter<'a> {
    line: &'a mut Line,
    limit: usize,
}

impl fmt::Write for LineWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.line.len + s.len();
        if end > self.limit {
            return Err(fmt::Error);
        }
        self.line.bytes[self.line.len..end].copy_from_slice(s.as_bytes());
        self.line.len = end;
        Ok(())
    }
}

/// One record before it becomes a line.
struct Record<'a> {
    ts: u64,
    n: u64,
    epoch: u64,
    revision: u64,
    queue: u32,
    latency_us: u64,
    kind: fmt::Arguments<'a>,
    message: fmt::Arguments<'a>,
    cause: Option<&'static str>,
    critical: bool,
}

/// The engine's log: a ring of preallocated lines and their counts.
#[derive(Debug)]
pub(super) struct DiagLog {
    cfg: LogConfig,
    reserve: usize,
    ring: Vec<Line>,
    head: usize,
    count: usize,
    scratch: Line,
    last_ts: u64,
    stats: LogStats,
}

impl core::fmt::Debug for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Line({} bytes)", self.len)
    }
}

impl DiagLog {
    fn new(cfg: LogConfig) -> Self {
        let ring = vec![Line::EMPTY; cfg.capacity];
        Self::with_ring(cfg, ring)
    }

    /// The same ring, reserved fallibly: `None` when the allocator cannot give it. The `Vec` that was reserved is the one kept.
    fn try_new(cfg: LogConfig) -> Option<Self> {
        let mut ring: Vec<Line> = Vec::new();
        ring.try_reserve_exact(cfg.capacity).ok()?;
        ring.resize(cfg.capacity, Line::EMPTY);
        Some(Self::with_ring(cfg, ring))
    }

    fn with_ring(cfg: LogConfig, ring: Vec<Line>) -> Self {
        Self {
            reserve: cfg.capacity / 4,
            ring,
            cfg,
            head: 0,
            count: 0,
            scratch: Line::EMPTY,
            last_ts: 0,
            stats: LogStats::default(),
        }
    }

    /// Bytes this ring holds on the heap.
    fn ring_bytes(&self) -> usize {
        self.ring.capacity() * core::mem::size_of::<Line>()
    }

    /// Heap this log holds: the ring; configuration text is inline.
    fn heap_bytes(&self) -> usize {
        self.ring_bytes().saturating_add(self.cfg.heap_bytes())
    }

    fn stats(&self) -> LogStats {
        LogStats {
            queued: self.count as u64,
            ..self.stats
        }
    }

    /// Format one record and queue it, or count why not. Never waits, never allocates.
    fn emit(&mut self, r: &Record<'_>) {
        self.stats.emitted += 1;
        let ts = r.ts.max(self.last_ts);
        self.last_ts = ts;
        self.scratch.len = 0;
        let fits = {
            let c = &self.cfg;
            let mut w = LineWriter {
                line: &mut self.scratch,
                limit: c.max_line,
            };
            write_record(&mut w, c, ts, r).is_ok()
        };
        if !fits {
            self.stats.dropped_oversize += 1;
            self.stats.critical_lost += u64::from(r.critical);
            return;
        }
        let capacity = self.ring.len();
        let limit = if r.critical {
            capacity
        } else {
            capacity - self.reserve
        };
        if self.count >= limit {
            self.stats.dropped_full += 1;
            self.stats.critical_lost += u64::from(r.critical);
            return;
        }
        let at = (self.head + self.count) % capacity;
        let n = self.scratch.len;
        self.ring[at].bytes[..n].copy_from_slice(&self.scratch.bytes[..n]);
        self.ring[at].len = n;
        self.count += 1;
    }

    fn drain(&mut self, sink: &mut dyn LogSink, budget: usize) -> DrainReport {
        let mut report = DrainReport {
            offered: 0,
            taken: 0,
            stop: DrainStop::Empty,
        };
        while report.offered < budget {
            if self.count == 0 {
                return report;
            }
            let line = &self.ring[self.head];
            let Ok(text) = core::str::from_utf8(&line.bytes[..line.len]) else {
                // Unreachable: a line is only ever written through `fmt::Write`, which writes whole `&str`s. Counted
                // as a lost critical record so that, if it ever happened, it could not pass silently.
                self.pop();
                self.stats.dropped_oversize += 1;
                self.stats.critical_lost += 1;
                continue;
            };
            report.offered += 1;
            self.stats.offers += 1;
            match sink.offer(text) {
                SinkReply::Taken => {
                    self.pop();
                    self.stats.delivered += 1;
                    report.taken += 1;
                }
                SinkReply::Full => {
                    self.stats.sink_full_polls += 1;
                    report.stop = DrainStop::SinkFull;
                    return report;
                }
                SinkReply::Unavailable => {
                    self.stats.sink_unavailable_polls += 1;
                    report.stop = DrainStop::SinkUnavailable;
                    return report;
                }
            }
        }
        report.stop = if self.count == 0 {
            DrainStop::Empty
        } else {
            DrainStop::Budget
        };
        report
    }

    fn pop(&mut self) {
        self.head = (self.head + 1) % self.ring.len();
        self.count -= 1;
    }
}

/// The record as one JSON object in the shared schema's field order. Everything written is a validated label, a
/// fixed word or a number, so nothing needs escaping.
fn write_record(w: &mut LineWriter<'_>, c: &LogConfig, ts: u64, r: &Record<'_>) -> fmt::Result {
    write!(
        w,
        r#"{{"schema_version":"{LOG_SCHEMA}","timestamp_mono_ns":{ts},"run_id":"{}","case_id":"{}","correlation_id":"{}#{}","member_id":"{}","group_id":"{}","source_epoch":{},"state_revision":{},"event_kind":"{}","message":"{}","queue_depth":{},"latency_us":{}"#,
        c.run_id,
        c.case_id,
        c.member_id,
        r.n,
        c.member_id,
        c.group_id,
        r.epoch,
        r.revision,
        r.kind,
        r.message,
        r.queue,
        r.latency_us,
    )?;
    if let Some(fault) = &c.fault {
        write!(w, r#","fault":"{fault}""#)?;
    }
    if let Some(cause) = r.cause {
        write!(w, r#","cause":"{cause}""#)?;
    }
    w.write_str("}")
}

/// `none` or the number.
struct OptionalNs(Option<u64>);

impl Display for OptionalNs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(v) => write!(f, "{v}"),
            None => f.write_str("none"),
        }
    }
}

struct DecisionText<'a>(&'a Decision);

impl Display for DecisionText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = self.0;
        write!(
            f,
            "block={} frames={} presentation_ns={} gap_before_ns={} submit_deadline_ns={} late_by_ns={}",
            d.block,
            d.frames,
            d.presentation_ns,
            d.gap_before_ns,
            d.submit_deadline_ns,
            d.late_by_ns
        )?;
        if let Outcome::Concealed { run } = d.outcome {
            write!(f, " run={run}")?;
        }
        Ok(())
    }
}

/// Why a decision was not a real block, in a fixed vocabulary.
const fn decision_cause(outcome: Outcome) -> Option<&'static str> {
    match outcome {
        Outcome::Real => None,
        Outcome::Concealed { .. } => Some("no_block_by_cutoff"),
        Outcome::MutedGap => Some("gap_longer_than_conceal_maximum"),
        Outcome::MutedNoHistory => Some("nothing_played_yet"),
        Outcome::MutedOverdue => Some("decided_at_or_after_presentation"),
        Outcome::Skipped => Some("latency_decrease"),
    }
}

impl LogConfig {
    /// Configuration text is inline, so construction, fault replacement and cloning retain no heap.
    /// Its storage is already counted by `size_of::<PlayoutEngine>()` when diagnostics are installed.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        0
    }
}

impl PlayoutEngine {
    /// Turn diagnostics on (or restart them with a new configuration). This is the only point that allocates for
    /// the log: `capacity` lines of [`MAX_LINE_BYTES`] each. Records start flowing with the next call.
    pub fn enable_log(&mut self, cfg: LogConfig) {
        self.diag = Some(DiagLog::new(cfg));
    }

    /// Bytes of the ring [`PlayoutEngine::enable_log`] allocates for `cfg`: `capacity` lines of `size_of::<Line>()` each (the
    /// [`MAX_LINE_BYTES`] of text and a length), by checked multiplication; `None` if that does not fit a `usize`. The inline handle is
    /// already part of `size_of::<PlayoutEngine>()` and is not counted again.
    #[must_use]
    pub fn log_ring_bytes_for(cfg: &LogConfig) -> Option<usize> {
        cfg.capacity.checked_mul(core::mem::size_of::<Line>())
    }

    /// Bytes of the ring held now (0 with diagnostics off).
    #[must_use]
    pub fn log_ring_bytes(&self) -> usize {
        self.diag.as_ref().map_or(0, DiagLog::ring_bytes)
    }

    /// Heap bytes [`PlayoutEngine::enable_log`] holds for `cfg`: the ring ([`Self::log_ring_bytes_for`]); configuration text is inline.
    /// `None` on overflow.
    #[must_use]
    pub fn log_heap_bytes_for(cfg: &LogConfig) -> Option<usize> {
        Self::log_ring_bytes_for(cfg)?.checked_add(cfg.heap_bytes())
    }

    /// Heap bytes the diagnostics hold now (0 with diagnostics off): the ring as the allocator gave it.
    #[must_use]
    pub fn log_heap_bytes(&self) -> usize {
        self.diag.as_ref().map_or(0, DiagLog::heap_bytes)
    }

    /// [`PlayoutEngine::enable_log`] under a budget: `budget_bytes` is what the caller's ledger leaves for diagnostics heap. A restart holds
    /// the old log until the new one exists, so both rings count against it, and what the allocator
    /// actually kept for the new ring is charged before it is published. A refusal (over budget, or an allocator that cannot give the
    /// ring) leaves the log as it was, running, with its records.
    ///
    /// # Errors
    /// The new log (and the one it replaces) does not fit `budget_bytes`, or the allocator could not give the ring.
    pub fn enable_log_within(
        &mut self,
        cfg: LogConfig,
        budget_bytes: usize,
    ) -> Result<(), super::AdmitError> {
        let ring_bytes = Self::log_ring_bytes_for(&cfg);
        let needed =
            Self::log_heap_bytes_for(&cfg).and_then(|n| n.checked_add(self.log_heap_bytes()));
        if !matches!(needed, Some(n) if n <= budget_bytes) {
            return Err(super::AdmitError::Capacity(super::CapacityError {
                needed_bytes: needed.unwrap_or(usize::MAX),
                budget_bytes,
            }));
        }
        let Some(log) = DiagLog::try_new(cfg) else {
            return Err(super::AdmitError::Allocation(super::AllocationError {
                requested_bytes: ring_bytes.unwrap_or(usize::MAX),
            }));
        };
        let kept = log.heap_bytes().checked_add(self.log_heap_bytes());
        if !matches!(kept, Some(n) if n <= budget_bytes) {
            return Err(super::AdmitError::Capacity(super::CapacityError {
                needed_bytes: kept.unwrap_or(usize::MAX),
                budget_bytes,
            }));
        }
        self.diag = Some(log);
        Ok(())
    }

    /// The log's counts, or `None` if diagnostics are off.
    #[must_use]
    pub fn log_stats(&self) -> Option<LogStats> {
        self.diag.as_ref().map(DiagLog::stats)
    }

    /// Offer queued lines to `sink`, oldest first, at most `budget` offers. Call from outside the render loop. With
    /// diagnostics off, nothing is offered.
    pub fn drain_log(&mut self, sink: &mut dyn LogSink, budget: usize) -> DrainReport {
        match self.diag.as_mut() {
            Some(d) => d.drain(sink, budget),
            None => DrainReport {
                offered: 0,
                taken: 0,
                stop: DrainStop::Empty,
            },
        }
    }

    /// The engine's state after the call being recorded: bound epoch (0 if none), decided blocks, occupied slots.
    fn log_state(&self) -> (u64, u64, u32) {
        let queued = self.slots.iter().filter(|s| s.used).count();
        (
            self.epoch.unwrap_or(0),
            self.cursor,
            u32::try_from(queued).unwrap_or(u32::MAX),
        )
    }

    pub(super) fn log_start(
        &mut self,
        epoch: u64,
        anchor_frame: u64,
        anchor_ns: u64,
        result: Result<(), StartReject>,
    ) {
        if self.diag.is_none() {
            return;
        }
        let (src_epoch, revision, queue) = self.log_state();
        let (kind, cause) = match result {
            Ok(()) => ("n04.stream.started", None),
            Err(why) => ("n04.stream.refused", Some(why.code())),
        };
        if let Some(d) = self.diag.as_mut() {
            let ts = d.last_ts;
            d.emit(&Record {
                ts,
                n: anchor_frame / BLOCK_FRAMES,
                epoch: src_epoch,
                revision,
                queue,
                latency_us: 0,
                kind: format_args!("{kind}"),
                message: format_args!(
                    "epoch={epoch} anchor_frame={anchor_frame} anchor_ns={anchor_ns}"
                ),
                cause,
                critical: true,
            });
        }
    }

    /// A packet or repair that was not admitted.
    pub(super) fn log_arrival(
        &mut self,
        view: ClockView,
        repair: bool,
        (epoch, start_frame, frames): (u64, u64, u32),
        result: Admission,
    ) {
        if self.diag.is_none() || result == Admission::Admitted {
            return;
        }
        let block = start_frame / BLOCK_FRAMES;
        let late_us = if result == Admission::Late {
            view.group_ns
                .saturating_sub(self.cutoff_of(block, view.uncertainty_ns))
                / 1000
        } else {
            0
        };
        let (src_epoch, revision, queue) = self.log_state();
        let source = if repair { "repair" } else { "media" };
        if let Some(d) = self.diag.as_mut() {
            d.emit(&Record {
                ts: view.group_ns,
                n: block,
                epoch: src_epoch,
                revision,
                queue,
                latency_us: late_us,
                kind: format_args!("n04.refusal.{}", result.code()),
                message: format_args!(
                    "source={source} frame={start_frame} frames={frames} packet_epoch={epoch}"
                ),
                cause: None,
                critical: false,
            });
        }
    }

    /// A decision, or a poll that could not decide. `Pending` is neither and writes nothing.
    pub(super) fn log_poll(&mut self, view: ClockView, poll: &Poll) {
        if self.diag.is_none() || *poll == Poll::Pending {
            return;
        }
        let (src_epoch, revision, queue) = self.log_state();
        let cursor = self.cursor;
        let Some(d) = self.diag.as_mut() else {
            return;
        };
        match poll {
            Poll::Decision(dec) => d.emit(&Record {
                ts: view.group_ns,
                n: dec.block,
                epoch: src_epoch,
                revision,
                queue,
                latency_us: dec.late_by_ns / 1000,
                kind: format_args!("n04.decision.{}", dec.outcome.code()),
                message: format_args!("{}", DecisionText(dec)),
                cause: decision_cause(dec.outcome),
                critical: dec.outcome != Outcome::Real,
            }),
            other => {
                let name = match other {
                    Poll::ClockUnusable => "clock_unusable",
                    Poll::ClockRegression => "clock_regression",
                    _ => "not_bound",
                };
                d.emit(&Record {
                    ts: view.group_ns,
                    n: cursor,
                    epoch: src_epoch,
                    revision,
                    queue,
                    latency_us: 0,
                    kind: format_args!("n04.poll.{name}"),
                    message: format_args!("cursor={cursor}"),
                    cause: None,
                    critical: true,
                });
            }
        }
    }

    pub(super) fn log_change(&mut self, ch: &LatencyChange, result: Result<i64, ChangeReject>) {
        if self.diag.is_none() {
            return;
        }
        let (src_epoch, revision, queue) = self.log_state();
        let Some(d) = self.diag.as_mut() else {
            return;
        };
        let ts = d.last_ts;
        let n = ch.effective_frame / BLOCK_FRAMES;
        let (id, frame) = (ch.change_id, ch.effective_frame);
        match result {
            Ok(delta) => d.emit(&Record {
                ts,
                n,
                epoch: src_epoch,
                revision,
                queue,
                latency_us: 0,
                kind: format_args!("n04.change.accepted"),
                message: format_args!("change_id={id} effective_frame={frame} delta_ns={delta}"),
                cause: None,
                critical: true,
            }),
            Err(why) => d.emit(&Record {
                ts,
                n,
                epoch: src_epoch,
                revision,
                queue,
                latency_us: 0,
                kind: format_args!("n04.change.refused"),
                message: format_args!("change_id={id} effective_frame={frame}"),
                cause: Some(why.code()),
                critical: true,
            }),
        }
    }

    pub(super) fn log_delivery(
        &mut self,
        submit_deadline_ns: u64,
        accepted_at_ns: Option<u64>,
        result: Delivery,
    ) {
        if self.diag.is_none() {
            return;
        }
        let (src_epoch, revision, queue) = self.log_state();
        let n = self.cursor.saturating_sub(1);
        let Some(d) = self.diag.as_mut() else {
            return;
        };
        let (name, late_us, critical) = match (result, accepted_at_ns) {
            (Delivery::Delivered, _) => ("delivered", 0, false),
            (Delivery::Abandoned, Some(at)) => (
                "abandoned",
                at.saturating_sub(submit_deadline_ns) / 1000,
                true,
            ),
            (Delivery::Abandoned, None) => ("abandoned", 0, true),
        };
        let ts = accepted_at_ns.unwrap_or(d.last_ts);
        d.emit(&Record {
            ts,
            n,
            epoch: src_epoch,
            revision,
            queue,
            latency_us: late_us,
            kind: format_args!("n04.delivery.{name}"),
            message: format_args!(
                "submit_deadline_ns={submit_deadline_ns} accepted_at_ns={}",
                OptionalNs(accepted_at_ns)
            ),
            cause: None,
            critical,
        });
    }
}

#[cfg(test)]
mod tests;
