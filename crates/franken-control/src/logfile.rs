//! A bounded file sink for the control channel's diagnostics (N02 / `ffw-ugf`, section 11), and the only code in this crate
//! that touches a filesystem.
//!
//! The channel never writes a record anywhere: `submit`, `step` and `acknowledge` push a line into the bounded ring of
//! [`ChannelLog`](crate::channel::diag::ChannelLog) and return. Getting lines out is the owner's, in its diagnostic drain,
//! between those calls ([`ChannelLog::drain_to`](crate::channel::diag::ChannelLog::drain_to)). This module is what the
//! drain offers lines to when they are to end up in a file. It is deliberately outside `channel/`, whose sources are scanned
//! for any use of the filesystem, a clock, a lock or a thread.
//!
//! # What is written
//!
//! The lines the log holds, as they are, one per line (`ffw.log.v1`, no header and no schema of its own), and at the end of a
//! run one more of the same shape, `n02.log.summary`, whose message carries the log's counts and the sink's, so a reader
//! that has only the file can check them against the lines it holds. A file is created exclusively (never overwritten) and,
//! on Unix, readable by its owner only.
//!
//! # The bounds
//!
//! The file holds at most `max_file_bytes` bytes and `max_lines` lines. Ordinary lines may use all but a quarter of each;
//! critical ones (an internal fault, evidence a run cannot be trusted without) may use all of it, so a flood of ordinary
//! records cannot crowd out the evidence that matters, as in the ring. A line that would go past its bound is **dropped by
//! the sink and counted** (`dropped`, and `critical_dropped` for a critical one): a bound is permanent, so keeping the line
//! queued would only block the lines behind it. A line that is not one line (empty, over the ring's bound, or holding a
//! newline) is dropped and counted the same way. Disk is bounded by the cap, memory by the ring, and what the cap cost is
//! a number.
//!
//! # What the device does
//!
//! * A **short write** (a device that takes fewer bytes than offered) is continued until the whole line is written, and
//!   counted; a line is never left half written because the device was slow to take it.
//! * A **full** device (`ENOSPC`), a file over its size limit, a write that would block, or a timeout answers
//!   [`SinkReply::Full`]: the line stays queued in the ring and the drain stops; the next drain offers it again.
//! * Any other error (a broken pipe, a vanished directory, a permission change) answers [`SinkReply::Unavailable`], the same.
//! * A write that fails **after some of a line is written** leaves a fragment. The sink remembers it, counts it
//!   (`torn_fragments`), ends it with a newline before anything else is written, and the line, still queued, is written
//!   whole on a later offer. The fragment's bytes count against the cap, so the file never exceeds it.
//!
//! # Evidence
//!
//! A run is complete ([`FileSink::evidence_complete`]) only if no critical record was lost by the ring, none is still waiting
//! in it, and none was dropped by the sink. A sink that was down at the end of a run, a file that filled, or a ring that
//! overflowed with a critical record in it all make the result incomplete; none is reported as clean.
//!
//! # What this does not do
//!
//! * It never blocks the channel, because it is never on its paths: it is offered lines only by the owner's drain. A
//!   filesystem that blocks inside `write` blocks the drain, which the owner runs from its diagnostic task, not from the
//!   control or render deadline paths. How long a real disk takes is not modelled, and nothing here measures it.
//! * It does not rotate, compress, encrypt or sign. The summary line and the counts are integrity aids, not signatures.
//! * It does not limit the rate in time: the rate is `budget` lines per drain, at whatever rate the owner drains, and the
//!   totals are the caps.

use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::path::Path;

use crate::channel::diag::{ChannelLog, LineSink, MAX_LINE_BYTES, SinkCounts, SinkReply};

/// Ordinary lines may use all but `1 / RESERVE_DIVISOR` of the file's bytes and of its lines.
const RESERVE_DIVISOR: u64 = 4;
/// A write that is interrupted is tried again this many times before it counts as an error.
const MAX_INTERRUPTS: usize = 3;

/// A sink that cannot be configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FileSinkError {
    #[error("`{field}` must be at least 1")]
    Zero { field: &'static str },
}

/// How much a file may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSinkConfig {
    max_file_bytes: u64,
    max_lines: u64,
}

impl FileSinkConfig {
    /// `max_file_bytes` and `max_lines` must both be at least 1.
    pub const fn new(max_file_bytes: u64, max_lines: u64) -> Result<Self, FileSinkError> {
        if max_file_bytes == 0 {
            return Err(FileSinkError::Zero {
                field: "max_file_bytes",
            });
        }
        if max_lines == 0 {
            return Err(FileSinkError::Zero { field: "max_lines" });
        }
        Ok(Self {
            max_file_bytes,
            max_lines,
        })
    }

    #[must_use]
    pub const fn max_file_bytes(&self) -> u64 {
        self.max_file_bytes
    }

    #[must_use]
    pub const fn max_lines(&self) -> u64 {
        self.max_lines
    }
}

/// What the sink has done. Every offer ends as exactly one of: written, dropped (counted), or refused (the line stays
/// queued, to be offered again), so `offered == written_lines + dropped + refused_full + refused_unavailable`, where
/// `dropped` includes the lines that were not one line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileSinkStats {
    pub offered: u64,
    pub written_lines: u64,
    /// Bytes handed to the device, including any fragment of a line that failed part way.
    pub written_bytes: u64,
    /// Lines taken off the ring and not written: over a cap, or not one line.
    pub dropped: u64,
    /// Of those, the critical ones.
    pub critical_dropped: u64,
    /// Offers answered `Full` and `Unavailable`; the line stayed queued.
    pub refused_full: u64,
    pub refused_unavailable: u64,
    /// Writes that took fewer bytes than offered.
    pub short_writes: u64,
    /// Lines whose write failed after some of them was written.
    pub torn_fragments: u64,
}

/// How a run ended, from [`FileSink::finish`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finish {
    /// The closing record is in the file.
    pub summary_written: bool,
    /// The device accepted the final flush.
    pub flushed: bool,
    /// Every critical record is in the file and the closing record is too.
    pub evidence_complete: bool,
}

/// What one line came to.
enum Put {
    Written,
    Dropped,
    Refused(SinkReply),
}

/// A write that failed, and how far it got.
struct PutFailure {
    done: usize,
    kind: ErrorKind,
}

/// The sink. It writes to `W`: a `File` ([`FileSink::create`]), or anything else that takes bytes.
#[derive(Debug)]
pub struct FileSink<W: Write> {
    writer: W,
    config: FileSinkConfig,
    stats: FileSinkStats,
    /// A write failed part way through a line: the fragment must be ended before anything else is written.
    torn: bool,
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// What a failed write means to the drain: a device that is full or would block may take the line later, and any other
/// error is a sink that is down.
fn reply_for(kind: ErrorKind) -> SinkReply {
    match kind {
        ErrorKind::StorageFull
        | ErrorKind::FileTooLarge
        | ErrorKind::WouldBlock
        | ErrorKind::TimedOut => SinkReply::Full,
        _ => SinkReply::Unavailable,
    }
}

impl<W: Write> FileSink<W> {
    #[must_use]
    pub const fn new(writer: W, config: FileSinkConfig) -> Self {
        Self {
            writer,
            config,
            stats: FileSinkStats {
                offered: 0,
                written_lines: 0,
                written_bytes: 0,
                dropped: 0,
                critical_dropped: 0,
                refused_full: 0,
                refused_unavailable: 0,
                short_writes: 0,
                torn_fragments: 0,
            },
            torn: false,
        }
    }

    #[must_use]
    pub const fn stats(&self) -> FileSinkStats {
        self.stats
    }

    #[must_use]
    pub const fn config(&self) -> FileSinkConfig {
        self.config
    }

    #[must_use]
    pub const fn writer(&self) -> &W {
        &self.writer
    }

    pub fn writer_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    #[must_use]
    pub fn into_writer(self) -> W {
        self.writer
    }

    /// What the closing record says of this sink.
    #[must_use]
    pub const fn counts(&self) -> SinkCounts {
        SinkCounts {
            written: self.stats.written_lines,
            dropped: self.stats.dropped,
            critical_dropped: self.stats.critical_dropped,
        }
    }

    /// Whether the file holds every critical record the run produced: none lost by the ring, none still waiting in it,
    /// none dropped here. Meaningful at the end of a run, after a final drain.
    #[must_use]
    pub fn evidence_complete(&self, log: &ChannelLog) -> bool {
        log.is_evidence_complete()
            && log.stats().critical_held == 0
            && self.stats.critical_dropped == 0
    }

    /// Whether a line of `need` more bytes (and one more line) fits under the bound its kind of record has.
    fn room(&self, critical: bool, need: u64) -> bool {
        let reserve = |max: u64| if critical { 0 } else { max / RESERVE_DIVISOR };
        let bytes = self.config.max_file_bytes - reserve(self.config.max_file_bytes);
        let lines = self.config.max_lines - reserve(self.config.max_lines);
        self.stats.written_bytes.saturating_add(need) <= bytes && self.stats.written_lines < lines
    }

    /// Hand `buf` to the device, whole. A short write is continued and counted; an interrupted one is tried again a few
    /// times. Every byte the device takes counts against the cap, whatever happens after.
    fn put(&mut self, buf: &[u8]) -> Result<(), PutFailure> {
        let mut done = 0usize;
        let mut interrupts = 0usize;
        while done < buf.len() {
            match self.writer.write(&buf[done..]) {
                Ok(0) => {
                    return Err(PutFailure {
                        done,
                        kind: ErrorKind::WriteZero,
                    });
                }
                Ok(n) => {
                    let n = n.min(buf.len() - done);
                    if n < buf.len() - done {
                        self.stats.short_writes = self.stats.short_writes.saturating_add(1);
                    }
                    done += n;
                    self.stats.written_bytes = self.stats.written_bytes.saturating_add(len_u64(n));
                }
                Err(error)
                    if error.kind() == ErrorKind::Interrupted && interrupts < MAX_INTERRUPTS =>
                {
                    interrupts += 1;
                }
                Err(error) => {
                    return Err(PutFailure {
                        done,
                        kind: error.kind(),
                    });
                }
            }
        }
        Ok(())
    }

    fn refuse(&mut self, reply: SinkReply) -> Put {
        match reply {
            SinkReply::Full => self.stats.refused_full = self.stats.refused_full.saturating_add(1),
            SinkReply::Unavailable | SinkReply::Taken => {
                self.stats.refused_unavailable = self.stats.refused_unavailable.saturating_add(1);
            }
        }
        Put::Refused(reply)
    }

    fn drop_line(&mut self, critical: bool) -> Put {
        self.stats.dropped = self.stats.dropped.saturating_add(1);
        if critical {
            self.stats.critical_dropped = self.stats.critical_dropped.saturating_add(1);
        }
        Put::Dropped
    }

    /// One line: written, dropped over a bound, or refused (it stays queued).
    fn write_line(&mut self, line: &str, critical: bool) -> Put {
        self.stats.offered = self.stats.offered.saturating_add(1);
        let one_line = !line.is_empty()
            && line.len() <= MAX_LINE_BYTES
            && !line.bytes().any(|b| b == b'\n' || b == b'\r');
        if !one_line {
            return self.drop_line(critical);
        }
        let need = len_u64(line.len()) + 1 + u64::from(self.torn);
        if !self.room(critical, need) {
            return self.drop_line(critical);
        }
        if self.torn {
            if let Err(failure) = self.put(b"\n") {
                return self.refuse(reply_for(failure.kind));
            }
            self.torn = false;
        }
        let mut buf = line.as_bytes().to_vec();
        buf.push(b'\n');
        match self.put(&buf) {
            Ok(()) => {
                self.stats.written_lines = self.stats.written_lines.saturating_add(1);
                Put::Written
            }
            Err(failure) => {
                if failure.done > 0 {
                    self.torn = true;
                    self.stats.torn_fragments = self.stats.torn_fragments.saturating_add(1);
                }
                self.refuse(reply_for(failure.kind))
            }
        }
    }

    /// End a run: write the closing record (into the reserved part of the file if the rest is used) and flush the device.
    /// `now_ns` is on the log's timebase.
    pub fn finish(&mut self, log: &ChannelLog, now_ns: u64) -> Finish {
        let summary_written = log
            .closing_line(&self.counts(), now_ns)
            .is_some_and(|line| matches!(self.write_line(&line, true), Put::Written));
        let flushed = self.writer.flush().is_ok();
        Finish {
            summary_written,
            flushed,
            evidence_complete: summary_written && flushed && self.evidence_complete(log),
        }
    }
}

impl FileSink<File> {
    /// Create `path` for this sink: it must not exist (a file is never overwritten), and on Unix only its owner may read it.
    pub fn create(path: &Path, config: FileSinkConfig) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        Ok(Self::new(options.open(path)?, config))
    }
}

impl<W: Write> LineSink for FileSink<W> {
    fn offer(&mut self, line: &str, critical: bool) -> SinkReply {
        match self.write_line(line, critical) {
            Put::Written | Put::Dropped => SinkReply::Taken,
            Put::Refused(reply) => reply,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use franken_session::{
        AuthorityToken, FencedControlCommand, GroupCommandPayload, UnifiedGroupSession,
    };
    use franken_test_support::{DiagnosticEvent, redact_sensitive_text};

    use super::*;
    use crate::channel::diag::{DrainStop, LogConfig, LogKey};
    use crate::channel::limiter::RateLimit;
    use crate::channel::peer::ephemeral::{EphemeralPeers, test_key};
    use crate::channel::peer::{PeerId, PeerRole, compute_proof};
    use crate::channel::pipeline::{ChannelConfig, ChannelStats, ControlChannel};
    use crate::channel::request::{
        AckBody, AckRequest, ControlCommand, ControlRequest, RequestBody,
    };
    use crate::channel::testkit::fixture_session;

    const EPOCH: u64 = 10;
    const MS: u64 = 1_000_000;

    // ------------------------------------------------------------------------------------------ devices

    /// A directory under the system temporary directory that is removed when it goes out of scope.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "ffw-n02-sink-{}-{}-{}",
                std::process::id(),
                tag,
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&dir).expect("a temporary directory");
            Self(dir)
        }

        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A device that misbehaves as scripted, and keeps what it accepted.
    #[derive(Debug, Default)]
    struct Flaky {
        data: Vec<u8>,
        /// Accept at most this many bytes per write call.
        per_call: Option<usize>,
        /// Accept this many more bytes in all, then fail with `fail`.
        budget: Option<usize>,
        fail: Option<ErrorKind>,
        /// The first this many writes answer `WouldBlock`.
        blocked: usize,
        /// Every write fails as a broken pipe.
        down: bool,
    }

    impl Write for Flaky {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.down {
                return Err(ErrorKind::BrokenPipe.into());
            }
            if self.blocked > 0 {
                self.blocked -= 1;
                return Err(ErrorKind::WouldBlock.into());
            }
            let mut take = buf.len();
            if let Some(k) = self.per_call {
                take = take.min(k);
            }
            if let Some(left) = self.budget {
                if left == 0 {
                    return Err(self.fail.unwrap_or(ErrorKind::StorageFull).into());
                }
                take = take.min(left);
                self.budget = Some(left - take);
            }
            self.data.extend_from_slice(&buf[..take]);
            Ok(take)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn config(bytes: u64, lines: u64) -> FileSinkConfig {
        FileSinkConfig::new(bytes, lines).unwrap()
    }

    fn sink(flaky: Flaky, bytes: u64, lines: u64) -> FileSink<Flaky> {
        FileSink::new(flaky, config(bytes, lines))
    }

    fn text(sink: &FileSink<Flaky>) -> String {
        String::from_utf8(sink.writer().data.clone()).expect("the file is text")
    }

    /// A little line of known length: `{"n":0007}` is ten bytes, eleven with its newline.
    fn line(n: usize) -> String {
        format!("{{\"n\":{n:04}}}")
    }

    // ----------------------------------------------------------------------------------------- the sink

    #[test]
    fn a_zero_bound_is_refused_and_a_valid_one_is_kept() {
        assert_eq!(
            FileSinkConfig::new(0, 5),
            Err(FileSinkError::Zero {
                field: "max_file_bytes"
            })
        );
        assert_eq!(
            FileSinkConfig::new(5, 0),
            Err(FileSinkError::Zero { field: "max_lines" })
        );
        let c = config(100, 7);
        assert_eq!((c.max_file_bytes(), c.max_lines()), (100, 7));
    }

    #[test]
    fn lines_are_written_whole_one_per_line_and_counted() {
        let mut s = sink(Flaky::default(), 1_000, 100);
        for n in 0..3 {
            assert_eq!(s.offer(&line(n), false), SinkReply::Taken);
        }
        assert_eq!(text(&s), format!("{}\n{}\n{}\n", line(0), line(1), line(2)));
        let st = s.stats();
        assert_eq!(
            (st.offered, st.written_lines, st.written_bytes, st.dropped),
            (3, 3, 3 * 11, 0)
        );
        assert_eq!(s.counts().written, 3);
    }

    #[test]
    fn the_caps_hold_and_a_critical_line_may_use_the_reserved_quarter() {
        // Eleven bytes a line. A cap of 90 bytes: ordinary lines may use 68 (six lines), critical ones 90 (eight).
        let mut s = sink(Flaky::default(), 90, 1_000);
        for n in 0..8 {
            assert_eq!(s.offer(&line(n), false), SinkReply::Taken);
        }
        let st = s.stats();
        assert_eq!((st.written_lines, st.written_bytes), (6, 66));
        assert_eq!((st.dropped, st.critical_dropped), (2, 0));
        for n in 100..103 {
            assert_eq!(s.offer(&line(n), true), SinkReply::Taken);
        }
        let st = s.stats();
        // Two critical lines fit in the 24 bytes left; the third does not and is lost, counted as critical.
        assert_eq!((st.written_lines, st.written_bytes), (8, 88));
        assert_eq!((st.dropped, st.critical_dropped), (3, 1));
        assert!(s.writer().data.len() <= 90);
        assert!(
            !s.evidence_complete(&empty_log()),
            "a critical line was dropped"
        );
        // The same for the line cap: 8 lines, ordinary may use 6.
        let mut s = sink(Flaky::default(), 10_000, 8);
        for n in 0..10 {
            s.offer(&line(n), false);
        }
        for n in 100..110 {
            s.offer(&line(n), true);
        }
        let st = s.stats();
        assert_eq!(st.written_lines, 8, "never more lines than the cap");
        assert_eq!((st.dropped, st.critical_dropped), (12, 8));
        let accounted = st.written_lines + st.dropped + st.refused_full + st.refused_unavailable;
        assert_eq!(st.offered, accounted);
    }

    fn empty_log() -> ChannelLog {
        ChannelLog::new(
            LogConfig::new("run-1", "case-1", 8, 8_192).unwrap(),
            LogKey::new([7; 32]),
        )
    }

    #[test]
    fn a_line_that_is_not_one_line_is_dropped_and_counted_and_a_critical_one_makes_the_evidence_incomplete()
     {
        let mut s = sink(Flaky::default(), 10_000, 100);
        let long = "x".repeat(MAX_LINE_BYTES + 1);
        for bad in ["", "two\nlines", "carriage\rreturn", long.as_str()] {
            assert_eq!(s.offer(bad, false), SinkReply::Taken);
        }
        let st = s.stats();
        assert_eq!((st.written_lines, st.written_bytes, st.dropped), (0, 0, 4));
        assert_eq!(st.critical_dropped, 0);
        assert!(text(&s).is_empty(), "nothing malformed reached the file");
        assert!(s.evidence_complete(&empty_log()));
        assert_eq!(s.offer("critical\nbroken", true), SinkReply::Taken);
        assert_eq!(s.stats().critical_dropped, 1);
        assert!(!s.evidence_complete(&empty_log()));
        // A line of exactly the bound is one line.
        let exact = "y".repeat(MAX_LINE_BYTES);
        assert_eq!(s.offer(&exact, false), SinkReply::Taken);
        assert_eq!(s.stats().written_lines, 1);
    }

    #[test]
    fn a_short_writing_device_gets_whole_lines_and_every_short_write_is_counted() {
        let flaky = Flaky {
            per_call: Some(3),
            ..Flaky::default()
        };
        let mut s = sink(flaky, 10_000, 100);
        for n in 0..4 {
            assert_eq!(s.offer(&line(n), false), SinkReply::Taken);
        }
        let want: String = (0..4).map(|n| format!("{}\n", line(n))).collect();
        assert_eq!(text(&s), want, "the file is exactly the lines, whole");
        // Eleven bytes a line in writes of three, three, three and two: three short writes and a last one that finishes it.
        assert_eq!(s.stats().short_writes, 4 * 3);
        assert_eq!(s.stats().written_bytes, 4 * 11);
    }

    #[test]
    fn a_full_device_refuses_cleanly_keeps_the_line_for_later_and_loses_nothing() {
        let flaky = Flaky {
            budget: Some(0),
            fail: Some(ErrorKind::StorageFull),
            ..Flaky::default()
        };
        let mut s = sink(flaky, 10_000, 100);
        assert_eq!(s.offer(&line(1), false), SinkReply::Full);
        assert_eq!(s.offer(&line(1), true), SinkReply::Full);
        let st = s.stats();
        assert_eq!(
            (
                st.refused_full,
                st.written_lines,
                st.written_bytes,
                st.torn_fragments
            ),
            (2, 0, 0, 0)
        );
        // Space comes back: the same line is taken, and nothing was written for the refusals.
        s.writer_mut().budget = None;
        assert_eq!(s.offer(&line(1), false), SinkReply::Taken);
        assert_eq!(text(&s), format!("{}\n", line(1)));
    }

    #[test]
    fn a_write_that_fails_midway_leaves_a_fragment_that_is_ended_and_the_line_is_written_whole_later()
     {
        // Room for 5 bytes of the 11: the device takes them, then reports a full disk.
        let flaky = Flaky {
            budget: Some(5),
            fail: Some(ErrorKind::StorageFull),
            ..Flaky::default()
        };
        let mut s = sink(flaky, 10_000, 100);
        assert_eq!(s.offer(&line(7), false), SinkReply::Full);
        let st = s.stats();
        assert_eq!(
            (st.torn_fragments, st.written_lines, st.written_bytes),
            (1, 0, 5)
        );
        // Still full: the terminator cannot be written, and the answer is the same.
        assert_eq!(s.offer(&line(7), false), SinkReply::Full);
        assert_eq!(
            s.stats().torn_fragments,
            1,
            "one fragment, however often it is refused"
        );
        s.writer_mut().budget = None;
        assert_eq!(s.offer(&line(7), false), SinkReply::Taken);
        assert_eq!(text(&s), format!("{{\"n\":\n{}\n", line(7)));
        let st = s.stats();
        assert_eq!((st.written_lines, st.torn_fragments), (1, 1));
        assert_eq!(
            st.written_bytes,
            5 + 1 + 11,
            "the fragment and its end count against the cap"
        );
        assert_eq!(st.written_bytes as usize, s.writer().data.len());
    }

    #[test]
    fn an_unavailable_device_is_reported_and_recovers_and_a_device_that_would_block_is_full() {
        let mut s = sink(
            Flaky {
                down: true,
                ..Flaky::default()
            },
            10_000,
            100,
        );
        assert_eq!(s.offer(&line(1), false), SinkReply::Unavailable);
        assert_eq!(s.stats().refused_unavailable, 1);
        s.writer_mut().down = false;
        // A slow device: the first two writes would block. Each is `Full`, the line stays queued, nothing is lost.
        s.writer_mut().blocked = 2;
        assert_eq!(s.offer(&line(1), false), SinkReply::Full);
        assert_eq!(s.offer(&line(1), false), SinkReply::Full);
        assert_eq!(s.offer(&line(1), false), SinkReply::Taken);
        let st = s.stats();
        assert_eq!(
            (
                st.refused_unavailable,
                st.refused_full,
                st.written_lines,
                st.torn_fragments
            ),
            (1, 2, 1, 0)
        );
        assert_eq!(text(&s), format!("{}\n", line(1)));
        let accounted = st.written_lines + st.dropped + st.refused_full + st.refused_unavailable;
        assert_eq!(st.offered, accounted);
    }

    // ------------------------------------------------------------------------------------ real files

    #[test]
    fn a_file_is_created_exclusively_and_a_missing_directory_is_reported() {
        let dir = TempDir::new("create");
        let path = dir.file("n02.jsonl");
        let first = FileSink::create(&path, config(1_000, 10)).expect("a new file");
        drop(first);
        let again = FileSink::create(&path, config(1_000, 10));
        assert_eq!(
            again.err().map(|e| e.kind()),
            Some(ErrorKind::AlreadyExists),
            "a file is never overwritten"
        );
        let nowhere = dir.file("missing").join("n02.jsonl");
        assert_eq!(
            FileSink::create(&nowhere, config(1_000, 10))
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::NotFound)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o077,
                0,
                "only the owner may read the file: {mode:o}"
            );
        }
    }

    /// `/dev/full` is a real device that fails every write with `ENOSPC`.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_real_full_device_answers_full_and_loses_nothing() {
        let device = OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("/dev/full exists on Linux");
        let mut s = FileSink::new(device, config(1_000, 10));
        assert_eq!(s.offer(&line(1), false), SinkReply::Full);
        assert_eq!(s.offer(&line(2), true), SinkReply::Full);
        let st = s.stats();
        assert_eq!(
            (
                st.refused_full,
                st.refused_unavailable,
                st.written_lines,
                st.torn_fragments
            ),
            (2, 0, 0, 0)
        );
        assert_eq!(
            s.stats().critical_dropped,
            0,
            "a refused line is still queued, not lost"
        );
    }

    // ------------------------------------------------------------------------------ through a channel

    struct Rig {
        channel: ControlChannel<EphemeralPeers>,
        session: UnifiedGroupSession,
    }

    fn id(raw: &str) -> PeerId {
        PeerId::parse(raw).unwrap()
    }

    fn set_group(volume: u8) -> ControlCommand {
        ControlCommand::SetGroupVolume { volume }
    }

    fn rig(records: usize, bytes: usize) -> Rig {
        let mut peers = EphemeralPeers::new();
        for (name, role, bound) in [
            ("ctl-a", PeerRole::Controller, Some(EPOCH)),
            ("panel", PeerRole::LocalUser, None),
        ] {
            peers
                .admit(&id(name), role, &test_key(name), bound, 1)
                .unwrap();
        }
        let session = fixture_session(EPOCH);
        let mut config = ChannelConfig::provisional();
        config.ordinary_rate = RateLimit::new(100_000, MS).unwrap();
        config.priority_rate = RateLimit::new(100_000, MS).unwrap();
        config.session_seq_base = 1_000;
        let mut channel = ControlChannel::new(peers, config).unwrap();
        let token = AuthorityToken::issue(&session, 100_000 * MS);
        channel.install_lease(&session, token, 0).unwrap();
        channel.enable_log(ChannelLog::new(
            LogConfig::new("run-1", "case-1", records, bytes).unwrap(),
            LogKey::new([7; 32]),
        ));
        Rig { channel, session }
    }

    fn request(
        peer: &str,
        signer: &[u8],
        seq: u64,
        revision: Option<u64>,
        command: ControlCommand,
    ) -> ControlRequest {
        let body = RequestBody::new(id(peer), seq, EPOCH, revision, command).unwrap();
        let proof = compute_proof(signer, &body.signing_bytes());
        ControlRequest::new(body, proof)
    }

    /// Everything the outside world can see after one fixed schedule.
    #[derive(Debug, PartialEq)]
    struct Observed {
        results: Vec<String>,
        stats: ChannelStats,
        revision: u64,
    }

    /// Eight rounds, each a genuine command, a forged request, a duplicate, an acknowledgement of the round before and a
    /// step; in round four another caller of the session takes the number the channel would mint next, so that command
    /// faults (a critical record). After each round the owner drains with `drain`.
    fn schedule(rig: &mut Rig, mut drain: impl FnMut(&mut ChannelLog, u64)) -> Observed {
        let mut results = Vec::new();
        let mut now = 0u64;
        for round in 1..=8u64 {
            now += 10 * MS;
            if round == 4 {
                let next = 1_000 + rig.session.state_revision + 1;
                rig.session
                    .apply_command(FencedControlCommand {
                        epoch: EPOCH,
                        command_seq: next,
                        payload: GroupCommandPayload::MarkMemberClockLocked {
                            member_id: "kitchen".to_string(),
                        },
                    })
                    .unwrap();
            }
            let revision = Some(rig.session.state_revision);
            let volume = 40 + u8::try_from(round).unwrap();
            let genuine = request(
                "ctl-a",
                &test_key("ctl-a"),
                round,
                revision,
                set_group(volume),
            );
            let forged = request(
                "tok-9f3a1c77e0b2",
                b"not a key",
                round,
                revision,
                set_group(10),
            );
            results.push(format!("{:?}", rig.channel.submit(now, genuine.clone())));
            results.push(format!("{:?}", rig.channel.submit(now, forged)));
            results.push(format!("{:?}", rig.channel.submit(now, genuine)));
            results.push(format!("{:?}", rig.channel.step(now, &mut rig.session)));
            if round > 1 {
                let body = AckBody::new(id("ctl-a"), round - 1, EPOCH).unwrap();
                let proof = compute_proof(&test_key("ctl-a"), &body.signing_bytes());
                let ack = AckRequest::new(body, proof);
                results.push(format!(
                    "{:?}",
                    rig.channel.acknowledge(now, &rig.session, &ack)
                ));
            }
            if let Some(log) = rig.channel.log_mut() {
                drain(log, now);
            }
        }
        Observed {
            results,
            stats: *rig.channel.stats(),
            revision: rig.session.state_revision,
        }
    }

    /// Records the lines a sink took, and whether each was critical.
    struct Tee<'a, S: LineSink> {
        inner: &'a mut S,
        taken: Vec<(String, bool)>,
    }

    impl<S: LineSink> LineSink for Tee<'_, S> {
        fn offer(&mut self, line: &str, critical: bool) -> SinkReply {
            let reply = self.inner.offer(line, critical);
            if reply == SinkReply::Taken {
                self.taken.push((line.to_string(), critical));
            }
            reply
        }
    }

    const BUDGET: usize = 4;
    const RING: (usize, usize) = (12, 16_384);

    /// Drain until the ring is empty or the sink stops taking lines.
    fn drain_all(log: &mut ChannelLog, sink: &mut dyn LineSink) -> usize {
        let mut rounds = 0;
        loop {
            rounds += 1;
            let report = log.drain_to(sink, BUDGET);
            if report.stop != DrainStop::Budget || rounds > 1_000 {
                return rounds;
            }
        }
    }

    #[test]
    fn a_real_temporary_file_round_trips_the_channels_lines_byte_for_byte() {
        let dir = TempDir::new("round-trip");
        let path = dir.file("n02.jsonl");
        let mut file = FileSink::create(&path, config(65_536, 1_000)).expect("a new file");
        let mut rig = rig(64, 65_536);
        let mut tee = Tee {
            inner: &mut file,
            taken: Vec::new(),
        };
        schedule(&mut rig, |log, _| {
            log.drain_to(&mut tee, BUDGET);
        });
        let log = rig.channel.log_mut().unwrap();
        drain_all(log, &mut tee);
        let taken = tee.taken;
        let stats = log.stats();
        assert_eq!(
            (stats.stored, stats.dropped, stats.critical_held),
            (0, 0, 0)
        );
        assert_eq!(stats.drained, u64::try_from(taken.len()).unwrap());
        assert_eq!(
            stats.emitted,
            stats.stored as u64 + stats.dropped + stats.drained
        );
        assert_eq!(
            taken.iter().filter(|(_, critical)| *critical).count(),
            1,
            "setup: the schedule produces exactly one critical record"
        );
        let finish = file.finish(rig.channel.log().unwrap(), 9_000 * MS);
        assert_eq!(
            finish,
            Finish {
                summary_written: true,
                flushed: true,
                evidence_complete: true
            }
        );
        drop(file);

        // The file is the lines the log produced, whole and in order, and one closing record.
        let content = fs::read_to_string(&path).expect("the file reads back");
        assert!(content.ends_with('\n'));
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), taken.len() + 1);
        for (got, (want, _)) in lines.iter().zip(&taken) {
            assert_eq!(*got, want.as_str());
        }
        assert_eq!(
            u64::try_from(content.len()).unwrap(),
            lines
                .iter()
                .map(|l| u64::try_from(l.len()).unwrap() + 1)
                .sum::<u64>()
        );
        // Every line is an event of the shared schema (Q00's `DiagnosticEvent`), survives its redactor unchanged, and
        // re-serializes to the same bytes; the time never goes backwards.
        let mut last = 0u64;
        for l in &lines {
            let event: DiagnosticEvent = serde_json::from_str(l).expect("a valid ffw.log.v1 event");
            assert_eq!(event.schema_version, "ffw.log.v1");
            assert_eq!(serde_json::to_string(&event).unwrap(), *l);
            assert_eq!(redact_sensitive_text(l), *l);
            assert!(event.timestamp_mono_ns >= last, "timestamps go forward");
            last = event.timestamp_mono_ns;
        }
        // The closing record carries the counts, and they agree with the lines the file holds.
        let closing: DiagnosticEvent = serde_json::from_str(lines[lines.len() - 1]).unwrap();
        assert_eq!(closing.event_kind, "n02.log.summary");
        assert_eq!(closing.cause, None);
        assert_eq!(
            closing.message,
            format!(
                "emitted={n} stored=0 dropped=0 drained={n} written={n} sink_dropped=0 critical_lost=0 critical_held=0 critical_sink_dropped=0",
                n = taken.len()
            )
        );
    }

    #[test]
    fn the_same_schedule_gives_the_same_results_whatever_the_sink_does() {
        // No drain at all is the baseline: the log is full and nobody reads it.
        let baseline = schedule(&mut rig(RING.0, RING.1), |_, _| {});

        struct Case {
            name: &'static str,
            flaky: Flaky,
            bytes: u64,
            lines: u64,
            delivers: bool,
        }
        let cases = [
            Case {
                name: "a faithful device",
                flaky: Flaky::default(),
                bytes: 1 << 20,
                lines: 10_000,
                delivers: true,
            },
            Case {
                name: "a short-writing device",
                flaky: Flaky {
                    per_call: Some(7),
                    ..Flaky::default()
                },
                bytes: 1 << 20,
                lines: 10_000,
                delivers: true,
            },
            Case {
                name: "a full device",
                flaky: Flaky {
                    budget: Some(0),
                    ..Flaky::default()
                },
                bytes: 1 << 20,
                lines: 10_000,
                delivers: false,
            },
            Case {
                name: "a device that is down",
                flaky: Flaky {
                    down: true,
                    ..Flaky::default()
                },
                bytes: 1 << 20,
                lines: 10_000,
                delivers: false,
            },
            Case {
                name: "a device that always would block",
                flaky: Flaky {
                    blocked: usize::MAX,
                    ..Flaky::default()
                },
                bytes: 1 << 20,
                lines: 10_000,
                delivers: false,
            },
        ];
        for case in cases {
            let mut file = FileSink::new(case.flaky, config(case.bytes, case.lines));
            let mut rig = rig(RING.0, RING.1);
            let observed = schedule(&mut rig, |log, _| {
                log.drain_to(&mut file, BUDGET);
            });
            assert_eq!(observed, baseline, "{} changed a result", case.name);
            let log = rig.channel.log_mut().unwrap();
            drain_all(log, &mut file);
            let stats = log.stats();
            assert_eq!(
                stats.emitted,
                stats.stored as u64 + stats.dropped + stats.drained,
                "{}: every record is held, delivered or counted",
                case.name
            );
            assert!(
                stats.stored <= RING.0 && stats.bytes <= RING.1,
                "{}",
                case.name
            );
            let log = rig.channel.log().unwrap();
            let written_before = file.stats().written_lines;
            let finish = file.finish(log, 9_000 * MS);
            if case.delivers {
                assert_eq!(stats.stored, 0, "{}", case.name);
                assert_eq!(stats.drained, written_before, "{}", case.name);
                assert!(finish.evidence_complete, "{}: {finish:?}", case.name);
            } else {
                // Nothing reached the device, the ring held what it could and counted the rest, and the one critical
                // record is still waiting: the result is incomplete, and says so.
                assert_eq!(stats.drained, 0, "{}", case.name);
                assert_eq!(file.writer().data.len(), 0, "{}", case.name);
                assert!(stats.dropped > 0, "{}: the ring overflowed", case.name);
                assert_eq!(stats.critical_held, 1, "{}", case.name);
                assert!(!file.evidence_complete(log), "{}", case.name);
                assert!(!finish.evidence_complete, "{}", case.name);
                assert!(
                    !finish.summary_written,
                    "{}: the closing record cannot be written either",
                    case.name
                );
            }
        }
    }

    #[test]
    fn a_file_with_a_tiny_cap_drops_and_counts_and_never_grows_past_it_and_says_it_is_incomplete() {
        // Records are about three hundred bytes: a cap of 700 holds ordinary lines up to 525 (one) and critical ones up to 700.
        let baseline = schedule(&mut rig(64, 65_536), |_, _| {});
        let mut file = FileSink::new(Flaky::default(), config(700, 1_000));
        let mut rig = rig(64, 65_536);
        let observed = schedule(&mut rig, |log, _| {
            log.drain_to(&mut file, BUDGET);
        });
        assert_eq!(observed, baseline, "the cap changed a result");
        let log = rig.channel.log_mut().unwrap();
        drain_all(log, &mut file);
        let st = file.stats();
        assert!(
            st.written_bytes <= 700,
            "the file never grows past its cap: {}",
            st.written_bytes
        );
        assert_eq!(file.writer().data.len() as u64, st.written_bytes);
        assert!(st.dropped > 0, "what did not fit is counted");
        let stats = rig.channel.log().unwrap().stats();
        assert_eq!(
            stats.stored, 0,
            "a bound is permanent: nothing waits for room that will not come"
        );
        assert_eq!(
            stats.emitted,
            stats.stored as u64 + stats.dropped + stats.drained
        );
        assert_eq!(
            stats.drained, st.offered,
            "every offer took the line off the ring"
        );
        assert_eq!(st.offered, st.written_lines + st.dropped);
        // The critical record was offered once the ordinary ones had used their share: whether it fit decides the verdict,
        // and the verdict must agree with the counts.
        let finish = file.finish(rig.channel.log().unwrap(), 9_000 * MS);
        assert_eq!(
            finish.evidence_complete,
            finish.summary_written && st.critical_dropped == 0
        );
    }

    #[test]
    fn the_closing_record_goes_into_the_reserved_part_and_a_file_with_no_room_says_incomplete() {
        let mut roomy = FileSink::new(Flaky::default(), config(10_000, 100));
        let log = empty_log();
        let ok = roomy.finish(&log, 5);
        assert_eq!(
            ok,
            Finish {
                summary_written: true,
                flushed: true,
                evidence_complete: true
            }
        );
        let written = text(&roomy);
        let closing: DiagnosticEvent = serde_json::from_str(written.trim_end()).unwrap();
        assert_eq!(closing.event_kind, "n02.log.summary");
        assert_eq!(closing.timestamp_mono_ns, 5);
        // The ordinary lines have used their three quarters; the closing record (a few hundred bytes) still fits in the
        // last quarter of a file that is a few kilobytes.
        let mut tight = FileSink::new(Flaky::default(), config(4_000, 10_000));
        for n in 0..400 {
            tight.offer(&line(n), false);
        }
        assert_eq!(
            tight.stats().written_bytes,
            272 * 11,
            "the ordinary share is 3000 bytes"
        );
        assert!(tight.stats().dropped > 0);
        assert!(tight.finish(&empty_log(), 5).summary_written);
        assert!(tight.stats().written_bytes <= 4_000);
        // No room at all, even in the reserve: it is dropped, counted as critical, and the run is incomplete.
        let mut none = FileSink::new(Flaky::default(), config(10, 100));
        let end = none.finish(&log, 5);
        assert!(!end.summary_written && !end.evidence_complete);
        assert_eq!(
            (none.stats().dropped, none.stats().critical_dropped),
            (1, 1)
        );
        // A device that is down cannot take it either, and a failed flush is not a clean end.
        let mut down = FileSink::new(
            Flaky {
                down: true,
                ..Flaky::default()
            },
            config(10_000, 100),
        );
        assert!(!down.finish(&log, 5).evidence_complete);
    }

    #[test]
    fn a_critical_record_that_the_sink_keeps_refusing_is_reported_waiting_and_a_recovered_sink_completes_the_run()
     {
        let mut file = FileSink::new(
            Flaky {
                down: true,
                ..Flaky::default()
            },
            config(1 << 20, 10_000),
        );
        let mut rig = rig(RING.0, RING.1);
        schedule(&mut rig, |log, _| {
            log.drain_to(&mut file, BUDGET);
        });
        let log = rig.channel.log_mut().unwrap();
        assert_eq!(log.stats().critical_held, 1, "the fault record is waiting");
        assert!(!file.evidence_complete(log));
        // The device comes back: the whole queue, the critical record included, is written and the run is complete.
        file.writer_mut().down = false;
        drain_all(log, &mut file);
        assert_eq!(log.stats().critical_held, 0);
        assert!(file.evidence_complete(log));
        let log = rig.channel.log().unwrap();
        assert!(file.finish(log, 9_000 * MS).evidence_complete);
    }

    #[test]
    fn a_sink_is_offered_nothing_until_the_owner_drains() {
        struct Spy(usize);
        impl LineSink for Spy {
            fn offer(&mut self, _line: &str, _critical: bool) -> SinkReply {
                self.0 += 1;
                SinkReply::Taken
            }
        }
        let mut spy = Spy(0);
        let mut rig = rig(RING.0, RING.1);
        schedule(&mut rig, |_, _| {});
        assert_eq!(spy.0, 0, "submit, step and acknowledge never reach a sink");
        let queued = rig.channel.log().unwrap().stats().stored;
        assert!(queued > 0);
        let log = rig.channel.log_mut().unwrap();
        let report = log.drain_to(&mut spy, usize::MAX);
        assert_eq!((report.offered, report.taken), (queued, queued));
        assert_eq!(spy.0, queued);
        assert_eq!(report.stop, DrainStop::Empty);
    }
}
