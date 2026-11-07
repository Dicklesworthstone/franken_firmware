//! Unit tests of the diagnostics (contract section 15) that do not need the vectors: configuration, exact golden
//! lines assembled by hand, the shared `ffw.log.v1` shape, the line bound, and the summary. The judged runs over every
//! world and sink scenario are in `playout/tests.rs`.

use franken_test_support::{DiagnosticEvent, LOG_SCHEMA_VERSION, redact_sensitive_text};

use super::super::{
    BLOCK_PAYLOAD_BYTES, ClockView, MediaPacket, PlayoutConfig, PlayoutEngine, PlayoutProfile,
};
use super::*;

/// `ffw.pseudonym.v1` of "member-a" and "group-a" under the key `[7; 32]`, computed with Python's hashlib (the
/// reference's anchors recompute them independently): the engine is only ever given these, never the key.
const MEMBER: &str = "p-988345be66cccefe";
const GROUP: &str = "p-30a4eba9cf6f5462";

const CFG: PlayoutConfig = PlayoutConfig {
    work_ns: 1_500_000,
    lead_ns: 2_000_000,
    tolerance_ns: 100_000,
};

fn config(capacity: usize) -> LogConfig {
    LogConfig::new("n04-log", "unit", MEMBER, GROUP, capacity).expect("valid config")
}

fn bare_engine() -> PlayoutEngine {
    PlayoutEngine::new(PlayoutProfile::MUSIC, CFG).expect("valid engine config")
}

fn engine(capacity: usize) -> PlayoutEngine {
    let mut eng = bare_engine();
    eng.enable_log(config(capacity));
    eng
}

fn view(group_ns: u64) -> ClockView {
    ClockView {
        group_ns,
        uncertainty_ns: 200_000,
        usable: true,
    }
}

/// Keeps every line it is offered.
#[derive(Default)]
struct Collect(Vec<String>);

impl LogSink for Collect {
    fn offer(&mut self, line: &str) -> SinkReply {
        self.0.push(line.to_string());
        SinkReply::Taken
    }
}

fn lines_of(eng: &mut PlayoutEngine) -> Vec<String> {
    let mut sink = Collect::default();
    eng.drain_log(&mut sink, usize::MAX);
    sink.0
}

/// begin, one admitted packet (no line), a duplicate of it, then two decisions: the first block was never sent, the
/// second plays.
fn script(eng: &mut PlayoutEngine) {
    let payload = vec![0u8; 1024];
    let pkt = MediaPacket {
        epoch: 1,
        start_frame: 256,
        presentation_ns: 2_005_333_333,
        frames: 256,
        payload: &payload,
    };
    let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
    eng.begin_stream(1, 0, 2_000_000_000).unwrap();
    eng.on_packet(view(1_000_000_000), &pkt);
    eng.on_packet(view(1_000_000_500), &pkt);
    eng.decide(view(1_996_300_000), &mut out);
    eng.decide(view(2_001_633_333), &mut out);
}

/// A packet for block 0, read 5 700 000 ns after block 0's cutoff (1 996 300 000): refused as late.
fn late_packet(eng: &mut PlayoutEngine) {
    let payload = vec![0u8; 1024];
    let pkt = MediaPacket {
        epoch: 1,
        start_frame: 0,
        presentation_ns: 2_000_000_000,
        frames: 256,
        payload: &payload,
    };
    eng.on_packet(view(2_002_000_000), &pkt);
}

#[test]
fn n04_log_golden_lines_are_the_hand_assembled_ones() {
    // Hand-assembled from the contract: field order of the shared event; ids are the pseudonyms; the timestamp is the
    // group time of the call (the start line carries the previous record's, here 0); revision = blocks decided;
    // queue = occupied slots after the call; the muted block has no deliverable submit deadline.
    let want = [
        r#"{"schema_version":"ffw.log.v1","timestamp_mono_ns":0,"run_id":"n04-log","case_id":"unit","correlation_id":"p-988345be66cccefe#0","member_id":"p-988345be66cccefe","group_id":"p-30a4eba9cf6f5462","source_epoch":1,"state_revision":0,"event_kind":"n04.stream.started","message":"epoch=1 anchor_frame=0 anchor_ns=2000000000","queue_depth":0,"latency_us":0}"#,
        r#"{"schema_version":"ffw.log.v1","timestamp_mono_ns":1000000500,"run_id":"n04-log","case_id":"unit","correlation_id":"p-988345be66cccefe#1","member_id":"p-988345be66cccefe","group_id":"p-30a4eba9cf6f5462","source_epoch":1,"state_revision":0,"event_kind":"n04.refusal.duplicate","message":"source=media frame=256 frames=256 packet_epoch=1","queue_depth":1,"latency_us":0}"#,
        r#"{"schema_version":"ffw.log.v1","timestamp_mono_ns":1996300000,"run_id":"n04-log","case_id":"unit","correlation_id":"p-988345be66cccefe#0","member_id":"p-988345be66cccefe","group_id":"p-30a4eba9cf6f5462","source_epoch":1,"state_revision":1,"event_kind":"n04.decision.muted_nohistory","message":"block=0 frames=0 presentation_ns=2000000000 gap_before_ns=0 submit_deadline_ns=0 late_by_ns=0","queue_depth":1,"latency_us":0,"cause":"nothing_played_yet"}"#,
        r#"{"schema_version":"ffw.log.v1","timestamp_mono_ns":2001633333,"run_id":"n04-log","case_id":"unit","correlation_id":"p-988345be66cccefe#1","member_id":"p-988345be66cccefe","group_id":"p-30a4eba9cf6f5462","source_epoch":1,"state_revision":2,"event_kind":"n04.decision.real","message":"block=1 frames=256 presentation_ns=2005333333 gap_before_ns=0 submit_deadline_ns=2003333333 late_by_ns=0","queue_depth":0,"latency_us":0}"#,
        // 2_002_000_000 - 1_996_300_000 = 5_700_000 ns = 5700 us after the cutoff of block 0.
        r#"{"schema_version":"ffw.log.v1","timestamp_mono_ns":2002000000,"run_id":"n04-log","case_id":"unit","correlation_id":"p-988345be66cccefe#0","member_id":"p-988345be66cccefe","group_id":"p-30a4eba9cf6f5462","source_epoch":1,"state_revision":2,"event_kind":"n04.refusal.late","message":"source=media frame=0 frames=256 packet_epoch=1","queue_depth":0,"latency_us":5700}"#,
    ];
    let mut eng = engine(8);
    script(&mut eng);
    late_packet(&mut eng);
    let got = lines_of(&mut eng);
    assert_eq!(got.len(), want.len(), "{got:#?}");
    for (g, w) in got.iter().zip(want) {
        assert_eq!(g, w);
    }
    // The fault label, when named, is on every line, before the cause.
    let mut eng = bare_engine();
    eng.enable_log(config(8).with_fault("sink-stalled").unwrap());
    script(&mut eng);
    late_packet(&mut eng);
    let got = lines_of(&mut eng);
    assert_eq!(got.len(), 5);
    assert!(
        got[2].ends_with(r#""latency_us":0,"fault":"sink-stalled","cause":"nothing_played_yet"}"#),
        "{}",
        got[2]
    );
    assert!(
        got[0].ends_with(r#""latency_us":0,"fault":"sink-stalled"}"#),
        "{}",
        got[0]
    );
}

#[test]
fn n04_log_a_record_is_a_valid_ffw_log_v1_event_and_round_trips_byte_for_byte() {
    let mut eng = engine(8);
    script(&mut eng);
    let lines = lines_of(&mut eng);
    assert_eq!(lines.len(), 4);
    for line in &lines {
        let event: DiagnosticEvent = serde_json::from_str(line).expect("a shared-schema event");
        assert_eq!(event.schema_version, LOG_SCHEMA_VERSION);
        assert_eq!(event.schema_version, LOG_SCHEMA);
        assert_eq!(
            serde_json::to_string(&event).unwrap(),
            *line,
            "byte-identical round trip"
        );
        assert!(line.len() <= MAX_LINE_BYTES);
        assert!(line.is_ascii() && !line.contains('\n'));
        assert_eq!(
            redact_sensitive_text(line),
            *line,
            "nothing sensitive-looking in {line}"
        );
    }
}

#[test]
fn n04_log_the_member_and_group_appear_only_as_pseudonyms() {
    let mut eng = engine(8);
    script(&mut eng);
    for line in lines_of(&mut eng) {
        let event: DiagnosticEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(
            (event.member_id.as_str(), event.group_id.as_str()),
            (MEMBER, GROUP)
        );
        assert!(
            event.correlation_id.starts_with(&format!("{MEMBER}#")),
            "{line}"
        );
    }
    // A raw identifier cannot be given as one, however it is written.
    for raw in [
        "kitchen",
        "member-a",
        "p-",
        "p-988345be66cccef",
        "p-988345be66cccefe0",
        "p-988345BE66CCCEFE",
        "P-988345be66cccefe",
        "q-988345be66cccefe",
        "p-988345be66cccefg",
        " p-988345be66cccefe",
    ] {
        assert_eq!(
            LogConfig::new("run", "case", raw, GROUP, 1),
            Err(LogConfigError::NotAPseudonym { field: "member_id" }),
            "{raw:?}"
        );
        assert_eq!(
            LogConfig::new("run", "case", MEMBER, raw, 1),
            Err(LogConfigError::NotAPseudonym { field: "group_id" }),
            "{raw:?}"
        );
    }
}

#[test]
fn n04_log_timestamps_never_go_backwards() {
    let mut eng = engine(16);
    let payload = vec![0u8; 1024];
    let pkt = |frame: u64| MediaPacket {
        epoch: 1,
        start_frame: frame,
        presentation_ns: 2_000_000_000 + frame * 20_833,
        frames: 256,
        payload: &payload,
    };
    eng.begin_stream(1, 0, 2_000_000_000).unwrap();
    // Two refused packets, the second stamped by an earlier clock than the first (a clock regression): the log
    // stamps neither earlier than its predecessor.
    eng.on_packet(view(1_500_000_000), &pkt(0));
    eng.on_packet(view(1_500_000_000), &pkt(0));
    eng.on_packet(view(1_400_000_000), &pkt(256));
    eng.on_packet(view(1_450_000_000), &pkt(512));
    let lines = lines_of(&mut eng);
    let events: Vec<DiagnosticEvent> = lines
        .iter()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let stamps: Vec<u64> = events.iter().map(|e| e.timestamp_mono_ns).collect();
    assert!(stamps.windows(2).all(|w| w[0] <= w[1]), "{stamps:?}");
    // begin (0), the duplicate (1.5 s), then both regressions are refused at 1.4 s and 1.45 s but stamped 1.5 s.
    let kinds: Vec<&str> = events.iter().map(|e| e.event_kind.as_str()).collect();
    assert_eq!(
        kinds,
        [
            "n04.stream.started",
            "n04.refusal.duplicate",
            "n04.refusal.clock_regression",
            "n04.refusal.clock_regression"
        ],
        "{lines:#?}"
    );
    assert_eq!(stamps, [0, 1_500_000_000, 1_500_000_000, 1_500_000_000]);
}

#[test]
fn n04_log_no_peer_supplied_text_reaches_a_record() {
    // Everything a peer controls is a number or a byte string; bytes are never copied. Send payloads of recognisable
    // text through every path that logs, and look for them.
    let marker = b"SECRET-PAYLOAD-MARKER-0123456789";
    let mut payload = Vec::new();
    while payload.len() < 1024 {
        payload.extend_from_slice(marker);
    }
    payload.truncate(1024);
    let mut eng = engine(32);
    let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
    let pkt = |epoch: u64, frame: u64, frames: u32, len: usize| MediaPacket {
        epoch,
        start_frame: frame,
        presentation_ns: 2_000_000_000 + frame * 20_833,
        frames,
        payload: &payload[..len],
    };
    eng.on_packet(view(1), &pkt(1, 0, 256, 1024)); // not bound
    eng.begin_stream(1, 0, 2_000_000_000).unwrap();
    eng.on_packet(view(2), &pkt(0, 0, 256, 1024)); // stale epoch
    eng.on_packet(view(3), &pkt(1, 0, 256, 10)); // malformed
    eng.on_packet(view(4), &pkt(1, 0, 256, 1024)); // admitted
    eng.on_packet(view(5), &pkt(1, 0, 256, 1024)); // duplicate
    eng.decide(view(1_996_300_000), &mut out); // real (the payload is in `out`)
    eng.decide(view(2_001_633_333), &mut out); // concealed, from the payload
    let lines = lines_of(&mut eng);
    assert!(lines.len() >= 6, "{lines:#?}");
    for line in &lines {
        assert!(
            !line.contains("SECRET") && !line.contains("MARKER") && !line.contains("0123456789"),
            "{line}"
        );
        // The message is made only of lowercase words, digits, `_`, `-`, `=` and spaces.
        let event: DiagnosticEvent = serde_json::from_str(line).unwrap();
        assert!(
            event.message.bytes().all(|b| b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'_' | b'=' | b' ' | b'-')),
            "{}",
            event.message
        );
    }
}

#[test]
fn n04_log_an_over_long_line_is_dropped_whole_and_counted() {
    // Measure the lines first, then bound the log at every length around them: a line of exactly the bound is kept
    // whole, one byte over is dropped, never cut.
    let mut eng = engine(16);
    script(&mut eng);
    let full = lines_of(&mut eng);
    let lengths: Vec<usize> = full.iter().map(String::len).collect();
    assert_eq!(lengths.len(), 4);
    let mut bounds: Vec<usize> = lengths.iter().flat_map(|&n| [n - 1, n, n + 1]).collect();
    bounds.sort_unstable();
    bounds.dedup();
    for bound in bounds {
        let mut eng = bare_engine();
        eng.enable_log(config(16).with_max_line(bound).unwrap());
        script(&mut eng);
        let stats = eng.log_stats().unwrap();
        let kept = full.iter().filter(|l| l.len() <= bound).count() as u64;
        assert_eq!(stats.emitted, 4, "bound {bound}");
        assert_eq!(stats.dropped_oversize, 4 - kept, "bound {bound}");
        assert_eq!(stats.queued, kept, "bound {bound}");
        assert!(stats.accounted(), "bound {bound}: {stats}");
        let got = lines_of(&mut eng);
        let want: Vec<&String> = full.iter().filter(|l| l.len() <= bound).collect();
        assert_eq!(got.iter().collect::<Vec<_>>(), want, "bound {bound}");
        // The start and the muted decision are critical; the refusal and the real block are not.
        let critical_lost = [(0, true), (1, false), (2, true), (3, false)]
            .iter()
            .filter(|&&(i, critical)| critical && lengths[i] > bound)
            .count() as u64;
        assert_eq!(stats.critical_lost, critical_lost, "bound {bound}");
        assert_eq!(stats.evidence_complete(), critical_lost == 0);
    }
}

#[test]
fn n04_log_stats_summary_line() {
    let stats = LogStats {
        emitted: 10,
        delivered: 4,
        queued: 3,
        dropped_full: 2,
        dropped_oversize: 1,
        dropped_rate: 0,
        critical_lost: 0,
        offers: 6,
        sink_full_polls: 1,
        sink_unavailable_polls: 1,
    };
    assert!(stats.accounted());
    assert_eq!(
        stats.to_string(),
        "n04 log: emitted=10 delivered=4 queued=3 dropped=3 (full=2 oversize=1 rate=0) critical_lost=0 evidence=complete"
    );
    let lost = LogStats {
        critical_lost: 2,
        ..stats
    };
    assert!(!lost.evidence_complete());
    assert!(
        lost.to_string()
            .ends_with("critical_lost=2 evidence=INCOMPLETE")
    );
    assert!(
        !LogStats {
            delivered: 3,
            ..stats
        }
        .accounted(),
        "a missing record is visible"
    );
}

#[test]
fn n04_log_rate_is_bounded_before_formatting_with_refill_and_critical_reserve() {
    let mut bucket = RateBucket::full();
    for _ in 0..LogConfig::BURST_EVENTS_PER_CLASS {
        assert!(bucket.take(0), "the declared initial burst is permitted");
    }
    let mut rows = Vec::new();
    for ts in [0, 976_562, 976_563, 0, u64::MAX, 0] {
        rows.push(bucket.take(ts));
    }
    for _ in 0..LogConfig::BURST_EVENTS_PER_CLASS - 2 {
        assert!(
            bucket.take(0),
            "a backwards read can spend only existing credit"
        );
    }
    rows.push(bucket.take(0));
    assert_eq!(rows, [false, false, true, false, true, true, false]);

    fn record(critical: bool) -> Record<'static> {
        Record {
            ts: 0,
            n: 0,
            epoch: 1,
            revision: 0,
            queue: 0,
            latency_us: 0,
            kind: if critical {
                format_args!("n04.poll.clock_unusable")
            } else {
                format_args!("n04.refusal.bad_input")
            },
            message: format_args!("fixed"),
            cause: None,
            critical,
        }
    }
    struct MustNotFormat;
    impl Display for MustNotFormat {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("rate refusal must precede formatting")
        }
    }
    let guarded = MustNotFormat;
    let mut log = DiagLog::new(config(4));
    for _ in 0..LogConfig::BURST_EVENTS_PER_CLASS {
        log.emit(&record(false));
    }
    log.emit(&Record {
        kind: format_args!("{guarded}"),
        ..record(false)
    });
    log.emit(&record(true));
    let normal = log.stats();
    assert!(normal.accounted() && normal.evidence_complete());
    assert_eq!(
        (normal.queued, normal.dropped_rate, normal.critical_lost),
        (4, 1, 0)
    );
    for _ in 1..LogConfig::BURST_EVENTS_PER_CLASS {
        log.emit(&record(true));
    }
    log.emit(&Record {
        kind: format_args!("{guarded}"),
        ..record(true)
    });
    let saturated = log.stats();
    assert!(saturated.accounted() && !saturated.evidence_complete());
    assert_eq!(saturated.dropped_rate, 2);
    assert_eq!(saturated.critical_lost, LogConfig::BURST_EVENTS_PER_CLASS);
    let fields = |s: LogStats| {
        serde_json::json!({
            "emitted": s.emitted, "queued": s.queued, "dropped_full": s.dropped_full,
            "dropped_rate": s.dropped_rate, "critical_lost": s.critical_lost,
        })
    };
    println!(
        "N04-OBSERVED {}",
        serde_json::json!({
        "id": "n04-log-rate", "policy": LogConfig::RATE_POLICY_VERSION, "rate": LogConfig::EVENTS_PER_SECOND_PER_CLASS,
            "burst": LogConfig::BURST_EVENTS_PER_CLASS, "rows": rows,
            "normal": fields(normal), "saturated": fields(saturated),
        })
    );
    // The permitted critical record remains queued beside the ordinary reserve, in original order.
    let mut sink = Collect::default();
    assert_eq!(log.drain(&mut sink, 4).taken, 4);
    assert_eq!(sink.0.len(), 4);
}

#[test]
fn n04_log_config_validates_labels_pseudonyms_capacity_and_bound() {
    for ok in ["n04-log", "a", "0", "a.b_c-d"] {
        assert!(LogConfig::new(ok, "case", MEMBER, GROUP, 1).is_ok(), "{ok}");
        assert!(LogConfig::new("run", ok, MEMBER, GROUP, 1).is_ok(), "{ok}");
        assert!(config(1).with_fault(ok).is_ok(), "{ok}");
    }
    for bad in [
        "",
        "Run",
        "has space",
        "-lead",
        "a\"b",
        "line\nbreak",
        "é",
        &"x".repeat(65),
    ] {
        assert_eq!(
            LogConfig::new(bad, "case", MEMBER, GROUP, 1),
            Err(LogConfigError::InvalidLabel { field: "run_id" }),
            "{bad:?}"
        );
        assert_eq!(
            LogConfig::new("run", bad, MEMBER, GROUP, 1),
            Err(LogConfigError::InvalidLabel { field: "case_id" }),
            "{bad:?}"
        );
        assert_eq!(
            config(1).with_fault(bad),
            Err(LogConfigError::InvalidLabel { field: "fault" }),
            "{bad:?}"
        );
    }
    assert!(LogConfig::new(&"x".repeat(64), "case", MEMBER, GROUP, 1).is_ok());
    assert_eq!(
        LogConfig::new("run", "case", MEMBER, GROUP, 0),
        Err(LogConfigError::ZeroCapacity)
    );
    assert_eq!(config(1).with_max_line(0), Err(LogConfigError::BadMaxLine));
    assert_eq!(
        config(1).with_max_line(MAX_LINE_BYTES + 1),
        Err(LogConfigError::BadMaxLine)
    );
    assert!(config(1).with_max_line(MAX_LINE_BYTES).is_ok());
    assert!(config(1).with_max_line(1).is_ok());
    for (e, code) in [
        (LogConfigError::InvalidLabel { field: "x" }, "invalid_label"),
        (
            LogConfigError::NotAPseudonym { field: "x" },
            "not_a_pseudonym",
        ),
        (LogConfigError::ZeroCapacity, "zero_capacity"),
        (LogConfigError::BadMaxLine, "bad_max_line"),
    ] {
        assert_eq!(e.code(), code);
    }
}

#[test]
fn n04_log_off_means_nothing_is_offered() {
    let mut eng = bare_engine();
    script(&mut eng);
    assert_eq!(eng.log_stats(), None);
    let mut sink = Collect::default();
    let report = eng.drain_log(&mut sink, 100);
    assert_eq!(
        (report.offered, report.taken, report.stop),
        (0, 0, DrainStop::Empty)
    );
    assert!(sink.0.is_empty());
    // Turning it on later starts a fresh, empty log; it does not replay what was not recorded.
    eng.enable_log(config(4));
    assert_eq!(eng.log_stats().unwrap(), LogStats::default());
}
