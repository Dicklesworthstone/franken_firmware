use franken_clock::events::EventBuffer;
use franken_clock::latency::events::{DiagnosticIds, EventOutcome, LatencyEventBuffer, to_jsonl};
use franken_clock::latency::{
    Context, DelayKind, Interval, LatencyError, LatencyTimeline, Observation, Provenance, Stage,
};
use franken_test_support::DiagnosticEvent;

const CONTEXT: Context = Context {
    clock_id: 7,
    epoch: 3,
    route_revision: 2,
    snapshot_id: 19,
};
const IDS: DiagnosticIds = DiagnosticIds {
    run_id: 1,
    case_id: 2,
    member_id: 3,
    group_id: 4,
};

fn timeline() -> LatencyTimeline {
    let mut timeline = LatencyTimeline::new(CONTEXT, 0, 1000, 10_000).unwrap();
    for (stage, start, end) in [(Stage::Ingress, 100, 200), (Stage::Output, 300, 500)] {
        timeline
            .record(
                stage,
                Observation {
                    context: CONTEXT,
                    interval: Interval::new(start, end).unwrap(),
                    uncertainty_ns: 10,
                    kind: DelayKind::Fixed,
                    provenance: Provenance::Measured,
                },
            )
            .unwrap();
    }
    timeline
}

#[test]
fn emitted_events_round_trip_through_shared_schema_on_control_side() {
    let timeline = timeline();
    let mut sink = LatencyEventBuffer::new(IDS, 10, 100);
    let expected = timeline.estimate(CONTEXT, 1000).unwrap();
    assert_eq!(sink.estimate(&timeline, CONTEXT, 1000).unwrap(), expected);
    assert_eq!(sink.estimate(&timeline, CONTEXT, 1001).unwrap(), expected);
    assert_eq!(sink.pending(), 2);
    for sequence in 1..=2 {
        let event = sink.pop().unwrap();
        assert_eq!(event.sequence, sequence);
        assert!(matches!(
            event.payload.outcome,
            EventOutcome::Estimated { .. }
        ));
        let line = to_jsonl(event).unwrap();
        println!("FFW_V01_EVENT {}", line.trim_end());
        assert!(line.ends_with('\n'));
        assert!(line.len() < 4096);
        let shared: DiagnosticEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(shared.schema_version, "ffw.log.v1");
        assert_eq!(shared.source_epoch, 3);
        assert_eq!(shared.queue_depth, sequence as usize - 1);
        assert_eq!(serde_json::to_string(&shared).unwrap(), line.trim_end());
    }
    assert!(sink.pop().is_none());
    assert!(sink.stats().loss_free());
    assert_eq!(sink.stats().delivered, 2);
}

#[test]
fn full_slow_and_unavailable_consumers_do_not_change_estimates() {
    let timeline = timeline();
    let mut healthy = LatencyEventBuffer::new(IDS, 1000, 1000);
    let mut slow = LatencyEventBuffer::new(IDS, 1000, 1000);
    let mut unavailable = LatencyEventBuffer::new(IDS, 1000, 1000);
    unavailable.set_available(false);
    for tick in 1000..1100 {
        let expected = timeline.estimate(CONTEXT, tick);
        assert_eq!(healthy.estimate(&timeline, CONTEXT, tick), expected);
        assert_eq!(slow.estimate(&timeline, CONTEXT, tick), expected);
        assert_eq!(unavailable.estimate(&timeline, CONTEXT, tick), expected);
        healthy.pop().unwrap();
        assert!(slow.pending() <= 8);
    }
    assert_eq!(slow.pending(), 8);
    assert_eq!(slow.stats().dropped_ordinary, 92);
    assert_eq!(unavailable.stats().unavailable_drops, 100);
    assert!(!slow.stats().loss_free());
    assert!(!unavailable.stats().loss_free());
    assert!(healthy.stats().loss_free());
    while slow.pop().is_some() {}
    assert_eq!(
        slow.stats().emitted,
        slow.stats().delivered + slow.stats().dropped_ordinary
    );
    unavailable.set_available(true);
    assert!(unavailable.estimate(&timeline, CONTEXT, 1100).is_ok());
    assert!(unavailable.pop().is_some());
}

#[test]
fn refusal_events_keep_cause_and_do_not_hide_missing_stages() {
    let timeline = LatencyTimeline::new(CONTEXT, 0, 1000, 100).unwrap();
    let mut sink = LatencyEventBuffer::new(IDS, 10, 100);
    let error = sink.estimate(&timeline, CONTEXT, 1000).unwrap_err();
    assert_eq!(
        error,
        LatencyError::MissingStages(Stage::Ingress.bit() | Stage::Output.bit())
    );
    let event = sink.pop().unwrap();
    assert!(matches!(
        event.payload.outcome,
        EventOutcome::Refused {
            code: "missing_stages",
            missing_mask: 129
        }
    ));
    let line = to_jsonl(event).unwrap();
    println!("FFW_V01_EVENT {}", line.trim_end());
    let shared: DiagnosticEvent = serde_json::from_str(&line).unwrap();
    assert_eq!(shared.cause.as_deref(), Some("missing_stages"));
    assert_eq!(shared.event_kind, "latency_refused");
}

#[test]
fn shared_buffer_rate_windows_wraparound_and_disabled_capacity() {
    let mut buffer = EventBuffer::<u32, 2>::new(2, 10);
    assert!(buffer.try_emit(100, 1));
    assert!(buffer.try_emit(101, 2));
    assert!(!buffer.try_emit(102, 3));
    assert_eq!(buffer.stats().rate_limited, 1);
    assert_eq!(buffer.pop().unwrap().payload, 1);
    assert_eq!(buffer.pop().unwrap().payload, 2);
    assert!(buffer.try_emit(110, 4));
    assert!(buffer.try_emit(111, 5));
    assert_eq!(buffer.pop().unwrap().sequence, 4);
    assert_eq!(buffer.pop().unwrap().sequence, 5);
    assert!(buffer.pop().is_none());
    let mut zero = EventBuffer::<u32, 0>::new(10, 10);
    assert!(!zero.try_emit(1, 5));
    assert_eq!(zero.stats().dropped_ordinary, 1);
    assert!(zero.pop().is_none());
    let mut zero_rate = EventBuffer::<u32, 2>::new(0, 10);
    assert!(!zero_rate.try_emit(1, 5));
    assert_eq!(zero_rate.stats().rate_limited, 1);
}

#[test]
fn clock_regression_is_counted_and_does_not_change_refusal() {
    let timeline = timeline();
    let mut sink = LatencyEventBuffer::new(IDS, 10, 100);
    assert!(sink.estimate(&timeline, CONTEXT, 1000).is_ok());
    assert_eq!(
        sink.estimate(&timeline, CONTEXT, 999),
        timeline.estimate(CONTEXT, 999)
    );
    assert_eq!(sink.stats().regression_drops, 1);
    assert_eq!(sink.pending(), 1);
    assert!(!sink.stats().loss_free());
}

#[test]
fn stale_route_error_survives_sink_loss_and_later_recovery() {
    let timeline = timeline();
    let mut sink = LatencyEventBuffer::new(IDS, 10, 100);
    sink.set_available(false);
    let next_route = Context {
        route_revision: 9,
        ..CONTEXT
    };
    assert_eq!(
        sink.estimate(&timeline, next_route, 1000),
        Err(LatencyError::ContextMismatch)
    );
    sink.set_available(true);
    assert_eq!(
        sink.estimate(&timeline, next_route, 1001),
        Err(LatencyError::ContextMismatch)
    );
    let event = sink.pop().unwrap();
    assert_eq!(event.sequence, 2);
    assert_eq!(event.counters_before.unavailable_drops, 1);
    assert!(matches!(
        event.payload.outcome,
        EventOutcome::Refused {
            code: "context_mismatch",
            ..
        }
    ));
}
