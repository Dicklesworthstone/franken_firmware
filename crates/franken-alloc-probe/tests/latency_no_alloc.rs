//! Real allocator instrumentation: render-side latency and event operations only.
use franken_alloc_probe::{CountingAllocator, is_active, measure};
use franken_clock::latency::events::{DiagnosticIds, LatencyEventBuffer, to_jsonl};
use franken_clock::latency::{
    Context, DelayKind, Interval, LatencyError, LatencyTimeline, Observation, Provenance, Stage,
};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator::new();

#[test]
fn latency_and_event_operations_do_not_allocate_but_control_serialization_does() {
    assert!(
        is_active(),
        "the counting allocator must detect a real allocation"
    );
    let context = Context {
        clock_id: 7,
        epoch: 3,
        route_revision: 2,
        snapshot_id: 19,
    };
    let mut timeline = LatencyTimeline::new(context, 0, 1000, 100_000).unwrap();
    for (stage, start, end) in [
        (Stage::Ingress, 100, 200),
        (Stage::Decode, 150, 300),
        (Stage::Output, 300, 500),
    ] {
        timeline
            .record(
                stage,
                Observation {
                    context,
                    interval: Interval::new(start, end).unwrap(),
                    uncertainty_ns: 10,
                    kind: DelayKind::Fixed,
                    provenance: Provenance::Measured,
                },
            )
            .unwrap();
    }
    let ids = DiagnosticIds {
        run_id: 1,
        case_id: 2,
        member_id: 3,
        group_id: 4,
    };
    let mut healthy = LatencyEventBuffer::new(ids, 1000, 1000);
    let mut full = LatencyEventBuffer::new(ids, 1000, 1000);
    let mut unavailable = LatencyEventBuffer::new(ids, 1000, 1000);
    unavailable.set_available(false);
    let mut rate_limited = LatencyEventBuffer::new(ids, 0, 1000);
    let (correct, delta) = measure(|| {
        let mut correct = true;
        for now in 1000..1100 {
            let expected = timeline.estimate(context, now);
            correct &= healthy.estimate(&timeline, context, now) == expected;
            correct &= full.estimate(&timeline, context, now) == expected;
            correct &= unavailable.estimate(&timeline, context, now) == expected;
            correct &= rate_limited.estimate(&timeline, context, now) == expected;
            correct &= healthy.pop().is_some();
        }
        let stale_route = Context {
            route_revision: 9,
            ..context
        };
        correct &=
            full.estimate(&timeline, stale_route, 1100) == Err(LatencyError::ContextMismatch);
        correct &= unavailable.estimate(&timeline, stale_route, 1100)
            == Err(LatencyError::ContextMismatch);
        correct
    });
    assert!(
        correct,
        "all sinks must preserve the numerical result and typed refusal"
    );
    assert!(
        delta.is_zero(),
        "render-side timeline or event operation allocated: {delta:?}"
    );
    assert_eq!(full.pending(), 8);
    assert_eq!(full.stats().dropped_ordinary, 92);
    assert_eq!(full.stats().evicted_ordinary, 1);
    assert_eq!(unavailable.stats().unavailable_drops, 101);
    assert_eq!(unavailable.stats().critical_lost, 1);
    assert_eq!(rate_limited.stats().rate_limited, 100);
    let popped = full.pop().unwrap();
    let (line, serialization) = measure(|| std::hint::black_box(to_jsonl(popped).unwrap()));
    assert!(line.contains("ffw.log.v1"));
    assert!(
        serialization.allocations > 0,
        "control-side serialization supplies the positive allocation control"
    );
}
