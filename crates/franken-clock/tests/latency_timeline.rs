use franken_clock::latency::{
    ClockTransform, Context, DelayKind, Interval, LatencyError, LatencyTimeline, Observation,
    Provenance, Stage,
};

const CONTEXT: Context = Context {
    clock_id: 7,
    epoch: 3,
    route_revision: 2,
    snapshot_id: 19,
};
const STAGES: [Stage; 8] = [
    Stage::Ingress,
    Stage::Decode,
    Stage::Repair,
    Stage::Jitter,
    Stage::Resample,
    Stage::Dsp,
    Stage::Dma,
    Stage::Output,
];

fn observation(start: u64, end: u64, kind: DelayKind) -> Observation {
    Observation {
        context: CONTEXT,
        interval: Interval::new(start, end).unwrap(),
        uncertainty_ns: 0,
        kind,
        provenance: Provenance::Measured,
    }
}

fn timeline() -> LatencyTimeline {
    LatencyTimeline::new(CONTEXT, 0, 1_000, 100).unwrap()
}

fn trace(id: &str, details: serde_json::Value) {
    println!(
        "FFW_V01_CASE {}",
        serde_json::json!({
            "schema": "ffw.v01.case.v1", "case_id": id, "run_id": "v01-deterministic",
            "correlation_id": "snapshot-19", "timebase": "virtual_monotonic_ns",
            "monotonic_ns": 1000, "source_epoch": 3, "route_revision": 2,
            "evidence_class": "host_simulation", "dropped_events": 0, "details": details
        })
    );
}

#[test]
fn injected_delays_match_independent_expected_values() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/v01/delays.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let mut ledger = timeline();
        for (index, stage) in STAGES.into_iter().enumerate() {
            let interval = &case["intervals"][index];
            let kind = if index % 2 == 0 {
                DelayKind::Fixed
            } else {
                DelayKind::Variable
            };
            ledger
                .record(
                    stage,
                    observation(
                        interval[0].as_u64().unwrap(),
                        interval[1].as_u64().unwrap(),
                        kind,
                    ),
                )
                .unwrap();
        }
        let result = ledger.estimate(CONTEXT, 1_000).unwrap();
        assert_eq!(
            result.effective_ns,
            case["elapsed"].as_u64().unwrap(),
            "{}",
            case["id"]
        );
        assert_eq!(
            result.accounted_ns,
            case["union"].as_u64().unwrap(),
            "{}",
            case["id"]
        );
        assert_eq!(
            result.unaccounted_ns,
            result.effective_ns - result.accounted_ns
        );
        assert_eq!(
            result.fixed_only_ns + result.variable_only_ns + result.shared_ns,
            result.accounted_ns
        );
        trace(
            case["id"].as_str().unwrap(),
            serde_json::to_value(result).unwrap(),
        );
    }
}

#[test]
fn overlap_matches_discrete_occupancy_for_every_small_interval_pair() {
    let mut checked = 0;
    for a in 0..=5 {
        for b in a..=5 {
            for c in 0..=5 {
                for d in c..=5 {
                    let mut ledger = timeline();
                    ledger
                        .record(Stage::Ingress, observation(0, 0, DelayKind::Fixed))
                        .unwrap();
                    ledger
                        .record(Stage::Output, observation(5, 5, DelayKind::Fixed))
                        .unwrap();
                    ledger
                        .record(Stage::Decode, observation(a, b, DelayKind::Fixed))
                        .unwrap();
                    ledger
                        .record(Stage::Jitter, observation(c, d, DelayKind::Variable))
                        .unwrap();
                    let expected = (0..5)
                        .filter(|&t| (a <= t && t < b) || (c <= t && t < d))
                        .count() as u64;
                    let result = ledger.estimate(CONTEXT, 1_000).unwrap();
                    assert_eq!(result.accounted_ns, expected, "{a}..{b}, {c}..{d}");
                    let shared = (0..5)
                        .filter(|&t| a <= t && t < b && c <= t && t < d)
                        .count() as u64;
                    assert_eq!(result.shared_ns, shared);
                    checked += 1;
                }
            }
        }
    }
    assert_eq!(checked, 441);
    trace("V01-OCCUPANCY", serde_json::json!({"pairs": checked}));
}

#[test]
fn order_and_queue_replacement_do_not_accumulate_latency() {
    let mut forward = timeline();
    let mut reverse = timeline();
    for (i, stage) in STAGES.into_iter().enumerate() {
        forward
            .record(
                stage,
                observation(i as u64 * 10, i as u64 * 10 + 10, DelayKind::Variable),
            )
            .unwrap();
    }
    for (i, stage) in STAGES.into_iter().enumerate().rev() {
        reverse
            .record(
                stage,
                observation(i as u64 * 10, i as u64 * 10 + 10, DelayKind::Variable),
            )
            .unwrap();
    }
    assert_eq!(
        forward.estimate(CONTEXT, 1_000),
        reverse.estimate(CONTEXT, 1_000)
    );
    forward
        .record(Stage::Jitter, observation(31, 35, DelayKind::Variable))
        .unwrap();
    let result = forward.estimate(CONTEXT, 1_000).unwrap();
    assert_eq!(result.effective_ns, 80);
    assert_eq!(result.accounted_ns, 74);
    assert_eq!(result.unaccounted_ns, 6);
    trace("V01-REPLACE", serde_json::to_value(result).unwrap());
}

#[test]
fn missing_unknown_and_stale_route_never_report_exact_latency() {
    let mut ledger = LatencyTimeline::new(CONTEXT, Stage::Dma.bit(), 1_000, 100).unwrap();
    assert!(matches!(
        ledger.estimate(CONTEXT, 1_000),
        Err(LatencyError::MissingStages(_))
    ));
    for stage in [Stage::Ingress, Stage::Dma, Stage::Output] {
        ledger
            .record(stage, observation(10, 20, DelayKind::Variable))
            .unwrap();
    }
    assert!(ledger.estimate(CONTEXT, 1_100).is_ok());
    for now in [999, 1_101] {
        assert_eq!(
            ledger.estimate(CONTEXT, now),
            Err(LatencyError::StaleSnapshot)
        );
    }
    for changed in [
        Context {
            clock_id: 8,
            ..CONTEXT
        },
        Context {
            epoch: 4,
            ..CONTEXT
        },
        Context {
            route_revision: 3,
            ..CONTEXT
        },
        Context {
            snapshot_id: 20,
            ..CONTEXT
        },
    ] {
        assert_eq!(
            ledger.estimate(changed, 1_000),
            Err(LatencyError::ContextMismatch)
        );
        assert_eq!(
            ledger.record(
                Stage::Dma,
                Observation {
                    context: changed,
                    ..observation(10, 20, DelayKind::Variable)
                }
            ),
            Err(LatencyError::ContextMismatch)
        );
    }
    ledger.invalidate(Stage::Dma);
    assert_eq!(
        ledger.estimate(CONTEXT, 1_000),
        Err(LatencyError::MissingStages(Stage::Dma.bit()))
    );
    trace(
        "V01-INVALIDATION",
        serde_json::json!({"rejected_context_changes": 4, "freshness_bound_ns": 100}),
    );
}

#[test]
fn checked_affine_transform_rounds_outward_and_propagates_uncertainty() {
    let transform = ClockTransform {
        source_clock_id: 7,
        target_clock_id: 9,
        epoch: 3,
        local_anchor_ns: 100,
        target_anchor_ns: 1_000,
        rate_ppb: 500_000_000,
        uncertainty_ns: 4,
        valid_local: Interval::new(90, 120).unwrap(),
    };
    assert_eq!(
        transform
            .map_interval(Interval::new(99, 101).unwrap())
            .unwrap(),
        Interval::new(998, 1002).unwrap()
    );
    let mapped = Observation {
        uncertainty_ns: 3,
        ..observation(100, 110, DelayKind::Fixed)
    }
    .transform(transform)
    .unwrap();
    assert_eq!(mapped.interval, Interval::new(1_000, 1_015).unwrap());
    assert_eq!(mapped.uncertainty_ns, 9); // ceil(3 * 1.5) + 4
    assert_eq!(mapped.context.clock_id, 9);
    assert_eq!(
        transform.map_interval(Interval::new(89, 100).unwrap()),
        Err(LatencyError::TransformExpired)
    );
    assert_eq!(
        ClockTransform {
            rate_ppb: -1_000_000_000,
            ..transform
        }
        .map_interval(Interval::new(100, 110).unwrap()),
        Err(LatencyError::InvalidRate)
    );
    assert_eq!(
        observation(100, 110, DelayKind::Fixed).transform(ClockTransform {
            epoch: 8,
            ..transform
        }),
        Err(LatencyError::ContextMismatch)
    );
    trace("V01-TRANSFORM", serde_json::to_value(mapped).unwrap());
}

#[test]
fn invalid_and_overflow_values_are_errors_and_preserve_last_observation() {
    assert_eq!(
        Interval::from_signed(-1, 3),
        Err(LatencyError::NegativeTimestamp)
    );
    assert_eq!(Interval::new(3, 2), Err(LatencyError::ReversedInterval));
    assert!(matches!(
        LatencyTimeline::new(CONTEXT, 1 << 8, 0, 0),
        Err(LatencyError::InvalidStageMask)
    ));
    let mut ledger = timeline();
    ledger
        .record(Stage::Ingress, observation(0, 0, DelayKind::Fixed))
        .unwrap();
    ledger
        .record(Stage::Output, observation(10, 10, DelayKind::Fixed))
        .unwrap();
    assert_eq!(
        ledger.record(
            Stage::Output,
            Observation {
                uncertainty_ns: 1,
                ..observation(u64::MAX, u64::MAX, DelayKind::Fixed)
            }
        ),
        Err(LatencyError::Overflow)
    );
    assert_eq!(ledger.estimate(CONTEXT, 1_000).unwrap().effective_ns, 10);
    ledger
        .record(Stage::Dma, observation(0, 11, DelayKind::Variable))
        .unwrap();
    assert_eq!(
        ledger.estimate(CONTEXT, 1_000),
        Err(LatencyError::OutsideTimeline)
    );
    let transform = ClockTransform {
        source_clock_id: 7,
        target_clock_id: 9,
        epoch: 3,
        local_anchor_ns: 0,
        target_anchor_ns: u64::MAX,
        rate_ppb: 0,
        uncertainty_ns: 0,
        valid_local: Interval::new(0, 2).unwrap(),
    };
    assert_eq!(
        transform.map_interval(Interval::new(0, 1).unwrap()),
        Err(LatencyError::Overflow)
    );
    trace(
        "V01-ARITHMETIC",
        serde_json::json!({"last_good_latency_ns":10}),
    );
}

#[test]
fn video_advice_uses_uncertainty_bounds_and_does_not_claim_percentiles() {
    let mut ledger = timeline();
    ledger
        .record(
            Stage::Ingress,
            observation(100_000_000, 100_000_000, DelayKind::Fixed),
        )
        .unwrap();
    ledger
        .record(
            Stage::Output,
            Observation {
                uncertainty_ns: 50_000_000,
                provenance: Provenance::Inferred,
                ..observation(160_000_000, 160_000_000, DelayKind::Fixed)
            },
        )
        .unwrap();
    let result = ledger.estimate(CONTEXT, 1_000).unwrap();
    assert_eq!(
        (result.minimum_ns, result.maximum_ns),
        (10_000_000, 110_000_000)
    );
    assert_eq!(result.inferred_stages, Stage::Output.bit());
    assert!(!result.video_delay_advice(60_000_000).within_40ms_bound);
    ledger
        .record(
            Stage::Output,
            observation(160_000_000, 160_000_000, DelayKind::Fixed),
        )
        .unwrap();
    let result = ledger.estimate(CONTEXT, 1_000).unwrap();
    assert!(result.video_delay_advice(60_000_000).within_40ms_bound);
    assert!(!result.video_delay_advice(u64::MAX).within_40ms_bound);
    trace(
        "V01-VIDEO-BOUNDS",
        serde_json::to_value(result.video_delay_advice(60_000_000)).unwrap(),
    );
}
