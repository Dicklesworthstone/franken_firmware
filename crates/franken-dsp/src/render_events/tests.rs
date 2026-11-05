//! Tests for the render-path event ring (the shared logging clause of `D01`, `D02` and `G02`).
//!
//! What they show: the ring's accounting is exact (against a plain queue, across the 32-bit counter wrap), a
//! critical event outranks ordinary ones, loss is counted and visible as a gap in `seq`, and a slow, full or
//! unavailable sink leaves the real D01 and D02 render path bit-identical with the same events attempted.
//!
//! What they do not show: how long `emit` takes on a board (nothing here measures time), that a log writer is
//! healthy, or any file format. The one test that uses threads uses no timing: the consumer is blocked until
//! the producer has finished, so a producer that waited on the consumer would never finish.

use super::*;
use crate::convert::convert_block;
use crate::format::{BufferSpec, Endian, MAX_BLOCK_FRAMES, SampleFormat, StreamFormat};
use crate::protection::{
    Admission, ProtectedBoardDsp, ProtectedOutput, ProtectionError, synthetic_calibration_for,
};
use crate::ring::ring_channel;
use crate::{FRAMES_PER_BLOCK, StereoAudioBlock};
use franken_board_profile::synthetic_test_fixture_catalog;
use std::collections::VecDeque;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

const ORDINARY: RenderEventKind = RenderEventKind::ConvertSaturated;
const CRITICAL: RenderEventKind = RenderEventKind::BoardFaultStateRange;

/// Seeded and fixed, so a failure replays: SplitMix64.
struct SplitMix(u64);

impl SplitMix {
    fn draw(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn pop_all(consumer: &mut EventConsumer) -> Vec<RenderEvent> {
    let mut out = Vec::new();
    while let Some(event) = consumer.pop() {
        out.push(event);
    }
    out
}

/// Run `call` on the producer and return the (kind, value) pairs it caused, oldest first.
fn after(
    producer: &mut EventProducer,
    consumer: &mut EventConsumer,
    call: impl FnOnce(&mut EventProducer),
) -> Vec<(RenderEventKind, u32)> {
    call(producer);
    pop_all(consumer)
        .into_iter()
        .map(|event| (event.kind, event.value))
        .collect()
}

fn report(status: BoardStatus, clipped: u32, thermal: u32, non_finite: u32) -> BlockReport {
    BlockReport {
        frames: FRAMES_PER_BLOCK,
        user_gain: 1.0,
        applied_gain: 1.0,
        source_fade: 1.0,
        min_limiter_gain: 1.0,
        max_thermal_level: 0.0,
        thermal_scaled_samples: thermal,
        clipped_samples: clipped,
        input_non_finite: non_finite,
        status,
    }
}

// ---- the kinds ----------------------------------------------------------------------------------------------------

#[test]
fn every_kind_round_trips_through_its_slot_index_and_its_name_is_the_serialized_form() {
    for (position, kind) in RenderEventKind::ALL.iter().enumerate() {
        let index = u32::try_from(position).unwrap();
        assert_eq!(kind.index(), index, "{kind:?} is out of place in ALL");
        assert_eq!(RenderEventKind::from_index(index), Some(*kind));
        assert_eq!(
            serde_json::to_value(kind).unwrap(),
            serde_json::json!(kind.code())
        );
    }
    let past_the_end = u32::try_from(RenderEventKind::ALL.len()).unwrap();
    assert_eq!(RenderEventKind::from_index(past_the_end), None);
    assert_eq!(RenderEventKind::from_index(u32::MAX), None);
    let critical: Vec<&str> = RenderEventKind::ALL
        .iter()
        .filter(|kind| kind.is_critical())
        .map(|kind| kind.code())
        .collect();
    assert_eq!(
        critical,
        [
            "board_fail_muted",
            "board_fault_non_finite_state",
            "board_fault_state_range",
            "board_fault_thermal_hard"
        ]
    );
}

#[test]
fn a_bad_capacity_or_reserve_is_refused() {
    for capacity in [0usize, 1, 3, 6, 12, 100, MAX_CAPACITY + 1, MAX_CAPACITY * 2] {
        assert_eq!(
            event_channel(capacity, 1).err(),
            Some(EventConfigError::Capacity { capacity }),
            "capacity {capacity}"
        );
    }
    for reserve in [0usize, 8, 9, 1000] {
        assert_eq!(
            event_channel(8, reserve).err(),
            Some(EventConfigError::Reserve {
                reserve,
                capacity: 8
            }),
            "reserve {reserve}"
        );
    }
    assert!(event_channel(2, 1).is_ok());
    assert!(event_channel(MAX_CAPACITY, MAX_CAPACITY - 1).is_ok());
}

// ---- the ring -----------------------------------------------------------------------------------------------------

#[test]
fn events_are_read_back_oldest_first_with_their_kind_value_and_sequence() {
    let (mut producer, mut consumer) = event_channel(8, 2).unwrap();
    assert_eq!(consumer.pop(), None);
    let sent = [
        (RenderEventKind::ConvertSaturated, 3),
        (RenderEventKind::RingUnderrun, 1),
        (RenderEventKind::BoardFaultThermalHard, 4),
        (RenderEventKind::ProtectionClipped, u32::MAX),
        (RenderEventKind::BoardActive, 0),
    ];
    for (kind, value) in sent {
        assert_eq!(producer.emit(kind, value), Emitted::Kept);
    }
    let want: Vec<RenderEvent> = sent
        .iter()
        .enumerate()
        .map(|(position, (kind, value))| RenderEvent {
            seq: u32::try_from(position).unwrap(),
            kind: *kind,
            value: *value,
        })
        .collect();
    assert_eq!(pop_all(&mut consumer), want);
    assert_eq!(consumer.stats().pending, 0);
    assert!(consumer.evidence_complete());
    assert_eq!(producer.attempted(), 5);
}

#[test]
fn ordinary_events_stop_at_capacity_minus_reserve_and_the_gap_shows_in_the_sequence() {
    let (mut producer, mut consumer) = event_channel(8, 2).unwrap();
    let outcomes: Vec<Emitted> = (0u32..10).map(|i| producer.emit(ORDINARY, i)).collect();
    assert_eq!(&outcomes[..6], &[Emitted::Kept; 6]);
    assert_eq!(&outcomes[6..], &[Emitted::DroppedOrdinary; 4]);
    assert_eq!(producer.dropped_ordinary(), 4);
    assert_eq!(producer.lost_critical(), 0);

    let first: Vec<(u32, u32)> = pop_all(&mut consumer)
        .iter()
        .map(|event| (event.seq, event.value))
        .collect();
    assert_eq!(first, (0u32..6).map(|i| (i, i)).collect::<Vec<_>>());

    // Room again. The next kept event has seq 10: 6..=9 were dropped between it and seq 5.
    assert_eq!(producer.emit(ORDINARY, 99), Emitted::Kept);
    assert_eq!(
        pop_all(&mut consumer),
        vec![RenderEvent {
            seq: 10,
            kind: ORDINARY,
            value: 99
        }]
    );
    assert!(
        consumer.evidence_complete(),
        "dropped ordinary events are counted, not incomplete evidence"
    );
    assert_eq!(consumer.stats().dropped_ordinary, 4);
}

#[test]
fn critical_events_use_the_reserve_and_are_lost_only_when_the_ring_is_completely_full() {
    let (mut producer, mut consumer) = event_channel(8, 2).unwrap();
    for i in 0u32..10 {
        let _ = producer.emit(ORDINARY, i); // 6 kept, 4 dropped
    }
    assert_eq!(producer.emit(CRITICAL, 1), Emitted::Kept);
    assert_eq!(producer.emit(CRITICAL, 2), Emitted::Kept);
    assert!(consumer.evidence_complete());
    assert_eq!(producer.emit(CRITICAL, 3), Emitted::LostCritical);
    assert!(!consumer.evidence_complete());

    let stats = consumer.stats();
    assert_eq!(
        (stats.pending, stats.dropped_ordinary, stats.lost_critical),
        (8, 4, 1)
    );
    let events = pop_all(&mut consumer);
    let tail: Vec<(u32, RenderEventKind, u32)> = events[6..]
        .iter()
        .map(|event| (event.seq, event.kind, event.value))
        .collect();
    assert_eq!(tail, [(10, CRITICAL, 1), (11, CRITICAL, 2)]);

    // Room again: a critical event is kept, but the earlier loss is never forgotten.
    assert_eq!(producer.emit(CRITICAL, 4), Emitted::Kept);
    assert!(
        !consumer.evidence_complete(),
        "a lost critical event is never forgotten"
    );
    assert_eq!(pop_all(&mut consumer)[0].seq, 13);
}

#[test]
fn a_dropped_consumer_changes_what_is_retained_never_what_emit_does() {
    let (mut with, with_consumer) = event_channel(8, 2).unwrap();
    let (mut without, gone) = event_channel(8, 2).unwrap();
    drop(gone);
    assert!(with.consumer_connected());
    assert!(!without.consumer_connected());
    for i in 0u32..40 {
        let kind = if i % 7 == 6 { CRITICAL } else { ORDINARY };
        assert_eq!(with.emit(kind, i), without.emit(kind, i), "step {i}");
    }
    assert_eq!(with.attempted(), without.attempted());
    assert_eq!(
        (with.dropped_ordinary(), with.lost_critical()),
        (without.dropped_ordinary(), without.lost_critical())
    );
    drop(with_consumer);
}

#[test]
fn the_ring_matches_a_plain_queue_across_counter_wraparound_and_small_capacities() {
    let mut rng = SplitMix(0x00D0_1F3B_0010);
    for (capacity, reserve) in [(2usize, 1usize), (4, 1), (4, 3), (8, 3), (64, 8)] {
        for start in [0u32, u32::MAX, u32::MAX - 3, u32::MAX - 100] {
            let (mut producer, mut consumer) = event_channel(capacity, reserve).unwrap();
            producer.shared.head.store(start, Ordering::Relaxed);
            producer.shared.tail.store(start, Ordering::Relaxed);
            let mut model: VecDeque<RenderEvent> = VecDeque::new();
            let (mut kept, mut dropped, mut lost) = (0u32, 0u32, 0u32);
            for step in 0..40_000u32 {
                let context =
                    format!("capacity {capacity} reserve {reserve} start {start} step {step}");
                let draw = rng.draw() % 8;
                if draw < 6 {
                    let critical = draw >= 4;
                    let kind = if critical { CRITICAL } else { ORDINARY };
                    let seq = producer.attempted();
                    let free = capacity - model.len();
                    let needed = if critical { 1 } else { reserve + 1 };
                    let expected = if free >= needed {
                        Emitted::Kept
                    } else if critical {
                        Emitted::LostCritical
                    } else {
                        Emitted::DroppedOrdinary
                    };
                    assert_eq!(producer.emit(kind, step), expected, "{context}");
                    match expected {
                        Emitted::Kept => {
                            kept += 1;
                            model.push_back(RenderEvent {
                                seq,
                                kind,
                                value: step,
                            });
                        }
                        Emitted::DroppedOrdinary => dropped += 1,
                        Emitted::LostCritical => lost += 1,
                    }
                } else if draw == 6 {
                    assert_eq!(consumer.pop(), model.pop_front(), "{context}");
                } else {
                    let mut got = Vec::new();
                    let appended = consumer.drain_into(&mut got);
                    let want: Vec<RenderEvent> = model.drain(..model.len().min(capacity)).collect();
                    assert_eq!(appended, want.len(), "{context}");
                    assert_eq!(got, want, "{context}");
                }
                assert_eq!(consumer.stats().pending, model.len(), "{context}");
            }
            assert_eq!(producer.attempted(), kept + dropped + lost);
            assert_eq!(
                (producer.dropped_ordinary(), producer.lost_critical()),
                (dropped, lost)
            );
            if start > 1 << 31 {
                assert!(
                    producer.shared.tail.load(Ordering::Relaxed) < start,
                    "the counters never wrapped (capacity {capacity}, start {start})"
                );
            }
        }
    }
}

// ---- the adapters -------------------------------------------------------------------------------------------------

#[test]
fn convert_stats_emit_one_event_per_nonzero_counter_and_none_for_a_clean_block() {
    let (mut producer, mut consumer) = event_channel(16, 4).unwrap();
    let clean = after(&mut producer, &mut consumer, |p| {
        p.convert_stats(ConvertStats::default());
    });
    assert!(clean.is_empty());
    assert_eq!(
        producer.attempted(),
        0,
        "a clean block consumes no sequence number"
    );

    let saturated = after(&mut producer, &mut consumer, |p| {
        p.convert_stats(ConvertStats {
            saturated: 3,
            non_finite: 0,
        });
    });
    assert_eq!(saturated, [(RenderEventKind::ConvertSaturated, 3)]);

    let both = after(&mut producer, &mut consumer, |p| {
        p.convert_stats(ConvertStats {
            saturated: 5,
            non_finite: 2,
        });
    });
    assert_eq!(
        both,
        [
            (RenderEventKind::ConvertSaturated, 5),
            (RenderEventKind::ConvertNonFinite, 2)
        ]
    );
}

#[test]
fn ring_counters_emit_the_growth_since_the_previous_call_not_the_cumulative_count() {
    let (mut producer, mut consumer) = event_channel(16, 4).unwrap();
    assert!(after(&mut producer, &mut consumer, |p| p.ring_counters(0, 0)).is_empty());
    assert_eq!(
        after(&mut producer, &mut consumer, |p| p.ring_counters(2, 0)),
        [(RenderEventKind::RingOverrun, 2)]
    );
    assert_eq!(
        after(&mut producer, &mut consumer, |p| p.ring_counters(2, 5)),
        [(RenderEventKind::RingUnderrun, 5)]
    );
    assert_eq!(
        after(&mut producer, &mut consumer, |p| p.ring_counters(4, 5)),
        [(RenderEventKind::RingOverrun, 2)]
    );
    assert_eq!(
        after(&mut producer, &mut consumer, |p| p.ring_counters(5, 8)),
        [
            (RenderEventKind::RingOverrun, 1),
            (RenderEventKind::RingUnderrun, 3)
        ]
    );
    // Counters that went backwards belong to a different ring: a new baseline, no event.
    assert!(after(&mut producer, &mut consumer, |p| p.ring_counters(1, 1)).is_empty());
    assert_eq!(
        after(&mut producer, &mut consumer, |p| p.ring_counters(2, 1)),
        [(RenderEventKind::RingOverrun, 1)]
    );
}

#[test]
fn protection_report_emits_nonzero_counters_and_only_changes_of_status() {
    let (mut producer, mut consumer) = event_channel(32, 4).unwrap();
    let active = BoardStatus::Active;
    let muted = BoardStatus::FailMuted(ProtectionError::NoCalibration);
    let faulted = BoardStatus::Faulted(FaultCode::ThermalHard { channel: 3 });

    // The producer assumes Active, so an Active block with clean counters says nothing.
    assert!(
        after(&mut producer, &mut consumer, |p| p
            .protection_report(&report(active, 0, 0, 0)))
        .is_empty()
    );
    assert_eq!(
        after(&mut producer, &mut consumer, |p| p
            .protection_report(&report(active, 5, 6, 7))),
        [
            (RenderEventKind::ProtectionClipped, 5),
            (RenderEventKind::ProtectionThermalScaled, 6),
            (RenderEventKind::ProtectionInputNonFinite, 7)
        ]
    );
    assert_eq!(
        after(&mut producer, &mut consumer, |p| p
            .protection_report(&report(muted, 0, 0, 0))),
        [(RenderEventKind::BoardFailMuted, 0)]
    );
    assert!(
        after(&mut producer, &mut consumer, |p| p
            .protection_report(&report(muted, 0, 0, 0)))
        .is_empty(),
        "the same status twice is one event"
    );
    assert_eq!(
        after(&mut producer, &mut consumer, |p| p
            .protection_report(&report(faulted, 1, 0, 0))),
        [
            (RenderEventKind::ProtectionClipped, 1),
            (RenderEventKind::BoardFaultThermalHard, 3)
        ]
    );
    assert_eq!(
        after(&mut producer, &mut consumer, |p| p
            .protection_report(&report(active, 0, 0, 0))),
        [(RenderEventKind::BoardActive, 0)]
    );

    // A board that is already fail-muted at the first block reports it.
    let (mut fresh, mut fresh_consumer) = event_channel(8, 2).unwrap();
    assert_eq!(
        after(&mut fresh, &mut fresh_consumer, |p| p
            .protection_report(&report(muted, 0, 0, 0))),
        [(RenderEventKind::BoardFailMuted, 0)]
    );
}

#[test]
fn each_fault_code_has_its_own_critical_kind_and_carries_its_channel() {
    let cases = [
        (
            FaultCode::NonFiniteState { channel: 1 },
            RenderEventKind::BoardFaultNonFiniteState,
            1,
        ),
        (
            FaultCode::StateRange { channel: 4 },
            RenderEventKind::BoardFaultStateRange,
            4,
        ),
        (
            FaultCode::ThermalHard { channel: 8 },
            RenderEventKind::BoardFaultThermalHard,
            8,
        ),
    ];
    for (code, kind, channel) in cases {
        assert!(kind.is_critical());
        let (mut producer, mut consumer) = event_channel(8, 2).unwrap();
        let events = after(&mut producer, &mut consumer, |p| {
            p.protection_report(&report(BoardStatus::Faulted(code), 0, 0, 0));
        });
        assert_eq!(events, [(kind, channel)], "{code:?}");
    }
}

#[test]
fn one_block_emits_at_most_max_events_per_block() {
    let (mut producer, _consumer) = event_channel(64, 8).unwrap();
    producer.convert_stats(ConvertStats {
        saturated: 1,
        non_finite: 1,
    });
    producer.ring_counters(1, 1);
    producer.protection_report(&report(
        BoardStatus::Faulted(FaultCode::ThermalHard { channel: 1 }),
        1,
        1,
        1,
    ));
    assert_eq!(
        usize::try_from(producer.attempted()).unwrap(),
        MAX_EVENTS_PER_BLOCK
    );
}

// ---- the real render path under every sink state -------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SinkState {
    /// No producer at all: the baseline the others must equal.
    NoSink,
    /// The consumer reads everything after every block.
    Healthy,
    /// The consumer never reads.
    Full,
    /// The consumer reads one event every fifth block.
    Slow,
    /// The consumer was dropped before the loop started.
    Unavailable,
}

/// What the render path produced. It must not depend on the sink.
#[derive(Debug, PartialEq, Eq)]
struct RenderOutcome {
    digest: u64,
    convert: ConvertStats,
    ring_overruns: u32,
    ring_underruns: u32,
    final_status: BoardStatus,
}

/// What the sink side saw. It is expected to differ between sink states.
#[derive(Debug)]
struct SinkFacts {
    attempted: u32,
    delivered: usize,
    pending: usize,
    dropped_ordinary: u32,
    lost_critical: u32,
    connected: bool,
    evidence_complete: bool,
}

fn fnv(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
}

/// 60 blocks through the real D01 path (float source -> s16 -> ring -> out) and the real D02 `render_into`, with
/// the adapters called after each step. Saturation (blocks 1, 5, 9, ...), NaN (6, 19, ...), ring overrun (7, 17,
/// ...), ring underrun (3, 15, ...) and non-finite D02 input (2, 10, ...) are provoked on fixed blocks. D01 alone
/// yields 16 ordinary events before block 30, more than the 12 an ordinary event may occupy, so the `Full` state
/// does not depend on what D02 reports. Five critical events are injected by this harness (blocks 30, 34, 38, 42
/// and 46) because driving a real latched fault is covered by the D02 tests.
fn run_render_loop(state: SinkState) -> (RenderOutcome, Option<SinkFacts>) {
    const BLOCKS: usize = 60;
    let profile = synthetic_test_fixture_catalog()
        .into_iter()
        .find(|profile| profile.model_number == "S5")
        .expect("fixture board S5");
    let calibration = synthetic_calibration_for(&profile);
    let mut dsp = ProtectedBoardDsp::admit(&profile, Some(&calibration), Admission::HostSimulation);
    dsp.set_muted(false).expect("an admitted board unmutes");
    let mut out = ProtectedOutput::new();

    let f32_format = StreamFormat::new(SampleFormat::F32, Endian::Little, 2, 48_000).unwrap();
    let s16_format = StreamFormat::new(SampleFormat::S16, Endian::Little, 2, 48_000).unwrap();
    let (f32_spec, s16_spec) = (
        BufferSpec::packed(f32_format),
        BufferSpec::packed(s16_format),
    );
    let (mut ring_in, mut ring_out) = ring_channel(s16_format, 3 * MAX_BLOCK_FRAMES).unwrap();
    let mut source = vec![0u8; MAX_BLOCK_FRAMES * f32_format.bytes_per_frame()];
    let mut converted = vec![0u8; MAX_BLOCK_FRAMES * s16_format.bytes_per_frame()];
    let mut popped = converted.clone();

    let (mut events, mut sink) = if state == SinkState::NoSink {
        (None, None)
    } else {
        let (producer, consumer) = event_channel(16, 4).unwrap();
        (Some(producer), Some(consumer))
    };
    if state == SinkState::Unavailable {
        sink = None;
    }

    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    let mut convert = ConvertStats::default();
    let mut delivered = 0usize;
    let mut final_status = dsp.status();

    for block in 0..BLOCKS {
        // D01: a float source block, with one out-of-range sample and now and then a NaN, to s16.
        for (frame, chunk) in source
            .chunks_exact_mut(f32_format.bytes_per_frame())
            .enumerate()
        {
            let (samples, rest) = chunk.as_chunks_mut::<4>();
            assert!(rest.is_empty(), "a frame is whole 4-byte samples");
            for (channel, bytes) in samples.iter_mut().enumerate() {
                let sign = if (frame + channel).is_multiple_of(2) {
                    1.0f32
                } else {
                    -1.0
                };
                let mut x = 0.8 * sign;
                if block % 4 == 1 && frame == 10 && channel == 0 {
                    x = 1.5;
                }
                if block % 13 == 6 && frame == 20 && channel == 1 {
                    x = f32::NAN;
                }
                bytes.copy_from_slice(&x.to_le_bytes());
            }
        }
        let stats = convert_block(
            &source,
            &f32_spec,
            &mut converted,
            &s16_spec,
            MAX_BLOCK_FRAMES,
        )
        .unwrap();
        convert.merge(stats);

        // D01: through the ring. Every tenth block (from block 7) overfills it, which is an overrun; one block in
        // twelve (from block 3) reads an empty ring, which is an underrun.
        let attempts = if block % 10 == 7 { 4 } else { 1 };
        let mut pushed = 0usize;
        for _ in 0..attempts {
            if ring_in.push(&converted).is_ok() {
                pushed += 1;
            }
        }
        for _ in 0..pushed {
            ring_out
                .pop(&mut popped)
                .expect("a block that was pushed can be popped");
            fnv(&mut digest, &popped);
        }
        if block % 12 == 3 {
            let _ = ring_out.pop(&mut popped);
        }

        // D02: the real protected render, with a NaN input sample on some blocks.
        let mut input = StereoAudioBlock::silence((block * FRAMES_PER_BLOCK) as u64);
        for (frame, (left, right)) in input
            .left
            .iter_mut()
            .zip(input.right.iter_mut())
            .enumerate()
        {
            let v = if frame.is_multiple_of(2) {
                0.9f32
            } else {
                -0.9
            };
            *left = v;
            *right = 0.5 * v;
        }
        if block % 8 == 2 {
            input.left[30] = f32::NAN;
        }
        let report = dsp.render_into(&input, &mut out);
        final_status = report.status;
        for lane in out.samples.iter().take(out.channels) {
            for sample in &lane[..out.frames] {
                fnv(&mut digest, &sample.to_le_bytes());
            }
        }
        for word in [
            report.applied_gain.to_bits(),
            report.min_limiter_gain.to_bits(),
            report.max_thermal_level.to_bits(),
            report.clipped_samples,
            report.thermal_scaled_samples,
            report.input_non_finite,
        ] {
            fnv(&mut digest, &word.to_le_bytes());
        }

        if let Some(events) = events.as_mut() {
            events.convert_stats(stats);
            events.ring_counters(ring_in.overruns(), ring_out.underruns());
            events.protection_report(&report);
            if (30..=46).contains(&block) && (block - 30).is_multiple_of(4) {
                events.emit(CRITICAL, 2);
            }
        }
        match (state, sink.as_mut()) {
            (SinkState::Healthy, Some(sink)) => delivered += sink.drain_into(&mut Vec::new()),
            (SinkState::Slow, Some(sink)) if block % 5 == 4 => {
                delivered += usize::from(sink.pop().is_some());
            }
            _ => {}
        }
    }

    let facts = events.as_ref().map(|producer| {
        let (pending, evidence_complete) = sink
            .as_ref()
            .map_or((0, producer.lost_critical() == 0), |consumer| {
                (consumer.stats().pending, consumer.evidence_complete())
            });
        SinkFacts {
            attempted: producer.attempted(),
            delivered,
            pending,
            dropped_ordinary: producer.dropped_ordinary(),
            lost_critical: producer.lost_critical(),
            connected: producer.consumer_connected(),
            evidence_complete,
        }
    });
    let outcome = RenderOutcome {
        digest,
        convert,
        ring_overruns: ring_in.overruns(),
        ring_underruns: ring_out.underruns(),
        final_status,
    };
    (outcome, facts)
}

#[test]
fn slow_full_and_unavailable_sinks_leave_the_real_render_path_bit_identical() {
    let (baseline, none) = run_render_loop(SinkState::NoSink);
    assert!(none.is_none());
    // The baseline really provoked what the events report; otherwise "identical" would be vacuous.
    assert!(baseline.convert.saturated > 0, "{baseline:?}");
    assert!(baseline.convert.non_finite > 0, "{baseline:?}");
    assert!(baseline.ring_overruns > 0, "{baseline:?}");
    assert!(baseline.ring_underruns > 0, "{baseline:?}");

    let mut attempted = Vec::new();
    for state in [
        SinkState::Healthy,
        SinkState::Full,
        SinkState::Slow,
        SinkState::Unavailable,
    ] {
        let (outcome, facts) = run_render_loop(state);
        assert_eq!(
            outcome, baseline,
            "{state:?} changed what the render path produced"
        );
        let facts = facts.expect("a producer was installed");
        attempted.push(facts.attempted);
        let attempted_here = usize::try_from(facts.attempted).unwrap();
        match state {
            SinkState::Healthy => {
                assert_eq!(
                    (facts.dropped_ordinary, facts.lost_critical, facts.pending),
                    (0, 0, 0),
                    "{facts:?}"
                );
                assert_eq!(facts.delivered, attempted_here, "{facts:?}");
                assert!(facts.evidence_complete && facts.connected, "{facts:?}");
            }
            SinkState::Full => {
                assert_eq!(facts.delivered, 0, "{facts:?}");
                assert_eq!(
                    facts.pending, 16,
                    "the ring holds exactly its capacity: {facts:?}"
                );
                assert!(facts.dropped_ordinary > 0, "{facts:?}");
                assert!(
                    facts.lost_critical >= 1,
                    "the fifth critical event had no room: {facts:?}"
                );
                assert!(!facts.evidence_complete && facts.connected, "{facts:?}");
            }
            SinkState::Slow => {
                assert!(
                    facts.delivered > 0 && facts.delivered < attempted_here,
                    "{facts:?}"
                );
                assert!(facts.dropped_ordinary > 0, "{facts:?}");
                assert!(facts.connected, "{facts:?}");
            }
            SinkState::Unavailable => {
                assert_eq!(facts.delivered, 0, "{facts:?}");
                assert!(!facts.connected, "{facts:?}");
                assert!(facts.dropped_ordinary > 0, "{facts:?}");
                assert!(
                    facts.lost_critical >= 1 && !facts.evidence_complete,
                    "{facts:?}"
                );
            }
            SinkState::NoSink => unreachable!("handled above"),
        }
    }
    assert!(
        attempted.windows(2).all(|pair| pair[0] == pair[1]),
        "the producer attempted different events under different sinks: {attempted:?}"
    );
    assert!(
        attempted[0] > 16,
        "too few events to fill the ring: {attempted:?}"
    );
}

// ---- a consumer that has read nothing ----------------------------------------------------------------------------

#[test]
fn a_consumer_that_has_read_nothing_does_not_stop_the_producer() {
    let (mut producer, mut consumer) = event_channel(16, 4).unwrap();
    let (release, wait) = std::sync::mpsc::channel::<()>();
    let reader = std::thread::spawn(move || {
        wait.recv().expect("released by the test");
        let mut events = Vec::new();
        consumer.drain_into(&mut events);
        (events, consumer.stats(), consumer.evidence_complete())
    });
    let done = Arc::new(AtomicBool::new(false));
    let finished = Arc::clone(&done);
    let writer = std::thread::spawn(move || {
        for i in 0..200_000u32 {
            let kind = if i % 1000 == 999 { CRITICAL } else { ORDINARY };
            producer.emit(kind, i);
        }
        finished.store(true, Ordering::Release);
        producer
    });

    // The reader is blocked until released below, so it has read nothing while the producer runs. A producer
    // that waited for it would never set `done`.
    let mut producer_finished = false;
    for _ in 0..10_000 {
        if done.load(Ordering::Acquire) {
            producer_finished = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        producer_finished,
        "the producer is waiting on a consumer that has read nothing"
    );
    release.send(()).unwrap();
    let (events, stats, complete) = reader.join().unwrap();
    let producer = writer.join().unwrap();

    // 200_000 attempts, 200 of them critical (every 1000th). With nothing read: the 12 ordinary slots filled by
    // the first 12 events, the 4 reserved slots by the first 4 critical events, everything else counted.
    assert_eq!(producer.attempted(), 200_000);
    let seqs: Vec<u32> = events.iter().map(|event| event.seq).collect();
    let mut want: Vec<u32> = (0..12).collect();
    want.extend([999, 1999, 2999, 3999]);
    assert_eq!(seqs, want);
    assert_eq!(stats.dropped_ordinary, 199_800 - 12);
    assert_eq!(stats.lost_critical, 200 - 4);
    assert!(!complete);
}

// ---- the source ----------------------------------------------------------------------------------------------------

#[test]
fn emit_has_no_loop_no_lock_and_no_allocation_in_its_source() {
    // A heuristic over source text, not a proof about compiled code: it catches someone adding a loop, a lock
    // or an allocation to the producer's hot call. Comment lines are skipped.
    let source = include_str!("../render_events.rs");
    let code = |text: &str| {
        text.lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let body = source
        .split("pub fn emit(")
        .nth(1)
        .expect("emit is in the file")
        .split("\n    }\n")
        .next()
        .expect("emit has a body");
    assert!(
        body.contains("Emitted::Kept"),
        "the extracted text is not emit's body"
    );
    let emit_code = code(body);
    for forbidden in [
        "loop", "while", "for ", ".lock(", "Vec", "Box", "Arc::", "format!", "String", ".clone()",
        "sleep", "recv", "wait",
    ] {
        assert!(
            !emit_code.contains(forbidden),
            "emit mentions `{forbidden}`"
        );
    }
    let everything = code(source);
    for forbidden in [
        "Mutex",
        "RwLock",
        "Condvar",
        "Barrier",
        "mpsc",
        ".lock(",
        "sleep",
        "park",
        ".join(",
        "recv",
        "yield_now",
        "spin_loop",
    ] {
        assert!(
            !everything.contains(forbidden),
            "render_events.rs mentions a blocking primitive: `{forbidden}`"
        );
    }
}
