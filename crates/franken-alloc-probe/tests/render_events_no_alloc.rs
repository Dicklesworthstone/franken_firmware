//! Proof that emitting render-path events does not allocate: `EventProducer::emit`, the three adapters, and the
//! consumer's `pop`, including when the ring is full, when critical events are lost and when the consumer is gone;
//! and a real D02 `render_into` followed by `protection_report`.
//!
//! Building the ring is control-path work and allocates; it is measured only to show the counter is live.
//! This test binary installs `CountingAllocator` as its global allocator and every measured region runs on the
//! test thread, so parallel tests cannot disturb the counts.

use franken_alloc_probe::{CountingAllocator, is_active, measure};
use franken_board_profile::synthetic_test_fixture_catalog;
use franken_dsp::StereoAudioBlock;
use franken_dsp::convert::ConvertStats;
use franken_dsp::protection::{
    Admission, BlockReport, BoardStatus, FaultCode, ProtectedBoardDsp, ProtectedOutput,
    synthetic_calibration_for,
};
use franken_dsp::render_events::{Emitted, RenderEventKind, event_channel};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator::new();

fn report(status: BoardStatus, clipped: u32) -> BlockReport {
    BlockReport {
        frames: 256,
        user_gain: 1.0,
        applied_gain: 1.0,
        source_fade: 1.0,
        min_limiter_gain: 1.0,
        max_thermal_level: 0.0,
        thermal_scaled_samples: clipped,
        clipped_samples: clipped,
        input_non_finite: clipped,
        status,
    }
}

#[test]
fn the_counter_is_installed_and_building_the_ring_is_where_allocation_lives() {
    assert!(
        is_active(),
        "CountingAllocator is not this binary's global allocator: a zero count would be vacuous"
    );
    let (ring, delta) = measure(|| event_channel(64, 8));
    assert!(ring.is_ok());
    assert!(
        delta.allocations >= 1,
        "constructing the ring is control-path work and must allocate: {delta:?}"
    );
}

#[test]
fn emit_the_adapters_and_pop_do_not_allocate_even_when_the_ring_is_full_or_the_consumer_is_gone() {
    assert!(is_active());
    let (mut producer, mut consumer) = event_channel(16, 4).expect("ring");
    let (mut orphan, gone) = event_channel(16, 4).expect("ring");
    drop(gone);
    let faulted = BoardStatus::Faulted(FaultCode::ThermalHard { channel: 2 });

    let ((kept, dropped, lost), delta) = measure(|| {
        let (mut kept, mut dropped, mut lost) = (0u32, 0u32, 0u32);
        for round in 0..1000u32 {
            for target in [&mut producer, &mut orphan] {
                let kind = if round % 50 == 49 {
                    RenderEventKind::BoardFaultStateRange
                } else {
                    RenderEventKind::ConvertSaturated
                };
                match target.emit(kind, round) {
                    Emitted::Kept => kept += 1,
                    Emitted::DroppedOrdinary => dropped += 1,
                    Emitted::LostCritical => lost += 1,
                }
                target.convert_stats(ConvertStats {
                    saturated: round,
                    non_finite: 1,
                });
                target.ring_counters(round, round / 2);
                let status = if round.is_multiple_of(2) {
                    BoardStatus::Active
                } else {
                    faulted
                };
                target.protection_report(&report(status, round % 3));
            }
            // The consumer reads a little, now and then, so room opens and closes while the producer runs.
            if round % 100 == 99 {
                for _ in 0..3 {
                    let _ = consumer.pop();
                }
                let _ = consumer.stats();
                let _ = consumer.evidence_complete();
            }
        }
        (kept, dropped, lost)
    });
    assert!(
        delta.is_zero(),
        "the event path touched the allocator: {delta:?}"
    );
    // The measured region really exercised every outcome; otherwise "zero allocations" would be vacuous.
    assert!(
        kept > 0 && dropped > 0 && lost > 0,
        "{kept} {dropped} {lost}"
    );
    assert!(producer.dropped_ordinary() > 0 && producer.lost_critical() > 0);
    assert!(!orphan.consumer_connected());
}

#[test]
fn a_real_protected_render_followed_by_its_report_does_not_allocate() {
    assert!(is_active());
    let profile = synthetic_test_fixture_catalog()
        .into_iter()
        .find(|profile| profile.model_number == "S5")
        .expect("fixture board S5");
    let calibration = synthetic_calibration_for(&profile);
    // Admission validates the calibration (control path) and is not measured.
    let mut dsp = ProtectedBoardDsp::admit(&profile, Some(&calibration), Admission::HostSimulation);
    dsp.set_muted(false).expect("an admitted board unmutes");
    let (mut producer, _consumer) = event_channel(16, 4).expect("ring");
    let faulted = BoardStatus::Faulted(FaultCode::ThermalHard { channel: 2 });
    let mut out = ProtectedOutput::new();
    let mut drive = StereoAudioBlock::silence(0);
    for (i, sample) in drive.left.iter_mut().enumerate() {
        *sample = if i.is_multiple_of(2) { 0.9 } else { -0.9 };
    }

    let (heard, delta) = measure(|| {
        let mut heard = 0i32;
        for block in 0..60 {
            if block % 8 == 2 {
                drive.left[30] = f32::NAN;
            } else {
                drive.left[30] = 0.9;
            }
            let block_report = dsp.render_into(&drive, &mut out);
            producer.protection_report(&block_report);
            if block == 30 {
                // Whatever the real board reported, make sure the adapter emitted: counters and a fault.
                producer.protection_report(&report(faulted, 7));
            }
            heard += i32::from(out.samples[0][100]).abs();
        }
        heard
    });
    assert!(
        delta.is_zero(),
        "render_into followed by protection_report touched the allocator: {delta:?}"
    );
    assert!(
        heard > 0,
        "the board produced audio during the measured region"
    );
    assert!(
        producer.attempted() >= 4,
        "the adapters emitted nothing, so zero allocations would be vacuous: {}",
        producer.attempted()
    );
}
