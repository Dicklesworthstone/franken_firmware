//! Proof that the D02 render path does not allocate: `ProtectedBoardDsp::render_into`, the setters,
//! source events, fault handling and fault clearing, on an admitted board and on a fail-muted one.
//! Admission and profile switching validate calibrations (control path) and are not measured.

use franken_alloc_probe::{CountingAllocator, is_active, measure};
use franken_board_profile::{BoardProfile, synthetic_test_fixture_catalog};
use franken_dsp::StereoAudioBlock;
use franken_dsp::protection::{
    Admission, BoardCalibration, BoardStatus, ProtectedBoardDsp, ProtectedOutput, ProtectionError,
    SourceEvent, synthetic_calibration_for,
};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator::new();

fn fixture(model: &str) -> BoardProfile {
    synthetic_test_fixture_catalog()
        .into_iter()
        .find(|profile| profile.model_number == model)
        .expect("fixture board")
}

fn nyquist_left(amplitude: f32) -> StereoAudioBlock {
    let mut block = StereoAudioBlock::silence(0);
    for (i, sample) in block.left.iter_mut().enumerate() {
        *sample = if i.is_multiple_of(2) {
            amplitude
        } else {
            -amplitude
        };
    }
    block
}

#[test]
fn protection_render_into_does_not_allocate() {
    assert!(
        is_active(),
        "the counter must be installed or a zero count is vacuous"
    );

    // ---- control path: admission validates the calibration and allocates ----
    let profile = fixture("S5");
    let calibration = synthetic_calibration_for(&profile);
    let (admitted, admit_delta) = measure(|| {
        ProtectedBoardDsp::admit(&profile, Some(&calibration), Admission::HostSimulation)
    });
    assert!(
        admit_delta.allocations >= 1,
        "admission is where allocation lives: {admit_delta:?}"
    );
    let mut dsp = admitted;
    assert_eq!(dsp.status(), BoardStatus::Active);
    let mut out = ProtectedOutput::new();
    let silence = StereoAudioBlock::silence(0);
    let drive = nyquist_left(0.9); // above the limiter threshold, so the limiter and clamp work

    // ---- render path: nothing may touch the allocator ----
    let (result, delta) = measure(|| {
        let mut heard = 0i32;
        dsp.set_muted(false).expect("an active board unmutes");
        for _ in 0..4 {
            dsp.render_into(&silence, &mut out);
        }
        for block in 0..40 {
            dsp.set_user_gain(if block % 2 == 0 { 1.0 } else { 0.7 });
            let report = dsp.render_into(&drive, &mut out);
            heard += i32::from(out.samples[0][100]).abs() + i32::from(out.samples[2][100]).abs();
            if block == 10 {
                dsp.on_source_event(SourceEvent::Seek);
            }
            if block == 20 {
                dsp.on_source_event(SourceEvent::Reconnect);
            }
            if block == 30 {
                dsp.set_muted(true).expect("mute is always allowed");
            }
            if block == 34 {
                dsp.set_muted(false).expect("unmute");
            }
            assert!(report.frames == 256);
        }
        let mut partial = nyquist_left(0.4);
        partial.frames = 7;
        dsp.render_into(&partial, &mut out);
        let mut empty = nyquist_left(0.4);
        empty.frames = 0;
        dsp.render_into(&empty, &mut out);
        let _ = (dsp.thermal_level(0), dsp.limiter_gain(2), dsp.status());
        heard
    });
    assert!(
        delta.is_zero(),
        "the render path touched the allocator: {delta:?}"
    );
    assert!(
        result > 0,
        "the board produced audio during the measured region"
    );
    assert_eq!(
        dsp.status(),
        BoardStatus::Active,
        "no fault under this drive"
    );
}

#[test]
fn protection_error_and_fault_paths_do_not_allocate() {
    assert!(is_active());
    let profile = fixture("S3");

    // A calibration that lets an overdrive latch a thermal fault within a few blocks.
    let mut hot: BoardCalibration = synthetic_calibration_for(&profile);
    hot.channels[0].thermal.tau_s = 0.05;
    hot.channels[0].thermal.soft_ms = 0.05;
    hot.channels[0].thermal.hard_ms = 0.2;
    let mut dsp = ProtectedBoardDsp::admit(&profile, Some(&hot), Admission::HostSimulation);
    assert_eq!(dsp.status(), BoardStatus::Active);

    // A board that never admitted.
    let mut muted = ProtectedBoardDsp::admit(&profile, None, Admission::HostSimulation);
    assert!(matches!(muted.status(), BoardStatus::FailMuted(_)));

    let mut out = ProtectedOutput::new();
    let silence = StereoAudioBlock::silence(0);
    let drive = nyquist_left(0.6);

    let ((faulted, cleared, refused), delta) = measure(|| {
        // fail-muted board: refusal values are Copy, rendering stays silent
        let refusal = muted.set_muted(false);
        let mut silent = true;
        for _ in 0..4 {
            muted.render_into(&drive, &mut out);
            silent &= out.samples[0][..256].iter().all(|&s| s == 0);
        }

        // thermal fault: ramp to silence, refuse to clear while hot, cool, clear, resume
        dsp.set_muted(false).expect("unmute");
        for _ in 0..4 {
            dsp.render_into(&silence, &mut out);
        }
        for _ in 0..16 {
            dsp.render_into(&drive, &mut out);
        }
        let faulted = matches!(dsp.status(), BoardStatus::Faulted(_));
        let hot_clear = dsp.clear_fault();
        let unmute_refused = dsp.set_muted(false);
        for _ in 0..20 {
            dsp.render_into(&silence, &mut out);
        }
        let cleared = dsp.clear_fault();
        for _ in 0..3 {
            dsp.render_into(&nyquist_left(0.3), &mut out);
        }
        (
            faulted && silent,
            cleared == Ok(()) && dsp.status() == BoardStatus::Active,
            refusal == Err(ProtectionError::UnmuteRefused)
                && hot_clear == Err(ProtectionError::NotCooled)
                && unmute_refused == Err(ProtectionError::UnmuteRefused),
        )
    });
    assert!(
        delta.is_zero(),
        "fault, refusal or clear paths allocated: {delta:?}"
    );
    assert!(
        faulted,
        "the overdrive latched a fault and the fail-muted board stayed silent"
    );
    assert!(cleared, "the board cooled, cleared and resumed");
    assert!(refused, "every refusal was the expected typed error");
}
