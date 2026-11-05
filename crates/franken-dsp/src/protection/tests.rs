//! Unit tests for `D02`. Expected values here are closed forms or hand-derived numbers; the
//! independent Python reference (`tests/d02/`) supplies the golden step/impulse responses and the
//! replayed scenarios, and `tests/d02_vectors.rs` compares them with this implementation.

use super::*;
use crate::{FRAMES_PER_BLOCK, StereoAudioBlock};
use franken_board_profile::{
    BoardProfile, EvidenceProvenance, FactStatus, FactStatuses, TransducerRole,
    canonical_board_catalog, synthetic_test_fixture_catalog,
};
use std::f64::consts::PI;

const FS: f64 = 48_000.0;

fn fixture(model: &str) -> BoardProfile {
    synthetic_test_fixture_catalog()
        .into_iter()
        .find(|profile| profile.model_number == model)
        .expect("fixture board")
}

fn host(profile: &BoardProfile) -> (BoardCalibration, ProtectedBoardDsp) {
    let calibration = synthetic_calibration_for(profile);
    let dsp = ProtectedBoardDsp::admit(profile, Some(&calibration), Admission::HostSimulation);
    (calibration, dsp)
}

fn constant(left: f32, right: f32) -> StereoAudioBlock {
    let mut block = StereoAudioBlock::silence(0);
    block.left = [left; FRAMES_PER_BLOCK];
    block.right = [right; FRAMES_PER_BLOCK];
    block
}

/// `+a, -a, +a, ...` on the left channel (a Nyquist-rate square: it passes DC rejection).
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

fn impulse(amplitude: f32) -> StereoAudioBlock {
    let mut block = StereoAudioBlock::silence(0);
    block.left[0] = amplitude;
    block.right[0] = amplitude;
    block
}

fn impulse_left(amplitude: f32) -> StereoAudioBlock {
    let mut block = StereoAudioBlock::silence(0);
    block.left[0] = amplitude;
    block
}

fn render(dsp: &mut ProtectedBoardDsp, input: &StereoAudioBlock) -> (BlockReport, ProtectedOutput) {
    let mut out = ProtectedOutput::new();
    let report = dsp.render_into(input, &mut out);
    (report, out)
}

/// Unmute and let the 10 ms gain ramp finish on silence.
fn settle(dsp: &mut ProtectedBoardDsp) {
    dsp.set_muted(false).expect("unmute");
    for _ in 0..4 {
        render(dsp, &StereoAudioBlock::silence(0));
    }
    assert!((dsp.applied_gain() - dsp.user_gain()).abs() < 1e-6);
}

fn peak(out: &ProtectedOutput, channel: usize) -> i32 {
    out.samples[channel][..out.frames]
        .iter()
        .map(|&s| i32::from(s).abs())
        .max()
        .unwrap_or(0)
}

fn all_silent(out: &ProtectedOutput) -> bool {
    (0..out.channels).all(|c| peak(out, c) == 0)
}

fn param(channel: Option<u8>, parameter: Param) -> ProtectionError {
    ProtectionError::InvalidParameter { channel, parameter }
}

/// A planted calibration defect must come up fail-muted with exactly `expected`, and stay silent.
fn expect(
    profile: &BoardProfile,
    name: &str,
    mutate: impl FnOnce(&mut BoardCalibration),
    expected: ProtectionError,
) {
    let mut calibration = synthetic_calibration_for(profile);
    mutate(&mut calibration);
    let mut dsp = ProtectedBoardDsp::admit(profile, Some(&calibration), Admission::HostSimulation);
    assert_eq!(dsp.status(), BoardStatus::FailMuted(expected), "{name}");
    assert_eq!(
        dsp.set_muted(false),
        Err(ProtectionError::UnmuteRefused),
        "{name}"
    );
    dsp.set_user_gain(1.0);
    let (_, out) = render(&mut dsp, &constant(0.9, 0.9));
    assert!(
        all_silent(&out),
        "{name}: a fail-muted board must render silence"
    );
}

// ---- admission --------------------------------------------------------------------------------

#[test]
fn every_synthetic_audio_board_admits_and_the_non_audio_bridge_is_refused_by_name() {
    let catalog = synthetic_test_fixture_catalog();
    let (audio, appliances): (Vec<&BoardProfile>, Vec<&BoardProfile>) = catalog
        .iter()
        .partition(|profile| profile.hardware_channels > 0);

    // The fixture Bridge row is "Sonos Bridge (Non-Audio)": hardware_channels 0, driver ABI
    // "none-non-audio-bridge", amplifier policy ForbiddenFailMuted; franken-board-profile asserts it
    // is never an audio target. Any further zero-output row needs a domain decision, not a pass.
    let appliance_models: Vec<&str> = appliances.iter().map(|p| p.model_number.as_str()).collect();
    assert_eq!(appliance_models, ["BR100"]);
    assert!(audio.len() >= 5, "the audio fixtures: {}", audio.len());

    for profile in audio {
        let (calibration, dsp) = host(profile);
        assert_eq!(dsp.status(), BoardStatus::Active, "{}", profile.profile_id);
        assert_eq!(dsp.channel_count(), usize::from(profile.hardware_channels));
        assert_eq!(calibration.channels.len(), profile.channel_routing.len());
        let provenance = dsp.provenance().expect("provenance is preserved");
        assert_eq!(provenance.kind, ProvenanceKind::Synthetic);
        assert_eq!(
            provenance.acoustic_qualification, None,
            "no acoustic receipt exists"
        );
    }

    // The Bridge has no output path: refused for exactly that reason, in every mode, and it can
    // never be unmuted. The refusal is the permitted negative that pairs with the audio boards.
    for bridge in appliances {
        let calibration = synthetic_calibration_for(bridge);
        assert!(calibration.channels.is_empty());
        for admission in [Admission::HostSimulation, Admission::Production] {
            let mut dsp = ProtectedBoardDsp::admit(bridge, Some(&calibration), admission);
            assert_eq!(
                dsp.status(),
                BoardStatus::FailMuted(ProtectionError::NoAudioOutput),
                "{} in {admission:?}",
                bridge.profile_id
            );
            assert_eq!(dsp.channel_count(), 0);
            assert_eq!(dsp.set_muted(false), Err(ProtectionError::UnmuteRefused));
            let (report, out) = render(&mut dsp, &constant(0.5, 0.5));
            assert_eq!((report.frames, out.channels), (256, 0));
        }
    }
}

#[test]
fn a_malformed_layout_is_invalid_layout_and_is_not_confused_with_no_audio_output() {
    let base = fixture("S3");
    let calibration = synthetic_calibration_for(&base);
    let invalid = BoardStatus::FailMuted(ProtectionError::InvalidLayout);

    let mut short_routing = base.clone();
    short_routing.channel_routing.pop();
    let dsp = ProtectedBoardDsp::admit(
        &short_routing,
        Some(&calibration),
        Admission::HostSimulation,
    );
    assert_eq!(
        dsp.status(),
        invalid,
        "routing list shorter than the channel count"
    );

    let mut too_many = base.clone();
    too_many.hardware_channels = 10;
    too_many.channel_routing = vec![TransducerRole::MidLeft; 10];
    let dsp = ProtectedBoardDsp::admit(&too_many, Some(&calibration), Admission::HostSimulation);
    assert_eq!(
        dsp.status(),
        invalid,
        "more driver channels than the renderer supports"
    );
}

#[test]
fn a_new_board_starts_muted_and_needs_an_explicit_unmute() {
    let (_, mut dsp) = host(&fixture("S3"));
    assert!(dsp.is_muted());
    for _ in 0..3 {
        let (_, out) = render(&mut dsp, &constant(0.5, 0.5));
        assert!(all_silent(&out));
    }
    dsp.set_muted(false).expect("an Active board may unmute");
    let mut heard = false;
    for _ in 0..6 {
        heard |= !all_silent(&render(&mut dsp, &nyquist_left(0.5)).1);
    }
    assert!(heard, "after unmute the board produces audio");
}

#[test]
fn unknown_unattested_and_calibration_less_boards_come_up_fail_muted() {
    let s3 = fixture("S3");
    let none = ProtectedBoardDsp::admit(&s3, None, Admission::HostSimulation);
    assert_eq!(
        none.status(),
        BoardStatus::FailMuted(ProtectionError::NoCalibration)
    );

    // The canonical catalog holds hypothesis profiles: refused even with a calibration.
    let canonical = canonical_board_catalog();
    assert!(!canonical.is_empty());
    for profile in &canonical {
        let calibration = synthetic_calibration_for(profile);
        for admission in [Admission::Production, Admission::HostSimulation] {
            let dsp = ProtectedBoardDsp::admit(profile, Some(&calibration), admission);
            assert!(
                matches!(dsp.status(), BoardStatus::FailMuted(_)),
                "{} must not admit in {admission:?}",
                profile.profile_id
            );
        }
    }

    // A fixture board is refused in Production even with a calibration that fits it.
    let calibration = synthetic_calibration_for(&s3);
    let production = ProtectedBoardDsp::admit(&s3, Some(&calibration), Admission::Production);
    assert_eq!(
        production.status(),
        BoardStatus::FailMuted(ProtectionError::UnknownBoard)
    );

    // A board without a usable layout.
    let mut broken = s3.clone();
    broken.channel_routing.pop();
    let dsp = ProtectedBoardDsp::admit(&broken, Some(&calibration), Admission::HostSimulation);
    assert_eq!(
        dsp.status(),
        BoardStatus::FailMuted(ProtectionError::InvalidLayout)
    );
}

#[test]
fn a_fail_muted_board_renders_silence_and_refuses_unmute_whatever_the_volume() {
    let mut dsp = ProtectedBoardDsp::admit(&fixture("S5"), None, Admission::HostSimulation);
    assert_eq!(dsp.set_muted(false), Err(ProtectionError::UnmuteRefused));
    assert_eq!(dsp.set_user_gain(1.0), 1.0);
    for _ in 0..4 {
        let (report, out) = render(&mut dsp, &constant(0.9, -0.9));
        assert!(all_silent(&out));
        assert!(matches!(report.status, BoardStatus::FailMuted(_)));
        assert_eq!(report.applied_gain, 0.0);
    }
    assert_eq!(dsp.set_muted(true), Ok(()), "muting is always allowed");
}

#[test]
fn production_admission_needs_an_attested_profile_and_a_real_acoustically_referenced_calibration() {
    // TEST FABRICATION of an attested board, only to exercise the gate logic. Not real data.
    let mut attested = fixture("S1");
    attested.provenance = EvidenceProvenance::DirectBinaryForensics;
    attested.facts = FactStatuses::uniform(FactStatus::Attested);
    let attested = attested.with_computed_digest();
    assert!(attested.activation_blockers().is_empty());

    let mut real = synthetic_calibration_for(&attested);
    real.provenance = CalibrationProvenance {
        kind: ProvenanceKind::OwnerMeasured,
        reference: "receipt-example".to_string(),
        acoustic_qualification: Some("acoustic-receipt-example".to_string()),
    };
    let dsp = ProtectedBoardDsp::admit(&attested, Some(&real), Admission::Production);
    assert_eq!(
        dsp.status(),
        BoardStatus::Active,
        "the permitted positive case"
    );

    let refuse = |mutate: &dyn Fn(&mut BoardCalibration), expected: ProtectionError| {
        let mut calibration = real.clone();
        mutate(&mut calibration);
        let dsp = ProtectedBoardDsp::admit(&attested, Some(&calibration), Admission::Production);
        assert_eq!(dsp.status(), BoardStatus::FailMuted(expected));
    };
    refuse(
        &|c| c.provenance.kind = ProvenanceKind::Synthetic,
        ProtectionError::ProvenanceRefused,
    );
    refuse(
        &|c| c.provenance.acoustic_qualification = None,
        ProtectionError::ProvenanceRefused,
    );
    refuse(
        &|c| c.provenance.acoustic_qualification = Some("  ".to_string()),
        ProtectionError::ProvenanceRefused,
    );
    refuse(
        &|c| c.provenance.reference.clear(),
        ProtectionError::ProvenanceRefused,
    );

    // The attested board is not a synthetic fixture, so host simulation refuses it.
    let host_sim = ProtectedBoardDsp::admit(&attested, Some(&real), Admission::HostSimulation);
    assert_eq!(
        host_sim.status(),
        BoardStatus::FailMuted(ProtectionError::UnknownBoard)
    );
}

#[test]
fn a_forbidden_amplifier_policy_is_reported_as_such() {
    let mut profile = fixture("S3");
    profile.amplifier_policy = franken_board_profile::AmplifierPolicy::ForbiddenFailMuted;
    let profile = profile.with_computed_digest();
    let dsp = ProtectedBoardDsp::admit(
        &profile,
        Some(&synthetic_calibration_for(&profile)),
        Admission::HostSimulation,
    );
    assert_eq!(
        dsp.status(),
        BoardStatus::FailMuted(ProtectionError::AmplifierForbidden)
    );
}

// ---- planted malformed calibrations -----------------------------------------------------------

#[test]
fn planted_malformed_calibrations_each_fail_muted_with_the_exact_reason() {
    // S5: ch0 TweeterLeft [HP], ch1 TweeterRight [HP], ch2 MidLeft [], ch3 MidRight [], ch4 WooferCenter [LP].
    let s5 = fixture("S5");
    let ok = |s: &BoardProfile| host(s).1.status();
    assert_eq!(
        ok(&s5),
        BoardStatus::Active,
        "the unmodified calibration is the positive control"
    );

    expect(
        &s5,
        "schema",
        |c| c.schema = "ffw.d02.calibration.v0".into(),
        ProtectionError::SchemaMismatch,
    );
    expect(
        &s5,
        "profile id",
        |c| c.profile_id.push('x'),
        ProtectionError::ProfileBindingMismatch,
    );
    expect(
        &s5,
        "profile digest",
        |c| c.profile_digest = "0".repeat(64),
        ProtectionError::ProfileBindingMismatch,
    );
    expect(
        &s5,
        "measured calibration under host simulation",
        |c| c.provenance.kind = ProvenanceKind::OwnerMeasured,
        ProtectionError::ProvenanceRefused,
    );
    expect(
        &s5,
        "sample rate",
        |c| c.sample_rate_hz = 44_100,
        param(None, Param::SampleRate),
    );
    expect(
        &s5,
        "ramp too short",
        |c| c.ramp_ms = 0.5,
        param(None, Param::Ramp),
    );
    expect(
        &s5,
        "fault ramp too long",
        |c| c.fault_ramp_ms = 200.0,
        param(None, Param::FaultRamp),
    );
    expect(
        &s5,
        "source ramp NaN",
        |c| c.source_ramp_ms = f64::NAN,
        param(None, Param::SourceRamp),
    );
    expect(
        &s5,
        "channel count",
        |c| {
            c.channels.pop();
        },
        ProtectionError::ChannelCountMismatch,
    );
    expect(
        &s5,
        "roles swapped",
        |c| c.channels.swap(0, 1),
        ProtectionError::RoleMismatch { channel: 0 },
    );

    expect(
        &s5,
        "trim NaN",
        |c| c.channels[1].trim = f64::NAN,
        param(Some(1), Param::Trim),
    );
    expect(
        &s5,
        "trim zero",
        |c| c.channels[1].trim = 0.0,
        param(Some(1), Param::Trim),
    );
    expect(
        &s5,
        "max gain",
        |c| c.channels[1].max_gain = 5.0,
        param(Some(1), Param::MaxGain),
    );
    expect(
        &s5,
        "ceiling above full scale",
        |c| c.channels[1].ceiling = 1.5,
        param(Some(1), Param::Ceiling),
    );
    expect(
        &s5,
        "dc corner",
        |c| c.channels[1].dc_block_hz = 0.5,
        param(Some(1), Param::DcBlockHz),
    );
    expect(
        &s5,
        "limiter threshold above ceiling",
        |c| c.channels[1].limiter.threshold = 0.99,
        param(Some(1), Param::LimiterThreshold),
    );
    expect(
        &s5,
        "limiter attack",
        |c| c.channels[1].limiter.attack_ms = 0.0,
        param(Some(1), Param::LimiterAttack),
    );
    expect(
        &s5,
        "limiter release",
        |c| c.channels[1].limiter.release_ms = -1.0,
        param(Some(1), Param::LimiterRelease),
    );
    expect(
        &s5,
        "thermal tau",
        |c| c.channels[1].thermal.tau_s = 0.0,
        param(Some(1), Param::ThermalTau),
    );
    expect(
        &s5,
        "thermal soft",
        |c| c.channels[1].thermal.soft_ms = 0.0,
        param(Some(1), Param::ThermalSoft),
    );
    expect(
        &s5,
        "thermal hard not above soft",
        |c| c.channels[1].thermal.hard_ms = c.channels[1].thermal.soft_ms,
        param(Some(1), Param::ThermalHard),
    );

    expect(
        &s5,
        "five sections",
        |c| {
            let extra = c.channels[0].sections[0];
            c.channels[0].sections.extend([extra; 4]);
        },
        ProtectionError::TooManySections { channel: 0 },
    );
    let coefficient = ProtectionError::CoefficientInvalid {
        channel: 0,
        section: 0,
    };
    expect(
        &s5,
        "coefficient NaN",
        |c| c.channels[0].sections[0].b0 = f64::NAN,
        coefficient,
    );
    expect(
        &s5,
        "coefficient infinite",
        |c| c.channels[0].sections[0].b1 = f64::INFINITY,
        coefficient,
    );
    expect(
        &s5,
        "coefficient above 8",
        |c| c.channels[0].sections[0].b2 = 9.0,
        coefficient,
    );
    expect(
        &s5,
        "coefficient overflows f32 when stored",
        |c| c.channels[0].sections[0].b0 = 1.0e39,
        coefficient,
    );
    let unstable = ProtectionError::Unstable {
        channel: 0,
        section: 0,
    };
    expect(
        &s5,
        "pole product on the unit circle",
        |c| c.channels[0].sections[0].a2 = 1.0,
        unstable,
    );
    expect(
        &s5,
        "poles outside the unit circle",
        |c| {
            c.channels[0].sections[0].a1 = 2.5;
            c.channels[0].sections[0].a2 = 0.5;
        },
        unstable,
    );

    expect(
        &s5,
        "high-Q resonator",
        |c| {
            c.channels[0].sections = vec![BiquadSpec {
                b0: 0.001,
                b1: 0.0,
                b2: 0.0,
                a1: -1.998,
                a2: 0.9981,
            }];
        },
        ProtectionError::GainBoundExceeded { channel: 0 },
    );
    // A converged one-sample section isolates the numeric limit: bound = 2 * |b0|, limit 8.
    let one_sample = |b0: f64| {
        vec![BiquadSpec {
            b0,
            b1: 0.0,
            b2: 0.0,
            a1: 0.0,
            a2: 0.0,
        }]
    };
    assert_eq!(
        {
            let mut c = synthetic_calibration_for(&s5);
            c.channels[2].sections = one_sample(3.0);
            ProtectedBoardDsp::admit(&s5, Some(&c), Admission::HostSimulation).status()
        },
        BoardStatus::Active,
        "gain bound 6 is under the limit"
    );
    expect(
        &s5,
        "converged section above the gain limit",
        |c| c.channels[2].sections = one_sample(5.0),
        ProtectionError::GainBoundExceeded { channel: 2 },
    );
    // Passes the gain bound (about 6.8 of 8) but its intermediate bound (about 23) exceeds 16.
    expect(
        &s5,
        "intermediate range",
        |c| {
            c.channels[2].sections = vec![BiquadSpec {
                b0: 1.0,
                b1: -2.0,
                b2: 1.0,
                a1: -1.7196056842803955,
                a2: 0.81,
            }];
        },
        ProtectionError::IntermediateRangeExceeded { channel: 2 },
    );

    expect(
        &s5,
        "tweeter with no crossover",
        |c| c.channels[0].sections.clear(),
        ProtectionError::BandPolicyViolated { channel: 0 },
    );
    expect(
        &s5,
        "tweeter with a low-pass",
        |c| c.channels[0].sections = vec![butterworth2_lowpass(2000.0, FS)],
        ProtectionError::BandPolicyViolated { channel: 0 },
    );
    // (A 2.2 kHz high-pass passes the intermediate bound at ~14.3; a 100 Hz one would trip it at ~20.3.)
    expect(
        &s5,
        "woofer with a high-pass",
        |c| c.channels[4].sections = vec![butterworth2_highpass(2_200.0, FS)],
        ProtectionError::BandPolicyViolated { channel: 4 },
    );
    expect(
        &fixture("Sub"),
        "sub with no low-pass",
        |c| c.channels[0].sections.clear(),
        ProtectionError::BandPolicyViolated { channel: 0 },
    );

    // Reporting order is fixed: parameters before sections, and lower channels before higher.
    expect(
        &s5,
        "parameter before section",
        |c| {
            c.channels[0].trim = f64::NAN;
            c.channels[0].sections[0].b0 = f64::NAN;
        },
        param(Some(0), Param::Trim),
    );
    expect(
        &s5,
        "lower channel first",
        |c| {
            c.channels[1].trim = 0.0;
            c.channels[0].sections[0].a2 = 1.0;
        },
        unstable,
    );
}

#[test]
fn coefficients_are_judged_on_the_stored_f32_value() {
    // 8.0000000001 stores as exactly 8.0, which is within the limit; 8.001 is not.
    let section = |b0: f64| BiquadSpec {
        b0,
        b1: 0.0,
        b2: 0.0,
        a1: 0.0,
        a2: 0.0,
    };
    assert!(Section::from_spec(&section(8.000_000_000_1)).is_ok());
    assert_eq!(
        Section::from_spec(&section(8.001)).unwrap_err(),
        ProtectionError::CoefficientInvalid {
            channel: 0,
            section: 0
        }
    );
    // A finite f64 that overflows f32 is refused: the realization cannot hold it.
    assert!(Section::from_spec(&section(1.0e39)).is_err());
}

#[test]
fn calibration_json_round_trips_and_rejects_malformed_documents() {
    let profile = fixture("S3");
    let calibration = synthetic_calibration_for(&profile);
    let text = serde_json::to_string(&calibration).expect("serialize");
    assert_eq!(BoardCalibration::from_json(&text), Ok(calibration.clone()));

    let malformed = ProtectionError::MalformedCalibration;
    assert_eq!(BoardCalibration::from_json("not json"), Err(malformed));
    assert_eq!(BoardCalibration::from_json("{}"), Err(malformed));
    let with_extra = text.replacen('{', "{\"unexpected\":1,", 1);
    assert_eq!(
        BoardCalibration::from_json(&with_extra),
        Err(malformed),
        "unknown fields are refused"
    );
    let wrong_type = text.replace("\"ramp_ms\":10.0", "\"ramp_ms\":\"fast\"");
    assert_ne!(wrong_type, text);
    assert_eq!(BoardCalibration::from_json(&wrong_type), Err(malformed));
}

// ---- realization primitives (closed forms) ------------------------------------------------------

#[test]
fn butterworth_designs_have_the_textbook_dc_and_nyquist_gains() {
    for fc in [120.0, 300.0, 2_000.0, 2_200.0] {
        let lp = butterworth2_lowpass(fc, FS);
        let hp = butterworth2_highpass(fc, FS);
        // 1 + a1 + a2 is ~2e-4 at 120 Hz, so its rounding error is amplified: allow 1e-9.
        let dc_lp = (lp.b0 + lp.b1 + lp.b2) / (1.0 + lp.a1 + lp.a2);
        assert!((dc_lp - 1.0).abs() < 1e-9, "LP {fc} Hz DC gain {dc_lp}");
        assert!(
            (hp.b0 + hp.b1 + hp.b2).abs() < 1e-15,
            "HP {fc} Hz has a zero at DC"
        );
        assert!(lp.a2.abs() < 1.0 && hp.a2.abs() < 1.0);
    }
}

#[test]
fn section_step_responses_settle_to_their_dc_gain() {
    let mut lp = Section::from_spec(&butterworth2_lowpass(300.0, FS)).unwrap();
    let mut last = 0.0;
    for _ in 0..20_000 {
        last = lp.process(1.0);
    }
    // The realized DC gain is sum(b)/(1+a1+a2) of the f32-stored values; 1+a1+a2 is ~1.5e-3 at
    // 300 Hz, so f32 quantization of a1/a2 moves it by up to ~1e-4.
    assert!(
        (last - 1.0).abs() < 1e-3,
        "low-pass step settles to 1, got {last}"
    );

    let mut hp = Section::from_spec(&butterworth2_highpass(2_200.0, FS)).unwrap();
    let first = hp.process(1.0);
    assert!(first > 0.5, "a step passes a high-pass at first: {first}");
    for _ in 0..2_000 {
        last = hp.process(1.0);
    }
    assert!(last.abs() < 1e-4, "high-pass step decays to 0, got {last}");
}

#[test]
fn low_cutoff_sections_track_an_f64_evaluation_of_the_same_stored_filter() {
    // Regression for the b9 divergence. With f32 arithmetic and state, the 120 Hz and 300 Hz
    // low-pass step responses drifted 5.2e-4 and 6.5e-5 from an exact evaluation of the very same
    // stored coefficients (poles at radius 0.989 and 0.973). The state is f64 now.
    for fc in [120.0, 300.0, 2_000.0] {
        let spec = butterworth2_lowpass(fc, FS);
        let mut section = Section::from_spec(&spec).expect("admissible");
        let c = [spec.b0, spec.b1, spec.b2, spec.a1, spec.a2].map(|v| f64::from(v as f32));
        let (mut x1, mut x2, mut y1, mut y2) = (0.0f64, 0.0f64, 0.0f64, 0.0f64);
        let mut worst = 0.0f64;
        for _ in 0..2_000 {
            let y = c[0] + c[1] * x1 + c[2] * x2 - c[3] * y1 - c[4] * y2; // x[n] = 1
            (x2, x1, y2, y1) = (x1, 1.0, y1, y);
            worst = worst.max((f64::from(section.process(1.0)) - y).abs());
        }
        // Only the final rounding of the output to f32 remains (about 6e-8).
        assert!(worst < 1.0e-6, "{fc} Hz low-pass: worst difference {worst}");
    }
}

#[test]
fn dc_rejector_decays_a_constant_like_r_to_the_n() {
    let mut dc = DcRejector::new(5.0, FS);
    let r = (-2.0 * PI * 5.0 / FS).exp();
    for n in 0..200 {
        let got = f64::from(dc.process(0.5));
        let want = 0.5 * r.powi(n);
        assert!((got - want).abs() < 1e-5, "n={n}: {got} vs {want}");
    }
    dc.reset();
    assert_eq!(
        dc.process(0.25),
        0.25,
        "after reset the first sample passes unchanged"
    );
}

#[test]
fn smoothing_coefficient_matches_one_minus_exp() {
    let want = 1.0 - (-1.0f64 / 48.0).exp();
    assert!((f64::from(smoothing_coefficient(1.0, FS)) - want).abs() < 1e-7);
    for degenerate in [0.0, -1.0, f64::NAN, f64::INFINITY] {
        assert_eq!(smoothing_coefficient(degenerate, FS), 1.0, "{degenerate}");
    }
}

#[test]
fn limiter_attack_and_release_follow_their_closed_forms() {
    let a_attack = smoothing_coefficient(1.0, FS);
    let a_release = smoothing_coefficient(50.0, FS);
    let (attack, release) = (f64::from(a_attack), f64::from(a_release));
    let mut limiter = Limiter::new(0.5, a_attack, a_release);

    // Below the threshold nothing moves.
    for _ in 0..100 {
        assert_eq!(limiter.process(0.25), 0.25);
    }
    assert_eq!(limiter.gain(), 1.0);

    // A constant 1.0 pulls the gain toward 0.5: g_n = 0.5 + 0.5 * (1 - a)^(n+1).
    for n in 0..400 {
        let out = limiter.process(1.0);
        let want = 0.5 + 0.5 * (1.0 - attack).powi(n + 1);
        assert!(
            (f64::from(limiter.gain()) - want).abs() < 2e-5,
            "attack n={n}"
        );
        assert!((f64::from(out) - want).abs() < 2e-5);
    }
    let held = f64::from(limiter.gain());
    assert!(
        (held - 0.5).abs() < 1e-3,
        "settled near the threshold ratio: {held}"
    );

    // Back below threshold the gain releases toward 1: g_k = 1 - (1 - g0) * (1 - a_rel)^k.
    for k in 1..=2_000 {
        limiter.process(0.0);
        let want = 1.0 - (1.0 - held) * (1.0 - release).powi(k);
        // A slow one-pole in f32 accumulates rounding of about eps/alpha; 3e-4 still rejects a
        // wrong time constant by orders of magnitude.
        assert!(
            (f64::from(limiter.gain()) - want).abs() < 3e-4,
            "release k={k}"
        );
    }
}

// ---- gain ceiling, output ceiling, thermal, ramps ----------------------------------------------------

#[test]
fn the_gain_ceiling_caps_trim_times_user_gain() {
    let profile = fixture("S3"); // ch0 MidLeft takes the left channel with no sections
    let mut calibration = synthetic_calibration_for(&profile);
    calibration.channels[0].trim = 4.0;
    calibration.channels[0].max_gain = 0.5;
    let mut dsp = ProtectedBoardDsp::admit(&profile, Some(&calibration), Admission::HostSimulation);
    assert_eq!(dsp.status(), BoardStatus::Active);
    settle(&mut dsp);
    let (_, out) = render(&mut dsp, &impulse(0.1));
    // The first sample of an impulse passes DC rejection unchanged: 0.1 * min(4 * 1, 0.5) = 0.05.
    assert_eq!(out.samples[0][0], 1638, "0.05 * 32768 = 1638.4");
}

#[test]
fn the_hard_output_ceiling_catches_a_limiter_overshoot_and_counts_it() {
    let profile = fixture("S3");
    let mut calibration = synthetic_calibration_for(&profile);
    calibration.channels[0].ceiling = 0.5;
    calibration.channels[0].limiter.threshold = 0.5;
    let mut dsp = ProtectedBoardDsp::admit(&profile, Some(&calibration), Admission::HostSimulation);
    settle(&mut dsp);
    let (report, out) = render(&mut dsp, &impulse_left(1.0));
    // No look-ahead: the first sample enters at ~0.99 gain, so the ceiling clamps it to 0.5.
    assert_eq!(out.samples[0][0], 16_384);
    assert_eq!(report.clipped_samples, 1);
    assert!(report.min_limiter_gain < 1.0);
}

#[test]
fn thermal_history_scales_output_then_latches_a_fault_and_must_cool_before_clearing() {
    let profile = fixture("S3");
    let mut calibration = synthetic_calibration_for(&profile);
    {
        let thermal = &mut calibration.channels[0].thermal;
        thermal.tau_s = 0.05; // alpha ~ 4.17e-4 per sample
        thermal.soft_ms = 0.05;
        thermal.hard_ms = 0.2;
    }
    let mut dsp = ProtectedBoardDsp::admit(&profile, Some(&calibration), Admission::HostSimulation);
    settle(&mut dsp);

    // A +-0.6 Nyquist square has v^2 ~ 0.36. level_n = 0.36 * (1 - (1-alpha)^n): soft (0.05) is
    // crossed near sample 360 and hard (0.2) near sample 1946, i.e. block 7.
    let drive = nyquist_left(0.6);
    let mut fault_block = None;
    let mut scaled_seen = false;
    for block in 0..16 {
        let (report, _) = render(&mut dsp, &drive);
        scaled_seen |= report.thermal_scaled_samples > 0;
        if matches!(report.status, BoardStatus::Faulted(_)) {
            fault_block = Some(block);
            break;
        }
    }
    let fault_block = fault_block.expect("sustained overdrive must latch a thermal fault");
    assert!(
        (6..=9).contains(&fault_block),
        "fault in block {fault_block}"
    );
    assert!(
        scaled_seen,
        "output was thermally scaled before the hard limit"
    );
    assert_eq!(
        dsp.status(),
        BoardStatus::Faulted(FaultCode::ThermalHard { channel: 0 })
    );
    assert_eq!(dsp.faults_total(), 1);

    // The whole board ramps to silence (2 ms) and stays there while the fault is latched.
    render(&mut dsp, &drive);
    let (report, out) = render(&mut dsp, &drive);
    assert!(all_silent(&out), "a faulted board is silent");
    assert_eq!(report.applied_gain, 0.0);
    assert_eq!(dsp.set_muted(false), Err(ProtectionError::UnmuteRefused));
    assert_eq!(
        dsp.clear_fault(),
        Err(ProtectionError::NotCooled),
        "still hot"
    );
    let hot = dsp.thermal_level(0).expect("channel 0");
    assert!(hot > 0.05, "thermal level is kept while faulted: {hot}");

    // Cooling continues on silence (decay by (1-alpha) per frame); ~13 blocks reach the soft limit.
    for _ in 0..20 {
        render(&mut dsp, &StereoAudioBlock::silence(0));
    }
    let cooled = dsp.thermal_level(0).expect("channel 0");
    assert!(cooled < 0.05 && cooled < hot, "cooled to {cooled}");
    assert_eq!(dsp.clear_fault(), Ok(()));
    assert_eq!(dsp.status(), BoardStatus::Active);
    assert_eq!(
        dsp.thermal_level(0),
        Some(cooled),
        "clearing a fault keeps thermal history"
    );

    // The board then ramps back up and produces audio again.
    let mut heard = false;
    for _ in 0..3 {
        heard |= !all_silent(&render(&mut dsp, &nyquist_left(0.3)).1);
    }
    assert!(heard);
}

#[test]
fn a_corrupted_filter_state_latches_a_fault_and_silences_that_channel_at_once() {
    for (state, expected) in [
        (f32::NAN, FaultCode::NonFiniteState { channel: 0 }),
        (1.0e6, FaultCode::StateRange { channel: 0 }),
    ] {
        let profile = fixture("S5");
        let (_, mut dsp) = host(&profile);
        settle(&mut dsp);
        for _ in 0..2 {
            render(&mut dsp, &nyquist_left(0.3));
        }
        dsp.corrupt_section_state_for_test(0, state);
        let (report, out) = render(&mut dsp, &nyquist_left(0.3));
        assert_eq!(dsp.status(), BoardStatus::Faulted(expected), "{state}");
        assert_eq!(report.status, BoardStatus::Faulted(expected));
        assert_eq!(
            peak(&out, 0),
            0,
            "the faulted channel is silenced immediately"
        );
        for lane in &out.samples[..out.channels] {
            assert!(lane.iter().all(|&s| s != i16::MIN), "no full-scale burst");
        }
        render(&mut dsp, &nyquist_left(0.3));
        let (_, out) = render(&mut dsp, &nyquist_left(0.3));
        assert!(
            all_silent(&out),
            "the board ramps to silence and stays there"
        );
    }
}

#[test]
fn the_user_gain_reaches_the_device_by_a_bounded_slew_never_a_step() {
    let (_, mut dsp) = host(&fixture("S3"));
    dsp.set_muted(false).unwrap();
    let step = 1.0 / (10.0e-3 * FS) as f32; // ramp_ms = 10
    let mut previous = 0.0f32;
    let mut reached_at = None;
    for block in 0..4 {
        let mut out = ProtectedOutput::new();
        // Render one frame at a time so the applied gain is observable per sample.
        for frame in 0..FRAMES_PER_BLOCK {
            let mut one = StereoAudioBlock::silence(0);
            one.frames = 1;
            dsp.render_into(&one, &mut out);
            let gain = dsp.applied_gain();
            assert!(
                gain - previous <= step * 1.0001,
                "block {block} frame {frame}: {previous}->{gain}"
            );
            if gain >= 1.0 && reached_at.is_none() {
                reached_at = Some(block * FRAMES_PER_BLOCK + frame);
            }
            previous = gain;
        }
    }
    let reached = reached_at.expect("the gain reaches the user value");
    assert!(
        (470..=490).contains(&reached),
        "0 -> 1 takes ~480 samples, got {reached}"
    );
    // And back down on mute.
    dsp.set_muted(true).unwrap();
    for _ in 0..4 {
        render(&mut dsp, &StereoAudioBlock::silence(0));
    }
    assert_eq!(dsp.applied_gain(), 0.0);
}

#[test]
fn non_finite_input_becomes_silence_and_is_counted_not_faulted() {
    let (_, mut dsp) = host(&fixture("S3"));
    settle(&mut dsp);
    let mut block = nyquist_left(0.4);
    block.left[3] = f32::NAN;
    block.left[4] = f32::INFINITY;
    block.right[5] = f32::NEG_INFINITY;
    let (report, out) = render(&mut dsp, &block);
    assert_eq!(report.input_non_finite, 3);
    assert_eq!(
        dsp.status(),
        BoardStatus::Active,
        "bad input is not a protection fault"
    );
    assert!(
        out.samples[0][..256]
            .iter()
            .all(|&s| i32::from(s).abs() < 32_767)
    );
}

#[test]
fn zero_length_and_partial_blocks_are_tolerated() {
    let (_, mut dsp) = host(&fixture("S5"));
    settle(&mut dsp);
    let mut empty = constant(0.5, 0.5);
    empty.frames = 0;
    let before = dsp.applied_gain();
    let (report, out) = render(&mut dsp, &empty);
    assert_eq!((report.frames, out.frames), (0, 0));
    assert_eq!(
        dsp.applied_gain(),
        before,
        "an empty block advances nothing"
    );

    let mut partial = nyquist_left(0.4);
    partial.frames = 7;
    let (report, out) = render(&mut dsp, &partial);
    assert_eq!((report.frames, out.frames, out.channels), (7, 7, 5));
    for lane in &out.samples[..5] {
        assert!(
            lane[7..].iter().all(|&s| s == 0),
            "nothing past the 7th frame"
        );
    }
    let mut oversize = constant(0.1, 0.1);
    oversize.frames = FRAMES_PER_BLOCK + 50;
    assert_eq!(
        render(&mut dsp, &oversize).0.frames,
        FRAMES_PER_BLOCK,
        "frames are clamped"
    );
}

// ---- board-lifetime history ----------------------------------------------------------------------

#[test]
fn seek_reconnect_and_source_replacement_never_reset_protection_history() {
    let (_, mut dsp) = host(&fixture("S3"));
    settle(&mut dsp);
    for _ in 0..6 {
        render(&mut dsp, &nyquist_left(0.9)); // above the 0.8 limiter threshold
    }
    for event in [
        SourceEvent::Seek,
        SourceEvent::Reconnect,
        SourceEvent::SourceReplaced,
    ] {
        let thermal = dsp.thermal_level(0).expect("channel 0");
        let limiter = dsp.limiter_gain(0).expect("channel 0");
        assert!(
            thermal > 0.0 && limiter < 0.95,
            "nonzero history before {event:?}: {thermal} {limiter}"
        );
        let (user, muted, status) = (dsp.user_gain(), dsp.is_muted(), dsp.status());

        dsp.on_source_event(event);
        assert_eq!(dsp.thermal_level(0), Some(thermal), "{event:?}");
        assert_eq!(dsp.limiter_gain(0), Some(limiter), "{event:?}");
        assert_eq!(
            (dsp.user_gain(), dsp.is_muted(), dsp.status()),
            (user, muted, status)
        );

        // Only a fade-in from silence is applied. The fade advances before each sample, so the
        // first sample carries 0.9 / 960 of full scale (about 31 LSB) and the fade ramps over
        // 20 ms (1/960 per sample, ~0.267 after one block), while the limiter keeps its history
        // and releases only at its own rate.
        let (report, out) = render(&mut dsp, &nyquist_left(0.9));
        assert!(
            i32::from(out.samples[0][0]).abs() < 40,
            "{event:?}: fade-in starts near silence"
        );
        assert!(
            peak(&out, 0) > 6_000,
            "{event:?}: and has grown by the end of the block"
        );
        assert!(
            (0.26..0.27).contains(&report.source_fade),
            "{event:?}: {}",
            report.source_fade
        );
        assert!(
            dsp.limiter_gain(0).expect("channel 0") < 0.95,
            "{event:?}: limiter history survives"
        );
        for _ in 0..6 {
            render(&mut dsp, &nyquist_left(0.9)); // fade completes and the limiter re-engages
        }
    }
}

#[test]
fn a_valid_profile_switch_drains_to_silence_swaps_and_carries_history() {
    let profile = fixture("S3");
    let (calibration, mut dsp) = host(&profile);
    settle(&mut dsp);
    for _ in 0..5 {
        render(&mut dsp, &nyquist_left(0.5));
    }
    let before = dsp.thermal_level(0).expect("channel 0");
    assert!(before > 0.0);

    let mut next = calibration.clone();
    next.channels[2].sections = vec![butterworth2_highpass(3_000.0, FS)];
    dsp.request_profile_switch(&profile, &next, Admission::HostSimulation)
        .expect("valid candidate");
    assert!(dsp.has_pending_switch());

    // One frame at a time, so the instant of the swap is observable.
    let mut swapped = None;
    for frame in 0..2_000usize {
        let mut one = StereoAudioBlock::silence(0);
        one.frames = 1;
        one.left[0] = if frame.is_multiple_of(2) { 0.5 } else { -0.5 };
        render(&mut dsp, &one);
        if swapped.is_none() && !dsp.has_pending_switch() {
            assert_eq!(
                dsp.applied_gain(),
                0.0,
                "the swap happens only at exact silence"
            );
            let at_swap = dsp.thermal_level(0).expect("channel 0");
            assert!(
                at_swap > 0.5 * before,
                "thermal history carried over: {before} -> {at_swap}"
            );
            swapped = Some(frame);
        }
    }
    let swapped = swapped.expect("the switch completes");
    assert!(
        (470..=490).contains(&swapped),
        "the 10 ms drain takes ~480 samples, swapped at {swapped}"
    );
    assert_eq!(dsp.status(), BoardStatus::Active);
    assert!(
        dsp.applied_gain() > 0.99,
        "the gain ramps back up after the swap"
    );
}

#[test]
fn an_unsafe_profile_switch_leaves_the_board_fail_muted_until_a_valid_one_is_admitted() {
    let profile = fixture("S3");
    let (calibration, mut dsp) = host(&profile);
    settle(&mut dsp);
    for _ in 0..4 {
        render(&mut dsp, &nyquist_left(0.5));
    }
    let thermal = dsp.thermal_level(0).expect("channel 0");

    let mut unsafe_calibration = calibration.clone();
    unsafe_calibration.channels[2].sections[0].a2 = 1.5;
    let expected = ProtectionError::Unstable {
        channel: 2,
        section: 0,
    };
    assert_eq!(
        dsp.request_profile_switch(&profile, &unsafe_calibration, Admission::HostSimulation),
        Err(expected)
    );
    assert_eq!(dsp.status(), BoardStatus::FailMuted(expected));
    assert!(!dsp.has_pending_switch());
    render(&mut dsp, &nyquist_left(0.5));
    let (_, out) = render(&mut dsp, &nyquist_left(0.5));
    assert!(all_silent(&out), "ramped to silence, then silent");
    assert_eq!(dsp.set_muted(false), Err(ProtectionError::UnmuteRefused));

    // A different board's profile id is never a switch.
    let other = fixture("S5");
    assert_eq!(
        dsp.request_profile_switch(
            &other,
            &synthetic_calibration_for(&other),
            Admission::HostSimulation
        ),
        Err(ProtectionError::ProfileBindingMismatch)
    );

    // Re-admission with a valid calibration restores audio, and the history is still there.
    dsp.request_profile_switch(&profile, &calibration, Admission::HostSimulation)
        .expect("valid");
    let mut heard = false;
    for _ in 0..6 {
        heard |= !all_silent(&render(&mut dsp, &nyquist_left(0.5)).1);
    }
    assert_eq!(dsp.status(), BoardStatus::Active);
    assert!(heard);
    assert!(
        dsp.thermal_level(0).expect("channel 0") > 0.5 * thermal,
        "history survives re-admission"
    );
}

#[test]
fn a_latched_fault_blocks_profile_switches_until_cleared() {
    let profile = fixture("S5");
    let (calibration, mut dsp) = host(&profile);
    settle(&mut dsp);
    dsp.corrupt_section_state_for_test(0, f32::NAN);
    render(&mut dsp, &nyquist_left(0.3));
    assert!(matches!(dsp.status(), BoardStatus::Faulted(_)));
    assert_eq!(
        dsp.request_profile_switch(&profile, &calibration, Admission::HostSimulation),
        Err(ProtectionError::FaultLatched)
    );
}

#[test]
fn the_compatibility_wrapper_matches_the_preallocated_path() {
    let profile = fixture("S5");
    let (_, mut a) = host(&profile);
    let (_, mut b) = host(&profile);
    settle(&mut a);
    settle(&mut b);
    let input = nyquist_left(0.3);
    let (_, out) = render(&mut a, &input);
    let block = b.render_block(&input);
    assert_eq!(block.profile_id, profile.profile_id);
    assert_eq!((block.frames, block.channels), (out.frames, out.channels));
    for (got, want) in block.channel_samples.iter().zip(out.samples.iter()) {
        assert_eq!(got, want);
    }
}
