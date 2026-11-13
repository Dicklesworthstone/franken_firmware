//! Unit tests for `D02`. Expected values here are closed forms or hand-derived numbers; the
//! independent Python reference (`tests/d02/`) supplies the golden step/impulse responses and the
//! replayed scenarios, and `tests/d02_vectors.rs` compares them with this implementation.

use super::calibration::{BOUND_MARGIN, StageBound, chain_bounds, dc_pole, quantize_section};
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
    // A +24 dB boost at 500 Hz followed by a 0.15 trim: the cascade's final gain bound (3.09) is far inside 8, but the
    // middle node's worst case is 20.4 against the limit of 16, and the realized chain really reaches it
    // (`the_refusal_is_warranted_the_refused_boost_really_overflows_and_the_admitted_one_does_not`). This case used
    // to be b = [1, -2, 1], a1 = -1.7196056842803955, a2 = 0.81, refused at a product bound of 23; its exact worst
    // case is 3.5, so it is admitted now and is a positive control in
    // `designs_the_product_bound_refused_are_admitted_and_run_without_a_fault`.
    expect(
        &s5,
        "intermediate range",
        |c| c.channels[2].sections = vec![boost_24_db(), gain_section(0.15)],
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
    // (A 2.2 kHz high-pass is within both bounds; the band policy is what refuses it on a woofer.)
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
fn admitted_profile_digest_changes_only_when_a_validated_switch_installs() {
    let profile = fixture("S3");
    let absent = ProtectedBoardDsp::admit(&profile, None, Admission::HostSimulation);
    assert_eq!(absent.profile_digest(), None);
    let (_, mut dsp) = host(&profile);
    assert_eq!(
        dsp.profile_digest(),
        Some(profile.integrity_sha256.as_bytes())
    );
    settle(&mut dsp);
    for _ in 0..4 {
        render(&mut dsp, &nyquist_left(0.5));
    }
    let thermal = dsp.thermal_level(0).unwrap();
    assert!(thermal > 0.0);

    let mut other = profile.clone();
    other.model_name.push_str(" fixture variant");
    other = other.with_computed_digest();
    assert_eq!(other.profile_id, profile.profile_id);
    assert_ne!(other.integrity_sha256, profile.integrity_sha256);
    assert!(other.verify_integrity().is_ok());
    let calibration = synthetic_calibration_for(&other);
    let mut invalid = calibration.clone();
    invalid.channels[2].sections[0].a2 = 1.5;
    assert!(
        dsp.request_profile_switch(&other, &invalid, Admission::HostSimulation)
            .is_err()
    );
    assert_eq!(
        dsp.profile_digest(),
        Some(profile.integrity_sha256.as_bytes())
    );
    assert_eq!(dsp.thermal_level(0), Some(thermal));
    assert!(matches!(dsp.status(), BoardStatus::FailMuted(_)));

    dsp.request_profile_switch(&other, &calibration, Admission::HostSimulation)
        .unwrap();
    assert!(dsp.has_pending_switch());
    assert_eq!(
        dsp.profile_digest(),
        Some(profile.integrity_sha256.as_bytes())
    );
    for _ in 0..16 {
        if !dsp.has_pending_switch() {
            break;
        }
        render(&mut dsp, &StereoAudioBlock::silence(0));
    }
    assert!(!dsp.has_pending_switch());
    assert_eq!(
        dsp.profile_digest(),
        Some(other.integrity_sha256.as_bytes())
    );
    assert_eq!(dsp.status(), BoardStatus::Active);
    assert!(dsp.thermal_level(0).unwrap() > 0.0);
}

#[test]
fn profile_pin_rejects_retarget_and_pending_mismatch_but_allows_matching_calibration() {
    let profile = fixture("S3");
    let mut other = profile.clone();
    other.model_name.push_str(" fixture variant");
    other = other.with_computed_digest();
    let calibration = synthetic_calibration_for(&profile);
    let other_calibration = synthetic_calibration_for(&other);
    let (_, mut dsp) = host(&profile);
    settle(&mut dsp);
    render(&mut dsp, &nyquist_left(0.5));
    let thermal = dsp.thermal_level(0);
    dsp.bind_profile_digest(profile.integrity_sha256.as_bytes())
        .unwrap();
    assert_eq!(
        dsp.bind_profile_digest(other.integrity_sha256.as_bytes()),
        Err(ProtectionError::ProfileBindingMismatch)
    );
    assert_eq!(
        dsp.request_profile_switch(&other, &other_calibration, Admission::HostSimulation),
        Err(ProtectionError::ProfileBindingMismatch)
    );
    assert_eq!(
        dsp.profile_digest(),
        Some(profile.integrity_sha256.as_bytes())
    );
    assert_eq!(dsp.status(), BoardStatus::Active);
    assert_eq!(dsp.thermal_level(0), thermal);
    assert!(!dsp.has_pending_switch());
    dsp.request_profile_switch(&profile, &calibration, Admission::HostSimulation)
        .unwrap();
    assert!(dsp.has_pending_switch());

    let (_, mut unbound) = host(&profile);
    unbound
        .request_profile_switch(&other, &other_calibration, Admission::HostSimulation)
        .unwrap();
    assert_eq!(
        unbound.bind_profile_digest(profile.integrity_sha256.as_bytes()),
        Err(ProtectionError::ProfileBindingMismatch)
    );
    assert!(unbound.has_pending_switch());
    assert_eq!(
        unbound.profile_digest(),
        Some(profile.integrity_sha256.as_bytes())
    );

    let mut blank = ProtectedBoardDsp::admit(&profile, None, Admission::HostSimulation);
    blank
        .bind_profile_digest(profile.integrity_sha256.as_bytes())
        .unwrap();
    assert_eq!(blank.profile_digest(), None);
    assert!(matches!(blank.status(), BoardStatus::FailMuted(_)));
    blank
        .request_profile_switch(&profile, &calibration, Admission::HostSimulation)
        .unwrap();
    render(&mut blank, &StereoAudioBlock::silence(0));
    assert_eq!(
        blank.profile_digest(),
        Some(profile.integrity_sha256.as_bytes())
    );
    assert_eq!(blank.status(), BoardStatus::Active);
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

// ---- the admitted bound against the realized chain ------------------------------------------------------------
//
// `calibration::chain_bounds` says how large the DC rejector, every section output and both DF2T states can get for
// |input| <= 1. These tests measure the same thing. For each quantity the input is the sign of the time-reversed impulse
// response from the chain input to that quantity (computed here in direct form I, independently of `Section`), which
// makes that quantity reach its exact L1 norm; the REAL `DcRejector` (f32) and `Section`s (f64 state, f32 output) are
// driven with it and the largest value they reach is recorded. `tests/d02/realized_chain.py` does the same with an
// operation-for-operation emulation, and the numbers pinned below come from `tests/d02/reference.py`, not from this code.

/// Samples driven through the chain: twice the horizon, so the part of the response past it is exercised.
const RUN: usize = 2 * L1_HORIZON;
const QUANTITY_NAMES: [&str; 3] = ["y", "z1", "z2"];

fn gain_section(gain: f64) -> BiquadSpec {
    BiquadSpec {
        b0: gain,
        b1: 0.0,
        b2: 0.0,
        a1: 0.0,
        a2: 0.0,
    }
}

/// RBJ peaking boost, +20 dB at 1 kHz, Q 1: `reference.peaking(1000, 20, 1)`.
fn boost_20_db() -> BiquadSpec {
    BiquadSpec {
        b0: 1.1819861960991969,
        b1: -1.942794327422395,
        b2: 0.7775724269898705,
        a1: -1.942794327422395,
        a2: 0.9595586230890674,
    }
}

/// RBJ peaking boost, +24 dB at 500 Hz, Q 2: `reference.peaking(500, 24, 2)`.
fn boost_24_db() -> BiquadSpec {
    BiquadSpec {
        b0: 1.060737050971506,
        b1: -1.9875546993106874,
        b2: 0.9310822864354036,
        a1: -1.9875546993106874,
        a2: 0.9918193374069095,
    }
}

struct Design {
    name: &'static str,
    dc_hz: f64,
    sections: Vec<BiquadSpec>,
}

fn design(name: &'static str, dc_hz: f64, sections: Vec<BiquadSpec>) -> Design {
    Design {
        name,
        dc_hz,
        sections,
    }
}

/// The committed designs: the six `D02-DESIGN` filters, the ordinary low-corner high-passes that the product bound refused,
/// cascades, a boost whose middle node is large, a pure gain (where the product bound is already exact), and two designs
/// with a 1 Hz DC corner, where the rejector has not settled by the end of the horizon (R^8191 = 0.34).
fn designs() -> Vec<Design> {
    let lp = |fc: f64| butterworth2_lowpass(fc, FS);
    let hp = |fc: f64| butterworth2_highpass(fc, FS);
    vec![
        design("LP120", 5.0, vec![lp(120.0)]),
        design("LP300", 5.0, vec![lp(300.0)]),
        design("LP2000", 5.0, vec![lp(2_000.0)]),
        design("HP2200", 5.0, vec![hp(2_200.0)]),
        design("HP3000", 5.0, vec![hp(3_000.0)]),
        design("HP100", 5.0, vec![hp(100.0)]),
        design("HP60", 5.0, vec![hp(60.0)]),
        design("HP20", 5.0, vec![hp(20.0)]),
        design("LR4 LP1000", 5.0, vec![lp(1_000.0), lp(1_000.0)]),
        design("HP60 + LP2000", 5.0, vec![hp(60.0), lp(2_000.0)]),
        design(
            "boost +20 dB then trim",
            5.0,
            vec![boost_20_db(), gain_section(0.25)],
        ),
        design("gain 3", 5.0, vec![gain_section(3.0)]),
        design("HP60, 1 Hz DC corner", 1.0, vec![hp(60.0)]),
        design("LP120, 1 Hz DC corner", 1.0, vec![lp(120.0)]),
    ]
}

fn named(name: &str) -> Design {
    designs()
        .into_iter()
        .find(|design| design.name == name)
        .expect("a committed design with that name")
}

fn stored_sections(sections: &[BiquadSpec]) -> Vec<[f64; 5]> {
    sections
        .iter()
        .enumerate()
        .map(|(k, spec)| {
            let index = u8::try_from(k).expect("section index");
            quantize_section(spec, 0, index)
                .expect("a stored section")
                .map(f64::from)
        })
        .collect()
}

fn component(bound: &StageBound, index: usize) -> f64 {
    [bound.y, bound.z1, bound.z2][index]
}

/// Independent f64 impulse responses from the chain input to `y`, `z1` and `z2` of every section. Direct form I gives `y`;
/// the DF2T states follow from `z2[n] = b2 x[n] - a2 y[n]` and `z1[n] = b1 x[n] - a1 y[n] + z2[n-1]`. The rejector's
/// response is written in closed form here (`1`, then `-(1 - R) R^(i-1)`); the bound uses the recurrence.
fn exact_responses(dc_r: f64, stored: &[[f64; 5]], n: usize) -> Vec<[Vec<f64>; 3]> {
    let mut signal: Vec<f64> = (0..n)
        .map(|i| {
            if i == 0 {
                1.0
            } else {
                -(1.0 - dc_r) * dc_r.powf((i - 1) as f64)
            }
        })
        .collect();
    let mut responses = Vec::with_capacity(stored.len());
    for c in stored {
        let (mut x1, mut x2, mut y1, mut y2) = (0.0f64, 0.0f64, 0.0f64, 0.0f64);
        let mut y_response: Vec<f64> = Vec::with_capacity(n);
        let mut z1_response: Vec<f64> = Vec::with_capacity(n);
        let mut z2_response: Vec<f64> = Vec::with_capacity(n);
        for &x in &signal {
            let y = c[0] * x + c[1] * x1 + c[2] * x2 - c[3] * y1 - c[4] * y2;
            let z2 = c[2] * x - c[4] * y;
            let z1 = c[1] * x - c[3] * y + z2_response.last().copied().unwrap_or(0.0);
            y_response.push(y);
            z1_response.push(z1);
            z2_response.push(z2);
            x2 = x1;
            x1 = x;
            y2 = y1;
            y1 = y;
        }
        signal.clone_from(&y_response);
        responses.push([y_response, z1_response, z2_response]);
    }
    responses
}

/// The input in [-1, 1] that makes the last output equal the L1 norm of `response`.
fn adversarial(response: &[f64]) -> Vec<f32> {
    response
        .iter()
        .rev()
        .map(|&h| if h >= 0.0 { 1.0 } else { -1.0 })
        .collect()
}

/// Drive the real rejector and sections; the largest `|y|` (the f32 output), `|z1|` and `|z2|` of each section.
fn realize(dc_hz: f64, sections: &[BiquadSpec], input: &[f32]) -> Vec<[f64; 3]> {
    let mut rejector = DcRejector::new(dc_hz, FS);
    let mut chain: Vec<Section> = sections
        .iter()
        .map(|spec| Section::from_spec(spec).expect("an admissible section"))
        .collect();
    let mut peaks = vec![[0.0f64; 3]; chain.len()];
    for &x in input {
        let mut value = rejector.process(x);
        for (section, peak) in chain.iter_mut().zip(peaks.iter_mut()) {
            value = section.process(value);
            let (z1, z2) = section.state();
            peak[0] = peak[0].max(f64::from(value).abs());
            peak[1] = peak[1].max(z1.abs());
            peak[2] = peak[2].max(z2.abs());
        }
    }
    peaks
}

struct Row {
    design: &'static str,
    stage: usize,
    quantity: &'static str,
    /// The original product bound.
    product: f64,
    /// The bound validation uses.
    bound: f64,
    /// Exact L1 norm over the horizon (the sum the bound is built on).
    exact_horizon: f64,
    /// Exact L1 norm over `RUN` samples (what an input of that length can reach).
    exact_run: f64,
    /// What the real chain reached under that input.
    realized: f64,
}

impl Row {
    fn label(&self) -> String {
        format!("{} stage {} {}", self.design, self.stage, self.quantity)
    }
}

fn measure(design: &Design) -> Vec<Row> {
    let stored = stored_sections(&design.sections);
    let dc_r = f64::from(dc_pole(design.dc_hz, FS));
    let bounds = chain_bounds(dc_r, &stored);
    let responses = exact_responses(dc_r, &stored, RUN);
    let mut rows = Vec::new();
    for (stage, response) in responses.iter().enumerate() {
        for (index, name) in QUANTITY_NAMES.iter().enumerate() {
            let input = adversarial(&response[index]);
            let realized = realize(design.dc_hz, &design.sections, &input)[stage][index];
            rows.push(Row {
                design: design.name,
                stage,
                quantity: name,
                product: component(&bounds.product[stage], index),
                bound: component(&bounds.stages[stage], index),
                exact_horizon: component(&bounds.exact[stage], index),
                exact_run: response[index].iter().map(|v| v.abs()).sum::<f64>(),
                realized,
            });
        }
    }
    rows
}

#[test]
fn step_one_the_harness_measures_correctly_against_the_old_product_bound() {
    // Before the bound moves: the realized peak of every quantity of every committed design is at most the old product
    // bound, equals the independent exact L1 norm, and the check can fail (it would catch a halved product bound).
    let mut bites = false;
    for design in designs() {
        for row in measure(&design) {
            assert!(
                row.realized <= row.product * (1.0 + 1.0e-6),
                "{}: realized {} above the product bound {}",
                row.label(),
                row.realized,
                row.product
            );
            assert!(
                (row.realized - row.exact_run).abs() <= 1.0e-5 * row.exact_run + 1.0e-12,
                "{}: realized {} differs from the independent exact value {}",
                row.label(),
                row.realized,
                row.exact_run
            );
            bites |= row.realized > 0.5 * row.product * (1.0 + 1.0e-6);
        }
    }
    assert!(
        bites,
        "no row would be caught by a halved bound: the check does not bite"
    );
}

#[test]
fn the_exact_bound_is_sound_against_the_realized_chain_with_room_to_spare() {
    for design in designs() {
        for row in measure(&design) {
            assert!(
                row.realized <= row.bound * (1.0 + 1.0e-6),
                "{}: the bound {} fell below a value the filter reaches, {}",
                row.label(),
                row.bound,
                row.realized
            );
            assert!(
                row.bound <= row.product * (1.0 + 1.0e-12),
                "{}: the bound {} is looser than the product bound {}",
                row.label(),
                row.bound,
                row.product
            );
            if row.bound < row.product - 1.0e-9 && row.realized > 0.0 {
                // The exact path is active: the explicit margin is spare on top of the allowance for the part past the
                // horizon, and f32 rounding (under 2e-7 of the exact value) is 50000 times smaller than that margin.
                assert!(
                    row.bound >= row.realized * (1.0 + BOUND_MARGIN / 2.0),
                    "{}: bound {} has less than half the margin over {}",
                    row.label(),
                    row.bound,
                    row.realized
                );
                if !design.name.contains("1 Hz") {
                    assert!(
                        row.bound <= row.realized * 1.10,
                        "{}: a bound 10% above the realized peak is loose ({} against {})",
                        row.label(),
                        row.bound,
                        row.realized
                    );
                }
            }
        }
    }
}

#[test]
fn the_long_tail_case_is_covered_by_the_remainder_allowance() {
    // A 1 Hz DC corner leaves R^8191 = 0.34 of the rejector's response past the horizon: the sum over the horizon alone is
    // low by up to 0.33, and the remainder allowance has to cover it.
    for name in ["HP60, 1 Hz DC corner", "LP120, 1 Hz DC corner"] {
        let rows: Vec<Row> = measure(&named(name))
            .into_iter()
            .filter(|row| row.realized > 0.0)
            .collect();
        let tail = rows
            .iter()
            .map(|row| row.exact_run - row.exact_horizon)
            .fold(0.0f64, f64::max);
        assert!(
            tail > 0.15,
            "{name}: the part past the horizon is {tail}, not the long-tail case it is meant to be"
        );
        for row in &rows {
            assert!(
                row.exact_horizon <= row.realized + 1.0e-9,
                "{}: the horizon sum {} exceeds the realized peak {}",
                row.label(),
                row.exact_horizon,
                row.realized
            );
            assert!(
                row.bound >= row.realized * (1.0 + BOUND_MARGIN / 2.0),
                "{}: bound {} against realized {}",
                row.label(),
                row.bound,
                row.realized
            );
        }
    }
}

#[test]
fn the_exact_bound_is_never_stricter_than_the_product_bound() {
    // Pure relaxation by construction (the bound is the minimum of the two), checked over a design grid and the committed
    // designs at three DC corners: nothing the product bound admitted is refused now.
    let mut grid: Vec<(String, Vec<BiquadSpec>)> = Vec::new();
    for fc in [
        20.0, 60.0, 100.0, 300.0, 1_000.0, 2_200.0, 8_000.0, 16_000.0,
    ] {
        for reps in [1usize, 2] {
            grid.push((
                format!("lp{fc}x{reps}"),
                vec![butterworth2_lowpass(fc, FS); reps],
            ));
            grid.push((
                format!("hp{fc}x{reps}"),
                vec![butterworth2_highpass(fc, FS); reps],
            ));
        }
    }
    for design in designs() {
        grid.push((design.name.to_string(), design.sections));
    }
    grid.push((
        "refused boost".to_string(),
        vec![boost_24_db(), gain_section(0.15)],
    ));
    let mut newly_admitted = 0;
    for dc_hz in [1.0, 5.0, 100.0] {
        let dc_r = f64::from(dc_pole(dc_hz, FS));
        for (name, sections) in &grid {
            let bounds = chain_bounds(dc_r, &stored_sections(sections));
            for (stage, product) in bounds.stages.iter().zip(bounds.product.iter()) {
                for (index, quantity) in QUANTITY_NAMES.iter().enumerate() {
                    assert!(
                        component(stage, index) <= component(product, index) * (1.0 + 1.0e-12),
                        "{name} at {dc_hz} Hz: {quantity} looser than the product bound"
                    );
                }
            }
            let old_gain = bounds.product.last().map_or(2.0, |stage| stage.y);
            let old_worst = bounds.product.iter().fold(2.0f64, |worst, stage| {
                worst.max(stage.y).max(stage.z1).max(stage.z2)
            });
            let old_ok =
                bounds.converged && old_gain <= MAX_L1_GAIN && old_worst <= MAX_INTERMEDIATE;
            let new_ok =
                bounds.converged && bounds.gain <= MAX_L1_GAIN && bounds.worst <= MAX_INTERMEDIATE;
            assert!(
                !old_ok || new_ok,
                "{name} at {dc_hz} Hz: admitted by the product bound, refused by the exact one"
            );
            newly_admitted += usize::from(new_ok && !old_ok);
        }
    }
    assert!(
        newly_admitted > 30,
        "the exact bound should admit the ordinary high-pass designs; only {newly_admitted}"
    );
}

#[test]
fn the_exact_bound_matches_the_independent_reference_on_pinned_designs() {
    // (design, gain bound, worst bound, relative tolerance) from `tests/d02/reference.py: chain_bounds`. The Butterworth
    // designs are computed from a formula in both languages and then rounded to f32; a coefficient on a rounding boundary
    // would differ by one f32 step, so they get 1e-4. The literal-coefficient designs get 1e-9.
    let pinned = [
        ("LP120", 1.900829189887, 2.0, 1.0e-4),
        ("HP100", 2.483242705140, 2.483242705140, 1.0e-4),
        ("HP60", 2.510871557174, 2.510871557174, 1.0e-4),
        (
            "boost +20 dB then trim",
            3.368107524692,
            13.472430098766,
            1.0e-9,
        ),
        ("gain 3", 6.0, 6.0, 1.0e-9),
        (
            "HP60, 1 Hz DC corner",
            3.295743724244,
            5.549311119716,
            1.0e-4,
        ),
    ];
    for (name, gain, worst, tolerance) in pinned {
        let design = named(name);
        let dc_r = f64::from(dc_pole(design.dc_hz, FS));
        let bounds = chain_bounds(dc_r, &stored_sections(&design.sections));
        assert!(bounds.converged, "{name}");
        assert!(
            (bounds.gain - gain).abs() <= tolerance * gain,
            "{name}: gain bound {} against the reference {gain}",
            bounds.gain
        );
        assert!(
            (bounds.worst - worst).abs() <= tolerance * worst,
            "{name}: worst bound {} against the reference {worst}",
            bounds.worst
        );
    }
    let refused = chain_bounds(
        f64::from(dc_pole(5.0, FS)),
        &stored_sections(&[boost_24_db(), gain_section(0.15)]),
    );
    assert!((refused.gain - 3.085408878402).abs() <= 1.0e-9 * 3.085408878402);
    assert!((refused.worst - 20.569391705325).abs() <= 1.0e-9 * 20.569391705325);
    assert!(refused.worst > MAX_INTERMEDIATE && refused.gain <= MAX_L1_GAIN);
}

#[test]
fn the_refusal_is_warranted_the_refused_boost_really_overflows_and_the_admitted_one_does_not() {
    // The +24 dB design is refused for its middle node. The refusal is not over-conservative: the real chain, driven with
    // that node's worst-case input, goes past the limit of 16. The +20 dB design is admitted and stays under it, and the
    // 60 and 100 Hz high-passes sit far inside it.
    let refused = design(
        "refused boost",
        5.0,
        vec![boost_24_db(), gain_section(0.15)],
    );
    let peak = measure(&refused)
        .iter()
        .filter(|row| row.stage == 0)
        .map(|row| row.realized)
        .fold(0.0f64, f64::max);
    assert!(
        peak > MAX_INTERMEDIATE,
        "the refused design reaches only {peak}: the refusal is over-conservative"
    );
    let admitted = measure(&named("boost +20 dB then trim"))
        .iter()
        .map(|row| row.realized)
        .fold(0.0f64, f64::max);
    assert!(
        admitted < MAX_INTERMEDIATE,
        "admitted boost reaches {admitted}"
    );
    for name in ["HP100", "HP60", "HP60, 1 Hz DC corner"] {
        let peak = measure(&named(name))
            .iter()
            .map(|row| row.realized)
            .fold(0.0f64, f64::max);
        assert!(peak < 0.2 * MAX_INTERMEDIATE, "{name} reaches {peak}");
    }
}

#[test]
fn designs_the_product_bound_refused_are_admitted_and_run_without_a_fault() {
    // Positive controls for the cases the product bound refused (the old b = [1, -2, 1] design at 23.2, the 100 Hz and 60
    // Hz high-passes at about 20.3, the +20 dB boost at 77.9): each is admitted by the real validator, and the real board,
    // driven with the worst-case input for its first section's output, never latches a fault. The user gain is low so the
    // thermal model (which reads the signal after gain) stays out of the way; the filter states do not depend on it.
    let s5 = fixture("S5");
    let cases: [(&str, Vec<BiquadSpec>, f64); 4] = [
        (
            "b = [1, -2, 1] design",
            vec![BiquadSpec {
                b0: 1.0,
                b1: -2.0,
                b2: 1.0,
                a1: -1.7196056842803955,
                a2: 0.81,
            }],
            5.0,
        ),
        (
            "100 Hz high-pass",
            vec![butterworth2_highpass(100.0, FS)],
            5.0,
        ),
        (
            "60 Hz high-pass, 1 Hz DC corner",
            vec![butterworth2_highpass(60.0, FS)],
            1.0,
        ),
        (
            "boost +20 dB then trim",
            vec![boost_20_db(), gain_section(0.25)],
            5.0,
        ),
    ];
    for (name, sections, dc_hz) in cases {
        let mut calibration = synthetic_calibration_for(&s5);
        calibration.channels[2].sections.clone_from(&sections);
        calibration.channels[2].dc_block_hz = dc_hz;
        let mut dsp = ProtectedBoardDsp::admit(&s5, Some(&calibration), Admission::HostSimulation);
        assert_eq!(dsp.status(), BoardStatus::Active, "{name}: admitted");
        dsp.set_user_gain(0.05);
        settle(&mut dsp);
        let stored = stored_sections(&sections);
        let responses = exact_responses(f64::from(dc_pole(dc_hz, FS)), &stored, RUN);
        for chunk in adversarial(&responses[0][0]).chunks(FRAMES_PER_BLOCK) {
            let mut block = StereoAudioBlock::silence(0);
            block.frames = chunk.len();
            block.left[..chunk.len()].copy_from_slice(chunk);
            render(&mut dsp, &block);
            assert_eq!(
                dsp.status(),
                BoardStatus::Active,
                "{name}: the worst-case input faulted the board"
            );
        }
        let (z1, z2) = dsp.section_state(2).expect("channel 2");
        assert!(
            z1.abs() < MAX_INTERMEDIATE && z2.abs() < MAX_INTERMEDIATE,
            "{name}: states {z1} {z2}"
        );
    }
}
