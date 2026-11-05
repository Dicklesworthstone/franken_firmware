//! D02 (`ffw-7s0`): board-lifetime protection history through the REAL render loop.
//!
//! The acceptance text says thermal and protection history survives seeks, reconnects and source
//! replacement, and that an unsafe board stays muted. `franken-dsp` shows that on `ProtectedBoardDsp`
//! alone (`D02-SCN-001..006`, `seek_reconnect_and_source_replacement_never_reset_protection_history`).
//! The production consumer of that board is `RenderLoop`, which is where a reconnect, a discontinuity
//! epoch, a stop-and-restart and a profile switch actually happen, so this file drives those through the
//! loop and reads the board back with `dsp()`.
//!
//! What is checked, and against what. Both laws below follow from the update rules the D02 contract
//! documents, not from the code under test:
//!
//! * thermal: `level += alpha * (v*v - level)` with `v*v >= 0`, so in any `n` frames the level cannot fall
//!   faster than pure cooling, `level_n >= level_0 * exp(-n / (tau * fs))`;
//! * limiter: `gain += (target - gain) * coef` with `target <= 1`, so the deficit `1 - gain` cannot shrink
//!   faster than the release time constant, `deficit_n >= deficit_0 * exp(-n / (release * fs))`.
//!
//! A board that was rebuilt at the event starts at level 0 and gain 1, which breaks both by a wide
//! margin, so the checks are not vacuous. Every case is run twice: the unplanted run is the control and
//! must find no violation, and the planted run replaces the board with a fresh one at the event
//! (`*loop.dsp_mut() = fresh`), the defect the acceptance text exists to prevent, and must be caught.
//!
//! Limits, stated plainly:
//!
//! * Host simulation: `FakeBackend`, a synthetic calibration, a scripted timeline. Nothing here is a
//!   board, an amplifier or a measurement of heat. Numerical tests do not prove physical protection.
//! * There is no excursion (displacement) history because D02 has no excursion model; one needs driver
//!   parameters from E04 (`ffw-25l`) and D02 invents none.
//! * `RenderLoop` has no seek call. `begin_epoch` reports every epoch to the board as
//!   `SourceEvent::Reconnect`, and the board treats `Seek`, `Reconnect` and `SourceReplaced` alike, so a
//!   seek is covered by the reconnect and discontinuity cases and has no case of its own.
//! * Cooling: `RenderLoop` renders nothing while it is `Faulted`, `Ready` or `Stopped`, so a latched
//!   board's thermal level does not move there, and nothing in the speaker calls `clear_fault`. The way
//!   out that exists is the one used below: feed the board silence through `dsp_mut()` until
//!   `clear_fault` succeeds. `a_latched_fault_survives_recover_and_every_loop_call_until_it_is_cooled_and_cleared`
//!   pins that behaviour so a change to it is a decision, not a drift.

use std::collections::BTreeMap;
use std::sync::Arc;

use franken_board_profile::{BoardProfile, synthetic_test_fixture_catalog};
use franken_dsp::StereoAudioBlock;
use franken_dsp::protection::{
    Admission, BoardCalibration, BoardStatus, FaultCode, ProtectedBoardDsp, ProtectedOutput,
    ProtectionError, ThermalSpec, synthetic_calibration_for,
};
use franken_dsp::resample::{DriftResampler, FrameSource, ResamplerConfig};
use franken_hal::abi::RawGeometry;
use franken_hal::backend::{FakeBackend, FakeConfig};
use franken_hal::session::{HalSession, SessionConfig, StartPreconditions};
use franken_hal::slots::LeakLedger;
use franken_speaker::render::{
    FaultReason, RenderConfig, RenderError, RenderLoop, RenderSource, RenderState, ScriptedTiming,
    Starvation,
};

const READY: StartPreconditions = StartPreconditions {
    presentation_mapping_installed: true,
    safe_gain_installed: true,
};

/// Frames per block; the fake device's block size is the same.
const BLOCK: usize = 64;
const BLOCK_FRAMES: u64 = 64;

/// In phase on both channels, so every driver that routes from `mid` sees this amplitude. Above the
/// synthetic limiter threshold (0.8) once it has passed the woofer's 2 kHz low-pass, so the limiter
/// engages.
const AMPLITUDE: f32 = 0.95;

/// Frames rendered before the event: about 3200 frames is 50 blocks, enough to build a thermal level well
/// above the floor below and to leave the limiter holding gain reduction.
const HEAT_FRAMES: u64 = 3200;

/// A thermal model that warms visibly under `AMPLITUDE` but cannot scale or fault in this run: its soft
/// limit (0.9) is above the steady-state mean square of the driven channel (about 0.4).
const WARM: ThermalSpec = ThermalSpec {
    tau_s: 0.1,
    soft_ms: 0.9,
    hard_ms: 3.0,
};

/// A thermal model that latches under `AMPLITUDE`: the hard limit (0.2) is below the steady-state mean
/// square of the driven channel, and the soft limit (0.05) is where a latched board counts as cooled.
const LATCHING: ThermalSpec = ThermalSpec {
    tau_s: 0.05,
    soft_ms: 0.05,
    hard_ms: 0.2,
};

/// A channel whose level is below this is not asked to show history (its decay would be lost in noise).
const THERMAL_FLOOR: f64 = 1.0e-3;
/// A limiter whose gain reduction is below this is not asked to show history.
const LIMITER_FLOOR: f64 = 1.0e-2;
/// Relative slack on both laws, for single-precision rounding over a few hundred updates.
const SLACK: f64 = 2.0e-3;

// ---- the fixture: a started RenderLoop over the fake device -------------------------------------------

fn profile() -> BoardProfile {
    synthetic_test_fixture_catalog()
        .into_iter()
        .find(|p| p.model_number == "S1")
        .expect("the S1 fixture exists")
}

/// Four 64-frame slots, two channels, a completion two ticks after a submit.
fn fake_config() -> FakeConfig {
    let mut cfg = FakeConfig::retained();
    cfg.geometry = RawGeometry {
        ring_depth: 4,
        frames_per_block: 64,
        channels: 2,
        bytes_per_sample: 2,
    };
    cfg.completion_delay_ticks = 2;
    cfg
}

/// The synthetic calibration for `profile` with `thermal` on every channel.
fn calibrated(profile: &BoardProfile, thermal: ThermalSpec) -> BoardCalibration {
    let mut calibration = synthetic_calibration_for(profile);
    for channel in &mut calibration.channels {
        channel.thermal = thermal;
    }
    calibration
}

fn build_loop(profile: &BoardProfile, calibration: &BoardCalibration) -> RenderLoop<FakeBackend> {
    let (backend, _probe) = FakeBackend::new(fake_config());
    let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2);
    let mut session =
        HalSession::open(profile.clone(), backend, config).expect("the fake device opens");
    session.prepare().expect("the fake device prepares");
    let resampler = DriftResampler::new(ResamplerConfig::default()).expect("the default resampler");
    let dsp = ProtectedBoardDsp::admit(profile, Some(calibration), Admission::HostSimulation);
    RenderLoop::new(session, dsp, resampler, RenderConfig::standard(BLOCK))
        .expect("the loop admits the fake device")
}

/// A steady 1 kHz tone, the same on both channels, that can be made to starve.
struct Tone {
    pos: u64,
    amplitude: f32,
    starved: Option<Starvation>,
}

impl Tone {
    fn new(amplitude: f32) -> Self {
        Self {
            pos: 0,
            amplitude,
            starved: None,
        }
    }
}

impl FrameSource for Tone {
    fn pull(&mut self) -> Option<[f32; 2]> {
        if self.starved.is_some() {
            return None;
        }
        let phase = (self.pos % 48) as f32 / 48.0;
        self.pos += 1;
        let v = self.amplitude * (2.0 * std::f32::consts::PI * phase).sin();
        Some([v, v])
    }
}

impl RenderSource for Tone {
    fn starvation(&self) -> Option<Starvation> {
        self.starved
    }
}

fn timing() -> ScriptedTiming {
    ScriptedTiming {
        default_cost: 1,
        costs: BTreeMap::new(),
        delays: BTreeMap::new(),
    }
}

/// Tick until the loop has rendered `frames` more frames through the board.
fn run_frames(
    l: &mut RenderLoop<FakeBackend>,
    src: &mut Tone,
    t: &mut ScriptedTiming,
    frames: u64,
) {
    let target = l.counters().frames_generated + frames;
    // A block is 64 frames per 4 ticks, so this is far more ticks than the frames need.
    for _ in 0..(frames * 8 + 64) {
        if l.counters().frames_generated >= target {
            return;
        }
        l.tick(src, t);
    }
    let state = l.state();
    panic!("the loop did not render {frames} frames; it is {state:?}");
}

/// Replace the loop's board with a fresh, unmuted one: the defect the checks must catch.
fn replace_board(
    l: &mut RenderLoop<FakeBackend>,
    profile: &BoardProfile,
    calibration: &BoardCalibration,
) {
    let mut fresh = ProtectedBoardDsp::admit(profile, Some(calibration), Admission::HostSimulation);
    fresh
        .set_muted(false)
        .expect("a fresh synthetic board unmutes");
    *l.dsp_mut() = fresh;
}

// ---- reading the board, and the two laws --------------------------------------------------------------

/// The board-lifetime history of every driver channel, and how many frames the loop had rendered.
#[derive(Debug, Clone)]
struct History {
    thermal: Vec<f32>,
    limiter: Vec<f32>,
    frames: u64,
}

fn history(l: &RenderLoop<FakeBackend>) -> History {
    let dsp = l.dsp();
    let channels = dsp.channel_count();
    History {
        thermal: (0..channels).filter_map(|c| dsp.thermal_level(c)).collect(),
        limiter: (0..channels).filter_map(|c| dsp.limiter_gain(c)).collect(),
        frames: l.counters().frames_generated,
    }
}

/// Violations of the two laws between two readings `frames` rendered frames apart; empty when the
/// history survived. A channel whose earlier reading is below the floors above is not asked for anything.
fn history_violations(
    what: &str,
    before: &History,
    after: &History,
    frames: u64,
    calibration: &BoardCalibration,
) -> Vec<String> {
    let fs = f64::from(calibration.sample_rate_hz);
    let n = frames as f64;
    let mut violations = Vec::new();
    for (channel, spec) in calibration.channels.iter().enumerate() {
        if let (Some(&b), Some(&a)) = (before.thermal.get(channel), after.thermal.get(channel)) {
            let (b, a) = (f64::from(b), f64::from(a));
            if b > THERMAL_FLOOR {
                let floor = b * (-n / (spec.thermal.tau_s * fs)).exp();
                if a < floor * (1.0 - SLACK) {
                    violations.push(format!(
                        "{what}: channel {channel} thermal level {a:.6} is below the {floor:.6} that cooling \
                         alone allows from {b:.6} over {frames} frames (history lost)"
                    ));
                }
            }
        }
        if let (Some(&b), Some(&a)) = (before.limiter.get(channel), after.limiter.get(channel)) {
            let (deficit_before, deficit_after) = (1.0 - f64::from(b), 1.0 - f64::from(a));
            if deficit_before > LIMITER_FLOOR {
                let floor = deficit_before * (-n / (spec.limiter.release_ms * 1.0e-3 * fs)).exp();
                if deficit_after < floor * (1.0 - SLACK) {
                    violations.push(format!(
                        "{what}: channel {channel} limiter gain reduction {deficit_after:.6} is below the \
                         {floor:.6} that the release time allows from {deficit_before:.6} over {frames} \
                         frames (history lost)"
                    ));
                }
            }
        }
    }
    violations
}

// ---- events that must keep history ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    /// `RenderLoop::reconnect`: a new epoch (`ResetReason::Rejoin`).
    Reconnect,
    /// The source loses packets and then resumes: the loop begins a discontinuity epoch itself.
    IngressLossEpoch,
    /// A graceful stop, then `start` again: a new epoch (`ResetReason::NewSource`) after a ramp to silence.
    StopThenStart,
    /// A valid calibration for the same board: the output ramps to silence, the chain is swapped, and the
    /// output ramps back.
    ProfileSwitch,
}

/// Heat the board through the loop, apply `event`, and return the violations of the two laws. With
/// `plant`, the board is replaced by a fresh one just before the event.
fn run_event(event: Event, plant: bool) -> Vec<String> {
    let profile = profile();
    let calibration = calibrated(&profile, WARM);
    let mut l = build_loop(&profile, &calibration);
    let (mut src, mut t) = (Tone::new(AMPLITUDE), timing());
    l.start(READY).expect("a healthy synthetic board starts");
    run_frames(&mut l, &mut src, &mut t, HEAT_FRAMES);

    // The state is nonzero before the event. If the heater did not build it, say so instead of passing.
    let before = history(&l);
    assert!(
        before.thermal.iter().any(|&level| level > 0.05),
        "{event:?}: the heater built no thermal level: {:?}",
        before.thermal
    );
    assert!(
        before.limiter.iter().any(|&gain| gain < 0.99),
        "{event:?}: the heater left the limiter idle: {:?}",
        before.limiter
    );
    assert_eq!(
        l.dsp().status(),
        BoardStatus::Active,
        "{event:?}: precondition"
    );
    let epochs = l.counters().epoch_resets;

    if plant {
        replace_board(&mut l, &profile, &calibration);
    }
    match event {
        Event::Reconnect => {
            l.reconnect().expect("a running loop reconnects");
            run_frames(&mut l, &mut src, &mut t, 2 * BLOCK_FRAMES);
        }
        Event::IngressLossEpoch => {
            src.starved = Some(Starvation::IngressLoss);
            run_frames(&mut l, &mut src, &mut t, 3 * BLOCK_FRAMES);
            src.starved = None;
            run_frames(&mut l, &mut src, &mut t, 3 * BLOCK_FRAMES);
        }
        Event::StopThenStart => {
            l.stop().expect("a running loop stops");
            for _ in 0..300 {
                if l.state() != RenderState::Draining {
                    break;
                }
                l.tick(&mut src, &mut t);
            }
            assert_eq!(l.state(), RenderState::Stopped, "the stop did not finish");
            l.start(READY).expect("a stopped loop restarts");
            run_frames(&mut l, &mut src, &mut t, 2 * BLOCK_FRAMES);
        }
        Event::ProfileSwitch => {
            l.dsp_mut()
                .request_profile_switch(&profile, &calibration, Admission::HostSimulation)
                .expect("a valid calibration for the same board is accepted");
            for _ in 0..40 {
                if !l.dsp().has_pending_switch() {
                    break;
                }
                run_frames(&mut l, &mut src, &mut t, BLOCK_FRAMES);
            }
            assert!(!l.dsp().has_pending_switch(), "the switch never installed");
            run_frames(&mut l, &mut src, &mut t, 2 * BLOCK_FRAMES);
        }
    }

    // The event really happened, in the planted run too: otherwise both runs would pass vacuously.
    match event {
        Event::ProfileSwitch => assert_eq!(l.dsp().status(), BoardStatus::Active),
        _ => assert!(
            l.counters().epoch_resets > epochs,
            "{event:?} began no resampler epoch, so the loop never told the board"
        ),
    }

    let after = history(&l);
    history_violations(
        &format!("{event:?}"),
        &before,
        &after,
        after.frames - before.frames,
        &calibration,
    )
}

/// The control finds nothing and the planted run is caught.
fn assert_survives_and_the_plant_is_caught(event: Event) {
    let control = run_event(event, false);
    assert!(
        control.is_empty(),
        "{event:?}: the loop lost board history: {control:#?}"
    );
    let planted = run_event(event, true);
    assert!(
        !planted.is_empty(),
        "{event:?}: a loop that replaced the board at the event was not caught"
    );
}

#[test]
fn history_survives_a_reconnect_through_the_real_loop() {
    assert_survives_and_the_plant_is_caught(Event::Reconnect);
}

#[test]
fn history_survives_an_ingress_loss_discontinuity_epoch_through_the_real_loop() {
    assert_survives_and_the_plant_is_caught(Event::IngressLossEpoch);
}

#[test]
fn history_survives_a_stop_and_restart_through_the_real_loop() {
    assert_survives_and_the_plant_is_caught(Event::StopThenStart);
}

#[test]
fn history_survives_a_profile_switch_through_the_real_loop() {
    assert_survives_and_the_plant_is_caught(Event::ProfileSwitch);
}

// ---- a latched fault must stay muted ------------------------------------------------------------------

/// Overdrive the board through the loop until it latches a thermal fault, then try every way back that
/// the loop offers, then cool the board by hand and clear it. With `plant`, the board is replaced by a
/// fresh one after `recover`, so the latch is gone. Returns the violations.
fn run_latch(plant: bool) -> Vec<String> {
    let profile = profile();
    let calibration = calibrated(&profile, LATCHING);
    let mut l = build_loop(&profile, &calibration);
    let (mut src, mut t) = (Tone::new(AMPLITUDE), timing());
    l.start(READY).expect("a healthy synthetic board starts");
    // About 30 blocks reach the hard limit; allow five times that.
    for _ in 0..(150 * 4) {
        if l.state() == RenderState::Faulted {
            break;
        }
        l.tick(&mut src, &mut t);
    }
    assert_eq!(
        l.state(),
        RenderState::Faulted,
        "sustained overdrive must latch a thermal fault through the loop"
    );
    assert_eq!(l.fault(), Some(FaultReason::ProtectionFault));
    let status = l.dsp().status();
    assert!(
        matches!(status, BoardStatus::Faulted(FaultCode::ThermalHard { .. })),
        "the board's own status is {status:?}"
    );
    assert_eq!(l.dsp().faults_total(), 1);
    let latched = history(&l);
    assert!(
        latched.thermal.iter().any(|&level| level > 0.15),
        "a latch means the level reached the hard limit: {:?}",
        latched.thermal
    );

    let mut violations = Vec::new();

    // The loop renders nothing while Faulted, so nothing cools. This pins today's behaviour.
    for _ in 0..32 {
        l.tick(&mut src, &mut t);
    }
    let parked = history(&l);
    if parked.thermal != latched.thermal || parked.frames != latched.frames {
        violations.push(
            "a Faulted loop rendered or cooled the board by itself: a cooling path now exists, so update \
             this test and the D02 acceptance-map row together"
                .to_string(),
        );
    }

    // Recovering the device does not recover the board.
    l.recover()
        .expect("a faulted loop whose device is intact recovers");
    assert_eq!(l.state(), RenderState::Ready);
    if plant {
        replace_board(&mut l, &profile, &calibration);
    }
    match l.start(READY) {
        Err(RenderError::ProtectionNotActive) => {}
        other => {
            violations.push(format!(
                "start() with the thermal fault still latched returned {other:?}, not ProtectionNotActive"
            ));
            return violations;
        }
    }
    match l.reconnect() {
        Err(RenderError::WrongState(RenderState::Ready)) => {}
        other => violations.push(format!("reconnect() on a Ready loop returned {other:?}")),
    }
    let unmuted = l.dsp_mut().set_muted(false);
    if unmuted != Err(ProtectionError::UnmuteRefused) {
        violations.push(format!("unmuting a latched board returned {unmuted:?}"));
    }
    let early = l.dsp_mut().clear_fault();
    if early != Err(ProtectionError::NotCooled) {
        violations.push(format!("clear_fault() while still hot returned {early:?}"));
    }

    // The way out: silence through the board until it is cool, then clear.
    let silence = StereoAudioBlock::silence(0);
    let mut out = ProtectedOutput::new();
    let mut fed = 0_u64;
    let mut cleared = false;
    for _ in 0..200 {
        if l.dsp_mut().clear_fault().is_ok() {
            cleared = true;
            break;
        }
        l.dsp_mut().render_into(&silence, &mut out);
        fed += u64::try_from(silence.frames).unwrap_or(u64::MAX);
    }
    if !cleared {
        violations
            .push("the board never cooled to its soft limit in 200 silent blocks".to_string());
        return violations;
    }
    let cooled = history(&l);
    violations.extend(history_violations(
        "latched -> cooled",
        &latched,
        &cooled,
        fed,
        &calibration,
    ));
    if l.dsp().status() != BoardStatus::Active {
        violations.push(format!(
            "after clear_fault the status is {:?}",
            l.dsp().status()
        ));
    }
    if l.dsp().faults_total() != 1 {
        violations.push(format!(
            "the fault was counted {} times, not once",
            l.dsp().faults_total()
        ));
    }

    // Cooled and cleared: the loop starts again.
    if let Err(error) = l.start(READY) {
        violations.push(format!(
            "start() after cooling and clear_fault failed: {error}"
        ));
        return violations;
    }
    run_frames(&mut l, &mut src, &mut t, 2 * BLOCK_FRAMES);
    if l.state() != RenderState::Running {
        violations.push(format!("after the restart the loop is {:?}", l.state()));
    }
    violations
}

#[test]
fn a_latched_fault_survives_recover_and_every_loop_call_until_it_is_cooled_and_cleared() {
    let control = run_latch(false);
    assert!(
        control.is_empty(),
        "the latched board did not stay muted: {control:#?}"
    );
}

#[test]
fn a_loop_that_unlatched_the_board_at_recover_is_caught() {
    let planted = run_latch(true);
    assert!(
        !planted.is_empty(),
        "a loop that replaced a latched board with a fresh one was not caught"
    );
}
