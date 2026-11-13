//! Tests for the physical-button adapter (`G02` / `ffw-ld0`, the fresh-eyes clause).
//!
//! The events come from the REAL `franken-hal` channel (`FakeEventSource` feeding `LocalEventChannel`, which debounces
//! and delivers `ChannelEvent`s) wherever the behaviour does not depend on a hand-picked tick, and from hand-built
//! `ChannelEvent` values where a test needs an exact tick. The member is a real `MemberVolume` and, where it matters,
//! the board is the real D02 (`ProtectedBoardDsp`), read through `MemberVolume::progress`.
//!
//! What they show: only a debounced `Down` of a mapped button acts; a release, an `Unknown` state and a stray id do
//! nothing; a held button is one press and is reported stuck; a bouncing button cannot ratchet; losing the button
//! device never unmutes; local mute and trim need no authority; they survive cloud retries and a rejoin; a fault mute
//! that overrides a requested unmute is reported. Each refusal is paired with the permitted behaviour. Planted wrong
//! mappings (a mute wired to the trim, a press that also releases) are caught by named tests.
//!
//! What they do not show: any real button, the audio-control device's ABI (E04 has not decoded it), or a UI.

use super::*;
use franken_board_profile::synthetic_test_fixture_catalog;
use franken_dsp::protection::{
    Admission, ProtectedBoardDsp, ProtectedOutput, synthetic_calibration_for,
};
use franken_dsp::volume::{CommandProgress, GroupSnapshot, Stamp, VolumeCommand};
use franken_dsp::{FRAMES_PER_BLOCK, StereoAudioBlock};
use franken_hal::backend::LocalEventCapability;
use franken_hal::events::{
    EventChannelConfig, FakeEventProbe, FakeEventSource, LocalEventChannel, LocalEventKind,
};

const EPOCH: u64 = 7;
const MUTE: u8 = 0;
const UP: u8 = 1;
const DOWN: u8 = 2;
/// An id the map gives no role. The HAL channel accepts ids below four.
const STRAY: u8 = 3;

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

fn map() -> ButtonMap {
    ButtonMap::new(MUTE, UP, DOWN).expect("three different ids")
}

/// 100 permille per step; a press closer than 10 ticks to the previous applied one is too soon; stuck after 1000.
fn bounds() -> ButtonBounds {
    ButtonBounds::new(100, 10, 1_000).expect("valid bounds")
}

fn adapter() -> ButtonAdapter {
    ButtonAdapter::new(map(), bounds())
}

fn stamp(revision: u64) -> Stamp {
    Stamp {
        epoch: EPOCH,
        revision,
    }
}

/// A member at epoch 7 whose join is complete.
fn member() -> MemberVolume {
    let mut m = MemberVolume::new(1.0);
    m.declare_epoch(EPOCH).expect("declare");
    m.complete_join();
    m
}

fn changed(id: u8, state: ButtonState, at: u64) -> ChannelEvent {
    ChannelEvent::ButtonChanged { id, state, at }
}

fn down(id: u8, at: u64) -> ChannelEvent {
    changed(id, ButtonState::Down, at)
}

fn up(id: u8, at: u64) -> ChannelEvent {
    changed(id, ButtonState::Up, at)
}

fn close(a: f32, b: f32) -> bool {
    (a - b).abs() < 1e-5
}

fn fixture(model: &str) -> franken_board_profile::BoardProfile {
    synthetic_test_fixture_catalog()
        .into_iter()
        .find(|profile| profile.model_number == model)
        .expect("fixture board")
}

fn board(model: &str) -> ProtectedBoardDsp {
    let profile = fixture(model);
    let calibration = synthetic_calibration_for(&profile);
    ProtectedBoardDsp::admit(&profile, Some(&calibration), Admission::HostSimulation)
}

fn render_silence(dsp: &mut ProtectedBoardDsp, frames: usize) {
    let mut out = ProtectedOutput::new();
    let mut left = frames;
    while left > 0 {
        let now = left.min(FRAMES_PER_BLOCK);
        let mut block = StereoAudioBlock::silence(0);
        block.frames = now;
        dsp.render_into(&block, &mut out);
        left -= now;
    }
}

/// The real HAL channel over its fake source, with its own tick.
struct Rig {
    channel: LocalEventChannel<FakeEventSource>,
    probe: FakeEventProbe,
    tick: u64,
}

impl Rig {
    fn new() -> Self {
        let (source, probe) = FakeEventSource::new();
        let capability = LocalEventCapability::Declared {
            abi_evidence: "harness model of docs/contracts/p04.md; no driver ABI is admitted"
                .to_string(),
        };
        let channel = LocalEventChannel::open(&capability, source, EventChannelConfig::standard())
            .expect("a declared capability opens");
        Self {
            channel,
            probe,
            tick: 100,
        }
    }

    fn drain(&mut self) -> Vec<ChannelEvent> {
        let mut delivered = Vec::new();
        while let Some(event) = self.channel.take() {
            delivered.push(event);
        }
        delivered
    }

    /// Nothing arrives for `ticks` channel ticks.
    fn wait(&mut self, ticks: u64) {
        self.tick += ticks;
        let _ = self.channel.pump(self.tick);
    }

    /// One raw edge from the device; the 3-tick debounce window passes; returns what the channel delivered.
    fn edge(&mut self, kind: LocalEventKind, id: u8) -> Vec<ChannelEvent> {
        self.probe.push_event(kind, id, 0);
        let _ = self.channel.pump(self.tick);
        self.tick += 3;
        let _ = self.channel.pump(self.tick);
        self.drain()
    }

    fn press(&mut self, id: u8) -> Vec<ChannelEvent> {
        self.edge(LocalEventKind::ButtonDown, id)
    }

    fn release(&mut self, id: u8) -> Vec<ChannelEvent> {
        self.edge(LocalEventKind::ButtonUp, id)
    }

    /// Press one button and feed what the channel delivered to the adapter.
    fn press_into(
        &mut self,
        id: u8,
        adapter: &mut ButtonAdapter,
        member: &mut MemberVolume,
    ) -> ButtonAction {
        let events = self.press(id);
        assert_eq!(events.len(), 1, "one debounced edge: {events:?}");
        assert!(matches!(
            events[0],
            ChannelEvent::ButtonChanged {
                state: ButtonState::Down,
                ..
            }
        ));
        adapter.on_event(events[0], member)
    }

    fn release_into(
        &mut self,
        id: u8,
        adapter: &mut ButtonAdapter,
        member: &mut MemberVolume,
    ) -> ButtonAction {
        let events = self.release(id);
        assert_eq!(events.len(), 1, "one debounced edge: {events:?}");
        adapter.on_event(events[0], member)
    }
}

// ---- what a press means -------------------------------------------------------------------------------------------

#[test]
fn a_press_is_one_local_action_and_a_release_is_none_through_the_real_hal_channel() {
    let mut rig = Rig::new();
    let mut a = adapter();
    let mut m = member();

    // The mute button toggles the room's own mute; the release does nothing.
    assert_eq!(
        rig.press_into(MUTE, &mut a, &mut m),
        ButtonAction::LocalMute {
            muted: true,
            effective_mute: Some(MuteReason::Local)
        }
    );
    assert_eq!(
        rig.release_into(MUTE, &mut a, &mut m),
        ButtonAction::Ignored(IgnoredButton::Release)
    );
    assert!(
        m.persisted().local_mute,
        "the release did not undo the press"
    );
    rig.wait(20);
    assert_eq!(
        rig.press_into(MUTE, &mut a, &mut m),
        ButtonAction::LocalMute {
            muted: false,
            effective_mute: None
        }
    );
    rig.release_into(MUTE, &mut a, &mut m);
    assert!(!m.persisted().local_mute);

    // The volume buttons move the room trim by one configured step per press, and the releases move nothing.
    rig.wait(20);
    assert_eq!(
        rig.press_into(UP, &mut a, &mut m),
        ButtonAction::TrimStep {
            trim_permille: 1_100,
            effective_mute: None
        }
    );
    rig.release_into(UP, &mut a, &mut m);
    rig.wait(20);
    assert_eq!(
        rig.press_into(DOWN, &mut a, &mut m),
        ButtonAction::TrimStep {
            trim_permille: 1_000,
            effective_mute: None
        }
    );
    rig.release_into(DOWN, &mut a, &mut m);
    rig.wait(20);
    assert_eq!(
        rig.press_into(DOWN, &mut a, &mut m),
        ButtonAction::TrimStep {
            trim_permille: 900,
            effective_mute: None
        }
    );
    assert_eq!(m.trim_permille(), 900);

    // An id with no role does nothing (refused), and the mapped ids above act (the permitted pair).
    rig.release_into(DOWN, &mut a, &mut m);
    rig.wait(20);
    let stray = rig.press(STRAY);
    assert_eq!(
        a.on_event(stray[0], &mut m),
        ButtonAction::Ignored(IgnoredButton::Unmapped)
    );
    assert_eq!(m.trim_permille(), 900);
    assert!(!m.persisted().local_mute);
    let stats = a.stats();
    assert_eq!(
        (stats.mute_toggles, stats.trim_steps, stats.unmapped),
        (2, 3, 1)
    );
}

#[test]
fn an_unknown_state_is_neither_a_press_nor_a_release() {
    let mut a = adapter();
    let mut m = member();
    assert_eq!(
        a.on_event(changed(MUTE, ButtonState::Unknown, 100), &mut m),
        ButtonAction::Ignored(IgnoredButton::UnknownState)
    );
    assert!(!m.persisted().local_mute);
    // Paired positive: the same button, a real Down, acts.
    assert_eq!(
        a.on_event(down(MUTE, 200), &mut m),
        ButtonAction::LocalMute {
            muted: true,
            effective_mute: Some(MuteReason::Local)
        }
    );
    // And Unknown on a button that was down clears it, so it is never later reported stuck.
    a.on_event(changed(MUTE, ButtonState::Unknown, 300), &mut m);
    assert!(a.poll(10_000).is_empty());
}

// ---- held, stuck and bouncing -------------------------------------------------------------------------------------

#[test]
fn a_held_button_is_one_press_and_is_reported_stuck_once() {
    let mut a = adapter();
    let mut m = member();
    assert_eq!(
        a.on_event(down(MUTE, 100), &mut m),
        ButtonAction::LocalMute {
            muted: true,
            effective_mute: Some(MuteReason::Local)
        }
    );
    // Held: no repeat is invented. Below the bound nothing is reported; at it, the button is stuck, once.
    assert!(a.poll(500).is_empty());
    assert!(!a.is_stuck(ButtonRole::Mute));
    assert_eq!(a.poll(1_100), vec![ButtonRole::Mute]);
    assert!(a.is_stuck(ButtonRole::Mute));
    assert!(a.poll(1_200).is_empty(), "reported once");
    assert_eq!(a.stats().stuck_detected, 1);
    assert!(m.persisted().local_mute, "a held button is still one press");
    assert_eq!(a.stats().mute_toggles, 1);

    // A Down that arrives while it is flagged stuck is ignored.
    assert_eq!(
        a.on_event(down(MUTE, 1_300), &mut m),
        ButtonAction::Ignored(IgnoredButton::WhileStuck)
    );
    assert!(m.persisted().local_mute);
    // The release clears the flag and is not a press.
    assert_eq!(
        a.on_event(up(MUTE, 1_400), &mut m),
        ButtonAction::Ignored(IgnoredButton::ReleaseOfStuckButton)
    );
    assert!(!a.is_stuck(ButtonRole::Mute));
    // Paired positive: the next press acts.
    assert_eq!(
        a.on_event(down(MUTE, 1_500), &mut m),
        ButtonAction::LocalMute {
            muted: false,
            effective_mute: None
        }
    );
}

#[test]
fn a_bouncing_button_cannot_ratchet_the_volume_and_a_spaced_press_acts() {
    let mut a = adapter();
    let mut m = member();
    let trim = |action: ButtonAction| match action {
        ButtonAction::TrimStep { trim_permille, .. } => Some(trim_permille),
        _ => None,
    };
    assert_eq!(trim(a.on_event(down(UP, 100), &mut m)), Some(1_100));
    a.on_event(up(UP, 103), &mut m);
    // Bounces that HAL's window let through, closer than the repeat bound to the last APPLIED press.
    assert_eq!(
        a.on_event(down(UP, 105), &mut m),
        ButtonAction::Ignored(IgnoredButton::TooSoonAfterLastPress)
    );
    a.on_event(up(UP, 106), &mut m);
    assert_eq!(
        a.on_event(down(UP, 109), &mut m),
        ButtonAction::Ignored(IgnoredButton::TooSoonAfterLastPress),
        "9 ticks after the applied press at 100 is still too soon: the ignored ones do not restart the clock"
    );
    a.on_event(up(UP, 109), &mut m);
    assert_eq!(m.trim_permille(), 1_100);
    assert_eq!(a.stats().too_soon, 2);
    // Exactly the bound is allowed (the bound is inclusive), and a different button has its own clock.
    assert_eq!(trim(a.on_event(down(UP, 110), &mut m)), Some(1_200));
    assert_eq!(trim(a.on_event(down(DOWN, 111), &mut m)), Some(1_100));
    assert_eq!(a.stats().trim_steps, 3);
}

// ---- losing the button device ----------------------------------------------------------------------------------------

#[test]
fn losing_the_button_device_never_unmutes_and_is_not_a_release() {
    let mut rig = Rig::new();
    let mut a = adapter();
    let mut m = member();
    assert!(matches!(
        rig.press_into(MUTE, &mut a, &mut m),
        ButtonAction::LocalMute { muted: true, .. }
    ));

    // The device vanishes with the button still down. HAL leaves it Unknown, not Up, and delivers one Lost.
    rig.probe.lose_device();
    rig.wait(1);
    let events = rig.drain();
    assert_eq!(events.len(), 1, "{events:?}");
    assert!(matches!(events[0], ChannelEvent::Lost { .. }));
    assert_eq!(a.on_event(events[0], &mut m), ButtonAction::ChannelReset);
    assert!(
        m.persisted().local_mute,
        "the room stays as muted as it was"
    );
    assert_eq!(m.effective_mute(), Some(MuteReason::Local));
    // The held press is forgotten, not carried on as a phantom: it is never reported stuck.
    assert!(a.poll(100_000).is_empty());
    assert_eq!(a.stats().channel_resets, 1);

    // Repeated faults cannot turn an uncertain held press into a new press.
    assert_eq!(
        a.on_event(ChannelEvent::Faulted { at: 4_000 }, &mut m),
        ButtonAction::ChannelReset
    );
    assert!(m.persisted().local_mute);
    assert_eq!(
        a.on_event(down(MUTE, 4_001), &mut m),
        ButtonAction::Ignored(IgnoredButton::AwaitingRelease)
    );
    assert!(m.persisted().local_mute);
    a.on_event(up(MUTE, 4_002), &mut m);
    assert_eq!(
        a.on_event(down(MUTE, 4_003), &mut m),
        ButtonAction::LocalMute {
            muted: false,
            effective_mute: None
        }
    );
}

#[test]
fn a_fault_that_is_not_a_button_is_ignored() {
    let mut a = adapter();
    let mut m = member();
    for event in [
        ChannelEvent::LedFault { id: 0, at: 5 },
        ChannelEvent::DeviceFault { id: 0, at: 6 },
    ] {
        assert_eq!(
            a.on_event(event, &mut m),
            ButtonAction::Ignored(IgnoredButton::NotAButtonEvent)
        );
    }
    assert_eq!(a.stats().other_events, 2);
    assert!(!m.persisted().local_mute);
    assert_eq!(m.trim_permille(), 1_000);
}

#[test]
fn actual_hal_fault_reset_requires_release_before_a_held_mute_can_unmute() {
    fn fault_and_reset(rig: &mut Rig, adapter: &mut ButtonAdapter, member: &mut MemberVolume) {
        use franken_hal::events::{ChannelState, SYNC};
        let bad_kind = [SYNC, 9, 0, 0, 0, 0, 0, 0];
        rig.probe.push_chunk(bad_kind.repeat(3));
        rig.wait(1);
        assert_eq!(rig.channel.channel_state(), ChannelState::Faulted);
        let events = rig.drain();
        assert_eq!(events.len(), 1, "one actual fault: {events:?}");
        assert!(matches!(events[0], ChannelEvent::Faulted { .. }));
        assert_eq!(
            adapter.on_event(events[0], member),
            ButtonAction::ChannelReset
        );
        assert!(rig.channel.reset());
    }

    for previously_observed_down in [true, false] {
        let mut rig = Rig::new();
        let mut adapter = adapter();
        let mut member = member();
        if previously_observed_down {
            assert!(matches!(
                rig.press_into(MUTE, &mut adapter, &mut member),
                ButtonAction::LocalMute { muted: true, .. }
            ));
        } else {
            // The mute was already set; a press can begin during the outage.
            // No pre-fault Down exists to identify that held button.
            member.local_mute(true);
        }
        fault_and_reset(&mut rig, &mut adapter, &mut member);
        for _ in 0..2 {
            assert_eq!(
                rig.press_into(MUTE, &mut adapter, &mut member),
                ButtonAction::Ignored(IgnoredButton::AwaitingRelease)
            );
            assert!(member.persisted().local_mute);
            assert_eq!(member.effective_mute(), Some(MuteReason::Local));
            assert_eq!(member.trim_permille(), 1_000);
            assert!(adapter.poll(rig.tick + 100_000).is_empty());
            fault_and_reset(&mut rig, &mut adapter, &mut member);
        }
        // An independent previously-up volume button remains useful.
        assert!(matches!(
            rig.press_into(UP, &mut adapter, &mut member),
            ButtonAction::TrimStep {
                trim_permille: 1_100,
                ..
            }
        ));
        assert!(member.persisted().local_mute);
        rig.wait(20);
        rig.release_into(MUTE, &mut adapter, &mut member);
        assert!(matches!(
            rig.press_into(MUTE, &mut adapter, &mut member),
            ButtonAction::LocalMute { muted: false, .. }
        ));
        assert!(!member.persisted().local_mute);
        assert_eq!(adapter.stats().awaiting_release, 2);
        eprintln!(
            "G02_BUTTON_RECOVERY observed_down={previously_observed_down} stats={:?} trim={}",
            adapter.stats(),
            member.trim_permille()
        );
    }
    for mute_set_during_outage in [true, false] {
        let mut rig = Rig::new();
        let mut adapter = adapter();
        let mut member = member();
        fault_and_reset(&mut rig, &mut adapter, &mut member);
        if mute_set_during_outage {
            member.local_mute(true);
        }
        let action = rig.press_into(MUTE, &mut adapter, &mut member);
        if mute_set_during_outage {
            assert_eq!(
                action,
                ButtonAction::Ignored(IgnoredButton::AwaitingRelease)
            );
        } else {
            assert!(matches!(
                action,
                ButtonAction::LocalMute { muted: true, .. }
            ));
        }
        assert!(member.persisted().local_mute);
        fault_and_reset(&mut rig, &mut adapter, &mut member);
        assert_eq!(
            rig.press_into(MUTE, &mut adapter, &mut member),
            ButtonAction::Ignored(IgnoredButton::AwaitingRelease)
        );
        assert!(member.persisted().local_mute);
        rig.wait(20);
        rig.release_into(MUTE, &mut adapter, &mut member);
        assert!(matches!(
            rig.press_into(MUTE, &mut adapter, &mut member),
            ButtonAction::LocalMute { muted: false, .. }
        ));
        assert!(!member.persisted().local_mute);
        eprintln!(
            "G02_BUTTON_RECOVERY late_mute={mute_set_during_outage} stats={:?}",
            adapter.stats()
        );
    }
}

#[test]
fn unknown_and_repeated_fault_preserve_release_and_repeat_guards() {
    let mut adapter = adapter();
    let mut member = member();
    assert!(matches!(
        adapter.on_event(down(UP, 100), &mut member),
        ButtonAction::TrimStep { .. }
    ));
    assert_eq!(
        adapter.on_event(changed(UP, ButtonState::Unknown, 101), &mut member),
        ButtonAction::Ignored(IgnoredButton::UnknownState)
    );
    adapter.on_event(ChannelEvent::Faulted { at: 102 }, &mut member);
    adapter.on_event(ChannelEvent::Lost { at: 103 }, &mut member);
    assert_eq!(
        adapter.on_event(down(UP, 104), &mut member),
        ButtonAction::Ignored(IgnoredButton::AwaitingRelease)
    );
    assert_eq!(member.trim_permille(), 1_100);
    adapter.on_event(up(UP, 105), &mut member);
    assert_eq!(
        adapter.on_event(down(UP, 106), &mut member),
        ButtonAction::Ignored(IgnoredButton::TooSoonAfterLastPress)
    );
    adapter.on_event(up(UP, 107), &mut member);
    assert!(matches!(
        adapter.on_event(down(UP, 110), &mut member),
        ButtonAction::TrimStep {
            trim_permille: 1_200,
            ..
        }
    ));
    assert_eq!(adapter.stats().awaiting_release, 1);
    for uncertain in [
        ChannelEvent::Lost { at: 1 },
        ChannelEvent::Faulted { at: 1 },
        changed(MUTE, ButtonState::Unknown, 1),
    ] {
        let mut adapter = super::ButtonAdapter::new(map(), bounds());
        let mut member = super::MemberVolume::new(1.0);
        adapter.on_event(uncertain, &mut member);
        assert!(matches!(
            adapter.on_event(down(MUTE, 100), &mut member),
            ButtonAction::LocalMute { muted: true, .. }
        ));
        assert_eq!(
            adapter.on_event(down(MUTE, 200), &mut member),
            ButtonAction::Ignored(IgnoredButton::AwaitingRelease)
        );
        assert!(member.persisted().local_mute);
        adapter.on_event(up(MUTE, 201), &mut member);
        assert!(matches!(
            adapter.on_event(down(MUTE, 210), &mut member),
            ButtonAction::LocalMute { muted: false, .. }
        ));
        adapter.on_event(uncertain, &mut member);
        member.local_mute(true);
        assert_eq!(
            adapter.on_event(down(MUTE, 300), &mut member),
            ButtonAction::Ignored(IgnoredButton::AwaitingRelease)
        );
        assert!(member.persisted().local_mute);
    }
}

// ---- authority and configuration -------------------------------------------------------------------------------------

#[test]
fn a_button_works_for_a_member_with_no_authority_and_the_remote_path_is_shown_dead() {
    let mut a = adapter();
    let mut m = MemberVolume::new(1.0); // never joined: no network, no controller, no epoch
    assert_eq!(
        m.apply(stamp(1), VolumeCommand::SetVolume(50)),
        Err(franken_dsp::volume::VolumeError::NoAuthority)
    );
    assert_eq!(
        a.on_event(down(MUTE, 100), &mut m),
        ButtonAction::LocalMute {
            muted: true,
            effective_mute: Some(MuteReason::Local)
        }
    );
    assert_eq!(
        a.on_event(down(UP, 200), &mut m),
        ButtonAction::TrimStep {
            trim_permille: 1_100,
            effective_mute: Some(MuteReason::Local)
        }
    );
    // The mute button clears the local reason; the room is still silent for a member that has not joined.
    assert_eq!(
        a.on_event(down(MUTE, 300), &mut m),
        ButtonAction::LocalMute {
            muted: false,
            effective_mute: Some(MuteReason::Join)
        }
    );
}

#[test]
fn a_configuration_that_cannot_work_is_refused_and_a_working_one_is_accepted() {
    assert_eq!(
        ButtonMap::new(0, 0, 2),
        Err(ButtonConfigError::SharedButton { id: 0 })
    );
    assert_eq!(
        ButtonMap::new(0, 1, 0),
        Err(ButtonConfigError::SharedButton { id: 0 })
    );
    assert_eq!(
        ButtonMap::new(0, 1, 1),
        Err(ButtonConfigError::SharedButton { id: 1 })
    );
    assert!(ButtonMap::new(0, 1, 2).is_ok());

    for step in [0i16, -1, 501, i16::MIN, i16::MAX] {
        assert_eq!(
            ButtonBounds::new(step, 10, 1_000),
            Err(ButtonConfigError::StepOutOfRange { step })
        );
    }
    for step in [1i16, 100, 500] {
        assert!(ButtonBounds::new(step, 10, 1_000).is_ok(), "{step}");
    }
    assert_eq!(
        ButtonBounds::new(100, 0, 1_000),
        Err(ButtonConfigError::NoRepeatBound)
    );
    assert_eq!(
        ButtonBounds::new(100, 10, 0),
        Err(ButtonConfigError::NoStuckBound)
    );

    // The member's own refusal is passed through if a step the constructor would have refused ever reached it,
    // and nothing changes; the validated bounds do not hit it (the pair).
    let mut bad = ButtonAdapter::new(
        map(),
        ButtonBounds {
            trim_step_permille: 900,
            min_press_interval_ticks: 10,
            stuck_after_ticks: 1_000,
        },
    );
    let mut m = member();
    assert_eq!(
        bad.on_event(down(UP, 100), &mut m),
        ButtonAction::Refused(franken_dsp::volume::VolumeError::StepOutOfRange { delta: 900 })
    );
    assert_eq!(m.trim_permille(), 1_000);
    let mut good = adapter();
    assert!(matches!(
        good.on_event(down(UP, 100), &mut m),
        ButtonAction::TrimStep { .. }
    ));
}

// ---- with the real board, cloud retries and a rejoin -------------------------------------------------------------------------

#[test]
fn a_local_mute_survives_cloud_retries_and_a_rejoin_and_unmuting_plays_the_groups_volume() {
    let mut rig = Rig::new();
    let mut a = adapter();
    let mut m = member();
    let mut dsp = board("S5");
    m.sync(&mut dsp).expect("hand the state to the board");

    // The cloud sets the group to 0.5, and it completes on the board.
    m.apply(stamp(1), VolumeCommand::SetVolume(50))
        .expect("accepted");
    m.apply_to(&mut dsp).expect("hand over");
    render_silence(&mut dsp, 300);
    assert!(matches!(
        m.progress(stamp(1), &dsp),
        Ok(CommandProgress::Completed { .. })
    ));

    // The room's mute button, a real HAL event, silences it. The button is released again: the channel reports a press
    // only on a change of state, so the same button pressed a second time without a release in between would be a
    // duplicate `Down` and deliver nothing (the unmute press at the end of this test depends on that release).
    assert!(matches!(
        rig.press_into(MUTE, &mut a, &mut m),
        ButtonAction::LocalMute { muted: true, .. }
    ));
    assert_eq!(
        rig.release_into(MUTE, &mut a, &mut m),
        ButtonAction::Ignored(IgnoredButton::Release)
    );
    assert!(
        m.persisted().local_mute,
        "the release did not undo the press"
    );
    m.sync(&mut dsp).expect("sync");
    render_silence(&mut dsp, 600);
    assert_eq!(dsp.applied_gain(), 0.0);
    // That command's 0.5 is no longer being pursued.
    assert_eq!(m.progress(stamp(1), &dsp), Ok(CommandProgress::Superseded));

    // Cloud retries: a replay of revision 1 is a duplicate and does not unmute; a new volume command is accepted and
    // the room stays silent, which the receipt says; a stale retry afterwards is refused.
    let replay = m
        .apply(stamp(1), VolumeCommand::SetVolume(50))
        .expect("duplicate");
    assert!(replay.duplicate);
    assert_eq!(replay.effective_mute, Some(MuteReason::Local));
    let second = m
        .apply(stamp(2), VolumeCommand::SetVolume(80))
        .expect("accepted");
    assert_eq!(second.effective_mute, Some(MuteReason::Local));
    assert!(close(second.target_gain, 0.0));
    m.sync(&mut dsp).expect("sync");
    render_silence(&mut dsp, 600);
    assert_eq!(
        m.progress(stamp(2), &dsp),
        Ok(CommandProgress::Completed {
            target_gain: 0.0,
            effective_mute: Some(MuteReason::Local)
        })
    );
    assert!(
        m.apply(stamp(1), VolumeCommand::SetVolume(50)).is_err(),
        "the stale retry is refused"
    );

    // A volume press while muted moves the trim and never unmutes; a bounce right after it is ignored.
    rig.wait(20);
    assert_eq!(
        rig.press_into(UP, &mut a, &mut m),
        ButtonAction::TrimStep {
            trim_permille: 1_100,
            effective_mute: Some(MuteReason::Local)
        }
    );
    rig.release_into(UP, &mut a, &mut m);
    assert_eq!(
        rig.press_into(UP, &mut a, &mut m),
        ButtonAction::Ignored(IgnoredButton::TooSoonAfterLastPress)
    );
    m.sync(&mut dsp).expect("sync");
    render_silence(&mut dsp, 600);
    assert_eq!(dsp.applied_gain(), 0.0, "a volume press does not unmute");

    // The room rejoins a LOUDER group (0.9). The local mute survives the reconnect and the whole join.
    m.reconnect(GroupSnapshot {
        epoch: EPOCH,
        revision: 5,
        master_volume: 90,
        group_mute: false,
    })
    .expect("reconnect");
    m.sync(&mut dsp).expect("sync");
    render_silence(&mut dsp, 600);
    assert_eq!(dsp.applied_gain(), 0.0);
    assert_eq!(m.effective_mute(), Some(MuteReason::Local));
    m.complete_join();
    m.sync(&mut dsp).expect("sync");
    render_silence(&mut dsp, 600);
    assert_eq!(
        dsp.applied_gain(),
        0.0,
        "the join finished, and the room's own mute still holds"
    );

    // Only the room's own button lifts it, and then the board plays the GROUP's volume (0.9) times the room's trim
    // (1.1): not the stale 0.5, and not louder than that.
    rig.wait(20);
    assert_eq!(
        rig.press_into(MUTE, &mut a, &mut m),
        ButtonAction::LocalMute {
            muted: false,
            effective_mute: None
        }
    );
    m.sync(&mut dsp).expect("sync");
    render_silence(&mut dsp, 600);
    assert!(close(m.output_gain(), 0.99), "{}", m.output_gain());
    assert!(close(dsp.applied_gain(), 0.99), "{}", dsp.applied_gain());
}

#[test]
fn a_fault_mute_that_overrides_a_requested_unmute_is_reported_and_the_board_stays_silent() {
    // A board that was not admitted (no calibration) is fail-muted: it cannot be unmuted.
    let profile = fixture("S5");
    let mut dsp = ProtectedBoardDsp::admit(&profile, None, Admission::HostSimulation);
    let mut a = adapter();
    let mut m = member();
    m.sync(&mut dsp)
        .expect("the member follows the board into a fault mute");

    assert_eq!(
        a.on_event(down(MUTE, 100), &mut m),
        ButtonAction::LocalMute {
            muted: true,
            effective_mute: Some(MuteReason::Fault)
        }
    );
    // The requested unmute is overridden, and the action says which reason is holding it.
    assert_eq!(
        a.on_event(down(MUTE, 200), &mut m),
        ButtonAction::LocalMute {
            muted: false,
            effective_mute: Some(MuteReason::Fault)
        }
    );
    m.sync(&mut dsp).expect("sync");
    render_silence(&mut dsp, 600);
    assert!(dsp.is_muted());
    assert_eq!(dsp.applied_gain(), 0.0);

    // Paired positive: the same two presses on an admitted board end audible, with no reason reported.
    let mut ok_member = member();
    let mut ok_board = board("S5");
    ok_member.sync(&mut ok_board).expect("sync");
    ok_member
        .apply(stamp(1), VolumeCommand::SetVolume(50))
        .expect("accepted");
    let mut ok_adapter = adapter();
    ok_adapter.on_event(down(MUTE, 100), &mut ok_member);
    assert_eq!(
        ok_adapter.on_event(down(MUTE, 200), &mut ok_member),
        ButtonAction::LocalMute {
            muted: false,
            effective_mute: None
        }
    );
    ok_member.sync(&mut ok_board).expect("sync");
    render_silence(&mut ok_board, 600);
    assert!(close(ok_board.applied_gain(), 0.5));
}

// ---- planted wrong mappings -----------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Planted {
    None,
    /// The defect "a press that also releases": every release is treated as one more press.
    PressAlsoReleases,
}

/// Events with ticks far enough apart that the repeat bound cannot hide a defect, run through an adapter with `map`.
fn mapping_trace(map: ButtonMap, planted: Planted) -> Vec<ButtonAction> {
    let mut a = ButtonAdapter::new(map, bounds());
    let mut m = member();
    let release = |id: u8, at: u64| {
        if planted == Planted::PressAlsoReleases {
            down(id, at)
        } else {
            up(id, at)
        }
    };
    [
        down(MUTE, 100),
        release(MUTE, 200),
        down(UP, 300),
        release(UP, 400),
        down(DOWN, 500),
    ]
    .into_iter()
    .map(|event| a.on_event(event, &mut m))
    .collect()
}

/// What the sound mapping must produce: mute on, release nothing, one step up, release nothing, one step down.
fn expected_trace() -> Vec<ButtonAction> {
    let local = Some(MuteReason::Local);
    vec![
        ButtonAction::LocalMute {
            muted: true,
            effective_mute: local,
        },
        ButtonAction::Ignored(IgnoredButton::Release),
        ButtonAction::TrimStep {
            trim_permille: 1_100,
            effective_mute: local,
        },
        ButtonAction::Ignored(IgnoredButton::Release),
        ButtonAction::TrimStep {
            trim_permille: 1_000,
            effective_mute: local,
        },
    ]
}

#[test]
fn the_sound_mapping_produces_exactly_the_expected_actions() {
    assert_eq!(mapping_trace(map(), Planted::None), expected_trace());
}

#[test]
fn a_mute_bound_to_the_trim_is_caught() {
    // The defect: the mute button's id wired to the volume-up role (and the volume-up id to mute).
    let swapped = ButtonMap::new(UP, MUTE, DOWN).expect("distinct ids");
    let trace = mapping_trace(swapped, Planted::None);
    assert_ne!(
        trace,
        expected_trace(),
        "the expectations must fail for a swapped mapping"
    );
    assert!(
        matches!(trace[0], ButtonAction::TrimStep { .. }),
        "the mute id now moves the trim: {:?}",
        trace[0]
    );
}

#[test]
fn a_press_that_also_releases_is_caught() {
    let trace = mapping_trace(map(), Planted::PressAlsoReleases);
    assert_ne!(
        trace,
        expected_trace(),
        "the expectations must fail when a release acts as a press"
    );
    // The release of the mute button toggles the mute straight back off: the press had no lasting effect.
    assert_eq!(
        trace[1],
        ButtonAction::LocalMute {
            muted: false,
            effective_mute: None
        }
    );
}

// ---- against an independent model ----------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct ModelPress {
    down_at: Option<u64>,
    last_applied: Option<u64>,
    stuck: bool,
    require_release: bool,
}

#[derive(PartialEq, Eq, Debug)]
enum Kind {
    Muted(bool),
    Trim(u16),
    Ignored(&'static str),
    Reset,
}

fn kind_of(action: ButtonAction) -> Kind {
    match action {
        ButtonAction::LocalMute { muted, .. } => Kind::Muted(muted),
        ButtonAction::TrimStep { trim_permille, .. } => Kind::Trim(trim_permille),
        ButtonAction::Ignored(IgnoredButton::Release) => Kind::Ignored("release"),
        ButtonAction::Ignored(IgnoredButton::ReleaseOfStuckButton) => {
            Kind::Ignored("release_of_stuck")
        }
        ButtonAction::Ignored(IgnoredButton::UnknownState) => Kind::Ignored("unknown"),
        ButtonAction::Ignored(IgnoredButton::Unmapped) => Kind::Ignored("unmapped"),
        ButtonAction::Ignored(IgnoredButton::TooSoonAfterLastPress) => Kind::Ignored("too_soon"),
        ButtonAction::Ignored(IgnoredButton::WhileStuck) => Kind::Ignored("while_stuck"),
        ButtonAction::Ignored(IgnoredButton::AwaitingRelease) => Kind::Ignored("awaiting_release"),
        ButtonAction::Ignored(IgnoredButton::NotAButtonEvent) => Kind::Ignored("not_a_button"),
        ButtonAction::Refused(_) => Kind::Ignored("refused"),
        ButtonAction::ChannelReset => Kind::Reset,
    }
}

#[test]
fn over_random_events_cloud_commands_and_rejoins_the_adapter_matches_a_plain_model_and_never_touches_the_group()
 {
    let mut rng = SplitMix(0x00_6705_B077);
    let mut tally = [0u32; 8]; // mute toggles, trim steps, too soon, while stuck, unknown, unmapped, resets, stuck polls
    for seed in 0..4u64 {
        let mut a = adapter();
        let mut m = member();
        let (mut local_mute, mut trim) = (false, 1_000i32);
        let mut model = [ModelPress::default(); 3];
        let (mut at, mut revision) = (0u64, 0u64);
        for step in 0..3_000u32 {
            let context = format!("seed {seed} step {step}");
            match rng.draw() % 10 {
                0..=5 => {
                    let id = (rng.draw() % 5) as u8; // 0, 1, 2 mapped; 3, 4 not
                    let state = match rng.draw() % 6 {
                        0..=2 => ButtonState::Down,
                        3 | 4 => ButtonState::Up,
                        _ => ButtonState::Unknown,
                    };
                    at += 1 + rng.draw() % 25;
                    let group_before = (m.desired_volume(), m.epoch(), m.last_revision());
                    let got = kind_of(a.on_event(changed(id, state, at), &mut m));
                    assert_eq!(
                        (m.desired_volume(), m.epoch(), m.last_revision()),
                        group_before,
                        "{context}: a button event touched the group's state"
                    );
                    // The model, restated from the clause and the bounds.
                    let want = match (usize::from(id), state) {
                        (3 | 4, _) => {
                            tally[5] += 1;
                            Kind::Ignored("unmapped")
                        }
                        (role, ButtonState::Unknown) => {
                            model[role].require_release |=
                                model[role].down_at.is_some() || model[role].stuck || role == 0;
                            model[role].down_at = None;
                            model[role].stuck = false;
                            tally[4] += 1;
                            Kind::Ignored("unknown")
                        }
                        (role, ButtonState::Up) => {
                            model[role].require_release = false;
                            let was_stuck = model[role].stuck;
                            model[role].down_at = None;
                            model[role].stuck = false;
                            Kind::Ignored(if was_stuck {
                                "release_of_stuck"
                            } else {
                                "release"
                            })
                        }
                        (role, ButtonState::Down) => {
                            if model[role].require_release && (role != 0 || local_mute) {
                                Kind::Ignored("awaiting_release")
                            } else if model[role].stuck {
                                tally[3] += 1;
                                Kind::Ignored("while_stuck")
                            } else {
                                model[role].down_at = Some(at);
                                let too_soon = model[role]
                                    .last_applied
                                    .is_some_and(|last| at.saturating_sub(last) < 10);
                                if too_soon {
                                    tally[2] += 1;
                                    Kind::Ignored("too_soon")
                                } else {
                                    model[role].last_applied = Some(at);
                                    match role {
                                        0 => {
                                            local_mute = !local_mute;
                                            tally[0] += 1;
                                            Kind::Muted(local_mute)
                                        }
                                        1 => {
                                            trim = (trim + 100).clamp(0, 2_000);
                                            tally[1] += 1;
                                            Kind::Trim(u16::try_from(trim).expect("0..=2000"))
                                        }
                                        _ => {
                                            trim = (trim - 100).clamp(0, 2_000);
                                            tally[1] += 1;
                                            Kind::Trim(u16::try_from(trim).expect("0..=2000"))
                                        }
                                    }
                                }
                            }
                        }
                    };
                    assert_eq!(got, want, "{context}: id {id} {state:?} at {at}");
                }
                6 => {
                    at += rng.draw() % 1_500;
                    let got = a.poll(at);
                    let mut want = Vec::new();
                    for (index, role) in ButtonRole::ALL.into_iter().enumerate() {
                        let press = &mut model[index];
                        if !press.stuck
                            && press.down_at.is_some_and(|d| at.saturating_sub(d) >= 1_000)
                        {
                            press.stuck = true;
                            want.push(role);
                            tally[7] += 1;
                        }
                    }
                    assert_eq!(got, want, "{context}: poll at {at}");
                }
                7 => {
                    // cloud traffic: a command, sometimes a replay of the last one
                    revision += 1;
                    let command = match rng.draw() % 3 {
                        0 => VolumeCommand::SetVolume((rng.draw() % 101) as u8),
                        1 => VolumeCommand::AdjustVolume((rng.draw() % 61) as i16 - 30),
                        _ => VolumeCommand::SetGroupMute(rng.draw().is_multiple_of(3)),
                    };
                    m.apply(stamp(revision), command)
                        .unwrap_or_else(|e| panic!("{context}: {e:?}"));
                    if rng.draw().is_multiple_of(4) {
                        let replay = m
                            .apply(stamp(revision), command)
                            .expect("a replay is a duplicate");
                        assert!(replay.duplicate, "{context}");
                    }
                }
                8 => {
                    let event = match rng.draw() % 3 {
                        0 => ChannelEvent::Lost { at },
                        1 => ChannelEvent::Faulted { at },
                        _ => ChannelEvent::LedFault { id: 0, at },
                    };
                    let got = kind_of(a.on_event(event, &mut m));
                    if matches!(event, ChannelEvent::LedFault { .. }) {
                        assert_eq!(got, Kind::Ignored("not_a_button"), "{context}");
                    } else {
                        assert_eq!(got, Kind::Reset, "{context}");
                        for (role, press) in model.iter_mut().enumerate() {
                            press.require_release |=
                                press.down_at.is_some() || press.stuck || role == 0;
                            press.down_at = None;
                            press.stuck = false;
                        }
                        tally[6] += 1;
                    }
                }
                _ => {
                    // a rejoin to a louder or quieter group: the room's own mute and trim are kept
                    revision += rng.draw() % 50;
                    m.reconnect(GroupSnapshot {
                        epoch: EPOCH,
                        revision,
                        master_volume: (rng.draw() % 101) as u8,
                        group_mute: false,
                    })
                    .expect("reconnect");
                    m.complete_join();
                }
            }
            // After every step: the room's own state is exactly the model's, whatever the cloud did.
            assert_eq!(m.persisted().local_mute, local_mute, "{context}");
            assert_eq!(i32::from(m.trim_permille()), trim, "{context}");
        }
    }
    // Floors at about a third of what the schedule produces in the Python mirror (mute toggles 663, trim steps 1316,
    // too soon 62, while stuck 163, unknown 714, unmapped 2823, resets 833, stuck polls 346), so every branch is reached.
    let [
        mutes,
        trims,
        too_soon,
        while_stuck,
        unknown,
        unmapped,
        resets,
        stuck_polls,
    ] = tally;
    assert!(
        mutes >= 200
            && trims >= 400
            && too_soon >= 20
            && while_stuck >= 50
            && unknown >= 230
            && unmapped >= 900
            && resets >= 270
            && stuck_polls >= 110,
        "the schedule stopped reaching every branch: {tally:?}"
    );
}
