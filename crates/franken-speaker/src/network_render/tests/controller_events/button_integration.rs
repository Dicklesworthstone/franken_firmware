//! Owned local-button integration over the modeled HAL and protected renderer.
//! All buttons and playback here are simulated, not physical-device evidence.
use super::*;
use crate::button_adapter::{ButtonAction, ButtonBounds, ButtonMap, ButtonRole, IgnoredButton};
use crate::settled_render::ButtonInputError;
use franken_dsp::volume::MuteReason;
use franken_hal::backend::LocalEventCapability;
use franken_hal::events::{
    ButtonState, ChannelEvent, ChannelState, EventChannelConfig, FakeEventProbe, FakeEventSource,
    LocalEventChannel, LocalEventKind, SYNC,
};

const MUTE: u8 = 0;
const UP: u8 = 1;
const DOWN: u8 = 2;

fn button_map() -> ButtonMap {
    ButtonMap::new(MUTE, UP, DOWN).unwrap()
}
fn button_bounds() -> ButtonBounds {
    ButtonBounds::new(100, 10, 1_000).unwrap()
}

/// A declared host model whose fake source is parsed and debounced by the
/// production HAL LocalEventChannel. No source calls any physical hardware.
struct ButtonChannel {
    channel: LocalEventChannel<FakeEventSource>,
    probe: FakeEventProbe,
    tick: u64,
}
impl ButtonChannel {
    fn new() -> Self {
        let (source, probe) = FakeEventSource::new();
        let capability = LocalEventCapability::Declared {
            abi_evidence: "P04 host model, not a hardware ABI".into(),
        };
        let channel =
            LocalEventChannel::open(&capability, source, EventChannelConfig::standard()).unwrap();
        Self {
            channel,
            probe,
            tick: 100,
        }
    }
    fn drain_one(&mut self) -> ChannelEvent {
        let event = self.channel.take().expect("one real debounced HAL event");
        assert!(self.channel.take().is_none());
        event
    }
    fn edge(&mut self, kind: LocalEventKind, id: u8) -> ChannelEvent {
        self.probe.push_event(kind, id, 0);
        let _ = self.channel.pump(self.tick);
        self.tick += 3;
        let _ = self.channel.pump(self.tick);
        self.drain_one()
    }
    fn down(&mut self, id: u8) -> ChannelEvent {
        let event = self.edge(LocalEventKind::ButtonDown, id);
        assert!(
            matches!(event, ChannelEvent::ButtonChanged { id: actual, state: ButtonState::Down, .. } if actual == id)
        );
        event
    }
    fn up(&mut self, id: u8) -> ChannelEvent {
        let event = self.edge(LocalEventKind::ButtonUp, id);
        assert!(
            matches!(event, ChannelEvent::ButtonChanged { id: actual, state: ButtonState::Up, .. } if actual == id)
        );
        event
    }
    fn wait(&mut self, ticks: u64) {
        self.tick += ticks;
        let _ = self.channel.pump(self.tick);
    }
    fn fault_and_reset(&mut self) -> ChannelEvent {
        self.probe.push_chunk([SYNC, 9, 0, 0, 0, 0, 0, 0].repeat(3));
        self.wait(1);
        assert_eq!(self.channel.channel_state(), ChannelState::Faulted);
        let event = self.drain_one();
        assert!(matches!(event, ChannelEvent::Faulted { .. }));
        assert!(self.channel.reset());
        event
    }
}

#[test]
fn owned_buttons_keep_initial_mute_until_observed_release_and_preserve_trim() {
    let mut rig = prepared_owner_with_completion(true, 2);
    let mut buttons = ButtonChannel::new();
    let before_calls = rig.probe.calls();
    let before_pcm = rig.probe.captured_submissions();
    let event = ChannelEvent::LedFault { id: 3, at: 0 };
    assert!(matches!(
        rig.owner.handle_button_event(event),
        Err(ButtonInputError::NotConfigured)
    ));
    assert!(matches!(
        rig.owner.poll_buttons(0),
        Err(ButtonInputError::NotConfigured)
    ));
    assert!(rig.owner.button_stats().is_none());
    assert_eq!(rig.owner.received_frames_pulled(), 0);
    assert_eq!(rig.probe.calls(), before_calls);
    assert_eq!(rig.probe.captured_submissions(), before_pcm);

    rig.owner
        .configure_buttons(button_map(), button_bounds())
        .unwrap();
    assert!(matches!(
        rig.owner.configure_buttons(button_map(), button_bounds()),
        Err(ButtonInputError::AlreadyConfigured)
    ));
    assert!(matches!(
        rig.owner.local_mute(true),
        Ok(RenderApplication::WaitingJoin)
    ));
    assert_eq!(rig.owner.effective_mute(), Some(MuteReason::Local));
    // No prior mute-channel edge has been delivered after attachment. An
    // initial Unknown->Down cannot clear intent set before the first edge.
    assert_eq!(buttons.channel.button_state(MUTE), ButtonState::Unknown);
    let before_calls = rig.probe.calls();
    let before_pcm = rig.probe.captured_submissions();
    let ignored = rig.owner.handle_button_event(buttons.down(MUTE)).unwrap();
    assert_eq!(
        ignored.action,
        ButtonAction::Ignored(IgnoredButton::AwaitingRelease)
    );
    assert!(ignored.render.is_none());
    assert_eq!(rig.owner.effective_mute(), Some(MuteReason::Local));
    assert_eq!(rig.probe.calls(), before_calls);
    assert_eq!(rig.probe.captured_submissions(), before_pcm);
    assert_eq!(rig.owner.received_frames_pulled(), 0);
    let different_map = ButtonMap::new(UP, MUTE, DOWN).unwrap();
    assert!(matches!(
        rig.owner.configure_buttons(different_map, button_bounds()),
        Err(ButtonInputError::AlreadyConfigured)
    ));
    assert_eq!(rig.owner.button_stats().unwrap().awaiting_release, 1);
    let fault = buttons.fault_and_reset();
    let reset = rig.owner.handle_button_event(fault).unwrap();
    assert_eq!(reset.action, ButtonAction::ChannelReset);
    assert!(reset.render.is_none());
    assert_eq!(buttons.channel.button_state(MUTE), ButtonState::Unknown);
    let held = rig.owner.handle_button_event(buttons.down(MUTE)).unwrap();
    assert_eq!(
        held.action,
        ButtonAction::Ignored(IgnoredButton::AwaitingRelease)
    );
    assert!(held.render.is_none());
    assert_eq!(rig.owner.effective_mute(), Some(MuteReason::Local));
    assert_eq!(rig.probe.calls(), before_calls);
    assert_eq!(rig.probe.captured_submissions(), before_pcm);

    let trim = rig.owner.handle_button_event(buttons.down(UP)).unwrap();
    assert!(matches!(
        trim.action,
        ButtonAction::TrimStep {
            trim_permille: 1_100,
            effective_mute: Some(MuteReason::Local)
        }
    ));
    assert!(matches!(
        trim.render,
        Some(Ok(RenderApplication::WaitingJoin))
    ));
    assert_eq!(rig.owner.effective_mute(), Some(MuteReason::Local));
    buttons.wait(1_000);
    assert_eq!(
        rig.owner.poll_buttons(buttons.tick).unwrap(),
        vec![ButtonRole::VolumeUp]
    );
    assert!(rig.owner.poll_buttons(buttons.tick).unwrap().is_empty());
    assert_eq!(rig.owner.button_is_stuck(ButtonRole::VolumeUp), Some(true));
    let release_volume = rig.owner.handle_button_event(buttons.up(UP)).unwrap();
    assert_eq!(
        release_volume.action,
        ButtonAction::Ignored(IgnoredButton::ReleaseOfStuckButton)
    );
    assert!(release_volume.render.is_none());
    assert_eq!(rig.owner.button_is_stuck(ButtonRole::VolumeUp), Some(false));
    let release = rig.owner.handle_button_event(buttons.up(MUTE)).unwrap();
    assert_eq!(
        release.action,
        ButtonAction::Ignored(IgnoredButton::Release)
    );
    assert!(release.render.is_none());
    buttons.wait(20);
    let unmute = rig.owner.handle_button_event(buttons.down(MUTE)).unwrap();
    assert!(matches!(
        unmute.action,
        ButtonAction::LocalMute {
            muted: false,
            effective_mute: Some(MuteReason::Join)
        }
    ));
    assert!(matches!(
        unmute.render,
        Some(Ok(RenderApplication::WaitingJoin))
    ));
    let stats = rig.owner.button_stats().unwrap();
    assert_eq!(stats.channel_resets, 1);
    assert_eq!(stats.awaiting_release, 2);
    assert_eq!(stats.trim_steps, 1);
    assert_eq!(stats.mute_toggles, 1);
    assert_eq!(stats.stuck_detected, 1);
    activate_for_media(&mut rig);
    assert!(matches!(
        rig.owner.configure_buttons(button_map(), button_bounds()),
        Err(ButtonInputError::AlreadyConfigured)
    ));
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    let mut audible = false;
    for step in 0..5000_u64 {
        rig.local_now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        assert!(matches!(
            rig.owner.render_step(&mut timing).unwrap(),
            PlaybackStep::Render(_)
        ));
        if rig
            .probe
            .captured_submissions()
            .iter()
            .skip(1)
            .flatten()
            .any(|b| *b != 0)
        {
            audible = true;
            break;
        }
    }
    assert!(audible);
    assert!(rig.owner.received_frames_pulled() > 0);
    assert!(rig.owner.request_stop().is_ok());
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert!(matches!(
        rig.owner.configure_buttons(button_map(), button_bounds()),
        Err(ButtonInputError::AlreadyConfigured)
    ));
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}

#[test]
fn buttons_cannot_be_configured_after_join_proposal_or_stop_even_if_absent() {
    let mut proposed = prepared_owner_with_completion(true, 2);
    assert!(proposed.owner.button_stats().is_none());
    let id = begin_local_join(&mut proposed);
    assert!(id > 0);
    assert!(matches!(
        proposed
            .owner
            .configure_buttons(button_map(), button_bounds()),
        Err(ButtonInputError::ConfigurationClosed)
    ));
    assert!(proposed.owner.button_stats().is_none());
    assert!(proposed.owner.request_stop().is_ok());
    assert!(finish_drain(&mut proposed.owner).acknowledged);
    assert!(matches!(
        proposed
            .owner
            .configure_buttons(button_map(), button_bounds()),
        Err(ButtonInputError::ConfigurationClosed)
    ));
    assert!(proposed.owner.button_stats().is_none());
}

/// Preserve full finite protected PCM so the applied trim can be compared with
/// the same source and same owner path without using a DSP gain fixture as proof.
fn rendered_button_trim(with_trim: bool) -> Vec<Vec<u8>> {
    let mut rig = prepared_owner_with_completion(true, 2);
    rig.probe.capture_submissions(128);
    rig.owner
        .configure_buttons(button_map(), button_bounds())
        .unwrap();
    let mut buttons = ButtonChannel::new();
    if with_trim {
        let action = rig.owner.handle_button_event(buttons.down(UP)).unwrap();
        assert!(matches!(
            action.action,
            ButtonAction::TrimStep {
                trim_permille: 1_100,
                ..
            }
        ));
        assert!(matches!(
            action.render,
            Some(Ok(RenderApplication::WaitingJoin))
        ));
        let release = rig.owner.handle_button_event(buttons.up(UP)).unwrap();
        assert_eq!(
            release.action,
            ButtonAction::Ignored(IgnoredButton::Release)
        );
        assert!(release.render.is_none());
    }
    activate_for_media(&mut rig);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    let mut draining = false;
    for step in 0..5000_u64 {
        rig.local_now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        assert!(matches!(
            rig.owner.render_step(&mut timing).unwrap(),
            PlaybackStep::Render(_)
        ));
        if rig.owner.render_state() == RenderState::Draining {
            draining = true;
            break;
        }
    }
    assert!(draining);
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert_eq!(rig.owner.received_frames_pulled(), 512);
    assert_eq!(rig.probe.pending(), 0);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    let pcm = rig.probe.captured_submissions();
    assert!(pcm.len() > 1);
    pcm[1..].to_vec()
}

#[test]
fn debounced_trim_changes_actual_protected_pcm_without_unmuting() {
    let baseline = rendered_button_trim(false);
    let trimmed = rendered_button_trim(true);
    assert_eq!(baseline.len(), trimmed.len());
    assert!(baseline.iter().flatten().any(|b| *b != 0));
    assert!(trimmed.iter().flatten().any(|b| *b != 0));
    assert_ne!(
        baseline, trimmed,
        "local trim must affect actual protected output"
    );
}

#[test]
fn local_button_mute_survives_clock_failure_and_reports_real_drain_custody() {
    for ack in [true, false] {
        let mut rig = prepared_owner_with_completion(true, 2);
        rig.probe.capture_submissions(128);
        rig.owner
            .configure_buttons(button_map(), button_bounds())
            .unwrap();
        activate_for_media(&mut rig);
        let mut timing = ScriptedTiming {
            default_cost: 1,
            ..ScriptedTiming::default()
        };
        let mut token = None;
        for step in 0..5000_u64 {
            rig.local_now
                .set(rig.start_local_ns - 15_000_000 + step * 100_000);
            assert!(matches!(
                rig.owner.render_step(&mut timing).unwrap(),
                PlaybackStep::Render(_)
            ));
            let captured = rig.probe.captured_submissions();
            if captured.len() > 1 && captured.last().unwrap().iter().any(|b| *b != 0) {
                let calls = rig.probe.calls();
                let submitted = calls
                    .iter()
                    .rev()
                    .find_map(|call| match call {
                        FakeCall::SubmitRetained {
                            slot, generation, ..
                        } => Some((*slot, *generation)),
                        _ => None,
                    })
                    .unwrap();
                assert!(rig.probe.pending_slots().contains(&submitted));
                token = Some(submitted);
                break;
            }
        }
        let token = token.expect("require an actual nonzero retained program submission");
        rig.probe.set_lose_completions(true);
        let held = rig.probe.pending_slots();
        let captured = rig.probe.captured_submissions();
        let pulled = rig.owner.received_frames_pulled();
        assert!(pulled > 0);
        assert!(held.contains(&token));
        assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
        rig.suppress_flush.set(!ack);
        rig.clock_fail.set(true);
        let mut buttons = ButtonChannel::new();
        // An initial uncertain Down may mute an unmuted room. Intent is
        // applied even though render reconciliation cannot read group time.
        let event = rig.owner.handle_button_event(buttons.down(MUTE)).unwrap();
        assert!(matches!(
            event.action,
            ButtonAction::LocalMute {
                muted: true,
                effective_mute: Some(MuteReason::Local)
            }
        ));
        assert!(matches!(
            event.render,
            Some(Err(OwnerError::Render(NetworkRenderError::Clock)))
        ));
        assert_eq!(rig.owner.effective_mute(), Some(MuteReason::Local));
        assert_eq!(rig.owner.render_state(), RenderState::Draining);
        assert_eq!(rig.owner.received_frames_pulled(), pulled);
        assert_eq!(rig.probe.captured_submissions(), captured);
        assert_eq!(rig.probe.pending_slots(), held);
        assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
        let stop = finish_drain(&mut rig.owner);
        assert_eq!(stop.acknowledged, ack);
        assert_eq!(rig.owner.received_frames_pulled(), pulled);
        assert_eq!(rig.probe.captured_submissions(), captured);
        if ack {
            assert_eq!(rig.owner.render_state(), RenderState::Stopped);
            assert_eq!(rig.probe.pending(), 0);
            assert!(!rig.probe.pending_slots().contains(&token));
        } else {
            assert_eq!(rig.owner.render_state(), RenderState::Faulted);
            assert_eq!(rig.probe.pending_slots(), held);
            assert!(rig.probe.pending_slots().contains(&token));
            assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
        }
        assert_eq!(rig.probe.use_after_free(), 0);
        assert_eq!(rig.probe.modified_while_owned(), 0);
    }
}

/// Route a signed control through the owner's actual journal-backed channel.
fn commit_member_mute(
    rig: &mut ControllerRig,
    seq: u64,
    muted: bool,
    expected_revision: u64,
    revision: u64,
) {
    let wire = test_wire(
        TEST_CONTROLLER,
        seq,
        Some(expected_revision),
        ControlCommand::SetMemberMute {
            member_id: TEST_MEMBER.into(),
            muted,
        },
    );
    assert!(matches!(
        rig.owner.receive(&wire).unwrap(),
        FecHandled::Control(Handled::Request {
            result: SubmitResult::Queued { .. },
            ..
        })
    ));
    let applied = rig.owner.step_control().unwrap();
    let settled = applied.control.unwrap();
    assert_eq!(settled.len(), 1);
    assert!(
        matches!(settled[0].outcome, Outcome::Committed { revision: actual } if actual == revision)
    );
    assert!(matches!(
        applied.render,
        Ok(RenderApplication::PolicyAccepted)
    ));
}

#[test]
fn group_member_mute_and_button_local_mute_keep_distinct_owned_intents() {
    let mut rig = prepared_owner_with_completion(true, 2);
    rig.owner
        .configure_buttons(button_map(), button_bounds())
        .unwrap();
    activate_for_media(&mut rig);
    let mut buttons = ButtonChannel::new();
    commit_member_mute(&mut rig, 1, true, 1, 2);
    assert_eq!(rig.owner.effective_mute(), Some(MuteReason::Group));

    let local_on = rig.owner.handle_button_event(buttons.down(MUTE)).unwrap();
    assert!(matches!(
        local_on.action,
        ButtonAction::LocalMute {
            muted: true,
            effective_mute: Some(MuteReason::Local)
        }
    ));
    assert!(matches!(
        local_on.render,
        Some(Ok(RenderApplication::PolicyAccepted))
    ));
    let release = rig.owner.handle_button_event(buttons.up(MUTE)).unwrap();
    assert_eq!(
        release.action,
        ButtonAction::Ignored(IgnoredButton::Release)
    );
    assert!(release.render.is_none());
    buttons.wait(20);
    let local_off = rig.owner.handle_button_event(buttons.down(MUTE)).unwrap();
    assert!(matches!(
        local_off.action,
        ButtonAction::LocalMute {
            muted: false,
            effective_mute: Some(MuteReason::Group)
        }
    ));
    assert!(matches!(
        local_off.render,
        Some(Ok(RenderApplication::PolicyAccepted))
    ));
    assert_eq!(rig.owner.effective_mute(), Some(MuteReason::Group));

    let release = rig.owner.handle_button_event(buttons.up(MUTE)).unwrap();
    assert_eq!(
        release.action,
        ButtonAction::Ignored(IgnoredButton::Release)
    );
    assert!(release.render.is_none());
    buttons.wait(20);
    let local_on = rig.owner.handle_button_event(buttons.down(MUTE)).unwrap();
    assert!(matches!(
        local_on.action,
        ButtonAction::LocalMute {
            muted: true,
            effective_mute: Some(MuteReason::Local)
        }
    ));
    assert!(matches!(
        local_on.render,
        Some(Ok(RenderApplication::PolicyAccepted))
    ));
    commit_member_mute(&mut rig, 2, false, 2, 3);
    assert_eq!(rig.owner.effective_mute(), Some(MuteReason::Local));

    let release = rig.owner.handle_button_event(buttons.up(MUTE)).unwrap();
    assert_eq!(
        release.action,
        ButtonAction::Ignored(IgnoredButton::Release)
    );
    assert!(release.render.is_none());
    buttons.wait(20);
    let local_off = rig.owner.handle_button_event(buttons.down(MUTE)).unwrap();
    assert!(matches!(
        local_off.action,
        ButtonAction::LocalMute {
            muted: false,
            effective_mute: None
        }
    ));
    assert!(matches!(
        local_off.render,
        Some(Ok(RenderApplication::PolicyAccepted))
    ));
    assert_eq!(rig.owner.effective_mute(), None);
    assert!(rig.owner.request_stop().is_ok());
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert_eq!(rig.probe.pending(), 0);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}

#[test]
fn ignored_release_and_channel_reset_do_not_touch_active_render_with_failed_clock() {
    let mut rig = prepared_owner_with_completion(true, 2);
    rig.probe.capture_submissions(128);
    rig.owner
        .configure_buttons(button_map(), button_bounds())
        .unwrap();
    activate_for_media(&mut rig);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    let mut token = None;
    for step in 0..5000_u64 {
        rig.local_now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        assert!(matches!(
            rig.owner.render_step(&mut timing).unwrap(),
            PlaybackStep::Render(_)
        ));
        let pcm = rig.probe.captured_submissions();
        if pcm.len() > 1 && pcm.last().unwrap().iter().any(|b| *b != 0) {
            let calls = rig.probe.calls();
            let submitted = calls
                .iter()
                .rev()
                .find_map(|call| match call {
                    FakeCall::SubmitRetained {
                        slot, generation, ..
                    } => Some((*slot, *generation)),
                    _ => None,
                })
                .unwrap();
            assert!(rig.probe.pending_slots().contains(&submitted));
            token = Some(submitted);
            break;
        }
    }
    let token = token.expect("require actual nonzero retained program output");
    rig.probe.set_lose_completions(true);
    let state = rig.owner.render_state();
    assert!(matches!(state, RenderState::Running | RenderState::Muted));
    let calls = rig.probe.calls();
    let pcm = rig.probe.captured_submissions();
    let pulled = rig.owner.received_frames_pulled();
    assert!(pulled > 0);
    let held = rig.probe.pending_slots();
    assert!(held.contains(&token));
    assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
    rig.clock_fail.set(true);
    let mut buttons = ButtonChannel::new();
    let release = rig.owner.handle_button_event(buttons.up(MUTE)).unwrap();
    assert_eq!(
        release.action,
        ButtonAction::Ignored(IgnoredButton::Release)
    );
    assert!(release.render.is_none());
    assert_eq!(rig.owner.render_state(), state);
    assert_eq!(rig.probe.calls(), calls);
    assert_eq!(rig.probe.captured_submissions(), pcm);
    assert_eq!(rig.owner.received_frames_pulled(), pulled);
    assert_eq!(rig.probe.pending_slots(), held);
    assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));

    let fault = buttons.fault_and_reset();
    let reset = rig.owner.handle_button_event(fault).unwrap();
    assert_eq!(reset.action, ButtonAction::ChannelReset);
    assert!(reset.render.is_none());
    assert_eq!(rig.owner.render_state(), state);
    assert_eq!(rig.probe.calls(), calls);
    assert_eq!(rig.probe.captured_submissions(), pcm);
    assert_eq!(rig.owner.received_frames_pulled(), pulled);
    assert_eq!(rig.probe.pending_slots(), held);
    assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
    // Explicit cancellation is separate from ignored events and its ACK is
    // obtained from the retained HAL, with group clock still unavailable.
    assert!(rig.owner.request_stop().is_ok());
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert_eq!(rig.probe.pending(), 0);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}
