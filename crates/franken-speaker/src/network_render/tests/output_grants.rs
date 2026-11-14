// Permission controls use the actual receiver, clock, renderer and retained HAL.
use super::*;

fn feed_two_blocks(rig: &mut RunningFixture) {
    for block in 0..2 {
        let wire = packet(&mut rig.sender, block, rig.start_group_ns, 256);
        rig.socket.send_to(&wire, rig.address).unwrap();
        let report = rig.owner.poll().unwrap();
        assert_eq!((report.media_read, report.media_accepted), (1, 1));
    }
}

#[test]
fn exclusive_output_bound_keeps_fraction_and_clock_uncertainty() {
    let mapping = TickMapping {
        anchor_tick: 0,
        anchor_group_ns: CLOCK_ORIGIN,
        ns_numerator: 1_000_000,
        tick_denominator: 3,
        uncertainty_ns: 0,
        presentation_tolerance_ns: 1,
    };
    // One third of a millisecond is exactly 16 frames; a single extra
    // nanosecond crosses that exclusive frame boundary.
    assert_eq!(mapping.output_end_frame(1, 0), Some(4_800_016));
    assert_eq!(mapping.output_end_frame(1, 1), Some(4_800_017));
    assert_eq!(
        TickMapping {
            tick_denominator: 0,
            ..mapping
        }
        .output_end_frame(1, 0),
        None
    );
}

#[test]
fn denied_next_block_does_not_prepare_and_full_permission_renders_pcm() {
    let mut rig = running(512);
    feed_two_blocks(&mut rig);
    rig.now.set(rig.start_local_ns - 10_500_000);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    let mut observed = None;
    assert!(matches!(
        rig.owner
            .step_with_output_permission(&mut timing, |through, latest| {
                observed = Some((through, latest));
                false
            })
            .unwrap(),
        OwnerStep::Waiting
    ));
    let (through, latest) = observed.expect("permission callback must be consulted");
    assert!(through > 0 && latest > 0);
    assert_eq!(rig.owner.queued_frames(), 0);
    assert_eq!(rig.owner.received_frames_pulled(), 0);
    assert!(rig.probe.captured_submissions().is_empty());
    assert!(matches!(
        rig.owner
            .step_with_output_permission(&mut timing, |end, _| end < through)
            .unwrap(),
        OwnerStep::Waiting
    ));
    assert_eq!(rig.owner.queued_frames(), 0);
    assert_eq!(rig.owner.received_frames_pulled(), 0);
    // The first check can pass while the fresh check after N04 prepare
    // refuses. Prepared PCM is retained, but D03 must not pull it.
    let mut checks = 0;
    assert!(matches!(
        rig.owner
            .step_with_output_permission(&mut timing, |_, _| {
                checks += 1;
                checks == 1
            })
            .unwrap(),
        OwnerStep::Waiting
    ));
    assert!(checks >= 2);
    assert_eq!(rig.owner.queued_frames(), 256);
    assert_eq!(rig.owner.received_frames_pulled(), 0);
    assert!(rig.probe.captured_submissions().is_empty());
    let mut complete = false;
    for step in 0..5000_u64 {
        rig.now
            .set(rig.start_local_ns - 10_500_000 + step * 100_000);
        if matches!(
            rig.owner
                .step_with_output_permission(&mut timing, |_, _| true)
                .unwrap(),
            OwnerStep::Complete
        ) {
            complete = true;
            break;
        }
    }
    assert!(complete);
    let (expected, frames) = expected_protected(&signal(0, 512), 0);
    assert_eq!(frames, 512);
    assert_eq!(rig.probe.captured_submissions(), expected);
    assert!(expected.iter().flatten().any(|byte| *byte != 0));
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}

#[test]
fn busy_block_may_finish_but_its_grant_cannot_start_next_block() {
    let mut rig = running(512);
    feed_two_blocks(&mut rig);
    let mut reference = running(512);
    feed_two_blocks(&mut reference);
    let mut timing = ScriptedTiming {
        default_cost: 4,
        ..ScriptedTiming::default()
    };
    let mut reference_timing = timing.clone();
    let mut busy_at = None;
    for step in 0..1000_u64 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        rig.owner
            .step_with_output_permission(&mut timing, |_, _| true)
            .unwrap();
        reference
            .now
            .set(reference.start_local_ns - 15_000_000 + step * 100_000);
        reference
            .owner
            .step_with_output_permission(&mut reference_timing, |_, _| true)
            .unwrap();
        if rig.owner.block_in_progress() {
            busy_at = Some(step);
            break;
        }
    }
    let start = busy_at.expect("a real block must be in progress");
    let pulled = rig.owner.received_frames_pulled();
    let mut finished = false;
    let mut saw_later_bound = false;
    for step in start + 1..1000_u64 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        let mut busy_end = None;
        let outcome = rig
            .owner
            .step_with_output_permission(&mut timing, |end, _| {
                let limit = *busy_end.get_or_insert(end);
                saw_later_bound |= end > limit;
                end <= limit
            })
            .unwrap();
        reference
            .now
            .set(reference.start_local_ns - 15_000_000 + step * 100_000);
        let control = reference
            .owner
            .step_with_output_permission(&mut reference_timing, |_, _| true)
            .unwrap();
        if let OwnerStep::Tick(tick) = outcome
            && tick.finished.is_some()
        {
            assert!(tick.started.is_none(), "the later block lacks permission");
            assert!(
                matches!(control, OwnerStep::Tick(control_tick) if control_tick.finished.is_some() && control_tick.started.is_some()),
                "the same tick starts the next block when permitted"
            );
            finished = true;
            break;
        }
    }
    assert!(saw_later_bound);
    assert!(finished, "the permitted in-flight block must finish");
    assert_eq!(rig.owner.received_frames_pulled(), pulled);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}

#[test]
fn revoking_inflight_permission_preserves_retained_hal_until_flush_ack() {
    let mut rig = running(512);
    feed_two_blocks(&mut rig);
    rig.probe.set_lose_completions(true);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    let mut reached = false;
    for step in 0..1000_u64 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        rig.owner
            .step_with_output_permission(&mut timing, |_, _| true)
            .unwrap();
        if rig.probe.pending() > 0 && rig.owner.block_in_progress() {
            reached = true;
            break;
        }
    }
    assert!(reached);
    let held = rig.probe.pending();
    let captured = rig.probe.captured_submissions();
    assert!(matches!(
        rig.owner
            .step_with_output_permission(&mut timing, |_, _| false),
        Err(NetworkRenderError::OutputPermission)
    ));
    assert_eq!(rig.probe.pending(), held);
    assert_eq!(rig.probe.captured_submissions(), captured);
    for _ in 0..2 {
        rig.owner.drain_tick(&mut timing).unwrap();
        assert_eq!(rig.probe.pending(), held);
    }
    for _ in 0..8 {
        if rig.owner.render_state() != RenderState::Draining {
            break;
        }
        rig.owner.drain_tick(&mut timing).unwrap();
    }
    assert_eq!(rig.probe.pending(), 0);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}

fn running_with_retained_completed_block() -> (RunningFixture, ScriptedTiming, u64) {
    let mut rig = running(512);
    feed_two_blocks(&mut rig);
    rig.probe.set_lose_completions(true);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    for step in 0..1000_u64 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        let outcome = rig
            .owner
            .step_with_output_permission(&mut timing, |_, _| true)
            .unwrap();
        if matches!(outcome, OwnerStep::Tick(tick) if tick.finished.is_some()) {
            assert!(!rig.owner.block_in_progress());
            assert_eq!(rig.probe.pending(), 1);
            return (rig, timing, step);
        }
    }
    panic!("must submit one retained block before testing the grant wait");
}

#[test]
fn running_without_next_grant_services_retained_completions_and_faults() {
    use franken_hal::backend::{DriverError, Op};

    let (mut rig, mut timing, start) = running_with_retained_completed_block();
    let pulled = rig.owner.received_frames_pulled();
    let captured = rig.probe.captured_submissions();
    rig.probe.set_lose_completions(false);
    let mut serviced_at = None;
    for step in start + 1..start + 30 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        let outcome = rig
            .owner
            .step_with_output_permission(&mut timing, |_, _| false)
            .unwrap();
        if let OwnerStep::Tick(tick) = outcome {
            assert!(tick.started.is_none());
        }
        if rig.probe.pending() == 0 {
            serviced_at = Some(step);
            break;
        }
    }
    let serviced_at = serviced_at.expect("the real completion must be polled while grant-starved");
    assert_eq!(rig.owner.received_frames_pulled(), pulled);
    assert_eq!(rig.probe.captured_submissions(), captured);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    let mut resumed = false;
    for step in serviced_at + 1..serviced_at + 30 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        let outcome = rig
            .owner
            .step_with_output_permission(&mut timing, |_, _| true)
            .unwrap();
        if matches!(outcome, OwnerStep::Tick(tick) if tick.started.is_some()) {
            resumed = true;
            break;
        }
    }
    assert!(resumed, "a timely extension permits the next real block");

    let (mut faulty, mut timing, start) = running_with_retained_completed_block();
    let held = faulty.probe.pending();
    let captured = faulty.probe.captured_submissions();
    faulty.probe.fail_next(Op::PollEvent, DriverError::Errno(5));
    let mut observed_fault = false;
    for step in start + 1..start + 30 {
        faulty
            .now
            .set(faulty.start_local_ns - 15_000_000 + step * 100_000);
        match faulty
            .owner
            .step_with_output_permission(&mut timing, |_, _| false)
        {
            Err(NetworkRenderError::Preparation) => {
                observed_fault = true;
                break;
            }
            Ok(OwnerStep::Waiting | OwnerStep::Tick(_)) => {}
            other => panic!("unexpected grant-wait outcome: {other:?}"),
        }
    }
    assert!(observed_fault, "the retained HAL poll failure must surface");
    assert_eq!(
        faulty.probe.pending(),
        held,
        "a fault is not a completion or flush ACK"
    );
    assert_eq!(faulty.probe.captured_submissions(), captured);
    assert_eq!(faulty.probe.use_after_free(), 0);
    assert_eq!(faulty.probe.modified_while_owned(), 0);
}

#[test]
fn granting_after_original_deadline_cannot_rebase_the_next_block() {
    let (mut rig, mut timing, _) = running_with_retained_completed_block();
    let pulled = rig.owner.received_frames_pulled();
    let captured = rig.probe.captured_submissions();
    let deadline = rig
        .owner
        .mapping
        .at(rig.owner.render.next_slot().unwrap().deadline_tick)
        .unwrap();
    let late_local = rig
        .owner
        .clock
        .local_for_group(deadline + 1_000_000, rig.now.get())
        .unwrap();
    rig.now.set(late_local);
    assert!(matches!(
        rig.owner
            .step_with_output_permission(&mut timing, |_, _| true),
        Err(NetworkRenderError::Timeline)
    ));
    assert_eq!(rig.owner.received_frames_pulled(), pulled);
    assert_eq!(rig.probe.captured_submissions(), captured);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}
