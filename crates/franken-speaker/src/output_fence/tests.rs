//! Tests for the HAL output fence. Every test drives a real `RenderLoop` over a real `HalSession` on the fake
//! device and a real `LookaheadQueue`; the only scripted inputs are the fake's position reports and its
//! (non-)acknowledgment of a flush. Each refusal is paired with the permitted counterpart.

use super::*;
use crate::render::{FaultReason, RenderConfig, RenderSource, ScriptedTiming, Starvation};
use franken_dsp::protection::{Admission, ProtectedBoardDsp, synthetic_calibration_for};
use franken_dsp::resample::{DriftResampler, FrameSource, ResamplerConfig};
use franken_hal::abi::{DeviceEvent, RawGeometry};
use franken_hal::backend::{FakeBackend, FakeConfig, FakeProbe};
use franken_hal::session::{SessionConfig, StartPreconditions};
use franken_hal::slots::LeakLedger;
use franken_session::{
    Chunk, FenceKind, FenceToken, Handoff, LookaheadLimits, TrackSerial, TransitionAck,
};
use std::sync::Arc;

const BLOCK: usize = 64;
const READY: StartPreconditions = StartPreconditions {
    presentation_mapping_installed: true,
    safe_gain_installed: true,
};

fn profile() -> franken_board_profile::BoardProfile {
    franken_board_profile::synthetic_test_fixture_catalog()
        .into_iter()
        .find(|p| p.model_number == "S1")
        .unwrap()
}

/// Four 64-frame slots, two channels, a completion two ticks after a submit, a minimum lead of one tick, a
/// stop deadline of eight, an exact position and a flush acknowledged one tick after it is asked.
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

fn dsp() -> ProtectedBoardDsp {
    let profile = profile();
    let calibration = synthetic_calibration_for(&profile);
    ProtectedBoardDsp::admit(&profile, Some(&calibration), Admission::HostSimulation)
}

/// A steady tone, so the source never runs dry.
struct Tone {
    pos: u64,
}

impl FrameSource for Tone {
    fn pull(&mut self) -> Option<[f32; 2]> {
        let phase = (self.pos % 48) as f32 / 48.0;
        self.pos += 1;
        let v = 0.25 * (2.0 * std::f32::consts::PI * phase).sin();
        Some([v, 0.5 * v])
    }
}

impl RenderSource for Tone {
    fn starvation(&self) -> Option<Starvation> {
        None
    }
}

/// A started render loop over a fake device, its probe, its source and its timing.
struct Rig {
    l: RenderLoop<FakeBackend>,
    probe: FakeProbe,
    src: Tone,
    t: ScriptedTiming,
}

impl Rig {
    fn new(cfg: FakeConfig) -> Self {
        let (backend, probe) = FakeBackend::new(cfg);
        let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2);
        let mut session = HalSession::open(profile(), backend, config).unwrap();
        session.prepare().unwrap();
        let resampler = DriftResampler::new(ResamplerConfig::default()).unwrap();
        let mut l =
            RenderLoop::new(session, dsp(), resampler, RenderConfig::standard(BLOCK)).unwrap();
        l.start(READY).unwrap();
        Self {
            l,
            probe,
            src: Tone { pos: 0 },
            t: ScriptedTiming {
                default_cost: 1,
                ..ScriptedTiming::default()
            },
        }
    }

    fn run(&mut self, ticks: u64) {
        for _ in 0..ticks {
            self.l.tick(&mut self.src, &mut self.t);
        }
    }

    /// Tick until the loop leaves `Draining`, to a bound.
    fn settle(&mut self) {
        for _ in 0..300 {
            if self.l.state() != RenderState::Draining {
                break;
            }
            self.l.tick(&mut self.src, &mut self.t);
        }
    }

    /// The device reports its consumed counter, and one tick handles it. The first report after the session
    /// opened is only a baseline.
    fn credit(&mut self, counter: u32) {
        self.probe.queue_event(DeviceEvent::Position { counter });
        self.run(1);
    }
}

fn limits() -> LookaheadLimits {
    LookaheadLimits {
        max_bytes: 4096,
        max_media_ms: 60_000,
        max_chunks: 16,
        max_chunk_bytes: 1024,
        max_outstanding: 4,
        ready_min_media_ms: 0,
    }
}

fn queue(epoch: u64) -> LookaheadQueue {
    LookaheadQueue::new(limits(), SourceEpoch::new(epoch), TrackSerial::new(1), 0).unwrap()
}

/// One second of 44.1 kHz audio, so the decoded rate differs from the output domain's.
fn chunk(epoch: u64, start_frame: u64) -> Chunk {
    Chunk {
        epoch: SourceEpoch::new(epoch),
        track: TrackSerial::new(1),
        start_frame,
        frames: 44_100,
        rate_hz: 44_100,
        last_of_track: false,
        payload: vec![0; 16],
    }
}

fn hand_out(q: &mut LookaheadQueue, epoch: u64, start_frame: u64) -> Handoff {
    q.push(chunk(epoch, start_frame)).unwrap();
    q.pop().unwrap().unwrap()
}

fn seek(q: &mut LookaheadQueue, epoch: u64) {
    let start = q
        .begin_transition(SourceEpoch::new(epoch), TrackSerial::new(1), 0)
        .unwrap();
    assert!(
        start.fence.is_some(),
        "output was handed out, so a fence is needed"
    );
}

fn ack(
    q: &mut LookaheadQueue,
    b: &OutputBoundary,
    l: &RenderLoop<FakeBackend>,
) -> Result<TransitionAck, LookaheadError> {
    q.ack_transition(&mut b.fence_over(l))
}

fn ask(b: &OutputBoundary, l: &RenderLoop<FakeBackend>, epoch: u64) -> OutputFence {
    b.fence_over(l).fence(FenceRequest {
        token: FenceToken::new(9),
        epoch: SourceEpoch::new(epoch),
    })
}

/// One 64-frame block accepted by the device, retired as submitted, a seek begun, the device credited with
/// all 64 frames, and the fence asked.
fn seek_after_full_credit(cfg: FakeConfig) -> Result<TransitionAck, LookaheadError> {
    let mut rig = Rig::new(cfg);
    rig.run(2);
    let mut q = queue(1);
    let h = hand_out(&mut q, 1, 0);
    let mut b = OutputBoundary::new();
    b.retire_submitted(&mut q, &rig.l, &h.ticket, 0).unwrap();
    seek(&mut q, 2);
    rig.credit(1000);
    rig.credit(1064);
    ack(&mut q, &b, &rig.l)
}

// -------------------------------------------------------------------------------- the output domain

#[test]
fn the_end_of_a_handoffs_audio_is_the_devices_tail_in_the_canonical_domain_not_the_chunks_frames() {
    let mut rig = Rig::new(fake_config());
    rig.run(2);
    let mut q = queue(1);
    let h = hand_out(&mut q, 1, 0);
    assert_eq!((h.chunk.rate_hz, h.chunk.frames), (44_100, 44_100));
    let mut b = OutputBoundary::new();
    let end = b.retire_submitted(&mut q, &rig.l, &h.ticket, 0).unwrap();
    let session = rig.l.session();
    assert_eq!(
        end.domain,
        OutputDomain {
            session: session.session_id(),
            generation: 0,
            rate_hz: CANONICAL_SAMPLE_RATE_HZ,
        }
    );
    assert_eq!(end.domain.rate_hz, 48_000);
    // The position is what the device accepted: one 64-frame block, not the chunk's 44,100 source frames.
    assert_eq!(end.frame, session.irrevocable_until_frames());
    assert_eq!(end.frame, 64);
    assert_ne!(end.frame, u64::from(h.chunk.frames));
    assert_eq!(b.output_epoch(), Some(SourceEpoch::new(1)));
    assert_eq!(b.submitted_end(), Some(end));
    assert_eq!(q.outstanding_count(), 0);
    // Counts in the chunk's own 44.1 kHz domain are a different domain: the queue refuses to mix them.
    let second = hand_out(&mut q, 1, 44_100);
    let mislabelled = OutputPosition {
        domain: OutputDomain {
            rate_hz: 44_100,
            ..end.domain
        },
        frame: end.frame,
    };
    assert_eq!(
        q.retire(&second.ticket, Retirement::Submitted { end: mislabelled }),
        Err(LookaheadError::OutputDomainChanged)
    );
    // The permitted counterpart: the boundary labels it in the epoch's own domain.
    assert!(
        b.retire_submitted(&mut q, &rig.l, &second.ticket, 0)
            .is_ok()
    );
}

#[test]
fn two_sessions_are_two_domains_and_a_fence_over_the_wrong_loop_is_refused() {
    let mut a = Rig::new(fake_config());
    a.run(2);
    let other = Rig::new(fake_config());
    assert_ne!(
        a.l.session().session_id(),
        other.l.session().session_id(),
        "two sessions never share an id"
    );
    let mut q = queue(1);
    let h = hand_out(&mut q, 1, 0);
    let mut b = OutputBoundary::new();
    b.retire_submitted(&mut q, &a.l, &h.ticket, 0).unwrap();
    seek(&mut q, 2);
    // The submissions were made in A's session; B's numbers cannot answer for them.
    assert_eq!(
        ack(&mut q, &b, &other.l),
        Err(LookaheadError::FenceDomainMismatch)
    );
    // A flush of ANOTHER session proves nothing about A's audio, even when that session's generation is past
    // the one A's audio was submitted in.
    let mut flushed = Rig::new(fake_config());
    flushed.run(2);
    flushed.l.cancel().unwrap();
    flushed.settle();
    assert_eq!(flushed.l.state(), RenderState::Stopped);
    assert_eq!(flushed.l.session().generation(), 1);
    assert_eq!(
        ack(&mut q, &b, &flushed.l),
        Err(LookaheadError::FenceDomainMismatch)
    );
    // The permitted counterpart: A's own loop, flushed, answers.
    a.l.cancel().unwrap();
    a.settle();
    assert_eq!(
        ack(&mut q, &b, &a.l).map(|done| done.via),
        Ok(FenceKind::Flushed)
    );
}

// -------------------------------------------------------------------------------- drained

#[test]
fn a_seek_over_audio_the_device_has_played_is_acknowledged_by_a_positive_drain_and_not_before() {
    let mut rig = Rig::new(fake_config());
    rig.run(2);
    let mut q = queue(1);
    let h = hand_out(&mut q, 1, 0);
    let mut b = OutputBoundary::new();
    let end = b.retire_submitted(&mut q, &rig.l, &h.ticket, 0).unwrap();
    seek(&mut q, 2);
    // Nothing played yet: the true numbers, refused with nothing changed.
    assert_eq!(
        ack(&mut q, &b, &rig.l),
        Err(LookaheadError::OutputNotDrained {
            tail_frame: 64,
            played_frame: 0
        })
    );
    rig.credit(1000); // the first report is only a baseline
    rig.credit(1032);
    assert_eq!(
        ack(&mut q, &b, &rig.l),
        Err(LookaheadError::OutputNotDrained {
            tail_frame: 64,
            played_frame: 32
        })
    );
    rig.credit(1064);
    let done = ack(&mut q, &b, &rig.l).unwrap();
    assert_eq!(done.via, FenceKind::Drained);
    assert_eq!(done.epoch, SourceEpoch::new(2));
    // The evidence was the device's own: tail and played in the domain the audio was submitted in.
    let fence = ask(&b, &rig.l, 1);
    assert_eq!(fence.token, FenceToken::new(9));
    assert_eq!(fence.epoch, SourceEpoch::new(1));
    assert_eq!(
        fence.outcome,
        FenceOutcome::Drained {
            tail: end,
            played: OutputPosition {
                domain: end.domain,
                frame: 64
            }
        }
    );
}

#[test]
fn a_position_that_is_only_bounded_or_unknown_cannot_certify_a_drain() {
    // Exact: all 64 frames reported consumed is a drain (the positive control).
    assert_eq!(
        seek_after_full_credit(fake_config()).map(|a| a.via),
        Ok(FenceKind::Drained)
    );
    // Bounded by 8 frames: the device reports 64, so only 56 are certain.
    let mut bounded = fake_config();
    bounded.position_error_frames = Some(8);
    assert_eq!(
        seek_after_full_credit(bounded),
        Err(LookaheadError::OutputNotDrained {
            tail_frame: 64,
            played_frame: 56
        })
    );
    // Unknown precision certifies nothing.
    let mut unknown = fake_config();
    unknown.position_error_frames = None;
    assert_eq!(
        seek_after_full_credit(unknown),
        Err(LookaheadError::OutputNotDrained {
            tail_frame: 64,
            played_frame: 0
        })
    );
}

// -------------------------------------------------------------------------------- flushed

#[test]
fn a_flushed_seek_is_acknowledged_only_after_the_device_acknowledged_the_flush() {
    let mut rig = Rig::new(fake_config());
    rig.run(2);
    let mut q = queue(1);
    let h = hand_out(&mut q, 1, 0);
    let mut b = OutputBoundary::new();
    let end = b.retire_submitted(&mut q, &rig.l, &h.ticket, 0).unwrap();
    seek(&mut q, 2);
    rig.l.cancel().unwrap();
    // Asked now, the stop is not finished: the true numbers say 0 of 64 frames were played.
    assert_eq!(rig.l.state(), RenderState::Draining);
    assert_eq!(rig.l.session().generation(), 0);
    assert_eq!(
        ack(&mut q, &b, &rig.l),
        Err(LookaheadError::OutputNotDrained {
            tail_frame: 64,
            played_frame: 0
        })
    );
    rig.settle();
    assert_eq!(rig.l.state(), RenderState::Stopped);
    assert!(rig.l.stop_report().acknowledged);
    assert_eq!(rig.l.session().generation(), 1);
    // The flushed frames were discarded, not played, and the report is about the old generation.
    assert_eq!(rig.l.session().receipt().discarded_frames, 64);
    let fence = ask(&b, &rig.l, 1);
    assert_eq!(
        fence.outcome,
        FenceOutcome::FlushAcknowledged {
            domain: end.domain,
            waited_ticks: rig.l.stop_report().ticks
        }
    );
    let done = ack(&mut q, &b, &rig.l).unwrap();
    assert_eq!(done.via, FenceKind::Flushed);
    assert_eq!(done.epoch, SourceEpoch::new(2));
}

#[test]
fn a_flush_the_device_acknowledged_still_answers_for_the_old_audio_after_the_loop_runs_again() {
    let mut rig = Rig::new(fake_config());
    rig.run(2);
    let mut q = queue(1);
    let h = hand_out(&mut q, 1, 0);
    let mut b = OutputBoundary::new();
    let end = b.retire_submitted(&mut q, &rig.l, &h.ticket, 0).unwrap();
    seek(&mut q, 2);
    rig.l.cancel().unwrap();
    rig.settle();
    // The loop starts again before the queue is asked. It is Running in the next generation, but the flush
    // the device acknowledged is still a fact about the old audio, and the report names the OLD domain.
    rig.l.start(READY).unwrap();
    assert_eq!(rig.l.state(), RenderState::Running);
    assert_eq!(rig.l.session().generation(), 1);
    assert_eq!(
        ask(&b, &rig.l, 1).outcome,
        FenceOutcome::FlushAcknowledged {
            domain: end.domain,
            waited_ticks: 0
        }
    );
    let done = ack(&mut q, &b, &rig.l).unwrap();
    assert_eq!(done.via, FenceKind::Flushed);
    // The permitted counterpart of the old-domain report: audio submitted in the NEW generation is a new
    // domain, and the queue would refuse to mix it into the old epoch's submissions.
    let next = hand_out(&mut q, 2, 0);
    rig.run(8); // two more blocks are accepted; the loop ends the eighth tick between blocks
    let end_two = b.retire_submitted(&mut q, &rig.l, &next.ticket, 0).unwrap();
    assert_eq!(end_two.domain.generation, 1);
    assert_eq!(end_two.domain.session, end.domain.session);
    assert_eq!(b.output_epoch(), Some(SourceEpoch::new(2)));
}

// -------------------------------------------------------------------------------- first failure

#[test]
fn an_unacknowledged_stop_fails_the_transition_for_good_until_a_reset_and_a_new_one() {
    let mut cfg = fake_config();
    cfg.flush_ack_delay_ticks = None;
    let mut rig = Rig::new(cfg);
    rig.probe.set_lose_completions(true);
    rig.run(2);
    let mut q = queue(1);
    let h = hand_out(&mut q, 1, 0);
    let mut b = OutputBoundary::new();
    b.retire_submitted(&mut q, &rig.l, &h.ticket, 0).unwrap();
    seek(&mut q, 2);
    rig.l.cancel().unwrap();
    rig.settle();
    assert_eq!(rig.l.state(), RenderState::Faulted);
    assert_eq!(rig.l.fault(), Some(FaultReason::DrainTimedOut));
    assert_eq!(rig.l.session().generation(), 0, "nothing was acknowledged");
    // The first failure: reported as a flush that timed out, and the transition is failed for good.
    assert_eq!(ack(&mut q, &b, &rig.l), Err(LookaheadError::FlushTimedOut));
    assert_eq!(
        ack(&mut q, &b, &rig.l),
        Err(LookaheadError::TransitionFailed)
    );
    // An acknowledged reset frees the held buffers, but it does not rescue the failed transition.
    rig.l.recover().unwrap();
    assert_eq!(rig.l.state(), RenderState::Ready);
    assert_eq!(rig.l.session().generation(), 1);
    assert_eq!(
        ack(&mut q, &b, &rig.l),
        Err(LookaheadError::TransitionFailed)
    );
    // A new transition supersedes it and is fenced against the SAME original output; the reset the device
    // acknowledged is the evidence that the old audio is gone.
    let again = q
        .begin_transition(SourceEpoch::new(3), TrackSerial::new(3), 0)
        .unwrap();
    assert!(again.superseded);
    assert_eq!(again.fence.map(|f| f.epoch), Some(SourceEpoch::new(1)));
    let done = ack(&mut q, &b, &rig.l).unwrap();
    assert_eq!(
        (done.via, done.epoch),
        (FenceKind::Flushed, SourceEpoch::new(3))
    );
}

// -------------------------------------------------------------------------------- decoder work

#[test]
fn cancelled_and_joined_decoder_work_leaves_nothing_to_drain_and_cannot_submit_afterwards() {
    let mut rig = Rig::new(fake_config());
    rig.run(2);
    let mut q = queue(1);
    let h = hand_out(&mut q, 1, 0);
    let mut b = OutputBoundary::new();
    b.retire_cancelled(&mut q, &h.ticket).unwrap();
    assert_eq!(b.output_epoch(), Some(SourceEpoch::new(1)));
    assert_eq!(b.submitted_end(), None);
    assert!(!q.may_submit(&h.ticket));
    // A decoder that ignored the cancellation and submits anyway is refused, and nothing is recorded.
    assert_eq!(
        b.retire_submitted(&mut q, &rig.l, &h.ticket, 0),
        Err(OutputFenceError::Queue(LookaheadError::UnknownHandoff {
            seq: h.ticket.seq()
        }))
    );
    assert_eq!(b.submitted_end(), None);
    // The epoch put nothing into the output, so the seek needs no drain, even with the loop running.
    seek(&mut q, 2);
    let done = ack(&mut q, &b, &rig.l).unwrap();
    assert_eq!(
        (done.via, done.epoch),
        (FenceKind::Drained, SourceEpoch::new(2))
    );
}

#[test]
fn a_submission_that_retires_after_the_seek_began_is_covered_by_the_fence() {
    let mut rig = Rig::new(fake_config());
    rig.run(2); // block 0: 64 frames accepted
    let mut q = queue(1);
    let first = hand_out(&mut q, 1, 0);
    let second = hand_out(&mut q, 1, 44_100);
    let mut b = OutputBoundary::new();
    let early = b
        .retire_submitted(&mut q, &rig.l, &first.ticket, 0)
        .unwrap();
    assert_eq!(early.frame, 64);
    seek(&mut q, 2);
    // The second decode is still running, so the renderer is not even asked.
    assert_eq!(
        ack(&mut q, &b, &rig.l),
        Err(LookaheadError::OutstandingDecoderWork { outstanding: 1 })
    );
    rig.run(4); // block 1: 128 frames accepted
    let late = b
        .retire_submitted(&mut q, &rig.l, &second.ticket, 0)
        .unwrap();
    assert_eq!(late.frame, 128);
    assert_eq!(b.submitted_end(), Some(late));
    rig.credit(1000);
    rig.credit(1064);
    // 64 of 128 frames played is not a drain: the fence follows the late audio.
    assert_eq!(
        ack(&mut q, &b, &rig.l),
        Err(LookaheadError::OutputNotDrained {
            tail_frame: 128,
            played_frame: 64
        })
    );
    rig.credit(1128);
    assert_eq!(
        ack(&mut q, &b, &rig.l).map(|a| a.via),
        Ok(FenceKind::Drained)
    );
}

// -------------------------------------------------------------------------------- refusals

#[test]
fn a_submission_is_refused_while_a_block_is_in_progress_or_decoded_frames_are_undelivered() {
    let mut rig = Rig::new(fake_config());
    let mut q = queue(1);
    let h = hand_out(&mut q, 1, 0);
    let mut b = OutputBoundary::new();
    rig.run(1); // block 0 has started and is not yet submitted
    assert_eq!(
        b.retire_submitted(&mut q, &rig.l, &h.ticket, 0),
        Err(OutputFenceError::BlockInProgress)
    );
    rig.run(1); // block 0 is submitted
    // The caller still holds 5 decoded frames the renderer has not pulled.
    assert_eq!(
        b.retire_submitted(&mut q, &rig.l, &h.ticket, 5),
        Err(OutputFenceError::SourceNotDrained { frames: 5 })
    );
    assert_eq!((q.outstanding_count(), b.output_epoch()), (1, None));
    // The permitted counterpart: between blocks, nothing undelivered.
    assert_eq!(
        b.retire_submitted(&mut q, &rig.l, &h.ticket, 0)
            .map(|e| e.frame),
        Ok(64)
    );
}

#[test]
fn a_cancel_that_drops_a_block_mid_flight_does_not_block_later_submissions() {
    let mut rig = Rig::new(fake_config());
    let mut q = queue(1);
    let h = hand_out(&mut q, 1, 0);
    let mut b = OutputBoundary::new();
    rig.run(1); // block 0 has started
    assert!(rig.l.block_in_progress());
    rig.l.cancel().unwrap(); // the block is dropped with no outcome
    assert!(!rig.l.block_in_progress());
    rig.settle();
    assert_eq!(rig.l.state(), RenderState::Stopped);
    rig.l.start(READY).unwrap();
    rig.run(1); // a block of the new run has started: genuinely busy
    assert!(rig.l.block_in_progress());
    assert_eq!(
        b.retire_submitted(&mut q, &rig.l, &h.ticket, 0),
        Err(OutputFenceError::BlockInProgress)
    );
    rig.run(7); // two blocks have been accepted and the loop is between blocks
    assert!(!rig.l.block_in_progress());
    // The cumulative counters never balance again after the dropped block; the loop's own state does.
    assert_ne!(
        rig.l.counters().blocks_started,
        rig.l.counters().blocks_on_time
    );
    let end = b.retire_submitted(&mut q, &rig.l, &h.ticket, 0).unwrap();
    assert_eq!((end.domain.generation, end.frame), (1, 128));
}

#[test]
fn a_session_fault_that_drops_a_block_mid_flight_does_not_block_later_submissions() {
    let mut rig = Rig::new(fake_config());
    let mut q = queue(1);
    let h = hand_out(&mut q, 1, 0);
    let mut b = OutputBoundary::new();
    rig.run(1); // block 0 has started
    assert!(rig.l.block_in_progress());
    // A completion for a slot the device never held: the session faults and the loop drops the block.
    rig.probe.queue_event(DeviceEvent::Completed {
        slot: 3,
        generation: 99,
    });
    rig.run(1);
    assert_eq!(rig.l.state(), RenderState::Faulted);
    assert_eq!(rig.l.fault(), Some(FaultReason::SessionFaulted));
    assert!(!rig.l.block_in_progress());
    rig.l.recover().unwrap();
    rig.l.start(READY).unwrap();
    rig.run(1); // a block of the new run has started: genuinely busy
    assert_eq!(
        b.retire_submitted(&mut q, &rig.l, &h.ticket, 0),
        Err(OutputFenceError::BlockInProgress)
    );
    rig.run(7); // two blocks have been accepted and the loop is between blocks
    let end = b.retire_submitted(&mut q, &rig.l, &h.ticket, 0).unwrap();
    assert_eq!((end.domain.generation, end.frame), (1, 128));
}

#[test]
fn a_submission_is_refused_when_the_session_is_not_taking_audio_but_a_cancel_is_not() {
    let mut rig = Rig::new(fake_config());
    rig.run(2);
    let mut q = queue(1);
    let h = hand_out(&mut q, 1, 0);
    let mut b = OutputBoundary::new();
    rig.l.cancel().unwrap();
    rig.settle();
    assert_eq!(rig.l.state(), RenderState::Stopped);
    assert_eq!(
        b.retire_submitted(&mut q, &rig.l, &h.ticket, 0),
        Err(OutputFenceError::SessionNotAccepting {
            phase: SessionPhase::Prepared
        })
    );
    assert_eq!(q.outstanding_count(), 1);
    assert_eq!(b.retire_cancelled(&mut q, &h.ticket), Ok(()));
    assert_eq!(q.outstanding_count(), 0);
}

#[test]
fn a_ticket_another_queue_issued_or_an_older_epoch_owns_retires_nothing() {
    let mut rig = Rig::new(fake_config());
    rig.run(2);
    let mut mine = queue(1);
    let mut theirs = queue(1);
    let foreign = hand_out(&mut theirs, 1, 0);
    let mut b = OutputBoundary::new();
    assert_eq!(
        b.retire_submitted(&mut mine, &rig.l, &foreign.ticket, 0),
        Err(OutputFenceError::Queue(LookaheadError::ForeignHandoff {
            seq: foreign.ticket.seq()
        }))
    );
    assert_eq!((b.output_epoch(), theirs.outstanding_count()), (None, 1));
    // The permitted counterpart: the queue that issued it.
    assert!(
        b.retire_submitted(&mut theirs, &rig.l, &foreign.ticket, 0)
            .is_ok()
    );
    // An older epoch's ticket is refused before the queue sees it, once a newer epoch is recorded.
    let mut old = queue(1);
    let old_ticket = hand_out(&mut old, 1, 0).ticket;
    let mut new = queue(2);
    let new_ticket = hand_out(&mut new, 2, 0).ticket;
    assert_eq!(b.retire_cancelled(&mut new, &new_ticket), Ok(()));
    assert_eq!(
        b.retire_cancelled(&mut old, &old_ticket),
        Err(OutputFenceError::StaleEpoch {
            ticket: 1,
            recorded: 2
        })
    );
    assert_eq!(old.outstanding_count(), 1);
}

#[test]
fn a_boundary_that_never_saw_the_retirements_has_no_evidence_and_fails_closed() {
    let rig = Rig::new(fake_config());
    let mut q = queue(1);
    let h = hand_out(&mut q, 1, 0);
    // Retired straight through the queue, with a position the boundary never recorded.
    let forged = OutputPosition {
        domain: OutputDomain {
            session: rig.l.session().session_id(),
            generation: 0,
            rate_hz: CANONICAL_SAMPLE_RATE_HZ,
        },
        frame: 0,
    };
    q.retire(&h.ticket, Retirement::Submitted { end: forged })
        .unwrap();
    seek(&mut q, 2);
    let b = OutputBoundary::new();
    assert_eq!(b.output_epoch(), None);
    assert_eq!(ack(&mut q, &b, &rig.l), Err(LookaheadError::FlushTimedOut));
}

#[test]
fn the_fence_names_the_epoch_it_speaks_for_not_the_one_it_was_asked_about() {
    let mut rig = Rig::new(fake_config());
    rig.run(2);
    let mut q = queue(1);
    let h = hand_out(&mut q, 1, 0);
    let mut b = OutputBoundary::new();
    b.retire_submitted(&mut q, &rig.l, &h.ticket, 0).unwrap();
    let fence = ask(&b, &rig.l, 7);
    assert_eq!(fence.epoch, SourceEpoch::new(1));
    assert_ne!(fence.epoch, SourceEpoch::new(7));
    assert_eq!(fence.token, FenceToken::new(9));
}
