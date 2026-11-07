//! The S03 output fence over the real HAL session (`ffw-mxt`, `docs/contracts/s03.md`).
//!
//! `franken-session`'s [`LookaheadQueue`] fences a seek or skip with evidence it asks an
//! [`OutputFenceSource`] for. This module is that source at the integration boundary: the one place that
//! sees both the queue (`franken-session`) and the renderer that owns the device (`render::RenderLoop` over a
//! `franken_hal::HalSession`). It reads numbers the device session already keeps and invents none.
//!
//! # What each number is
//!
//! * **Session.** [`HalSession::session_id`]: unique in the process, never reused.
//! * **Generation.** [`HalSession::generation`]: how many flushes and resets the device has acknowledged. The
//!   frame counters keep counting across an acknowledgment (the flushed frames are counted as discarded), so
//!   the generation is what separates the audio before a flush from the audio after it.
//! * **Rate.** [`CANONICAL_SAMPLE_RATE_HZ`], the one rate the render path produces: D02 refuses a calibration
//!   at another rate and D03 resamples to it. The HAL ABI carries no device rate, so this is a statement about
//!   the render path, not a measurement of the device. A decoded chunk may be at 44.1 kHz; the output domain is
//!   at the canonical rate, and a chunk's frame count never becomes an output position.
//! * **Tail.** [`HalSession::irrevocable_until_frames`]: frames the device accepted. The end of a handoff's
//!   audio is this number, read after the renderer has submitted that audio, never arithmetic on chunk frames.
//! * **Played.** The consumed-frame count, as a LOWER bound: the reported count minus the stated position
//!   error, and zero when the position class is unknown or the driver's counter went backwards.
//! * **Flush.** The session's generation has advanced past the generation the audio was submitted in: the
//!   device acknowledged a flush or a reset after that audio, which is a fact about the old audio whatever the
//!   loop has done since. A stop that the device never acknowledged is a fault
//!   (`FaultReason::DrainTimedOut`) and is reported as a flush that timed out. Nothing here waits, drains or
//!   acknowledges anything itself.
//!
//! # What is attested, and by whom
//!
//! The boundary records only what the caller tells the queue through it ([`OutputBoundary::retire_submitted`],
//! [`OutputBoundary::retire_cancelled`]), and only when the queue accepted the retirement. A `Cancelled`
//! retirement is the decoder owner's attestation that nothing of that handoff is or will be in the output; a
//! device session cannot see inside a decoder. A `Submitted` retirement is refused while a render block is in
//! progress, while the session is not accepting audio, and while the caller reports decoded frames the
//! renderer has not yet pulled, because each of those would put the end of the audio short of its true end.
//!
//! The boundary is NOT a renderer and NOT a drain: the owner of the loop calls `stop()` or `cancel()` and
//! ticks until the loop leaves `Draining`, then asks the queue to acknowledge. Asked earlier, the fence
//! reports the true, unfinished numbers and the queue refuses them with nothing changed.
//!
//! The device behavior behind these numbers is unqualified: against the fake device this shows the protocol
//! and the accounting, not a board's driver.

use crate::render::{RenderLoop, RenderState};
use franken_dsp::CANONICAL_SAMPLE_RATE_HZ;
use franken_hal::backend::DeviceBackend;
use franken_hal::session::{HalSession, PositionClass, SessionPhase};
use franken_session::{
    FenceOutcome, FenceRequest, HandoffTicket, LookaheadError, LookaheadQueue, OutputDomain,
    OutputFence, OutputFenceSource, OutputPosition, Retirement, SourceEpoch,
};

/// Why a retirement was not passed to the queue. Every variant carries numbers and identifiers only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OutputFenceError {
    /// The queue refused the retirement itself (a foreign, unknown or already retired ticket, or a change of
    /// output domain within one epoch). Nothing was recorded.
    #[error("the queue refused the retirement: {0}")]
    Queue(LookaheadError),
    /// The output session is not in a phase that accepts audio, so a count read from it is not the end of
    /// this handoff's audio.
    #[error("the output session is {phase:?}, so it cannot be taking this handoff's audio")]
    SessionNotAccepting { phase: SessionPhase },
    /// A render block is in progress: audio it carries is not yet in the output, so the tail read now would
    /// end short of it.
    #[error("a render block is in progress, so audio it carries is not yet in the output")]
    BlockInProgress,
    /// The caller still holds decoded frames of this handoff that the renderer has not pulled.
    #[error("{frames} decoded frame(s) of this handoff have not yet been pulled by the renderer")]
    SourceNotDrained { frames: u64 },
    /// The ticket belongs to an epoch older than the one this boundary already records.
    #[error("the ticket's epoch {ticket} is behind the recorded epoch {recorded}")]
    StaleEpoch { ticket: u64, recorded: u64 },
    /// The tail read now is below the end already recorded for this epoch in the same output domain.
    #[error("the output tail went backwards: recorded {recorded}, now {now}")]
    TailWentBackwards { recorded: u64, now: u64 },
}

/// What the boundary knows about the epoch whose output the device holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EpochRecord {
    epoch: SourceEpoch,
    /// Where the epoch's submitted audio ends (the largest end seen). `None` while every handoff of the epoch
    /// retired as cancelled, which says the epoch put nothing into the output.
    end: Option<OutputPosition>,
}

/// The integration boundary between a [`LookaheadQueue`] and the device session behind a `RenderLoop`.
/// One boundary serves one queue; it is long-lived and holds only the latest epoch's record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutputBoundary {
    record: Option<EpochRecord>,
}

impl OutputBoundary {
    #[must_use]
    pub const fn new() -> Self {
        Self { record: None }
    }

    /// The epoch this boundary can speak for: the one whose handoffs it last saw retire.
    #[must_use]
    pub fn output_epoch(&self) -> Option<SourceEpoch> {
        self.record.map(|record| record.epoch)
    }

    /// Where the recorded epoch's submitted audio ends in the output, if any of it was submitted.
    #[must_use]
    pub fn submitted_end(&self) -> Option<OutputPosition> {
        self.record.and_then(|record| record.end)
    }

    /// End a handoff whose decoded audio has been submitted to the output. The end position is read from
    /// the device session now: its identity, its generation, the canonical rate and the frames it has
    /// accepted. Call it after the render tick that finished the block carrying the handoff's last frame.
    /// `undelivered_source_frames` is how many decoded frames of this handoff the caller still holds that the
    /// renderer has not pulled (zero when the decoder is done and the source is empty).
    ///
    /// Refused, with the queue and the boundary unchanged and the ticket still outstanding, if the ticket is
    /// older than the recorded epoch, the output session is not running or draining, frames are undelivered,
    /// a block is in progress (the loop's own `block_in_progress`, true from a block's start to its end; a
    /// cancel, a fault or a recovery that drops a block clears it), or the tail went backwards; and whenever
    /// the queue refuses it.
    pub fn retire_submitted<B: DeviceBackend>(
        &mut self,
        queue: &mut LookaheadQueue,
        render: &RenderLoop<B>,
        ticket: &HandoffTicket,
        undelivered_source_frames: u64,
    ) -> Result<OutputPosition, OutputFenceError> {
        self.check_epoch(ticket)?;
        let session = render.session();
        let phase = session.phase();
        if !matches!(phase, SessionPhase::Running | SessionPhase::Draining) {
            return Err(OutputFenceError::SessionNotAccepting { phase });
        }
        if undelivered_source_frames > 0 {
            return Err(OutputFenceError::SourceNotDrained {
                frames: undelivered_source_frames,
            });
        }
        if render.block_in_progress() {
            return Err(OutputFenceError::BlockInProgress);
        }
        let end = OutputPosition {
            domain: domain_of(session),
            frame: session.irrevocable_until_frames(),
        };
        let earlier = self
            .record
            .filter(|record| record.epoch == ticket.epoch())
            .and_then(|record| record.end);
        if let Some(have) = earlier
            && have.domain == end.domain
            && end.frame < have.frame
        {
            return Err(OutputFenceError::TailWentBackwards {
                recorded: have.frame,
                now: end.frame,
            });
        }
        queue
            .retire(ticket, Retirement::Submitted { end })
            .map_err(OutputFenceError::Queue)?;
        self.note(ticket.epoch(), Some(end));
        Ok(end)
    }

    /// End a handoff whose decode was cancelled and joined: the decoder owner attests that nothing of it is
    /// or will be in the output. Refused, with nothing changed, for a ticket older than the recorded epoch and
    /// whenever the queue refuses it (a ticket that already retired cannot be cancelled, and one that was
    /// cancelled can no longer be retired as submitted).
    pub fn retire_cancelled(
        &mut self,
        queue: &mut LookaheadQueue,
        ticket: &HandoffTicket,
    ) -> Result<(), OutputFenceError> {
        self.check_epoch(ticket)?;
        queue
            .retire(ticket, Retirement::Cancelled)
            .map_err(OutputFenceError::Queue)?;
        self.note(ticket.epoch(), None);
        Ok(())
    }

    /// The fence source for one acknowledgment attempt over `render`, to pass to
    /// `LookaheadQueue::ack_transition`. It measures when the queue asks, never earlier.
    #[must_use]
    pub const fn fence_over<'a, B: DeviceBackend>(
        &'a self,
        render: &'a RenderLoop<B>,
    ) -> HalFence<'a, B> {
        HalFence {
            boundary: self,
            render,
        }
    }

    fn check_epoch(&self, ticket: &HandoffTicket) -> Result<(), OutputFenceError> {
        if let Some(record) = self.record
            && ticket.epoch() < record.epoch
        {
            return Err(OutputFenceError::StaleEpoch {
                ticket: ticket.epoch().get(),
                recorded: record.epoch.get(),
            });
        }
        Ok(())
    }

    fn note(&mut self, epoch: SourceEpoch, end: Option<OutputPosition>) {
        let mut record = match self.record {
            Some(have) if have.epoch == epoch => have,
            _ => EpochRecord { epoch, end: None },
        };
        if let Some(new) = end {
            record.end = Some(match record.end {
                Some(have) if have.domain == new.domain => OutputPosition {
                    domain: new.domain,
                    frame: have.frame.max(new.frame),
                },
                _ => new,
            });
        }
        self.record = Some(record);
    }
}

/// The [`OutputFenceSource`] over a boundary and the render loop that owns the device session.
pub struct HalFence<'a, B: DeviceBackend> {
    boundary: &'a OutputBoundary,
    render: &'a RenderLoop<B>,
}

impl<B: DeviceBackend> OutputFenceSource for HalFence<'_, B> {
    fn fence(&mut self, request: FenceRequest) -> OutputFence {
        let Some(record) = self.boundary.record else {
            // The boundary never saw a handoff of any epoch retire through it, so it has no evidence about the
            // output. It says so the way the unqualified stand-in does: a flush that was never acknowledged.
            return OutputFence {
                token: request.token,
                epoch: request.epoch,
                outcome: FenceOutcome::FlushTimedOut { waited_ticks: 0 },
            };
        };
        OutputFence {
            token: request.token,
            epoch: record.epoch,
            outcome: self.outcome(record),
        }
    }
}

impl<B: DeviceBackend> HalFence<'_, B> {
    /// The evidence, measured now.
    fn outcome(&self, record: EpochRecord) -> FenceOutcome {
        let render = self.render;
        let session = render.session();
        let now = domain_of(session);
        let played = OutputPosition {
            domain: now,
            frame: played_lower_bound(session),
        };
        let Some(end) = record.end else {
            // Every handoff of the epoch retired as cancelled: there is no output of it to drain or flush.
            return FenceOutcome::Drained {
                tail: played,
                played,
            };
        };
        // Ticks from the stop request to now: known only while the loop is stopped, ready again after a reset
        // or faulted. A running loop has no stop in progress, and says 0.
        let waited_ticks = match render.state() {
            RenderState::Stopped | RenderState::Ready | RenderState::Faulted => {
                render.stop_report().ticks
            }
            _ => 0,
        };
        // The device acknowledged a flush or a reset of this session after the audio was submitted: the
        // generation is past the one the audio was submitted in. That is a fact about the old audio whatever
        // the loop has done since, including starting again.
        if end.domain.session == now.session && end.domain.generation < now.generation {
            return FenceOutcome::FlushAcknowledged {
                domain: end.domain,
                waited_ticks,
            };
        }
        if render.state() == RenderState::Faulted || session.phase() == SessionPhase::Faulted {
            // A stop the device did not acknowledge (`FaultReason::DrainTimedOut`), or any other fault: the
            // old output is muted and held, not flushed.
            return FenceOutcome::FlushTimedOut { waited_ticks };
        }
        // Not flushed: the old audio is drained only if it has been played. The tail is the end of the epoch's
        // own audio (later audio of a newer epoch does not count against it), capped by what the device says
        // it accepted, so a boundary used with the wrong loop reports a tail the queue refuses.
        FenceOutcome::Drained {
            tail: OutputPosition {
                domain: end.domain,
                frame: end.frame.min(session.irrevocable_until_frames()),
            },
            played,
        }
    }
}

fn domain_of<B: DeviceBackend>(session: &HalSession<B>) -> OutputDomain {
    OutputDomain {
        session: session.session_id(),
        generation: session.generation(),
        rate_hz: CANONICAL_SAMPLE_RATE_HZ,
    }
}

/// Frames the device has certainly played: the reported count less the stated error. Unknown precision, or a
/// counter that went backwards, certify nothing.
fn played_lower_bound<B: DeviceBackend>(session: &HalSession<B>) -> u64 {
    if session.counter_regressed() {
        return 0;
    }
    let position = session.position();
    match position.class {
        PositionClass::Exact => position.consumed_frames,
        PositionClass::Bounded { max_error_frames } => position
            .consumed_frames
            .saturating_sub(u64::from(max_error_frames)),
        PositionClass::Unknown => 0,
    }
}

#[cfg(test)]
mod tests;
