//! Accepted versus completed (`G02` / `ffw-ld0`, section 2).
//!
//! The bead says: *"Control acknowledgement means accepted or completed according to the protocol's actual
//! semantics. The adapter must not report completed playback merely because it queued a command."*
//!
//! A [`CommandReceipt`](super::CommandReceipt) says a command was **accepted**: it passed the authority checks and
//! changed the member's target. It says nothing about the sound. D02 ramps the applied gain toward that target by a
//! bounded slew, and only rendered samples advance the ramp. [`MemberVolume::progress`] reports whether the command
//! has **completed**, read from the real board and not inferred from the receipt:
//!
//! * the command is the last one applied (a newer one has taken over the target otherwise);
//! * the member's target is still the one the command produced (a local mute, a trim step, a ceiling or a fault
//!   since then moved it);
//! * the board has been **told**: D02's user gain and mute equal the member's. A target that was accepted but
//!   never handed to the board has not begun to ramp, and a board that was told something else will ramp away;
//! * D02's own effective target, which is its user gain only while it is `Active`, unmuted and not mid profile
//!   switch, equals the member's target, so the board is not heading somewhere else;
//! * D02's applied gain has landed on it **exactly**. D02's slew assigns the target itself once it is within one
//!   step, so this is an exact comparison, and one sample early is still `Accepted`.
//!
//! "Completed" is a statement about the gain. A command whose target is silence because of a fault or a local mute
//! completes when the output is silent, and says so in `effective_mute`; it does not claim the requested level is
//! audible. Protection limiting (D02's limiter and thermal scaling) acts after this gain and is reported by
//! D02's block report, not here. The answer describes the state NOW, not history: a command that was `Superseded`
//! by a local change does not become `Completed` again unless the member's target returns to the command's own.
//!
//! This module reads the board and never writes it. It does not know about transports: an adapter (G03, X01) asks
//! this when its protocol has a "done" to report. Group-wide completion is each present member's progress, asked
//! with that member's board; [`GroupVolume`](super::GroupVolume) holds no boards.

use super::{CommandOutcome, MemberVolume, MuteReason, Stamp, VolumeError};
use crate::protection::{BoardStatus, ProtectedBoardDsp};

/// How far a command with one `(epoch, revision)` id has got.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CommandProgress {
    /// The member never accepted a command with this id (or cannot say). The outcome says which; see
    /// [`CommandOutcome`].
    NotAccepted(CommandOutcome),
    /// Accepted, and the output has not reached its target. `handed_to_board` is false until D02 has been given the
    /// member's gain and mute (`apply_to` or `sync`): a queued command is not a completed one.
    Accepted {
        handed_to_board: bool,
        /// D02's applied gain right now.
        applied_gain: f32,
        /// The gain this command is heading for (`0.0` while any mute reason holds).
        target_gain: f32,
    },
    /// The output has reached the command's target and the board is heading nowhere else. `effective_mute` is why
    /// that target is silence, if it is.
    Completed {
        target_gain: f32,
        effective_mute: Option<MuteReason>,
    },
    /// A newer command, or a change of local state (a local mute, a trim step, a ceiling, a fault), has moved the
    /// target away from this command's. This command's target is no longer being pursued.
    Superseded,
}

impl MemberVolume {
    /// How far the command with this id has got on `dsp`. Asking changes nothing, on the member or the board.
    /// The epoch rules are those of [`command_outcome`](Self::command_outcome).
    pub fn progress(
        &self,
        stamp: Stamp,
        dsp: &ProtectedBoardDsp,
    ) -> Result<CommandProgress, VolumeError> {
        let accepted_target = match self.command_outcome(stamp)? {
            CommandOutcome::Applied { receipt, .. } => receipt.target_gain,
            not_accepted => return Ok(CommandProgress::NotAccepted(not_accepted)),
        };
        if stamp.revision != self.last_revision() {
            return Ok(CommandProgress::Superseded);
        }
        let target = self.output_gain();
        if target != accepted_target {
            return Ok(CommandProgress::Superseded);
        }
        let silent = self.effective_mute().is_some();
        let handed_to_board = dsp.user_gain() == self.unmuted_gain() && dsp.is_muted() == silent;
        // What D02 is actually ramping toward, from its own state: it follows the user gain only while Active,
        // unmuted and not switching profile, and heads for silence otherwise.
        let board_target =
            if matches!(dsp.status(), BoardStatus::Active) && !dsp.is_muted() && !dsp.has_pending_switch() {
                dsp.user_gain()
            } else {
                0.0
            };
        let applied_gain = dsp.applied_gain();
        if handed_to_board && board_target == target && applied_gain == target {
            Ok(CommandProgress::Completed {
                target_gain: target,
                effective_mute: self.effective_mute(),
            })
        } else {
            Ok(CommandProgress::Accepted {
                handed_to_board,
                applied_gain,
                target_gain: target,
            })
        }
    }
}
