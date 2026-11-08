//! Group volume, per-room trim, mute and channel roles (`G02` / `ffw-ld0`).
//! Contract: `docs/contracts/g02.md`.
//!
//! This is the control layer above D02's [`ProtectedBoardDsp`]. It decides the *target* gain and mute
//! state; D02 owns the smooth ramp, and its slew always retargets from the current applied gain, so
//! every change is one ramp and a new target never restarts from the old one.
//!
//! * **Bounded before the ramp.** `volume * trim` is clamped to the protection ceiling and to any
//!   fault ceiling here, so the ramp can never be handed a target above them.
//! * **Mute always wins.** Four independent mute reasons (fault, local, join, group) each have one
//!   owner who can clear them; a volume command never unmutes, and a group unmute cannot undo a
//!   local or fault mute. The effective reason is reported by priority.
//! * **Authority.** Commands carry `(epoch, revision)`. A member accepts only the epoch it was told
//!   about (it never adopts an epoch from a command), refuses stale ones with nothing changed, and
//!   treats a replay of the last command as a duplicate that is not applied again.
//! * **Results by command id.** A member remembers the result of its last [`RESULT_RETENTION`] applied
//!   commands, so a client that timed out on revision N can ask what became of it
//!   ([`MemberVolume::command_outcome`], [`GroupVolume::command_outcome`]): applied (with the receipt it
//!   produced then), never applied, or too old to say. Asking changes nothing, and `apply` answers exactly
//!   as before: an older replay is still `stale_revision`.
//! * **Reconnect.** A (re)joining member starts muted and takes the group's *current* snapshot, so a
//!   stored high volume is never audible and the first ramp starts from silence. A rejoin keeps the
//!   room's own local mute, fault mute and fault ceiling, and a snapshot older than what the member
//!   has applied in its own epoch is refused, so a late snapshot cannot put back a replaced volume.
//! * **Roles.** `Stereo`/`Left`/`Right`/`Sub` map onto the admitted channel layout as an input remap;
//!   a role a board lacks is refused by name.
//!
//! Numerical tests do not prove physical behavior; nothing here touches a device.

use crate::StereoAudioBlock;
use crate::protection::{BoardStatus, ProtectedBoardDsp, ProtectionError};
use franken_board_profile::{BoardProfile, TransducerRole};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod local_mute_tests;
#[cfg(test)]
mod outcome_tests;
mod progress;
#[cfg(test)]
mod progress_tests;
#[cfg(test)]
mod rejoin_tests;
#[cfg(test)]
mod tests;

pub use progress::CommandProgress;

/// How many applied commands a member remembers the result of. Older ones are reported as forgotten.
pub const RESULT_RETENTION: usize = 32;
/// Highest group master volume (percent).
pub const MAX_VOLUME: u8 = 100;
/// Per-room trim in thousandths: 1000 is unity.
pub const TRIM_UNITY_PERMILLE: u16 = 1_000;
/// Highest per-room trim (2.0x), still bounded by the protection ceiling.
pub const MAX_TRIM_PERMILLE: u16 = 2_000;
/// Largest accepted relative volume step (percent, either direction).
pub const MAX_RELATIVE_STEP: i16 = 100;
/// Largest accepted local trim step (thousandths, either direction).
pub const MAX_LOCAL_TRIM_STEP: i16 = 500;

/// Authority token and ordering for one control command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    /// Fencing token: the group incarnation's authority epoch.
    pub epoch: u64,
    /// Strictly increasing within an epoch; revisions start at 1.
    pub revision: u64,
}

/// A group- or room-level volume command. All are absolute or explicitly relative; only
/// [`AdjustVolume`](Self::AdjustVolume) needs duplicate suppression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeCommand {
    /// Group master volume, `0..=100`.
    SetVolume(u8),
    /// Relative change of the group master volume, `-100..=100`, saturating at 0 and 100.
    AdjustVolume(i16),
    /// Per-room trim in thousandths, `0..=2000`.
    SetTrim(u16),
    /// Back to unity trim. A group volume change otherwise never touches a room's trim.
    ResetTrim,
    /// Group mute on or off. Clears only the group's own mute reason.
    SetGroupMute(bool),
}

/// Why a member is muted. Declaration order is priority: the first present reason is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MuteReason {
    /// The board is not `Active` (fault, fail-muted, unadmitted). Clears only when it is `Active` again.
    Fault,
    /// The room's own mute control. Cleared only by [`MemberVolume::local_mute`].
    Local,
    /// A new or rejoining member: silent until the join completes.
    Join,
    /// The group's mute command.
    Group,
}

impl MuteReason {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fault => "fault",
            Self::Local => "local",
            Self::Join => "join",
            Self::Group => "group",
        }
    }
}

/// Channel role of a room in a stereo pair or with a sub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Left and right as calibrated.
    Stereo,
    /// Every driver plays the left channel.
    Left,
    /// Every driver plays the right channel.
    Right,
    /// A sub receives the bass-managed mono mix; the crossover is in the board's D02 calibration.
    Sub,
}

impl Role {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stereo => "stereo",
            Self::Left => "left",
            Self::Right => "right",
            Self::Sub => "sub",
        }
    }
}

/// Why a board lacks a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleRefusal {
    /// No driver channels at all (an appliance such as the Bridge).
    NoAudioOutput,
    /// The channel layout and the channel count disagree.
    InvalidLayout,
    /// `Sub` was requested on a board with no subwoofer path.
    NoSubwooferPath,
    /// `Stereo`/`Left`/`Right` was requested on a pure sub, which has no left or right path.
    SubwooferOnly,
    /// A board mixing a subwoofer path with other drivers cannot be given a role by an input remap.
    MixedSubLayout,
}

impl RoleRefusal {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoAudioOutput => "no_audio_output",
            Self::InvalidLayout => "invalid_layout",
            Self::NoSubwooferPath => "no_subwoofer_path",
            Self::SubwooferOnly => "subwoofer_only",
            Self::MixedSubLayout => "mixed_sub_layout",
        }
    }
}

/// Typed, `Copy` refusal. A refused command changes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VolumeError {
    #[error("no authority epoch has been declared for this member")]
    NoAuthority,
    #[error("command epoch {command} is older than the current epoch {current}")]
    StaleEpoch { command: u64, current: u64 },
    #[error("command epoch {command} is newer than the declared epoch {current}")]
    UndeclaredEpoch { command: u64, current: u64 },
    #[error("revision {revision} is not newer than {last}")]
    StaleRevision { revision: u64, last: u64 },
    #[error("revision {revision} was already used for a different command")]
    RevisionConflict { revision: u64 },
    #[error("volume {value} is above the maximum volume")]
    VolumeOutOfRange { value: u8 },
    #[error("step {delta} is outside the accepted range")]
    StepOutOfRange { delta: i16 },
    #[error("trim {permille} is above the maximum trim")]
    TrimOutOfRange { permille: u16 },
    #[error("the {role:?} role is unavailable on this board: {reason:?}")]
    RoleUnavailable { role: Role, reason: RoleRefusal },
    #[error("this command addresses one room, not the whole group")]
    NotGroupWide,
    #[error("member {id} is not in this group")]
    UnknownMember { id: u32 },
    #[error("member {id} is already in this group")]
    DuplicateMember { id: u32 },
}

impl VolumeError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NoAuthority => "no_authority",
            Self::StaleEpoch { .. } => "stale_epoch",
            Self::UndeclaredEpoch { .. } => "undeclared_epoch",
            Self::StaleRevision { .. } => "stale_revision",
            Self::RevisionConflict { .. } => "revision_conflict",
            Self::VolumeOutOfRange { .. } => "volume_out_of_range",
            Self::StepOutOfRange { .. } => "step_out_of_range",
            Self::TrimOutOfRange { .. } => "trim_out_of_range",
            Self::RoleUnavailable { .. } => "role_unavailable",
            Self::NotGroupWide => "not_group_wide",
            Self::UnknownMember { .. } => "unknown_member",
            Self::DuplicateMember { .. } => "duplicate_member",
        }
    }
}

/// The result of an accepted command.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CommandReceipt {
    /// True when this was a replay of the last applied command and nothing was applied again.
    pub duplicate: bool,
    /// The reason the member is silent after this command, if any (so a requested unmute that did
    /// not produce sound can be explained).
    pub effective_mute: Option<MuteReason>,
    /// The bounded target the ramp now heads for (`0.0` while muted).
    pub target_gain: f32,
}

/// What became of the command with one `(epoch, revision)` id, as a member can truthfully say it.
///
/// A refused command changes nothing and consumes no revision, so a refusal is never recorded: it is
/// reported as [`NotApplied`](Self::NotApplied) or [`Skipped`](Self::Skipped), which is what is true of it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CommandOutcome {
    /// Applied once, here, with the receipt it produced at that moment (`duplicate` is false). A later
    /// replay of the last command reports the state *then*; this reports the result of the command itself.
    Applied {
        command: VolumeCommand,
        receipt: CommandReceipt,
    },
    /// Nothing carries this revision and nothing newer was applied: the command was lost, refused, or has
    /// not arrived. A valid command sent now with this revision is accepted.
    NotApplied,
    /// A newer revision was applied and this one never was (it was lost or refused). Sending it again is
    /// refused as `stale_revision`; send a new revision.
    Skipped,
    /// Older than the member can say: its record was evicted, or the member joined from a snapshot at or
    /// after this revision. The command MAY have been applied; the member's current state, not a
    /// per-command result, is authoritative. `remembered_from` is the oldest revision still reported.
    Forgotten { remembered_from: u64 },
}

/// One applied command and the receipt it produced, kept so its result can be reported later.
#[derive(Debug, Clone, Copy, PartialEq)]
struct AppliedRecord {
    revision: u64,
    command: VolumeCommand,
    receipt: CommandReceipt,
}

/// The group's current state, as the authority reports it to a (re)joining member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupSnapshot {
    pub epoch: u64,
    pub revision: u64,
    pub master_volume: u8,
    pub group_mute: bool,
}

/// What a member persists across a restart. Deliberately small: a restored member is not a restored
/// live session, so it comes back muted, with no authority, until it rejoins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedMember {
    pub volume: u8,
    pub trim_permille: u16,
    pub local_mute: bool,
}

/// One room as a UI reports it. `applied_gain` is the only instantaneous value; the others are
/// intent and bounds, so a slider at its desired position is not mistaken for audible output.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MemberView {
    /// Persisted group master volume, `0..=100`.
    pub desired_volume: u8,
    pub trim_permille: u16,
    /// `volume * trim` before any bound; can exceed `1.0`.
    pub requested_gain: f32,
    /// The target handed to D02 once unmuted: after the protection and fault ceilings.
    pub bounded_gain: f32,
    /// The tighter of the protection and fault ceilings.
    pub ceiling: f32,
    /// D02's ramped gain right now.
    pub applied_gain: f32,
    /// Why the room is silent, if it is. A requested unmute that a fault overrides shows `Fault`.
    pub effective_mute: Option<MuteReason>,
    /// True when a ceiling is holding the gain below what was requested.
    pub limited_by_ceiling: bool,
}

fn bounded_ceiling(value: f32) -> f32 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

/// One room's volume, trim and mute state.
#[derive(Debug, Clone)]
pub struct MemberVolume {
    epoch: Option<u64>,
    last_revision: u64,
    last_command: Option<(u64, VolumeCommand)>,
    /// The last [`RESULT_RETENTION`] applied commands, oldest overwritten first; revisions only ever increase.
    history: [Option<AppliedRecord>; RESULT_RETENTION],
    /// Where the next record goes.
    history_next: usize,
    /// The lowest revision whose fate this member can state individually. Revisions at or above it that have
    /// no record were never applied here; revisions below it are forgotten (evicted, or covered by a snapshot).
    history_floor: u64,
    volume: u8,
    trim_permille: u16,
    group_mute: bool,
    local_mute: bool,
    join_mute: bool,
    fault_mute: bool,
    protection_ceiling: f32,
    fault_ceiling: Option<f32>,
}

impl MemberVolume {
    /// A new member: no authority, volume 0, unity trim, and muted until a join completes.
    /// `protection_ceiling` is the highest gain the board's protection admits (`0.0..=1.0`).
    #[must_use]
    pub fn new(protection_ceiling: f32) -> Self {
        Self {
            epoch: None,
            last_revision: 0,
            last_command: None,
            history: [None; RESULT_RETENTION],
            history_next: 0,
            history_floor: 1,
            volume: 0,
            trim_permille: TRIM_UNITY_PERMILLE,
            group_mute: false,
            local_mute: false,
            join_mute: true,
            fault_mute: false,
            protection_ceiling: bounded_ceiling(protection_ceiling),
            fault_ceiling: None,
        }
    }

    /// Restore after a restart: persisted intent comes back, the live session does not. The member
    /// is join-muted with no authority, so a stored loud volume is never audible before it rejoins.
    #[must_use]
    pub fn restore(persisted: PersistedMember, protection_ceiling: f32) -> Self {
        let mut member = Self::new(protection_ceiling);
        member.volume = persisted.volume.min(MAX_VOLUME);
        member.trim_permille = persisted.trim_permille.min(MAX_TRIM_PERMILLE);
        member.local_mute = persisted.local_mute;
        member
    }

    #[must_use]
    pub const fn persisted(&self) -> PersistedMember {
        PersistedMember {
            volume: self.volume,
            trim_permille: self.trim_permille,
            local_mute: self.local_mute,
        }
    }

    /// Tell the member which authority epoch is current (from the membership layer, never from a
    /// command). A newer epoch resets revision tracking; an older one is refused.
    pub fn declare_epoch(&mut self, epoch: u64) -> Result<(), VolumeError> {
        match self.epoch {
            Some(current) if epoch < current => Err(VolumeError::StaleEpoch {
                command: epoch,
                current,
            }),
            Some(current) if epoch == current => Ok(()),
            _ => {
                self.epoch = Some(epoch);
                self.last_revision = 0;
                self.last_command = None;
                self.forget_results(1);
                Ok(())
            }
        }
    }

    /// Apply a stamped command. On any refusal nothing changes and the revision is not consumed.
    pub fn apply(
        &mut self,
        stamp: Stamp,
        command: VolumeCommand,
    ) -> Result<CommandReceipt, VolumeError> {
        let current = self.epoch.ok_or(VolumeError::NoAuthority)?;
        if stamp.epoch < current {
            return Err(VolumeError::StaleEpoch {
                command: stamp.epoch,
                current,
            });
        }
        if stamp.epoch > current {
            return Err(VolumeError::UndeclaredEpoch {
                command: stamp.epoch,
                current,
            });
        }
        if let Some((revision, previous)) = self.last_command
            && revision == stamp.revision
        {
            return if previous == command {
                Ok(self.receipt(true))
            } else {
                Err(VolumeError::RevisionConflict {
                    revision: stamp.revision,
                })
            };
        }
        if stamp.revision <= self.last_revision {
            return Err(VolumeError::StaleRevision {
                revision: stamp.revision,
                last: self.last_revision,
            });
        }
        let volume = self.checked_volume(command)?;
        let trim = self.checked_trim(command)?;
        if let Some(volume) = volume {
            self.volume = volume;
        }
        if let Some(trim) = trim {
            self.trim_permille = trim;
        }
        if let VolumeCommand::SetGroupMute(muted) = command {
            self.group_mute = muted;
        }
        self.last_revision = stamp.revision;
        self.last_command = Some((stamp.revision, command));
        let receipt = self.receipt(false);
        self.remember(stamp.revision, command, receipt);
        Ok(receipt)
    }

    /// Keep an applied command's result, overwriting the oldest once [`RESULT_RETENTION`] are held. The
    /// overwritten revision moves the floor above itself: it can no longer be reported individually.
    fn remember(&mut self, revision: u64, command: VolumeCommand, receipt: CommandReceipt) {
        let record = AppliedRecord {
            revision,
            command,
            receipt,
        };
        if let Some(slot) = self.history.get_mut(self.history_next)
            && let Some(evicted) = slot.replace(record)
        {
            self.history_floor = self.history_floor.max(evicted.revision.saturating_add(1));
        }
        self.history_next = (self.history_next + 1) % RESULT_RETENTION;
    }

    /// Drop every retained result: nothing below `floor` can be reported, and nothing from `floor` up has been
    /// applied here yet.
    fn forget_results(&mut self, floor: u64) {
        self.history = [None; RESULT_RETENTION];
        self.history_next = 0;
        self.history_floor = floor;
    }

    /// What became of the command with this id, so a client that timed out can reconcile. Asking changes
    /// nothing. The epoch rules are those of [`apply`](Self::apply): no declared epoch, an older epoch or an
    /// undeclared newer one is an error, because a result is only reportable under the authority that issued it.
    pub fn command_outcome(&self, stamp: Stamp) -> Result<CommandOutcome, VolumeError> {
        let current = self.epoch.ok_or(VolumeError::NoAuthority)?;
        if stamp.epoch < current {
            return Err(VolumeError::StaleEpoch {
                command: stamp.epoch,
                current,
            });
        }
        if stamp.epoch > current {
            return Err(VolumeError::UndeclaredEpoch {
                command: stamp.epoch,
                current,
            });
        }
        let revision = stamp.revision;
        if let Some(record) = self
            .history
            .iter()
            .flatten()
            .find(|r| r.revision == revision)
        {
            return Ok(CommandOutcome::Applied {
                command: record.command,
                receipt: record.receipt,
            });
        }
        Ok(if revision > self.last_revision {
            CommandOutcome::NotApplied
        } else if revision == 0 || revision >= self.history_floor {
            // Revision 0 is never valid (revisions start at 1). Otherwise the revision is inside the window in
            // which every applied command has a record, and this one has none: it was never applied here.
            CommandOutcome::Skipped
        } else {
            CommandOutcome::Forgotten {
                remembered_from: self.history_floor,
            }
        })
    }

    fn checked_volume(&self, command: VolumeCommand) -> Result<Option<u8>, VolumeError> {
        match command {
            VolumeCommand::SetVolume(value) if value > MAX_VOLUME => {
                Err(VolumeError::VolumeOutOfRange { value })
            }
            VolumeCommand::SetVolume(value) => Ok(Some(value)),
            // A range check, not `abs()`: `i16::MIN.abs()` overflows.
            VolumeCommand::AdjustVolume(delta)
                if !(-MAX_RELATIVE_STEP..=MAX_RELATIVE_STEP).contains(&delta) =>
            {
                Err(VolumeError::StepOutOfRange { delta })
            }
            VolumeCommand::AdjustVolume(delta) => {
                let next =
                    (i32::from(self.volume) + i32::from(delta)).clamp(0, i32::from(MAX_VOLUME));
                Ok(Some(next as u8))
            }
            _ => Ok(None),
        }
    }

    fn checked_trim(&self, command: VolumeCommand) -> Result<Option<u16>, VolumeError> {
        match command {
            VolumeCommand::SetTrim(permille) if permille > MAX_TRIM_PERMILLE => {
                Err(VolumeError::TrimOutOfRange { permille })
            }
            VolumeCommand::SetTrim(permille) => Ok(Some(permille)),
            VolumeCommand::ResetTrim => Ok(Some(TRIM_UNITY_PERMILLE)),
            _ => Ok(None),
        }
    }

    fn receipt(&self, duplicate: bool) -> CommandReceipt {
        CommandReceipt {
            duplicate,
            effective_mute: self.effective_mute(),
            target_gain: self.output_gain(),
        }
    }

    /// The room's own mute control (a button). Only this call changes the local reason.
    pub fn local_mute(&mut self, muted: bool) {
        self.local_mute = muted;
    }

    /// A local volume button: a bounded step of the room trim. It never unmutes.
    pub fn local_trim_step(&mut self, delta_permille: i16) -> Result<u16, VolumeError> {
        if !(-MAX_LOCAL_TRIM_STEP..=MAX_LOCAL_TRIM_STEP).contains(&delta_permille) {
            return Err(VolumeError::StepOutOfRange {
                delta: delta_permille,
            });
        }
        let next = (i32::from(self.trim_permille) + i32::from(delta_permille))
            .clamp(0, i32::from(MAX_TRIM_PERMILLE));
        self.trim_permille = next as u16;
        Ok(self.trim_permille)
    }

    /// Follow the board: while it is not `Active` the member is fault-muted, and only the board
    /// returning to `Active` clears that.
    pub fn observe_board(&mut self, status: BoardStatus) {
        self.fault_mute = !matches!(status, BoardStatus::Active);
    }

    /// The highest gain the board's protection admits. Non-finite input becomes `0.0`.
    pub fn set_protection_ceiling(&mut self, ceiling: f32) {
        self.protection_ceiling = bounded_ceiling(ceiling);
    }

    /// A temporary lower ceiling (for example while the board is thermally limited). `None` removes it.
    pub fn set_fault_ceiling(&mut self, ceiling: Option<f32>) {
        self.fault_ceiling = ceiling.map(bounded_ceiling);
    }

    /// Rejoin the group. The member goes join-muted and takes the group's *current* volume and
    /// mute from `snapshot`, never its own stored values. The room's own state is kept: its trim, its
    /// local mute, its fault mute (only the board returning to `Active` clears that) and its fault
    /// ceiling. Refused, with nothing changed, if the volume is out of range, if the snapshot's epoch
    /// is older than the member's, or if it is from the member's own epoch but older than the last
    /// revision the member has applied: a delayed snapshot is not the group's *current* state, and
    /// taking it would put back a volume the group has since replaced and reopen the revisions
    /// between the two. A snapshot at the member's own revision is the same state again and is taken;
    /// a newer epoch numbers its revisions afresh, so its revision is not compared.
    pub fn reconnect(&mut self, snapshot: GroupSnapshot) -> Result<(), VolumeError> {
        if snapshot.master_volume > MAX_VOLUME {
            return Err(VolumeError::VolumeOutOfRange {
                value: snapshot.master_volume,
            });
        }
        if let Some(current) = self.epoch
            && snapshot.epoch < current
        {
            return Err(VolumeError::StaleEpoch {
                command: snapshot.epoch,
                current,
            });
        }
        if self.epoch == Some(snapshot.epoch) && snapshot.revision < self.last_revision {
            return Err(VolumeError::StaleRevision {
                revision: snapshot.revision,
                last: self.last_revision,
            });
        }
        self.adopt(snapshot);
        Ok(())
    }

    /// Take a snapshot that has already been validated (`master_volume <= 100`, epoch not older, and
    /// not a rollback within the member's own epoch).
    fn adopt(&mut self, snapshot: GroupSnapshot) {
        self.epoch = Some(snapshot.epoch);
        self.last_revision = snapshot.revision;
        self.last_command = None;
        // The snapshot covers every revision up to its own; none of them was applied here, so none can be reported.
        self.forget_results(snapshot.revision.saturating_add(1));
        self.volume = snapshot.master_volume;
        self.group_mute = snapshot.group_mute;
        self.join_mute = true;
    }

    /// The join finished (the member is synchronized). Clears only the join reason.
    pub fn complete_join(&mut self) {
        self.join_mute = false;
    }

    #[must_use]
    pub const fn epoch(&self) -> Option<u64> {
        self.epoch
    }

    #[must_use]
    pub const fn last_revision(&self) -> u64 {
        self.last_revision
    }

    /// The desired group master volume (what a UI shows), distinct from the ramped gain.
    #[must_use]
    pub const fn desired_volume(&self) -> u8 {
        self.volume
    }

    #[must_use]
    pub const fn trim_permille(&self) -> u16 {
        self.trim_permille
    }

    /// The highest-priority reason this member is silent, if any.
    #[must_use]
    pub fn effective_mute(&self) -> Option<MuteReason> {
        [
            (self.fault_mute, MuteReason::Fault),
            (self.local_mute, MuteReason::Local),
            (self.join_mute, MuteReason::Join),
            (self.group_mute, MuteReason::Group),
        ]
        .into_iter()
        .find_map(|(active, reason)| active.then_some(reason))
    }

    /// `volume/100 * trim/1000` before any bound. Can exceed `1.0` (trim goes to 2.0).
    fn requested_gain(&self) -> f32 {
        (f32::from(self.volume) / 100.0) * (f32::from(self.trim_permille) / 1000.0)
    }

    /// The tighter of the protection ceiling and any fault ceiling.
    #[must_use]
    pub fn effective_ceiling(&self) -> f32 {
        self.fault_ceiling
            .map_or(self.protection_ceiling, |c| c.min(self.protection_ceiling))
    }

    /// `volume/100 * trim/1000`, clamped to the protection ceiling and any fault ceiling. This is
    /// the bounded value D02 ramps toward when the member is not muted.
    ///
    /// A member with no declared authority has no valid volume yet (a restored member holds only
    /// its stale stored value), so its gain is `0.0` until it rejoins.
    #[must_use]
    pub fn unmuted_gain(&self) -> f32 {
        if self.epoch.is_none() {
            return 0.0;
        }
        self.requested_gain()
            .min(self.effective_ceiling())
            .clamp(0.0, 1.0)
    }

    /// What a UI or a physical-button adapter should show, with the three quantities kept apart:
    /// the *desired* volume (persisted intent), the *bounded target* (after the ceilings, before
    /// the ramp) and D02's *applied* gain (the instantaneous ramped value).
    #[must_use]
    pub fn view(&self, dsp: &ProtectedBoardDsp) -> MemberView {
        let requested = self.requested_gain();
        MemberView {
            desired_volume: self.volume,
            trim_permille: self.trim_permille,
            requested_gain: requested,
            bounded_gain: self.unmuted_gain(),
            ceiling: self.effective_ceiling(),
            applied_gain: dsp.applied_gain(),
            effective_mute: self.effective_mute(),
            limited_by_ceiling: self.epoch.is_some() && requested > self.effective_ceiling(),
        }
    }

    /// The target gain: `0.0` while any mute reason holds, otherwise [`unmuted_gain`](Self::unmuted_gain).
    #[must_use]
    pub fn output_gain(&self) -> f32 {
        if self.effective_mute().is_some() {
            0.0
        } else {
            self.unmuted_gain()
        }
    }

    /// Hand the bounded target and mute to D02. The bounded gain is set before the mute, and D02
    /// ramps; nothing here steps the output. Call after [`observe_board`](Self::observe_board).
    pub fn apply_to(&self, dsp: &mut ProtectedBoardDsp) -> Result<(), ProtectionError> {
        dsp.set_user_gain(self.unmuted_gain());
        dsp.set_muted(self.effective_mute().is_some())
    }

    /// `observe_board` then `apply_to`: keep one board in step with this member.
    pub fn sync(&mut self, dsp: &mut ProtectedBoardDsp) -> Result<(), ProtectionError> {
        self.observe_board(dsp.status());
        self.apply_to(dsp)
    }
}

// ---- channel roles -------------------------------------------------------------------------------------

/// A role validated against one board's admitted channel layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RolePlan {
    role: Role,
}

impl RolePlan {
    /// Refuses, by name, a role the board's layout does not have.
    pub fn for_profile(profile: &BoardProfile, role: Role) -> Result<Self, VolumeError> {
        let refuse = |reason| Err(VolumeError::RoleUnavailable { role, reason });
        let routing = &profile.channel_routing;
        if profile.hardware_channels == 0 || routing.is_empty() {
            return refuse(RoleRefusal::NoAudioOutput);
        }
        if routing.len() != usize::from(profile.hardware_channels) {
            return refuse(RoleRefusal::InvalidLayout);
        }
        let subs = routing
            .iter()
            .filter(|r| **r == TransducerRole::SubwooferLfe)
            .count();
        let (none_sub, all_sub) = (subs == 0, subs == routing.len());
        match role {
            Role::Sub if all_sub => Ok(Self { role }),
            Role::Sub if none_sub => refuse(RoleRefusal::NoSubwooferPath),
            Role::Stereo | Role::Left | Role::Right if none_sub => Ok(Self { role }),
            Role::Stereo | Role::Left | Role::Right if all_sub => {
                refuse(RoleRefusal::SubwooferOnly)
            }
            _ => refuse(RoleRefusal::MixedSubLayout),
        }
    }

    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The (left, right) pair this role feeds to the board.
    #[inline]
    #[must_use]
    pub fn map(&self, left: f32, right: f32) -> (f32, f32) {
        match self.role {
            Role::Stereo => (left, right),
            Role::Left => (left, left),
            Role::Right => (right, right),
            Role::Sub => {
                let mid = 0.5 * (left + right);
                (mid, mid)
            }
        }
    }

    /// Map a whole block into `out` (no allocation). At most [`crate::FRAMES_PER_BLOCK`] frames.
    pub fn map_block(&self, input: &StereoAudioBlock, out: &mut StereoAudioBlock) {
        let frames = input.frames.min(crate::FRAMES_PER_BLOCK);
        out.start_frame = input.start_frame;
        out.frames = frames;
        for (i, (&l, &r)) in input
            .left
            .iter()
            .zip(input.right.iter())
            .take(frames)
            .enumerate()
        {
            let (ml, mr) = self.map(l, r);
            out.left[i] = ml;
            out.right[i] = mr;
        }
    }
}

// ---- group with missing members ---------------------------------------------------------------------------

/// How one member fared under a group-wide command.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemberResult {
    Accepted(CommandReceipt),
    Rejected(VolumeError),
    /// Not present: nothing was sent. It reconciles from a snapshot when it rejoins.
    Missing,
}

/// One member's answer about a group command, as that member remembers it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MemberOutcome {
    pub id: u32,
    /// Whether the member is present now. An absent member was sent nothing, so its answer is `NotApplied`,
    /// `Skipped` or `Forgotten`, never `Applied`, unless it applied the command before it left.
    pub present: bool,
    /// An error only if the member is at a different epoch from the one asked about.
    pub outcome: Result<CommandOutcome, VolumeError>,
}

/// What became of a group command: the authority's own outcome, and each member's.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupOutcome {
    /// The authority replica's outcome. This is the group's answer: `Applied` means the group accepted the
    /// command and fanned it out.
    pub authority: CommandOutcome,
    /// Every member, in the order they were added, so a client can see who has it and who missed it.
    pub members: Vec<MemberOutcome>,
}

#[derive(Debug)]
struct GroupMember {
    id: u32,
    present: bool,
    volume: MemberVolume,
}

/// The authority's view of one group and its members. Group-wide commands fan out to the members
/// that are present; absent members are skipped and rejoin from a fresh snapshot, never from the
/// volume they last held.
#[derive(Debug)]
pub struct GroupVolume {
    authority: MemberVolume,
    members: Vec<GroupMember>,
}

impl GroupVolume {
    /// A group at `epoch`. Its authority replica validates ordering for every group-wide command.
    #[must_use]
    pub fn new(epoch: u64) -> Self {
        let mut authority = MemberVolume::new(1.0);
        authority.epoch = Some(epoch);
        authority.join_mute = false;
        Self {
            authority,
            members: Vec::new(),
        }
    }

    /// Add a present member at the group's epoch, holding the group's current volume. It stays
    /// join-muted until `complete_join`. Refused if `id` is already a member (nothing changes).
    pub fn add_member(&mut self, id: u32, protection_ceiling: f32) -> Result<(), VolumeError> {
        if self.members.iter().any(|m| m.id == id) {
            return Err(VolumeError::DuplicateMember { id });
        }
        let mut volume = MemberVolume::new(protection_ceiling);
        // The authority's own snapshot is always in range and never older than the epoch it holds.
        volume.adopt(self.snapshot());
        self.members.push(GroupMember {
            id,
            present: true,
            volume,
        });
        Ok(())
    }

    #[must_use]
    pub fn snapshot(&self) -> GroupSnapshot {
        GroupSnapshot {
            epoch: self.authority.epoch().unwrap_or(0),
            revision: self.authority.last_revision(),
            master_volume: self.authority.desired_volume(),
            group_mute: self.authority.effective_mute() == Some(MuteReason::Group),
        }
    }

    /// Mark a member present or absent. An absent member is skipped by group commands.
    pub fn set_present(&mut self, id: u32, present: bool) -> Result<(), VolumeError> {
        let member = self
            .members
            .iter_mut()
            .find(|m| m.id == id)
            .ok_or(VolumeError::UnknownMember { id })?;
        member.present = present;
        Ok(())
    }

    #[must_use]
    pub fn member(&self, id: u32) -> Option<&MemberVolume> {
        self.members.iter().find(|m| m.id == id).map(|m| &m.volume)
    }

    pub fn member_mut(&mut self, id: u32) -> Option<&mut MemberVolume> {
        self.members
            .iter_mut()
            .find(|m| m.id == id)
            .map(|m| &mut m.volume)
    }

    /// Apply a group-wide command. The authority replica validates first; a refusal there changes
    /// nothing anywhere. Accepted commands (and accepted *replays*, which let a member that missed
    /// the first delivery catch up) fan out to the present members, each of which validates
    /// independently. `SetTrim` and `ResetTrim` are per-room and refused here.
    pub fn apply(
        &mut self,
        stamp: Stamp,
        command: VolumeCommand,
    ) -> Result<Vec<(u32, MemberResult)>, VolumeError> {
        if matches!(
            command,
            VolumeCommand::SetTrim(_) | VolumeCommand::ResetTrim
        ) {
            return Err(VolumeError::NotGroupWide);
        }
        self.authority.apply(stamp, command)?;
        Ok(self
            .members
            .iter_mut()
            .map(|m| {
                let result = if m.present {
                    match m.volume.apply(stamp, command) {
                        Ok(receipt) => MemberResult::Accepted(receipt),
                        Err(error) => MemberResult::Rejected(error),
                    }
                } else {
                    MemberResult::Missing
                };
                (m.id, result)
            })
            .collect())
    }

    /// What became of group command `stamp`, so a client that timed out can reconcile. Asking changes
    /// nothing. Refused for the epoch reasons [`MemberVolume::command_outcome`] refuses.
    pub fn command_outcome(&self, stamp: Stamp) -> Result<GroupOutcome, VolumeError> {
        let authority = self.authority.command_outcome(stamp)?;
        let members = self
            .members
            .iter()
            .map(|m| MemberOutcome {
                id: m.id,
                present: m.present,
                outcome: m.volume.command_outcome(stamp),
            })
            .collect();
        Ok(GroupOutcome { authority, members })
    }

    /// A member comes back: present again, join-muted, with the group's current snapshot.
    pub fn rejoin(&mut self, id: u32) -> Result<(), VolumeError> {
        let snapshot = self.snapshot();
        let member = self
            .members
            .iter_mut()
            .find(|m| m.id == id)
            .ok_or(VolumeError::UnknownMember { id })?;
        member.volume.reconnect(snapshot)?;
        member.present = true;
        Ok(())
    }
}
