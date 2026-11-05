//! Physical-button adapter (`G02` / `ffw-ld0`, the fresh-eyes clause).
//!
//! The bead says: *"Explicit physical-button event adapter ownership: consume admitted P04 button/event ABI with
//! debounce/repeat/stuck-button bounds. Local mute/stop remains available without WAN or a functioning remote
//! controller; distinguish desired persisted volume from instantaneous ramp and fault ceiling. Test held/bouncing
//! buttons concurrent with cloud retries and rejoin; reconnect may not clear local mute or restore stale louder
//! state. UI reports the effective reason when fault mute overrides requested unmute."*
//!
//! [`ButtonAdapter::on_event`] takes the events `franken-hal` delivers ([`ChannelEvent`]) and applies them to a
//! [`MemberVolume`] through exactly two of its calls, `local_mute` and `local_trim_step`. Both take no epoch, no
//! revision and no network, which is how local control stays available without a WAN or a controller. The adapter
//! writes nothing to the board (the caller hands the member's state to D02 with `sync`, as for any change) and sends
//! no remote command.
//!
//! # What a press means
//!
//! Only a debounced **`Down`** edge acts. The mute button **toggles** the member's local mute; the volume buttons
//! each apply one local trim step of the configured size. A release does nothing, an `Unknown` state does nothing,
//! and a volume press never unmutes (that is `local_trim_step`'s own rule). Every action reports
//! [`MemberVolume::effective_mute`], so a UI can say that a fault mute overrides a requested unmute.
//!
//! # What P04 cannot express, named and not invented
//!
//! * **Which id is which button.** [`ButtonMap`] is an input. The audio-control device has not been decoded (E04),
//!   and HAL says "G02 owns what a press means", so nothing is inferred and no default map exists.
//! * **Long-press.** HAL reports one `Down` and one `Up`; the time between them is not a gesture here.
//! * **Auto-repeat while held.** A held button is ONE `Down` edge. The adapter does not invent a repeat; holding
//!   the button down changes the volume by one step, not by a rate.
//! * **Chords.** Edges are per id.
//! * **"Stop" as a playback transport.** It is not a member operation in G02; this adapter provides local mute and
//!   local trim.
//!
//! # The bounds
//!
//! **Debounce** is HAL's (a raw state must be steady for the whole window); it is not repeated here. The **repeat
//! bound** is `min_press_interval_ticks`: a `Down` closer than that to the previous *applied* press
//! of the same button is ignored (and counted), so a contact that bounces slower than HAL's window cannot ratchet
//! the volume. The **stuck bound** is `stuck_after_ticks`: [`ButtonAdapter::poll`] reports a button
//! that has been down longer than that as stuck. With no auto-repeat a stuck button has no ongoing effect to bound,
//! so the adapter reports it, ignores a `Down` that arrives while it is flagged, and clears the flag on `Up`. Both
//! are caller-supplied and refused if zero; no value is chosen here.
//!
//! # Device loss
//!
//! [`ChannelEvent::Lost`] and [`ChannelEvent::Faulted`] leave every HAL button `Unknown`, which is not `Up`. The
//! adapter forgets which buttons it saw pressed, **changes nothing else**, and in particular never unmutes: a room
//! whose button device vanished stays as muted as it was.
//!
//! Numerical and host tests do not prove a physical button; nothing here touches a device.

use franken_dsp::volume::{MAX_LOCAL_TRIM_STEP, MemberVolume, MuteReason, VolumeError};
use franken_hal::events::{ButtonState, ChannelEvent};

#[cfg(test)]
mod tests;

/// What a button does. Three roles, each on its own HAL button id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonRole {
    /// Toggles the member's local mute.
    Mute,
    /// One local trim step up.
    VolumeUp,
    /// One local trim step down.
    VolumeDown,
}

impl ButtonRole {
    /// Every role, in `index` order.
    pub const ALL: [Self; 3] = [Self::Mute, Self::VolumeUp, Self::VolumeDown];

    const fn index(self) -> usize {
        match self {
            Self::Mute => 0,
            Self::VolumeUp => 1,
            Self::VolumeDown => 2,
        }
    }
}

/// Why a configuration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ButtonConfigError {
    #[error("button id {id} is assigned to more than one role")]
    SharedButton { id: u8 },
    #[error(
        "trim step {step} permille is outside what a local step accepts (1 up to the member's local step limit)"
    )]
    StepOutOfRange { step: i16 },
    #[error("the repeat bound must be at least one tick")]
    NoRepeatBound,
    #[error("the stuck bound must be at least one tick")]
    NoStuckBound,
}

/// Which HAL button id has which role. An input: nothing about the board is inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ButtonMap {
    mute: u8,
    volume_up: u8,
    volume_down: u8,
}

impl ButtonMap {
    /// The three ids must differ: a button cannot have two roles.
    pub fn new(mute: u8, volume_up: u8, volume_down: u8) -> Result<Self, ButtonConfigError> {
        if mute == volume_up || mute == volume_down {
            return Err(ButtonConfigError::SharedButton { id: mute });
        }
        if volume_up == volume_down {
            return Err(ButtonConfigError::SharedButton { id: volume_up });
        }
        Ok(Self {
            mute,
            volume_up,
            volume_down,
        })
    }

    fn role_of(&self, id: u8) -> Option<ButtonRole> {
        if id == self.mute {
            Some(ButtonRole::Mute)
        } else if id == self.volume_up {
            Some(ButtonRole::VolumeUp)
        } else if id == self.volume_down {
            Some(ButtonRole::VolumeDown)
        } else {
            None
        }
    }
}

/// The step size and the two bounds, in the units the caller owns: permille of trim, and channel ticks (the `at`
/// of a HAL event). No default is offered because none is chosen by the clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ButtonBounds {
    trim_step_permille: i16,
    min_press_interval_ticks: u64,
    stuck_after_ticks: u64,
}

impl ButtonBounds {
    /// `trim_step_permille` must be from 1 up to the member's local step limit; both tick bounds must be nonzero.
    pub fn new(
        trim_step_permille: i16,
        min_press_interval_ticks: u64,
        stuck_after_ticks: u64,
    ) -> Result<Self, ButtonConfigError> {
        if !(1..=MAX_LOCAL_TRIM_STEP).contains(&trim_step_permille) {
            return Err(ButtonConfigError::StepOutOfRange {
                step: trim_step_permille,
            });
        }
        if min_press_interval_ticks == 0 {
            return Err(ButtonConfigError::NoRepeatBound);
        }
        if stuck_after_ticks == 0 {
            return Err(ButtonConfigError::NoStuckBound);
        }
        Ok(Self {
            trim_step_permille,
            min_press_interval_ticks,
            stuck_after_ticks,
        })
    }
}

/// Why an event did nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoredButton {
    /// A debounced `Up`: a release is not a press.
    Release,
    /// A debounced `Up` of a button that had been flagged stuck: the flag is cleared, nothing else happens.
    ReleaseOfStuckButton,
    /// `Unknown` is neither `Up` nor `Down`.
    UnknownState,
    /// An id with no role in the [`ButtonMap`].
    Unmapped,
    /// A `Down` closer than the repeat bound to the previous applied press of the same button.
    TooSoonAfterLastPress,
    /// A `Down` while the button is flagged stuck.
    WhileStuck,
    /// An LED or device fault: not a button.
    NotAButtonEvent,
}

/// What one event did to the member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonAction {
    /// The mute button toggled the local mute. `effective_mute` is why the room is silent after it, if it is: a
    /// requested unmute that a fault overrides shows `Some(Fault)`.
    LocalMute {
        muted: bool,
        effective_mute: Option<MuteReason>,
    },
    /// A volume button moved the room trim. It never unmutes.
    TrimStep {
        trim_permille: u16,
        effective_mute: Option<MuteReason>,
    },
    /// Nothing changed, for the stated reason.
    Ignored(IgnoredButton),
    /// The member refused the trim step. Cannot happen with a validated [`ButtonBounds`]; kept typed instead of
    /// unwrapped.
    Refused(VolumeError),
    /// The channel was lost or faulted: pressed-button bookkeeping was forgotten, and nothing else changed.
    ChannelReset,
}

/// Exact counts of what the adapter did with the events it saw (saturating).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ButtonStats {
    pub mute_toggles: u32,
    pub trim_steps: u32,
    pub releases: u32,
    pub unknown_states: u32,
    pub unmapped: u32,
    pub too_soon: u32,
    pub while_stuck: u32,
    pub stuck_detected: u32,
    pub channel_resets: u32,
    pub other_events: u32,
}

#[derive(Debug, Clone, Copy)]
struct Press {
    /// The tick the current debounced `Down` was reported at, while the button is down.
    down_at: Option<u64>,
    /// The tick of the last press that was applied.
    last_applied_at: Option<u64>,
    stuck: bool,
}

const IDLE: Press = Press {
    down_at: None,
    last_applied_at: None,
    stuck: false,
};

/// Turns debounced HAL button events into local mute and local trim on one member.
#[derive(Debug, Clone)]
pub struct ButtonAdapter {
    map: ButtonMap,
    bounds: ButtonBounds,
    presses: [Press; 3],
    stats: ButtonStats,
}

fn bump(counter: &mut u32) {
    *counter = counter.saturating_add(1);
}

impl ButtonAdapter {
    #[must_use]
    pub const fn new(map: ButtonMap, bounds: ButtonBounds) -> Self {
        Self {
            map,
            bounds,
            presses: [IDLE; 3],
            stats: ButtonStats {
                mute_toggles: 0,
                trim_steps: 0,
                releases: 0,
                unknown_states: 0,
                unmapped: 0,
                too_soon: 0,
                while_stuck: 0,
                stuck_detected: 0,
                channel_resets: 0,
                other_events: 0,
            },
        }
    }

    /// Apply one event the HAL channel delivered. Only a debounced `Down` of a mapped button acts.
    pub fn on_event(&mut self, event: ChannelEvent, member: &mut MemberVolume) -> ButtonAction {
        match event {
            ChannelEvent::ButtonChanged { id, state, at } => self.on_button(id, state, at, member),
            ChannelEvent::Lost { .. } | ChannelEvent::Faulted { .. } => {
                // Every HAL button is now Unknown, which is not Up. Forget what was pressed; touch nothing else.
                self.presses = [IDLE; 3];
                bump(&mut self.stats.channel_resets);
                ButtonAction::ChannelReset
            }
            ChannelEvent::LedFault { .. } | ChannelEvent::DeviceFault { .. } => {
                bump(&mut self.stats.other_events);
                ButtonAction::Ignored(IgnoredButton::NotAButtonEvent)
            }
        }
    }

    fn on_button(
        &mut self,
        id: u8,
        state: ButtonState,
        at: u64,
        member: &mut MemberVolume,
    ) -> ButtonAction {
        let Some(role) = self.map.role_of(id) else {
            bump(&mut self.stats.unmapped);
            return ButtonAction::Ignored(IgnoredButton::Unmapped);
        };
        let slot = role.index();
        let mut press = self.presses[slot];
        match state {
            ButtonState::Unknown => {
                press.down_at = None;
                press.stuck = false;
                self.presses[slot] = press;
                bump(&mut self.stats.unknown_states);
                ButtonAction::Ignored(IgnoredButton::UnknownState)
            }
            ButtonState::Up => {
                press.down_at = None;
                let was_stuck = press.stuck;
                press.stuck = false;
                self.presses[slot] = press;
                if was_stuck {
                    ButtonAction::Ignored(IgnoredButton::ReleaseOfStuckButton)
                } else {
                    bump(&mut self.stats.releases);
                    ButtonAction::Ignored(IgnoredButton::Release)
                }
            }
            ButtonState::Down => {
                if press.stuck {
                    bump(&mut self.stats.while_stuck);
                    return ButtonAction::Ignored(IgnoredButton::WhileStuck);
                }
                press.down_at = Some(at);
                let too_soon = press.last_applied_at.is_some_and(|last| {
                    at.saturating_sub(last) < self.bounds.min_press_interval_ticks
                });
                if !too_soon {
                    press.last_applied_at = Some(at);
                }
                self.presses[slot] = press;
                if too_soon {
                    bump(&mut self.stats.too_soon);
                    return ButtonAction::Ignored(IgnoredButton::TooSoonAfterLastPress);
                }
                self.apply(role, member)
            }
        }
    }

    fn apply(&mut self, role: ButtonRole, member: &mut MemberVolume) -> ButtonAction {
        match role {
            ButtonRole::Mute => {
                let muted = !member.persisted().local_mute;
                member.local_mute(muted);
                bump(&mut self.stats.mute_toggles);
                ButtonAction::LocalMute {
                    muted,
                    effective_mute: member.effective_mute(),
                }
            }
            ButtonRole::VolumeUp | ButtonRole::VolumeDown => {
                let step = if role == ButtonRole::VolumeUp {
                    self.bounds.trim_step_permille
                } else {
                    -self.bounds.trim_step_permille
                };
                match member.local_trim_step(step) {
                    Ok(trim_permille) => {
                        bump(&mut self.stats.trim_steps);
                        ButtonAction::TrimStep {
                            trim_permille,
                            effective_mute: member.effective_mute(),
                        }
                    }
                    Err(error) => ButtonAction::Refused(error),
                }
            }
        }
    }

    /// Report, once, each button that has now been down for at least the stuck bound. `now` is the channel tick.
    /// A held button produced one press when it went down and nothing since (HAL expresses no repeat), so being
    /// stuck changes no volume; this reports it so a UI can say so.
    pub fn poll(&mut self, now: u64) -> Vec<ButtonRole> {
        let mut newly_stuck = Vec::new();
        for role in ButtonRole::ALL {
            let press = &mut self.presses[role.index()];
            if !press.stuck
                && press.down_at.is_some_and(|down_at| {
                    now.saturating_sub(down_at) >= self.bounds.stuck_after_ticks
                })
            {
                press.stuck = true;
                newly_stuck.push(role);
            }
        }
        let count = u32::try_from(newly_stuck.len()).unwrap_or(u32::MAX);
        self.stats.stuck_detected = self.stats.stuck_detected.saturating_add(count);
        newly_stuck
    }

    /// Whether the button is currently flagged stuck.
    #[must_use]
    pub fn is_stuck(&self, role: ButtonRole) -> bool {
        self.presses[role.index()].stuck
    }

    #[must_use]
    pub const fn stats(&self) -> ButtonStats {
        self.stats
    }
}
