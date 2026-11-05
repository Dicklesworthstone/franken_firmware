//! Typed command contract (P01 / `ffw-h3g`, bead section 2, "Integration boundary").
//!
//! Every adapter submits commands to one authoritative playback state machine through
//! [`CommandSink`]. This module fixes what a command is, when repeating it is safe, and what an
//! acknowledgement is allowed to claim.
//!
//! **Idempotency.** Each [`CommandKind`] knows whether repeating it is harmless ([`RepeatSafety`]).
//! An absolute volume or a mute is naturally repeatable; a relative volume change or a skip is not,
//! so it must carry an [`IdempotencyToken`] and a [`CommandEnvelope`] without one is refused when it is
//! built. A sink suppresses a repeated token for commands that need it.
//!
//! **Acknowledgement.** [`AckLevel::Accepted`] means the command was taken; [`AckLevel::Completed`]
//! means its effect is real. The only public way to produce a completed [`CommandAck`] is
//! [`CommandAck::from_report`], which needs a [`RendererReport`] that actually evidences the effect: a
//! volume change completes only when the renderer reports the state applied, and a stop, seek or skip
//! completes only when the old submitted output has drained or been flushed and muted. Queueing a
//! command can never be reported as completing it, and an old stream still playing never completes a
//! seek.
//!
//! **Bounds.** A sink holds a fixed number of pending commands and answers a full queue with
//! [`CommandError::QueueFull`]. A command that is refused does not consume its token, so a corrected
//! or retried submission is judged on its own merits.
//!
//! [`EphemeralCommandSink`] is an in-memory double of the state-machine boundary for tests. It is not
//! the group-command fence in `franken-session`, which owns the real epoch and dedup rules.

use std::fmt;

#[cfg(test)]
use std::collections::BTreeMap;

use super::source_session::{SessionId, StreamEpoch};

/// Longest idempotency token, in bytes.
pub const MAX_TOKEN_LEN: usize = 64;
/// Relative volume changes are limited to this many steps either way.
pub const MAX_VOLUME_STEP: i8 = 100;

/// A transport-supplied token that identifies one logical command across redelivery. Opaque and
/// bounded: one to [`MAX_TOKEN_LEN`] printable ASCII bytes. It is a transport identity, not a
/// credential, so it may be logged.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdempotencyToken(String);

impl IdempotencyToken {
    /// Validate and wrap a token.
    pub fn parse(raw: &str) -> Result<Self, CommandError> {
        if raw.is_empty() {
            return Err(CommandError::InvalidToken { reason: "empty" });
        }
        if raw.len() > MAX_TOKEN_LEN {
            return Err(CommandError::InvalidToken {
                reason: "longer than the token limit",
            });
        }
        if !raw.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(CommandError::InvalidToken {
                reason: "only printable ASCII without spaces is allowed",
            });
        }
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IdempotencyToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Identifies one accepted command within a sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommandId(u64);

impl CommandId {
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Whether delivering a command twice is harmless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepeatSafety {
    NaturallyRepeatable,
    NeedsDuplicateSuppression,
}

/// What a command asks for. `Play` and `Pause` are explicit states, not toggles, so repeating them
/// changes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandKind {
    SetVolume { level: u8 },
    AdjustVolume { delta: i8 },
    SetMute { muted: bool },
    Play,
    Pause,
    Stop,
    SeekTo { position_ms: u64 },
    Skip { tracks: i8 },
}

impl CommandKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SetVolume { .. } => "set-volume",
            Self::AdjustVolume { .. } => "adjust-volume",
            Self::SetMute { .. } => "set-mute",
            Self::Play => "play",
            Self::Pause => "pause",
            Self::Stop => "stop",
            Self::SeekTo { .. } => "seek-to",
            Self::Skip { .. } => "skip",
        }
    }

    /// Absolute commands can be repeated; relative ones cannot.
    #[must_use]
    pub const fn repeat_safety(self) -> RepeatSafety {
        match self {
            Self::SetVolume { .. }
            | Self::SetMute { .. }
            | Self::Play
            | Self::Pause
            | Self::Stop
            | Self::SeekTo { .. } => RepeatSafety::NaturallyRepeatable,
            Self::AdjustVolume { .. } | Self::Skip { .. } => {
                RepeatSafety::NeedsDuplicateSuppression
            }
        }
    }

    /// Whether the command changes what is being played, as opposed to how loudly.
    #[must_use]
    pub const fn affects_playback(self) -> bool {
        matches!(
            self,
            Self::Play | Self::Pause | Self::Stop | Self::SeekTo { .. } | Self::Skip { .. }
        )
    }
}

/// A command ready to submit, validated when built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandEnvelope {
    source: SessionId,
    epoch: StreamEpoch,
    kind: CommandKind,
    token: Option<IdempotencyToken>,
}

impl CommandEnvelope {
    /// Build an envelope, refusing a command that needs duplicate suppression but has no token, and
    /// values outside their range.
    pub fn new(
        source: SessionId,
        epoch: StreamEpoch,
        kind: CommandKind,
        token: Option<IdempotencyToken>,
    ) -> Result<Self, CommandError> {
        match kind {
            CommandKind::SetVolume { level } if level > 100 => {
                return Err(CommandError::VolumeOutOfRange { level });
            }
            CommandKind::AdjustVolume { delta }
                if delta == 0 || delta.unsigned_abs() > MAX_VOLUME_STEP.unsigned_abs() =>
            {
                return Err(CommandError::StepOutOfRange { delta });
            }
            CommandKind::Skip { tracks: 0 } => {
                return Err(CommandError::ZeroSkip);
            }
            _ => {}
        }
        if kind.repeat_safety() == RepeatSafety::NeedsDuplicateSuppression && token.is_none() {
            return Err(CommandError::MissingIdempotencyToken { kind: kind.label() });
        }
        Ok(Self {
            source,
            epoch,
            kind,
            token,
        })
    }

    #[must_use]
    pub const fn source(&self) -> SessionId {
        self.source
    }

    #[must_use]
    pub const fn epoch(&self) -> StreamEpoch {
        self.epoch
    }

    #[must_use]
    pub const fn kind(&self) -> CommandKind {
        self.kind
    }

    #[must_use]
    pub const fn token(&self) -> Option<&IdempotencyToken> {
        self.token.as_ref()
    }
}

/// What the renderer has told the state machine about a command's effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RendererReport {
    /// Nothing yet.
    NotReported,
    /// Output submitted before the command is still playing.
    OldOutputStillPlaying,
    /// Output submitted before the command has drained.
    OldOutputDrained,
    /// Output submitted before the command was flushed and the output muted.
    OldOutputFlushedMuted,
    /// The renderer applied the requested state (volume, mute, play, pause).
    StateApplied,
}

/// How far a command has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckLevel {
    /// Taken, effect not yet evidenced.
    Accepted,
    /// Effect evidenced by the renderer.
    Completed,
}

/// The level a renderer report justifies for a command kind. Volume, mute, play and pause need the
/// state applied; stop, seek and skip need the old output drained or flushed and muted. Every other
/// combination, including an old stream that is still playing, stays [`AckLevel::Accepted`].
#[must_use]
pub const fn completion_level(kind: CommandKind, report: RendererReport) -> AckLevel {
    let evidenced = match kind {
        CommandKind::SetVolume { .. }
        | CommandKind::AdjustVolume { .. }
        | CommandKind::SetMute { .. }
        | CommandKind::Play
        | CommandKind::Pause => matches!(report, RendererReport::StateApplied),
        CommandKind::Stop | CommandKind::SeekTo { .. } | CommandKind::Skip { .. } => matches!(
            report,
            RendererReport::OldOutputDrained | RendererReport::OldOutputFlushedMuted
        ),
    };
    if evidenced {
        AckLevel::Completed
    } else {
        AckLevel::Accepted
    }
}

/// An acknowledgement. Its fields are private and the only way to build a completed one is
/// [`CommandAck::from_report`], so an adapter cannot claim completion it has no evidence for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandAck {
    id: CommandId,
    level: AckLevel,
}

impl CommandAck {
    /// The command was taken. This is all that queueing can claim.
    #[must_use]
    pub const fn accepted(id: CommandId) -> Self {
        Self {
            id,
            level: AckLevel::Accepted,
        }
    }

    /// The acknowledgement a renderer report justifies for `kind`.
    #[must_use]
    pub const fn from_report(id: CommandId, kind: CommandKind, report: RendererReport) -> Self {
        Self {
            id,
            level: completion_level(kind, report),
        }
    }

    #[must_use]
    pub const fn id(&self) -> CommandId {
        self.id
    }

    #[must_use]
    pub const fn level(&self) -> AckLevel {
        self.level
    }
}

/// Why a command was refused. No variant carries anything beyond the command's own labels.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommandError {
    #[error("invalid idempotency token: {reason}")]
    InvalidToken { reason: &'static str },
    #[error("`{kind}` is not safe to repeat, so it needs an idempotency token")]
    MissingIdempotencyToken { kind: &'static str },
    #[error("volume {level} is above 100")]
    VolumeOutOfRange { level: u8 },
    #[error("volume step {delta} is zero or beyond +/-100")]
    StepOutOfRange { delta: i8 },
    #[error("a skip of zero tracks does nothing")]
    ZeroSkip,
    #[error("stale stream epoch {command}: the sink is at epoch {current}")]
    StaleEpoch { command: u64, current: u64 },
    #[error("stream epoch {command} is ahead of the sink's epoch {current}")]
    EpochAhead { command: u64, current: u64 },
    #[error("duplicate command: token `{token}` was already accepted")]
    DuplicateCommand { token: IdempotencyToken },
    #[error("the pending-command queue is full ({capacity} entries)")]
    QueueFull { capacity: usize },
    #[error("no such command {id}")]
    UnknownCommand { id: u64 },
    #[error("command {id} has not completed, so it cannot be retired")]
    NotCompleted { id: u64 },
}

/// The boundary adapters use to reach the authoritative playback state machine.
pub trait CommandSink {
    /// Take a command. A refused command changes nothing, and in particular does not consume its
    /// token.
    fn submit(&mut self, command: CommandEnvelope) -> Result<CommandAck, CommandError>;

    /// The renderer reports a command's effect. The acknowledgement returned is the one the report
    /// justifies, which may still be only `Accepted`.
    fn report_renderer(
        &mut self,
        id: CommandId,
        report: RendererReport,
    ) -> Result<CommandAck, CommandError>;

    /// Release a completed command's slot (and its token). A command that has not completed is
    /// refused: abandoning one is a separate, explicit decision.
    fn retire(&mut self, id: CommandId) -> Result<(), CommandError>;
}

/// A pending command and the renderer report that completed it, if one has.
#[cfg(test)]
struct Tracked {
    command: CommandEnvelope,
    evidence: Option<RendererReport>,
}

/// In-memory sink for tests. It remembers a duplicate token only while its command is unretired, so
/// its suppression horizon is the pending window; the real state machine uses `franken-session`'s
/// windowed floor instead.
#[cfg(test)]
pub struct EphemeralCommandSink {
    epoch: StreamEpoch,
    capacity: usize,
    next_id: u64,
    commands: BTreeMap<CommandId, Tracked>,
}

#[cfg(test)]
impl EphemeralCommandSink {
    #[must_use]
    pub fn new(epoch: StreamEpoch, capacity: usize) -> Self {
        Self {
            epoch,
            capacity,
            next_id: 1,
            commands: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn pending(&self) -> usize {
        self.commands.len()
    }
}

#[cfg(test)]
impl CommandSink for EphemeralCommandSink {
    fn submit(&mut self, command: CommandEnvelope) -> Result<CommandAck, CommandError> {
        if command.epoch() < self.epoch {
            return Err(CommandError::StaleEpoch {
                command: command.epoch().get(),
                current: self.epoch.get(),
            });
        }
        if command.epoch() > self.epoch {
            return Err(CommandError::EpochAhead {
                command: command.epoch().get(),
                current: self.epoch.get(),
            });
        }
        if command.kind().repeat_safety() == RepeatSafety::NeedsDuplicateSuppression
            && let Some(token) = command.token()
        {
            let seen = self.commands.values().any(|t| {
                t.command.source() == command.source()
                    && t.command.kind().repeat_safety() == RepeatSafety::NeedsDuplicateSuppression
                    && t.command.token() == Some(token)
            });
            if seen {
                return Err(CommandError::DuplicateCommand {
                    token: token.clone(),
                });
            }
        }
        if self.commands.len() >= self.capacity {
            return Err(CommandError::QueueFull {
                capacity: self.capacity,
            });
        }
        let id = CommandId::new(self.next_id);
        self.next_id += 1;
        self.commands.insert(
            id,
            Tracked {
                command,
                evidence: None,
            },
        );
        Ok(CommandAck::accepted(id))
    }

    fn report_renderer(
        &mut self,
        id: CommandId,
        report: RendererReport,
    ) -> Result<CommandAck, CommandError> {
        let tracked = self
            .commands
            .get_mut(&id)
            .ok_or(CommandError::UnknownCommand { id: id.get() })?;
        let kind = tracked.command.kind();
        // Remember the first report that evidences completion. A completed command stays completed:
        // a later, weaker report is judged against the stored evidence, never against itself.
        if tracked.evidence.is_none() && completion_level(kind, report) == AckLevel::Completed {
            tracked.evidence = Some(report);
        }
        let judged_by = tracked.evidence.unwrap_or(report);
        Ok(CommandAck::from_report(id, kind, judged_by))
    }

    fn retire(&mut self, id: CommandId) -> Result<(), CommandError> {
        match self.commands.get(&id) {
            None => Err(CommandError::UnknownCommand { id: id.get() }),
            Some(t) if t.evidence.is_none() => Err(CommandError::NotCompleted { id: id.get() }),
            Some(_) => {
                self.commands.remove(&id);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORTS: [RendererReport; 5] = [
        RendererReport::NotReported,
        RendererReport::OldOutputStillPlaying,
        RendererReport::OldOutputDrained,
        RendererReport::OldOutputFlushedMuted,
        RendererReport::StateApplied,
    ];

    fn sid(n: u64) -> SessionId {
        SessionId::new(n)
    }

    fn epoch(n: u64) -> StreamEpoch {
        StreamEpoch::new(n)
    }

    fn token(raw: &str) -> IdempotencyToken {
        IdempotencyToken::parse(raw).unwrap()
    }

    fn envelope(kind: CommandKind, tok: Option<&str>) -> CommandEnvelope {
        CommandEnvelope::new(sid(1), epoch(5), kind, tok.map(token)).unwrap()
    }

    fn adjust(delta: i8, tok: &str) -> CommandEnvelope {
        envelope(CommandKind::AdjustVolume { delta }, Some(tok))
    }

    #[test]
    fn tokens_are_bounded_printable_ascii() {
        assert_eq!(token("req-7f3a").as_str(), "req-7f3a");
        assert_eq!(
            token(&"t".repeat(MAX_TOKEN_LEN)).as_str().len(),
            MAX_TOKEN_LEN
        );
        let long = "t".repeat(MAX_TOKEN_LEN + 1);
        for raw in ["", "has space", "tab\there", "caf\u{e9}", long.as_str()] {
            assert!(
                matches!(
                    IdempotencyToken::parse(raw),
                    Err(CommandError::InvalidToken { .. })
                ),
                "{raw:?} must be refused"
            );
        }
    }

    /// Written independently of `repeat_safety`: which kinds are naturally repeatable.
    #[test]
    fn repeat_safety_matches_an_independently_written_table() {
        let table: [(CommandKind, RepeatSafety); 8] = [
            (
                CommandKind::SetVolume { level: 30 },
                RepeatSafety::NaturallyRepeatable,
            ),
            (
                CommandKind::SetMute { muted: true },
                RepeatSafety::NaturallyRepeatable,
            ),
            (CommandKind::Play, RepeatSafety::NaturallyRepeatable),
            (CommandKind::Pause, RepeatSafety::NaturallyRepeatable),
            (CommandKind::Stop, RepeatSafety::NaturallyRepeatable),
            (
                CommandKind::SeekTo { position_ms: 1_000 },
                RepeatSafety::NaturallyRepeatable,
            ),
            (
                CommandKind::AdjustVolume { delta: 5 },
                RepeatSafety::NeedsDuplicateSuppression,
            ),
            (
                CommandKind::Skip { tracks: 1 },
                RepeatSafety::NeedsDuplicateSuppression,
            ),
        ];
        for (kind, expected) in table {
            assert_eq!(kind.repeat_safety(), expected, "{}", kind.label());
        }
    }

    #[test]
    fn a_command_that_needs_suppression_without_a_token_is_refused_at_construction() {
        for kind in [
            CommandKind::AdjustVolume { delta: -5 },
            CommandKind::Skip { tracks: -1 },
        ] {
            assert_eq!(
                CommandEnvelope::new(sid(1), epoch(5), kind, None).unwrap_err(),
                CommandError::MissingIdempotencyToken { kind: kind.label() }
            );
            assert!(CommandEnvelope::new(sid(1), epoch(5), kind, Some(token("t1"))).is_ok());
        }
        // Naturally repeatable commands do not need one.
        assert!(
            CommandEnvelope::new(sid(1), epoch(5), CommandKind::SetVolume { level: 10 }, None)
                .is_ok()
        );
    }

    #[test]
    fn out_of_range_values_are_refused() {
        let ok =
            |k: CommandKind| CommandEnvelope::new(sid(1), epoch(5), k, Some(token("t"))).is_ok();
        assert!(ok(CommandKind::SetVolume { level: 100 }));
        assert!(ok(CommandKind::AdjustVolume { delta: 100 }));
        assert!(ok(CommandKind::AdjustVolume { delta: -100 }));
        assert_eq!(
            CommandEnvelope::new(
                sid(1),
                epoch(5),
                CommandKind::SetVolume { level: 101 },
                None
            )
            .unwrap_err(),
            CommandError::VolumeOutOfRange { level: 101 }
        );
        for delta in [0, 101, -101, i8::MIN, i8::MAX] {
            assert_eq!(
                CommandEnvelope::new(
                    sid(1),
                    epoch(5),
                    CommandKind::AdjustVolume { delta },
                    Some(token("t"))
                )
                .unwrap_err(),
                CommandError::StepOutOfRange { delta },
                "delta {delta}"
            );
        }
        assert_eq!(
            CommandEnvelope::new(
                sid(1),
                epoch(5),
                CommandKind::Skip { tracks: 0 },
                Some(token("t"))
            )
            .unwrap_err(),
            CommandError::ZeroSkip
        );
    }

    #[test]
    fn affects_playback_separates_transport_from_volume() {
        assert!(CommandKind::Play.affects_playback());
        assert!(CommandKind::Skip { tracks: 1 }.affects_playback());
        assert!(!CommandKind::SetVolume { level: 1 }.affects_playback());
        assert!(!CommandKind::SetMute { muted: false }.affects_playback());
        assert!(!CommandKind::AdjustVolume { delta: 1 }.affects_playback());
    }

    /// Every (kind, report) pair, against a matrix written by hand. Columns follow `REPORTS`:
    /// not reported, old still playing, drained, flushed and muted, state applied.
    #[test]
    fn completion_needs_the_evidence_that_fits_the_command() {
        let matrix: [(CommandKind, [bool; 5]); 8] = [
            (
                CommandKind::SetVolume { level: 30 },
                [false, false, false, false, true],
            ),
            (
                CommandKind::AdjustVolume { delta: 5 },
                [false, false, false, false, true],
            ),
            (
                CommandKind::SetMute { muted: true },
                [false, false, false, false, true],
            ),
            (CommandKind::Play, [false, false, false, false, true]),
            (CommandKind::Pause, [false, false, false, false, true]),
            (CommandKind::Stop, [false, false, true, true, false]),
            (
                CommandKind::SeekTo { position_ms: 5 },
                [false, false, true, true, false],
            ),
            (
                CommandKind::Skip { tracks: 1 },
                [false, false, true, true, false],
            ),
        ];
        for (kind, expected) in matrix {
            for (report, completes) in REPORTS.into_iter().zip(expected) {
                let level = completion_level(kind, report);
                let want = if completes {
                    AckLevel::Completed
                } else {
                    AckLevel::Accepted
                };
                assert_eq!(level, want, "{} with {report:?}", kind.label());
            }
        }
    }

    #[test]
    fn queueing_alone_never_reports_completion() {
        let ack = CommandAck::accepted(CommandId::new(9));
        assert_eq!(ack.level(), AckLevel::Accepted);
        let none = CommandAck::from_report(
            CommandId::new(9),
            CommandKind::Play,
            RendererReport::NotReported,
        );
        assert_eq!(none.level(), AckLevel::Accepted);
    }

    #[test]
    fn an_old_stream_still_playing_never_completes_a_seek_or_skip() {
        for kind in [
            CommandKind::SeekTo {
                position_ms: 30_000,
            },
            CommandKind::Skip { tracks: 1 },
            CommandKind::Stop,
        ] {
            let mut sink = EphemeralCommandSink::new(epoch(5), 4);
            let tok = Some("t1");
            let ack = sink.submit(envelope(kind, tok)).unwrap();
            assert_eq!(ack.level(), AckLevel::Accepted);
            for report in [
                RendererReport::OldOutputStillPlaying,
                RendererReport::StateApplied,
            ] {
                assert_eq!(
                    sink.report_renderer(ack.id(), report).unwrap().level(),
                    AckLevel::Accepted,
                    "{} with {report:?}",
                    kind.label()
                );
            }
            assert_eq!(
                sink.report_renderer(ack.id(), RendererReport::OldOutputFlushedMuted)
                    .unwrap()
                    .level(),
                AckLevel::Completed
            );
        }
    }

    #[test]
    fn a_completed_command_stays_completed_and_only_then_can_be_retired() {
        let mut sink = EphemeralCommandSink::new(epoch(5), 4);
        let id = sink
            .submit(envelope(CommandKind::SetVolume { level: 40 }, None))
            .unwrap()
            .id();
        assert_eq!(
            sink.retire(id).unwrap_err(),
            CommandError::NotCompleted { id: id.get() }
        );
        assert_eq!(
            sink.report_renderer(id, RendererReport::StateApplied)
                .unwrap()
                .level(),
            AckLevel::Completed
        );
        // A later, weaker report does not undo it.
        assert_eq!(
            sink.report_renderer(id, RendererReport::NotReported)
                .unwrap()
                .level(),
            AckLevel::Completed
        );
        sink.retire(id).unwrap();
        assert_eq!(
            sink.retire(id).unwrap_err(),
            CommandError::UnknownCommand { id: id.get() }
        );
        assert_eq!(
            sink.report_renderer(id, RendererReport::StateApplied)
                .unwrap_err(),
            CommandError::UnknownCommand { id: id.get() }
        );
    }

    #[test]
    fn a_repeated_relative_command_is_suppressed_but_a_repeated_absolute_one_is_not() {
        let mut sink = EphemeralCommandSink::new(epoch(5), 8);
        sink.submit(adjust(5, "t1")).unwrap();
        assert_eq!(
            sink.submit(adjust(5, "t1")).unwrap_err(),
            CommandError::DuplicateCommand { token: token("t1") }
        );
        // The same token on a different command of the same source is still the same logical command.
        assert!(sink.submit(adjust(-5, "t1")).is_err());
        // A new token is a new command.
        assert!(sink.submit(adjust(5, "t2")).is_ok());

        // Absolute volume repeats freely, with or without a token.
        let set = envelope(CommandKind::SetVolume { level: 30 }, Some("t1"));
        assert!(sink.submit(set.clone()).is_ok());
        assert!(sink.submit(set).is_ok());
        assert!(
            sink.submit(envelope(CommandKind::SetVolume { level: 30 }, None))
                .is_ok()
        );
    }

    #[test]
    fn the_same_token_from_two_sources_is_two_commands() {
        let mut sink = EphemeralCommandSink::new(epoch(5), 8);
        let from = |n: u64| {
            CommandEnvelope::new(
                sid(n),
                epoch(5),
                CommandKind::Skip { tracks: 1 },
                Some(token("t1")),
            )
            .unwrap()
        };
        assert!(sink.submit(from(1)).is_ok());
        assert!(sink.submit(from(2)).is_ok());
        assert!(sink.submit(from(1)).is_err());
    }

    #[test]
    fn a_full_queue_refuses_without_burning_the_token() {
        let mut sink = EphemeralCommandSink::new(epoch(5), 2);
        let a = sink.submit(adjust(1, "a")).unwrap().id();
        sink.submit(adjust(1, "b")).unwrap();
        assert_eq!(sink.pending(), 2);

        // Refused for want of room: nothing was recorded, not even the token.
        assert_eq!(
            sink.submit(adjust(1, "c")).unwrap_err(),
            CommandError::QueueFull { capacity: 2 }
        );
        assert_eq!(sink.pending(), 2);

        // Free a slot, and the very same token is accepted: it was never consumed.
        sink.report_renderer(a, RendererReport::StateApplied)
            .unwrap();
        sink.retire(a).unwrap();
        assert!(sink.submit(adjust(1, "c")).is_ok());
        assert_eq!(sink.pending(), 2);
    }

    #[test]
    fn a_duplicate_is_reported_as_a_duplicate_even_when_the_queue_is_full() {
        let mut sink = EphemeralCommandSink::new(epoch(5), 1);
        sink.submit(adjust(1, "a")).unwrap();
        assert!(matches!(
            sink.submit(adjust(1, "a")).unwrap_err(),
            CommandError::DuplicateCommand { .. }
        ));
    }

    #[test]
    fn commands_from_another_epoch_are_refused_and_change_nothing() {
        let mut sink = EphemeralCommandSink::new(epoch(5), 4);
        let at = |n: u64| CommandEnvelope::new(sid(1), epoch(n), CommandKind::Play, None).unwrap();
        assert_eq!(
            sink.submit(at(4)).unwrap_err(),
            CommandError::StaleEpoch {
                command: 4,
                current: 5
            }
        );
        assert_eq!(
            sink.submit(at(6)).unwrap_err(),
            CommandError::EpochAhead {
                command: 6,
                current: 5
            }
        );
        assert_eq!(sink.pending(), 0);
        assert!(sink.submit(at(5)).is_ok());
    }

    #[test]
    fn errors_name_labels_and_tokens_only() {
        let text = CommandError::MissingIdempotencyToken { kind: "skip" }.to_string();
        assert_eq!(
            text,
            "`skip` is not safe to repeat, so it needs an idempotency token"
        );
        let dup = CommandError::DuplicateCommand { token: token("t1") }.to_string();
        assert_eq!(dup, "duplicate command: token `t1` was already accepted");
    }
}
