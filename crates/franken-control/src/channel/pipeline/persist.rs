//! The revision high-water mark on the settings journal (N02 / `ffw-ugf`, over U01 / `ffw-mgb`).
//!
//! The `restart` module gave the channel a way to take a stored mark: after a full process restart
//! the first `step` raises the revision floor to it, so a copy composed against the old history is refused
//! as `StaleRevision`. It left the storing to the owner, in the right order, without help. This module is
//! that storing, over [`franken_journal`]'s monotone `Marks` namespace, and the order is in code.
//!
//! # The calls
//!
//! * [`restore_from_open`], at boot, before the first `step`: reads the mark from the result of
//!   `Journal::open` and hands it to the channel.
//! * [`restore_seq_floors_from_open`], at boot, likewise: reads the relative-command floors
//!   ([`seqfloor`](crate::channel::seqfloor)) and hands them to the channel.
//! * [`step_then_store`], instead of `step`: see below. **The mark is durable before any outcome that raised it is
//!   delivered, and nothing the step did is visible until it is.** If the store fails, the outcomes come back inside
//!   [`StoreFailed`], withheld, with the journal's error, and the durable path is **latched failed**.
//! * [`reopen_from_open`], after the owner has dropped a failed journal and opened the medium again: the only way out
//!   of the latch.
//! * [`store_high_water`], the store alone, for an owner that has its own loop.
//! * [`Stepper`], for a caller that must not care which of the above it was given: [`Durable`] steps through
//!   [`step_then_store`]; [`DevelopmentVolatile`] is the plain step, named so that nobody gets it by omission.
//!
//! # The boundary `step_then_store` draws
//!
//! A step has things anyone can see: the **session** the commands were applied to, the **ledger** entry that answers
//! a retry, the **outcomes** returned to the owner, the **counters**, and the **log**. Storing the mark *after* a plain
//! `step` leaves all of them visible before the mark is durable. So the step is a transaction.
//!
//! * **Stage.** The step runs on a *copy* of the session. Only when the mark is durable is the copy put in the
//!   caller's session. If the store fails the caller's session is untouched, so the effect, and the revision it
//!   would have revealed, never appeared.
//! * **Keep an undo.** While the step is open the ledger remembers what it recorded and what it evicted to make room
//!   (`OutcomeLedger::begin`). On failure all of it is taken back: the step's outcomes are `Unseen` again, and the
//!   older outcomes it pushed out answer as before, with the floors it raised undone. The counters are restored and
//!   the log facts the step gathered are dropped, so nothing says "committed" about an effect that never happened;
//!   one critical record says a store failed. On success the facts are written.
//! * **Clone only when there is work.** An idle poll stages nothing, copies nothing and touches no journal. A step
//!   that cannot have moved the mark (every command refused, the session's revision unchanged) does not call the
//!   journal for it either, so a poisoned journal does not turn a pure refusal into a failure.
//!
//! A relative command of an identity with a stable retry number is protected by one more thing, written **before**
//! its effect rather than after: its identity's floor, in the record `n02.seq` ([`SEQ_FLOORS_KEY`]), made durable by
//! [`ControlChannel::step_reserving`] through this module's journal store. A crash at any point after that write
//! leaves the command at or below a durable floor, so its retry is `OutOfWindow` (unknown), never a second
//! application; a crash before it leaves nothing applied. If the write cannot be made, the command is not applied
//! (`Refused(InternalFault)`, cause `store_<code>`, recorded: send it under a new number). An identity declared with
//! [`ControlChannel::declare_unstable_retry_ids`] (the legacy SOAP bridge, which composes a fresh number for every
//! request) is given no floor: no write, and no claim to deduplicate.
//!
//! # The latch
//!
//! The first store that fails leaves the medium in a state the channel cannot know: a storage fault poisons the
//! journal until it is reopened, and an error reported after the write took leaves the journal ahead of the rolled
//! back session. [`step_then_store`] therefore latches [`Durability::Failed`] and from then on does no staging and
//! calls no journal (no copy, no write, no repeated failure). While latched:
//!
//! * the **local user's stop and mute-on** are applied to the live session (silence is never withdrawn for want of a
//!   disk), and a cancel still withdraws;
//! * **every other command is refused** (`Refusal::InternalFault`, cause `durability_failed`) without being
//!   recorded, so no command that raises volume, relative or absolute, gets through, and the same request can be sent
//!   again after the reopen. The legacy bridge is a controller; its stop is refused like any other controller's.
//!
//! The mark is not stored while latched. After a [`reopen_from_open`] the channel offers at least the mark the
//! journal holds (so a mark that is ahead of the session does not make every later store a `MarkRegressed`), and its
//! floors are the larger of what it knew and what the medium holds.
//!
//! # Why the order matters, and what recovery gives
//!
//! A client composes a command at a revision it was *told*. If the mark is durable before it is told, every
//! revision any client holds is at or below the mark, and after a restart a duplicate of a command that
//! was applied and acknowledged names a revision below the floor and is refused. U01 recovers exactly the
//! old or exactly the new state of a commit cut short by a power failure, never a mixture. So a cut
//! during the store leaves either the old mark (the step's outcomes were never delivered, so nobody holds
//! a revision above it) or the new one.
//!
//! # What a journal that cannot be read does
//!
//! It does not start the channel from revision 0, which would admit every copy composed against the old
//! history. [`restore_from_open`] sets the floor to [`REFUSING_FLOOR`], the largest number: for this run
//! every remote command that names a revision is refused as `StaleRevision { observed, floor: u64::MAX }`.
//! The local user is exempt from revision checks and keeps the group controllable at the device. That also
//! refuses a *fresh* remote command: with the mark gone the channel cannot tell a stale copy from a fresh
//! one, and it says so rather than guess. The floor is never stored (see [`store_high_water`]), so it
//! lasts for the run, not for ever.
//!
//! # What this does not do
//!
//! * **Restore the session.** A session rebuilt at a revision below the mark leaves remote controllers
//!   refused until it catches up. Rebuilding it at or above the mark, with its history continued, is G01's.
//! * **Survive a lost mark for good.** After an unrecoverable journal the next boot finds an empty,
//!   intact one and starts from the session's revision. A lost mark is a lost history; closing that for
//!   good takes a new epoch or a new pairing (the credentials are in the same journal and are gone too).
//! * **Detect a medium put back to an older image.** U01 puts physical rollback out of scope, and so does this.
//! * **Admit the wear.** One journal frame is written per step that moved the mark, and one more per relative command
//!   of a stable identity (42 bytes for one identity with a floor, 252 for sixteen). Whether that is safe for the
//!   flash part is **not** established; nothing here claims a hardware-safe write rate, and the per-peer rate limits
//!   are what bound it. A stride (storing ahead by a block of revisions or numbers) would cut it and would lengthen
//!   the refusal after a restart; it is not taken.
//! * **Make the legacy bridge idempotent.** A plain SOAP retry of a relative change composes a new number and applies
//!   twice; that is pinned, and the authenticated tailnet route is the deduplicated one.
//!
//! The tests run on U01's in-memory medium with fault injection. That is not a flash part, and nothing
//! here has run on a device.

use franken_journal::codec::ERASED;
use franken_journal::{
    Commit, Journal, JournalError, Limits, Namespace, Recovery, Source, Storage, StorageFault,
};
use franken_session::UnifiedGroupSession;

use super::{ControlChannel, Durability, FloorNotStored, FloorStore, HighWaterError, Settlement};
use crate::channel::peer::PeerAuthority;
use crate::channel::seqfloor::{DecodeError, SeqFloors};

/// The key of the mark in the journal's `Marks` namespace: six bytes, so it fits the smallest configuration
/// (`Limits::tiny()` allows eight) as well as the device one (sixteen).
pub const HIGH_WATER_KEY: &[u8] = b"n02.hw";

/// The key of the relative-command floors in the journal's `Records` namespace: seven bytes, so it fits the
/// smallest configuration (`Limits::tiny()` allows eight) as well as the device one (thirty-two). It is **one of the
/// device journal's four record slots**; U02 holds three (`u02.inst`, `u02.upd`, `u02.fail`).
pub const SEQ_FLOORS_KEY: &[u8] = b"n02.seq";

/// The floor the channel is given when the mark cannot be read: no revision a command can name is at or
/// above it, so every remote command that names one is refused.
pub const REFUSING_FLOOR: u64 = u64::MAX;

/// Why the mark could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// Neither segment of a medium that is not blank holds a valid state. The journal was formatted empty,
    /// and the mark, if there was one, is gone.
    Unrecoverable,
    /// Opening the journal failed. The stable code of its error.
    OpenFailed(&'static str),
}

/// What [`restore_from_open`] found, and what it told the channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restored {
    /// The journal held a mark. The channel's floor is at least this.
    Mark(u64),
    /// The medium was blank: the first boot of this device. Nothing was ever stored, and the channel starts
    /// from the session's revision.
    FreshMedium,
    /// The journal is intact and holds no mark. An owner that stores through [`step_then_store`] stores the
    /// mark before delivering the first outcome, so none was ever delivered; the channel starts from the
    /// session's revision.
    NeverStored,
    /// The mark could not be read. The channel's floor is [`REFUSING_FLOOR`]. The owner should raise an alarm.
    Refusing(Cause),
}

/// The mark could not be stored, so the outcomes of the step that reached it were kept back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreFailed {
    /// What the journal said.
    pub cause: JournalError,
    /// What the step settled. None was delivered, because the mark that covers it is not durable, and none is in the
    /// channel's ledger any more (the step was rolled back), so a client that asks again is **not** answered with it.
    /// The caller's session is as it was before the step: the step ran on a copy that was dropped. The channel's
    /// [`Durability`] is now `Failed`.
    pub withheld: Vec<Settlement>,
    /// The local user's stop and mute-on that the step applied and that were then applied again to the live session,
    /// because silence is never withdrawn for want of a disk ([`ControlChannel`], `apply_silencing_live`). These took
    /// effect, so unlike `withheld` they are to be delivered; their mark is not stored. Empty unless the step held one.
    pub applied: Vec<Settlement>,
}

/// Why the relative-command floors could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorCause {
    /// Neither segment of a medium that is not blank holds a valid state; the journal was formatted empty.
    Unrecoverable,
    /// Opening the journal failed. The stable code of its error.
    OpenFailed(&'static str),
    /// The record is there but is not exactly what [`SeqFloors::encode`] writes.
    Malformed(DecodeError),
}

/// What [`restore_seq_floors_from_open`] found, and what it told the channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoredFloors {
    /// The record was read: `identities` floors were handed to the channel.
    Table { identities: usize },
    /// A blank medium, or an intact journal without the record: no relative command was ever begun. Nothing to hand over.
    Nothing,
    /// The floors could not be read. Every relative command is answered `OutOfWindow` for this run; absolute and
    /// stop commands keep working. The owner should raise an alarm.
    Refusing(FloorCause),
}

/// Hand the channel the relative-command floors found by `Journal::open`, before its first `step`.
///
/// # Errors
/// [`HighWaterError::AlreadyRunning`] if the channel has already stepped.
pub fn restore_seq_floors_from_open<A: PeerAuthority, S: Storage>(
    channel: &mut ControlChannel<A>,
    opened: &Result<(Journal<S>, Recovery), JournalError>,
) -> Result<RestoredFloors, HighWaterError> {
    let (restored, table) = match opened {
        Err(error) => (
            RestoredFloors::Refusing(FloorCause::OpenFailed(error.code())),
            SeqFloors::refusing(),
        ),
        Ok((_, recovery)) if recovery.source == Source::Unrecoverable => (
            RestoredFloors::Refusing(FloorCause::Unrecoverable),
            SeqFloors::refusing(),
        ),
        Ok((journal, _)) => match journal.state().records.get(SEQ_FLOORS_KEY) {
            None => (RestoredFloors::Nothing, SeqFloors::new()),
            Some(bytes) => match SeqFloors::decode(bytes) {
                Ok(table) => (
                    RestoredFloors::Table {
                        identities: table.len(),
                    },
                    table,
                ),
                Err(error) => (
                    RestoredFloors::Refusing(FloorCause::Malformed(error)),
                    SeqFloors::refusing(),
                ),
            },
        },
    };
    channel.restore_seq_floors(table)?;
    Ok(restored)
}

/// The journal as a [`FloorStore`]: one `Put` of the packed record in the `Records` namespace, one frame. It keeps the
/// first error the journal gave, so the step can tell a medium fault (the journal is poisoned) from a refusal that
/// wrote nothing.
struct JournalFloors<'a, S: Storage> {
    journal: &'a mut Journal<S>,
    failure: Option<JournalError>,
}

impl<S: Storage> FloorStore for JournalFloors<'_, S> {
    fn store(&mut self, packed: &[u8]) -> Result<(), FloorNotStored> {
        match self.journal.put(Namespace::Records, SEQ_FLOORS_KEY, packed) {
            Ok(_) => Ok(()),
            Err(error) => {
                let code = error.code();
                if self.failure.is_none() {
                    self.failure = Some(error);
                }
                Err(FloorNotStored { code })
            }
        }
    }
}

/// Hand the channel the mark found by `Journal::open`, before its first `step`.
///
/// A mark is restored as it is. A blank medium, or an intact journal that holds no mark, restores nothing.
/// A journal that failed to open, or was formatted empty because neither segment was valid, gives the
/// channel the floor [`REFUSING_FLOOR`].
///
/// # Errors
/// [`HighWaterError::AlreadyRunning`] if the channel has already stepped: the floor is set at the first
/// `step`, and a mark offered after it would change nothing.
pub fn restore_from_open<A: PeerAuthority, S: Storage>(
    channel: &mut ControlChannel<A>,
    opened: &Result<(Journal<S>, Recovery), JournalError>,
) -> Result<Restored, HighWaterError> {
    let restored = match opened {
        Err(error) => Restored::Refusing(Cause::OpenFailed(error.code())),
        Ok((_, recovery)) if recovery.source == Source::Unrecoverable => {
            Restored::Refusing(Cause::Unrecoverable)
        }
        Ok((journal, recovery)) => match journal.state().marks.get(HIGH_WATER_KEY) {
            Some(&mark) => Restored::Mark(mark),
            None if recovery.source == Source::Blank => Restored::FreshMedium,
            None => Restored::NeverStored,
        },
    };
    match restored {
        Restored::Mark(mark) => channel.restore_high_water(mark)?,
        Restored::Refusing(_) => channel.restore_high_water(REFUSING_FLOOR)?,
        Restored::FreshMedium | Restored::NeverStored => {}
    }
    Ok(restored)
}

/// Store the mark the channel has reached: the session's revision, or the restored mark if that is higher.
///
/// The journal refuses a mark below the stored one and writes nothing for an equal one ([`Commit::Noop`]),
/// so a stored mark never goes down. [`REFUSING_FLOOR`] is never stored: it says the mark could not be read,
/// not that the session reached the largest revision, and storing it would refuse remote commands on every
/// later boot.
///
/// # Errors
/// The journal's: a storage fault (the journal is then poisoned until reopened), a full `Marks` namespace,
/// or [`JournalError::MarkRegressed`] if the journal already holds a higher mark than the channel was given,
/// which is what an owner that did not restore gets.
pub fn store_high_water<A: PeerAuthority, S: Storage>(
    channel: &ControlChannel<A>,
    session: &UnifiedGroupSession,
    journal: &mut Journal<S>,
) -> Result<Commit, JournalError> {
    let mark = channel.high_water(session);
    if mark == REFUSING_FLOOR {
        return Ok(Commit::Noop);
    }
    // Nothing moved the mark: there is nothing to store, and a journal that is poisoned has nothing to say about it.
    // (A stored mark that is *higher* still goes to the journal, which refuses it as `MarkRegressed`.)
    if journal.state().marks.get(HIGH_WATER_KEY) == Some(&mark) {
        return Ok(Commit::Noop);
    }
    journal.raise_mark(HIGH_WATER_KEY, mark)
}

/// `step`, then store the mark, then return the outcomes: none is delivered, and nothing the step did is visible in
/// `session`, the ledger, the counters or the log, before the mark that covers it is durable.
///
/// The step is a transaction ([the module documentation](self) draws the boundary). With work waiting and the durable
/// path healthy it runs on a copy of `session`, each **relative** command of a stable identity first making its floor
/// durable (the record `n02.seq`) and not being applied if it cannot, then stores the mark from the copy if the
/// copy moved it. Only if that succeeds is the copy put in `session`, the ledger's undo dropped and the log written.
///
/// With nothing waiting it copies nothing and writes nothing. With the durable path latched failed it stages nothing
/// and calls no journal: the local user's stop and mute-on apply to the live session and everything else is refused
/// without being recorded.
///
/// # Errors
/// [`StoreFailed`], holding the journal's error and the outcomes the step settled. The step has been rolled back (ledger,
/// counters, log) and the channel's [`Durability`] is `Failed`. `session` is as it was, **except** that the local user's
/// stop and mute-on the step held have been applied to it (`StoreFailed::applied`): silence is not withdrawn for want of
/// a disk.
pub fn step_then_store<A: PeerAuthority, S: Storage>(
    channel: &mut ControlChannel<A>,
    now_ns: u64,
    session: &mut UnifiedGroupSession,
    journal: &mut Journal<S>,
) -> Result<Vec<Settlement>, StoreFailed> {
    // Latched: the channel steps itself in its degraded mode; idle: there is nothing to stage. Either way, no copy
    // and no journal call.
    if channel.durability() != Durability::Healthy || !channel.has_work() {
        return Ok(channel.step(now_ns, session));
    }
    let before = channel.begin_step(now_ns, session);
    let mut staged = session.clone();
    let mut floors = JournalFloors {
        journal: &mut *journal,
        failure: None,
    };
    let settled = channel.step_reserving(now_ns, &mut staged, &mut floors);
    let floor_failure = floors.failure;
    // A floor write that failed for a reason on the medium poisoned the journal: nothing the step did can be stored.
    // A floor refused before anything was written (a record too long) did not, and the step goes on to the mark. A
    // journal that was already poisoned fails the mark only if the step moved it: a pure refusal stores nothing.
    let failure = match floor_failure {
        Some(error) if journal.is_poisoned() => Some(error),
        _ => store_high_water(channel, &staged, journal).err(),
    };
    match failure {
        None => {
            *session = staged;
            channel.commit_step(now_ns, session);
            Ok(settled)
        }
        Some(cause) => {
            let code = cause.code();
            channel.rollback_step(before, now_ns, session, &settled, code);
            channel.latch_durability(code);
            // The explicit exception: what only silences is not lost with the step.
            let applied = channel.apply_silencing_live(now_ns, session);
            let withheld = settled
                .into_iter()
                .filter(|s| !applied.iter().any(|a| a.peer == s.peer && a.seq == s.seq))
                .collect();
            Err(StoreFailed {
                cause,
                withheld,
                applied,
            })
        }
    }
}

/// What [`reopen_from_open`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reopened {
    /// The journal was read and the latch is cleared. `mark` is what it holds (the channel will offer at least that),
    /// and `identities` is how many floors it holds; the channel's own floors are the larger of the two tables.
    Healthy {
        mark: Option<u64>,
        identities: usize,
    },
    /// The medium could not be opened or holds no valid state. The latch stays.
    StillFailed(Cause),
}

/// Take the channel out of the failed state after the owner has dropped the failed journal and opened the medium
/// again. This is the only way out of the latch, and it is the owner's decision: the channel does not retry on its
/// own.
///
/// What the medium holds may be the state before the failed step or after it (U01 recovers exactly one of the two).
/// The channel keeps the larger of its own mark and the journal's, so it never offers a mark below the stored one, and
/// the larger of each identity's floor, so a floor the medium took is not forgotten. A floor record that does not
/// decode makes every relative command refuse for the run, as at boot. The session is not touched and the revision
/// floor stays as it was: the rolled-back step revealed nothing to any client.
pub fn reopen_from_open<A: PeerAuthority, S: Storage>(
    channel: &mut ControlChannel<A>,
    opened: &Result<(Journal<S>, Recovery), JournalError>,
) -> Reopened {
    let journal = match opened {
        Err(error) => return Reopened::StillFailed(Cause::OpenFailed(error.code())),
        Ok((_, recovery)) if recovery.source == Source::Unrecoverable => {
            return Reopened::StillFailed(Cause::Unrecoverable);
        }
        Ok((journal, _)) => journal,
    };
    let mark = journal.state().marks.get(HIGH_WATER_KEY).copied();
    let table = match journal.state().records.get(SEQ_FLOORS_KEY) {
        None => SeqFloors::new(),
        Some(bytes) => SeqFloors::decode(bytes).unwrap_or_else(|_| SeqFloors::refusing()),
    };
    channel.reopen_durable(mark, &table);
    Reopened::Healthy {
        mark,
        identities: table.len(),
    }
}

/// How a caller steps the channel without deciding, per call, whether the step is durable. The caller (the fsonos
/// server, the Q01 harness) is handed one of the implementations below by its owner; it never builds one.
pub trait Stepper<A: PeerAuthority> {
    /// Apply what the channel has accepted. `Err` means the step was rolled back and its outcomes were not delivered.
    ///
    /// # Errors
    /// [`StoreFailed`], from a durable stepper whose store failed.
    fn step(
        &mut self,
        channel: &mut ControlChannel<A>,
        now_ns: u64,
        session: &mut UnifiedGroupSession,
    ) -> Result<Vec<Settlement>, StoreFailed>;
}

/// The plain step, named. It stores nothing: a relative command takes effect with no durable record that it did, and
/// a restart forgets everything. It is for the Q01 campaign harness and for tests; a production owner holds a
/// [`Durable`]. A source scan in the fsonos tests keeps this name out of every production file but the harness.
pub struct DevelopmentVolatile;

impl<A: PeerAuthority> Stepper<A> for DevelopmentVolatile {
    fn step(
        &mut self,
        channel: &mut ControlChannel<A>,
        now_ns: u64,
        session: &mut UnifiedGroupSession,
    ) -> Result<Vec<Settlement>, StoreFailed> {
        Ok(channel.step(now_ns, session))
    }
}

/// Steps through [`step_then_store`] over a journal the owner opened.
pub struct Durable<'j, S: Storage> {
    journal: &'j mut Journal<S>,
}

impl<'j, S: Storage> Durable<'j, S> {
    #[must_use]
    pub fn new(journal: &'j mut Journal<S>) -> Self {
        Self { journal }
    }
}

impl<A: PeerAuthority, S: Storage> Stepper<A> for Durable<'_, S> {
    fn step(
        &mut self,
        channel: &mut ControlChannel<A>,
        now_ns: u64,
        session: &mut UnifiedGroupSession,
    ) -> Result<Vec<Settlement>, StoreFailed> {
        step_then_store(channel, now_ns, session, self.journal)
    }
}

/// The stepper of a channel whose durable path never opened ([`Booted::Latched`](super::Booted)): it stores nothing and steps the
/// channel in its latched mode, so the local user's stop and mute-on work and everything else is refused (`durability_failed`).
/// It cannot be mistaken for a volatile stepper: given a channel that is not latched it latches it first, so it never applies a
/// step as if it were durable.
pub struct LatchedStepper;

impl<A: PeerAuthority> Stepper<A> for LatchedStepper {
    fn step(
        &mut self,
        channel: &mut ControlChannel<A>,
        now_ns: u64,
        session: &mut UnifiedGroupSession,
    ) -> Result<Vec<Settlement>, StoreFailed> {
        if channel.durability() == Durability::Healthy {
            channel.latch_durability("unbacked");
        }
        Ok(channel.step(now_ns, session))
    }
}

/// [`Durable`], owning its journal: what [`boot_durable`](super::boot_durable) returns, for an owner that keeps the stepper
/// beside the channel. [`OwnedDurable::into_journal`] gives the journal back, for a reopen
/// ([`reopen_from_open`]) or a restart over the same medium.
pub struct OwnedDurable<S: Storage> {
    journal: Journal<S>,
}

impl<S: Storage> OwnedDurable<S> {
    #[must_use]
    pub fn new(journal: Journal<S>) -> Self {
        Self { journal }
    }

    #[must_use]
    pub fn journal(&self) -> &Journal<S> {
        &self.journal
    }

    #[must_use]
    pub fn into_journal(self) -> Journal<S> {
        self.journal
    }
}

impl<A: PeerAuthority, S: Storage> Stepper<A> for OwnedDurable<S> {
    fn step(
        &mut self,
        channel: &mut ControlChannel<A>,
        now_ns: u64,
        session: &mut UnifiedGroupSession,
    ) -> Result<Vec<Settlement>, StoreFailed> {
        step_then_store(channel, now_ns, session, &mut self.journal)
    }
}

/// Flash semantics in RAM and nothing else: two segments, programming only clears bits, erase sets them, `sync` is
/// immediate. No fault injection and no per-operation record, so a measurement over it sees the journal's own work and
/// not an instrument's growth. **Nothing survives the process**: it is the storage of a prototype or a measurement, not of a
/// device (no file-backed or flash-backed [`Storage`] exists in this tree yet).
#[derive(Clone)]
pub struct RamMedium {
    segment: usize,
    bytes: Vec<u8>,
}

impl RamMedium {
    /// A blank medium: two erased segments of `segment_bytes`.
    #[must_use]
    pub fn new(segment_bytes: usize) -> Self {
        Self {
            segment: segment_bytes,
            bytes: vec![ERASED; 2 * segment_bytes],
        }
    }
}

impl Storage for RamMedium {
    fn segment_bytes(&self) -> usize {
        self.segment
    }

    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), StorageFault> {
        let end = offset
            .checked_add(out.len())
            .ok_or(StorageFault::OutOfRange)?;
        let from = self
            .bytes
            .get(offset..end)
            .ok_or(StorageFault::OutOfRange)?;
        out.copy_from_slice(from);
        Ok(())
    }

    fn program(&mut self, offset: usize, data: &[u8]) -> Result<(), StorageFault> {
        let end = offset
            .checked_add(data.len())
            .ok_or(StorageFault::OutOfRange)?;
        let to = self
            .bytes
            .get_mut(offset..end)
            .ok_or(StorageFault::OutOfRange)?;
        if to.iter().zip(data).any(|(have, want)| *want & !*have != 0) {
            return Err(StorageFault::BitsCannotRise);
        }
        for (have, want) in to.iter_mut().zip(data) {
            *have &= *want;
        }
        Ok(())
    }

    fn erase(&mut self, segment: usize) -> Result<(), StorageFault> {
        if segment > 1 {
            return Err(StorageFault::OutOfRange);
        }
        let base = segment * self.segment;
        let span = self
            .bytes
            .get_mut(base..base + self.segment)
            .ok_or(StorageFault::OutOfRange)?;
        span.fill(ERASED);
        Ok(())
    }

    fn sync(&mut self) -> Result<(), StorageFault> {
        Ok(())
    }
}

/// The product's durable step ([`step_then_store`]) over a journal on a medium in RAM: the same staging, the same
/// commits, the same compaction, and nothing survives the process. For measurements and tests that must run the
/// product's path without a device (the heap test runs its flood through this). It is **not** durable: a production
/// owner opens a journal on its medium and holds a [`Durable`]. A source scan keeps this name, like the volatile
/// development step, out of every production file but the harness.
pub struct MemoryJournalStepper {
    journal: Journal<RamMedium>,
}

impl MemoryJournalStepper {
    /// A fresh journal with the device's limits on a blank RAM medium.
    ///
    /// # Panics
    /// If the device limits cannot open a blank medium, which would be a defect in the limits and not a runtime event.
    #[must_use]
    pub fn new() -> Self {
        let limits = Limits::standard();
        let medium = RamMedium::new(limits.segment_bytes);
        let journal = match Journal::open(medium, limits) {
            Ok((journal, _recovery)) => journal,
            Err(error) => panic!("the device limits do not open a blank RAM medium: {error}"),
        };
        Self { journal }
    }

    /// [`MemoryJournalStepper::new`], with every namespace of the journal loaded to the device limits: every entry slot
    /// full and every value at its length cap, but for the two slots N02 itself uses (the revision mark, and the fourth
    /// record, the floors). It is the largest snapshot the device limits let the journal write, so a compaction over it
    /// is the most the journal can hold at once: what a measurement of a durable step must be taken over, since a blank
    /// journal compacts a few bytes.
    ///
    /// # Panics
    /// If the journal refuses its own limits while loading, which would be a defect in the limits.
    #[must_use]
    pub fn at_device_limits_occupancy() -> Self {
        let mut stepper = Self::new();
        let limits = Limits::standard();
        let journal = &mut stepper.journal;
        let key = |prefix: u8, index: usize, len: usize| -> Vec<u8> {
            let mut key = vec![b'x'; len];
            if let Some(slot) = key.first_mut() {
                *slot = prefix;
            }
            if let Some(slot) = key.get_mut(1) {
                *slot = b'a' + u8::try_from(index).unwrap_or(0);
            }
            key
        };
        for (namespace, caps, slots) in [
            (
                Namespace::Settings,
                limits.settings,
                limits.settings.entries,
            ),
            (
                Namespace::Calibration,
                limits.calibration,
                limits.calibration.entries,
            ),
            // The fourth record is N02's own.
            (
                Namespace::Records,
                limits.records,
                limits.records.entries - 1,
            ),
        ] {
            for index in 0..slots {
                let loaded = journal.put(
                    namespace,
                    &key(b'#', index, caps.key_max),
                    &vec![0xA5; caps.value_max],
                );
                if let Err(error) = loaded {
                    panic!("loading the worst-case occupancy failed: {error}");
                }
            }
        }
        for index in 0..limits.credentials.entries {
            let loaded = journal.install(
                &key(b'c', index, limits.credentials.key_max),
                1,
                &vec![0x5A; limits.credentials.value_max],
            );
            if let Err(error) = loaded {
                panic!("loading the worst-case occupancy failed: {error}");
            }
        }
        // The revision mark is N02's own slot among the marks.
        for index in 0..limits.marks.entries - 1 {
            let loaded = journal.raise_mark(&key(b'm', index, limits.marks.key_max), 1);
            if let Err(error) = loaded {
                panic!("loading the worst-case occupancy failed: {error}");
            }
        }
        stepper
    }

    /// The floors record as the journal holds it, if it holds one.
    #[must_use]
    pub fn stored_floors(&self) -> Option<&[u8]> {
        self.journal
            .state()
            .records
            .get(SEQ_FLOORS_KEY)
            .map(Vec::as_slice)
    }

    /// The revision mark as the journal holds it, if it holds one.
    #[must_use]
    pub fn stored_mark(&self) -> Option<u64> {
        self.journal.state().marks.get(HIGH_WATER_KEY).copied()
    }

    /// How many compactions the journal has made.
    #[must_use]
    pub fn compactions(&self) -> u64 {
        self.journal.compactions()
    }

    /// How many frames the journal has written.
    #[must_use]
    pub fn frames_written(&self) -> u64 {
        self.journal.frames_written()
    }

    /// What a restart over this medium would open: a copy of the medium, opened. Hand it to the restore calls.
    ///
    /// # Errors
    /// The journal's, if the medium holds no state the journal can open.
    pub fn reopen(&self) -> Result<(Journal<RamMedium>, Recovery), JournalError> {
        Journal::open(self.journal.storage().clone(), Limits::standard())
    }
}

impl Default for MemoryJournalStepper {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: PeerAuthority> Stepper<A> for MemoryJournalStepper {
    fn step(
        &mut self,
        channel: &mut ControlChannel<A>,
        now_ns: u64,
        session: &mut UnifiedGroupSession,
    ) -> Result<Vec<Settlement>, StoreFailed> {
        step_then_store(channel, now_ns, session, &mut self.journal)
    }
}

#[cfg(test)]
mod tests {
    use franken_journal::codec::SEG_HEADER;
    use franken_journal::{Limits, MemStorage};
    use franken_session::AuthorityToken;

    use super::*;
    use crate::channel::diag::{ChannelLog, LogConfig, LogKey};
    use crate::channel::limiter::RateLimit;
    use crate::channel::peer::ephemeral::{EphemeralPeers, test_key};
    use crate::channel::peer::{AuthFailure, PeerId, PeerRole, compute_proof};
    use crate::channel::pipeline::{ChannelConfig, Outcome, Refusal, Rejection, SubmitResult};
    use crate::channel::request::{ControlCommand, ControlRequest, RequestBody};
    use crate::channel::seqfloor::{ENTRY_LEN, HEADER_LEN, MAX_ENCODED_LEN};
    use crate::channel::testkit::fixture_session;

    const EPOCH: u64 = 10;
    const MS: u64 = 1_000_000;

    fn id(raw: &str) -> PeerId {
        PeerId::parse(raw).unwrap()
    }

    fn set_group(volume: u8) -> ControlCommand {
        ControlCommand::SetGroupVolume { volume }
    }

    fn mute(on: bool) -> ControlCommand {
        ControlCommand::SetMemberMute {
            member_id: "kitchen".to_string(),
            muted: on,
        }
    }

    fn adjust(delta: i8) -> ControlCommand {
        ControlCommand::AdjustGroupVolume { delta }
    }

    fn stop() -> ControlCommand {
        ControlCommand::StopGroupPlayback {
            now_ns: 1_000,
            irrevocable_dma_tail_ns: 500,
        }
    }

    fn committed(outcome: &Outcome) -> bool {
        matches!(outcome, Outcome::Committed { .. })
    }

    fn limits() -> Limits {
        Limits::standard()
    }

    fn blank_medium() -> MemStorage {
        MemStorage::new(limits().segment_bytes)
    }

    /// How an owner of the channel and the journal behaves. `Faithful` restores the mark and steps through
    /// `step_then_store`; each other variant is a fault an owner could have.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Owner {
        Faithful,
        /// Opens the journal and never hands the mark to the channel; steps without storing.
        NeverRestores,
        /// Never hands the mark to the channel, but steps through `step_then_store`.
        Unrestored,
        /// Restores the mark and steps without storing anything.
        NeverStores,
        /// Restores, steps, delivers the outcomes, and only then tries to store.
        DeliversBeforeStoring,
        /// Treats a journal that failed to open, or was formatted empty, as "no mark".
        IgnoresAFailedOpen,
        /// Stages the step and stores the mark like `step_then_store`, but when the store fails it never rolls the
        /// step back, so the withheld outcomes stay in the ledger.
        KeepsWithheldOutcomes,
        /// Reserves floors, stores the mark and rolls the step back on failure like `step_then_store`, but steps the
        /// live session itself instead of a copy: a failed store leaves the effect (and its revision) visible.
        UnstagedStep,
    }

    /// What one owner turn delivered to the clients.
    struct Delivered {
        delivered: Vec<Settlement>,
        store_failed: bool,
    }

    /// One incarnation of the process: a session rebuilt at revision 2, a channel with an empty ledger, and
    /// the journal opened on the medium (none if it could not be opened).
    struct Incarnation<'m> {
        channel: ControlChannel<EphemeralPeers>,
        session: UnifiedGroupSession,
        journal: Option<Journal<&'m mut MemStorage>>,
        owner: Owner,
        restored: Option<Restored>,
        /// What the relative-command floors were restored as (owners that restore the mark restore these too).
        floors: Option<RestoredFloors>,
    }

    impl<'m> Incarnation<'m> {
        fn boot(medium: &'m mut MemStorage, owner: Owner) -> Self {
            Self::boot_over(medium, owner, fixture_session(EPOCH))
        }

        /// A channel restart over a session that kept running: the new channel has an empty ledger, and `session`
        /// is whatever the old process left (the effect of every command it applied is still in it).
        fn boot_over(
            medium: &'m mut MemStorage,
            owner: Owner,
            session: UnifiedGroupSession,
        ) -> Self {
            let mut peers = EphemeralPeers::new();
            peers
                .admit(
                    &id("ctl-a"),
                    PeerRole::Controller,
                    &test_key("ctl-a"),
                    Some(EPOCH),
                    1,
                )
                .unwrap();
            peers
                .admit(
                    &id("panel"),
                    PeerRole::LocalUser,
                    &test_key("panel"),
                    None,
                    1,
                )
                .unwrap();
            let mut config = ChannelConfig::provisional();
            config.ordinary_rate = RateLimit::new(100_000, MS).unwrap();
            config.priority_rate = RateLimit::new(100_000, MS).unwrap();
            config.session_seq_base = 1_000;
            let mut channel = ControlChannel::new(peers, config).unwrap();
            let token = AuthorityToken::issue(&session, 100_000 * MS);
            channel.install_lease(&session, token, 0).unwrap();

            let opened = Journal::open(medium, limits());
            let restored = match owner {
                Owner::NeverRestores | Owner::Unrestored => None,
                Owner::IgnoresAFailedOpen => match &opened {
                    Ok((_, recovery)) if recovery.source != Source::Unrecoverable => {
                        Some(restore_from_open(&mut channel, &opened).unwrap())
                    }
                    _ => None,
                },
                Owner::Faithful
                | Owner::NeverStores
                | Owner::DeliversBeforeStoring
                | Owner::KeepsWithheldOutcomes
                | Owner::UnstagedStep => Some(restore_from_open(&mut channel, &opened).unwrap()),
            };
            let floors = match owner {
                Owner::Faithful
                | Owner::NeverStores
                | Owner::DeliversBeforeStoring
                | Owner::KeepsWithheldOutcomes
                | Owner::UnstagedStep => {
                    Some(restore_seq_floors_from_open(&mut channel, &opened).unwrap())
                }
                Owner::NeverRestores | Owner::Unrestored | Owner::IgnoresAFailedOpen => None,
            };
            let journal = opened.ok().map(|(journal, _recovery)| journal);
            Self {
                channel,
                session,
                journal,
                owner,
                restored,
                floors,
            }
        }

        /// A request as a client composes it: controllers name `revision`, the local user none.
        fn request_at(
            &self,
            peer: &str,
            seq: u64,
            revision: Option<u64>,
            command: ControlCommand,
        ) -> ControlRequest {
            let body = RequestBody::new(id(peer), seq, EPOCH, revision, command).unwrap();
            let proof = compute_proof(&test_key(peer), &body.signing_bytes());
            ControlRequest::new(body, proof)
        }

        /// A request as a client composes it now: controllers name the session's current revision.
        fn request(&self, peer: &str, seq: u64, command: ControlCommand) -> ControlRequest {
            let revision = (peer != "panel").then_some(self.session.state_revision);
            self.request_at(peer, seq, revision, command)
        }

        /// A relative request as a client composes it: every role, the local user too, names the revision its delta
        /// was computed against (the request format requires it).
        fn relative(&self, peer: &str, seq: u64, delta: i8) -> ControlRequest {
            self.request_at(peer, seq, Some(self.session.state_revision), adjust(delta))
        }

        /// One owner turn: what the owner delivers after stepping, in the order its fault (or its
        /// faithfulness) gives.
        fn turn_step(&mut self) -> Delivered {
            match self.owner {
                Owner::NeverRestores | Owner::NeverStores => Delivered {
                    delivered: self.channel.step(0, &mut self.session),
                    store_failed: false,
                },
                Owner::KeepsWithheldOutcomes => match self.journal.as_mut() {
                    Some(journal) => {
                        let mut staged = self.session.clone();
                        let mut floors = JournalFloors {
                            journal: &mut *journal,
                            failure: None,
                        };
                        let settled = self.channel.step_reserving(0, &mut staged, &mut floors);
                        match store_high_water(&self.channel, &staged, journal) {
                            Ok(_) => {
                                self.session = staged;
                                Delivered {
                                    delivered: settled,
                                    store_failed: false,
                                }
                            }
                            // The fault: the outcomes are kept back, but left in the ledger.
                            Err(_failed) => Delivered {
                                delivered: Vec::new(),
                                store_failed: true,
                            },
                        }
                    }
                    None => Delivered {
                        delivered: self.channel.step(0, &mut self.session),
                        store_failed: false,
                    },
                },
                Owner::UnstagedStep => match self.journal.as_mut() {
                    Some(journal) => {
                        let before = self.channel.begin_step(0, &self.session);
                        let mut floors = JournalFloors {
                            journal: &mut *journal,
                            failure: None,
                        };
                        let settled =
                            self.channel
                                .step_reserving(0, &mut self.session, &mut floors);
                        match store_high_water(&self.channel, &self.session, journal) {
                            Ok(_) => {
                                self.channel.commit_step(0, &self.session);
                                Delivered {
                                    delivered: settled,
                                    store_failed: false,
                                }
                            }
                            // The outcomes are withheld and the step is taken back, but the effect already happened
                            // in the live session.
                            Err(_failed) => {
                                self.channel.rollback_step(
                                    before,
                                    0,
                                    &self.session,
                                    &settled,
                                    "test",
                                );
                                Delivered {
                                    delivered: Vec::new(),
                                    store_failed: true,
                                }
                            }
                        }
                    }
                    None => Delivered {
                        delivered: self.channel.step(0, &mut self.session),
                        store_failed: false,
                    },
                },
                Owner::DeliversBeforeStoring => {
                    let delivered = self.channel.step(0, &mut self.session);
                    let store_failed = match self.journal.as_mut() {
                        Some(journal) => {
                            store_high_water(&self.channel, &self.session, journal).is_err()
                        }
                        None => false,
                    };
                    Delivered {
                        delivered,
                        store_failed,
                    }
                }
                Owner::Faithful | Owner::Unrestored | Owner::IgnoresAFailedOpen => {
                    match self.journal.as_mut() {
                        Some(journal) => {
                            match step_then_store(&mut self.channel, 0, &mut self.session, journal)
                            {
                                Ok(delivered) => Delivered {
                                    delivered,
                                    store_failed: false,
                                },
                                Err(failed) => Delivered {
                                    delivered: failed.applied,
                                    store_failed: true,
                                },
                            }
                        }
                        None => Delivered {
                            delivered: self.channel.step(0, &mut self.session),
                            store_failed: false,
                        },
                    }
                }
            }
        }

        /// Submit and run one turn: how `seq` of `peer` settled, as the owner delivered it.
        fn deliver(
            &mut self,
            request: ControlRequest,
            peer: &str,
            seq: u64,
        ) -> Result<Outcome, String> {
            let queued = self.channel.submit(0, request);
            if !matches!(queued, SubmitResult::Queued { .. }) {
                return Err(format!("setup: submitting ({peer}, {seq}) gave {queued:?}"));
            }
            let turn = self.turn_step();
            if turn.store_failed {
                return Err(format!(
                    "STORE-FAILED: the mark could not be stored, so the outcome of ({peer}, {seq}) was withheld"
                ));
            }
            turn.delivered
                .into_iter()
                .find(|s| s.peer.as_str() == peer && s.seq == seq)
                .map(|s| s.outcome)
                .ok_or_else(|| format!("setup: ({peer}, {seq}) was not settled by that step"))
        }

        fn run(
            &mut self,
            peer: &str,
            seq: u64,
            command: ControlCommand,
        ) -> Result<Outcome, String> {
            let request = self.request(peer, seq, command);
            self.deliver(request, peer, seq)
        }

        fn stored_mark(&self) -> Option<u64> {
            self.journal
                .as_ref()
                .and_then(|j| j.state().marks.get(HIGH_WATER_KEY).copied())
        }

        fn ops_done(&self) -> usize {
            self.journal.as_ref().map_or(0, |j| j.storage().ops_done())
        }

        fn pending_before(&self) -> Vec<usize> {
            self.journal
                .as_ref()
                .map_or_else(Vec::new, |j| j.storage().pending_before().to_vec())
        }

        /// Cut the power when storage operation `n` is about to start, keeping `k` bytes of what is unsynced.
        fn arm_cut(&mut self, n: usize, k: usize) {
            if let Some(journal) = self.journal.as_mut() {
                let storage = journal.storage_mut();
                storage.cut_after_ops = Some(n);
                storage.cut_budget = k;
            }
        }
    }

    /// The first process: five controller commands (revision 2 to 7), the mark stored after each, and one
    /// command composed at revision 4 (the third) that is held back. Returns the held-back copy.
    fn first_life(medium: &mut MemStorage, owner: Owner) -> Result<ControlRequest, String> {
        let mut one = Incarnation::boot(medium, owner);
        let mut held_back = None;
        let (mut after_first, mut last) = (0, 0);
        for seq in 1..=5u64 {
            if seq == 3 {
                held_back = Some(one.request("ctl-a", 100, set_group(99)));
            }
            let volume = 60 + u8::try_from(seq).unwrap();
            if !committed(&one.run("ctl-a", seq, set_group(volume))?) {
                return Err(format!("LOCKED-OUT: command {seq} did not commit"));
            }
            last = one.channel.high_water(&one.session);
            if seq == 1 {
                after_first = last;
            }
        }
        if (after_first, last) != (3, 7) {
            return Err(format!(
                "setup: marks were {after_first} and {last}, not 3 and 7"
            ));
        }
        held_back.ok_or_else(|| "setup: nothing was held back".to_string())
    }

    /// Five local commands bring the rebuilt session to revision 7.
    fn bring_to_seven(two: &mut Incarnation<'_>) -> Result<(), String> {
        for seq in 1..=5u64 {
            if !committed(&two.run("panel", seq, mute(seq % 2 == 1))?) {
                return Err(format!(
                    "LOCKED-OUT: local command {seq} did not commit after the restart"
                ));
            }
        }
        if two.session.state_revision != 7 {
            return Err(format!(
                "setup: the rebuilt session is at revision {}, not 7",
                two.session.state_revision
            ));
        }
        Ok(())
    }

    /// A controller composes a command at revision 4 and it is held back. The first process runs to revision
    /// 7, storing the mark on a real journal after every step, and dies: only the durable bytes of its medium
    /// survive. The second process opens that medium, restores the mark, and is rebuilt at revision 2; the
    /// local user brings the group back to 7. Then a fresh controller command must be admitted (`LOCKED-OUT`
    /// if not) and stored (`NOT-STORED`), and the held-back copy must be refused **exactly** as
    /// `StaleRevision { observed: 4, floor: 7 }` (`ADMITTED` if it was applied, `WRONG-REASON` if it was
    /// refused any other way). Returns what the second process restored.
    fn judge_a_stale_copy_after_a_real_journal_round_trip(
        first: Owner,
        second: Owner,
    ) -> Result<Option<Restored>, String> {
        let mut medium = blank_medium();
        let held_back = first_life(&mut medium, first)?;
        let mut reborn = MemStorage::from_image(limits().segment_bytes, medium.durable());
        let mut two = Incarnation::boot(&mut reborn, second);
        let restored = two.restored;
        bring_to_seven(&mut two)?;

        let fresh = two.run("ctl-a", 101, set_group(70))?;
        if !committed(&fresh) {
            return Err(format!(
                "LOCKED-OUT: a fresh controller command composed against the restored session gave {fresh:?}"
            ));
        }
        if two.session.state_revision != 8 {
            return Err(format!(
                "setup: the fresh command left revision {}, not 8",
                two.session.state_revision
            ));
        }
        if second == Owner::Faithful && two.stored_mark() != Some(8) {
            return Err(format!(
                "NOT-STORED: after the fresh command the journal holds {:?}, not Some(8)",
                two.stored_mark()
            ));
        }

        let copy = two.deliver(held_back, "ctl-a", 100)?;
        if committed(&copy) {
            return Err(format!(
                "ADMITTED: the held-back copy was applied after the restart (group volume {})",
                two.session.group_master_volume
            ));
        }
        let expected = Outcome::Refused(Refusal::StaleRevision {
            observed: 4,
            floor: 7,
        });
        if copy != expected {
            return Err(format!(
                "WRONG-REASON: the held-back copy gave {copy:?}, not {expected:?}"
            ));
        }
        Ok(restored)
    }

    #[test]
    fn a_stale_copy_is_refused_after_a_journal_round_trip_and_a_fresh_command_applies() {
        assert_eq!(
            judge_a_stale_copy_after_a_real_journal_round_trip(Owner::Faithful, Owner::Faithful),
            Ok(Some(Restored::Mark(7)))
        );
    }

    #[test]
    fn each_planted_owner_fault_fails_the_round_trip_judge_by_name() {
        // A judge that fails everything proves nothing, so the faithful round trip passes first.
        assert_eq!(
            judge_a_stale_copy_after_a_real_journal_round_trip(Owner::Faithful, Owner::Faithful),
            Ok(Some(Restored::Mark(7)))
        );
        for (first, second, tag) in [
            // The second process never hands the stored mark to its channel.
            (Owner::Faithful, Owner::NeverRestores, "ADMITTED"),
            // The first process never stored one.
            (Owner::NeverStores, Owner::Faithful, "ADMITTED"),
        ] {
            let verdict = judge_a_stale_copy_after_a_real_journal_round_trip(first, second);
            assert!(
                verdict.as_ref().is_err_and(|e| e.starts_with(tag)),
                "{first:?} then {second:?} was not caught as {tag}: {verdict:?}"
            );
        }
    }

    /// What one cut of the sixth command's store left, as the first process saw it and the medium kept it.
    struct LifeOne {
        /// `(seq, revision composed at)` of every command whose outcome was delivered.
        delivered: Vec<(u64, u64)>,
        /// The storage operations before and after the sixth turn.
        ops: (usize, usize),
        /// The bytes pending before each of those operations (an uncut run only).
        pending: Vec<usize>,
        durable: Vec<u8>,
    }

    /// Five commands, then a sixth (revision 7 to 8) whose store is cut at `cut` (operation, byte budget).
    fn life_one(owner: Owner, cut: Option<(usize, usize)>) -> Result<LifeOne, String> {
        let mut medium = blank_medium();
        let (delivered, ops, pending) = {
            let mut one = Incarnation::boot(&mut medium, owner);
            let mut delivered = Vec::new();
            for seq in 1..=5u64 {
                let observed = one.session.state_revision;
                let volume = 60 + u8::try_from(seq).unwrap();
                if !committed(&one.run("ctl-a", seq, set_group(volume))?) {
                    return Err(format!("setup: command {seq} did not commit"));
                }
                delivered.push((seq, observed));
            }
            let before = one.ops_done();
            if let Some((n, k)) = cut {
                one.arm_cut(n, k);
            }
            let observed = one.session.state_revision;
            let request = one.request("ctl-a", 6, set_group(66));
            let queued = one.channel.submit(0, request);
            if !matches!(queued, SubmitResult::Queued { .. }) {
                return Err(format!("setup: submitting the sixth gave {queued:?}"));
            }
            let turn = one.turn_step();
            if turn
                .delivered
                .iter()
                .any(|s| s.peer.as_str() == "ctl-a" && s.seq == 6)
            {
                delivered.push((6, observed));
            }
            let after = one.ops_done();
            let pending = if cut.is_none() {
                one.pending_before()[before..after].to_vec()
            } else {
                Vec::new()
            };
            (delivered, (before, after), pending)
        };
        Ok(LifeOne {
            delivered,
            ops,
            pending,
            durable: medium.durable().to_vec(),
        })
    }

    /// The second process after one cut: it opens what survived and restores. The recovered mark must be
    /// exactly the old one (7) or the new one (8): U01's old-or-new. Then, with the rebuilt session brought
    /// to revision 8, the duplicate of **every command whose outcome was delivered** must be refused exactly
    /// as `StaleRevision { observed, floor: <the recovered mark> }` (`ADMITTED` if it was applied again,
    /// `WRONG-REASON` otherwise). Returns the recovered mark.
    fn after_the_cut(life: &LifeOne) -> Result<u64, String> {
        let mut medium = MemStorage::from_image(limits().segment_bytes, &life.durable);
        let mut two = Incarnation::boot(&mut medium, Owner::Faithful);
        let mark = match two.restored {
            Some(Restored::Mark(mark)) if mark == 7 || mark == 8 => mark,
            other => {
                return Err(format!(
                    "OLD-OR-NEW: the recovered state gave {other:?}, neither the old mark 7 nor the new mark 8"
                ));
            }
        };
        for seq in 1..=6u64 {
            if !committed(&two.run("panel", seq, mute(seq % 2 == 1))?) {
                return Err(format!(
                    "LOCKED-OUT: local command {seq} did not commit after the restart"
                ));
            }
        }
        if two.session.state_revision != 8 {
            return Err(format!(
                "setup: the rebuilt session is at revision {}, not 8",
                two.session.state_revision
            ));
        }
        for &(seq, observed) in &life.delivered {
            let volume = 60 + u8::try_from(seq).unwrap();
            let duplicate = two.request_at("ctl-a", seq, Some(observed), set_group(volume));
            let outcome = two.deliver(duplicate, "ctl-a", seq)?;
            if committed(&outcome) {
                return Err(format!(
                    "ADMITTED: the duplicate of delivered command {seq} (composed at revision {observed}) was applied again after the restart; the recovered mark was {mark}"
                ));
            }
            let expected = Outcome::Refused(Refusal::StaleRevision {
                observed,
                floor: mark,
            });
            if outcome != expected {
                return Err(format!(
                    "WRONG-REASON: the duplicate of command {seq} gave {outcome:?}, not {expected:?}"
                ));
            }
        }
        Ok(mark)
    }

    /// Cut the power at every storage operation and every byte budget of the sixth command's store, and
    /// judge each recovery. Returns how many cuts recovered the old mark and how many the new one.
    fn judge_every_cut_of_the_mark_store(owner: Owner) -> Result<(usize, usize), String> {
        let uncut = life_one(owner, None)?;
        let (before, after) = uncut.ops;
        if after <= before || uncut.pending.len() != after - before {
            return Err(format!(
                "setup: the sixth command's store ran operations {before}..{after}, with {} pending counts",
                uncut.pending.len()
            ));
        }
        let mut cuts = vec![None];
        for (index, budget) in uncut.pending.iter().enumerate() {
            for k in 0..=*budget {
                cuts.push(Some((before + index, k)));
            }
        }
        let (mut old, mut new) = (0, 0);
        for cut in cuts {
            let life = life_one(owner, cut)?;
            let mark = after_the_cut(&life).map_err(|e| format!("{e} (cut {cut:?})"))?;
            if mark == 7 {
                old += 1;
            } else {
                new += 1;
            }
        }
        Ok((old, new))
    }

    #[test]
    fn every_cut_of_the_mark_store_leaves_the_old_or_the_new_mark_and_no_replay() {
        let (old, new) = judge_every_cut_of_the_mark_store(Owner::Faithful).unwrap();
        // The sweep is not vacuous: some cuts leave the old mark and some the new one.
        assert!(old > 0, "no cut recovered the old mark");
        assert!(new > 0, "no cut recovered the new mark");
    }

    #[test]
    fn an_owner_that_delivers_before_it_stores_is_caught_by_the_cut_sweep() {
        // The faithful owner passes the whole sweep first.
        assert!(judge_every_cut_of_the_mark_store(Owner::Faithful).is_ok());
        let verdict = judge_every_cut_of_the_mark_store(Owner::DeliversBeforeStoring);
        assert!(
            verdict.as_ref().is_err_and(|e| e.starts_with("ADMITTED")),
            "delivering before storing was not caught as ADMITTED: {verdict:?}"
        );
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Damage {
        /// Both segment headers are overwritten: the medium is not blank and holds no valid state.
        Unrecoverable,
        /// The medium does not answer reads.
        NotAnswering,
    }

    /// The first process runs to revision 7 and stores the mark; then the medium is damaged. The second process
    /// must not start from the session's revision: for this run the local user still commits (`LOCKED-OUT` if
    /// not), the held-back copy is refused exactly as `StaleRevision { observed: 4, floor: REFUSING_FLOOR }`
    /// (`ADMITTED`, `WRONG-REASON`), a fresh remote command is refused the same way (the stated cost), and the
    /// floor is never stored (`STORED-SENTINEL`). Returns what the second process restored.
    fn judge_a_journal_that_cannot_be_read_refuses_instead_of_starting_from_zero(
        damage: Damage,
        second: Owner,
    ) -> Result<Option<Restored>, String> {
        let mut medium = blank_medium();
        let held_back = first_life(&mut medium, Owner::Faithful)?;
        let seg = limits().segment_bytes;
        let mut image = medium.durable().to_vec();
        let mut damaged = match damage {
            Damage::Unrecoverable => {
                for base in [0, seg] {
                    image[base..base + SEG_HEADER].fill(0);
                }
                MemStorage::from_image(seg, &image)
            }
            Damage::NotAnswering => {
                let mut dead = MemStorage::from_image(seg, &image);
                dead.power_cut(0, false);
                dead
            }
        };
        let mut two = Incarnation::boot(&mut damaged, second);
        let restored = two.restored;
        bring_to_seven(&mut two)?;

        let copy = two.deliver(held_back, "ctl-a", 100)?;
        if committed(&copy) {
            return Err(format!(
                "ADMITTED: the held-back copy was applied although the mark could not be read (group volume {})",
                two.session.group_master_volume
            ));
        }
        let expected = Outcome::Refused(Refusal::StaleRevision {
            observed: 4,
            floor: REFUSING_FLOOR,
        });
        if copy != expected {
            return Err(format!(
                "WRONG-REASON: the held-back copy gave {copy:?}, not {expected:?}"
            ));
        }
        let fresh = two.run("ctl-a", 101, set_group(70))?;
        let expected_fresh = Outcome::Refused(Refusal::StaleRevision {
            observed: 7,
            floor: REFUSING_FLOOR,
        });
        if committed(&fresh) {
            return Err(format!(
                "ADMITTED: a fresh remote command was applied although the mark could not be read (group volume {})",
                two.session.group_master_volume
            ));
        }
        if fresh != expected_fresh {
            return Err(format!(
                "WRONG-REASON: a fresh remote command gave {fresh:?}, not {expected_fresh:?}"
            ));
        }
        if two.stored_mark().is_some() {
            return Err(format!(
                "STORED-SENTINEL: the journal holds {:?} after a run that never read a mark",
                two.stored_mark()
            ));
        }
        Ok(restored)
    }

    #[test]
    fn an_unreadable_journal_refuses_remote_commands_and_does_not_start_from_zero() {
        assert_eq!(
            judge_a_journal_that_cannot_be_read_refuses_instead_of_starting_from_zero(
                Damage::Unrecoverable,
                Owner::Faithful
            ),
            Ok(Some(Restored::Refusing(Cause::Unrecoverable)))
        );
        assert_eq!(
            judge_a_journal_that_cannot_be_read_refuses_instead_of_starting_from_zero(
                Damage::NotAnswering,
                Owner::Faithful
            ),
            Ok(Some(Restored::Refusing(Cause::OpenFailed("storage"))))
        );
    }

    #[test]
    fn an_owner_that_ignores_an_unreadable_journal_fails_the_refusal_judge_by_name() {
        // The faithful owner passes both damages first.
        for damage in [Damage::Unrecoverable, Damage::NotAnswering] {
            assert!(
                judge_a_journal_that_cannot_be_read_refuses_instead_of_starting_from_zero(
                    damage,
                    Owner::Faithful
                )
                .is_ok(),
                "{damage:?}"
            );
            let verdict = judge_a_journal_that_cannot_be_read_refuses_instead_of_starting_from_zero(
                damage,
                Owner::IgnoresAFailedOpen,
            );
            assert!(
                verdict.as_ref().is_err_and(|e| e.starts_with("ADMITTED")),
                "{damage:?} was not caught as ADMITTED: {verdict:?}"
            );
        }
    }

    #[test]
    fn restoring_tells_a_blank_medium_from_an_intact_journal_without_a_mark_from_a_mark() {
        let mut medium = blank_medium();
        {
            let mut one = Incarnation::boot(&mut medium, Owner::Faithful);
            assert_eq!(one.restored, Some(Restored::FreshMedium));
            // Nothing was stepped yet, so nothing was stored.
            assert_eq!(one.stored_mark(), None);
            assert!(committed(&one.run("panel", 1, mute(true)).unwrap()));
            // A local command raised the revision to 3, and the mark followed it.
            assert_eq!(one.stored_mark(), Some(3));
        }
        let mut other = blank_medium();
        {
            // A journal that was opened and closed, with no step: intact, no mark.
            let _ = Incarnation::boot(&mut other, Owner::Faithful);
        }
        let again = Incarnation::boot(&mut other, Owner::Faithful);
        assert_eq!(again.restored, Some(Restored::NeverStored));
        let two = Incarnation::boot(&mut medium, Owner::Faithful);
        assert_eq!(two.restored, Some(Restored::Mark(3)));
        // The channel was given it: its mark is the larger of the rebuilt session's revision (2) and 3.
        assert_eq!(two.channel.high_water(&two.session), 3);
    }

    #[test]
    fn a_step_that_changed_nothing_writes_nothing() {
        let mut medium = blank_medium();
        let mut one = Incarnation::boot(&mut medium, Owner::Faithful);
        assert!(committed(&one.run("panel", 1, mute(true)).unwrap()));
        let frames = one.journal.as_ref().unwrap().frames_written();
        // An idle step offers the same mark again, and the journal writes nothing.
        let journal = one.journal.as_mut().unwrap();
        let settled = step_then_store(&mut one.channel, 0, &mut one.session, journal).unwrap();
        assert!(settled.is_empty());
        assert_eq!(one.journal.as_ref().unwrap().frames_written(), frames);
    }

    #[test]
    fn the_refusal_floor_is_never_stored() {
        let mut medium = blank_medium();
        let mut one = Incarnation::boot(&mut medium, Owner::Faithful);
        one.channel.restore_high_water(REFUSING_FLOOR).unwrap();
        assert_eq!(one.channel.high_water(&one.session), REFUSING_FLOOR);
        let journal = one.journal.as_mut().unwrap();
        assert_eq!(
            store_high_water(&one.channel, &one.session, journal),
            Ok(Commit::Noop)
        );
        assert_eq!(one.stored_mark(), None);
    }

    #[test]
    fn a_mark_offered_after_the_first_step_is_an_error_and_not_a_silent_no_op() {
        let mut medium = blank_medium();
        let _held_back = first_life(&mut medium, Owner::Faithful).unwrap();
        let mut reborn = MemStorage::from_image(limits().segment_bytes, medium.durable());
        let mut two = Incarnation::boot(&mut reborn, Owner::NeverRestores);
        assert!(committed(&two.run("panel", 1, mute(true)).unwrap()));
        // The channel has stepped. A journal that holds a mark is offered to it now, and that is refused.
        let third = MemStorage::from_image(limits().segment_bytes, medium.durable());
        let opened = Journal::open(third, limits());
        assert_eq!(
            restore_from_open(&mut two.channel, &opened),
            Err(HighWaterError::AlreadyRunning)
        );
    }

    #[test]
    fn an_owner_that_forgot_to_restore_has_its_outcomes_withheld_by_the_journal() {
        let mut medium = blank_medium();
        let _held_back = first_life(&mut medium, Owner::Faithful).unwrap();
        let mut reborn = MemStorage::from_image(limits().segment_bytes, medium.durable());
        let mut two = Incarnation::boot(&mut reborn, Owner::Unrestored);
        assert_eq!(two.restored, None);
        // A command that does more than silence: a volume set. (The local user's mute-on and stop are the one exception to
        // "withheld" and are tested next, with their own exact expectations.)
        let request = two.request("panel", 1, set_group(70));
        assert!(matches!(
            two.channel.submit(0, request),
            SubmitResult::Queued { .. }
        ));
        // The channel offers 3 (its session is at revision 2 and has moved to 3); the journal holds 7 and does not go down.
        let journal = two.journal.as_mut().unwrap();
        let failed = step_then_store(&mut two.channel, 0, &mut two.session, journal).unwrap_err();
        assert_eq!(failed.cause, JournalError::MarkRegressed { current: 7 });
        assert_eq!(failed.withheld.len(), 1);
        assert_eq!(two.stored_mark(), Some(7));
        // No effect and no success: nothing was applied, nothing is to be delivered, the volume is where it was.
        assert!(failed.applied.is_empty());
        assert_eq!(two.session.group_master_volume, BASE);
        // The paired positive: the same command from an owner that restored the mark goes through.
        let mut restored_medium = MemStorage::from_image(limits().segment_bytes, medium.durable());
        let mut ok = Incarnation::boot(&mut restored_medium, Owner::Faithful);
        assert_eq!(ok.restored, Some(Restored::Mark(7)));
        assert!(committed(&ok.run("panel", 1, set_group(70)).unwrap()));
        assert_eq!(ok.session.group_master_volume, 70);
        assert_eq!(ok.stored_mark(), Some(7));
    }

    #[test]
    fn an_owner_that_forgot_to_restore_still_gets_the_first_local_mute_on_applied_and_nothing_else()
    {
        let mut medium = blank_medium();
        let _held_back = first_life(&mut medium, Owner::Faithful).unwrap();
        let mut reborn = MemStorage::from_image(limits().segment_bytes, medium.durable());
        let mut two = Incarnation::boot(&mut reborn, Owner::Unrestored);
        assert_eq!(two.restored, None);
        // The local mute-on and a volume set arrive together.
        queue(&mut two, "panel", 1, mute(true));
        queue(&mut two, "panel", 2, set_group(70));
        let journal = two.journal.as_mut().unwrap();
        let failed = step_then_store(&mut two.channel, 0, &mut two.session, journal).unwrap_err();
        // The journal still refuses to go down, for the same reason as above...
        assert_eq!(failed.cause, JournalError::MarkRegressed { current: 7 });
        assert_eq!(two.stored_mark(), Some(7));
        // ...the volume set is withheld and has no effect, as it must...
        assert_eq!(seqs(&failed.withheld), vec![2]);
        assert_eq!(two.session.group_master_volume, BASE);
        // ...and the mute-on, which only silences, took effect on the live session after all and is to be delivered.
        assert_eq!(seqs(&failed.applied), vec![1]);
        assert!(committed(&failed.applied[0].outcome));
        assert!(two.session.members["kitchen"].muted);
        assert!(matches!(
            two.channel.durability(),
            Durability::Failed { .. }
        ));
    }

    #[test]
    fn the_key_and_the_value_fit_the_smallest_and_the_device_configuration() {
        for lim in [Limits::tiny(), Limits::standard()] {
            assert!(HIGH_WATER_KEY.len() <= lim.marks.key_max);
            assert!(lim.marks.value_max >= 8, "a mark is eight bytes");
            assert!(lim.marks.entries >= 1);
            // The relative-command floors: the key fits both, a record of two identities fits the smallest, and a
            // record of all sixteen fits the device configuration.
            assert!(SEQ_FLOORS_KEY.len() <= lim.records.key_max);
            assert!(lim.records.entries >= 1);
            assert!(HEADER_LEN + 2 * ENTRY_LEN <= lim.records.value_max);
        }
        assert!(MAX_ENCODED_LEN <= Limits::standard().records.value_max);
        assert!(
            SEQ_FLOORS_KEY != HIGH_WATER_KEY,
            "different namespaces, but never the same name"
        );
    }

    // ------------------------------------------------------------ relative commands: the floors

    /// The group volume the fixture starts at, and what one relative command moves it by.
    const BASE: u8 = 50;
    const STEP: u8 = 5;

    /// How the cut command ended for the client that sent it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Ended {
        /// Its outcome was delivered.
        Delivered(Outcome),
        /// The store failed and the owner kept the outcomes back.
        Withheld,
    }

    /// What one cut of a relative command's two stores (its floor, then the mark) left, as the first process saw it.
    struct RelLife {
        /// `(seq, revision composed at)` of every relative command whose committed outcome was delivered.
        delivered: Vec<(u64, u64)>,
        /// The command whose stores were cut: `(seq, revision composed at)`.
        cut_command: (u64, u64),
        ended: Ended,
        /// The live session right after the cut turn: the effect that survives the process.
        survivor: UnifiedGroupSession,
        /// How the same process answered a retry of the cut command, and the volume after that retry's turn.
        retry: SubmitResult,
        volume_after_retry: u8,
        /// The storage operations before and after the cut turn.
        ops: (usize, usize),
        /// The bytes pending before each of those operations (an uncut run only).
        pending: Vec<usize>,
        durable: Vec<u8>,
    }

    /// `peer` sends relative `+5` as number 1 (delivered), then as number 2, whose stores are cut at `cut`
    /// (operation, byte budget). Every relative request names the revision it was composed at.
    fn rel_life(owner: Owner, peer: &str, cut: Option<(usize, usize)>) -> Result<RelLife, String> {
        let mut medium = blank_medium();
        let mut life = {
            let mut one = Incarnation::boot(&mut medium, owner);
            let mut delivered = Vec::new();
            let first_at = one.session.state_revision;
            let first = one.relative(peer, 1, 5);
            if !committed(&one.deliver(first, peer, 1)?) {
                return Err("setup: the first relative command did not commit".to_string());
            }
            delivered.push((1, first_at));
            let before = one.ops_done();
            if let Some((n, k)) = cut {
                one.arm_cut(n, k);
            }
            let cut_at = one.session.state_revision;
            let request = one.relative(peer, 2, 5);
            let queued = one.channel.submit(0, request.clone());
            if !matches!(queued, SubmitResult::Queued { .. }) {
                return Err(format!("setup: submitting the cut command gave {queued:?}"));
            }
            let turn = one.turn_step();
            let settled = turn
                .delivered
                .iter()
                .find(|s| s.peer.as_str() == peer && s.seq == 2)
                .map(|s| s.outcome.clone());
            let ended = match (settled, turn.store_failed) {
                (Some(outcome), _) => Ended::Delivered(outcome),
                (None, true) => Ended::Withheld,
                (None, false) => {
                    return Err(
                        "setup: the cut turn neither delivered the command nor failed".to_string(),
                    );
                }
            };
            if matches!(&ended, Ended::Delivered(outcome) if committed(outcome)) {
                delivered.push((2, cut_at));
            }
            let after = one.ops_done();
            let pending = if cut.is_none() {
                one.pending_before()[before..after].to_vec()
            } else {
                Vec::new()
            };
            // The process dies here: what survives is the live session as it now stands.
            let survivor = one.session.clone();
            // A client that did not hear back asks again, in the same process.
            let retry = one.channel.submit(0, request);
            if matches!(retry, SubmitResult::Queued { .. }) {
                let _ = one.turn_step();
            }
            RelLife {
                delivered,
                cut_command: (2, cut_at),
                ended,
                survivor,
                retry,
                volume_after_retry: one.session.group_master_volume,
                ops: (before, after),
                pending,
                durable: Vec::new(),
            }
        };
        life.durable = medium.durable().to_vec();
        Ok(life)
    }

    /// Local mutes (absolute, so they write no floor) raise a rebuilt session to `revision`; their numbers continue
    /// from `next`.
    fn realign(two: &mut Incarnation<'_>, revision: u64, next: &mut u64) -> Result<(), String> {
        while two.session.state_revision < revision {
            let seq = *next;
            *next += 1;
            if !committed(&two.run("panel", seq, mute(seq % 2 == 1))?) {
                return Err(format!(
                    "LOCKED-OUT: local command {seq} did not commit after the restart"
                ));
            }
        }
        if two.session.state_revision != revision {
            return Err(format!(
                "setup: the rebuilt session is at revision {}, not {revision}",
                two.session.state_revision
            ));
        }
        Ok(())
    }

    /// Judge one cut of a relative command's stores. In the first process, if the store failed (`Withheld`): the live
    /// session must show no effect (`NOT-STAGED`), a retry in the same process must not be answered from the ledger
    /// (`LAUNDERED`) and must not move the volume (`DOUBLE-APPLIED`). If the outcome was delivered, a retry is answered
    /// with exactly that outcome and moves nothing. Then a second process opens what survived. A `panel` peer meets the
    /// surviving session (the effect of every delivered command is in it); a `ctl-a` peer meets a session rebuilt at
    /// revision 2 and brought back to the revision each request names. The duplicate of **every delivered command**
    /// must be answered `OutOfWindow { floor: <the recovered floor> }` at once: unknown, and never queued
    /// (`ADMITTED`, `WRONG-REASON`). The recovered floor is exactly the old one or the new one (`OLD-OR-NEW`). A cut
    /// command whose outcome was never delivered is then retried: it is unknown if its floor was recorded, and applies
    /// exactly once if it was not (`DOUBLE-APPLIED`, `LOCKED-OUT`). Returns the recovered floor of `peer`.
    fn judge_a_cut_of_a_relative_command(life: &RelLife, peer: &str) -> Result<u64, String> {
        let volume = life.survivor.group_master_volume;
        match &life.ended {
            Ended::Withheld => {
                if volume != BASE + STEP {
                    return Err(format!(
                        "NOT-STAGED: the store failed and the outcome was withheld, but the live session shows volume {volume}, not {}",
                        BASE + STEP
                    ));
                }
                if let SubmitResult::Settled(outcome) = &life.retry {
                    return Err(format!(
                        "LAUNDERED: a retry in the same process was answered {outcome:?}, a result the client was never given"
                    ));
                }
                if life.volume_after_retry != volume {
                    return Err(format!(
                        "DOUBLE-APPLIED: a retry in the same process moved the volume from {volume} to {} although the journal could not record it",
                        life.volume_after_retry
                    ));
                }
            }
            Ended::Delivered(outcome) => {
                if life.retry != SubmitResult::Settled(outcome.clone()) {
                    return Err(format!(
                        "WRONG-REASON: a retry of a delivered command gave {:?}, not its outcome {outcome:?}",
                        life.retry
                    ));
                }
                if life.volume_after_retry != volume {
                    return Err(format!(
                        "DOUBLE-APPLIED: a retry of a delivered command moved the volume from {volume} to {}",
                        life.volume_after_retry
                    ));
                }
                if committed(outcome) && volume != BASE + 2 * STEP {
                    return Err(format!(
                        "setup: two committed commands left volume {volume}, not {}",
                        BASE + 2 * STEP
                    ));
                }
            }
        }

        let keeps_session = peer == "panel";
        let mut medium = MemStorage::from_image(limits().segment_bytes, &life.durable);
        let world = if keeps_session {
            life.survivor.clone()
        } else {
            fixture_session(EPOCH)
        };
        let mut two = Incarnation::boot_over(&mut medium, Owner::Faithful, world);
        let recovered = two.channel.seq_floors().floor_of(&id(peer));
        let mut next_local = 1u64;
        for &(seq, observed) in &life.delivered {
            if !keeps_session {
                realign(&mut two, observed, &mut next_local)?;
            }
            let duplicate = two.request_at(peer, seq, Some(observed), adjust(5));
            let before = two.session.group_master_volume;
            match two.channel.submit(0, duplicate) {
                SubmitResult::OutOfWindow { floor } if Some(floor) == recovered => {}
                SubmitResult::Queued { .. } => {
                    let turn = two.turn_step();
                    let applied = turn
                        .delivered
                        .iter()
                        .any(|s| s.peer.as_str() == peer && s.seq == seq && committed(&s.outcome));
                    return Err(format!(
                        "ADMITTED: the duplicate of delivered command {seq} (composed at revision {observed}) was queued after the restart instead of answered unknown (applied: {applied}, volume {before} to {}; recovered floor {recovered:?})",
                        two.session.group_master_volume
                    ));
                }
                other => {
                    return Err(format!(
                        "WRONG-REASON: the duplicate of delivered command {seq} gave {other:?}; the recovered floor is {recovered:?}"
                    ));
                }
            }
        }
        let floor = match recovered {
            Some(floor @ (1 | 2)) => floor,
            other => {
                return Err(format!(
                    "OLD-OR-NEW: the recovered floor of {peer} is {other:?}, neither the old floor 1 nor the new floor 2"
                ));
            }
        };

        if !life.delivered.iter().any(|&(seq, _)| seq == 2) {
            let (seq, observed) = life.cut_command;
            if !keeps_session {
                realign(&mut two, observed, &mut next_local)?;
            }
            let before = two.session.group_master_volume;
            let again = two.request_at(peer, seq, Some(observed), adjust(5));
            match two.channel.submit(0, again) {
                // Its floor was recorded before the cut: unknown, and it will not be applied.
                SubmitResult::OutOfWindow { floor: reported } if floor == 2 && reported == 2 => {}
                // Its floor was not recorded, so nothing of it was ever visible: this is its first application.
                SubmitResult::Queued { .. } if floor == 1 => {
                    let turn = two.turn_step();
                    let outcome = turn
                        .delivered
                        .iter()
                        .find(|s| s.peer.as_str() == peer && s.seq == seq)
                        .map(|s| s.outcome.clone());
                    match outcome {
                        Some(outcome) if committed(&outcome) => {}
                        other => {
                            return Err(format!(
                                "LOCKED-OUT: the first application of the unrecorded command gave {other:?}"
                            ));
                        }
                    }
                    let after = two.session.group_master_volume;
                    if after != before + STEP {
                        return Err(format!(
                            "DOUBLE-APPLIED: the retry moved the volume from {before} to {after}, not by one step"
                        ));
                    }
                }
                other => {
                    return Err(format!(
                        "WRONG-REASON: the retry of the undelivered command gave {other:?} with recovered floor {floor}"
                    ));
                }
            }
        }
        Ok(floor)
    }

    /// Cut the power at every storage operation and every byte budget of the second relative command's stores and
    /// judge each. Returns how many cuts recovered the old floor, how many the new one, and how many withheld the
    /// outcome.
    fn judge_every_cut_of_a_relative_command(
        owner: Owner,
        peer: &str,
    ) -> Result<(usize, usize, usize), String> {
        let uncut = rel_life(owner, peer, None)?;
        let first =
            judge_a_cut_of_a_relative_command(&uncut, peer).map_err(|e| format!("{e} (uncut)"))?;
        let (before, after) = uncut.ops;
        if after <= before || uncut.pending.len() != after - before {
            return Err(format!(
                "setup: the second command's stores ran operations {before}..{after}, with {} pending counts",
                uncut.pending.len()
            ));
        }
        let mut cuts = Vec::new();
        for (index, budget) in uncut.pending.iter().enumerate() {
            for k in 0..=*budget {
                cuts.push((before + index, k));
            }
        }
        let (mut old, mut new, mut withheld) =
            (usize::from(first == 1), usize::from(first == 2), 0);
        for cut in cuts {
            let life = rel_life(owner, peer, Some(cut))?;
            let floor = judge_a_cut_of_a_relative_command(&life, peer)
                .map_err(|e| format!("{e} (cut {cut:?})"))?;
            if floor == 1 {
                old += 1;
            } else {
                new += 1;
            }
            if life.ended == Ended::Withheld {
                withheld += 1;
            }
        }
        Ok((old, new, withheld))
    }

    #[test]
    fn a_delivered_relative_command_is_unknown_after_a_channel_restart_and_the_next_one_applies_once()
     {
        let mut medium = blank_medium();
        let survivor = {
            let mut one = Incarnation::boot(&mut medium, Owner::Faithful);
            assert_eq!(one.floors, Some(RestoredFloors::Nothing));
            // An absolute command writes one frame (the mark); a relative one writes two (its floor, then the mark).
            let frames = one.journal.as_ref().unwrap().frames_written();
            assert!(committed(&one.run("panel", 1, mute(true)).unwrap()));
            let after_absolute = one.journal.as_ref().unwrap().frames_written();
            assert_eq!(after_absolute, frames + 1);
            let first = one.relative("panel", 2, 5);
            assert!(committed(&one.deliver(first, "panel", 2).unwrap()));
            assert_eq!(
                one.journal.as_ref().unwrap().frames_written(),
                after_absolute + 2
            );
            assert_eq!(one.session.group_master_volume, BASE + STEP);
            let record = one
                .journal
                .as_ref()
                .unwrap()
                .state()
                .records
                .get(SEQ_FLOORS_KEY)
                .map(Vec::len);
            assert_eq!(record, Some(HEADER_LEN + ENTRY_LEN));
            one.session.clone()
        };
        let mut reborn = MemStorage::from_image(limits().segment_bytes, medium.durable());
        let mut two = Incarnation::boot_over(&mut reborn, Owner::Faithful, survivor);
        assert_eq!(two.floors, Some(RestoredFloors::Table { identities: 1 }));
        // The restarted channel has an empty ledger. The duplicate is unknown and is not applied...
        let duplicate = two.request_at("panel", 2, Some(3), adjust(5));
        assert_eq!(
            two.channel.submit(0, duplicate),
            SubmitResult::OutOfWindow { floor: 2 }
        );
        assert_eq!(two.session.group_master_volume, BASE + STEP);
        // ...and the next number is a new command that applies once.
        let next = two.relative("panel", 3, 5);
        assert!(committed(&two.deliver(next, "panel", 3).unwrap()));
        assert_eq!(two.session.group_master_volume, BASE + 2 * STEP);
        assert_eq!(two.channel.seq_floors().floor_of(&id("panel")), Some(3));
    }

    #[test]
    fn every_cut_of_a_relative_commands_stores_applies_it_at_most_once_for_the_local_user() {
        let (old, new, withheld) =
            judge_every_cut_of_a_relative_command(Owner::Faithful, "panel").unwrap();
        // The sweep is not vacuous: some cuts recover the old floor and some the new one, and some withhold.
        assert!(old > 0, "no cut recovered the old floor");
        assert!(new > 0, "no cut recovered the new floor");
        assert!(withheld > 0, "no cut withheld the outcome");
    }

    #[test]
    fn every_cut_of_a_relative_commands_stores_applies_it_at_most_once_for_a_controller() {
        let (old, new, withheld) =
            judge_every_cut_of_a_relative_command(Owner::Faithful, "ctl-a").unwrap();
        assert!(old > 0, "no cut recovered the old floor");
        assert!(new > 0, "no cut recovered the new floor");
        assert!(withheld > 0, "no cut withheld the outcome");
    }

    #[test]
    fn each_planted_owner_fault_fails_the_relative_command_sweep_by_name() {
        for peer in ["panel", "ctl-a"] {
            // The faithful owner passes first, so the faults below are not failing for another reason.
            assert!(
                judge_every_cut_of_a_relative_command(Owner::Faithful, peer).is_ok(),
                "{peer}"
            );
            for (owner, tag) in [
                // Steps the live session and never reserves a floor or stores the mark.
                (Owner::NeverStores, "ADMITTED"),
                // Delivers the effect and the outcome before it stores the mark; reserves no floor.
                (Owner::DeliversBeforeStoring, "ADMITTED"),
                // Stages and stores correctly, but leaves a withheld outcome in the ledger.
                (Owner::KeepsWithheldOutcomes, "LAUNDERED"),
                // Reserves and withholds correctly, but steps the live session instead of a copy.
                (Owner::UnstagedStep, "NOT-STAGED"),
            ] {
                let verdict = judge_every_cut_of_a_relative_command(owner, peer);
                assert!(
                    verdict.as_ref().is_err_and(|e| e.starts_with(tag)),
                    "{owner:?} for {peer} was not caught as {tag}: {verdict:?}"
                );
            }
        }
    }

    #[test]
    fn a_store_failure_after_the_floor_is_durable_withholds_the_result_and_makes_the_retry_unknown()
    {
        let uncut = rel_life(Owner::Faithful, "panel", None).unwrap();
        // The last storage operation of the turn is the mark's sync: cutting it keeps the floor and loses the mark.
        let last = uncut.ops.1 - 1;
        let life = rel_life(Owner::Faithful, "panel", Some((last, 0))).unwrap();
        assert_eq!(life.ended, Ended::Withheld);
        // The effect never appeared in the live session, nor the revision it would have revealed.
        assert_eq!(life.survivor.group_master_volume, BASE + STEP);
        assert_eq!(life.survivor.state_revision, 3);
        // A retry is unknown (the floor is durable) and moves nothing; it is not answered from the ledger.
        assert_eq!(life.retry, SubmitResult::OutOfWindow { floor: 2 });
        assert_eq!(life.volume_after_retry, BASE + STEP);
        assert_eq!(judge_a_cut_of_a_relative_command(&life, "panel"), Ok(2));
    }

    #[test]
    fn an_absolute_command_withheld_by_a_store_failure_applies_once_when_retried_after_a_restart() {
        // The twin run learns where the mark's last storage operation falls.
        let last = {
            let mut twin_medium = blank_medium();
            let mut twin = Incarnation::boot(&mut twin_medium, Owner::Faithful);
            assert!(committed(&twin.run("panel", 1, mute(true)).unwrap()));
            assert!(committed(&twin.run("panel", 2, set_group(70)).unwrap()));
            twin.ops_done() - 1
        };
        let mut medium = blank_medium();
        let survivor = {
            let mut one = Incarnation::boot(&mut medium, Owner::Faithful);
            assert!(committed(&one.run("panel", 1, mute(true)).unwrap()));
            one.arm_cut(last, 0);
            let request = one.request("panel", 2, set_group(70));
            let failed = one.deliver(request, "panel", 2);
            assert!(
                failed
                    .as_ref()
                    .is_err_and(|e| e.starts_with("STORE-FAILED")),
                "{failed:?}"
            );
            // The staged effect was dropped.
            assert_eq!(one.session.group_master_volume, BASE);
            one.session.clone()
        };
        let mut reborn = MemStorage::from_image(limits().segment_bytes, medium.durable());
        let mut two = Incarnation::boot_over(&mut reborn, Owner::Faithful, survivor);
        // An absolute command records no floor, so nothing stands in the way of its retry: a first application.
        assert_eq!(two.channel.seq_floors().floor_of(&id("panel")), None);
        let again = two.request("panel", 2, set_group(70));
        assert!(committed(&two.deliver(again, "panel", 2).unwrap()));
        assert_eq!(two.session.group_master_volume, 70);
    }

    /// A floor store that can be told to fail, and keeps the last record it was given.
    struct ScriptedStore {
        fail: bool,
        calls: usize,
        last: Vec<u8>,
    }

    impl FloorStore for ScriptedStore {
        fn store(&mut self, packed: &[u8]) -> Result<(), FloorNotStored> {
            self.calls += 1;
            if self.fail {
                return Err(FloorNotStored { code: "storage" });
            }
            self.last = packed.to_vec();
            Ok(())
        }
    }

    #[test]
    fn a_floor_that_cannot_be_stored_refuses_the_relative_command_untouched_and_other_commands_keep_working()
     {
        let mut medium = blank_medium();
        let mut one = Incarnation::boot(&mut medium, Owner::Faithful);
        let mut store = ScriptedStore {
            fail: true,
            calls: 0,
            last: Vec::new(),
        };
        let revision = one.session.state_revision;
        let request = one.relative("panel", 1, 5);
        assert!(matches!(
            one.channel.submit(0, request.clone()),
            SubmitResult::Queued { .. }
        ));
        let settled = one.channel.step_reserving(0, &mut one.session, &mut store);
        assert_eq!(settled.len(), 1);
        assert_eq!(settled[0].outcome, Outcome::Refused(Refusal::InternalFault));
        assert_eq!(store.calls, 1);
        // Not applied, and no floor claimed.
        assert_eq!(
            (one.session.group_master_volume, one.session.state_revision),
            (BASE, revision)
        );
        assert!(one.channel.seq_floors().is_empty());
        // The refusal is on record: asking again with the same number gets the same answer, and the sender must
        // use a new number.
        assert_eq!(
            one.channel.submit(0, request),
            SubmitResult::Settled(Outcome::Refused(Refusal::InternalFault))
        );

        // A local absolute command never touches the store...
        let set = one.request("panel", 2, set_group(70));
        assert!(matches!(
            one.channel.submit(0, set),
            SubmitResult::Queued { .. }
        ));
        let settled = one.channel.step_reserving(0, &mut one.session, &mut store);
        assert!(committed(&settled[0].outcome), "{settled:?}");
        assert_eq!((one.session.group_master_volume, store.calls), (70, 1));

        // ...and with the store working, a relative command with a new number applies and its floor is what was stored.
        store.fail = false;
        let again = one.relative("panel", 3, 5);
        assert!(matches!(
            one.channel.submit(0, again),
            SubmitResult::Queued { .. }
        ));
        let settled = one.channel.step_reserving(0, &mut one.session, &mut store);
        assert!(committed(&settled[0].outcome), "{settled:?}");
        assert_eq!(one.session.group_master_volume, 70 + STEP);
        assert_eq!(store.calls, 2);
        let stored = SeqFloors::decode(&store.last).unwrap();
        assert_eq!(stored.floor_of(&id("panel")), Some(3));
        assert_eq!(one.channel.seq_floors(), &stored);

        // A local stop never touches the store either.
        let halt = one.request("panel", 4, stop());
        assert!(matches!(
            one.channel.submit(0, halt),
            SubmitResult::Queued { .. }
        ));
        let settled = one.channel.step_reserving(0, &mut one.session, &mut store);
        assert!(committed(&settled[0].outcome), "{settled:?}");
        assert_eq!(store.calls, 2);
    }

    #[test]
    fn a_duplicate_with_a_bad_proof_is_unauthenticated_and_not_answered_from_the_floor() {
        let mut medium = blank_medium();
        {
            let mut one = Incarnation::boot(&mut medium, Owner::Faithful);
            let first = one.relative("ctl-a", 1, 5);
            assert!(committed(&one.deliver(first, "ctl-a", 1).unwrap()));
        }
        let mut reborn = MemStorage::from_image(limits().segment_bytes, medium.durable());
        let mut two = Incarnation::boot(&mut reborn, Owner::Faithful);
        let body = RequestBody::new(id("ctl-a"), 1, EPOCH, Some(2), adjust(5)).unwrap();
        let forged = ControlRequest::new(
            body.clone(),
            compute_proof(&test_key("panel"), &body.signing_bytes()),
        );
        // Authentication comes first: a forger learns nothing about which numbers were used.
        assert_eq!(
            two.channel.submit(0, forged),
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::BadProof))
        );
        // The genuine duplicate is unknown.
        let genuine = ControlRequest::new(
            body.clone(),
            compute_proof(&test_key("ctl-a"), &body.signing_bytes()),
        );
        assert_eq!(
            two.channel.submit(0, genuine),
            SubmitResult::OutOfWindow { floor: 1 }
        );
    }

    #[test]
    fn a_malformed_floor_record_refuses_relative_commands_for_the_run_and_leaves_the_rest_working()
    {
        let mut medium = blank_medium();
        {
            let (mut journal, _) = Journal::open(&mut medium, limits()).unwrap();
            journal
                .put(Namespace::Records, SEQ_FLOORS_KEY, &[9, 0])
                .unwrap();
        }
        let mut one = Incarnation::boot(&mut medium, Owner::Faithful);
        assert_eq!(
            one.floors,
            Some(RestoredFloors::Refusing(FloorCause::Malformed(
                DecodeError::Format(9)
            )))
        );
        // Refused: a relative command, from either role, is answered unknown and not applied.
        for (peer, seq) in [("panel", 1), ("ctl-a", 1)] {
            let request = one.relative(peer, seq, 5);
            assert_eq!(
                one.channel.submit(0, request),
                SubmitResult::OutOfWindow { floor: u64::MAX }
            );
        }
        assert_eq!(one.session.group_master_volume, BASE);
        // Permitted: absolute and stop commands, which are repeatable, still work, so the group stays controllable.
        assert!(committed(&one.run("panel", 1, set_group(70)).unwrap()));
        assert!(committed(&one.run("ctl-a", 2, set_group(75)).unwrap()));
        assert!(committed(&one.run("panel", 2, stop()).unwrap()));
        assert_eq!(one.session.group_master_volume, 75);
        // The sentinel is never stored.
        let stored = one
            .journal
            .as_ref()
            .unwrap()
            .state()
            .records
            .get(SEQ_FLOORS_KEY)
            .cloned();
        assert_eq!(stored, Some(vec![9, 0]));
    }

    #[test]
    fn a_plain_step_reserves_nothing_and_floors_offered_after_the_first_step_are_an_error() {
        let mut medium = blank_medium();
        let mut one = Incarnation::boot(&mut medium, Owner::NeverStores);
        let request = one.relative("panel", 1, 5);
        assert!(committed(&one.deliver(request, "panel", 1).unwrap()));
        assert!(one.channel.seq_floors().is_empty());
        let mut other = blank_medium();
        let opened = Journal::open(&mut other, limits());
        assert_eq!(
            restore_seq_floors_from_open(&mut one.channel, &opened),
            Err(HighWaterError::AlreadyRunning)
        );
    }

    #[test]
    fn absolute_and_stop_commands_write_no_floor_record() {
        let mut medium = blank_medium();
        let mut one = Incarnation::boot(&mut medium, Owner::Faithful);
        assert!(committed(&one.run("ctl-a", 1, set_group(60)).unwrap()));
        assert!(committed(&one.run("panel", 1, mute(true)).unwrap()));
        assert!(committed(&one.run("panel", 2, stop()).unwrap()));
        assert_eq!(
            one.journal
                .as_ref()
                .unwrap()
                .state()
                .records
                .get(SEQ_FLOORS_KEY),
            None
        );
        assert!(one.channel.seq_floors().is_empty());
    }

    #[test]
    fn sixteen_identities_make_a_record_the_standard_journal_holds_and_a_restart_restores_in_full()
    {
        let peers: Vec<PeerId> = (0..16).map(|i| id(&format!("peer-{i:02}"))).collect();
        let mut table = SeqFloors::new();
        for (i, peer) in peers.iter().enumerate() {
            table = table
                .raised(peer, 100 + u64::try_from(i).unwrap())
                .expect("room for sixteen identities");
        }
        assert_eq!(table.len(), 16);
        // A seventeenth is refused rather than evicting one; the sixteen keep raising.
        assert_eq!(table.raised(&id("seventeenth"), 1), None);
        assert!(table.raised(&peers[0], 500).is_some());
        let packed = table.encode();
        assert_eq!(packed.len(), MAX_ENCODED_LEN);
        assert_eq!(MAX_ENCODED_LEN, 226);
        let mut medium = blank_medium();
        {
            let (mut journal, _) = Journal::open(&mut medium, limits()).unwrap();
            journal
                .put(Namespace::Records, SEQ_FLOORS_KEY, &packed)
                .unwrap();
        }
        let mut reborn = MemStorage::from_image(limits().segment_bytes, medium.durable());
        let two = Incarnation::boot(&mut reborn, Owner::Faithful);
        assert_eq!(two.floors, Some(RestoredFloors::Table { identities: 16 }));
        for (i, peer) in peers.iter().enumerate() {
            assert_eq!(
                two.channel.seq_floors().floor_of(peer),
                Some(100 + u64::try_from(i).unwrap())
            );
        }
    }

    #[test]
    fn the_smallest_journal_holds_two_identities_and_refuses_a_third_without_poisoning() {
        let lim = Limits::tiny();
        let mut medium = MemStorage::new(lim.segment_bytes);
        let (mut journal, _) = Journal::open(&mut medium, Limits::tiny()).unwrap();
        let mut table = SeqFloors::new();
        for name in ["peer-00", "peer-01"] {
            table = table.raised(&id(name), 1).unwrap();
        }
        assert!(table.encode().len() <= lim.records.value_max);
        journal
            .put(Namespace::Records, SEQ_FLOORS_KEY, &table.encode())
            .unwrap();
        let three = table.raised(&id("peer-02"), 1).unwrap();
        assert!(three.encode().len() > lim.records.value_max);
        assert!(
            journal
                .put(Namespace::Records, SEQ_FLOORS_KEY, &three.encode())
                .is_err()
        );
        // A refused record is nothing written, so the journal is still usable.
        assert!(!journal.is_poisoned());
        assert!(journal.raise_mark(HIGH_WATER_KEY, 3).is_ok());
    }

    // ------------------------------------------------------------ the transaction, the latch, the bridge

    /// A first process with a failed store: `set_group(60)` (number 1) commits, then the next turn's storage is cut at
    /// its first operation. Returns the incarnation, with the channel latched, and what the journal holds.
    fn latched_after_one_command(medium: &mut MemStorage) -> Incarnation<'_> {
        let mut one = Incarnation::boot(medium, Owner::Faithful);
        assert!(committed(&one.run("panel", 1, set_group(60)).unwrap()));
        assert_eq!(one.channel.durability(), Durability::Healthy);
        let next = one.ops_done();
        one.arm_cut(next, 0);
        let failed = one.run("panel", 2, set_group(70));
        assert!(
            failed
                .as_ref()
                .is_err_and(|e| e.starts_with("STORE-FAILED")),
            "{failed:?}"
        );
        assert!(matches!(
            one.channel.durability(),
            Durability::Failed { .. }
        ));
        one
    }

    #[test]
    fn a_latched_path_still_silences_for_the_local_user_and_refuses_everything_else_without_touching_the_journal()
     {
        let mut medium = blank_medium();
        let mut one = latched_after_one_command(&mut medium);
        assert_eq!(
            one.session.group_master_volume, 60,
            "the failed step left no trace"
        );
        let (ops, mark, frames) = (
            one.ops_done(),
            one.stored_mark(),
            one.journal.as_ref().unwrap().frames_written(),
        );

        // Permitted: the person at the device can mute and stop, with the journal poisoned.
        assert!(committed(&one.run("panel", 3, mute(true)).unwrap()));
        assert!(committed(&one.run("panel", 4, stop()).unwrap()));
        // Refused, by name and not recorded: nothing that raises volume or lifts silence gets through, from any role.
        let refused = Outcome::Refused(Refusal::InternalFault);
        assert_eq!(one.run("panel", 5, set_group(90)).unwrap(), refused);
        let relative = one.relative("panel", 6, 5);
        assert_eq!(one.deliver(relative, "panel", 6).unwrap(), refused);
        assert_eq!(one.run("panel", 7, mute(false)).unwrap(), refused);
        assert_eq!(one.run("ctl-a", 1, set_group(90)).unwrap(), refused);
        // The legacy bridge is a controller: its stop is refused like any controller's (the local user's is not).
        assert_eq!(one.run("ctl-a", 2, stop()).unwrap(), refused);
        assert_eq!(one.session.group_master_volume, 60);
        // Fast: no copy of the session was written to the journal, no operation was started, no mark moved.
        assert_eq!(
            (
                one.ops_done(),
                one.stored_mark(),
                one.journal.as_ref().unwrap().frames_written()
            ),
            (ops, mark, frames)
        );
        // Not recorded: the same request is judged afresh, not answered with the refusal.
        let again = one.request("panel", 5, set_group(90));
        assert!(matches!(
            one.channel.submit(0, again),
            SubmitResult::Queued { .. }
        ));
    }

    #[test]
    fn reopening_the_journal_clears_the_latch_and_what_was_refused_while_it_held_can_be_sent_again()
    {
        let mut medium = blank_medium();
        let mut one = latched_after_one_command(&mut medium);
        let refused = one.run("panel", 5, set_group(90)).unwrap();
        assert_eq!(refused, Outcome::Refused(Refusal::InternalFault));
        // The owner drops the failed journal and opens what the medium kept.
        let image = one.journal.as_ref().unwrap().storage().durable().to_vec();
        let mut copy = MemStorage::from_image(limits().segment_bytes, &image);
        let opened = Journal::open(&mut copy, limits());
        assert_eq!(
            reopen_from_open(&mut one.channel, &opened),
            Reopened::Healthy {
                mark: Some(3),
                identities: 0
            }
        );
        assert_eq!(one.channel.durability(), Durability::Healthy);
        let (mut fresh, _) = opened.unwrap();
        // The same request, same number, now applies: the latch refusal was never recorded.
        let again = one.request("panel", 5, set_group(90));
        assert!(matches!(
            one.channel.submit(0, again),
            SubmitResult::Queued { .. }
        ));
        let settled = step_then_store(&mut one.channel, 0, &mut one.session, &mut fresh).unwrap();
        assert!(committed(&settled[0].outcome), "{settled:?}");
        assert_eq!(one.session.group_master_volume, 90);
        assert_eq!(fresh.state().marks.get(HIGH_WATER_KEY), Some(&4));
        // A medium that cannot be opened leaves the latch where it was.
        let mut blank = blank_medium();
        let mut dead = MemStorage::from_image(limits().segment_bytes, blank.durable());
        dead.power_cut(0, false);
        let unreadable = Journal::open(&mut dead, limits());
        let mut other = Incarnation::boot(&mut blank, Owner::Faithful);
        other.channel.latch_durability("test");
        assert_eq!(
            reopen_from_open(&mut other.channel, &unreadable),
            Reopened::StillFailed(Cause::OpenFailed("storage"))
        );
        assert_eq!(
            other.channel.durability(),
            Durability::Failed { code: "test" }
        );
    }

    /// Two absolute commands in one step, whose mark store is cut at its last operation with every unsynced byte kept:
    /// the failure is reported, and the medium took the write, so the journal is ahead of the session that was rolled
    /// back. After a reopen the next command must still apply (`MarkRegressed` would lock the channel out).
    #[test]
    fn a_write_the_medium_took_despite_the_error_does_not_lock_the_channel_out_after_a_reopen() {
        // The twin run learns where the two-command step's mark store ends and how many bytes it leaves unsynced.
        let (last, kept) = {
            let mut twin_medium = blank_medium();
            let mut twin = Incarnation::boot(&mut twin_medium, Owner::Faithful);
            assert!(committed(&twin.run("panel", 1, set_group(60)).unwrap()));
            for (seq, volume) in [(2, 70), (3, 71)] {
                let request = twin.request("panel", seq, set_group(volume));
                assert!(matches!(
                    twin.channel.submit(0, request),
                    SubmitResult::Queued { .. }
                ));
            }
            assert_eq!(twin.turn_step().delivered.len(), 2);
            let after = twin.ops_done();
            (after - 1, twin.pending_before()[after - 1])
        };
        let mut medium = blank_medium();
        let mut one = Incarnation::boot(&mut medium, Owner::Faithful);
        assert!(committed(&one.run("panel", 1, set_group(60)).unwrap()));
        one.arm_cut(last, kept);
        for (seq, volume) in [(2, 70), (3, 71)] {
            let request = one.request("panel", seq, set_group(volume));
            assert!(matches!(
                one.channel.submit(0, request),
                SubmitResult::Queued { .. }
            ));
        }
        let turn = one.turn_step();
        assert!(turn.store_failed && turn.delivered.is_empty());
        // Rolled back: the live session is at revision 3 with volume 60, and the channel is latched.
        assert_eq!(
            (one.session.group_master_volume, one.session.state_revision),
            (60, 3)
        );
        assert!(matches!(
            one.channel.durability(),
            Durability::Failed { .. }
        ));
        // The medium kept the new image: the journal is ahead of the session (mark 5 against revision 3).
        let image = one.journal.as_ref().unwrap().storage().durable().to_vec();
        let mut copy = MemStorage::from_image(limits().segment_bytes, &image);
        let opened = Journal::open(&mut copy, limits());
        assert_eq!(
            reopen_from_open(&mut one.channel, &opened),
            Reopened::Healthy {
                mark: Some(5),
                identities: 0
            }
        );
        let (mut fresh, _) = opened.unwrap();
        // The next command would offer revision 4, below the stored 5. The channel offers the larger, so the store is
        // the same mark (nothing to write) and the command applies; without the reopen's merge every later step would
        // fail as `MarkRegressed`.
        assert_eq!(one.channel.high_water(&one.session), 5);
        let next = one.request("panel", 4, set_group(80));
        assert!(matches!(
            one.channel.submit(0, next),
            SubmitResult::Queued { .. }
        ));
        let settled = step_then_store(&mut one.channel, 0, &mut one.session, &mut fresh).unwrap();
        assert!(committed(&settled[0].outcome), "{settled:?}");
        assert_eq!(one.session.group_master_volume, 80);
        assert_eq!(fresh.state().marks.get(HIGH_WATER_KEY), Some(&5));
    }

    #[test]
    fn an_identity_with_unstable_retry_numbers_gets_no_floor_and_a_stable_one_gets_exactly_one() {
        let mut medium = blank_medium();
        let survivor = {
            let mut one = Incarnation::boot(&mut medium, Owner::Faithful);
            assert!(one.channel.declare_unstable_retry_ids(&id("ctl-a")));
            let frames = one.journal.as_ref().unwrap().frames_written();
            // Forty relative commands from the bridge: one frame each (the mark), none for a floor.
            for seq in 1..=40u64 {
                let request = one.relative("ctl-a", seq, if seq % 2 == 1 { 1 } else { -1 });
                assert!(
                    committed(&one.deliver(request, "ctl-a", seq).unwrap()),
                    "{seq}"
                );
            }
            assert_eq!(one.journal.as_ref().unwrap().frames_written(), frames + 40);
            assert_eq!(
                one.journal
                    .as_ref()
                    .unwrap()
                    .state()
                    .records
                    .get(SEQ_FLOORS_KEY),
                None
            );
            assert!(one.channel.seq_floors().is_empty());
            assert_eq!(one.channel.seq_floor(&id("ctl-a")), None);
            // A tailnet-style relative command of a stable identity writes its floor first, then the mark.
            let after = one.journal.as_ref().unwrap().frames_written();
            let stable = one.relative("panel", 1, 5);
            assert!(committed(&one.deliver(stable, "panel", 1).unwrap()));
            assert_eq!(one.journal.as_ref().unwrap().frames_written(), after + 2);
            assert_eq!(one.channel.seq_floor(&id("panel")), Some(1));
            one.session.clone()
        };
        let mut reborn = MemStorage::from_image(limits().segment_bytes, medium.durable());
        let mut two = Incarnation::boot_over(&mut reborn, Owner::Faithful, survivor);
        assert!(two.channel.declare_unstable_retry_ids(&id("ctl-a")));
        assert_eq!(two.floors, Some(RestoredFloors::Table { identities: 1 }));
        // The stable identity's pre-restart number is unknown. The bridge's is not: it has no floor, and the channel
        // does not pretend to deduplicate it (a plain retry of a legacy relative change applies again).
        let stable_dup = two.request_at("panel", 1, Some(42), adjust(5));
        assert_eq!(
            two.channel.submit(0, stable_dup),
            SubmitResult::OutOfWindow { floor: 1 }
        );
        let bridge_dup = two.request_at("ctl-a", 40, Some(two.session.state_revision), adjust(-1));
        assert!(matches!(
            two.channel.submit(0, bridge_dup),
            SubmitResult::Queued { .. }
        ));
        // The table of unstable identities is bounded at sixteen.
        for i in 0..15 {
            assert!(
                two.channel
                    .declare_unstable_retry_ids(&id(&format!("legacy-{i:02}")))
            );
        }
        assert!(!two.channel.declare_unstable_retry_ids(&id("one-too-many")));
    }

    #[test]
    fn a_failed_step_leaves_the_counters_the_log_and_every_older_outcome_as_they_were() {
        let mut medium = blank_medium();
        let mut one = Incarnation::boot(&mut medium, Owner::Faithful);
        let config = LogConfig::new("run-1", "case-1", 4096, 1_048_576).unwrap();
        one.channel
            .enable_log(ChannelLog::new(config, LogKey::new([7; 32])));
        // Fill the ledger with acknowledged-looking history: one outcome per slot.
        let capacity = ChannelConfig::provisional().ledger_capacity;
        for seq in 1..=u64::try_from(capacity).unwrap() {
            let volume = u8::try_from(seq % 90).unwrap();
            assert!(committed(
                &one.run("panel", seq, set_group(volume)).unwrap()
            ));
        }
        assert_eq!(one.channel.diagnostics(&one.session).ledger_len, capacity);
        let committed_before = one.channel.stats().committed;
        let lines_before = one.channel.log().unwrap().lines().count();
        let revision_before = one.session.state_revision;
        // A step that evicts the oldest outcome and then fails to store.
        let next = one.ops_done();
        one.arm_cut(next, 0);
        let failed = one.run("ctl-a", 1, set_group(95));
        assert!(
            failed
                .as_ref()
                .is_err_and(|e| e.starts_with("STORE-FAILED")),
            "{failed:?}"
        );
        // Counters and session are as they were...
        assert_eq!(one.channel.stats().committed, committed_before);
        assert_eq!(one.session.state_revision, revision_before);
        // ...the log holds one new record, a critical one that says a store failed, and none that says committed...
        let lines: Vec<&str> = one.channel.log().unwrap().lines().collect();
        assert_eq!(lines.len(), lines_before + 1);
        let last = lines.last().unwrap();
        assert!(last.contains("store_failed_"), "{last}");
        assert!(
            !lines[lines_before..]
                .iter()
                .any(|l| l.contains("n02.step.committed")),
            "a committed record for an effect that never happened"
        );
        // ...and every older outcome still answers as it did, the oldest included, which the step had evicted.
        let oldest = one.request_at("panel", 1, None, set_group(1));
        assert!(
            matches!(
                one.channel.submit(0, oldest),
                SubmitResult::Settled(Outcome::Committed { .. })
            ),
            "the oldest acknowledged outcome was lost to a step that did not stand"
        );
        // The step's own outcome was never recorded.
        let theirs = one.request("ctl-a", 1, set_group(95));
        assert!(matches!(
            one.channel.submit(0, theirs),
            SubmitResult::Queued { .. }
        ));
    }

    #[test]
    fn a_retry_after_a_failed_step_and_a_reopen_is_logged_exactly_once() {
        let mut medium = blank_medium();
        let mut one = Incarnation::boot(&mut medium, Owner::Faithful);
        let config = LogConfig::new("run-1", "case-1", 4096, 1_048_576).unwrap();
        one.channel
            .enable_log(ChannelLog::new(config, LogKey::new([7; 32])));
        assert!(committed(&one.run("panel", 1, set_group(60)).unwrap()));
        let next = one.ops_done();
        one.arm_cut(next, 0);
        assert!(one.run("panel", 2, set_group(70)).is_err());
        let image = one.journal.as_ref().unwrap().storage().durable().to_vec();
        let mut copy = MemStorage::from_image(limits().segment_bytes, &image);
        let opened = Journal::open(&mut copy, limits());
        assert!(matches!(
            reopen_from_open(&mut one.channel, &opened),
            Reopened::Healthy { .. }
        ));
        let (mut fresh, _) = opened.unwrap();
        let retry = one.request("panel", 2, set_group(70));
        assert!(matches!(
            one.channel.submit(0, retry),
            SubmitResult::Queued { .. }
        ));
        let settled = step_then_store(&mut one.channel, 0, &mut one.session, &mut fresh).unwrap();
        assert!(committed(&settled[0].outcome), "{settled:?}");
        // Number 2 has one terminal record in all: the retry's.
        let committed_lines = one
            .channel
            .log()
            .unwrap()
            .lines()
            .filter(|l| l.contains("n02.step.committed") && l.contains("#2"))
            .count();
        assert_eq!(committed_lines, 1);
    }

    #[test]
    fn an_idle_poll_and_a_pure_refusal_do_not_touch_the_journal_even_when_it_is_poisoned() {
        let mut medium = blank_medium();
        let mut one = Incarnation::boot(&mut medium, Owner::Faithful);
        assert!(committed(&one.run("panel", 1, set_group(60)).unwrap()));
        let (ops, frames) = (
            one.ops_done(),
            one.journal.as_ref().unwrap().frames_written(),
        );
        // Idle: nothing waits, so nothing is staged and nothing is written.
        assert!(one.turn_step().delivered.is_empty());
        assert_eq!(
            (
                one.ops_done(),
                one.journal.as_ref().unwrap().frames_written()
            ),
            (ops, frames)
        );
        // Poison the journal from outside the channel (another writer's fault), without latching the channel.
        let poison_at = one.ops_done();
        one.arm_cut(poison_at, 0);
        let journal = one.journal.as_mut().unwrap();
        assert!(journal.put(Namespace::Records, b"other", b"x").is_err());
        assert!(journal.is_poisoned());
        assert_eq!(one.channel.durability(), Durability::Healthy);
        // A command that is refused changes nothing, so there is nothing to store: it is delivered as refused,
        // and the channel stays healthy.
        // (A controller naming a revision the session has not reached: refused before the session is touched.)
        let ahead = one.request_at("ctl-a", 2, Some(99), set_group(10));
        let outcome = one.deliver(ahead, "ctl-a", 2).unwrap();
        assert!(matches!(
            outcome,
            Outcome::Refused(Refusal::RevisionMismatch { .. })
        ));
        assert_eq!(one.channel.durability(), Durability::Healthy);
        // A command that would change the group needs the mark, the journal cannot take it, and the step is rolled back.
        let failed = one.run("panel", 3, set_group(70));
        assert!(
            failed
                .as_ref()
                .is_err_and(|e| e.starts_with("STORE-FAILED")),
            "{failed:?}"
        );
        assert_eq!(one.session.group_master_volume, 60);
        assert!(matches!(
            one.channel.durability(),
            Durability::Failed { .. }
        ));
    }

    // ------------------------------------------------------ the first failure: silence survives it, evidence is not invented

    /// A healthy channel with one command applied, and a journal whose very next storage operation is cut: the first accepted
    /// step that needs the mark is the one that discovers the fault.
    fn healthy_with_a_dying_journal(medium: &mut MemStorage) -> Incarnation<'_> {
        let mut one = Incarnation::boot(medium, Owner::Faithful);
        assert!(committed(&one.run("panel", 1, set_group(60)).unwrap()));
        assert_eq!(one.channel.durability(), Durability::Healthy);
        let next = one.ops_done();
        one.arm_cut(next, 0);
        one
    }

    fn queue(one: &mut Incarnation<'_>, peer: &str, seq: u64, command: ControlCommand) {
        let request = one.request(peer, seq, command);
        assert!(
            matches!(one.channel.submit(0, request), SubmitResult::Queued { .. }),
            "{peer} {seq}"
        );
    }

    fn seqs(settled: &[Settlement]) -> Vec<u64> {
        let mut seqs: Vec<u64> = settled.iter().map(|s| s.seq).collect();
        seqs.sort_unstable();
        seqs
    }

    #[test]
    fn the_first_local_mute_on_that_discovers_a_failed_store_still_silences_the_live_session() {
        let mut medium = blank_medium();
        let mut one = healthy_with_a_dying_journal(&mut medium);
        let (volume, revision) = (one.session.group_master_volume, one.session.state_revision);
        // Queued together: a volume increase, the local mute-on, and the local unmute that follows it.
        queue(&mut one, "panel", 2, set_group(90));
        queue(&mut one, "panel", 4, mute(true));
        queue(&mut one, "panel", 5, mute(false));
        let journal = one.journal.as_mut().unwrap();
        let failed = step_then_store(&mut one.channel, 0, &mut one.session, journal).unwrap_err();
        // The mute-on took effect on the live session and is to be delivered...
        assert_eq!(seqs(&failed.applied), vec![4]);
        assert!(committed(&failed.applied[0].outcome));
        assert!(
            one.session.members["kitchen"].muted,
            "the first command did not silence"
        );
        // ...and what came with it did not: the increase and the unmute are withheld and unapplied.
        assert_eq!(seqs(&failed.withheld), vec![2, 5]);
        assert_eq!(one.session.group_master_volume, volume);
        assert_eq!(
            one.session.state_revision,
            revision + 1,
            "only the mute advanced the live revision"
        );
        // Its mark is not stored; the path is latched.
        assert_eq!(one.stored_mark(), Some(3));
        assert!(matches!(
            one.channel.durability(),
            Durability::Failed { .. }
        ));
        // A retry of the withheld increase is not answered from the ledger and, the path being latched, is not applied.
        queue(&mut one, "panel", 2, set_group(90));
        let settled = one.channel.step(0, &mut one.session);
        assert_eq!(settled[0].outcome, Outcome::Refused(Refusal::InternalFault));
        assert_eq!(one.session.group_master_volume, volume);
        // The mute-on that took effect is on record: its retry is answered with its outcome, not applied twice.
        let retry = one.request("panel", 4, mute(true));
        assert_eq!(
            one.channel.submit(0, retry),
            SubmitResult::Settled(failed.applied[0].outcome.clone())
        );
    }

    #[test]
    fn the_first_local_stop_that_discovers_a_failed_store_still_stops_the_live_session() {
        let mut medium = blank_medium();
        let mut one = healthy_with_a_dying_journal(&mut medium);
        let lifecycle = format!("{:?}", one.session.members["kitchen"].lifecycle);
        let volume = one.session.group_master_volume;
        queue(&mut one, "panel", 2, set_group(90));
        queue(&mut one, "panel", 3, stop());
        let journal = one.journal.as_mut().unwrap();
        let failed = step_then_store(&mut one.channel, 0, &mut one.session, journal).unwrap_err();
        assert_eq!(seqs(&failed.applied), vec![3]);
        assert_ne!(
            format!("{:?}", one.session.members["kitchen"].lifecycle),
            lifecycle,
            "the first stop did not stop"
        );
        assert_eq!(seqs(&failed.withheld), vec![2]);
        assert_eq!(one.session.group_master_volume, volume);
        assert!(matches!(
            one.channel.durability(),
            Durability::Failed { .. }
        ));
    }

    #[test]
    fn a_journal_poisoned_from_outside_before_the_first_local_mute_on_does_not_lose_it() {
        let mut medium = blank_medium();
        let mut one = Incarnation::boot(&mut medium, Owner::Faithful);
        assert!(committed(&one.run("panel", 1, set_group(60)).unwrap()));
        // Another writer's fault poisons the journal; the channel has not noticed and is not latched.
        let next = one.ops_done();
        one.arm_cut(next, 0);
        assert!(
            one.journal
                .as_mut()
                .unwrap()
                .put(Namespace::Records, b"other", b"x")
                .is_err()
        );
        assert_eq!(one.channel.durability(), Durability::Healthy);
        queue(&mut one, "panel", 2, mute(true));
        queue(&mut one, "panel", 3, set_group(90));
        let journal = one.journal.as_mut().unwrap();
        let failed = step_then_store(&mut one.channel, 0, &mut one.session, journal).unwrap_err();
        assert_eq!(failed.cause, JournalError::Poisoned);
        assert_eq!(seqs(&failed.applied), vec![2]);
        assert!(one.session.members["kitchen"].muted);
        assert_eq!(seqs(&failed.withheld), vec![3]);
        assert_eq!(one.session.group_master_volume, 60);
    }

    #[test]
    fn a_revoked_or_forged_local_mute_on_is_not_applied_by_the_first_failure() {
        let mut medium = blank_medium();
        let mut one = healthy_with_a_dying_journal(&mut medium);
        // A controller's volume increase is what makes the step need the mark. The local mute-on is accepted, and its peer
        // is revoked before the step runs; a second mute-on carries a proof made under another identity's key.
        let revision = one.session.state_revision;
        let increase = one.request_at("ctl-a", 1, Some(revision), set_group(90));
        assert!(matches!(
            one.channel.submit(0, increase),
            SubmitResult::Queued { .. }
        ));
        queue(&mut one, "panel", 2, mute(true));
        one.channel.authority_mut().revoke(&id("panel"));
        let body = RequestBody::new(id("panel"), 3, EPOCH, None, mute(true)).unwrap();
        let forged = ControlRequest::new(
            body.clone(),
            compute_proof(&test_key("ctl-a"), &body.signing_bytes()),
        );
        assert!(matches!(
            one.channel.submit(0, forged),
            SubmitResult::Rejected(Rejection::Unauthenticated(_))
        ));
        let journal = one.journal.as_mut().unwrap();
        let failed = step_then_store(&mut one.channel, 0, &mut one.session, journal).unwrap_err();
        assert!(failed.applied.is_empty(), "{:?}", failed.applied);
        assert!(!one.session.members["kitchen"].muted);
        assert_eq!(one.session.group_master_volume, 60);
        assert!(seqs(&failed.withheld).contains(&1));
    }

    fn log_lines(one: &Incarnation<'_>) -> Vec<serde_json::Value> {
        one.channel
            .log()
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).expect("a shared-schema event"))
            .collect()
    }

    fn enable_log(one: &mut Incarnation<'_>) {
        let config = LogConfig::new("run-1", "case-1", 4096, 1_048_576).unwrap();
        one.channel
            .enable_log(ChannelLog::new(config, LogKey::new([7; 32])));
    }

    /// A request turned away at `submit` for a proof made under the wrong key: its record waits for the next step.
    fn turn_away_a_forged_request(one: &mut Incarnation<'_>) {
        let body = RequestBody::new(
            id("ctl-a"),
            9,
            EPOCH,
            Some(one.session.state_revision),
            set_group(10),
        )
        .unwrap();
        let forged = ControlRequest::new(
            body.clone(),
            compute_proof(&test_key("panel"), &body.signing_bytes()),
        );
        assert!(matches!(
            one.channel.submit(0, forged),
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::BadProof))
        ));
    }

    #[test]
    fn a_rejection_pending_before_a_failed_step_is_logged_once_against_the_live_revision() {
        let mut medium = blank_medium();
        let mut one = Incarnation::boot(&mut medium, Owner::Faithful);
        enable_log(&mut one);
        assert!(committed(&one.run("panel", 1, set_group(60)).unwrap()));
        let live = one.session.state_revision;
        turn_away_a_forged_request(&mut one);
        queue(&mut one, "ctl-a", 2, set_group(70));
        let next = one.ops_done();
        one.arm_cut(next, 0);
        let journal = one.journal.as_mut().unwrap();
        assert!(step_then_store(&mut one.channel, 0, &mut one.session, journal).is_err());
        let lines = log_lines(&one);
        // The genuine rejection is written once, against the revision the session really had...
        let rejected: Vec<_> = lines
            .iter()
            .filter(|l| l["event_kind"] == "n02.submit.rejected.unauthenticated")
            .collect();
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0]["state_revision"], live);
        // ...nothing is stamped with the revision the failed step would have reached, no committed record exists for it,
        // and one critical record says a store failed.
        assert!(lines.iter().all(|l| l["state_revision"] != live + 1));
        assert_eq!(
            lines
                .iter()
                .filter(|l| l["event_kind"] == "n02.step.committed")
                .count(),
            1,
            "only the first command was committed"
        );
        assert_eq!(
            lines
                .iter()
                .filter(|l| l["cause"]
                    .as_str()
                    .is_some_and(|c| c.starts_with("store_failed_")))
                .count(),
            1
        );
        // A step that has nothing to reject writes no second copy of the rejection.
        assert_eq!(one.channel.step(0, &mut one.session).len(), 0);
        assert_eq!(log_lines(&one).len(), lines.len());
    }

    #[test]
    fn the_same_pending_rejection_with_a_successful_store_is_logged_once_before_the_step_it_preceded()
     {
        let mut medium = blank_medium();
        let mut one = Incarnation::boot(&mut medium, Owner::Faithful);
        enable_log(&mut one);
        assert!(committed(&one.run("panel", 1, set_group(60)).unwrap()));
        let live = one.session.state_revision;
        turn_away_a_forged_request(&mut one);
        queue(&mut one, "ctl-a", 2, set_group(70));
        let journal = one.journal.as_mut().unwrap();
        let settled = step_then_store(&mut one.channel, 0, &mut one.session, journal).unwrap();
        assert!(committed(&settled[0].outcome));
        let lines = log_lines(&one);
        let kinds: Vec<(String, u64)> = lines
            .iter()
            .map(|l| {
                (
                    l["event_kind"].as_str().unwrap().to_string(),
                    l["state_revision"].as_u64().unwrap(),
                )
            })
            .collect();
        // The rejection comes first, at the revision before the step; then the committed record, at the revision after it.
        assert_eq!(
            kinds,
            vec![
                ("n02.step.committed".to_string(), live),
                ("n02.submit.rejected.unauthenticated".to_string(), live),
                ("n02.step.committed".to_string(), live + 1),
            ]
        );
    }

    #[test]
    fn a_failed_step_names_a_withheld_command_in_its_one_critical_record_and_not_a_silence_it_then_applies()
     {
        let mut medium = blank_medium();
        let mut one = Incarnation::boot(&mut medium, Owner::Faithful);
        enable_log(&mut one);
        assert!(committed(&one.run("panel", 1, set_group(60)).unwrap()));
        // The local mute-on is the step's first command; a volume increase comes after it.
        queue(&mut one, "panel", 2, mute(true));
        queue(&mut one, "panel", 3, set_group(90));
        let next = one.ops_done();
        one.arm_cut(next, 0);
        let journal = one.journal.as_mut().unwrap();
        let failed = step_then_store(&mut one.channel, 0, &mut one.session, journal).unwrap_err();
        assert_eq!(seqs(&failed.applied), vec![2]);
        let lines = log_lines(&one);
        let correlation = |l: &serde_json::Value| l["correlation_id"].as_str().unwrap().to_string();
        let critical: Vec<_> = lines
            .iter()
            .filter(|l| {
                l["cause"]
                    .as_str()
                    .is_some_and(|c| c.starts_with("store_failed_"))
            })
            .collect();
        assert_eq!(critical.len(), 1, "exactly one critical record");
        assert!(
            correlation(critical[0]).ends_with("#3"),
            "it names the withheld volume set"
        );
        // The mute-on has one record, and it says committed: it is never also logged as refused.
        let about_the_mute: Vec<_> = lines
            .iter()
            .filter(|l| correlation(l).ends_with("#2"))
            .collect();
        assert_eq!(about_the_mute.len(), 1);
        assert_eq!(about_the_mute[0]["event_kind"], "n02.step.committed");
    }

    #[test]
    fn a_step_of_only_a_local_mute_on_and_a_failing_store_still_writes_one_critical_record() {
        let mut medium = blank_medium();
        let mut one = healthy_with_a_dying_journal(&mut medium);
        enable_log(&mut one);
        queue(&mut one, "panel", 2, mute(true));
        let journal = one.journal.as_mut().unwrap();
        let failed = step_then_store(&mut one.channel, 0, &mut one.session, journal).unwrap_err();
        assert_eq!(seqs(&failed.applied), vec![2]);
        assert!(failed.withheld.is_empty());
        assert!(one.session.members["kitchen"].muted);
        let lines = log_lines(&one);
        let critical: Vec<_> = lines
            .iter()
            .filter(|l| {
                l["cause"]
                    .as_str()
                    .is_some_and(|c| c.starts_with("store_failed_"))
            })
            .collect();
        // The fault is not invisible, and it does not name the mute as refused: it carries number 0.
        assert_eq!(critical.len(), 1);
        assert!(
            critical[0]["correlation_id"]
                .as_str()
                .unwrap()
                .ends_with("#0")
        );
        let mute_lines: Vec<_> = lines
            .iter()
            .filter(|l| l["correlation_id"].as_str().unwrap().ends_with("#2"))
            .collect();
        assert_eq!(mute_lines.len(), 1);
        assert_eq!(mute_lines[0]["event_kind"], "n02.step.committed");
    }
}
