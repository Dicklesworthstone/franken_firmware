//! The revision high-water mark on the settings journal (N02 / `ffw-ugf`, over U01 / `ffw-mgb`).
//!
//! The `restart` module gave the channel a way to take a stored mark: after a full process restart
//! the first `step` raises the revision floor to it, so a copy composed against the old history is refused
//! as `StaleRevision`. It left the storing to the owner, in the right order, without help. This module is
//! that storing, over [`franken_journal`]'s monotone `Marks` namespace, and the order is in code.
//!
//! # The three calls
//!
//! * [`restore_from_open`], at boot, before the first `step`: reads the mark from the result of
//!   `Journal::open` and hands it to the channel.
//! * [`step_then_store`], instead of `step`: steps, stores the mark the step reached, and only then
//!   returns the outcomes. **The mark is durable before any outcome that raised it is delivered.** If the
//!   store fails, the outcomes come back inside [`StoreFailed`], withheld, with the journal's error.
//! * [`store_high_water`], the store alone, for an owner that has its own loop.
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
//! * **Bound the wear.** One journal frame is written per step that changed the mark. A stride (storing
//!   ahead by a block of revisions) would cut that, and would lengthen the refusal after a restart; it is not taken.
//!
//! The tests run on U01's in-memory medium with fault injection. That is not a flash part, and nothing
//! here has run on a device.

use franken_journal::{Commit, Journal, JournalError, Recovery, Source, Storage};
use franken_session::UnifiedGroupSession;

use super::{ControlChannel, HighWaterError, Settlement};
use crate::channel::peer::PeerAuthority;

/// The key of the mark in the journal's `Marks` namespace: six bytes, so it fits the smallest configuration
/// (`Limits::tiny()` allows eight) as well as the device one (sixteen).
pub const HIGH_WATER_KEY: &[u8] = b"n02.hw";

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
    /// What the step settled. Each is in the channel's ledger, so a client that asks again is answered with
    /// it; none was delivered, because the mark that covers it is not durable.
    pub withheld: Vec<Settlement>,
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
    journal.raise_mark(HIGH_WATER_KEY, mark)
}

/// `step`, then store the mark, then return the outcomes: none is delivered before the mark that covers it is durable.
///
/// # Errors
/// [`StoreFailed`], holding the journal's error and the outcomes the step settled.
pub fn step_then_store<A: PeerAuthority, S: Storage>(
    channel: &mut ControlChannel<A>,
    now_ns: u64,
    session: &mut UnifiedGroupSession,
    journal: &mut Journal<S>,
) -> Result<Vec<Settlement>, StoreFailed> {
    let settled = channel.step(now_ns, session);
    match store_high_water(channel, session, journal) {
        Ok(_) => Ok(settled),
        Err(cause) => Err(StoreFailed {
            cause,
            withheld: settled,
        }),
    }
}

#[cfg(test)]
mod tests {
    use franken_journal::codec::SEG_HEADER;
    use franken_journal::{Limits, MemStorage};
    use franken_session::AuthorityToken;

    use super::*;
    use crate::channel::limiter::RateLimit;
    use crate::channel::peer::ephemeral::{EphemeralPeers, test_key};
    use crate::channel::peer::{PeerId, PeerRole, compute_proof};
    use crate::channel::pipeline::{ChannelConfig, Outcome, Refusal, SubmitResult};
    use crate::channel::request::{ControlCommand, ControlRequest, RequestBody};
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
    }

    impl<'m> Incarnation<'m> {
        fn boot(medium: &'m mut MemStorage, owner: Owner) -> Self {
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
            let session = fixture_session(EPOCH);
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
                Owner::Faithful | Owner::NeverStores | Owner::DeliversBeforeStoring => {
                    Some(restore_from_open(&mut channel, &opened).unwrap())
                }
            };
            let journal = opened.ok().map(|(journal, _recovery)| journal);
            Self {
                channel,
                session,
                journal,
                owner,
                restored,
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

        /// One owner turn: what the owner delivers after stepping, in the order its fault (or its
        /// faithfulness) gives.
        fn turn_step(&mut self) -> Delivered {
            match self.owner {
                Owner::NeverRestores | Owner::NeverStores => Delivered {
                    delivered: self.channel.step(0, &mut self.session),
                    store_failed: false,
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
        let request = two.request("panel", 1, mute(true));
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
    }

    #[test]
    fn the_key_and_the_value_fit_the_smallest_and_the_device_configuration() {
        for lim in [Limits::tiny(), Limits::standard()] {
            assert!(HIGH_WATER_KEY.len() <= lim.marks.key_max);
            assert!(lim.marks.value_max >= 8, "a mark is eight bytes");
            assert!(lim.marks.entries >= 1);
        }
    }
}
