//! The boot of a durable owner (N02 / `ffw-ugf`): one call that opens the journal, hands the channel what it stored, and
//! returns the stepper that stores from now on.
//!
//! An owner that opens the settings journal, restores the revision mark, restores the relative-command floors and builds
//! the stepper has four things to get right in an order, and each of the ways to get one wrong was a fault the tests plant
//! (`NeverRestores`, `Unrestored`, `IgnoresAFailedOpen`): a mark nobody restored admits a held-back copy, floors nobody
//! restored let a delivered relative command be applied again, an unreadable journal treated as an empty one starts from
//! revision zero. [`boot_durable`] does all of it once, before the channel's first step, and cannot return a stepper that
//! skipped a restore.
//!
//! # What it returns
//!
//! * [`Booted::Durable`]: the journal opened (possibly after recovery, possibly formatted empty because neither segment was
//!   valid: then the mark and the floors are *refusing* for this run, as [`restore_from_open`] and
//!   [`restore_seq_floors_from_open`] say). It holds the [`OwnedDurable`] stepper to put in the request handler's `Context`
//!   and what was restored, for the owner's log and alarm.
//! * [`Booted::Latched`]: the medium could not be opened at all. There is no journal to store in, so the channel is
//!   **latched failed** ([`Durability::Failed`](super::Durability)) from its first step: remote commands are refused (the mark
//!   and the floors are refusing), the local user's stop and mute-on work, nothing else does. The owner raises an alarm and
//!   may try again with [`reopen_from_open`](super::reopen_from_open) once it has a medium that opens.
//!
//! # What it does not do
//!
//! * **Provide a medium.** The storage is the owner's, behind [`Storage`]. No file-backed or flash-backed implementation
//!   exists in this tree; [`RamMedium`](super::RamMedium) is RAM and is lost with the process. [`Limits`] and [`Storage`] are
//!   re-exported here so an owner above this crate names them without a new crate edge (the P01 workspace contract pins the
//!   edges).
//! * **Restore the peers.** The directory of peers is rebuilt from the same journal by `custody::restore_peers`, which needs
//!   the concrete `PeerDirectory` and so is not generic over the channel's authority; the owner calls it on the
//!   `opened` result it already has (or admits its peers after boot with `admit_durably`).
//! * **Restore the session.** G01's.

use franken_journal::{Journal, Recovery};
// `StorageFault` is what every `Storage` method returns: an owner outside this crate (the speaker's file-backed prototype)
// names it to implement `Storage`, with no `franken-journal` edge of its own.
pub use franken_journal::{Limits, Storage, StorageFault};

use super::persist::{
    Cause, LatchedStepper, OwnedDurable, Reopened, Restored, RestoredFloors, reopen_from_open,
    restore_from_open, restore_seq_floors_from_open,
};
use super::{ControlChannel, HighWaterError};
use crate::channel::peer::PeerAuthority;

/// The journal opened and the channel restored from it.
pub struct DurableBoot<S: Storage> {
    /// The stepper that stores from now on: put it in the request handler's `Context`.
    pub stepper: OwnedDurable<S>,
    /// What the mark was restored as.
    pub mark: Restored,
    /// What the floors were restored as.
    pub floors: RestoredFloors,
    /// What the journal found when it opened.
    pub recovery: Recovery,
}

/// What [`boot_durable`] made of a medium.
pub enum Booted<S: Storage> {
    /// Boxed: the journal and what was restored from it are large beside a latched boot.
    /// Opening allocates `size_of::<DurableBoot<S>>()` bytes for this box, separately from the journal's nested allocations.
    /// This allocation precedes the first channel step and is outside the step/datagram measurement windows.
    Durable(Box<DurableBoot<S>>),
    /// The medium could not be opened. The channel is latched failed and refusing. `code` is the journal's error code.
    /// `stepper` is what goes in the request handler's `Context` meanwhile: it stores nothing, and the local user's stop and
    /// mute-on work through it while everything else is refused.
    Latched {
        mark: Restored,
        floors: RestoredFloors,
        code: &'static str,
        stepper: LatchedStepper,
    },
}

/// Open the journal on `storage`, restore the channel's revision mark and relative-command floors from it, and return the
/// stepper. Call it once, after the channel is built and before its first `step`.
///
/// # Errors
/// [`HighWaterError::AlreadyRunning`] if the channel has already stepped: what was stored would arrive too late to cover
/// what it has already applied.
pub fn boot_durable<A: PeerAuthority, S: Storage>(
    channel: &mut ControlChannel<A>,
    storage: S,
    limits: Limits,
) -> Result<Booted<S>, HighWaterError> {
    let opened = Journal::open(storage, limits);
    let mark = restore_from_open(channel, &opened)?;
    let floors = restore_seq_floors_from_open(channel, &opened)?;
    Ok(match opened {
        Ok((journal, recovery)) => Booted::Durable(Box::new(DurableBoot {
            stepper: OwnedDurable::new(journal),
            mark,
            floors,
            recovery,
        })),
        Err(error) => {
            let code = error.code();
            channel.latch_durability(code);
            Booted::Latched {
                mark,
                floors,
                code,
                stepper: LatchedStepper,
            }
        }
    })
}

/// Take a latched owner out of the failed state in one call: open the journal again on `storage`, give the channel what the medium
/// holds ([`reopen_from_open`]: at least its mark, the larger of each identity's floor, the latch cleared) and return the stepper
/// that stores from now on. The owner puts it back in the request handler's `Context` in place of the one that failed.
///
/// Pass a **freshly opened handle** to the medium (the device by path, or a clone of a RAM medium): `Journal::open` takes the
/// storage by value, so a medium that cannot be opened is dropped with the error, and the latch stays where it was.
///
/// # Errors
/// [`Cause`] if the medium cannot be opened or holds no valid state: the channel is left exactly as it was, still latched, and
/// the owner may try again later.
pub fn reopen_durable<A: PeerAuthority, S: Storage>(
    channel: &mut ControlChannel<A>,
    storage: S,
    limits: Limits,
) -> Result<(OwnedDurable<S>, Reopened), Cause> {
    let opened = Journal::open(storage, limits);
    let reopened = reopen_from_open(channel, &opened);
    match (reopened, opened) {
        (Reopened::StillFailed(cause), _) => Err(cause),
        (healthy @ Reopened::Healthy { .. }, Ok((journal, _recovery))) => {
            Ok((OwnedDurable::new(journal), healthy))
        }
        // `reopen_from_open` clears the latch only for a journal that opened, so this is not reachable; it is answered, not
        // trusted, and leaves the latch set.
        (Reopened::Healthy { .. }, Err(error)) => {
            channel.latch_durability(error.code());
            Err(Cause::OpenFailed(error.code()))
        }
    }
}

#[cfg(test)]
mod tests {
    use franken_journal::{MemStorage, Namespace};
    use franken_session::{AuthorityToken, UnifiedGroupSession};

    use super::*;
    use crate::channel::limiter::RateLimit;
    use crate::channel::peer::ephemeral::{EphemeralPeers, test_key};
    use crate::channel::peer::{PeerId, PeerRole, compute_proof};
    use crate::channel::pipeline::{
        Cause, ChannelConfig, Durability, FloorCause, HIGH_WATER_KEY, LatchedStepper, Outcome,
        Refusal, SEQ_FLOORS_KEY, Stepper, SubmitResult,
    };
    use crate::channel::request::{ControlCommand, ControlRequest, RequestBody};
    use crate::channel::seqfloor::SeqFloors;
    use crate::channel::testkit::fixture_session;

    const EPOCH: u64 = 10;
    const MS: u64 = 1_000_000;

    fn id(raw: &str) -> PeerId {
        PeerId::parse(raw).unwrap()
    }

    fn channel_over(session: &UnifiedGroupSession) -> ControlChannel<EphemeralPeers> {
        let mut peers = EphemeralPeers::new();
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
        let token = AuthorityToken::issue(session, 100_000 * MS);
        channel.install_lease(session, token, 0).unwrap();
        channel
    }

    fn relative(seq: u64, revision: u64) -> ControlRequest {
        let body = RequestBody::new(
            id("panel"),
            seq,
            EPOCH,
            Some(revision),
            ControlCommand::AdjustGroupVolume { delta: 5 },
        )
        .unwrap();
        let proof = compute_proof(&test_key("panel"), &body.signing_bytes());
        ControlRequest::new(body, proof)
    }

    fn medium() -> MemStorage {
        MemStorage::new(Limits::standard().segment_bytes)
    }

    fn durable<S: Storage>(booted: Booted<S>) -> DurableBoot<S> {
        match booted {
            Booted::Durable(boot) => *boot,
            Booted::Latched { code, .. } => panic!("latched at boot: {code}"),
        }
    }

    #[test]
    fn a_blank_medium_boots_durable_with_nothing_to_restore() {
        let session = fixture_session(EPOCH);
        let mut channel = channel_over(&session);
        let boot = durable(boot_durable(&mut channel, medium(), Limits::standard()).unwrap());
        assert_eq!(boot.mark, Restored::FreshMedium);
        assert_eq!(boot.floors, RestoredFloors::Nothing);
        assert_eq!(channel.durability(), Durability::Healthy);
        assert!(channel.seq_floors().is_empty());
    }

    #[test]
    fn one_call_restores_the_mark_and_the_floors_a_journal_holds() {
        let mut storage = medium();
        {
            let (mut journal, _) = Journal::open(&mut storage, Limits::standard()).unwrap();
            journal.raise_mark(HIGH_WATER_KEY, 7).unwrap();
            let floors = SeqFloors::new().raised(&id("panel"), 4).unwrap();
            journal
                .put(Namespace::Records, SEQ_FLOORS_KEY, &floors.encode())
                .unwrap();
        }
        let session = fixture_session(EPOCH);
        let mut channel = channel_over(&session);
        let boot = durable(boot_durable(&mut channel, storage, Limits::standard()).unwrap());
        assert_eq!(boot.mark, Restored::Mark(7));
        assert_eq!(boot.floors, RestoredFloors::Table { identities: 1 });
        assert_eq!(channel.high_water(&session), 7);
        assert_eq!(channel.seq_floor(&id("panel")), Some(4));
        // The restored floor is in force: a relative command at or below it is unknown, one above it is queued.
        assert_eq!(
            channel.submit(0, relative(4, 2)),
            SubmitResult::OutOfWindow { floor: 4 }
        );
        assert!(matches!(
            channel.submit(0, relative(5, 2)),
            SubmitResult::Queued { .. }
        ));
    }

    #[test]
    fn a_medium_that_cannot_be_opened_boots_latched_and_refusing() {
        let mut dead = medium();
        dead.power_cut(0, false);
        let session = fixture_session(EPOCH);
        let mut channel = channel_over(&session);
        let booted = boot_durable(&mut channel, dead, Limits::standard()).unwrap();
        let Booted::Latched {
            mark, floors, code, ..
        } = booted
        else {
            panic!("a dead medium booted durable");
        };
        assert_eq!(code, "storage");
        assert_eq!(mark, Restored::Refusing(Cause::OpenFailed("storage")));
        assert_eq!(
            floors,
            RestoredFloors::Refusing(FloorCause::OpenFailed("storage"))
        );
        assert_eq!(channel.durability(), Durability::Failed { code: "storage" });
        assert_eq!(channel.high_water(&session), u64::MAX);
        // Relative commands are unknown for the run...
        assert_eq!(
            channel.submit(0, relative(1, 2)),
            SubmitResult::OutOfWindow { floor: u64::MAX }
        );
    }

    #[test]
    fn a_medium_with_no_valid_state_boots_durable_but_refusing_for_the_run() {
        let mut storage = medium();
        {
            let (mut journal, _) = Journal::open(&mut storage, Limits::standard()).unwrap();
            journal.raise_mark(HIGH_WATER_KEY, 7).unwrap();
        }
        // Both segment headers overwritten: not blank, and nothing valid.
        let segment = Limits::standard().segment_bytes;
        let mut image = storage.durable().to_vec();
        for base in [0, segment] {
            image[base..base + franken_journal::codec::SEG_HEADER].fill(0);
        }
        let storage = MemStorage::from_image(segment, &image);
        let session = fixture_session(EPOCH);
        let mut channel = channel_over(&session);
        let boot = durable(boot_durable(&mut channel, storage, Limits::standard()).unwrap());
        assert_eq!(boot.mark, Restored::Refusing(Cause::Unrecoverable));
        assert_eq!(
            boot.floors,
            RestoredFloors::Refusing(FloorCause::Unrecoverable)
        );
        assert_eq!(channel.high_water(&session), u64::MAX);
        // The journal itself is usable (it was formatted empty): the channel is not latched.
        assert_eq!(channel.durability(), Durability::Healthy);
    }

    #[test]
    fn a_channel_that_has_already_stepped_cannot_be_booted() {
        let mut session = fixture_session(EPOCH);
        let mut channel = channel_over(&session);
        assert!(channel.step(0, &mut session).is_empty());
        assert!(matches!(
            boot_durable(&mut channel, medium(), Limits::standard()),
            Err(HighWaterError::AlreadyRunning)
        ));
    }

    #[test]
    fn what_a_booted_stepper_stores_is_what_the_next_boot_restores() {
        let mut session = fixture_session(EPOCH);
        let mut channel = channel_over(&session);
        let mut boot = durable(boot_durable(&mut channel, medium(), Limits::standard()).unwrap());
        // A relative command from a stable identity: its floor, then the mark, are stored by the booted stepper.
        let request = relative(1, session.state_revision);
        assert!(matches!(
            channel.submit(0, request),
            SubmitResult::Queued { .. }
        ));
        let settled = boot.stepper.step(&mut channel, 0, &mut session).unwrap();
        assert_eq!(settled.len(), 1);
        assert_eq!(session.group_master_volume, 55);
        // The process dies; the medium is all that is left.
        let storage = boot.stepper.into_journal().into_storage();
        let mut reborn = fixture_session(EPOCH);
        let mut channel = channel_over(&reborn);
        let again = durable(boot_durable(&mut channel, storage, Limits::standard()).unwrap());
        assert_eq!(again.mark, Restored::Mark(3));
        assert_eq!(again.floors, RestoredFloors::Table { identities: 1 });
        // The delivered relative command is unknown after the restart, not applied again.
        assert_eq!(
            channel.submit(0, relative(1, 2)),
            SubmitResult::OutOfWindow { floor: 1 }
        );
        assert_eq!(reborn.group_master_volume, 50);
        assert!(channel.step(0, &mut reborn).is_empty());
    }

    #[test]
    fn a_latched_owner_is_reopened_in_one_call_and_steps_durably_again() {
        let mut session = fixture_session(EPOCH);
        let mut channel = channel_over(&session);
        let boot = durable(boot_durable(&mut channel, medium(), Limits::standard()).unwrap());
        // The durable path fails (here: declared so; the failing store itself is tested with `step_then_store`).
        let storage = boot.stepper.into_journal().into_storage();
        channel.latch_durability("test");
        assert_eq!(channel.durability(), Durability::Failed { code: "test" });
        // One call: the medium is opened again, the latch is cleared and the stepper is back.
        let (mut stepper, reopened) =
            reopen_durable(&mut channel, storage, Limits::standard()).unwrap();
        assert_eq!(
            reopened,
            Reopened::Healthy {
                mark: None,
                identities: 0
            }
        );
        assert_eq!(channel.durability(), Durability::Healthy);
        // It steps durably again: the relative command's floor and the mark are stored.
        assert!(matches!(
            channel.submit(0, relative(1, session.state_revision)),
            SubmitResult::Queued { .. }
        ));
        let settled = stepper.step(&mut channel, 0, &mut session).unwrap();
        assert_eq!(settled.len(), 1);
        assert_eq!(session.group_master_volume, 55);
        assert_eq!(
            stepper.journal().state().marks.get(HIGH_WATER_KEY),
            Some(&3)
        );
        assert!(
            stepper
                .journal()
                .state()
                .records
                .contains_key(SEQ_FLOORS_KEY)
        );
    }

    #[test]
    fn a_medium_that_still_cannot_be_opened_leaves_the_latch_where_it_was() {
        let session = fixture_session(EPOCH);
        let mut channel = channel_over(&session);
        let _boot = durable(boot_durable(&mut channel, medium(), Limits::standard()).unwrap());
        channel.latch_durability("test");
        let mut dead = medium();
        dead.power_cut(0, false);
        assert!(matches!(
            reopen_durable(&mut channel, dead, Limits::standard()),
            Err(Cause::OpenFailed("storage"))
        ));
        assert_eq!(channel.durability(), Durability::Failed { code: "test" });
        // The permitted positive, from the same state: a medium that opens clears it.
        assert!(reopen_durable(&mut channel, medium(), Limits::standard()).is_ok());
        assert_eq!(channel.durability(), Durability::Healthy);
    }

    #[test]
    fn a_reopen_over_a_journal_that_is_ahead_of_the_session_offers_the_larger_mark_and_keeps_its_floors()
     {
        // The medium took a write the failed step reported as an error: it holds mark 9 and a floor, the session is at 2.
        let mut storage = medium();
        {
            let (mut journal, _) = Journal::open(&mut storage, Limits::standard()).unwrap();
            journal.raise_mark(HIGH_WATER_KEY, 9).unwrap();
            let floors = SeqFloors::new().raised(&id("panel"), 6).unwrap();
            journal
                .put(Namespace::Records, SEQ_FLOORS_KEY, &floors.encode())
                .unwrap();
        }
        let session = fixture_session(EPOCH);
        let mut channel = channel_over(&session);
        let _boot = durable(boot_durable(&mut channel, medium(), Limits::standard()).unwrap());
        channel.latch_durability("test");
        let (_stepper, reopened) =
            reopen_durable(&mut channel, storage, Limits::standard()).unwrap();
        assert_eq!(
            reopened,
            Reopened::Healthy {
                mark: Some(9),
                identities: 1
            }
        );
        // The channel never offers a mark below the stored one, and a floor the medium took is in force.
        assert_eq!(channel.high_water(&session), 9);
        assert_eq!(
            channel.submit(0, relative(6, 2)),
            SubmitResult::OutOfWindow { floor: 6 }
        );
    }

    fn signed(
        peer: &str,
        seq: u64,
        revision: Option<u64>,
        command: ControlCommand,
    ) -> ControlRequest {
        let body = RequestBody::new(id(peer), seq, EPOCH, revision, command).unwrap();
        let proof = compute_proof(&test_key(peer), &body.signing_bytes());
        ControlRequest::new(body, proof)
    }

    #[test]
    fn a_latched_boot_returns_a_stepper_through_which_the_local_user_can_still_silence_and_nothing_else_works()
     {
        let mut dead = medium();
        dead.power_cut(0, false);
        let mut session = fixture_session(EPOCH);
        let mut channel = channel_over(&session);
        channel
            .authority_mut()
            .admit(
                &id("ctl-a"),
                PeerRole::Controller,
                &test_key("ctl-a"),
                Some(EPOCH),
                1,
            )
            .unwrap();
        let Booted::Latched { mut stepper, .. } =
            boot_durable(&mut channel, dead, Limits::standard()).unwrap()
        else {
            panic!("a dead medium booted durable");
        };
        let mute = ControlCommand::SetMemberMute {
            member_id: "kitchen".to_string(),
            muted: true,
        };
        let volume = ControlCommand::SetGroupVolume { volume: 90 };
        assert!(matches!(
            channel.submit(0, signed("panel", 1, None, mute)),
            SubmitResult::Queued { .. }
        ));
        assert!(matches!(
            channel.submit(0, signed("ctl-a", 1, Some(session.state_revision), volume)),
            SubmitResult::Queued { .. }
        ));
        let settled = stepper.step(&mut channel, 0, &mut session).unwrap();
        // The local mute-on applied; the controller's volume set was refused and nothing was stored.
        assert!(session.members["kitchen"].muted);
        assert_eq!(session.group_master_volume, 50);
        let outcome = |peer: &str| {
            settled
                .iter()
                .find(|s| s.peer.as_str() == peer)
                .map(|s| s.outcome.clone())
        };
        assert!(matches!(outcome("panel"), Some(Outcome::Committed { .. })));
        assert_eq!(
            outcome("ctl-a"),
            Some(Outcome::Refused(Refusal::InternalFault))
        );
        assert_eq!(channel.durability(), Durability::Failed { code: "storage" });
    }

    #[test]
    fn the_latched_stepper_never_lets_a_healthy_channel_step_as_if_it_were_durable() {
        let mut session = fixture_session(EPOCH);
        let mut channel = channel_over(&session);
        assert_eq!(channel.durability(), Durability::Healthy);
        let mut stepper = LatchedStepper;
        let volume = ControlCommand::SetGroupVolume { volume: 90 };
        assert!(matches!(
            channel.submit(0, signed("panel", 1, None, volume)),
            SubmitResult::Queued { .. }
        ));
        let settled = stepper.step(&mut channel, 0, &mut session).unwrap();
        // It latched the channel first, so the volume set was refused instead of applied volatilely.
        assert_eq!(settled[0].outcome, Outcome::Refused(Refusal::InternalFault));
        assert_eq!(session.group_master_volume, 50);
        assert_eq!(
            channel.durability(),
            Durability::Failed { code: "unbacked" }
        );
    }
}
