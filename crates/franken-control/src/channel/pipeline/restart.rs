//! A persisted revision high-water mark: what the channel does across a full process restart (N02 / `ffw-ugf`).
//!
//! # The hole this closes
//!
//! Inside one run, a command composed before the channel started is refused: the channel's *revision
//! floor* is the session's revision at its first `step`, and a volume or mute command naming an older
//! revision is `StaleRevision`. After a **channel** restart over the same session that is enough, because
//! the session's revision only grows. After a **full process** restart the session is rebuilt from
//! persisted intent ("a restored desired group is not a restored live session") and its revision starts
//! over, so the floor starts over too. A copy that a peer or an attacker held back, composed against the
//! old history at revision 4, then names a revision at or above the new floor of 2, and is applied to a
//! group whose history it never saw.
//!
//! # What the channel does about it
//!
//! The owner stores a **high-water mark**: the highest revision the channel's session had reached, taken
//! with [`ControlChannel::high_water`] after every `step`. After a restart it hands the stored mark to the
//! new channel with [`ControlChannel::restore_high_water`], before the first `step`. The first `step` then
//! sets the floor to the larger of the session's revision and the mark. Nothing else changes: the same
//! `StaleRevision` refusal, the same ledger, the same logs.
//!
//! # What it costs, and what it does not solve
//!
//! * **Remote controllers are refused until the session catches up.** A restored session whose revision is
//!   below the mark leaves every remote volume or mute command naming a revision below the mark refused as
//!   `StaleRevision { observed, floor }`, which is the true statement: the group's state is behind the
//!   durable history. The local user is never affected (it is exempt from the revision checks), so the group
//!   stays controllable at the device. Restoring the session at or above the mark is G01's and U01's.
//! * **The mark must be stored before the outcome that raised it is delivered**, or a crash between the two
//!   leaves a client holding a revision above the stored mark. That ordering is the owner's; the channel
//!   cannot enforce an fsync.
//! * A copy composed at exactly the mark against the old history is indistinguishable from a fresh command if
//!   the rebuilt session reaches the mark by a different history. The number alone cannot tell; continuing
//!   the history is G01's.

use franken_session::UnifiedGroupSession;

use super::ControlChannel;
use crate::channel::peer::PeerAuthority;

/// A high-water mark could not be restored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HighWaterError {
    /// The floor is set at the first `step`; a mark offered after it would change nothing.
    #[error("the channel has already stepped: a high-water mark is restored before the first step")]
    AlreadyRunning,
}

impl<A: PeerAuthority> ControlChannel<A> {
    /// Hand the channel the stored high-water mark, before its first `step`. Calling it again before then
    /// keeps the larger. After the first `step` it is refused.
    pub fn restore_high_water(&mut self, revision: u64) -> Result<(), HighWaterError> {
        if self.revision_floor.is_some() {
            return Err(HighWaterError::AlreadyRunning);
        }
        self.restored_high_water = self.restored_high_water.max(revision);
        Ok(())
    }

    /// The mark to store now: the session's revision, or the restored mark if that is higher, so a mark
    /// never goes down. Take it after every `step` and store it before delivering that step's outcomes.
    #[must_use]
    pub fn high_water(&self, session: &UnifiedGroupSession) -> u64 {
        session.state_revision.max(self.restored_high_water)
    }
}

#[cfg(test)]
mod tests {
    use franken_session::{AuthorityToken, UnifiedGroupSession};

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

    /// One incarnation of the process: a session rebuilt at revision 2 and a channel with an empty ledger.
    struct Incarnation {
        channel: ControlChannel<EphemeralPeers>,
        session: UnifiedGroupSession,
    }

    impl Incarnation {
        fn start() -> Self {
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
            Self { channel, session }
        }

        /// A request as a client composes it now: controllers name the session's current revision.
        fn request(&self, peer: &str, seq: u64, command: ControlCommand) -> ControlRequest {
            let revision = (peer != "panel").then_some(self.session.state_revision);
            let body = RequestBody::new(id(peer), seq, EPOCH, revision, command).unwrap();
            let proof = compute_proof(&test_key(peer), &body.signing_bytes());
            ControlRequest::new(body, proof)
        }

        /// Submit and step: how `seq` of `peer` settled.
        fn run(&mut self, peer: &str, seq: u64, command: ControlCommand) -> Outcome {
            let request = self.request(peer, seq, command);
            self.deliver(request, peer, seq)
        }

        fn deliver(&mut self, request: ControlRequest, peer: &str, seq: u64) -> Outcome {
            assert!(matches!(
                self.channel.submit(0, request),
                SubmitResult::Queued { .. }
            ));
            self.channel
                .step(0, &mut self.session)
                .into_iter()
                .find(|s| s.peer.as_str() == peer && s.seq == seq)
                .expect("the command settled in this step")
                .outcome
        }
    }

    fn committed(outcome: &Outcome) -> bool {
        matches!(outcome, Outcome::Committed { .. })
    }

    /// What the persistence layer gives the new incarnation. `Faithful` is the last mark stored; the others
    /// are faults a careless owner could have: nothing stored, a mark stored before the last commits (a
    /// crash between a commit and the store), and a mark that overshoots.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Persisted {
        Faithful,
        Skipped,
        StaleMark,
        TooHigh,
    }

    /// A controller composes a command at revision 4 and it is held back. The first process goes on to
    /// revision 7 and dies. The second is rebuilt at revision 2, and the local user brings the group back
    /// to revision 7. Then a fresh controller command must be admitted (`LOCKED-OUT` if it is not) and the
    /// held-back copy must be refused **exactly** as `StaleRevision { observed: 4, floor: 7 }` (`ADMITTED`
    /// if it was applied, `WRONG-REASON` if it was refused any other way).
    fn judge_a_held_back_copy_does_not_survive_a_process_restart(
        persisted: Persisted,
    ) -> Result<(), String> {
        let mut one = Incarnation::start();
        let mut held_back = None;
        let (mut after_first, mut last) = (0, 0);
        for seq in 1..=5u64 {
            if seq == 3 {
                held_back = Some(one.request("ctl-a", 100, set_group(99)));
            }
            let volume = 60 + u8::try_from(seq).unwrap();
            if !committed(&one.run("ctl-a", seq, set_group(volume))) {
                return Err(format!("setup: command {seq} did not commit"));
            }
            last = one.channel.high_water(&one.session);
            if seq == 1 {
                after_first = last;
            }
        }
        let held_back = held_back.expect("composed at the third command");
        if (after_first, last) != (3, 7) {
            return Err(format!(
                "setup: marks were {after_first} and {last}, not 3 and 7"
            ));
        }

        let mut two = Incarnation::start();
        let restored = match persisted {
            Persisted::Faithful => two.channel.restore_high_water(last),
            Persisted::Skipped => Ok(()),
            Persisted::StaleMark => two.channel.restore_high_water(after_first),
            Persisted::TooHigh => two.channel.restore_high_water(last + 2),
        };
        restored.map_err(|e| format!("RESTORE: {e}"))?;
        for seq in 1..=5u64 {
            if !committed(&two.run("panel", seq, mute(seq % 2 == 1))) {
                return Err(format!("setup: local command {seq} did not commit"));
            }
        }
        if two.session.state_revision != 7 {
            return Err(format!(
                "setup: the rebuilt session is at revision {}, not 7",
                two.session.state_revision
            ));
        }

        let fresh = two.run("ctl-a", 101, set_group(70));
        if !committed(&fresh) {
            return Err(format!(
                "LOCKED-OUT: a fresh controller command composed against the restored session gave {fresh:?}"
            ));
        }
        let copy = two.deliver(held_back, "ctl-a", 100);
        let expected = Outcome::Refused(Refusal::StaleRevision {
            observed: 4,
            floor: 7,
        });
        if committed(&copy) {
            return Err(format!(
                "ADMITTED: the held-back copy was applied after the restart (group volume {})",
                two.session.group_master_volume
            ));
        }
        if copy != expected {
            return Err(format!(
                "WRONG-REASON: the held-back copy gave {copy:?}, not {expected:?}"
            ));
        }
        Ok(())
    }

    #[test]
    fn a_faithful_restart_refuses_the_held_back_copy_and_admits_a_fresh_command() {
        assert_eq!(
            judge_a_held_back_copy_does_not_survive_a_process_restart(Persisted::Faithful),
            Ok(())
        );
    }

    #[test]
    fn each_planted_mark_fault_fails_the_judge_by_name() {
        // A judge that fails everything proves nothing, so the faithful restart passes first.
        assert_eq!(
            judge_a_held_back_copy_does_not_survive_a_process_restart(Persisted::Faithful),
            Ok(())
        );
        for (fault, tag) in [
            (Persisted::Skipped, "ADMITTED"),
            (Persisted::StaleMark, "ADMITTED"),
            (Persisted::TooHigh, "LOCKED-OUT"),
        ] {
            let verdict = judge_a_held_back_copy_does_not_survive_a_process_restart(fault);
            assert!(
                verdict.as_ref().is_err_and(|e| e.starts_with(tag)),
                "{fault:?} was not caught as {tag}: {verdict:?}"
            );
        }
    }

    #[test]
    fn the_mark_follows_every_commit_and_never_goes_down() {
        let mut inc = Incarnation::start();
        assert_eq!(inc.channel.high_water(&inc.session), 2);
        let mut marks = Vec::new();
        for seq in 1..=3u64 {
            let volume = 60 + u8::try_from(seq).unwrap();
            assert!(committed(&inc.run("ctl-a", seq, set_group(volume))));
            marks.push(inc.channel.high_water(&inc.session));
        }
        assert_eq!(marks, [3, 4, 5]);

        // A restored mark above the rebuilt session's revision is what it reports until the session passes it.
        let mut next = Incarnation::start();
        next.channel.restore_high_water(9).unwrap();
        assert_eq!(next.channel.high_water(&next.session), 9);
        // A lower mark does not lower it, and the larger of two is kept.
        next.channel.restore_high_water(4).unwrap();
        assert_eq!(next.channel.high_water(&next.session), 9);
    }

    #[test]
    fn a_mark_is_restored_before_the_first_step_only() {
        let mut inc = Incarnation::start();
        inc.channel.restore_high_water(5).unwrap();
        assert!(committed(&inc.run("panel", 1, mute(true))));
        assert_eq!(
            inc.channel.restore_high_water(50),
            Err(HighWaterError::AlreadyRunning)
        );
        // The refused mark changed nothing.
        assert_eq!(inc.channel.revision_floor(), Some(5));
    }

    #[test]
    fn the_floor_is_the_larger_of_the_first_steps_revision_and_the_mark() {
        for (mark, floor) in [(None, 2), (Some(1), 2), (Some(2), 2), (Some(7), 7)] {
            let mut inc = Incarnation::start();
            if let Some(mark) = mark {
                inc.channel.restore_high_water(mark).unwrap();
            }
            assert_eq!(
                inc.channel.revision_floor(),
                None,
                "unset until the first step"
            );
            assert!(committed(&inc.run("panel", 1, mute(true))));
            assert_eq!(inc.channel.revision_floor(), Some(floor), "mark {mark:?}");
        }
    }

    #[test]
    fn the_local_user_is_never_locked_out_by_a_mark_and_a_remote_controller_is_told_why() {
        let mut inc = Incarnation::start();
        inc.channel.restore_high_water(50).unwrap();
        // The device's own user acts on what is audible; the mark does not touch it.
        assert!(committed(&inc.run("panel", 1, mute(true))));
        // A remote controller that read the rebuilt session (revision 3) is refused, with the true reason.
        let outcome = inc.run("ctl-a", 1, set_group(70));
        assert_eq!(
            outcome,
            Outcome::Refused(Refusal::StaleRevision {
                observed: 3,
                floor: 50
            })
        );
        assert_eq!(inc.session.group_master_volume, 50, "nothing was applied");
    }
}
