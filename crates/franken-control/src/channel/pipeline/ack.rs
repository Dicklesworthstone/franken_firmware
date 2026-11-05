//! Acknowledgements: a sender telling the channel it received the outcome of a command (N02 / `ffw-ugf`).
//!
//! A command is settled when the channel has recorded its outcome; it is *acknowledged* when the sender
//! says it saw that outcome. The two are different on purpose: the response can be lost (the sender then
//! retries and is answered from the ledger), and an acknowledgement can be slow or lost too.
//!
//! # What an acknowledgement is allowed to do
//!
//! **Almost nothing, and that is the design.** It is a signed note, checked first like every other
//! message, that flips one flag on one ledger entry and bumps one counter. It
//!
//! * never applies, re-applies or resurrects a command: [`ControlChannel::acknowledge`] takes the
//!   session by shared reference, so it cannot write it, and it never touches a queue;
//! * never extends authority: it does not read or change the group lease, the epoch, the key binding or
//!   the revision floor;
//! * never gates anything: no step, no stop, no mute and no ordinary command waits for an acknowledgement.
//!   The local stop is served at the first `step` after it is accepted whether or not acknowledgements
//!   are pending, because nothing in `step` looks at them;
//! * never shortens or lengthens retention. An acknowledged outcome is remembered exactly as long as an
//!   unacknowledged one, so a retry of an acknowledged command is still answered from the ledger.
//!
//! # The typed outcome
//!
//! Every acknowledgement is counted in exactly one [`AckOutcome`] bucket (`ChannelStats::acks_accounted`
//! equals `acks_received`). The ones that complete an entry are `OnTime`, `Late` and `Superseded`, in
//! that order of precedence:
//!
//! * `Superseded`: the command was issued under an epoch older than the session's current one. The
//!   group has moved on; the acknowledgement is recorded as the delivery note it is and nothing else.
//! * `Late`: the first acknowledgement came after the declared `ack_budget_ns`, but while the outcome is
//!   still remembered.
//! * `OnTime`: the first acknowledgement, within the budget.
//!
//! The rest change nothing: `Duplicate`, `NotSettled` (the command is still waiting), `Unknown` (never
//! seen), `OutOfWindow` (forgotten: aged out or evicted), `Mismatch` (a different epoch from the recorded
//! command) and `Unauthenticated`.
//!
//! The acknowledgement path is O(log n) and keeps no per-acknowledgement state beyond that one flag (it
//! builds a few small transient buffers: the bytes it checks and the record it may write). It has no rate
//! limit of its own: the worst a flood can do is be counted, and logged within the share of the diagnostics
//! log that acknowledgements are held to (`diag`), which can never push a command record out.

use franken_session::UnifiedGroupSession;

use super::{ControlChannel, bump};
use crate::channel::diag::AckFact;
use crate::channel::ledger::{Lookup, Marked};
use crate::channel::peer::{AuthFailure, PeerAuthority};
use crate::channel::request::AckRequest;

/// What the channel made of one acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckOutcome {
    /// The first acknowledgement, `age_ns` after the outcome was recorded, inside the budget.
    OnTime { age_ns: u64 },
    /// The first acknowledgement, after the budget (by `over_by_ns`) but inside retention.
    Late { age_ns: u64, over_by_ns: u64 },
    /// The first acknowledgement of a command issued under `epoch`, when the group is at `current`.
    Superseded { epoch: u64, current: u64 },
    /// Already acknowledged. Nothing changed.
    Duplicate,
    /// The command is still waiting in a queue: an acknowledgement cannot precede an outcome.
    NotSettled,
    /// The channel never recorded this command number.
    Unknown,
    /// The command number is forgotten (aged out or evicted): whether it was acknowledged earlier, or
    /// applied, is no longer known. Nothing changed.
    OutOfWindow { floor: u64 },
    /// It names an epoch other than the one the command was issued under.
    Mismatch { recorded_epoch: u64 },
    /// It did not authenticate. Nothing changed but a counter and, within its share, a log record.
    Unauthenticated(AuthFailure),
}

impl<A: PeerAuthority> ControlChannel<A> {
    /// Record that the sender received the outcome of one of its commands.
    ///
    /// `session` is only read, for its epoch. See the module documentation for everything this does not
    /// do. `now_ns` is on the same timebase as `submit` and `step`.
    pub fn acknowledge(
        &mut self,
        now_ns: u64,
        session: &UnifiedGroupSession,
        ack: &AckRequest,
    ) -> AckOutcome {
        let outcome = self.decide_ack(now_ns, session, ack);
        self.log_ack(now_ns, session, ack, outcome);
        outcome
    }

    /// Write the record for `outcome`, if a log is enabled. The outcome is already decided and is not
    /// consulted again, so no log state, full, tiny or absent, can change it.
    fn log_ack(
        &mut self,
        now_ns: u64,
        session: &UnifiedGroupSession,
        ack: &AckRequest,
        outcome: AckOutcome,
    ) {
        let queue_depth = self.ordinary.len() + self.priority.len();
        if let Some(log) = self.log.as_mut() {
            let fact = AckFact {
                peer: ack.body().peer().clone(),
                seq: ack.body().seq(),
                outcome,
                revision: session.state_revision,
                queue_depth,
            };
            log.emit_ack(&fact, now_ns, session.current_epoch, &session.group_id);
        }
    }

    fn decide_ack(
        &mut self,
        now_ns: u64,
        session: &UnifiedGroupSession,
        ack: &AckRequest,
    ) -> AckOutcome {
        bump(&mut self.stats.acks_received);
        let body = ack.body();

        // 1. Authenticate, before anything else is touched.
        if let Err(failure) =
            self.authority
                .authenticate(body.peer(), &body.signing_bytes(), ack.proof())
        {
            bump(&mut self.stats.acks_rejected_unauthenticated);
            return AckOutcome::Unauthenticated(failure);
        }

        // 2. Forget what has aged out, then see what is left.
        self.ledger.expire(now_ns);
        let recorded_epoch = match self.ledger.lookup(body.peer(), body.seq()) {
            Lookup::Settled { body: recorded, .. } => recorded.epoch(),
            Lookup::OutOfWindow { floor } => {
                bump(&mut self.stats.acks_out_of_window);
                return AckOutcome::OutOfWindow { floor };
            }
            Lookup::Unseen => {
                if self.find_pending(body.peer(), body.seq()).is_some() {
                    bump(&mut self.stats.acks_not_settled);
                    return AckOutcome::NotSettled;
                }
                bump(&mut self.stats.acks_unknown);
                return AckOutcome::Unknown;
            }
        };
        if recorded_epoch != body.epoch() {
            bump(&mut self.stats.acks_mismatch);
            return AckOutcome::Mismatch { recorded_epoch };
        }

        // 3. Mark the entry. This is the whole effect.
        match self.ledger.mark_acked(body.peer(), body.seq(), now_ns) {
            Marked::Already => {
                bump(&mut self.stats.acks_duplicate);
                AckOutcome::Duplicate
            }
            // The entry was found a moment ago and nothing runs in between; if it ever were gone, it is
            // reported as never seen rather than guessed at.
            Marked::Absent => {
                bump(&mut self.stats.acks_unknown);
                AckOutcome::Unknown
            }
            Marked::First { age_ns } => {
                let current = session.current_epoch;
                if recorded_epoch < current {
                    bump(&mut self.stats.acks_superseded);
                    AckOutcome::Superseded {
                        epoch: recorded_epoch,
                        current,
                    }
                } else if age_ns > self.config.ack_budget_ns {
                    bump(&mut self.stats.acks_late);
                    AckOutcome::Late {
                        age_ns,
                        over_by_ns: age_ns - self.config.ack_budget_ns,
                    }
                } else {
                    bump(&mut self.stats.acks_on_time);
                    AckOutcome::OnTime { age_ns }
                }
            }
        }
    }

    /// How many remembered outcomes nobody has acknowledged yet. Nothing waits for these to reach zero.
    #[must_use]
    pub fn unacked(&self) -> usize {
        self.ledger.unacked()
    }
}

#[cfg(test)]
mod tests {
    use franken_session::{
        AuthorityToken, FencedControlCommand, GroupCommandPayload, UnifiedGroupSession,
    };

    use super::*;
    use crate::channel::diag::{ChannelLog, LogConfig, LogKey};
    use crate::channel::limiter::RateLimit;
    use crate::channel::peer::ephemeral::{EphemeralPeers, test_key};
    use crate::channel::peer::{PeerId, PeerRole, compute_proof};
    use crate::channel::pipeline::{
        ChannelConfig, ChannelStats, Outcome, Refusal, Settlement, SubmitResult,
    };
    use crate::channel::request::{
        ACK_MAGIC, AckBody, ControlCommand, ControlRequest, RequestBody, WIRE_MAGIC,
    };
    use crate::channel::testkit::fixture_session;

    const EPOCH: u64 = 10;
    const MS: u64 = 1_000_000;
    const BUDGET: u64 = 2_000 * MS;
    const RETENTION: u64 = 30_000 * MS;
    const LEASE_UNTIL: u64 = 100_000 * MS;

    fn id(raw: &str) -> PeerId {
        PeerId::parse(raw).unwrap()
    }

    fn config() -> ChannelConfig {
        let mut c = ChannelConfig::provisional();
        c.ordinary_rate = RateLimit::new(100_000, MS).unwrap();
        c.priority_rate = RateLimit::new(100_000, MS).unwrap();
        c.ordinary_capacity = 64;
        c.ledger_capacity = 128;
        c.session_seq_base = 1_000;
        c.ack_budget_ns = BUDGET;
        c
    }

    fn set_group(volume: u8) -> ControlCommand {
        ControlCommand::SetGroupVolume { volume }
    }

    fn stop() -> ControlCommand {
        ControlCommand::StopGroupPlayback {
            now_ns: 1_000,
            irrevocable_dma_tail_ns: 500,
        }
    }

    /// How a test-side acknowledgement handler behaves. `Honest` is the channel's own `acknowledge`; the
    /// others plant a fault the judges below must notice.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Path {
        Honest,
        /// Treats a late acknowledgement as carrying the command's result and applies it again under
        /// whatever epoch is current.
        ReplaysLateResult {
            volume: u8,
        },
        /// Will not serve any step while acknowledgements are pending.
        StopWaitsForAcks,
    }

    struct Rig {
        channel: ControlChannel<EphemeralPeers>,
        session: UnifiedGroupSession,
        now: u64,
    }

    impl Rig {
        fn new() -> Self {
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
            let mut channel = ControlChannel::new(peers, config()).unwrap();
            let token = AuthorityToken::issue(&session, LEASE_UNTIL);
            channel.install_lease(&session, token, 0).unwrap();
            Self {
                channel,
                session,
                now: 0,
            }
        }

        fn with_log(max_records: usize, max_bytes: usize) -> Self {
            let mut rig = Self::new();
            rig.channel.enable_log(ChannelLog::new(
                LogConfig::new("run-1", "case-1", max_records, max_bytes).unwrap(),
                LogKey::new([7; 32]),
            ));
            rig
        }

        fn log_lines(&self) -> Vec<serde_json::Value> {
            self.channel
                .log()
                .expect("a log is enabled")
                .lines()
                .map(|line| serde_json::from_str(line).expect("a JSON line"))
                .collect()
        }

        fn request(
            &self,
            peer: &str,
            seq: u64,
            epoch: u64,
            command: ControlCommand,
        ) -> ControlRequest {
            let revision = (peer != "panel").then_some(self.session.state_revision);
            let body = RequestBody::new(id(peer), seq, epoch, revision, command).unwrap();
            let proof = compute_proof(&test_key(peer), &body.signing_bytes());
            ControlRequest::new(body, proof)
        }

        fn submit(&mut self, peer: &str, seq: u64, epoch: u64, command: ControlCommand) {
            let request = self.request(peer, seq, epoch, command);
            assert!(matches!(
                self.channel.submit(self.now, request),
                SubmitResult::Queued { .. }
            ));
        }

        fn step(&mut self) -> Vec<Settlement> {
            self.channel.step(self.now, &mut self.session)
        }

        /// Submit one command and step: how it settled.
        fn run(&mut self, peer: &str, seq: u64, epoch: u64, command: ControlCommand) -> Outcome {
            self.submit(peer, seq, epoch, command);
            self.step()
                .into_iter()
                .find(|s| s.peer.as_str() == peer && s.seq == seq)
                .expect("the command settled in this step")
                .outcome
        }

        fn ack_request(&self, peer: &str, key_of: &str, seq: u64, epoch: u64) -> AckRequest {
            let body = AckBody::new(id(peer), seq, epoch).unwrap();
            let proof = compute_proof(&test_key(key_of), &body.signing_bytes());
            AckRequest::new(body, proof)
        }

        fn ack(&mut self, peer: &str, seq: u64, epoch: u64) -> AckOutcome {
            let request = self.ack_request(peer, peer, seq, epoch);
            self.channel.acknowledge(self.now, &self.session, &request)
        }

        /// The test-side handler: the honest one, or one with a planted fault.
        fn ack_via(&mut self, path: Path, peer: &str, seq: u64, epoch: u64) -> AckOutcome {
            let outcome = self.ack(peer, seq, epoch);
            if let Path::ReplaysLateResult { volume } = path
                && matches!(
                    outcome,
                    AckOutcome::Late { .. } | AckOutcome::Superseded { .. }
                )
            {
                // The planted fault: apply the acknowledged command's result under the current epoch.
                let command_seq = self.channel.next_session_seq;
                self.channel.next_session_seq = command_seq + 1;
                self.session
                    .apply_command(FencedControlCommand {
                        epoch: self.session.current_epoch,
                        command_seq,
                        payload: GroupCommandPayload::SetGroupVolume {
                            volume_0_to_100: volume,
                        },
                    })
                    .expect("the planted replay applies");
            }
            outcome
        }

        /// The test-side step: the honest one, or one that waits for acknowledgements to drain.
        fn step_via(&mut self, path: Path) -> Vec<Settlement> {
            if path == Path::StopWaitsForAcks && self.channel.unacked() > 0 {
                return Vec::new();
            }
            self.step()
        }

        fn snapshot(&self) -> serde_json::Value {
            serde_json::to_value(&self.session).unwrap()
        }

        /// The group moves to epoch 11 (a newer issuer is adopted), the owner installs the lease for it,
        /// and the controller's key is rebound.
        fn move_to_epoch_11(&mut self) {
            self.session
                .apply_command(FencedControlCommand {
                    epoch: 11,
                    command_seq: 5,
                    payload: GroupCommandPayload::MarkMemberClockLocked {
                        member_id: "kitchen".to_string(),
                    },
                })
                .expect("a newer epoch is adopted");
            let token = AuthorityToken::issue(&self.session, LEASE_UNTIL);
            self.channel
                .install_lease(&self.session, token, self.now)
                .unwrap();
            self.channel.authority_mut().rebind(&id("ctl-a"), Some(11));
        }
    }

    fn committed(outcome: &Outcome) -> bool {
        matches!(outcome, Outcome::Committed { .. })
    }

    // ------------------------------------------------------------------ the wire form

    #[test]
    fn an_acknowledgement_is_signed_over_fixed_bytes_that_no_request_proof_can_stand_in_for() {
        let body = AckBody::new(id("ctl-a"), 7, 10).unwrap();
        let mut expected = b"FFCA".to_vec(); // magic
        expected.push(1); // version
        expected.push(5); // peer length
        expected.extend_from_slice(b"ctl-a");
        expected.extend_from_slice(&7u64.to_be_bytes());
        expected.extend_from_slice(&10u64.to_be_bytes());
        assert_eq!(body.signing_bytes(), expected);

        // Another purpose, another magic: a request's proof does not verify as an acknowledgement's.
        assert_ne!(ACK_MAGIC, WIRE_MAGIC);
        let key = test_key("ctl-a");
        let as_request = compute_proof(&key, b"FFCP\x01\x05ctl-a");
        let as_ack = compute_proof(&key, &body.signing_bytes());
        assert_ne!(as_request, as_ack);
    }

    #[test]
    fn an_acknowledgement_needs_a_command_number() {
        assert!(AckBody::new(id("ctl-a"), 0, 10).is_err());
        assert!(AckBody::new(id("ctl-a"), 1, 0).is_ok());
    }

    // ------------------------------------------------------------------ the positive case

    #[test]
    fn an_on_time_ack_completes_exactly_once() {
        let mut rig = Rig::new();
        assert!(committed(&rig.run("ctl-a", 1, EPOCH, set_group(61))));
        assert_eq!(rig.channel.unacked(), 1);
        let before = rig.snapshot();

        rig.now = 1_000 * MS;
        assert_eq!(
            rig.ack("ctl-a", 1, EPOCH),
            AckOutcome::OnTime { age_ns: 1_000 * MS }
        );
        assert_eq!(rig.channel.unacked(), 0);
        // A second acknowledgement of the same command completes nothing.
        assert_eq!(rig.ack("ctl-a", 1, EPOCH), AckOutcome::Duplicate);

        let stats = rig.channel.stats();
        assert_eq!(
            (
                stats.acks_received,
                stats.acks_on_time,
                stats.acks_duplicate
            ),
            (2, 1, 1)
        );
        assert_eq!(stats.acks_accounted(), stats.acks_received);
        assert_eq!(rig.snapshot(), before, "an acknowledgement writes nothing");
    }

    #[test]
    fn the_budget_boundary_is_exact() {
        let mut rig = Rig::new();
        rig.run("ctl-a", 1, EPOCH, set_group(61));
        rig.run("ctl-a", 2, EPOCH, set_group(62));
        rig.now = BUDGET;
        assert_eq!(
            rig.ack("ctl-a", 1, EPOCH),
            AckOutcome::OnTime { age_ns: BUDGET }
        );
        rig.now = BUDGET + 1;
        assert_eq!(
            rig.ack("ctl-a", 2, EPOCH),
            AckOutcome::Late {
                age_ns: BUDGET + 1,
                over_by_ns: 1
            }
        );
    }

    // ------------------------------------------------------------------ the retention boundary

    #[test]
    fn a_late_ack_inside_retention_is_recorded_typed_and_counted() {
        let mut rig = Rig::new();
        rig.run("ctl-a", 1, EPOCH, set_group(61));
        rig.now = RETENTION - 1;
        assert_eq!(
            rig.ack("ctl-a", 1, EPOCH),
            AckOutcome::Late {
                age_ns: RETENTION - 1,
                over_by_ns: RETENTION - 1 - BUDGET
            }
        );
        assert_eq!(rig.channel.stats().acks_late, 1);
        assert_eq!(rig.channel.unacked(), 0);
    }

    #[test]
    fn an_ack_at_the_retention_boundary_is_out_of_window_and_changes_nothing() {
        let mut rig = Rig::new();
        rig.run("ctl-a", 1, EPOCH, set_group(61));
        let before = rig.snapshot();
        rig.now = RETENTION;
        assert_eq!(
            rig.ack("ctl-a", 1, EPOCH),
            AckOutcome::OutOfWindow { floor: 1 }
        );
        assert_eq!(rig.snapshot(), before);
        assert_eq!(rig.channel.stats().acks_out_of_window, 1);
        // The ledger agrees: a retry of the same command is unknown too, never re-applied.
        let retry = rig.request("ctl-a", 1, EPOCH, set_group(61));
        assert_eq!(
            rig.channel.submit(rig.now, retry),
            SubmitResult::OutOfWindow { floor: 1 }
        );
    }

    #[test]
    fn an_ack_does_not_change_how_long_an_outcome_is_remembered() {
        let mut rig = Rig::new();
        let original = rig.request("ctl-a", 1, EPOCH, set_group(61));
        rig.channel.submit(rig.now, original.clone());
        rig.step();
        rig.now = MS;
        assert!(matches!(
            rig.ack("ctl-a", 1, EPOCH),
            AckOutcome::OnTime { .. }
        ));
        // Acknowledged, and still answered from the ledger right up to the retention boundary.
        rig.now = RETENTION - 1;
        assert!(matches!(
            rig.channel.submit(rig.now, original),
            SubmitResult::Settled(Outcome::Committed { .. })
        ));
    }

    // ------------------------------------------------------------------ what the ack can name

    #[test]
    fn an_ack_for_a_command_still_waiting_is_not_settled_and_one_never_seen_is_unknown() {
        let mut rig = Rig::new();
        rig.submit("ctl-a", 1, EPOCH, set_group(61));
        assert_eq!(rig.ack("ctl-a", 1, EPOCH), AckOutcome::NotSettled);
        assert_eq!(rig.ack("ctl-a", 99, EPOCH), AckOutcome::Unknown);
        // The command is still waiting, so it settles on the next step and is then acknowledged normally.
        rig.step();
        assert!(matches!(
            rig.ack("ctl-a", 1, EPOCH),
            AckOutcome::OnTime { .. }
        ));
        let stats = rig.channel.stats();
        assert_eq!((stats.acks_not_settled, stats.acks_unknown), (1, 1));
    }

    #[test]
    fn an_ack_naming_another_epoch_than_the_recorded_one_is_a_mismatch_and_changes_nothing() {
        let mut rig = Rig::new();
        rig.run("ctl-a", 1, EPOCH, set_group(61));
        assert_eq!(
            rig.ack("ctl-a", 1, EPOCH - 1),
            AckOutcome::Mismatch {
                recorded_epoch: EPOCH
            }
        );
        assert_eq!(rig.channel.unacked(), 1, "still waiting for its real ack");
        assert!(matches!(
            rig.ack("ctl-a", 1, EPOCH),
            AckOutcome::OnTime { .. }
        ));
    }

    #[test]
    fn an_ack_that_does_not_authenticate_changes_nothing() {
        let mut rig = Rig::new();
        rig.run("ctl-a", 1, EPOCH, set_group(61));
        let forged = rig.ack_request("ctl-a", "panel", 1, EPOCH);
        assert_eq!(
            rig.channel.acknowledge(rig.now, &rig.session, &forged),
            AckOutcome::Unauthenticated(AuthFailure::BadProof)
        );
        let stranger = rig.ack_request("ghost", "ghost", 1, EPOCH);
        assert_eq!(
            rig.channel.acknowledge(rig.now, &rig.session, &stranger),
            AckOutcome::Unauthenticated(AuthFailure::UnknownPeer)
        );
        // Neither marked the entry: the real acknowledgement still completes it, and is not a duplicate.
        assert_eq!(rig.channel.unacked(), 1);
        assert!(matches!(
            rig.ack("ctl-a", 1, EPOCH),
            AckOutcome::OnTime { .. }
        ));
        assert_eq!(rig.channel.stats().acks_rejected_unauthenticated, 2);
    }

    // ------------------------------------------------------------------ authority and superseded commands

    #[test]
    fn an_ack_after_the_epoch_moved_is_superseded_and_leaves_the_group_and_the_lease_alone() {
        let mut rig = Rig::new();
        assert!(committed(&rig.run("ctl-a", 1, EPOCH, set_group(61))));
        rig.move_to_epoch_11();
        assert!(committed(&rig.run("ctl-a", 2, 11, set_group(77))));
        let lease = rig.channel.lease().cloned();
        let before = rig.snapshot();

        // The new command's acknowledgement is ordinary.
        rig.now = 1_000 * MS;
        assert!(matches!(rig.ack("ctl-a", 2, 11), AckOutcome::OnTime { .. }));
        // The old one arrives after the epoch moved: typed, counted, recorded, and inert.
        rig.now = 5_000 * MS;
        assert_eq!(
            rig.ack("ctl-a", 1, EPOCH),
            AckOutcome::Superseded {
                epoch: EPOCH,
                current: 11
            }
        );
        assert_eq!(rig.snapshot(), before);
        assert_eq!(rig.session.group_master_volume, 77);
        assert_eq!(rig.channel.lease().cloned(), lease);
        assert_eq!(rig.channel.stats().acks_superseded, 1);
        assert!(rig.step().is_empty(), "nothing is resurrected");
    }

    #[test]
    fn a_late_ack_after_the_lease_lapsed_extends_nothing() {
        let mut rig = Rig::new();
        let short = AuthorityToken::issue(&rig.session, 10_000 * MS);
        rig.channel.install_lease(&rig.session, short, 0).unwrap();
        assert!(committed(&rig.run("ctl-a", 1, EPOCH, set_group(61))));
        let lease = rig.channel.lease().cloned();

        // The lease ends at 10 s; the acknowledgement arrives at 12 s, past the budget and the lease.
        rig.now = 12_000 * MS;
        assert!(matches!(
            rig.ack("ctl-a", 1, EPOCH),
            AckOutcome::Late { .. }
        ));
        assert_eq!(
            rig.channel.lease().cloned(),
            lease,
            "the lease is untouched"
        );
        // And the channel still refuses group-affecting work for want of a live lease.
        let outcome = rig.run("ctl-a", 2, EPOCH, set_group(90));
        assert!(
            matches!(outcome, Outcome::Refused(Refusal::Lease(_))),
            "{outcome:?}"
        );
        assert_eq!(rig.session.group_master_volume, 61);
    }

    #[test]
    fn an_ack_for_a_withdrawn_command_resurrects_nothing() {
        let mut rig = Rig::new();
        rig.submit("ctl-a", 1, EPOCH, set_group(61));
        rig.submit("ctl-a", 2, EPOCH, ControlCommand::Cancel { target_seq: 1 });
        let settled = rig.step();
        assert!(
            settled
                .iter()
                .any(|s| s.seq == 1 && s.outcome == Outcome::Withdrawn),
            "{settled:?}"
        );
        assert_eq!(rig.session.group_master_volume, 50);

        // The sender acknowledges both outcomes. Neither brings the withdrawn command back.
        assert!(matches!(
            rig.ack("ctl-a", 1, EPOCH),
            AckOutcome::OnTime { .. }
        ));
        assert!(matches!(
            rig.ack("ctl-a", 2, EPOCH),
            AckOutcome::OnTime { .. }
        ));
        assert!(rig.step().is_empty());
        assert_eq!(rig.session.group_master_volume, 50);
        assert_eq!(rig.channel.unacked(), 0);
    }

    // ------------------------------------------------------------------ accounting

    #[test]
    fn every_ack_is_counted_in_exactly_one_bucket() {
        let mut rig = Rig::new();
        rig.run("ctl-a", 1, EPOCH, set_group(61));
        rig.run("ctl-a", 2, EPOCH, set_group(62));
        rig.submit("ctl-a", 3, EPOCH, set_group(63));
        rig.now = 1_000 * MS;
        rig.ack("ctl-a", 1, EPOCH); // on time
        rig.ack("ctl-a", 1, EPOCH); // duplicate
        rig.ack("ctl-a", 3, EPOCH); // still waiting
        rig.ack("ctl-a", 9, EPOCH); // never seen
        rig.ack("ctl-a", 2, 3); // wrong epoch
        let forged = rig.ack_request("ctl-a", "panel", 2, EPOCH);
        rig.channel.acknowledge(rig.now, &rig.session, &forged);
        rig.now = 3_000 * MS;
        rig.ack("ctl-a", 2, EPOCH); // late
        rig.now = RETENTION;
        rig.ack("ctl-a", 2, EPOCH); // forgotten

        let s = *rig.channel.stats();
        assert_eq!(s.acks_received, 8);
        assert_eq!(s.acks_accounted(), s.acks_received);
        assert_eq!(
            (
                s.acks_on_time,
                s.acks_late,
                s.acks_duplicate,
                s.acks_not_settled,
                s.acks_unknown,
                s.acks_mismatch,
                s.acks_rejected_unauthenticated,
                s.acks_out_of_window,
                s.acks_superseded
            ),
            (1, 1, 1, 1, 1, 1, 1, 1, 0)
        );
    }

    // ------------------------------------------------------------------ the judges, and the planted faults

    /// A late acknowledgement for a command the group has moved past is inert: it is typed, and it
    /// changes neither the group, nor the lease, nor the queue. Failures begin with `ACK-TYPE`,
    /// `REPLAYED` or `AUTHORITY`.
    fn judge_late_ack_is_inert(rig: &mut Rig, path: Path) -> Result<(), String> {
        if !committed(&rig.run("ctl-a", 1, EPOCH, set_group(61))) {
            return Err("ACK-TYPE: setup: the first command did not commit".to_string());
        }
        rig.move_to_epoch_11();
        if !committed(&rig.run("ctl-a", 2, 11, set_group(77))) {
            return Err("ACK-TYPE: setup: the second command did not commit".to_string());
        }
        let lease = rig.channel.lease().cloned();
        let before = rig.snapshot();
        rig.now = 5_000 * MS;
        let outcome = rig.ack_via(path, "ctl-a", 1, EPOCH);
        if outcome
            != (AckOutcome::Superseded {
                epoch: EPOCH,
                current: 11,
            })
        {
            return Err(format!("ACK-TYPE: expected Superseded, got {outcome:?}"));
        }
        if rig.snapshot() != before || rig.session.group_master_volume != 77 {
            return Err("REPLAYED: the late acknowledgement changed the group".to_string());
        }
        if rig.channel.lease().cloned() != lease {
            return Err("AUTHORITY: the late acknowledgement changed the lease".to_string());
        }
        if !rig.step().is_empty() {
            return Err("REPLAYED: the late acknowledgement queued work".to_string());
        }
        Ok(())
    }

    /// Ten outcomes nobody has acknowledged, ordinary work waiting, and then the person at the device
    /// presses stop: it is the first thing the next step settles, and the acknowledgements are still
    /// pending afterwards. Failures begin with `STOP-WAITED`.
    fn judge_stop_first_with_pending_acks(rig: &mut Rig, path: Path) -> Result<(), String> {
        for seq in 1..=10u64 {
            let volume = 40 + u8::try_from(seq).unwrap();
            if !committed(&rig.run("ctl-a", seq, EPOCH, set_group(volume))) {
                return Err(format!("STOP-WAITED: setup: command {seq} did not commit"));
            }
        }
        if rig.channel.unacked() != 10 {
            return Err("STOP-WAITED: setup: the acknowledgements are not pending".to_string());
        }
        for seq in 11..=14u64 {
            rig.submit("ctl-a", seq, EPOCH, set_group(90));
        }
        rig.submit("panel", 1, EPOCH, stop());
        let settled = rig.step_via(path);
        match settled.first() {
            Some(first) if first.peer.as_str() == "panel" && committed(&first.outcome) => {}
            other => {
                return Err(format!(
                    "STOP-WAITED: the stop was not the first settlement of the first step: {other:?}"
                ));
            }
        }
        if rig.channel.unacked() < 10 {
            return Err("STOP-WAITED: the acknowledgements were not left pending".to_string());
        }
        Ok(())
    }

    #[test]
    fn the_honest_channel_passes_both_judges() {
        assert_eq!(
            judge_late_ack_is_inert(&mut Rig::new(), Path::Honest),
            Ok(())
        );
        assert_eq!(
            judge_stop_first_with_pending_acks(&mut Rig::new(), Path::Honest),
            Ok(())
        );
    }

    #[test]
    fn the_local_stop_takes_effect_at_the_first_step_even_with_acks_pending() {
        let mut rig = Rig::new();
        assert_eq!(
            judge_stop_first_with_pending_acks(&mut rig, Path::Honest),
            Ok(())
        );
        // And the pending acknowledgements are still welcome afterwards.
        rig.now = 1_000 * MS;
        assert!(matches!(
            rig.ack("ctl-a", 3, EPOCH),
            AckOutcome::OnTime { .. }
        ));
    }

    #[test]
    fn the_planted_channel_that_applies_a_late_acks_result_fails_the_inertness_judge() {
        let mut broken = Rig::new();
        let verdict = judge_late_ack_is_inert(&mut broken, Path::ReplaysLateResult { volume: 61 });
        assert!(
            verdict.as_ref().is_err_and(|e| e.starts_with("REPLAYED")),
            "the planted fault was not caught for the right reason: {verdict:?}"
        );
        // Remove-the-plant control: the plant is what failed it. The same fault leaves the other judge
        // satisfied (no late acknowledgement arrives there), and the honest channel passes this one.
        assert_eq!(
            judge_stop_first_with_pending_acks(
                &mut Rig::new(),
                Path::ReplaysLateResult { volume: 61 }
            ),
            Ok(())
        );
        assert_eq!(
            judge_late_ack_is_inert(&mut Rig::new(), Path::Honest),
            Ok(())
        );
    }

    #[test]
    fn the_planted_channel_whose_stop_waits_behind_pending_acks_fails_the_stop_judge() {
        let mut broken = Rig::new();
        let verdict = judge_stop_first_with_pending_acks(&mut broken, Path::StopWaitsForAcks);
        assert!(
            verdict
                .as_ref()
                .is_err_and(|e| e.starts_with("STOP-WAITED")),
            "the planted fault was not caught for the right reason: {verdict:?}"
        );
        assert_eq!(
            judge_late_ack_is_inert(&mut Rig::new(), Path::StopWaitsForAcks),
            Ok(())
        );
        assert_eq!(
            judge_stop_first_with_pending_acks(&mut Rig::new(), Path::Honest),
            Ok(())
        );
    }

    // ------------------------------------------------------------------ the diagnostics records

    fn kind_of(record: &serde_json::Value) -> String {
        record["event_kind"].as_str().expect("a kind").to_string()
    }

    #[test]
    fn a_permitted_ack_writes_one_correlated_bounded_record() {
        let mut rig = Rig::with_log(64, 65_536);
        rig.run("ctl-a", 1, EPOCH, set_group(61));
        rig.now = 1_000 * MS;
        assert_eq!(
            rig.ack("ctl-a", 1, EPOCH),
            AckOutcome::OnTime { age_ns: 1_000 * MS }
        );
        let lines = rig.log_lines();
        assert_eq!(
            lines.len(),
            2,
            "one command record and one acknowledgement record"
        );
        let (step, ack) = (&lines[0], &lines[1]);
        assert_eq!(kind_of(step), "n02.step.committed");
        assert_eq!(kind_of(ack), "n02.ack.on_time");
        assert_eq!(
            ack["correlation_id"], step["correlation_id"],
            "the two records join"
        );
        assert_eq!(ack["latency_us"], 1_000_000);
        assert_eq!(ack["state_revision"], rig.session.state_revision);
        assert_eq!(ack["source_epoch"], EPOCH);
        assert_eq!(ack["member_id"], "");
        assert_eq!(ack["queue_depth"], 0);
        assert_eq!(ack["message"], "acknowledged 1000000 us after the outcome");
        assert!(ack.get("cause").is_none());
        let stats = rig.channel.log().unwrap().stats();
        assert_eq!((stats.emitted, stats.stored, stats.dropped), (2, 2, 0));
        assert_eq!(stats.ack_stored, 1);
    }

    #[test]
    fn every_outcome_has_its_own_record_and_a_peers_text_is_never_echoed() {
        let mut rig = Rig::with_log(64, 65_536);
        rig.run("ctl-a", 1, EPOCH, set_group(61));
        rig.run("ctl-a", 2, EPOCH, set_group(62));
        rig.submit("ctl-a", 3, EPOCH, set_group(63));
        rig.now = 1_000 * MS;
        rig.ack("ctl-a", 1, EPOCH); // on time
        rig.ack("ctl-a", 1, EPOCH); // duplicate
        rig.ack("ctl-a", 3, EPOCH); // still waiting
        rig.ack("ctl-a", 9, EPOCH); // never seen
        rig.ack("ctl-a", 2, 3); // wrong epoch
        let forged = rig.ack_request("ctl-a", "panel", 2, EPOCH);
        rig.channel.acknowledge(rig.now, &rig.session, &forged);
        let stranger = rig.ack_request("tok-9f3a1c77e0b2", "tok-9f3a1c77e0b2", 5, EPOCH);
        rig.channel.acknowledge(rig.now, &rig.session, &stranger);
        rig.now = 3_000 * MS;
        rig.ack("ctl-a", 2, EPOCH); // late
        rig.now = RETENTION;
        rig.ack("ctl-a", 2, EPOCH); // forgotten

        let acks: Vec<serde_json::Value> = rig
            .log_lines()
            .into_iter()
            .filter(|record| kind_of(record).starts_with("n02.ack."))
            .collect();
        let kinds: Vec<String> = acks.iter().map(kind_of).collect();
        assert_eq!(
            kinds,
            [
                "n02.ack.on_time",
                "n02.ack.rejected.duplicate",
                "n02.ack.rejected.not_settled",
                "n02.ack.rejected.unknown",
                "n02.ack.rejected.mismatch",
                "n02.ack.rejected.unauthenticated",
                "n02.ack.rejected.unauthenticated",
                "n02.ack.late",
                "n02.ack.rejected.out_of_window"
            ]
        );
        assert_eq!(acks[5]["cause"], "bad_proof");
        assert_eq!(acks[6]["cause"], "unknown_peer");
        // The stranger's claimed identifier is only a pseudonym, in the correlation id.
        let log = rig.channel.log().unwrap();
        assert_eq!(
            acks[6]["correlation_id"].as_str().unwrap(),
            format!("{}#5", log.pseudonym_of("tok-9f3a1c77e0b2"))
        );
        for line in log.lines() {
            assert!(!line.contains("9f3a1c77e0b2"), "{line}");
        }
    }

    #[test]
    fn a_superseded_ack_is_recorded_as_superseded_with_both_epochs() {
        let mut rig = Rig::with_log(64, 65_536);
        rig.run("ctl-a", 1, EPOCH, set_group(61));
        rig.move_to_epoch_11();
        rig.now = 5_000 * MS;
        rig.ack("ctl-a", 1, EPOCH);
        let record = rig.log_lines().pop().expect("a record");
        assert_eq!(kind_of(&record), "n02.ack.superseded");
        assert_eq!(record["source_epoch"], 11);
        assert_eq!(
            record["message"],
            "command issued under epoch 10, the group is at 11"
        );
    }

    // ------------------------------------------------------------------ sinks that are absent, full or tiny

    /// Everything an acknowledgement or a command can show the outside world after one fixed script.
    #[derive(Debug, PartialEq)]
    struct Observed {
        results: Vec<String>,
        session: serde_json::Value,
        stats: ChannelStats,
        unacked: usize,
    }

    /// Two commands settle, a third waits; eight different acknowledgements; a flood of fifty on one
    /// command; the waiting command settles; the retention passes. 58 acknowledgements and 3 command
    /// records are handed to the log in all.
    fn script(rig: &mut Rig) -> Observed {
        let first = format!("{:?}", rig.run("ctl-a", 1, EPOCH, set_group(61)));
        let second = format!("{:?}", rig.run("ctl-a", 2, EPOCH, set_group(62)));
        let mut results = vec![first, second];
        rig.submit("ctl-a", 3, EPOCH, set_group(63));
        rig.now = 1_000 * MS;
        for (seq, epoch) in [(1, EPOCH), (1, EPOCH), (3, EPOCH), (9, EPOCH), (2, 3)] {
            results.push(format!("{:?}", rig.ack("ctl-a", seq, epoch)));
        }
        let forged = rig.ack_request("ctl-a", "panel", 2, EPOCH);
        results.push(format!(
            "{:?}",
            rig.channel.acknowledge(rig.now, &rig.session, &forged)
        ));
        rig.now = 3_000 * MS;
        results.push(format!("{:?}", rig.ack("ctl-a", 2, EPOCH)));
        results.push(format!("{:?}", rig.step()));
        for _ in 0..50 {
            results.push(format!("{:?}", rig.ack("ctl-a", 1, EPOCH)));
        }
        rig.now = RETENTION;
        results.push(format!("{:?}", rig.ack("ctl-a", 2, EPOCH)));
        Observed {
            results,
            session: rig.snapshot(),
            stats: *rig.channel.stats(),
            unacked: rig.channel.unacked(),
        }
    }

    #[test]
    fn no_sink_state_changes_a_result_and_every_drop_is_counted() {
        // No log at all is the baseline: the sink is unavailable.
        let baseline = script(&mut Rig::new());

        // Roomy, small, tiny and byte-starved logs: each must give the very same results.
        let configs: [(usize, usize); 6] = [
            (64, 65_536),
            (8, 65_536),
            (2, 65_536),
            (1, 65_536),
            (64, 10),
            (64, 300),
        ];
        for (max_records, max_bytes) in configs {
            let mut rig = Rig::with_log(max_records, max_bytes);
            assert_eq!(
                script(&mut rig),
                baseline,
                "a log of {max_records} records and {max_bytes} bytes changed a result"
            );
            let s = rig.channel.log().unwrap().stats();
            assert_eq!(s.emitted, 61, "58 acknowledgements and 3 command records");
            assert_eq!(
                s.emitted,
                s.stored as u64 + s.dropped,
                "every record is held or counted ({max_records}/{max_bytes})"
            );
            assert!(s.stored <= max_records && s.bytes <= max_bytes);
            assert!(s.ack_stored <= max_records / 2);
            assert!(s.ack_dropped <= s.dropped);
        }

        // Exact counts at the degenerate ends and in the roomy case.
        let stats_for = |max_records: usize, max_bytes: usize| {
            let mut rig = Rig::with_log(max_records, max_bytes);
            script(&mut rig);
            rig.channel.log().unwrap().stats()
        };
        let one_record = stats_for(1, 65_536);
        assert_eq!(
            (
                one_record.stored,
                one_record.dropped,
                one_record.ack_dropped
            ),
            (1, 60, 58),
            "a one-record log keeps the first command record and counts the rest"
        );
        let no_room = stats_for(64, 10);
        assert_eq!(
            (no_room.stored, no_room.dropped, no_room.ack_dropped),
            (0, 61, 58)
        );
        let roomy = stats_for(64, 65_536);
        assert_eq!(
            (
                roomy.stored,
                roomy.ack_stored,
                roomy.ack_dropped,
                roomy.dropped
            ),
            (35, 32, 26, 26),
            "three command records and the acknowledgements' half of the log"
        );
    }

    /// One command record, then more acknowledgements than the log's acknowledgement half can hold (two
    /// hundred forged ones against four places), then three more commands. Every command record must still
    /// be there, and exactly the excess acknowledgements must be dropped and counted. Every failure is
    /// reported, each beginning with `ACK-DROPS` or `COMMAND-RECORDS-LOST`.
    fn judge_ack_flood_keeps_command_records(rig: &mut Rig) -> Result<(), String> {
        let mut problems = Vec::new();
        rig.run("ctl-a", 1, EPOCH, set_group(61));
        let forged = rig.ack_request("ctl-a", "panel", 1, EPOCH);
        for _ in 0..200 {
            let outcome = rig.channel.acknowledge(rig.now, &rig.session, &forged);
            if !matches!(outcome, AckOutcome::Unauthenticated(_)) {
                return Err(format!(
                    "ACK-DROPS: a forged acknowledgement gave {outcome:?}"
                ));
            }
        }
        let s = rig.channel.log().expect("a log is enabled").stats();
        if (s.ack_stored, s.ack_dropped) != (4, 196) {
            problems.push(format!(
                "ACK-DROPS: expected 4 held and exactly the excess 196 dropped, got {} held and {} dropped",
                s.ack_stored, s.ack_dropped
            ));
        }
        for seq in 2..=4u64 {
            let volume = 60 + u8::try_from(seq).unwrap();
            if !committed(&rig.run("ctl-a", seq, EPOCH, set_group(volume))) {
                return Err("COMMAND-RECORDS-LOST: setup: a command did not commit".to_string());
            }
        }
        let commands = rig
            .log_lines()
            .iter()
            .filter(|record| kind_of(record).starts_with("n02.step."))
            .count();
        if commands != 4 {
            problems.push(format!(
                "COMMAND-RECORDS-LOST: {commands} of 4 command records survived the flood"
            ));
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems.join("; "))
        }
    }

    #[test]
    fn a_flood_of_acknowledgements_cannot_crowd_out_command_records() {
        let mut rig = Rig::with_log(8, 65_536);
        assert_eq!(judge_ack_flood_keeps_command_records(&mut rig), Ok(()));
        // Each forged acknowledgement was typed and counted by the channel, whatever the log did with it.
        assert_eq!(rig.channel.stats().acks_rejected_unauthenticated, 200);
        // The owner drains the log; acknowledgements are recorded again.
        assert_eq!(rig.channel.log_mut().unwrap().drain().len(), 8);
        rig.ack("ctl-a", 1, EPOCH);
        assert_eq!(rig.channel.log().unwrap().stats().ack_stored, 1);
    }

    #[test]
    fn the_planted_log_that_gives_acks_the_whole_budget_fails_the_flood_judge() {
        let mut broken = Rig::with_log(8, 65_536);
        broken
            .channel
            .log_mut()
            .expect("a log is enabled")
            .plant_whole_budget_for_acks();
        let message = judge_ack_flood_keeps_command_records(&mut broken)
            .expect_err("the planted log must fail the judge");
        // It fails for both reasons: the acknowledgements took more than their half, and the command
        // records that came after the flood found the log full.
        assert!(
            message.contains("ACK-DROPS") && message.contains("COMMAND-RECORDS-LOST"),
            "{message}"
        );
        // Remove-the-plant control: the same judge on an unplanted log passes.
        assert_eq!(
            judge_ack_flood_keeps_command_records(&mut Rig::with_log(8, 65_536)),
            Ok(())
        );
    }
}
