//! The records of requests turned away at `submit` (N02 / `ffw-ugf`, section 11).
//!
//! A request that is turned away before it is queued (it did not authenticate, named an epoch its key is not
//! bound to, named no revision, was rate limited, found the queue full, reused a number for another request, or
//! retried a number the ledger has forgotten) used to be counted in [`ChannelStats`](super::ChannelStats) and
//! nothing else. A controller that is refused, and the person debugging it, saw a counter move and could not tell
//! why. This module writes one record for each, in the shape and under the rules of the other records
//! ([`diag`](crate::channel::diag)): peers appear only as keyed pseudonyms, the claimed identifier of a sender
//! that did not authenticate is never echoed, the words come from a fixed vocabulary, and the records are held
//! to a share of the log so that nobody can crowd command records out by sending requests that fail.
//!
//! # When the record is written
//!
//! `submit` has no session, and a record says which epoch and revision it was made under, so `submit` only
//! gathers a fact (the claimed peer, the number, what happened) and the record is written when the session is at
//! hand: at the end of the next [`step`](super::ControlChannel::step), or when the owner calls
//! [`flush_log`](super::ControlChannel::flush_log). The datagram endpoint calls it after every submit, so a
//! record made there carries the epoch and revision the request was turned away under. The facts waiting are
//! bounded by [`MAX_PENDING_REJECTS`]; a request turned away while they are full is counted as a dropped record
//! and nothing else, so a flood of forged requests holds a bounded amount of memory and cannot make the channel
//! wait.
//!
//! # What it does not do
//!
//! * It does not change any result. The fact is gathered after the result is decided and the result is not
//!   consulted again; with no log, a full log or a tiny log, every `submit` returns what it would have returned.
//! * It does not log requests that were queued, found already waiting or answered from the ledger: those were not
//!   turned away, and a retry storm of a settled command is not an incident.
//! * It does not write a file. The owner drains the log, as for every other record.

use franken_session::UnifiedGroupSession;

use super::{ControlChannel, SubmitResult};
use crate::channel::diag::RejectFact;
use crate::channel::peer::{PeerAuthority, PeerId};

/// Most requests turned away that wait for the session to be at hand so their record can be written. A request
/// turned away while this many wait is counted as a dropped record.
pub const MAX_PENDING_REJECTS: usize = 32;

impl<A: PeerAuthority> ControlChannel<A> {
    /// Gather the fact for what `submit` returned for a request that claimed `claimed` (its peer and number), if a
    /// log is enabled and the request was turned away. Changes nothing the caller can see.
    pub(super) fn note_submit(
        &mut self,
        now_ns: u64,
        claimed: Option<(PeerId, u64)>,
        result: &SubmitResult,
    ) {
        let Some((peer, seq)) = claimed else {
            return;
        };
        let queue_depth = self.ordinary.len() + self.priority.len();
        let Some(fact) = RejectFact::new(peer, seq, now_ns, queue_depth, result) else {
            return;
        };
        if self.reject_facts.len() >= MAX_PENDING_REJECTS {
            if let Some(log) = self.log.as_mut() {
                log.note_reject_overflow();
            }
            return;
        }
        self.reject_facts.push(fact);
    }

    /// Write the records of the requests turned away since the last flush, made under the epoch and revision
    /// `session` is at now. `step` does this itself; the owner calls it to have them sooner. Nothing to do, and
    /// nothing done, if no log is enabled.
    pub fn flush_log(&mut self, session: &UnifiedGroupSession) {
        if let Some(log) = self.log.as_mut() {
            for fact in self.reject_facts.drain(..) {
                log.emit_reject(
                    &fact,
                    session.current_epoch,
                    session.state_revision,
                    &session.group_id,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use franken_session::AuthorityToken;

    use super::*;
    use crate::channel::diag::{ChannelLog, LogConfig, LogKey};
    use crate::channel::peer::ephemeral::{EphemeralPeers, test_key};
    use crate::channel::peer::{AuthFailure, PeerRole, compute_proof};
    use crate::channel::pipeline::{ChannelConfig, ChannelStats, Rejection, Settlement};
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

    struct Rig {
        channel: ControlChannel<EphemeralPeers>,
        session: UnifiedGroupSession,
    }

    impl Rig {
        /// Three controllers (one revoked) and the local user, a lease, and a log of the given size if `log` is
        /// `Some((records, bytes))`.
        fn new(config: ChannelConfig, log: Option<(usize, usize)>) -> Self {
            let mut peers = EphemeralPeers::new();
            for (name, role, bound) in [
                ("ctl-a", PeerRole::Controller, Some(EPOCH)),
                ("ctl-b", PeerRole::Controller, Some(EPOCH)),
                ("ctl-c", PeerRole::Controller, Some(EPOCH)),
                ("panel", PeerRole::LocalUser, None),
            ] {
                peers
                    .admit(&id(name), role, &test_key(name), bound, 1)
                    .unwrap();
            }
            assert!(peers.revoke(&id("ctl-b")));
            let session = fixture_session(EPOCH);
            let mut channel = ControlChannel::new(peers, config).unwrap();
            let token = AuthorityToken::issue(&session, 100_000 * MS);
            channel.install_lease(&session, token, 0).unwrap();
            if let Some((records, bytes)) = log {
                channel.enable_log(ChannelLog::new(
                    LogConfig::new("run-1", "case-1", records, bytes).unwrap(),
                    LogKey::new([7; 32]),
                ));
            }
            Self { channel, session }
        }

        /// A request signed with `signer`'s key, naming `peer`.
        fn request(
            &self,
            peer: &str,
            signer: &[u8],
            seq: u64,
            epoch: u64,
            revision: Option<u64>,
            command: ControlCommand,
        ) -> ControlRequest {
            let body = RequestBody::new(id(peer), seq, epoch, revision, command).unwrap();
            let proof = compute_proof(signer, &body.signing_bytes());
            ControlRequest::new(body, proof)
        }

        /// A genuine request from `peer`, composed against the session's revision now.
        fn genuine(&self, peer: &str, seq: u64, volume: u8) -> ControlRequest {
            let revision = (peer != "panel").then_some(self.session.state_revision);
            self.request(
                peer,
                &test_key(peer),
                seq,
                EPOCH,
                revision,
                set_group(volume),
            )
        }

        fn submit(&mut self, now_ns: u64, request: ControlRequest) -> SubmitResult {
            self.channel.submit(now_ns, request)
        }

        fn step(&mut self, now_ns: u64) -> Vec<Settlement> {
            self.channel.step(now_ns, &mut self.session)
        }

        fn records(&self) -> Vec<serde_json::Value> {
            self.channel
                .log()
                .expect("a log is enabled")
                .lines()
                .map(|line| serde_json::from_str(line).expect("a JSON line"))
                .collect()
        }

        /// The records of requests turned away, in the order they were written.
        fn submit_records(&self) -> Vec<serde_json::Value> {
            self.records()
                .into_iter()
                .filter(|r| kind_of(r).starts_with("n02.submit."))
                .collect()
        }
    }

    fn kind_of(record: &serde_json::Value) -> String {
        record["event_kind"]
            .as_str()
            .expect("an event kind")
            .to_string()
    }

    fn config() -> ChannelConfig {
        let mut config = ChannelConfig::provisional();
        config.ordinary_capacity = 8;
        config.retention_ns = 1_000 * MS;
        config.session_seq_base = 1_000;
        config
    }

    #[test]
    fn every_way_a_request_is_turned_away_is_logged_once_with_its_cause() {
        let mut rig = Rig::new(config(), Some((64, 65_536)));
        let revision = Some(rig.session.state_revision);
        let stranger = rig.request(
            "tok-9f3a1c77e0b2",
            b"a key nobody admitted",
            4,
            EPOCH,
            revision,
            set_group(10),
        );
        let wrong_key = rig.request(
            "ctl-a",
            &test_key("panel"),
            2,
            EPOCH,
            revision,
            set_group(10),
        );
        let revoked = rig.genuine("ctl-b", 1, 10);
        let wrong_epoch = rig.request(
            "ctl-a",
            &test_key("ctl-a"),
            3,
            EPOCH - 1,
            revision,
            set_group(10),
        );
        let no_revision = rig.request("ctl-a", &test_key("ctl-a"), 5, EPOCH, None, set_group(10));
        let first = rig.genuine("ctl-a", 1, 70);
        let reused = rig.genuine("ctl-a", 1, 71);
        let answers = [
            rig.submit(0, stranger),
            rig.submit(0, wrong_key),
            rig.submit(0, revoked),
            rig.submit(0, wrong_epoch),
            rig.submit(0, no_revision),
            rig.submit(0, first.clone()),
            rig.submit(0, reused),
        ];
        let rejected = SubmitResult::Rejected;
        assert_eq!(
            answers,
            [
                rejected(Rejection::Unauthenticated(AuthFailure::UnknownPeer)),
                rejected(Rejection::Unauthenticated(AuthFailure::BadProof)),
                rejected(Rejection::Unauthenticated(AuthFailure::Revoked)),
                rejected(Rejection::EpochNotBound {
                    bound: EPOCH,
                    request: EPOCH - 1
                }),
                rejected(Rejection::RevisionRequired {
                    command: "set-group-volume"
                }),
                SubmitResult::Queued {
                    lane: crate::channel::request::Lane::Ordinary
                },
                rejected(Rejection::IdReuse),
            ]
        );
        // The local user fills the ordinary queue (one is already taken) and is then turned away twice.
        for seq in 1..=7u64 {
            let request = rig.genuine("panel", seq, 50);
            assert!(matches!(
                rig.submit(0, request),
                SubmitResult::Queued { .. }
            ));
        }
        let full = rig.genuine("panel", 8, 50);
        let limited = rig.genuine("panel", 9, 50);
        assert_eq!(
            rig.submit(0, full),
            rejected(Rejection::QueueFull {
                lane: crate::channel::request::Lane::Ordinary
            })
        );
        assert!(matches!(
            rig.submit(0, limited),
            SubmitResult::Rejected(Rejection::RateLimited { .. })
        ));
        // Nothing is written until the session is at hand; then one record per request turned away, in order.
        assert_eq!(rig.submit_records().len(), 0);
        assert_eq!(
            rig.step(0).len(),
            4,
            "the step settles what its bound allows"
        );
        // The retry of a number the ledger has forgotten.
        let _ = rig.step(1_000 * MS);
        let forgotten = rig.submit(1_000 * MS, first);
        assert_eq!(forgotten, SubmitResult::OutOfWindow { floor: 1 });
        rig.channel.flush_log(&rig.session);

        let records = rig.submit_records();
        let summary: Vec<(String, Option<String>)> = records
            .iter()
            .map(|r| (kind_of(r), r["cause"].as_str().map(str::to_string)))
            .collect();
        let want = [
            ("n02.submit.rejected.unauthenticated", Some("unknown_peer")),
            ("n02.submit.rejected.unauthenticated", Some("bad_proof")),
            ("n02.submit.rejected.unauthenticated", Some("revoked")),
            ("n02.submit.rejected.epoch_not_bound", None),
            ("n02.submit.rejected.revision_required", None),
            ("n02.submit.rejected.id_reuse", None),
            ("n02.submit.rejected.queue_full", None),
            ("n02.submit.rejected.rate_limited", None),
            ("n02.submit.out_of_window", None),
        ];
        let want: Vec<(String, Option<String>)> = want
            .into_iter()
            .map(|(kind, cause)| (kind.to_string(), cause.map(str::to_string)))
            .collect();
        assert_eq!(summary, want);
        assert_eq!(
            records[3]["message"],
            "key bound to epoch 10, request named 9"
        );
        assert_eq!(
            records[4]["message"],
            "set-group-volume must name the revision it last read"
        );
        assert_eq!(records[6]["message"], "the ordinary queue is full");
        assert!(
            records[7]["message"]
                .as_str()
                .unwrap()
                .starts_with("rate limited on the ordinary lane, retry in ")
        );
        assert_eq!(
            records[8]["message"],
            "forgotten: at or below the remembered floor 1"
        );
        // Each record joins nothing: a request turned away has no command record, and the correlation is the claimed
        // peer's pseudonym and the number it named.
        let log = rig.channel.log().unwrap();
        assert_eq!(
            records[0]["correlation_id"].as_str().unwrap(),
            format!("{}#4", log.pseudonym_of("tok-9f3a1c77e0b2"))
        );
        assert_eq!(
            records[5]["correlation_id"].as_str().unwrap(),
            format!("{}#1", log.pseudonym_of("ctl-a"))
        );
        // The records are written under the epoch and revision the session is at when they are written, and the
        // timestamps never go backwards, whichever kind of record they sit beside.
        for record in &records {
            assert_eq!(record["source_epoch"], EPOCH);
            assert_eq!(record["member_id"], "");
            assert_eq!(record["latency_us"], 0);
            assert_eq!(record["schema_version"], "ffw.log.v1");
        }
        let stamps: Vec<u64> = rig
            .records()
            .iter()
            .map(|r| r["timestamp_mono_ns"].as_u64().unwrap())
            .collect();
        assert!(stamps.windows(2).all(|w| w[0] <= w[1]), "{stamps:?}");
        // Each way a request can be turned away has its counter, and the counters add up to the records written.
        let stats: &ChannelStats = rig.channel.stats();
        assert_eq!(
            (
                stats.rejected_unauthenticated,
                stats.rejected_epoch_not_bound,
                stats.rejected_revision_required,
                stats.rejected_id_reuse,
                stats.rejected_queue_full,
                stats.rejected_rate_limited,
                stats.out_of_window
            ),
            (3, 1, 1, 1, 1, 1, 1)
        );
        assert_eq!(
            stats.rejected_unauthenticated
                + stats.rejected_epoch_not_bound
                + stats.rejected_revision_required
                + stats.rejected_id_reuse
                + stats.rejected_queue_full
                + stats.rejected_rate_limited
                + stats.out_of_window,
            u64::try_from(records.len()).unwrap()
        );
        let log_stats = rig.channel.log().unwrap().stats();
        assert_eq!(log_stats.reject_stored, 9);
        assert_eq!(
            log_stats.emitted,
            log_stats.stored as u64 + log_stats.dropped
        );
    }

    #[test]
    fn a_request_that_was_queued_waiting_or_answered_from_the_ledger_writes_no_record() {
        let mut rig = Rig::new(config(), Some((64, 65_536)));
        let request = rig.genuine("ctl-a", 1, 70);
        assert!(matches!(
            rig.submit(0, request.clone()),
            SubmitResult::Queued { .. }
        ));
        assert!(matches!(
            rig.submit(0, request.clone()),
            SubmitResult::AlreadyQueued { .. }
        ));
        assert_eq!(rig.step(0).len(), 1);
        assert!(matches!(
            rig.submit(0, request.clone()),
            SubmitResult::Settled(_)
        ));
        rig.channel.flush_log(&rig.session);
        assert_eq!(rig.submit_records(), Vec::<serde_json::Value>::new());
        assert_eq!(rig.channel.log().unwrap().stats().reject_stored, 0);
        assert!(rig.channel.reject_facts.is_empty());
    }

    #[test]
    fn a_sender_that_did_not_authenticate_is_never_echoed_only_pseudonymized() {
        let mut rig = Rig::new(config(), Some((64, 65_536)));
        let claimed = "tok-9f3a1c77e0b2";
        let revision = Some(rig.session.state_revision);
        let forged = rig.request(
            claimed,
            b"sk-live-0123456789abcdef",
            7,
            EPOCH,
            revision,
            set_group(10),
        );
        assert!(matches!(rig.submit(0, forged), SubmitResult::Rejected(_)));
        rig.channel.flush_log(&rig.session);
        let log = rig.channel.log().unwrap();
        let everything: String = log.lines().collect::<Vec<_>>().join("\n");
        for piece in [
            "tok-9f3a1c77e0b2",
            "9f3a1c77e0b2",
            "tok-",
            "sk-live",
            "0123456789abcdef",
        ] {
            assert!(
                !everything.contains(piece),
                "the log echoes {piece:?}: {everything}"
            );
        }
        assert!(everything.contains(&log.pseudonym_of(claimed)));
        assert_eq!(log.stats().reject_stored, 1);
        // The summary line is free of anything a sender supplied too.
        assert!(!log.summary_line().contains("9f3a"));
    }

    /// One command record, then more forged requests than the log's share for them can hold (two hundred against
    /// two places, each flushed as it arrives), then three more commands. Every command record must still be there,
    /// and exactly the excess records must be dropped and counted. Every failure is reported, each beginning with
    /// `REJECT-DROPS` or `COMMAND-RECORDS-LOST`.
    fn judge_a_flood_of_forged_requests_keeps_command_records(rig: &mut Rig) -> Result<(), String> {
        let mut problems = Vec::new();
        let first = rig.genuine("ctl-a", 1, 61);
        rig.submit(0, first);
        rig.step(0);
        for n in 0..200u64 {
            let revision = Some(rig.session.state_revision);
            let forged = rig.request(
                "tok-9f3a1c77e0b2",
                b"not a key",
                100 + n,
                EPOCH,
                revision,
                set_group(10),
            );
            if !matches!(rig.submit(0, forged), SubmitResult::Rejected(_)) {
                return Err("REJECT-DROPS: a forged request was not turned away".to_string());
            }
            rig.channel.flush_log(&rig.session);
        }
        let s = rig.channel.log().expect("a log is enabled").stats();
        if (s.reject_stored, s.reject_dropped) != (2, 198) {
            problems.push(format!(
                "REJECT-DROPS: expected 2 held and exactly the excess 198 dropped, got {} held and {} dropped",
                s.reject_stored, s.reject_dropped
            ));
        }
        for seq in 2..=4u64 {
            let request = rig.genuine("ctl-a", seq, 60 + u8::try_from(seq).unwrap());
            rig.submit(0, request);
            rig.step(0);
        }
        let commands = rig
            .records()
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
    fn a_flood_of_forged_requests_cannot_crowd_out_command_records() {
        let mut rig = Rig::new(config(), Some((8, 65_536)));
        assert_eq!(
            judge_a_flood_of_forged_requests_keeps_command_records(&mut rig),
            Ok(())
        );
        // Each forged request was typed and counted by the channel, whatever the log did with it.
        assert_eq!(rig.channel.stats().rejected_unauthenticated, 200);
        // The owner drains the log; the records are written again.
        assert_eq!(rig.channel.log_mut().unwrap().drain().len(), 6);
        let revision = Some(rig.session.state_revision);
        let forged = rig.request(
            "tok-9f3a1c77e0b2",
            b"not a key",
            999,
            EPOCH,
            revision,
            set_group(10),
        );
        rig.submit(0, forged);
        rig.channel.flush_log(&rig.session);
        assert_eq!(rig.channel.log().unwrap().stats().reject_stored, 1);
    }

    #[test]
    fn the_planted_log_that_gives_these_records_the_whole_budget_fails_the_flood_judge() {
        let mut broken = Rig::new(config(), Some((8, 65_536)));
        broken
            .channel
            .log_mut()
            .expect("a log is enabled")
            .plant_whole_budget_for_rejects();
        let message = judge_a_flood_of_forged_requests_keeps_command_records(&mut broken)
            .expect_err("the planted log must fail the judge");
        // It fails for both reasons: the records took more than their quarter, and the command records that came
        // after the flood found the log full.
        assert!(message.contains("REJECT-DROPS"), "{message}");
        assert!(message.contains("COMMAND-RECORDS-LOST"), "{message}");
    }

    #[test]
    fn the_facts_waiting_for_a_record_are_bounded_and_the_overflow_is_counted() {
        let mut rig = Rig::new(config(), Some((64, 65_536)));
        for n in 0..100u64 {
            let revision = Some(rig.session.state_revision);
            let forged = rig.request(
                "tok-9f3a1c77e0b2",
                b"not a key",
                1 + n,
                EPOCH,
                revision,
                set_group(10),
            );
            assert!(matches!(rig.submit(0, forged), SubmitResult::Rejected(_)));
            assert!(rig.channel.reject_facts.len() <= MAX_PENDING_REJECTS);
        }
        assert_eq!(rig.channel.reject_facts.len(), MAX_PENDING_REJECTS);
        rig.channel.flush_log(&rig.session);
        assert!(rig.channel.reject_facts.is_empty());
        let s = rig.channel.log().unwrap().stats();
        // Sixty-four records of room hold sixteen for these; thirty-two facts were waiting and sixty-eight did not fit.
        assert_eq!(
            (
                s.emitted,
                s.stored,
                s.dropped,
                s.reject_stored,
                s.reject_dropped
            ),
            (100, 16, 84, 16, 84)
        );
        assert_eq!(s.emitted, s.stored as u64 + s.dropped);
        assert!(s.bytes <= 65_536);
        assert!(rig.channel.log().unwrap().is_evidence_complete());
    }

    /// Everything a sender can see after one fixed script: what `submit` and `step` returned, the counters and the
    /// session.
    #[derive(Debug, PartialEq)]
    struct Observed {
        results: Vec<String>,
        stats: ChannelStats,
        revision: u64,
    }

    /// Accepted, answered and turned-away requests of every kind, with steps between.
    fn script(rig: &mut Rig) -> Observed {
        let mut results = Vec::new();
        let mut now = 0;
        for seq in 1..=12u64 {
            let revision = Some(rig.session.state_revision);
            let request = match seq % 4 {
                0 => rig.request(
                    "tok-9f3a1c77e0b2",
                    b"not a key",
                    seq,
                    EPOCH,
                    revision,
                    set_group(10),
                ),
                1 => rig.genuine("ctl-a", seq, 50),
                2 => rig.request(
                    "ctl-a",
                    &test_key("ctl-a"),
                    seq,
                    EPOCH - 1,
                    revision,
                    set_group(10),
                ),
                _ => rig.genuine("panel", seq, 40),
            };
            results.push(format!("{:?}", rig.submit(now, request.clone())));
            results.push(format!("{:?}", rig.submit(now, request)));
            if seq % 3 == 0 {
                now += 10 * MS;
                results.push(format!("{:?}", rig.step(now)));
            }
        }
        now += 2_000 * MS;
        results.push(format!("{:?}", rig.step(now)));
        let request = rig.genuine("ctl-a", 1, 50);
        results.push(format!("{:?}", rig.submit(now, request)));
        Observed {
            results,
            stats: *rig.channel.stats(),
            revision: rig.session.state_revision,
        }
    }

    #[test]
    fn no_log_state_changes_what_a_request_gets() {
        // No log at all is the baseline.
        let baseline = script(&mut Rig::new(config(), None));
        // A roomy log, a tiny one and a byte-starved one: every result is the same.
        for (records, bytes) in [(64, 65_536), (8, 65_536), (1, 65_536), (64, 10), (64, 300)] {
            let mut rig = Rig::new(config(), Some((records, bytes)));
            assert_eq!(
                script(&mut rig),
                baseline,
                "a log of {records} records and {bytes} bytes changed a result"
            );
            let s = rig.channel.log().unwrap().stats();
            assert_eq!(s.emitted, s.stored as u64 + s.dropped, "{records}/{bytes}");
            assert!(s.stored <= records && s.bytes <= bytes);
            assert!(s.reject_stored <= records / 4);
            assert!(s.reject_dropped <= s.dropped);
        }
    }
}
