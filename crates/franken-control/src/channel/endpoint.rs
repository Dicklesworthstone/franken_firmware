//! The datagram endpoint (N02 / `ffw-ugf`, section 9.3): bytes in, the channel, bytes out.
//!
//! The channel works on values and the replies of section 9.1 are values too; [`wire`](super::wire) gives both a byte
//! form. This module is the glue that turns one received datagram into the channel's call and the channel's answer into the
//! datagram to send back, and nothing more: it opens no socket, reads no clock and keeps no per-sender state. A caller that
//! owns a socket (N07 and T02 will) calls [`Endpoint::handle`] once per datagram it receives, with the time it received it,
//! and sends what comes back, if anything.
//!
//! # What it does with a datagram
//!
//! * **A request** is decoded, submitted to the channel as it is, and answered with the reply the channel makes for the
//!   submit result (section 9.1). A retry of a command whose outcome is on record is answered with that outcome and applies
//!   nothing: the one-transition guarantee of the ledger reaches the wire unchanged. A request whose reply the owner wants
//!   to send later (the terminal outcome of a step) is answered through `ControlChannel::reply_to_outcome` and
//!   `Reply::to_bytes`, which the caller already has; a client that never receives it asks again and is answered here.
//! * **An acknowledgement** is decoded and offered to the channel. It is never answered.
//! * **Anything that does not decode** is dropped: [`Handled::Malformed`] names the refusal for the caller's log, and nothing
//!   is sent, queued or counted by the channel. A datagram longer than any request is refused unread.
//!
//! # What it never says
//!
//! **A request that does not authenticate gets no reply, and neither does a datagram that does not decode.** An unknown peer,
//! a revoked one, a wrong key and a tampered byte are indistinguishable from the outside: silence. A signed refusal would
//! need the key of someone who has not proven they hold it, and an unsigned one would tell a stranger which identities exist
//! (section 9.1). A request that does authenticate and is then refused (a stale epoch, a full queue, a rate limit) gets the
//! signed reply that says so.
//!
//! # What this does not do
//!
//! * **Move a byte.** Loss, duplication and reordering are the transport's; the channel's ledger and floors are what make
//!   them harmless, and the tests here deliver datagrams dropped, duplicated and reordered to show it.
//! * **Rate-limit what it cannot attribute.** A flood of datagrams that do not decode costs a decode each and is counted in
//!   [`EndpointStats`]; limiting it per source address is the transport's, because this layer has no address. A flood that
//!   does authenticate is the channel's per-peer limit.
//! * **Remember anything.** The counters are the only state, saturating, and bounded by their width.

use franken_session::UnifiedGroupSession;

use super::peer::{PeerAuthority, ReplySigner};
use super::pipeline::{AckOutcome, ControlChannel, SubmitResult};
use super::wire::{Datagram, WireError, decode_datagram};

/// What one datagram did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handled {
    /// A request was submitted. `reply` is the datagram to send back: `None` if the request did not authenticate (nothing is
    /// ever signed for it).
    Request {
        result: SubmitResult,
        reply: Option<Vec<u8>>,
    },
    /// An acknowledgement was offered to the channel. Nothing is sent back.
    Ack(AckOutcome),
    /// The bytes did not decode. Nothing was done and nothing is sent.
    Malformed(WireError),
}

/// How many datagrams of each kind the endpoint has seen. Saturating.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EndpointStats {
    /// Requests that decoded and were submitted.
    pub requests: u64,
    /// Of those, the ones that were answered.
    pub answered: u64,
    /// Of those, the ones that were not answered because they did not authenticate.
    pub silent: u64,
    /// Acknowledgements that decoded and were offered.
    pub acks: u64,
    /// Datagrams that did not decode, other than for their length.
    pub malformed: u64,
    /// Datagrams refused unread for their length.
    pub too_long: u64,
}

fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// The glue between a transport and a [`ControlChannel`]. It holds counters only.
#[derive(Debug, Default)]
pub struct Endpoint {
    stats: EndpointStats,
}

impl Endpoint {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn stats(&self) -> EndpointStats {
        self.stats
    }

    /// Handle one received datagram. `now_ns` is when it was received, on the timebase of `submit` and `step`; `session`
    /// is read for the epoch and revision a reply is made under.
    pub fn handle<A: PeerAuthority + ReplySigner>(
        &mut self,
        channel: &mut ControlChannel<A>,
        now_ns: u64,
        session: &UnifiedGroupSession,
        datagram: &[u8],
    ) -> Handled {
        match decode_datagram(datagram) {
            Err(error) => {
                if matches!(error, WireError::TooLong { .. }) {
                    bump(&mut self.stats.too_long);
                } else {
                    bump(&mut self.stats.malformed);
                }
                Handled::Malformed(error)
            }
            Ok(Datagram::Request(request)) => {
                bump(&mut self.stats.requests);
                let result = channel.submit(now_ns, request.clone());
                let reply = channel
                    .reply_to_submit(&request, &result, session)
                    .map(|reply| reply.to_bytes());
                if reply.is_some() {
                    bump(&mut self.stats.answered);
                } else {
                    bump(&mut self.stats.silent);
                }
                Handled::Request { result, reply }
            }
            Ok(Datagram::Ack(ack)) => {
                bump(&mut self.stats.acks);
                Handled::Ack(channel.acknowledge(now_ns, session, &ack))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use franken_session::AuthorityToken;

    use super::*;
    use crate::channel::limiter::RateLimit;
    use crate::channel::peer::ephemeral::{EphemeralPeers, test_key};
    use crate::channel::peer::{AuthFailure, PeerId, PeerRole, compute_proof};
    use crate::channel::pipeline::{ChannelConfig, Outcome, Rejection};
    use crate::channel::reply::{Freshness, ReplyExpectation, ReplyStatus, verify_wire};
    use crate::channel::request::{
        AckBody, AckRequest, ControlCommand, ControlRequest, Lane, RequestBody,
    };
    use crate::channel::testkit::fixture_session;
    use crate::channel::wire::{decode_request, encode_ack, encode_request};

    const EPOCH: u64 = 10;
    const MS: u64 = 1_000_000;

    fn id(raw: &str) -> PeerId {
        PeerId::parse(raw).unwrap()
    }

    fn set_group(volume: u8) -> ControlCommand {
        ControlCommand::SetGroupVolume { volume }
    }

    fn roomy() -> ChannelConfig {
        let mut config = ChannelConfig::provisional();
        config.ordinary_rate = RateLimit::new(100_000, MS).unwrap();
        config.priority_rate = RateLimit::new(100_000, MS).unwrap();
        config.session_seq_base = 1_000;
        config
    }

    struct Rig {
        channel: ControlChannel<EphemeralPeers>,
        session: franken_session::UnifiedGroupSession,
        endpoint: Endpoint,
    }

    impl Rig {
        fn with(config: ChannelConfig) -> Self {
            let mut peers = EphemeralPeers::new();
            for (name, role, bound) in [
                ("ctl-a", PeerRole::Controller, Some(EPOCH)),
                ("panel", PeerRole::LocalUser, None),
            ] {
                peers
                    .admit(&id(name), role, &test_key(name), bound, 1)
                    .unwrap();
            }
            let session = fixture_session(EPOCH);
            let mut channel = ControlChannel::new(peers, config).unwrap();
            let token = AuthorityToken::issue(&session, 100_000 * MS);
            channel.install_lease(&session, token, 0).unwrap();
            Self {
                channel,
                session,
                endpoint: Endpoint::new(),
            }
        }

        fn new() -> Self {
            Self::with(roomy())
        }

        fn send(&mut self, now_ns: u64, bytes: &[u8]) -> Handled {
            self.endpoint
                .handle(&mut self.channel, now_ns, &self.session, bytes)
        }

        /// The owner's step: what the channel settled.
        fn step(&mut self, now_ns: u64) -> usize {
            self.channel.step(now_ns, &mut self.session).len()
        }
    }

    /// A request as a client composes it, signed with its own fixture key.
    fn request(
        peer: &str,
        seq: u64,
        revision: Option<u64>,
        command: ControlCommand,
    ) -> ControlRequest {
        let body = RequestBody::new(id(peer), seq, EPOCH, revision, command).unwrap();
        let proof = compute_proof(&test_key(peer), &body.signing_bytes());
        ControlRequest::new(body, proof)
    }

    fn wire(request: &ControlRequest) -> Vec<u8> {
        encode_request(request).unwrap()
    }

    /// What a client learns from the reply bytes it received for `request`, checking them under its own key.
    fn status_of(request: &ControlRequest, bytes: &[u8]) -> ReplyStatus {
        let key = test_key(request.body().peer().as_str());
        let expected = ReplyExpectation::for_request(request.body(), Freshness::default());
        verify_wire(&key, &expected, bytes)
            .expect("a genuine reply verifies")
            .status()
    }

    fn answered(handled: Handled) -> (SubmitResult, Vec<u8>) {
        match handled {
            Handled::Request {
                result,
                reply: Some(reply),
            } => (result, reply),
            other => panic!("expected an answered request, got {other:?}"),
        }
    }

    #[test]
    fn a_dropped_reply_then_a_retry_of_the_same_bytes_is_one_effect_and_the_same_answer() {
        let mut rig = Rig::new();
        let req = request("ctl-a", 1, Some(rig.session.state_revision), set_group(70));
        let bytes = wire(&req);

        // 1. The datagram arrives: queued, and the client can check the reply is the channel's.
        let (result, reply) = answered(rig.send(0, &bytes));
        assert!(matches!(result, SubmitResult::Queued { .. }));
        assert_eq!(
            status_of(&req, &reply),
            ReplyStatus::Queued {
                lane: Lane::Ordinary
            }
        );

        // 2. The owner steps and the command commits. The reply that says so never reaches the client.
        assert_eq!(rig.step(0), 1);
        assert_eq!(rig.session.group_master_volume, 70);
        assert_eq!(rig.session.state_revision, 3);

        // 3. The client sends the same bytes again, and again: the recorded outcome comes back each time.
        for _ in 0..2 {
            let (result, reply) = answered(rig.send(0, &bytes));
            assert_eq!(
                result,
                SubmitResult::Settled(Outcome::Committed { revision: 3 })
            );
            assert_eq!(
                status_of(&req, &reply),
                ReplyStatus::Committed { revision: 3 }
            );
        }
        assert_eq!(rig.step(0), 0, "a retry queues nothing");
        assert_eq!(rig.session.state_revision, 3, "the session changed once");
        assert_eq!(rig.endpoint.stats().requests, 3);
        assert_eq!(rig.endpoint.stats().silent, 0);
    }

    #[test]
    fn a_duplicated_datagram_is_answered_as_already_queued_and_applied_once() {
        let mut rig = Rig::new();
        let req = request("ctl-a", 1, Some(rig.session.state_revision), set_group(40));
        let bytes = wire(&req);
        let (first, _) = answered(rig.send(0, &bytes));
        assert!(matches!(first, SubmitResult::Queued { .. }));
        let (second, reply) = answered(rig.send(0, &bytes));
        assert!(matches!(second, SubmitResult::AlreadyQueued { .. }));
        assert_eq!(
            status_of(&req, &reply),
            ReplyStatus::AlreadyQueued {
                lane: Lane::Ordinary
            }
        );
        assert_eq!(rig.channel.pending(Lane::Ordinary), 1);
        assert_eq!(rig.step(0), 1);
        assert_eq!(rig.session.state_revision, 3);
        // A third copy, after the step, is a retry and is answered from the ledger.
        let (third, _) = answered(rig.send(0, &bytes));
        assert_eq!(
            third,
            SubmitResult::Settled(Outcome::Committed { revision: 3 })
        );
        assert_eq!(rig.session.state_revision, 3);
    }

    #[test]
    fn reordered_datagrams_each_apply_once_in_arrival_order_and_replays_change_nothing() {
        let mut rig = Rig::new();
        let revision = Some(rig.session.state_revision);
        let first = request("ctl-a", 1, revision, set_group(30));
        let second = request("ctl-a", 2, revision, set_group(40));
        // The network delivers the later command first.
        let (a, _) = answered(rig.send(0, &wire(&second)));
        let (b, _) = answered(rig.send(0, &wire(&first)));
        assert!(matches!(a, SubmitResult::Queued { .. }));
        assert!(matches!(b, SubmitResult::Queued { .. }));
        assert_eq!(rig.step(0), 2);
        assert_eq!(
            rig.session.group_master_volume, 30,
            "applied in arrival order"
        );
        assert_eq!(rig.session.state_revision, 4, "each applied exactly once");
        // Replays in either order are answered with each command's own recorded outcome and change nothing.
        for (req, committed_at) in [(&first, 4), (&second, 3), (&first, 4)] {
            let (result, reply) = answered(rig.send(0, &wire(req)));
            assert_eq!(
                result,
                SubmitResult::Settled(Outcome::Committed {
                    revision: committed_at
                })
            );
            assert_eq!(
                status_of(req, &reply),
                ReplyStatus::Committed {
                    revision: committed_at
                }
            );
        }
        assert_eq!(rig.step(0), 0);
        assert_eq!(rig.session.state_revision, 4);
        assert_eq!(rig.session.group_master_volume, 30);
    }

    #[test]
    fn a_request_that_does_not_authenticate_gets_silence_and_changes_nothing() {
        let mut rig = Rig::new();
        rig.channel
            .authority_mut()
            .admit(
                &id("ctl-b"),
                PeerRole::Controller,
                &test_key("ctl-b"),
                Some(EPOCH),
                1,
            )
            .unwrap();
        // A genuine request is answered first, so the silence below is the endpoint and not a broken rig.
        let genuine = request("ctl-a", 1, Some(rig.session.state_revision), set_group(70));
        let (result, _) = answered(rig.send(0, &wire(&genuine)));
        assert!(matches!(result, SubmitResult::Queued { .. }));
        assert_eq!(rig.step(0), 1);
        let (revision, volume) = (rig.session.state_revision, rig.session.group_master_volume);

        assert!(rig.channel.authority_mut().revoke(&id("ctl-b")));
        let revision_now = Some(revision);
        let wrong_key = {
            // Named ctl-a, signed under another peer's key.
            let body =
                RequestBody::new(id("ctl-a"), 2, EPOCH, revision_now, set_group(10)).unwrap();
            let proof = compute_proof(&test_key("panel"), &body.signing_bytes());
            ControlRequest::new(body, proof)
        };
        let unknown = {
            let body =
                RequestBody::new(id("ghost"), 1, EPOCH, revision_now, set_group(10)).unwrap();
            let proof = compute_proof(b"a key nobody admitted", &body.signing_bytes());
            ControlRequest::new(body, proof)
        };
        let revoked = request("ctl-b", 1, revision_now, set_group(10));
        let tampered = {
            // A genuine request with the volume changed after it was signed: it still decodes, and its proof is for another body.
            let mut bytes = wire(&request("ctl-a", 3, revision_now, set_group(10)));
            let volume_at = bytes.len() - 32 - 1;
            bytes[volume_at] = 11;
            assert!(
                decode_request(&bytes).is_ok(),
                "the tamper must reach the proof check"
            );
            bytes
        };
        let cases = [
            ("a wrong key", wire(&wrong_key), AuthFailure::BadProof),
            ("an unknown peer", wire(&unknown), AuthFailure::UnknownPeer),
            ("a revoked peer", wire(&revoked), AuthFailure::Revoked),
            ("a tampered byte", tampered, AuthFailure::BadProof),
        ];
        for (how, bytes, failure) in cases {
            assert_eq!(
                rig.send(0, &bytes),
                Handled::Request {
                    result: SubmitResult::Rejected(Rejection::Unauthenticated(failure)),
                    reply: None
                },
                "{how} must get silence"
            );
        }
        assert_eq!(rig.channel.pending(Lane::Ordinary), 0);
        assert_eq!(rig.step(0), 0);
        assert_eq!(
            (rig.session.state_revision, rig.session.group_master_volume),
            (revision, volume)
        );
        let stats = rig.endpoint.stats();
        assert_eq!((stats.requests, stats.answered, stats.silent), (5, 1, 4));
        assert_eq!(rig.channel.stats().rejected_unauthenticated, 4);
    }

    #[test]
    fn malformed_datagrams_are_not_answered_and_never_reach_the_channel() {
        let mut rig = Rig::new();
        let genuine = request("ctl-a", 1, Some(rig.session.state_revision), set_group(70));
        let good = wire(&genuine);
        // A reply is a well-formed datagram of another kind.
        let (_, reply_bytes) = answered(rig.send(0, &good));
        let mut one_more = good.clone();
        one_more.push(0);
        let mut empty_peer = good.clone();
        empty_peer[5] = 0;
        let cases: [(&str, Vec<u8>, &str); 6] = [
            ("nothing", Vec::new(), "truncated"),
            ("half a magic", good[..2].to_vec(), "truncated"),
            ("a byte after the tag", one_more, "trailing_bytes"),
            ("an empty peer id", empty_peer, "invalid_peer"),
            ("a reply", reply_bytes, "bad_magic"),
            (
                "the longest request and one byte more",
                vec![0u8; 163],
                "too_long",
            ),
        ];
        let received_before = rig.channel.stats().received;
        for (how, bytes, code) in cases {
            match rig.send(0, &bytes) {
                Handled::Malformed(error) => assert_eq!(error.code(), code, "{how}"),
                other => panic!("{how}: expected a refusal, got {other:?}"),
            }
        }
        assert_eq!(
            rig.channel.stats().received,
            received_before,
            "a datagram that does not decode never reaches the channel"
        );
        let stats = rig.endpoint.stats();
        assert_eq!((stats.malformed, stats.too_long), (5, 1));
        assert_eq!(
            rig.channel.pending(Lane::Ordinary),
            1,
            "only the genuine request is waiting"
        );
    }

    #[test]
    fn a_retry_after_retention_is_answered_out_of_window_and_not_applied_again() {
        let mut config = roomy();
        config.retention_ns = 1_000 * MS;
        let mut rig = Rig::with(config);
        let req = request("ctl-a", 1, Some(rig.session.state_revision), set_group(70));
        let bytes = wire(&req);
        let _ = answered(rig.send(0, &bytes));
        assert_eq!(rig.step(0), 1);
        let (inside, _) = answered(rig.send(999 * MS, &bytes));
        assert_eq!(
            inside,
            SubmitResult::Settled(Outcome::Committed { revision: 3 })
        );
        let (outside, reply) = answered(rig.send(1_000 * MS, &bytes));
        assert_eq!(outside, SubmitResult::OutOfWindow { floor: 1 });
        assert_eq!(
            status_of(&req, &reply),
            ReplyStatus::OutOfWindow { floor: 1 }
        );
        assert_eq!(rig.step(1_000 * MS), 0, "nothing was queued");
        assert_eq!(
            rig.session.state_revision, 3,
            "unknown, and not applied a second time"
        );
    }

    #[test]
    fn an_acknowledgement_datagram_completes_its_command_once_and_a_forged_one_changes_nothing() {
        let mut rig = Rig::new();
        let req = request("ctl-a", 1, Some(rig.session.state_revision), set_group(70));
        let _ = answered(rig.send(0, &wire(&req)));
        assert_eq!(rig.step(0), 1);
        let ack = |peer: &str, signer: &str, seq: u64| {
            let body = AckBody::new(id(peer), seq, EPOCH).unwrap();
            let proof = compute_proof(&test_key(signer), &body.signing_bytes());
            encode_ack(&AckRequest::new(body, proof)).unwrap()
        };
        assert!(matches!(
            rig.send(0, &ack("ctl-a", "ctl-a", 1)),
            Handled::Ack(AckOutcome::OnTime { .. })
        ));
        assert_eq!(
            rig.send(0, &ack("ctl-a", "ctl-a", 1)),
            Handled::Ack(AckOutcome::Duplicate)
        );
        assert_eq!(
            rig.send(0, &ack("ctl-a", "panel", 2)),
            Handled::Ack(AckOutcome::Unauthenticated(AuthFailure::BadProof))
        );
        assert_eq!(
            rig.send(0, &ack("ctl-a", "ctl-a", 99)),
            Handled::Ack(AckOutcome::Unknown)
        );
        assert_eq!(rig.endpoint.stats().acks, 4);
        assert_eq!(
            rig.session.state_revision, 3,
            "an acknowledgement writes nothing"
        );
        // A retry after the acknowledgement is still answered from the ledger.
        let (result, _) = answered(rig.send(0, &wire(&req)));
        assert_eq!(
            result,
            SubmitResult::Settled(Outcome::Committed { revision: 3 })
        );
    }

    /// How the thing between the socket and the channel behaves. `Faithful` is the endpoint; each other variant is a fault.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Handler {
        Faithful,
        /// Answers a request that did not authenticate with some bytes.
        AnswersTheUnauthenticated,
        /// Answers a datagram that did not decode with some bytes.
        AnswersMalformed,
        /// Treats a retry as a new command: it re-signs it under a fresh number and submits that too.
        ReappliesRetries,
    }

    /// Run one datagram through `handler` and return what it would put on the wire.
    fn through(handler: Handler, rig: &mut Rig, now_ns: u64, bytes: &[u8]) -> Option<Vec<u8>> {
        match (handler, rig.send(now_ns, bytes)) {
            // The fault: a retry also goes in again as a new command. The client still gets the right answer.
            (
                Handler::ReappliesRetries,
                Handled::Request {
                    result: SubmitResult::Settled(_),
                    reply,
                },
            ) => {
                let original = decode_request(bytes).expect("a retry decodes");
                let body = original.body();
                let again = RequestBody::new(
                    body.peer().clone(),
                    body.seq() + 1_000,
                    body.epoch(),
                    body.expected_revision(),
                    body.command().clone(),
                )
                .unwrap();
                let proof = compute_proof(&test_key(body.peer().as_str()), &again.signing_bytes());
                let _ = rig
                    .channel
                    .submit(now_ns, ControlRequest::new(again, proof));
                reply
            }
            // The faults: an answer where there must be silence.
            (
                Handler::AnswersTheUnauthenticated,
                Handled::Request {
                    result: SubmitResult::Rejected(Rejection::Unauthenticated(_)),
                    reply: None,
                },
            )
            | (Handler::AnswersMalformed, Handled::Malformed(_)) => {
                Some(b"here is an answer".to_vec())
            }
            (_, Handled::Request { reply, .. }) => reply,
            _ => None,
        }
    }

    /// A client sends a command and the reply that says it committed is lost; it sends the same bytes again; a stranger sends a
    /// request that does not authenticate and a datagram that does not decode. The retry must be answered with the recorded
    /// outcome (`WRONG-ANSWER`) and apply nothing (`TWICE`, judged after the owner steps again), and the stranger must get
    /// nothing, in either form (`ORACLE-UNAUTHENTICATED`, `ORACLE-MALFORMED`).
    fn judge_the_datagram_world(handler: Handler) -> Result<(), String> {
        let mut rig = Rig::new();
        let req = request("ctl-a", 1, Some(rig.session.state_revision), set_group(70));
        let bytes = wire(&req);
        let sent = through(handler, &mut rig, 0, &bytes)
            .ok_or("setup: the first datagram was not answered")?;
        if status_of(&req, &sent)
            != (ReplyStatus::Queued {
                lane: Lane::Ordinary,
            })
        {
            return Err("setup: the first answer was not queued".into());
        }
        if rig.step(0) != 1 || rig.session.state_revision != 3 {
            return Err("setup: the command did not commit once".into());
        }
        let sent = through(handler, &mut rig, 0, &bytes)
            .ok_or("WRONG-ANSWER: the retry was not answered")?;
        let status = status_of(&req, &sent);
        if status != (ReplyStatus::Committed { revision: 3 }) {
            return Err(format!("WRONG-ANSWER: the retry was answered {status:?}"));
        }
        rig.step(0);
        if rig.session.state_revision != 3 {
            return Err(format!(
                "TWICE: a retry was applied again (the session is at revision {}, not 3)",
                rig.session.state_revision
            ));
        }
        let stranger = {
            let body = RequestBody::new(id("ctl-a"), 2, EPOCH, Some(3), set_group(10)).unwrap();
            let proof = compute_proof(b"not the key of ctl-a at all", &body.signing_bytes());
            encode_request(&ControlRequest::new(body, proof)).unwrap()
        };
        if through(handler, &mut rig, 0, &stranger).is_some() {
            return Err(
                "ORACLE-UNAUTHENTICATED: a request that did not authenticate was answered".into(),
            );
        }
        if through(handler, &mut rig, 0, b"garbage").is_some() {
            return Err("ORACLE-MALFORMED: a datagram that did not decode was answered".into());
        }
        Ok(())
    }

    #[test]
    fn each_planted_endpoint_fault_fails_the_datagram_judge_by_name() {
        // A judge that fails everything proves nothing, so the faithful endpoint passes first.
        assert_eq!(judge_the_datagram_world(Handler::Faithful), Ok(()));
        for (handler, tag) in [
            (Handler::AnswersTheUnauthenticated, "ORACLE-UNAUTHENTICATED"),
            (Handler::AnswersMalformed, "ORACLE-MALFORMED"),
            (Handler::ReappliesRetries, "TWICE"),
        ] {
            let verdict = judge_the_datagram_world(handler);
            assert!(
                verdict.as_ref().is_err_and(|e| e.starts_with(tag)),
                "{handler:?} was not caught as {tag}: {verdict:?}"
            );
        }
    }
}
