//! Replays the golden N02 scenarios against the real channel. Compiled only for tests.
//!
//! The scenarios in `tests/vectors/n02_scenarios.json` were worked out by hand from
//! `docs/contracts/n02.md` before either implementation produced them, and `tests/n02/reference.py`
//! replays the same file with an independently built model. A disagreement between the file, that
//! model and this replay is a finding, whichever of the three is wrong.
//!
//! Requests are signed here the way a client would: with the key it holds, through the same
//! synthetic MAC the test authority checks. That keeps working after a peer is revoked, when the
//! authority has already wiped its copy of the key.

use serde_json::{Value, json};

use franken_session::{
    AuthorityToken, FencedControlCommand, GroupCommandPayload, GroupMembership, GroupTime,
    MemberLifecycleState, MembershipConfig,
};

use super::limiter::RateLimit;
use super::peer::ephemeral::{EphemeralPeers, test_key};
use super::peer::{AuthFailure, AuthProof, PeerAuthority, PeerId, PeerRole, compute_proof};
use super::pipeline::{
    ChannelConfig, ControlChannel, Outcome, Refusal, Rejection, Settlement, SubmitResult,
};
use super::request::{ControlCommand, ControlRequest, Lane, RequestBody};
use super::testkit::fixture_session;

const VECTORS_JSON: &str = include_str!("../../tests/vectors/n02_scenarios.json");
const MS: u64 = 1_000_000;
const EPOCH: u64 = 10;

/// Who speaks in the scenarios: name, role and the epoch the key is bound to. Each peer's key is
/// `test_key(name)`, held by the client side of the replay and by the authority.
const PEERS: [(&str, PeerRole, Option<u64>); 4] = [
    ("ctl-a", PeerRole::Controller, Some(EPOCH)),
    ("ctl-b", PeerRole::Controller, Some(EPOCH)),
    ("panel", PeerRole::LocalUser, None),
    ("rogue", PeerRole::Controller, Some(900)),
];

fn id(raw: &str) -> PeerId {
    PeerId::parse(raw).expect("scenario peers are valid ids")
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("`{key}` must be a string in {v}"))
}

fn number(v: &Value, key: &str) -> u64 {
    v[key]
        .as_u64()
        .unwrap_or_else(|| panic!("`{key}` must be a number in {v}"))
}

fn lane_name(lane: Lane) -> &'static str {
    match lane {
        Lane::Ordinary => "ordinary",
        Lane::Priority => "priority",
    }
}

fn command_from(cmd: &Value) -> ControlCommand {
    let member = || text(cmd, "member").to_string();
    let volume = || u8::try_from(number(cmd, "volume")).expect("volume fits in a byte");
    let delta = || i8::try_from(cmd["delta"].as_i64().expect("delta")).expect("delta fits");
    match text(cmd, "kind") {
        "set_member_volume" => ControlCommand::SetMemberVolume {
            member_id: member(),
            volume: volume(),
        },
        "set_group_volume" => ControlCommand::SetGroupVolume { volume: volume() },
        "adjust_member_volume" => ControlCommand::AdjustMemberVolume {
            member_id: member(),
            delta: delta(),
        },
        "adjust_group_volume" => ControlCommand::AdjustGroupVolume { delta: delta() },
        "set_member_mute" => ControlCommand::SetMemberMute {
            member_id: member(),
            muted: cmd["muted"].as_bool().expect("muted"),
        },
        "stop" => ControlCommand::StopGroupPlayback {
            now_ns: number(cmd, "now_ns"),
            irrevocable_dma_tail_ns: number(cmd, "tail_ns"),
        },
        "cancel" => ControlCommand::Cancel {
            target_seq: number(cmd, "target_seq"),
        },
        other => panic!("unknown command kind `{other}`"),
    }
}

fn body_from(step: &Value) -> RequestBody {
    RequestBody::new(
        id(text(step, "peer")),
        number(step, "seq"),
        number(step, "epoch"),
        step["rev"].as_u64(),
        command_from(&step["cmd"]),
    )
    .expect("scenario requests are well formed")
}

fn request_from(step: &Value) -> ControlRequest {
    let body = body_from(step);
    let key = if step["proof"].as_str() == Some("forged") {
        b"not-the-peers-key-0123456789".to_vec()
    } else {
        test_key(text(step, "peer"))
    };
    let proof = compute_proof(&key, &body.signing_bytes());
    ControlRequest::new(body, proof)
}

fn rate(v: &Value) -> RateLimit {
    RateLimit::new(
        u32::try_from(v[0].as_u64().expect("burst")).expect("burst fits"),
        v[1].as_u64().expect("interval") * MS,
    )
    .expect("scenario rate limits are valid")
}

fn config_from(doc: &Value, scenario: &Value) -> ChannelConfig {
    let config = merged_config(doc, scenario);
    let size = |key: &str| usize::try_from(number(&config, key)).expect("size fits");
    ChannelConfig {
        ordinary_capacity: size("ordinary_capacity"),
        priority_shared_capacity: size("priority_shared_capacity"),
        priority_local_reserved: size("priority_local_reserved"),
        ledger_capacity: size("ledger_capacity"),
        retention_ns: number(&config, "retention_ms") * MS,
        pending_ttl_ns: number(&config, "pending_ttl_ms") * MS,
        max_per_step: size("max_per_step"),
        ordinary_rate: rate(&config["ordinary_rate"]),
        priority_rate: rate(&config["priority_rate"]),
        session_seq_base: number(&config, "session_seq_base"),
    }
}

fn refusal_name(refusal: &Refusal) -> String {
    match refusal {
        Refusal::StaleEpoch { .. } => "stale_epoch".to_string(),
        Refusal::EpochAhead { .. } => "epoch_ahead".to_string(),
        Refusal::RevisionMismatch { .. } => "revision_mismatch".to_string(),
        Refusal::StaleRevision { .. } => "stale_revision".to_string(),
        Refusal::UnknownMember { .. } => "unknown_member".to_string(),
        Refusal::Session(_) => "session".to_string(),
        Refusal::InternalFault => "internal_fault".to_string(),
        Refusal::NoLease => "no_lease".to_string(),
        Refusal::Lease(error) => format!("lease:{}", error.code().to_lowercase()),
        Refusal::AuthorityExpired => "authority_expired".to_string(),
        Refusal::Expired => "expired".to_string(),
        Refusal::TooLateToCancel => "too_late_to_cancel".to_string(),
        Refusal::NothingToCancel => "nothing_to_cancel".to_string(),
        Refusal::TargetOutOfWindow { .. } => "target_out_of_window".to_string(),
        Refusal::NotCancellable => "not_cancellable".to_string(),
    }
}

fn show_outcome(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Committed { revision } => format!("committed:{revision}"),
        Outcome::Withdrawn => "withdrawn".to_string(),
        Outcome::CancelApplied { target_seq } => format!("cancel_applied:{target_seq}"),
        Outcome::Refused(refusal) => format!("refused:{}", refusal_name(refusal)),
    }
}

fn show_submit(result: &SubmitResult) -> String {
    match result {
        SubmitResult::Queued { lane } => format!("queued:{}", lane_name(*lane)),
        SubmitResult::AlreadyQueued { lane } => format!("already_queued:{}", lane_name(*lane)),
        SubmitResult::Settled(outcome) => format!("settled:{}", show_outcome(outcome)),
        SubmitResult::OutOfWindow { floor } => format!("out_of_window:{floor}"),
        SubmitResult::Rejected(rejection) => match rejection {
            Rejection::Unauthenticated(failure) => format!(
                "rejected:unauthenticated:{}",
                match failure {
                    AuthFailure::UnknownPeer => "unknown_peer",
                    AuthFailure::Revoked => "revoked",
                    AuthFailure::BadProof => "bad_proof",
                }
            ),
            Rejection::EpochNotBound { .. } => "rejected:epoch_not_bound".to_string(),
            Rejection::RevisionRequired { .. } => "rejected:revision_required".to_string(),
            Rejection::RateLimited {
                lane,
                retry_after_ns,
            } => {
                assert_eq!(
                    retry_after_ns % MS,
                    0,
                    "scenario waits are whole milliseconds"
                );
                format!(
                    "rejected:rate_limited:{}:{}",
                    lane_name(*lane),
                    retry_after_ns / MS
                )
            }
            Rejection::QueueFull { lane } => format!("rejected:queue_full:{}", lane_name(*lane)),
            Rejection::IdReuse => "rejected:id_reuse".to_string(),
        },
    }
}

fn show_settlement(settlement: &Settlement) -> String {
    format!(
        "{}#{}={}",
        settlement.peer,
        settlement.seq,
        show_outcome(&settlement.outcome)
    )
}

fn final_state(session: &franken_session::UnifiedGroupSession) -> Value {
    let mut muted: Vec<&str> = session
        .members
        .values()
        .filter(|m| m.muted)
        .map(|m| m.member_id.as_str())
        .collect();
    muted.sort_unstable();
    json!({
        "revision": session.state_revision,
        "epoch": session.current_epoch,
        "group_volume": session.group_master_volume,
        "kitchen": session.members["kitchen"].volume_0_to_100,
        "den": session.members["den"].volume_0_to_100,
        "muted": muted,
        "stopped": session
            .members
            .values()
            .all(|m| matches!(m.lifecycle, MemberLifecycleState::StoppingDmaTail { .. })),
    })
}

/// The scenario peers, each admitted with `test_key(name)`.
fn directory() -> EphemeralPeers {
    let mut peers = EphemeralPeers::new();
    for (name, role, bound) in PEERS {
        peers
            .admit(&id(name), role, &test_key(name), bound, 1)
            .expect("scenario peers are admitted");
    }
    peers
}

/// Replay one scenario; the returned list is empty when everything matched.
fn replay(doc: &Value, scenario: &Value) -> Vec<String> {
    let scenario_id = text(scenario, "id");
    let mut problems = Vec::new();
    let mut channel = ControlChannel::new(directory(), config_from(doc, scenario))
        .expect("scenario config is valid");
    let mut session = fixture_session(EPOCH);
    let lease_ms = lease_ms(doc, scenario);
    // The issuer's own token, as G01 mints it. The channel is given a copy unless the scenario starts
    // without a lease.
    let mut issuer_token = AuthorityToken::issue(&session, lease_ms * MS);
    let mut membership = GroupMembership::new(MembershipConfig::default());
    if !starts_without_lease(doc, scenario) {
        channel
            .install_lease(&session, issuer_token.clone(), 0)
            .expect("the first lease is accepted");
    }

    for (index, step) in scenario["steps"]
        .as_array()
        .expect("steps")
        .iter()
        .enumerate()
    {
        let op = text(step, "op");
        let where_ = format!("{scenario_id} step {index} ({op})");
        match op {
            "submit" => {
                let now = number(step, "at_ms") * MS;
                let repeat = step["repeat"].as_u64().unwrap_or(1);
                for n in 0..repeat {
                    let got = show_submit(&channel.submit(now, request_from(step)));
                    if got != text(step, "expect") {
                        problems.push(format!(
                            "{where_} repeat {n}: expected {:?}, got {got:?}",
                            text(step, "expect")
                        ));
                        break;
                    }
                }
            }
            "step" => {
                let got: Vec<String> = channel
                    .step(number(step, "at_ms") * MS, &mut session)
                    .iter()
                    .map(show_settlement)
                    .collect();
                let want: Vec<String> = step["expect"]
                    .as_array()
                    .expect("expect list")
                    .iter()
                    .map(|v| v.as_str().expect("expect entry").to_string())
                    .collect();
                if got != want {
                    problems.push(format!("{where_}: expected {want:?}, got {got:?}"));
                }
            }
            "session_epoch" => {
                // A membership change under a newer epoch, made outside the channel.
                session
                    .apply_command(FencedControlCommand {
                        epoch: number(step, "epoch"),
                        command_seq: 3,
                        payload: GroupCommandPayload::MarkMemberClockLocked {
                            member_id: "kitchen".to_string(),
                        },
                    })
                    .expect("the epoch change applies");
            }
            "rebind" => {
                let peer = id(text(step, "peer"));
                assert!(
                    channel
                        .authority_mut()
                        .rebind(&peer, Some(number(step, "epoch")))
                        .is_some(),
                    "{where_}: the peer must be admitted"
                );
            }
            "lease" => {
                // The issuer mints a lease for the session's current epoch and the owner installs it.
                let at = step["at_ms"].as_u64().unwrap_or(0) * MS;
                let token = AuthorityToken::issue(&session, number(step, "expires_ms") * MS);
                issuer_token = token.clone();
                let got = show_install(channel.install_lease(&session, token, at));
                if got != text(step, "expect") {
                    problems.push(format!(
                        "{where_}: expected {:?}, got {got:?}",
                        text(step, "expect")
                    ));
                }
            }
            "foreign_lease" => {
                // A token the session must not accept: the owner tries to install it.
                let at = number(step, "at_ms") * MS;
                let mut token = AuthorityToken::issue(&session, lease_ms * MS);
                // One flaw, or several joined by `+`: a token flawed in two ways pins the order in which
                // the session judges them.
                for flaw in text(step, "flaw").split('+') {
                    match flaw {
                        "issuer" => token.issuer_id = "intruder".to_string(),
                        "group" => token.group_id = "elsewhere".to_string(),
                        "stale" => token.epoch = session.current_epoch - 1,
                        "future" => token.epoch = session.current_epoch + 1,
                        "expired" => token.expires_at_ns = at,
                        other => panic!("unknown flaw `{other}`"),
                    }
                }
                let got = show_install(channel.install_lease(&session, token, at));
                if got != text(step, "expect") {
                    problems.push(format!(
                        "{where_}: expected {:?}, got {got:?}",
                        text(step, "expect")
                    ));
                }
            }
            "advance_epoch" => {
                // The issuer moves the group to a newer epoch. The channel keeps the lease it had.
                issuer_token = membership
                    .advance_epoch(
                        &mut session,
                        &issuer_token,
                        number(step, "epoch"),
                        GroupTime {
                            ns: step["at_ms"].as_u64().unwrap_or(0) * MS,
                            frame: 0,
                        },
                    )
                    .expect("the issuer's epoch advance is accepted");
            }
            "restart" => {
                // A new incarnation: no queue, no outcome, no limiter, no revision floor. The group
                // state, the session's record and the peer directory carry on.
                channel = ControlChannel::new(directory(), config_from(doc, scenario))
                    .expect("scenario config is valid");
            }
            "external_command" => {
                // Another caller of the session, in the same epoch, using a number of its own choosing.
                session
                    .apply_command(FencedControlCommand {
                        epoch: session.current_epoch,
                        command_seq: number(step, "seq"),
                        payload: GroupCommandPayload::MarkMemberClockLocked {
                            member_id: "kitchen".to_string(),
                        },
                    })
                    .expect("the external command applies");
            }
            "revoke" => {
                assert!(
                    channel.authority_mut().revoke(&id(text(step, "peer"))),
                    "{where_}: the peer must be admitted"
                );
            }
            other => problems.push(format!("{where_}: unknown op `{other}`")),
        }
    }

    let got = final_state(&session);
    if got != scenario["final"] {
        problems.push(format!(
            "{scenario_id} final: expected {}, got {got}",
            scenario["final"]
        ));
    }
    let stats = channel.stats();
    if stats.accounted() != stats.received {
        problems.push(format!("{scenario_id} accounting: {stats:?}"));
    }
    if stats.ledger_record_failures != 0 {
        problems.push(format!("{scenario_id} ledger record failures: {stats:?}"));
    }
    problems
}

fn merged_config(doc: &Value, scenario: &Value) -> Value {
    let mut merged = doc["base_config"].as_object().expect("base_config").clone();
    if let Some(overrides) = scenario["config"].as_object() {
        merged.extend(overrides.clone());
    }
    Value::Object(merged)
}

fn lease_ms(doc: &Value, scenario: &Value) -> u64 {
    number(&merged_config(doc, scenario), "lease_ms")
}

fn starts_without_lease(doc: &Value, scenario: &Value) -> bool {
    merged_config(doc, scenario)["lease"].as_str() == Some("none")
}

/// What `install_lease` said, in the file's words.
fn show_install(result: Result<(), franken_session::MembershipError>) -> String {
    match result {
        Ok(()) => "installed".to_string(),
        Err(error) => error.code().to_string(),
    }
}

fn doc() -> Value {
    serde_json::from_str(VECTORS_JSON).expect("the scenario file parses")
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "hex has an even number of digits");
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex digits"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[test]
fn every_golden_scenario_matches_the_channel() {
    let doc = doc();
    let scenarios = doc["scenarios"].as_array().expect("scenarios");
    assert!(
        scenarios.len() >= 20,
        "the scenario file must not shrink silently"
    );
    let mut problems = Vec::new();
    for scenario in scenarios {
        problems.extend(replay(&doc, scenario));
    }
    assert!(
        problems.is_empty(),
        "scenario mismatches:\n{}",
        problems.join("\n")
    );
}

#[test]
fn the_signing_bytes_match_the_independently_derived_vectors() {
    let doc = doc();
    let vectors = doc["signing_vectors"].as_array().expect("signing_vectors");
    assert!(vectors.len() >= 5);
    for vector in vectors {
        let body = body_from(vector);
        assert_eq!(
            hex(&body.signing_bytes()),
            text(vector, "hex"),
            "{}",
            text(vector, "id")
        );
    }
}

#[test]
fn the_replay_notices_a_wrong_expectation() {
    // A replay that cannot fail proves nothing: alter one expectation and it must be reported.
    let mut doc = doc();
    let scenario = &mut doc["scenarios"][0];
    scenario["steps"][0]["expect"] = json!("rejected:id_reuse");
    let scenario = doc["scenarios"][0].clone();
    let problems = replay(&doc, &scenario);
    assert!(
        problems
            .iter()
            .any(|p| p.contains("expected \"rejected:id_reuse\"")),
        "{problems:?}"
    );

    let mut doc = self::doc();
    doc["scenarios"][0]["final"]["revision"] = json!(99);
    let scenario = doc["scenarios"][0].clone();
    assert!(replay(&doc, &scenario).iter().any(|p| p.contains("final")));
}

#[test]
fn scenario_ids_are_unique_and_every_operation_is_known() {
    let doc = doc();
    let mut seen = std::collections::BTreeSet::new();
    for scenario in doc["scenarios"].as_array().expect("scenarios") {
        assert!(seen.insert(text(scenario, "id")), "duplicate scenario id");
        assert!(
            !scenario["invariants"]
                .as_array()
                .expect("invariants")
                .is_empty()
        );
        for step in scenario["steps"].as_array().expect("steps") {
            assert!(
                [
                    "submit",
                    "step",
                    "session_epoch",
                    "rebind",
                    "revoke",
                    "restart",
                    "external_command",
                    "lease",
                    "foreign_lease",
                    "advance_epoch"
                ]
                .contains(&text(step, "op")),
                "unknown op in {}",
                text(scenario, "id")
            );
        }
    }
}

/// The expected tags were computed with Python's standard `hmac`, a different implementation of the
/// same standard, so this also pins the context label, the order of the parts and the full length.
#[test]
fn the_proofs_match_the_python_hmac_vectors_and_the_directory_accepts_them() {
    let doc = doc();
    let signing = doc["signing_vectors"].as_array().expect("signing_vectors");
    let auth = doc["auth_vectors"].as_array().expect("auth_vectors");
    assert!(
        auth.len() >= signing.len(),
        "one auth vector per signing vector"
    );
    let peers = directory();
    for vector in auth {
        let source = signing
            .iter()
            .find(|s| text(s, "id") == text(vector, "signing_vector"))
            .expect("the auth vector names a signing vector");
        let body = body_from(source);
        let key = text(vector, "key");
        assert_eq!(
            key.as_bytes(),
            test_key(text(source, "peer")).as_slice(),
            "{}: the vector key is the fixture key of its peer",
            text(vector, "id")
        );
        let proof = compute_proof(key.as_bytes(), &body.signing_bytes());
        assert_eq!(
            hex(proof.as_bytes()),
            text(vector, "tag_hex"),
            "{}",
            text(vector, "id")
        );
        // The directory accepts the Python-computed tag itself, not only its own.
        let python_tag = AuthProof::new(unhex(text(vector, "tag_hex"))).expect("a 32-byte tag");
        assert!(
            peers
                .authenticate(body.peer(), &body.signing_bytes(), &python_tag)
                .is_ok(),
            "{}",
            text(vector, "id")
        );
    }
}

#[test]
fn every_tampered_field_is_refused_under_the_original_tag() {
    let doc = doc();
    let signing = doc["signing_vectors"].as_array().expect("signing_vectors");
    let auth = doc["auth_vectors"].as_array().expect("auth_vectors");
    let tampers = doc["tamper_vectors"].as_array().expect("tamper_vectors");
    assert!(tampers.len() >= 8, "one per signed field");
    let peers = directory();
    for tamper in tampers {
        let base_auth = auth
            .iter()
            .find(|a| text(a, "id") == text(tamper, "auth_vector"))
            .expect("the tamper names an auth vector");
        let base = signing
            .iter()
            .find(|s| text(s, "id") == text(base_auth, "signing_vector"))
            .expect("the auth vector names a signing vector");
        let original = body_from(base);
        let changed = body_from(tamper);
        assert_ne!(
            original.signing_bytes(),
            changed.signing_bytes(),
            "{}: a tamper must change the signed bytes",
            text(tamper, "id")
        );
        let tag = AuthProof::new(unhex(text(base_auth, "tag_hex"))).expect("a 32-byte tag");
        assert_eq!(
            peers.authenticate(changed.peer(), &changed.signing_bytes(), &tag),
            Err(AuthFailure::BadProof),
            "{} ({})",
            text(tamper, "id"),
            text(tamper, "field")
        );
    }
}
