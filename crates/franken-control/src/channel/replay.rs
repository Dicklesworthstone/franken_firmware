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

use franken_session::{FencedControlCommand, GroupCommandPayload, MemberLifecycleState};

use super::limiter::RateLimit;
use super::peer::ephemeral::{EphemeralPeers, test_key};
use super::peer::{AuthFailure, PeerId, PeerRole, compute_proof};
use super::pipeline::{
    ChannelConfig, ControlChannel, Outcome, Refusal, Rejection, Settlement, SubmitResult,
};
use super::request::{ControlCommand, ControlRequest, Lane, RequestBody};
use super::testkit::fixture_session;

const VECTORS_JSON: &str = include_str!("../../tests/vectors/n02_scenarios.json");
const MS: u64 = 1_000_000;
const EPOCH: u64 = 10;
const SESSION_SEQ_BASE: u64 = 1_000;

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
    let mut merged = doc["base_config"].as_object().expect("base_config").clone();
    if let Some(overrides) = scenario["config"].as_object() {
        merged.extend(overrides.clone());
    }
    let config = Value::Object(merged);
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
        session_seq_base: SESSION_SEQ_BASE,
    }
}

fn refusal_name(refusal: &Refusal) -> &'static str {
    match refusal {
        Refusal::StaleEpoch { .. } => "stale_epoch",
        Refusal::EpochAhead { .. } => "epoch_ahead",
        Refusal::RevisionMismatch { .. } => "revision_mismatch",
        Refusal::UnknownMember { .. } => "unknown_member",
        Refusal::Session(_) => "session",
        Refusal::AuthorityExpired => "authority_expired",
        Refusal::Expired => "expired",
        Refusal::TooLateToCancel => "too_late_to_cancel",
        Refusal::NothingToCancel => "nothing_to_cancel",
        Refusal::TargetOutOfWindow { .. } => "target_out_of_window",
        Refusal::NotCancellable => "not_cancellable",
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

/// Replay one scenario; the returned list is empty when everything matched.
fn replay(doc: &Value, scenario: &Value) -> Vec<String> {
    let scenario_id = text(scenario, "id");
    let mut problems = Vec::new();
    let mut peers = EphemeralPeers::new();
    for (name, role, bound) in PEERS {
        peers
            .admit(&id(name), role, &test_key(name), bound, 1)
            .expect("scenario peers are admitted");
    }
    let mut channel =
        ControlChannel::new(peers, config_from(doc, scenario)).expect("scenario config is valid");
    let mut session = fixture_session(EPOCH);

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

fn doc() -> Value {
    serde_json::from_str(VECTORS_JSON).expect("the scenario file parses")
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
        let body = RequestBody::new(
            id(text(vector, "peer")),
            number(vector, "seq"),
            number(vector, "epoch"),
            vector["rev"].as_u64(),
            command_from(&vector["cmd"]),
        )
        .expect("vector request is well formed");
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
                ["submit", "step", "session_epoch", "rebind", "revoke"].contains(&text(step, "op")),
                "unknown op in {}",
                text(scenario, "id")
            );
        }
    }
}
