//! Replays the hand-written G01 scenarios against the real `franken_session` engine.
//!
//! `tests/vectors/g01_scenarios.json` holds 40 scenarios whose expected values were derived by hand
//! from docs/contracts/g01.md, plus two sections that are the output of the independent Python model
//! in tests/g01/reference.py: the exact counts of 32 seeded partition-schedule runs, and the set of
//! scenarios each planted fault must break. Nothing here reads an expected value from the engine.
//!
//! This is an integration test, so it can only use the crate's public API. The seeded schedule in
//! `membership.rs` lives in that file's private test module and cannot be called from here; this file
//! carries its own driver of the same schedule (same SplitMix64, same draws) and runs it against the
//! real `LeaseVoter`, `QuorumRound`, `GroupMembership` and `UnifiedGroupSession`. What is compared
//! with the model is the engine's behaviour, not a harness shared with the model.
//!
//! The faults are planted in the driver (zero clock uncertainty, voters judged at a far-future clock,
//! the missing-acknowledgement policy swapped, the epoch-minting mode swapped) and not in the engine,
//! so no production code carries a fault switch. Each must break at least one scenario, and exactly
//! the scenarios the model says it breaks.
//!
//! Every result is also printed as one `G01-OBSERVED {json}` line, so scripts/e2e/g01 --judge can
//! judge the log of a central run:
//!   RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- \
//!     cargo test -p franken-session --test g01_replay --locked -- --nocapture --test-threads=1

use franken_board_profile::{
    BoardProfile, canonical_board_catalog, synthetic_test_fixture_catalog,
};
use franken_session::{
    AbortReason, AuthorityToken, ChannelRole, DurableVoterRecord, EpochMint, FencedControlCommand,
    GroupCommandPayload, GroupMembership, GroupTime, LeaseAck, LeaseRequest, LeaseRequestKind,
    LeaseTerms, LeaseView, LeaseVoter, LeaseWin, MembershipChange, MembershipConfig,
    MembershipError, MissingAckPolicy, OutputResolution, ProposalSpec, ProposalStatus,
    QuorumConfig, QuorumRound, ReadinessReport, UnifiedGroupSession,
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::OnceLock;

const VECTORS: &str = include_str!("vectors/g01_scenarios.json");
const GROUP: &str = "grp";
const FAR_FUTURE: u64 = 4_000_000_000_000_000_000;
const PLANTS: [&str; 4] = [
    "zero_uncertainty",
    "early_voter_clock",
    "flipped_policy",
    "flipped_mint",
];
const KNOWN_OPS: [&str; 38] = [
    "quorum",
    "found",
    "observe",
    "request",
    "raw_request",
    "respond",
    "gather",
    "round_start",
    "round_ack",
    "round_outcome",
    "record",
    "restart",
    "restore",
    "forget",
    "node",
    "issue",
    "live",
    "renew",
    "assume",
    "adopt",
    "session",
    "probe",
    "advance",
    "discover",
    "gate",
    "grant_output",
    "permitted",
    "propose",
    "ack",
    "commit",
    "abort",
    "tick",
    "status",
    "resolve",
    "start_gate",
    "unresolved",
    "restart_node",
    "repeat",
];

// ------------------------------------------------------------------------------------ fixtures

fn fixture(model: &str) -> BoardProfile {
    static CATALOG: OnceLock<Vec<BoardProfile>> = OnceLock::new();
    CATALOG
        .get_or_init(synthetic_test_fixture_catalog)
        .iter()
        .find(|p| p.model_number == model)
        .expect("fixture model present")
        .clone()
}

fn board(name: &str) -> BoardProfile {
    static CANONICAL: OnceLock<Vec<BoardProfile>> = OnceLock::new();
    match name.strip_prefix("hypothesis:") {
        Some(model) => CANONICAL
            .get_or_init(canonical_board_catalog)
            .iter()
            .find(|p| p.model_number == model)
            .expect("hypothesis model present")
            .clone(),
        None => fixture(name),
    }
}

/// Epoch 1, issuer `coordinator`, members `a` (S5) and `b` (S12), state revision 2.
fn session(coordinator: &str) -> UnifiedGroupSession {
    let mut s = UnifiedGroupSession::new(GROUP, coordinator, 1);
    for (seq, (id, model)) in [("a", "S5"), ("b", "S12")].into_iter().enumerate() {
        s.apply_command(FencedControlCommand {
            epoch: 1,
            command_seq: u64::try_from(seq).expect("small") + 1,
            payload: GroupCommandPayload::AdmitMember {
                member_id: id.to_string(),
                board: fixture(model),
                role: ChannelRole::Stereo,
            },
        })
        .expect("fixture admission");
    }
    s
}

// --------------------------------------------------------------------------------- refusals

/// A refusal as the scenarios describe it: the stable code and the numbers the error carries. The
/// code `HARNESS` is this file's own complaint (a step names something that does not exist).
#[derive(Debug)]
struct Refusal {
    code: String,
    details: Value,
}

impl Refusal {
    fn harness(message: String) -> Self {
        Self {
            code: "HARNESS".to_string(),
            details: json!({ "message": message }),
        }
    }
}

impl From<MembershipError> for Refusal {
    fn from(error: MembershipError) -> Self {
        // The error serialises externally tagged: {"StaleAuthority": {"token_epoch": 1, ...}}.
        let details = match serde_json::to_value(&error) {
            Ok(Value::Object(map)) => map
                .into_iter()
                .next()
                .map_or(Value::Null, |(_, inner)| inner),
            _ => Value::Null,
        };
        Self {
            code: error.code().to_string(),
            details,
        }
    }
}

type Outcome = Result<Value, Refusal>;

fn text<'a>(step: &'a Value, key: &str) -> Result<&'a str, Refusal> {
    step.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::harness(format!("step lacks text `{key}`")))
}

fn num(step: &Value, key: &str) -> Result<u64, Refusal> {
    step.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| Refusal::harness(format!("step lacks number `{key}`")))
}

fn strings(step: &Value, key: &str) -> Result<Vec<String>, Refusal> {
    step.get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .ok_or_else(|| Refusal::harness(format!("step lacks list `{key}`")))
}

fn time(step: &Value) -> Result<GroupTime, Refusal> {
    let pair = step
        .get("now")
        .and_then(Value::as_array)
        .filter(|a| a.len() == 2)
        .map(|a| (a[0].as_u64(), a[1].as_u64()));
    match pair {
        Some((Some(ns), Some(frame))) => Ok(GroupTime { ns, frame }),
        _ => Err(Refusal::harness(
            "step lacks `now` as [ns, frame]".to_string(),
        )),
    }
}

fn save_name(step: &Value) -> Option<String> {
    step.get("save").and_then(Value::as_str).map(str::to_string)
}

fn kind_of(name: &str) -> Result<LeaseRequestKind, Refusal> {
    match name {
        "renew" => Ok(LeaseRequestKind::Renew),
        "takeover" => Ok(LeaseRequestKind::Takeover),
        other => Err(Refusal::harness(format!("unknown request kind `{other}`"))),
    }
}

fn view_of(raw: &Value) -> Result<LeaseView, Refusal> {
    Ok(LeaseView {
        group_id: raw
            .get("group")
            .and_then(Value::as_str)
            .unwrap_or(GROUP)
            .to_string(),
        epoch: num(raw, "epoch")?,
        holder: text(raw, "holder")?.to_string(),
        expires_at_ns: num(raw, "expires")?,
    })
}

fn token_view(t: &AuthorityToken) -> Value {
    json!({
        "epoch": t.epoch,
        "issuer": t.issuer_id,
        "expires": t.expires_at_ns,
        "group": t.group_id,
    })
}

fn win_view(w: &LeaseWin) -> Value {
    let kind = match w.kind() {
        LeaseRequestKind::Renew => "renew",
        LeaseRequestKind::Takeover => "takeover",
    };
    json!({
        "kind": kind,
        "epoch": w.epoch(),
        "requester": w.requester(),
        "expires": w.expires_at_ns(),
        "prior": w.prior_expires_at_ns(),
        "acks": w.acks(),
    })
}

fn status_view(status: &ProposalStatus) -> Value {
    match status {
        ProposalStatus::Pending {
            acked,
            missing,
            excluded,
        } => json!({"phase": "pending", "acked": acked, "missing": missing, "excluded": excluded}),
        ProposalStatus::Committed {
            activate_at_frame,
            excluded,
        } => json!({
            "phase": "committed",
            "activate_at_frame": activate_at_frame,
            "excluded": excluded,
        }),
        ProposalStatus::Activated { revision, excluded } => {
            json!({"phase": "activated", "revision": revision, "excluded": excluded})
        }
        ProposalStatus::Aborted { reason } => match reason {
            AbortReason::ByAuthority => json!({"phase": "aborted", "reason": "BY_AUTHORITY"}),
            AbortReason::AckDeadlineMissed { missing } => {
                json!({"phase": "aborted", "reason": "ACK_DEADLINE_MISSED", "missing": missing})
            }
            AbortReason::EpochAdvanced => json!({"phase": "aborted", "reason": "EPOCH_ADVANCED"}),
            AbortReason::CutoverMissed => json!({"phase": "aborted", "reason": "CUTOVER_MISSED"}),
            AbortReason::PreconditionFailed => {
                json!({"phase": "aborted", "reason": "PRECONDITION_FAILED"})
            }
        },
    }
}

// ----------------------------------------------------------------------------------- context

struct Node {
    engine: GroupMembership,
    session: UnifiedGroupSession,
    config: MembershipConfig,
}

struct Ctx {
    plant: Option<&'static str>,
    config: MembershipConfig,
    quorum: Option<QuorumConfig>,
    voters: BTreeMap<String, LeaseVoter>,
    nodes: BTreeMap<String, Node>,
    requests: BTreeMap<String, LeaseRequest>,
    acks: BTreeMap<String, LeaseAck>,
    wins: BTreeMap<String, LeaseWin>,
    rounds: BTreeMap<String, QuorumRound>,
    tokens: BTreeMap<String, AuthorityToken>,
    records: BTreeMap<String, DurableVoterRecord>,
}

fn config_of(raw: &Value, plant: Option<&str>) -> MembershipConfig {
    let mut config = MembershipConfig::default();
    let get = |key: &str| raw.get(key).and_then(Value::as_u64);
    if let Some(v) = get("max_members") {
        config.max_members = usize::try_from(v).expect("fits");
    }
    if let Some(v) = get("lead") {
        config.min_cutover_lead_frames = v;
    }
    if let Some(v) = get("max_lease") {
        config.lease.max_lease_ns = v;
    }
    if let Some(v) = get("u") {
        config.lease.clock_uncertainty_ns = v;
    }
    if let Some(v) = get("horizon_ns") {
        config.lease.max_output_horizon_ns = v;
    }
    if let Some(v) = get("horizon_frames") {
        config.max_output_horizon_frames = v;
    }
    config.epoch_mint = if raw.get("mode").and_then(Value::as_str) == Some("quorum") {
        EpochMint::Quorum
    } else {
        EpochMint::ConfiguredIssuer
    };
    config.missing_ack_policy = if raw.get("policy").and_then(Value::as_str) == Some("exclude") {
        MissingAckPolicy::ExcludeUnreachable
    } else {
        MissingAckPolicy::Abort
    };
    match plant {
        Some("zero_uncertainty") => config.lease.clock_uncertainty_ns = 0,
        Some("flipped_policy") => {
            config.missing_ack_policy = match config.missing_ack_policy {
                MissingAckPolicy::Abort => MissingAckPolicy::ExcludeUnreachable,
                MissingAckPolicy::ExcludeUnreachable => MissingAckPolicy::Abort,
            };
        }
        Some("flipped_mint") => {
            config.epoch_mint = match config.epoch_mint {
                EpochMint::Quorum => EpochMint::ConfiguredIssuer,
                EpochMint::ConfiguredIssuer => EpochMint::Quorum,
            };
        }
        _ => {}
    }
    config
}

impl Ctx {
    fn new(scenario: &Value, plant: Option<&'static str>) -> Result<Self, Refusal> {
        let raw = scenario.get("config").cloned().unwrap_or_default();
        let config = config_of(&raw, plant);
        let ids: Vec<String> = raw
            .get("electorate")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let mut voters = BTreeMap::new();
        let quorum = if ids.is_empty() {
            None
        } else {
            let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
            let q = QuorumConfig::new(GROUP, &refs)?;
            for id in &ids {
                voters.insert(id.clone(), LeaseVoter::new(id, q.clone(), config.lease)?);
            }
            Some(q)
        };
        Ok(Self {
            plant,
            config,
            quorum,
            voters,
            nodes: BTreeMap::new(),
            requests: BTreeMap::new(),
            acks: BTreeMap::new(),
            wins: BTreeMap::new(),
            rounds: BTreeMap::new(),
            tokens: BTreeMap::new(),
            records: BTreeMap::new(),
        })
    }

    fn quorum(&self) -> Result<QuorumConfig, Refusal> {
        self.quorum
            .clone()
            .ok_or_else(|| Refusal::harness("the scenario names no electorate".to_string()))
    }

    fn request(&self, name: &str) -> Result<LeaseRequest, Refusal> {
        self.requests
            .get(name)
            .cloned()
            .ok_or_else(|| Refusal::harness(format!("no request named `{name}`")))
    }

    fn win(&self, step: &Value) -> Result<LeaseWin, Refusal> {
        let name = text(step, "win")?;
        self.wins
            .get(name)
            .cloned()
            .ok_or_else(|| Refusal::harness(format!("no win named `{name}`")))
    }

    fn token(&self, step: &Value) -> Result<AuthorityToken, Refusal> {
        let name = text(step, "token")?;
        self.tokens
            .get(name)
            .cloned()
            .ok_or_else(|| Refusal::harness(format!("no token named `{name}`")))
    }

    fn voter(&mut self, id: &str) -> Result<&mut LeaseVoter, Refusal> {
        self.voters
            .get_mut(id)
            .ok_or_else(|| Refusal::harness(format!("no voter `{id}`")))
    }

    /// What the voter's clock reads when it judges a request: the step's, unless the plant is that
    /// every voter is judged at a far-future instant.
    fn voter_clock(&self, wanted: u64) -> u64 {
        if self.plant == Some("early_voter_clock") {
            FAR_FUTURE
        } else {
            wanted
        }
    }
}

// ---------------------------------------------------------------------------------- the ops

fn do_step(ctx: &mut Ctx, step: &Value) -> Outcome {
    match text(step, "op")? {
        "quorum" => op_quorum(step),
        "found" => op_found(ctx, step),
        "observe" => {
            let view = view_of(step.get("view").unwrap_or(&Value::Null))?;
            ctx.voter(text(step, "voter")?)?.observe(&view)?;
            Ok(json!({}))
        }
        "request" => op_request(ctx, step),
        "raw_request" => {
            let request = LeaseRequest {
                kind: kind_of(text(step, "kind")?)?,
                group_id: step
                    .get("group")
                    .and_then(Value::as_str)
                    .unwrap_or(GROUP)
                    .to_string(),
                requester: text(step, "requester")?.to_string(),
                epoch: num(step, "epoch")?,
                expires_at_ns: num(step, "expires")?,
            };
            ctx.requests
                .insert(text(step, "save")?.to_string(), request);
            Ok(json!({}))
        }
        "respond" => op_respond(ctx, step),
        "gather" => op_gather(ctx, step),
        "round_start" => {
            let request = ctx.request(text(step, "request")?)?;
            let round =
                QuorumRound::start(&ctx.quorum()?, ctx.config.lease, request, num(step, "now")?)?;
            ctx.rounds.insert(text(step, "round")?.to_string(), round);
            Ok(json!({}))
        }
        "round_ack" => op_round_ack(ctx, step),
        "round_outcome" => {
            let name = text(step, "round")?;
            let round = ctx
                .rounds
                .get(name)
                .ok_or_else(|| Refusal::harness(format!("no round named `{name}`")))?;
            Ok(win_view(&round.outcome(num(step, "now")?)?))
        }
        "record" => op_record(ctx, step),
        "restart" => {
            let id = text(step, "voter")?;
            let voter = LeaseVoter::after_restart(id, ctx.quorum()?, ctx.config.lease)?;
            ctx.voters.insert(id.to_string(), voter);
            Ok(json!({}))
        }
        "restore" => {
            let name = text(step, "record")?;
            let record = ctx
                .records
                .get(name)
                .cloned()
                .ok_or_else(|| Refusal::harness(format!("no record named `{name}`")))?;
            ctx.voter(text(step, "voter")?)?.restore(record)?;
            Ok(json!({}))
        }
        "forget" => {
            let id = text(step, "voter")?;
            let mut voter = LeaseVoter::new(id, ctx.quorum()?, ctx.config.lease)?;
            voter.observe(&view_of(step.get("view").unwrap_or(&Value::Null))?)?;
            ctx.voters.insert(id.to_string(), voter);
            Ok(json!({}))
        }
        "node" => op_node(ctx, step),
        other => node_step(ctx, other, step),
    }
}

fn op_quorum(step: &Value) -> Outcome {
    let ids = strings(step, "voters")?;
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let q = QuorumConfig::new(GROUP, &refs)?;
    Ok(json!({ "need": q.quorum() }))
}

fn op_found(ctx: &mut Ctx, step: &Value) -> Outcome {
    let view = LeaseView {
        group_id: GROUP.to_string(),
        epoch: 1,
        holder: text(step, "holder")?.to_string(),
        expires_at_ns: num(step, "expires")?,
    };
    for voter in ctx.voters.values_mut() {
        voter.observe(&view)?;
    }
    Ok(json!({}))
}

fn op_request(ctx: &mut Ctx, step: &Value) -> Outcome {
    let (at, len) = (num(step, "at")?, num(step, "len")?);
    let id = text(step, "voter")?;
    let voter = ctx
        .voters
        .get(id)
        .ok_or_else(|| Refusal::harness(format!("no voter `{id}`")))?;
    let request = if text(step, "kind")? == "renew" {
        voter.renew_request(at, len)?
    } else {
        voter.takeover_request(at, len)?
    };
    let out = json!({
        "epoch": request.epoch,
        "expires": request.expires_at_ns,
        "requester": request.requester,
    });
    ctx.requests
        .insert(text(step, "save")?.to_string(), request);
    Ok(out)
}

fn op_respond(ctx: &mut Ctx, step: &Value) -> Outcome {
    let request = ctx.request(text(step, "request")?)?;
    let clock = ctx.voter_clock(num(step, "clock")?);
    let ack = ctx.voter(text(step, "voter")?)?.respond(&request, clock)?;
    let out = json!({
        "voter": ack.voter,
        "epoch": ack.epoch,
        "prior": ack.prior_expires_at_ns,
        "expires": ack.expires_at_ns,
    });
    if let Some(name) = save_name(step) {
        ctx.acks.insert(name, ack);
    }
    Ok(out)
}

fn op_gather(ctx: &mut Ctx, step: &Value) -> Outcome {
    let request = ctx.request(text(step, "request")?)?;
    let now = num(step, "now")?;
    let mut round = QuorumRound::start(&ctx.quorum()?, ctx.config.lease, request.clone(), now)?;
    let default_clock = step.get("clock").and_then(Value::as_u64).unwrap_or(now);
    for id in strings(step, "reach")? {
        let wanted = step
            .get("clocks")
            .and_then(|c| c.get(&id))
            .and_then(Value::as_u64)
            .unwrap_or(default_clock);
        let clock = ctx.voter_clock(wanted);
        if let Ok(ack) = ctx.voter(&id)?.respond(&request, clock) {
            round.record(&ack, now)?;
        }
    }
    let win = round.outcome(now)?;
    let out = win_view(&win);
    if let Some(name) = save_name(step) {
        ctx.wins.insert(name, win);
    }
    Ok(out)
}

fn op_round_ack(ctx: &mut Ctx, step: &Value) -> Outcome {
    let name = text(step, "ack")?;
    let mut ack = ctx
        .acks
        .get(name)
        .cloned()
        .ok_or_else(|| Refusal::harness(format!("no ack named `{name}`")))?;
    if let Some(tamper) = step.get("tamper").and_then(Value::as_object) {
        for (key, value) in tamper {
            let as_text = value.as_str().unwrap_or_default().to_string();
            let as_number = value.as_u64().unwrap_or_default();
            match key.as_str() {
                "epoch" => ack.epoch = as_number,
                "expires" => ack.expires_at_ns = as_number,
                "prior" => ack.prior_expires_at_ns = as_number,
                "kind" => ack.kind = kind_of(&as_text)?,
                "requester" => ack.requester = as_text,
                "group" => ack.group_id = as_text,
                "voter" => ack.voter = as_text,
                other => return Err(Refusal::harness(format!("cannot tamper with `{other}`"))),
            }
        }
    }
    let round_name = text(step, "round")?;
    let round = ctx
        .rounds
        .get_mut(round_name)
        .ok_or_else(|| Refusal::harness(format!("no round named `{round_name}`")))?;
    round.record(&ack, num(step, "now")?)?;
    Ok(json!({}))
}

fn op_record(ctx: &mut Ctx, step: &Value) -> Outcome {
    let record = ctx.voter(text(step, "voter")?)?.durable_record();
    let view = record
        .view
        .as_ref()
        .map(|v| json!({"epoch": v.epoch, "holder": v.holder, "expires": v.expires_at_ns}));
    let grant = record.grant.as_ref().map(|g| {
        json!({
            "epoch": g.epoch,
            "candidate": g.candidate,
            "expires": g.expires_at_ns,
            "prior": g.prior_expires_at_ns,
        })
    });
    let out = json!({"voter_id": record.voter_id, "view": view, "grant": grant});
    if let Some(name) = save_name(step) {
        ctx.records.insert(name, record);
    }
    Ok(out)
}

fn op_node(ctx: &mut Ctx, step: &Value) -> Outcome {
    let mut config = ctx.config;
    if let Some(mode) = step.get("mode").and_then(Value::as_str) {
        // An explicit mode is the scenario's; the mint plant swaps it like it swaps the default.
        let quorum = (mode == "quorum") != (ctx.plant == Some("flipped_mint"));
        config.epoch_mint = if quorum {
            EpochMint::Quorum
        } else {
            EpochMint::ConfiguredIssuer
        };
    }
    let coordinator = step.get("coordinator").and_then(Value::as_str).map_or_else(
        || {
            if config.epoch_mint == EpochMint::Quorum {
                "v1".to_string()
            } else {
                "coord".to_string()
            }
        },
        str::to_string,
    );
    let engine = if step.get("restarted").and_then(Value::as_bool) == Some(true) {
        GroupMembership::after_restart(config)
    } else {
        GroupMembership::new(config)
    };
    ctx.nodes.insert(
        text(step, "name")?.to_string(),
        Node {
            engine,
            session: session(&coordinator),
            config,
        },
    );
    Ok(json!({}))
}

fn change_of(raw: &Value) -> Result<MembershipChange, Refusal> {
    let member_id = text(raw, "member")?.to_string();
    match text(raw, "kind")? {
        "join" => Ok(MembershipChange::Join {
            member_id,
            board: Box::new(board(text(raw, "board")?)),
            role: ChannelRole::Stereo,
        }),
        "leave" => Ok(MembershipChange::Leave { member_id }),
        other => Err(Refusal::harness(format!("unknown change `{other}`"))),
    }
}

fn report_of(step: &Value) -> ReadinessReport {
    let raw = step.get("report");
    let flag = |key: &str| {
        raw.and_then(|r| r.get(key))
            .and_then(Value::as_bool)
            .unwrap_or(true)
    };
    ReadinessReport {
        format_ok: flag("format_ok"),
        buffer_ok: flag("buffer_ok"),
        clock_confident: flag("clock_confident"),
        can_stop_flush: flag("can_stop_flush"),
        old_output_tail_complete_frame: raw
            .and_then(|r| r.get("tail"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
    }
}

fn node_step(ctx: &mut Ctx, op: &str, step: &Value) -> Outcome {
    let name = text(step, "node")?;
    // Anything that lives in another map is looked up before the node is borrowed.
    let token = ctx.token(step);
    let win = ctx.win(step);
    let node = ctx
        .nodes
        .get_mut(name)
        .ok_or_else(|| Refusal::harness(format!("no node `{name}`")))?;
    match op {
        "issue" => {
            let mut issued = AuthorityToken::issue(&node.session, num(step, "expires")?);
            if let Some(over) = step.get("override").and_then(Value::as_object) {
                for (key, value) in over {
                    let as_text = value.as_str().unwrap_or_default().to_string();
                    let as_number = value.as_u64().unwrap_or_default();
                    match key.as_str() {
                        "group" => issued.group_id = as_text,
                        "issuer" => issued.issuer_id = as_text,
                        "epoch" => issued.epoch = as_number,
                        "expires" => issued.expires_at_ns = as_number,
                        other => {
                            return Err(Refusal::harness(format!("cannot override `{other}`")));
                        }
                    }
                }
            }
            let out = token_view(&issued);
            ctx.tokens.insert(text(step, "save")?.to_string(), issued);
            Ok(out)
        }
        "live" => Ok(json!({
            "live": node.engine.lease_is_live(&node.session, &token?, num(step, "at")?),
        })),
        "renew" => {
            let renewed = node
                .engine
                .renew_lease(&node.session, &token?, &win?, time(step)?)?;
            let out = token_view(&renewed);
            if let Some(save) = save_name(step) {
                ctx.tokens.insert(save, renewed);
            }
            Ok(out)
        }
        "assume" => {
            let assumed = node
                .engine
                .assume_authority(&mut node.session, &win?, time(step)?)?;
            let out = token_view(&assumed);
            if let Some(save) = save_name(step) {
                ctx.tokens.insert(save, assumed);
            }
            Ok(out)
        }
        "adopt" => {
            let view = view_of(step.get("view").unwrap_or(&Value::Null))?;
            node.engine.adopt_authority(&mut node.session, &view)?;
            Ok(json!({}))
        }
        "session" => Ok(json!({
            "epoch": node.session.current_epoch,
            "coordinator": node.session.coordinator_id,
            "revision": node.session.state_revision,
            "members": node.session.members.keys().collect::<Vec<_>>(),
        })),
        "probe" => {
            // A stand-in for a real mutation: propose a join of "probe" and abort it.
            let now = time(step)?;
            let token = token?;
            let spec = ProposalSpec {
                change: MembershipChange::Join {
                    member_id: "probe".to_string(),
                    board: Box::new(board("S1")),
                    role: ChannelRole::Stereo,
                },
                cutover_frame: now.frame + 100_000,
                ack_deadline_ns: now.ns + 10_000,
            };
            let id = node.engine.propose(&node.session, &token, spec, now)?;
            node.engine.abort(&node.session, &token, id, now)?;
            Ok(json!({}))
        }
        "advance" => {
            let advanced = node.engine.advance_epoch(
                &mut node.session,
                &token?,
                num(step, "epoch")?,
                time(step)?,
            )?;
            let out = token_view(&advanced);
            if let Some(save) = save_name(step) {
                ctx.tokens.insert(save, advanced);
            }
            Ok(out)
        }
        "discover" => {
            node.engine
                .discover_authority(&node.session, &token?, num(step, "at")?)?;
            Ok(json!({}))
        }
        "gate" => Ok(match node.engine.takeover_start_gate(num(step, "at")?) {
            Ok(()) => json!({"open": true, "until": Value::Null}),
            Err(until) => json!({"open": false, "until": until}),
        }),
        "grant_output" => {
            let granted = node.engine.grant_output(
                &node.session,
                &token?,
                text(step, "member")?,
                num(step, "through")?,
                time(step)?,
            )?;
            Ok(json!({ "granted": granted }))
        }
        "permitted" => Ok(json!({
            "permitted": node.engine.output_permitted(text(step, "member")?, num(step, "frame")?),
        })),
        "propose" => {
            let spec = ProposalSpec {
                change: change_of(step.get("change").unwrap_or(&Value::Null))?,
                cutover_frame: num(step, "cutover")?,
                ack_deadline_ns: num(step, "deadline")?,
            };
            let id = node
                .engine
                .propose(&node.session, &token?, spec, time(step)?)?;
            Ok(json!({ "id": id }))
        }
        "ack" => {
            node.engine.ack(
                num(step, "id")?,
                text(step, "member")?,
                report_of(step),
                time(step)?,
            )?;
            Ok(json!({}))
        }
        "commit" => {
            let status =
                node.engine
                    .commit(&node.session, &token?, num(step, "id")?, time(step)?)?;
            Ok(json!({ "status": status_view(&status) }))
        }
        "abort" => {
            let status =
                node.engine
                    .abort(&node.session, &token?, num(step, "id")?, time(step)?)?;
            Ok(json!({ "status": status_view(&status) }))
        }
        "tick" => {
            let settled: Vec<Value> = node
                .engine
                .tick(&mut node.session, time(step)?)
                .iter()
                .map(|(id, status)| json!({"id": id, "status": status_view(status)}))
                .collect();
            Ok(json!({ "settled": settled }))
        }
        "status" => {
            let status = node.engine.status(num(step, "id")?)?;
            Ok(json!({ "status": status_view(&status) }))
        }
        "resolve" => {
            let raw = step.get("resolution").unwrap_or(&Value::Null);
            let resolution = match text(raw, "kind")? {
                "stop" => OutputResolution::StopAcknowledged,
                "expires" => OutputResolution::ExpiresAtFrame(num(raw, "frame")?),
                other => return Err(Refusal::harness(format!("unknown resolution `{other}`"))),
            };
            node.engine
                .resolve_output(text(step, "member")?, resolution)?;
            Ok(json!({}))
        }
        "start_gate" => Ok(
            match node.engine.conflicting_start_gate(num(step, "frame")?) {
                Ok(()) => json!({"open": true, "blocked": Vec::<String>::new()}),
                Err(blocked) => json!({"open": false, "blocked": blocked}),
            },
        ),
        "unresolved" => Ok(json!({ "members": node.engine.unresolved_output() })),
        "restart_node" => {
            node.engine = GroupMembership::after_restart(node.config);
            Ok(json!({}))
        }
        other => Err(Refusal::harness(format!("unknown op `{other}`"))),
    }
}

// ------------------------------------------------------------------------------- replaying

/// Every key of `expected` is present in `actual` with an equal value, recursively for objects.
fn subset(expected: &Value, actual: &Value, path: &str) -> Option<String> {
    if let (Value::Object(want), Value::Object(got)) = (expected, actual) {
        for (key, wanted) in want {
            match got.get(key) {
                None => return Some(format!("{path}.{key} missing")),
                Some(found) => {
                    if let Some(problem) = subset(wanted, found, &format!("{path}.{key}")) {
                        return Some(problem);
                    }
                }
            }
        }
        return None;
    }
    if expected == actual {
        None
    } else {
        Some(format!("{path}: wanted {expected}, got {actual}"))
    }
}

/// `None` when the step met its expectation, else a short description of the mismatch.
fn run_step(ctx: &mut Ctx, step: &Value) -> Option<String> {
    let expect = step.get("expect").unwrap_or(&Value::Null);
    let empty = json!({});
    match do_step(ctx, step) {
        Err(refusal) => {
            let Some(code) = expect.get("error").and_then(Value::as_str) else {
                return Some(format!(
                    "refused {} {}, wanted success",
                    refusal.code, refusal.details
                ));
            };
            if code != refusal.code {
                return Some(format!("refused {}, wanted {code}", refusal.code));
            }
            subset(
                expect.get("details").unwrap_or(&empty),
                &refusal.details,
                "details",
            )
        }
        Ok(value) => {
            if let Some(code) = expect.get("error") {
                return Some(format!("succeeded with {value}, wanted {code}"));
            }
            subset(expect.get("ok").unwrap_or(&empty), &value, "ok")
        }
    }
}

fn substitute(value: &Value, n: u64) -> Value {
    match value {
        Value::String(s) if s == "$n" => json!(n),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), substitute(v, n)))
                .collect::<Map<String, Value>>(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(|v| substitute(v, n)).collect()),
        other => other.clone(),
    }
}

/// A `repeat` step stands for `count` copies of its steps, with "$n" counting from 1.
fn expand(steps: &[Value]) -> Vec<Value> {
    let mut out = Vec::new();
    for step in steps {
        if step.get("op").and_then(Value::as_str) == Some("repeat") {
            let count = step.get("count").and_then(Value::as_u64).unwrap_or(0);
            let inner = step
                .get("steps")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for n in 1..=count {
                out.extend(inner.iter().map(|s| substitute(s, n)));
            }
        } else {
            out.push(step.clone());
        }
    }
    out
}

/// Replay one scenario: the number of steps run and every mismatch.
fn replay(scenario: &Value, plant: Option<&'static str>) -> (usize, Vec<String>) {
    let raw_steps = scenario
        .get("steps")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let steps = expand(&raw_steps);
    let mut ctx = match Ctx::new(scenario, plant) {
        Ok(ctx) => ctx,
        Err(refusal) => {
            return (
                steps.len(),
                vec![format!("setup refused: {}", refusal.code)],
            );
        }
    };
    let mut problems = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        if let Some(problem) = run_step(&mut ctx, step) {
            let op = step.get("op").and_then(Value::as_str).unwrap_or("?");
            problems.push(format!("step {index} ({op}): {problem}"));
        }
    }
    (steps.len(), problems)
}

fn doc() -> Value {
    serde_json::from_str(VECTORS).expect("the vector file is valid JSON")
}

fn observe(line: &Value) {
    println!("G01-OBSERVED {line}");
}

fn scenario_id(scenario: &Value) -> &str {
    scenario.get("id").and_then(Value::as_str).unwrap_or("?")
}

fn scenarios(doc: &Value) -> &[Value] {
    doc.get("scenarios")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
}

// ---------------------------------------------------------------------- the seeded schedule

struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }
}

#[derive(Default, Clone, Copy)]
struct Counts {
    renewals: u64,
    minority_refused: u64,
    takeovers: u64,
    takeovers_refused: u64,
    fenced: u64,
    mutations_accepted: u64,
    led_steps: u64,
    leaderless_steps: u64,
    overlaps: u64,
    conflicts: u64,
}

impl Counts {
    fn to_json(self) -> Value {
        json!({
            "renewals": self.renewals,
            "minority_refused": self.minority_refused,
            "takeovers": self.takeovers,
            "takeovers_refused": self.takeovers_refused,
            "fenced": self.fenced,
            "mutations_accepted": self.mutations_accepted,
            "led_steps": self.led_steps,
            "leaderless_steps": self.leaderless_steps,
            "overlaps": self.overlaps,
            "conflicts": self.conflicts,
        })
    }
}

struct SimNode {
    voter: LeaseVoter,
    engine: GroupMembership,
    session: UnifiedGroupSession,
    token: Option<AuthorityToken>,
    /// This node's clock reads true time plus this offset.
    offset: i64,
}

/// Nodes that renew, take over, mutate and hear announcements, on a network that partitions at
/// random and clocks that disagree by up to a bounded offset, driven through the public API.
struct Cluster {
    quorum: QuorumConfig,
    terms: LeaseTerms,
    nodes: Vec<SimNode>,
    side: Vec<u8>,
    true_ns: u64,
    winners: BTreeMap<u64, usize>,
    counts: Counts,
    rng: SplitMix64,
    lossy: bool,
    mute: bool,
    join_board: BoardProfile,
}

fn code_of(error: &MembershipError) -> String {
    error.code().to_string()
}

impl Cluster {
    fn new(
        seed: u64,
        voters: usize,
        uncertainty_ns: u64,
        max_offset: i64,
        skew_holder: bool,
    ) -> Result<Self, String> {
        let terms = LeaseTerms {
            max_lease_ns: 2_000,
            clock_uncertainty_ns: uncertainty_ns,
            max_output_horizon_ns: 1_000,
        };
        let ids: Vec<String> = (1..=voters).map(|i| format!("v{i}")).collect();
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let quorum = QuorumConfig::new(GROUP, &refs).map_err(|e| code_of(&e))?;
        let mut rng = SplitMix64(seed);
        let span = u64::try_from(2 * max_offset + 1).map_err(|e| e.to_string())?;
        let founding = 11_500;
        let config = MembershipConfig {
            epoch_mint: EpochMint::Quorum,
            lease: terms,
            max_output_horizon_frames: 1_000,
            ..MembershipConfig::default()
        };
        let mut nodes: Vec<SimNode> = Vec::new();
        for id in quorum.voters() {
            let mut voter = LeaseVoter::new(id, quorum.clone(), terms).map_err(|e| code_of(&e))?;
            voter
                .observe(&LeaseView {
                    group_id: GROUP.to_string(),
                    epoch: 1,
                    holder: "v1".to_string(),
                    expires_at_ns: founding,
                })
                .map_err(|e| code_of(&e))?;
            let mut offset =
                i64::try_from(rng.below(span)).map_err(|e| e.to_string())? - max_offset;
            if skew_holder {
                // The worst case: the holder's clock is the slowest, everyone else's the fastest.
                offset = if nodes.is_empty() {
                    -max_offset
                } else {
                    max_offset
                };
            }
            let fresh = session("v1");
            let token = if nodes.is_empty() {
                Some(AuthorityToken::issue(&fresh, founding))
            } else {
                None
            };
            nodes.push(SimNode {
                voter,
                engine: GroupMembership::new(config),
                session: fresh,
                token,
                offset,
            });
        }
        Ok(Self {
            quorum,
            terms,
            nodes,
            side: vec![0; voters],
            true_ns: 10_000,
            winners: BTreeMap::new(),
            counts: Counts::default(),
            rng,
            lossy: false,
            mute: false,
            join_board: fixture("S1"),
        })
    }

    fn clock(&self, i: usize) -> u64 {
        self.true_ns
            .checked_add_signed(self.nodes[i].offset)
            .expect("clocks stay positive")
    }

    fn time(&self, i: usize) -> GroupTime {
        let ns = self.clock(i);
        GroupTime { ns, frame: ns }
    }

    /// Nodes on the same side of the partition as `i`, `i` included.
    fn reach(&self, i: usize) -> Vec<usize> {
        (0..self.nodes.len())
            .filter(|&j| self.side[j] == self.side[i])
            .collect()
    }

    /// The node holding the highest-epoch token (the lowest index on a tie), if any.
    fn newest_holder(&self) -> Option<usize> {
        (0..self.nodes.len())
            .filter_map(|i| {
                self.nodes[i]
                    .token
                    .as_ref()
                    .map(|t| (t.epoch, std::cmp::Reverse(i)))
            })
            .max()
            .map(|(_, std::cmp::Reverse(i))| i)
    }

    fn pick_node(&mut self) -> usize {
        let n = u64::try_from(self.nodes.len()).expect("small");
        usize::try_from(self.rng.below(n)).expect("small")
    }

    /// Node `i` sends `request` to its side and gathers what comes back, each voter judging it by
    /// its own clock. `None` if no round could even start.
    fn collect(
        &mut self,
        i: usize,
        request: &LeaseRequest,
    ) -> Option<Result<LeaseWin, MembershipError>> {
        let now = self.clock(i);
        let mut round = QuorumRound::start(&self.quorum, self.terms, request.clone(), now).ok()?;
        for j in self.reach(i) {
            let at = self.clock(j);
            if let Ok(ack) = self.nodes[j].voter.respond(request, at) {
                let _ = round.record(&ack, now);
            }
        }
        Some(round.outcome(now))
    }

    fn try_renew(&mut self, i: usize, len: u64) {
        let Some(token) = self.nodes[i].token.clone() else {
            return;
        };
        let now = self.clock(i);
        let Ok(request) = self.nodes[i].voter.renew_request(now, len) else {
            return;
        };
        match self.collect(i, &request) {
            Some(Ok(win)) => {
                let time = self.time(i);
                let node = &mut self.nodes[i];
                if let Ok(renewed) = node.engine.renew_lease(&node.session, &token, &win, time) {
                    node.token = Some(renewed);
                    self.counts.renewals += 1;
                }
            }
            Some(Err(MembershipError::NoQuorum { .. })) => self.counts.minority_refused += 1,
            Some(Err(_)) | None => {}
        }
    }

    fn try_takeover(&mut self, i: usize, len: u64) -> Result<(), String> {
        let now = self.clock(i);
        let Ok(request) = self.nodes[i].voter.takeover_request(now, len) else {
            return Ok(());
        };
        match self.collect(i, &request) {
            Some(Ok(win)) => {
                let time = self.time(i);
                let node = &mut self.nodes[i];
                match node.engine.assume_authority(&mut node.session, &win, time) {
                    Ok(token) => {
                        node.token = Some(token.clone());
                        // The winner learns its own lease like every other voter.
                        node.voter
                            .observe(&token.lease_view())
                            .map_err(|e| code_of(&e))?;
                        let first = *self.winners.entry(win.epoch()).or_insert(i);
                        if first != i {
                            return Err(format!("two nodes won epoch {}", win.epoch()));
                        }
                        self.counts.takeovers += 1;
                        self.announce(i, &token.lease_view());
                    }
                    Err(_) => self.counts.takeovers_refused += 1,
                }
            }
            Some(Err(_)) => self.counts.takeovers_refused += 1,
            None => {}
        }
        Ok(())
    }

    /// `from` tells every node on its side which lease is current.
    fn announce(&mut self, from: usize, view: &LeaseView) {
        if self.mute {
            return;
        }
        for j in self.reach(from) {
            if j == from {
                continue;
            }
            if self.lossy && self.rng.below(3) == 0 {
                continue;
            }
            let node = &mut self.nodes[j];
            if matches!(
                node.voter.observe(view),
                Err(MembershipError::ConflictingLeaders { .. })
            ) {
                self.counts.conflicts += 1;
            }
            if matches!(
                node.engine.adopt_authority(&mut node.session, view),
                Err(MembershipError::ConflictingLeaders { .. })
            ) {
                self.counts.conflicts += 1;
            }
        }
    }

    /// The newest holder tells everyone it can reach.
    fn gossip(&mut self) {
        let Some(holder) = self.newest_holder() else {
            return;
        };
        let Some(view) = self.nodes[holder]
            .token
            .as_ref()
            .map(AuthorityToken::lease_view)
        else {
            return;
        };
        self.announce(holder, &view);
    }

    /// Node `i` tries to start a membership change under whatever token it holds.
    fn try_mutation(&mut self, i: usize) -> Result<(), String> {
        let Some(token) = self.nodes[i].token.clone() else {
            return Ok(());
        };
        let time = self.time(i);
        let board = self.join_board.clone();
        let node = &mut self.nodes[i];
        let live = node.engine.lease_is_live(&node.session, &token, time.ns);
        let spec = ProposalSpec {
            change: MembershipChange::Join {
                member_id: "c".to_string(),
                board: Box::new(board),
                role: ChannelRole::Stereo,
            },
            cutover_frame: time.frame + 100_000,
            ack_deadline_ns: time.ns + 10_000,
        };
        match node.engine.propose(&node.session, &token, spec, time) {
            Ok(id) => {
                if !live {
                    return Err(format!(
                        "node {i} proposed on a lease it should consider over"
                    ));
                }
                node.engine
                    .abort(&node.session, &token, id, time)
                    .map_err(|e| code_of(&e))?;
                self.counts.mutations_accepted += 1;
            }
            Err(error) => {
                let fenced = matches!(error, MembershipError::StaleAuthority { .. });
                if fenced {
                    self.counts.fenced += 1;
                }
                let expired = matches!(error, MembershipError::AuthorityExpired { .. });
                if !live && !fenced && !expired {
                    return Err(format!(
                        "node {i} was refused for the wrong reason: {}",
                        error.code()
                    ));
                }
            }
        }
        Ok(())
    }

    fn repartition(&mut self) {
        let together = self.rng.below(4) == 0;
        let n = self.nodes.len();
        let mut sides = Vec::with_capacity(n);
        for _ in 0..n {
            sides.push(if together {
                0
            } else {
                u8::try_from(self.rng.below(2)).expect("a bit")
            });
        }
        self.side = sides;
        self.gossip();
    }

    /// Checked after every step: how many nodes consider their own lease live right now.
    fn check(&mut self) {
        let live = (0..self.nodes.len())
            .filter(|&i| {
                let node = &self.nodes[i];
                node.token.as_ref().is_some_and(|token| {
                    node.engine
                        .lease_is_live(&node.session, token, self.clock(i))
                })
            })
            .count();
        match live {
            0 => self.counts.leaderless_steps += 1,
            1 => self.counts.led_steps += 1,
            _ => self.counts.overlaps += 1,
        }
    }

    fn expect(&self, got: u64, want: u64, why: &str) -> Result<(), String> {
        if got == want {
            Ok(())
        } else {
            Err(format!("prologue: {why} (got {got}, wanted {want})"))
        }
    }

    /// The paths random choice reaches only occasionally, taken on purpose.
    fn prologue(&mut self) -> Result<(), String> {
        self.true_ns += 200;
        self.try_renew(0, 1_500);
        self.expect(self.counts.renewals, 1, "a connected holder renews")?;
        self.side[0] = 1;
        self.true_ns += 100;
        self.try_renew(0, 1_500);
        self.expect(
            self.counts.minority_refused,
            1,
            "an isolated holder gets one acknowledgement and no more",
        )?;
        // The earliest true time at which every other node's clock has reached the holder's expiry
        // plus u, so every voter on the majority side will grant.
        let expiry = self.nodes[0]
            .token
            .as_ref()
            .ok_or("the holder lost its token")?
            .expires_at_ns;
        let slowest = self.nodes[1..]
            .iter()
            .map(|n| n.offset)
            .min()
            .ok_or("there are no other nodes")?;
        let boundary = (expiry + self.terms.clock_uncertainty_ns)
            .checked_add_signed(-slowest)
            .ok_or("clocks went negative")?;
        self.true_ns = self.true_ns.max(boundary);
        self.check();
        self.try_takeover(1, 1_500)?;
        self.expect(self.counts.takeovers, 1, "the majority side takes over")?;
        self.check();
        self.side = vec![0; self.nodes.len()];
        self.gossip();
        self.try_mutation(0)?;
        self.expect(self.counts.fenced, 1, "the old holder is fenced by epoch")?;
        self.check();
        self.duel()
    }

    /// Two candidates for one epoch, the first announcement lost. Node 2 wins epoch 3 with the nodes
    /// on its side; nodes 1 (and 4) never hear of it. Later node 1, unaware, asks a voter that holds
    /// only its grant for the same epoch.
    fn duel(&mut self) -> Result<(), String> {
        let n = self.nodes.len();
        let late: Vec<usize> = if n == 5 { vec![1, 4] } else { vec![1] };
        self.true_ns += 4_000;
        self.side = (0..n).map(|j| u8::from(late.contains(&j))).collect();
        self.mute = true;
        let before = self.counts.takeovers;
        self.try_takeover(2, 1_500)?;
        self.mute = false;
        self.expect(
            self.counts.takeovers,
            before + 1,
            "the first candidate wins",
        )?;
        self.true_ns += 3_000;
        let together: Vec<usize> = if n == 5 { vec![0, 1, 4] } else { vec![0, 1] };
        self.side = (0..n).map(|j| u8::from(!together.contains(&j))).collect();
        self.try_takeover(1, 1_500)?;
        self.expect(
            self.counts.takeovers,
            before + 1,
            "a rival for a granted epoch must not win",
        )?;
        self.side = vec![0; n];
        self.gossip();
        self.check();
        Ok(())
    }

    fn step(&mut self) -> Result<(), String> {
        self.true_ns += 1 + self.rng.below(300);
        let len = 500 + self.rng.below(1_500);
        let actor = self.pick_node();
        match self.rng.below(100) {
            0..30 => {
                // The newest holder usually renews; sometimes any node, possibly a stale one.
                let i = if self.rng.below(4) == 0 {
                    actor
                } else {
                    self.newest_holder().unwrap_or(actor)
                };
                self.try_renew(i, len);
            }
            30..65 => self.try_takeover(actor, len)?,
            65..85 => self.try_mutation(actor)?,
            _ => self.repartition(),
        }
        self.check();
        Ok(())
    }
}

fn run_schedule(
    seed: u64,
    uncertainty_ns: u64,
    max_offset: i64,
    skew_holder: bool,
    steps: u64,
) -> Result<Counts, String> {
    let voters = 3 + 2 * usize::try_from(seed % 2).expect("a bit");
    let mut cluster = Cluster::new(seed, voters, uncertainty_ns, max_offset, skew_holder)?;
    cluster.prologue()?;
    cluster.lossy = true;
    for _ in 0..steps {
        cluster.step()?;
    }
    Ok(cluster.counts)
}

// ------------------------------------------------------------------------------------ tests

#[test]
fn every_golden_scenario_matches_the_engine() {
    let doc = doc();
    let mut failed = Vec::new();
    for scenario in scenarios(&doc) {
        let id = scenario_id(scenario);
        let (steps, problems) = replay(scenario, None);
        observe(&json!({"kind": "scenario", "id": id, "steps": steps, "mismatches": problems}));
        if !problems.is_empty() {
            failed.push(format!("{id}: {}", problems.join("; ")));
        }
    }
    assert!(
        failed.is_empty(),
        "{} of {} scenarios disagree with the engine:\n{}",
        failed.len(),
        scenarios(&doc).len(),
        failed.join("\n")
    );
}

#[test]
fn the_seeded_schedule_reproduces_the_models_counts_exactly() {
    let doc = doc();
    let section = &doc["schedule"];
    let steps = section["steps"]
        .as_u64()
        .expect("the schedule names its steps");
    let runs = section["runs"]
        .as_array()
        .expect("the schedule names its runs");
    let mut wrong = Vec::new();
    for run in runs {
        let seed = run["seed"].as_u64().expect("seed");
        let uncertainty = run["u"].as_u64().expect("u");
        let max_offset = run["max_offset"].as_i64().expect("max_offset");
        let skew = run["skew_holder"].as_bool().expect("skew_holder");
        let outcome = run_schedule(seed, uncertainty, max_offset, skew, steps);
        let (counts, error) = match &outcome {
            Ok(counts) => (counts.to_json(), Value::Null),
            Err(message) => (Value::Null, json!(message)),
        };
        let agree = counts == run["counts"];
        observe(&json!({
            "kind": "schedule",
            "seed": seed,
            "u": uncertainty,
            "max_offset": max_offset,
            "skew_holder": skew,
            "counts": counts,
            "error": error,
            "matches": agree,
        }));
        if !agree {
            wrong.push(format!(
                "seed {seed} u={uncertainty} offset={max_offset} skew={skew}: engine {counts} error {error}, model {}",
                run["counts"]
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} schedule runs differ from the model:\n{}",
        wrong.len(),
        runs.len(),
        wrong.join("\n")
    );
}

/// Change one expected number in the first step of `op` that has one.
fn corrupt_number(scenario: &Value, op: &str) -> Value {
    let mut copy = scenario.clone();
    let steps = copy["steps"].as_array_mut().expect("steps");
    for step in steps {
        if step["op"].as_str() == Some(op) && step["expect"]["ok"]["revision"].is_number() {
            step["expect"]["ok"]["revision"] = json!(99_999);
            return copy;
        }
    }
    panic!("no `{op}` step with a revision to corrupt");
}

/// Change one expected error code in the first refusal of `scenario`.
fn corrupt_code(scenario: &Value) -> Value {
    let mut copy = scenario.clone();
    let steps = copy["steps"].as_array_mut().expect("steps");
    for step in steps {
        if step["expect"]["error"].is_string() {
            step["expect"]["error"] = json!("NOT_A_CODE_THE_ENGINE_HAS");
            return copy;
        }
    }
    panic!("no refusal to corrupt");
}

#[test]
fn a_planted_fault_breaks_exactly_the_scenarios_the_model_predicts() {
    let doc = doc();
    let all = scenarios(&doc);
    let clean: Vec<&str> = all
        .iter()
        .filter(|s| !replay(s, None).1.is_empty())
        .map(scenario_id)
        .collect();
    assert!(
        clean.is_empty(),
        "the unplanted replay must be green first: {clean:?}"
    );

    let plants = doc["plants"]
        .as_array()
        .expect("the vector file names its plants");
    assert_eq!(plants.len(), PLANTS.len());
    let mut disagreements = Vec::new();
    for entry in plants {
        let name = entry["name"].as_str().expect("plant name");
        let plant: &'static str = PLANTS
            .iter()
            .copied()
            .find(|p| *p == name)
            .expect("a plant this replay knows");
        let broken: Vec<String> = all
            .iter()
            .filter(|s| !replay(s, Some(plant)).1.is_empty())
            .map(|s| scenario_id(s).to_string())
            .collect();
        let predicted: Vec<String> = entry["fails"]
            .as_array()
            .expect("the plant names the scenarios it breaks")
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        observe(&json!({"kind": "plant", "name": name, "broken": broken, "predicted": predicted}));
        assert!(
            !broken.is_empty(),
            "plant {name} broke nothing, so the replay cannot tell the fault from the engine"
        );
        if broken != predicted {
            disagreements.push(format!("{name}: engine {broken:?}, model {predicted:?}"));
        }
    }

    // A replay that accepted anything would also be green. Corrupt one number and one code.
    let first = &all[0];
    let wrong_number = replay(&corrupt_number(first, "session"), None).1;
    let wrong_code = replay(&corrupt_code(&all[3]), None).1;
    observe(&json!({
        "kind": "corrupted",
        "wrong_number_reported": !wrong_number.is_empty(),
        "wrong_code_reported": !wrong_code.is_empty(),
    }));
    assert!(
        !wrong_number.is_empty(),
        "a wrong expected number was accepted"
    );
    assert!(!wrong_code.is_empty(), "a wrong expected code was accepted");
    assert!(
        disagreements.is_empty(),
        "planted faults break different scenarios in the engine and the model:\n{}",
        disagreements.join("\n")
    );
}

#[test]
fn the_vector_file_is_the_one_this_replay_understands() {
    let doc = doc();
    assert_eq!(doc["schema"].as_str(), Some("ffw.g01.scenarios.v1"));
    assert_eq!(doc["bead"].as_str(), Some("ffw-kh0"));
    let all = scenarios(&doc);
    let mut ids: Vec<&str> = all.iter().map(scenario_id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), all.len(), "scenario ids repeat");
    let mut steps = 0;
    for scenario in all {
        for step in scenario["steps"].as_array().expect("steps") {
            let op = step["op"].as_str().expect("every step names an op");
            assert!(
                KNOWN_OPS.contains(&op),
                "{}: unknown op `{op}`",
                scenario_id(scenario)
            );
            if op != "repeat" {
                assert!(
                    step.get("expect").is_some(),
                    "{}: `{op}` has no expectation",
                    scenario_id(scenario)
                );
            }
            steps += 1;
        }
    }
    let plant_names: Vec<&str> = doc["plants"]
        .as_array()
        .expect("plants")
        .iter()
        .filter_map(|p| p["name"].as_str())
        .collect();
    assert_eq!(plant_names, PLANTS);
    observe(&json!({
        "kind": "vectors",
        "scenarios": all.len(),
        "step_entries": steps,
        "schedule_runs": doc["schedule"]["runs"].as_array().map_or(0, Vec::len),
        "plants": plant_names.len(),
    }));
}
