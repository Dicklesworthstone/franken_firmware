//! The cases shared by the N03 target guest (`ffw-n03-target`, PID 1 on big-endian MIPS) and the host test
//! `crates/franken-clock/tests/n03_target_worlds.rs`, so that "the host build's records" and "the guest's records" come
//! from the same source text and differ only in the machine that ran it.
//!
//! No `unsafe` here: the host test includes this file under the workspace's `forbid(unsafe_code)`.
//!
//! Two kinds of case, both through the PUBLIC API of `franken_clock::group` only:
//!
//! * the scripted WORLDS of `tests/n03/vectors.json` (the 32 worlds plus the two members of the mixed-generation join):
//!   an interpreter of the op lists, one JSON record per op, in the shape `tests/n03/reference.py::run_script` produces,
//!   which is a port of `run_ops` in `crates/franken-clock/src/group/tests.rs` (without its asserts: the judge compares
//!   the records, so a platform difference is reported as a difference and not as a panic);
//! * the SEEDED simulated worlds: a coordinator clock, a member clock with an offset, a skew and a resolution, and seeded
//!   asymmetric delay with jitter and loss (`Sim` in `tests/n03/reference.py`, mirrored here), whose LCG seed is derived
//!   from a per-run seed the host chooses. A transcript from another run, or canned records, cannot carry the right ones.

use franken_clock::group::{
    ClockStatus, GroupClock, GroupClockConfig, GroupClockError, Output, ProbeResponse, StartPlan,
    StartReject, StartSchedule, group_at,
};
use serde_json::{Map, Value, json};

/// The committed vectors, the one source of the worlds and of the reference's expected records.
pub const VECTORS_JSON: &str = include_str!("../../../../tests/n03/vectors.json");

/// The seeded simulated worlds: `(skew ppb, base delay us, jitter us, extra forward delay us, loss percent, seconds)`.
/// They are the second and fourth of the five fixed worlds of the host test, so the reference has run them before.
pub const SIM_SHAPES: [(i64, u64, u64, u64, u64, u64); 2] = [
    (90_000, 100, 300, 0, 10, 300),
    (25_000, 200, 800, 400, 20, 600),
];

pub fn vectors() -> Value {
    serde_json::from_str(VECTORS_JSON).expect("vectors.json parses")
}

fn u(v: &Value, key: &str) -> u64 {
    v[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is not a u64 in {v}"))
}

fn opt_u64(v: &Value) -> Option<u64> {
    v.as_u64()
}

fn cfg_with(over: &Value) -> GroupClockConfig {
    let mut cfg = GroupClockConfig::standard().expect("standard config");
    if let Some(map) = over.as_object() {
        for (key, value) in map {
            let n = value
                .as_u64()
                .unwrap_or_else(|| panic!("override {key} is not a u64"));
            match key.as_str() {
                "max_delay_ns" => cfg.max_delay_ns = n,
                "request_ttl_ns" => cfg.request_ttl_ns = n,
                "lock_uncertainty_ns" => cfg.lock_uncertainty_ns = n,
                "fresh_ns" => cfg.fresh_ns = n,
                "calibration_uncertainty_ns" => cfg.calibration_uncertainty_ns = n,
                "output_delay_ns" => cfg.output_delay_ns = n,
                "catchup_ns" => cfg.catchup_ns = n,
                "max_future_ns" => cfg.max_future_ns = n,
                "timer_resolution_ns" => cfg.timer_resolution_ns = n,
                "oscillator_bound_ppb" => cfg.oscillator_bound_ppb = n,
                "prediction_slack_ns" => cfg.prediction_slack_ns = n,
                other => panic!("unknown config override {other}"),
            }
        }
    }
    cfg.validate().expect("overridden config is valid");
    cfg
}

fn resp_from(v: &Value) -> ProbeResponse {
    ProbeResponse {
        epoch: u(v, "epoch"),
        leader: u(v, "leader"),
        seq: u(v, "seq"),
        t1_echo_ns: u(v, "t1_echo"),
        t2_group_ns: u(v, "t2"),
        t3_group_ns: u(v, "t3"),
    }
}

fn apply_override(r: &mut ProbeResponse, ovr: &Value) {
    let Some(map) = ovr.as_object() else { return };
    for (key, value) in map {
        let n = value.as_u64().expect("override value");
        match key.as_str() {
            "epoch" => r.epoch = n,
            "leader" => r.leader = n,
            "seq" => r.seq = n,
            "t1_echo" => r.t1_echo_ns = n,
            "t2" => r.t2_group_ns = n,
            "t3" => r.t3_group_ns = n,
            other => panic!("unknown response override {other}"),
        }
    }
}

fn output_fields(rec: &mut Map<String, Value>, out: Output) {
    match out {
        Output::Muted(reason) => {
            rec.insert("output".into(), json!("Muted"));
            rec.insert("mute".into(), json!(reason.code()));
        }
        Output::Armed { starts_in_ns } => {
            rec.insert("output".into(), json!("Armed"));
            rec.insert("starts_in_ns".into(), json!(starts_in_ns));
        }
        Output::Audible => {
            rec.insert("output".into(), json!("Audible"));
        }
    }
}

fn plan_fields(rec: &mut Map<String, Value>, plan: Result<StartPlan, StartReject>) {
    match plan {
        Ok(p) => {
            rec.insert("result".into(), json!("ok"));
            rec.insert("start_local_ns".into(), json!(p.start_local_ns));
            rec.insert("deadline_local_ns".into(), json!(p.deadline_local_ns));
            rec.insert(
                "uncertainty_at_start_ns".into(),
                json!(p.uncertainty_at_start_ns),
            );
            rec.insert("valid_until_local_ns".into(), json!(p.valid_until_local_ns));
            rec.insert("binding".into(), json!(p.binding.code()));
        }
        Err(r) => {
            rec.insert("result".into(), json!(r.code()));
        }
    }
}

fn sched_of(v: &Value) -> StartSchedule {
    StartSchedule {
        epoch: u(v, "epoch"),
        start_group_ns: u(v, "start_group_ns"),
    }
}

/// Every scripted world to run: the 32 of the vectors, then the two members of the mixed-generation join.
pub fn all_worlds(vec: &Value) -> Vec<Value> {
    let mut worlds: Vec<Value> = vec["worlds"].as_array().expect("worlds").to_vec();
    for member in vec["mixed"]["members"].as_array().expect("members") {
        worlds.push(member["world"].clone());
    }
    worlds
}

/// Run one scripted world and return one record per op (the shape `reference.run_script` produces).
pub fn run_ops(w: &Value) -> Vec<Value> {
    let cfg = cfg_with(&w["cfg"]);
    let mut gc = GroupClock::new(cfg.clone(), u(w, "epoch"), u(w, "leader"), u(w, "seq_base"))
        .expect("member");
    let mut sent: Vec<Option<ProbeResponse>> = Vec::new();
    let mut out = Vec::new();
    for op in w["ops"].as_array().expect("ops") {
        let kind = op["op"].as_str().expect("op kind");
        let mut rec = Map::new();
        rec.insert("op".into(), json!(kind));
        let mut this_resp = None;
        match kind {
            "probe" | "raw" | "replay" => {
                let (resp, t4) = match kind {
                    "probe" => {
                        let req = gc.next_probe(u(op, "t1"));
                        rec.insert("seq".into(), json!(req.seq));
                        let mut r = ProbeResponse {
                            epoch: req.epoch,
                            leader: gc.leader(),
                            seq: req.seq,
                            t1_echo_ns: req.t1_local_ns,
                            t2_group_ns: u(op, "t2"),
                            t3_group_ns: u(op, "t3"),
                        };
                        apply_override(&mut r, &op["ovr"]);
                        (r, u(op, "t4"))
                    }
                    "raw" => (resp_from(&op["resp"]), u(op, "t4")),
                    _ => {
                        let of = usize::try_from(u(op, "of")).expect("index");
                        (
                            sent[of].expect("the replayed op built a response"),
                            u(op, "t4"),
                        )
                    }
                };
                this_resp = Some(resp);
                match gc.on_response(resp, t4) {
                    Ok(a) => {
                        rec.insert("result".into(), json!("ok"));
                        rec.insert("delay".into(), json!(a.delay_ns));
                        rec.insert("offset".into(), json!(a.offset_ns));
                    }
                    Err(reason) => {
                        rec.insert("result".into(), json!(reason.code()));
                    }
                }
                rec.insert("status".into(), json!(gc.status(t4).code()));
            }
            "next" => {
                rec.insert("seq".into(), json!(gc.next_probe(u(op, "t1")).seq));
            }
            "check" => {
                let now = u(op, "now");
                let report = gc.report(now);
                let stats = gc.stats();
                rec.insert("status".into(), json!(report.status));
                rec.insert("samples".into(), json!(report.samples));
                rec.insert("accepted".into(), json!(report.accepted));
                rec.insert("rejected_total".into(), json!(report.rejected_total));
                rec.insert("resets".into(), json!(stats.resets));
                rec.insert("rate_restarts".into(), json!(stats.rate_restarts));
                let o = gc.output(now);
                output_fields(&mut rec, o);
                if !rec.contains_key("mute") {
                    rec.insert("mute".into(), Value::Null);
                }
                if let Some(a) = gc.reading(now) {
                    rec.insert("uncertainty_ns".into(), json!(a.uncertainty_ns));
                    rec.insert("ratio_ppb".into(), json!(a.ratio_ppb));
                    rec.insert("ratio_unc_ppb".into(), json!(a.ratio_unc_ppb));
                    rec.insert("group_ns".into(), json!(group_at(&a, now)));
                    rec.insert("anchor_local_mid".into(), json!(a.sample.local_mid_ns));
                }
                if let Some(h) = gc.holdover(now) {
                    rec.insert("holdover_until".into(), json!(h.until_local_ns));
                    rec.insert("binding".into(), json!(h.binding.code()));
                }
                // The world carries the known truth: record the estimated error against it.
                if let Some(truth) = op.get("truth_group").and_then(Value::as_u64) {
                    let _ = gc.note_truth(now, truth);
                }
            }
            "tick" => {
                let o = gc.tick(u(op, "now"));
                output_fields(&mut rec, o);
            }
            "plan" => plan_fields(
                &mut rec,
                gc.plan_start(sched_of(&op["sched"]), u(op, "now")),
            ),
            "admit" => plan_fields(&mut rec, gc.admit(sched_of(&op["sched"]), u(op, "now"))),
            "begin_epoch" => {
                let r = gc.begin_epoch(u(op, "epoch"), u(op, "leader"));
                rec.insert(
                    "result".into(),
                    json!(match r {
                        Ok(()) => "ok",
                        Err(GroupClockError::EpochNotAdvanced { .. }) => "EpochNotAdvanced",
                        Err(_) => "UnexpectedError",
                    }),
                );
            }
            "authority" => {
                let r = gc.set_authority(u(op, "epoch"), u(op, "expires"), u(op, "now"));
                rec.insert(
                    "result".into(),
                    json!(match r {
                        Ok(()) => "ok",
                        Err(GroupClockError::WrongEpoch { .. }) => "WrongEpoch",
                        Err(_) => "UnexpectedError",
                    }),
                );
            }
            "buffer" => {
                gc.set_buffer_until(opt_u64(&op["until"]));
                rec.insert("result".into(), json!("ok"));
            }
            "fault" => {
                gc.report_clock_fault();
                rec.insert("result".into(), json!("ok"));
            }
            "reboot" => {
                gc = GroupClock::new(cfg.clone(), gc.epoch(), gc.leader(), u(op, "seq_base"))
                    .expect("member");
                rec.insert("result".into(), json!("ok"));
            }
            other => panic!("unknown op {other}"),
        }
        sent.push(this_resp);
        rec.insert("rate_in_force".into(), json!(gc.rate_in_force()));
        let mut labels = Vec::new();
        while let Some(event) = gc.pop_event() {
            labels.push(json!(event.payload.label()));
        }
        rec.insert("events".into(), Value::Array(labels));
        out.push(Value::Object(rec));
    }
    out
}

/// What a world's records say about the known truth, computed from the records alone (as the host test does):
/// `(checks, max error ns, max uncertainty ns, minimum margin ns)`.
pub fn truth_summary(w: &Value, steps: &[Value]) -> (u64, u64, u64, Option<u64>) {
    let (mut checks, mut max_err, mut max_unc) = (0_u64, 0_u64, 0_u64);
    let mut min_margin: Option<u64> = None;
    for (op, rec) in w["ops"].as_array().expect("ops").iter().zip(steps) {
        if let (Some(t), Some(g), Some(unc)) = (
            op.get("truth_group").and_then(Value::as_u64),
            rec.get("group_ns").and_then(Value::as_u64),
            rec.get("uncertainty_ns").and_then(Value::as_u64),
        ) {
            let err = t.abs_diff(g);
            checks += 1;
            max_err = max_err.max(err);
            max_unc = max_unc.max(unc);
            let margin = unc.saturating_sub(err);
            min_margin = Some(min_margin.map_or(margin, |m| m.min(margin)));
        }
    }
    (checks, max_err, max_unc, min_margin)
}

/// FNV-1a 64 over `text`, one `\n` after each of `lines`: a digest of a world's records, comparable across machines.
pub fn fnv1a64_lines(lines: &[String]) -> u64 {
    let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
    for line in lines {
        for byte in line.bytes().chain(std::iter::once(b'\n')) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
        }
    }
    hash
}

/// SplitMix64's output for `state` (the state is advanced once, then mixed).
pub fn splitmix64(state: u64) -> u64 {
    let mut z = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The LCG seed of seeded world `index` for a run seed: the high 32 bits of SplitMix64 over the seed and the index.
pub fn sim_seed(run_seed: u64, index: u64) -> u32 {
    u32::try_from(splitmix64(run_seed ^ (0x4E30_3353_0000_0000 | index)) >> 32).unwrap_or(0)
}

/// A simulated world: a coordinator clock, a member clock (offset, skew, resolution) and a seeded LCG.
struct Sim {
    skew_ppb: i64,
    local0: u64,
    group0: u64,
    res: u64,
    seed: u32,
}

impl Sim {
    fn rand(&mut self) -> u64 {
        self.seed = self
            .seed
            .wrapping_mul(1_664_525)
            .wrapping_add(1_013_904_223);
        u64::from(self.seed >> 8)
    }

    fn q(&self, v: u64) -> u64 {
        v - v % self.res
    }

    fn local(&self, t: u64) -> u64 {
        let skewed = i128::from(t) * i128::from(self.skew_ppb);
        let v = i128::from(self.local0) + i128::from(t) + skewed.div_euclid(1_000_000_000);
        self.q(u64::try_from(v).unwrap_or(0))
    }

    fn group(&self, t: u64) -> u64 {
        self.q(self.group0 + t)
    }
}

/// What one simulated world produced. Nothing here panics: a rejected exchange, a truth outside the uncertainty or a
/// reset is counted, so the judge can say which figure differs from the reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimRun {
    pub seed32: u32,
    pub probes: u64,
    pub lost: u64,
    pub rejected: u64,
    pub checks: u64,
    pub violations: u64,
    pub max_err: u64,
    pub max_unc: u64,
    pub min_margin: Option<u64>,
    pub locked: bool,
    pub resets: u32,
}

/// The world of `Sim` in `tests/n03/reference.py`, with the LCG seeded by `seed32`.
pub fn run_sim(
    seed32: u32,
    skew_ppb: i64,
    base_us: u64,
    jitter_us: u64,
    asym_us: u64,
    loss_pct: u64,
    seconds: u64,
) -> SimRun {
    let mut sim = Sim {
        skew_ppb,
        local0: 3_000_000_000,
        group0: 40_000_000_000_000,
        res: 1_000,
        seed: seed32,
    };
    let cfg = GroupClockConfig::standard().expect("standard config");
    let mut gc = GroupClock::new(cfg, 1, 7, u64::from(seed32) << 20).expect("member");
    let mut run = SimRun {
        seed32,
        probes: 0,
        lost: 0,
        rejected: 0,
        checks: 0,
        violations: 0,
        max_err: 0,
        max_unc: 0,
        min_margin: None,
        locked: false,
        resets: 0,
    };
    for k in 0..seconds {
        let ts = k * 1_000_000_000 + sim.rand() % 5_000_000;
        let req = gc.next_probe(sim.local(ts));
        run.probes += 1;
        if sim.rand() % 100 < loss_pct {
            run.lost += 1;
            continue;
        }
        let df = (base_us + sim.rand() % (jitter_us + 1) + asym_us) * 1_000;
        let dr = (base_us + sim.rand() % (jitter_us + 1)) * 1_000;
        let dwell = 40_000;
        let resp = ProbeResponse {
            epoch: req.epoch,
            leader: 7,
            seq: req.seq,
            t1_echo_ns: req.t1_local_ns,
            t2_group_ns: sim.group(ts + df),
            t3_group_ns: sim.group(ts + df + dwell),
        };
        let t_end = ts + df + dwell + dr;
        if gc.on_response(resp, sim.local(t_end)).is_err() {
            run.rejected += 1;
            continue;
        }
        let t_now = t_end + 1_500_000;
        let now = sim.local(t_now);
        if let Some(a) = gc.reading(now) {
            let err = group_at(&a, now).abs_diff(sim.group(t_now));
            if err > a.uncertainty_ns {
                run.violations += 1;
            }
            run.checks += 1;
            run.max_err = run.max_err.max(err);
            run.max_unc = run.max_unc.max(a.uncertainty_ns);
            let margin = a.uncertainty_ns.saturating_sub(err);
            run.min_margin = Some(run.min_margin.map_or(margin, |m| m.min(margin)));
        }
    }
    run.locked = gc.status(sim.local(seconds * 1_000_000_000)) != ClockStatus::Unlocked;
    run.resets = gc.stats().resets;
    run
}

/// The seeded world `index` (0 or 1) for `run_seed`.
pub fn seeded_run(run_seed: u64, index: usize) -> SimRun {
    let (skew, base, jitter, asym, loss, seconds) = SIM_SHAPES[index];
    run_sim(
        sim_seed(run_seed, index as u64),
        skew,
        base,
        jitter,
        asym,
        loss,
        seconds,
    )
}

/// The probes of a steady stream for timing: for `count` exchanges, `(t1 local, t2 group, t3 group, t4 local)` from a
/// loss-free simulated world, generated outside any timed region.
pub fn timing_stream(count: usize) -> Vec<(u64, u64, u64, u64)> {
    let mut sim = Sim {
        skew_ppb: 5_000,
        local0: 3_000_000_000,
        group0: 40_000_000_000_000,
        res: 1_000,
        seed: 7,
    };
    let mut out = Vec::with_capacity(count);
    for k in 0..count as u64 {
        let ts = k * 1_000_000_000 + sim.rand() % 5_000_000;
        let df = (150 + sim.rand() % 101) * 1_000;
        let dr = (150 + sim.rand() % 101) * 1_000;
        let dwell = 40_000;
        out.push((
            sim.local(ts),
            sim.group(ts + df),
            sim.group(ts + df + dwell),
            sim.local(ts + df + dwell + dr),
        ));
    }
    out
}

/// The member the timing regions run: the standard configuration, epoch 1, leader 7, a fixed sequence base.
pub fn timing_clock() -> GroupClock {
    let cfg = GroupClockConfig::standard().expect("standard config");
    GroupClock::new(cfg, 1, 7, 100).expect("member")
}
