use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::{SystematicEncoder, SystematicParams};
use franken_stream::playout::{
    Admission, BLOCK_FRAMES, BLOCK_PAYLOAD_BYTES, ClockView, MediaPacket, Outcome, PlayoutConfig,
    PlayoutEngine, PlayoutProfile, Poll, RepairBlock, consume_by, frames_to_ns,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;

pub const PROFILE: &str = "n05.rfc6330.k4-r4.v4";
pub const CODING_LIBRARY: &str = "asupersync@14032b8f2c832ee7ef1946404f5efb18162af045";
pub const SOURCE_SYMBOLS: usize = 4;
pub const REPAIR_SYMBOLS: usize = 4;
pub const MAX_SYMBOLS: usize = 8;
pub const BLOCKS: usize = 64;
pub const ORIGIN_NS: u64 = 500_000_000;
pub const WORK_NS: u64 = 1_000_000;
pub const LEAD_NS: u64 = 1_000_000;
pub const RENDER_RESERVED_NS: u64 = WORK_NS + LEAD_NS;
pub const UNCERTAINTY_NS: u64 = 500_000;
pub const MAX_WINDOW_WORK_NS: u64 = 20_000_000;
pub const CODING_RESERVE_NS: u64 = 1_000_000;
pub const REQUEST_COST_NS: u64 = 50_000;
pub const PLANTED_OVERRUN_NS: u64 = 600_000_000;
pub const HEADER_BYTES: u64 = 80;
pub const FEEDBACK_BYTES: u64 = 32;
pub const BUILD_RECIPE: &str = "n05.host-test-o3-d0.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    Concealment,
    Retransmit,
    Raptorq,
    Hybrid,
}
impl Strategy {
    pub const ALL: [Self; 4] = [
        Self::Concealment,
        Self::Retransmit,
        Self::Raptorq,
        Self::Hybrid,
    ];
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scenario {
    Clean,
    Independent,
    Burst,
    CodingWindowOutage,
    PositiveRecovery,
    LateRepair,
    PartialSalvage,
    WorkExhausted,
    Cancelled,
}
impl Scenario {
    pub const ALL: [Self; 9] = [
        Self::Clean,
        Self::Independent,
        Self::Burst,
        Self::CodingWindowOutage,
        Self::PositiveRecovery,
        Self::LateRepair,
        Self::PartialSalvage,
        Self::WorkExhausted,
        Self::Cancelled,
    ];
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StudyInput {
    pub scenario: Scenario,
    pub strategy: Strategy,
    pub seed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub stream: u64,
    pub epoch: u64,
    pub window: usize,
}
pub fn context(window: usize) -> Context {
    Context {
        stream: 1,
        epoch: 1,
        window,
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolMeta {
    pub stream: u64,
    pub epoch: u64,
    pub window: usize,
    pub esi: u32,
    pub source_symbols: usize,
    pub symbol_bytes: usize,
}
#[derive(Debug, Clone)]
pub struct CodingSymbol {
    pub meta: SymbolMeta,
    pub payload: Vec<u8>,
}
pub fn symbol(ctx: Context, esi: u32, payload: Vec<u8>) -> CodingSymbol {
    CodingSymbol {
        meta: SymbolMeta {
            stream: ctx.stream,
            epoch: ctx.epoch,
            window: ctx.window,
            esi,
            source_symbols: SOURCE_SYMBOLS,
            symbol_bytes: BLOCK_PAYLOAD_BYTES,
        },
        payload,
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolReject {
    Identity,
    Window,
    Shape,
    Esi,
    Duplicate,
    Count,
}
pub fn validate_symbol(
    meta: &SymbolMeta,
    ctx: Context,
    bytes: usize,
    seen: &[u32],
) -> Result<(), SymbolReject> {
    if meta.stream != ctx.stream || meta.epoch != ctx.epoch {
        return Err(SymbolReject::Identity);
    }
    if meta.window != ctx.window || meta.window >= BLOCKS / SOURCE_SYMBOLS {
        return Err(SymbolReject::Window);
    }
    if meta.source_symbols != SOURCE_SYMBOLS
        || meta.symbol_bytes != BLOCK_PAYLOAD_BYTES
        || bytes != BLOCK_PAYLOAD_BYTES
    {
        return Err(SymbolReject::Shape);
    }
    if meta.esi >= MAX_SYMBOLS as u32 {
        return Err(SymbolReject::Esi);
    }
    if seen.contains(&meta.esi) {
        return Err(SymbolReject::Duplicate);
    }
    if seen.len() >= MAX_SYMBOLS {
        return Err(SymbolReject::Count);
    }
    Ok(())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeReject {
    Metadata(SymbolReject),
    Library,
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct DecodeWork {
    pub gauss_ops: usize,
    pub dense_core_rows: usize,
    pub dense_core_cols: usize,
    pub peeled: usize,
    pub pivots: usize,
}
#[derive(Debug)]
pub struct DecodedWindow {
    pub source: Vec<Vec<u8>>,
    pub work: DecodeWork,
    pub assembled_row_payload_bytes: usize,
}

/// Metadata is carried with every actual received symbol and checked before decoder construction.
pub fn decode_window(
    ctx: Context,
    seed: u64,
    received: &[CodingSymbol],
) -> Result<DecodedWindow, DecodeReject> {
    if !(SOURCE_SYMBOLS..=MAX_SYMBOLS).contains(&received.len()) {
        return Err(DecodeReject::Metadata(SymbolReject::Count));
    }
    let mut seen = [0; MAX_SYMBOLS];
    for (index, item) in received.iter().enumerate() {
        validate_symbol(&item.meta, ctx, item.payload.len(), &seen[..index])
            .map_err(DecodeReject::Metadata)?;
        seen[index] = item.meta.esi;
    }
    let decoder = InactivationDecoder::try_new(SOURCE_SYMBOLS, BLOCK_PAYLOAD_BYTES, seed)
        .map_err(|_| DecodeReject::Library)?;
    let mut rows = decoder.constraint_symbols();
    for item in received {
        let esi = item.meta.esi;
        if esi < SOURCE_SYMBOLS as u32 {
            rows.push(ReceivedSymbol::source(esi, item.payload.clone()));
        } else {
            let (columns, coefficients) = decoder
                .repair_equation(esi)
                .map_err(|_| DecodeReject::Library)?;
            rows.push(ReceivedSymbol::repair(
                esi,
                columns,
                coefficients,
                item.payload.clone(),
            ));
        }
    }
    let bytes = rows.len() * BLOCK_PAYLOAD_BYTES;
    let decoded = decoder.decode(&rows).map_err(|_| DecodeReject::Library)?;
    Ok(DecodedWindow {
        source: decoded.source,
        assembled_row_payload_bytes: bytes,
        work: DecodeWork {
            gauss_ops: decoded.stats.gauss_ops,
            dense_core_rows: decoded.stats.dense_core_rows,
            dense_core_cols: decoded.stats.dense_core_cols,
            peeled: decoded.stats.peeled,
            pivots: decoded.stats.pivots_selected,
        },
    })
}
pub fn encode_repairs(
    ctx: Context,
    source: &[CodingSymbol],
    seed: u64,
) -> Result<Vec<CodingSymbol>, &'static str> {
    if source.len() != SOURCE_SYMBOLS {
        return Err("source count");
    }
    for (esi, item) in source.iter().enumerate() {
        validate_symbol(&item.meta, ctx, item.payload.len(), &[]).map_err(|_| "source metadata")?;
        if item.meta.esi != esi as u32 {
            return Err("source ESI order");
        }
    }
    let payload: Vec<_> = source.iter().map(|item| item.payload.clone()).collect();
    let encoder =
        SystematicEncoder::new(&payload, BLOCK_PAYLOAD_BYTES, seed).ok_or("encoder singular")?;
    (SOURCE_SYMBOLS..MAX_SYMBOLS)
        .map(|esi| {
            encoder
                .try_repair_symbol(esi as u32)
                .map(|bytes| symbol(ctx, esi as u32, bytes))
                .map_err(|_| "repair generation")
        })
        .collect()
}
pub fn coding_shape() -> Result<(usize, usize, usize), &'static str> {
    let p = SystematicParams::try_for_source_block(SOURCE_SYMBOLS, BLOCK_PAYLOAD_BYTES)
        .map_err(|_| "shape")?;
    Ok((p.k_prime, p.s + p.h, p.l))
}

#[derive(Debug, Clone, Serialize)]
pub struct OutputBlock {
    pub block: usize,
    pub consume_by_ns: u64,
    pub presentation_ns: u64,
    pub outcome: &'static str,
    pub payload_sha256: String,
    pub late_by_ns: u64,
    pub render_reserved_end_ns: u64,
    pub render_served_end_ns: u64,
    pub render_late_by_ns: u64,
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct TailAccounting {
    pub requested: u64,
    pub admitted: u64,
    pub received: u64,
    pub admitted_to_playout: u64,
    pub late: u64,
    pub duplicate: u64,
    pub refused_work: u64,
    pub refused_deadline: u64,
    pub refused_cancelled: u64,
    pub feedback_messages: u64,
    pub max_outstanding: usize,
    pub air_bytes: u64,
    pub feedback_air_bytes: u64,
    pub work_charged_ns: u64,
    pub recovered_blocks: Vec<usize>,
    pub decision_barriers: Vec<(usize, u64)>,
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct RepairAccounting {
    pub attempts: u64,
    pub admitted: u64,
    pub late: u64,
    pub duplicate: u64,
    pub no_information_windows: u64,
    pub insufficient_information_windows: u64,
    pub decode_failures: u64,
    pub deadline_refusals: u64,
    pub work_refusals: u64,
    pub cancelled_windows: u64,
    pub no_information_window_ids: Vec<usize>,
    pub insufficient_window_ids: Vec<usize>,
    pub decode_window_ids: Vec<usize>,
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct Resources {
    pub source_payload_bytes: u64,
    pub source_air_bytes: u64,
    pub repair_air_bytes: u64,
    pub feedback_air_bytes: u64,
    pub real_output_payload_bytes: u64,
    pub sender_encode_host_elapsed_ns: u64,
    pub receiver_decode_host_elapsed_ns: u64,
    pub library_attempts: u64,
    pub work_charged_ns: u64,
    pub max_window_work_ns: u64,
    pub work_allowance_per_window_ns: u64,
    pub work_overruns: u64,
    pub playout_resident_bytes: usize,
    pub retained_symbol_payload_peak_bytes: usize,
    pub decode_process_peak_rss_bytes: Option<u64>,
    pub encoded_airtime_at_6mbps_ns: u64,
    pub max_repair_latency_ns: u64,
    pub max_decision_late_by_ns: u64,
    pub max_render_late_by_ns: u64,
    pub concealed_blocks: u64,
    pub muted_blocks: u64,
    pub longest_nonreal_run_blocks: u64,
    pub source_duplicates_seen: u64,
    pub source_duplicates_admitted_as_duplicate: u64,
    pub decode_work: DecodeWork,
    pub original_collection_barriers: Vec<(usize, u64)>,
    pub fec_collection_barriers: Vec<(usize, u64)>,
}
#[derive(Debug, Clone, Serialize)]
pub struct BuildProfile {
    pub recipe: &'static str,
    pub opt_level: &'static str,
    pub debug: &'static str,
    pub cargo_profile: &'static str,
}
#[derive(Debug, Clone, Serialize)]
pub struct StudyResult {
    pub schema: &'static str,
    pub profile: &'static str,
    pub library: &'static str,
    pub evidence_class: &'static str,
    pub build_profile: BuildProfile,
    pub input: StudyInput,
    pub source_trace_sha256: String,
    pub payload_sha256: String,
    pub blocks: usize,
    pub frames_per_packet: u64,
    pub source_symbols: usize,
    pub repair_symbols: usize,
    pub source_epoch: u64,
    pub repair: RepairAccounting,
    pub tail: TailAccounting,
    pub resources: Resources,
    pub output: Vec<OutputBlock>,
    pub unrecovered_blocks: Vec<usize>,
    pub diagnostics_dropped: u64,
    pub promotion: &'static str,
}
fn elapsed(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn hash(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn mix(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
    value ^ (value >> 31)
}
pub fn source_payload(block: usize) -> Vec<u8> {
    (0..BLOCK_PAYLOAD_BYTES / 2)
        .flat_map(|sample| ((((block * 997 + sample * 31) % 24001) as i16) - 12000).to_be_bytes())
        .collect()
}
pub fn source_time(block: usize) -> u64 {
    frames_to_ns(block as u64 * BLOCK_FRAMES)
}
pub fn presentation(block: usize) -> u64 {
    ORIGIN_NS + source_time(block)
}
pub fn cutoff(block: usize) -> u64 {
    consume_by(presentation(block), WORK_NS, LEAD_NS, UNCERTAINTY_NS)
}
fn view(now: u64) -> ClockView {
    ClockView {
        group_ns: now,
        uncertainty_ns: UNCERTAINTY_NS,
        usable: true,
    }
}
fn arrival(input: StudyInput, window: usize, slot: usize, repair: bool, sent: u64) -> Option<u64> {
    let damaged = matches!(
        input.scenario,
        Scenario::PositiveRecovery
            | Scenario::LateRepair
            | Scenario::PartialSalvage
            | Scenario::WorkExhausted
            | Scenario::Cancelled
    );
    let later_damage = matches!(
        input.scenario,
        Scenario::WorkExhausted | Scenario::Cancelled
    );
    if damaged && !repair && (window == 1 || (later_damage && window == 3)) && slot < 2 {
        return None;
    }
    if input.scenario == Scenario::CodingWindowOutage && window == 1 {
        return None;
    }
    if input.scenario == Scenario::Burst && (100_000_000..200_000_000).contains(&sent) {
        return None;
    }
    let draw =
        mix(input.seed
            ^ (window * MAX_SYMBOLS + slot + if repair { SOURCE_SYMBOLS } else { 0 }) as u64);
    if input.scenario == Scenario::Independent && draw % 10000 < 100 {
        return None;
    }
    let jitter = if matches!(input.scenario, Scenario::Independent | Scenario::Burst) {
        (draw >> 16) % 50_000_001
    } else {
        0
    };
    Some(sent + 2_000_000 + jitter)
}
fn jitter_bound(input: StudyInput) -> u64 {
    if matches!(input.scenario, Scenario::Independent | Scenario::Burst) {
        50_000_000
    } else {
        0
    }
}
fn original_barrier(input: StudyInput, window: usize) -> u64 {
    source_time(window * 4 + 4).max(source_time(window * 4 + 3) + 2_000_000 + jitter_bound(input))
}
fn fec_barrier(input: StudyInput, window: usize, encoded_at: u64) -> u64 {
    let declared = encoded_at + 300_000 + 2_000_000 + jitter_bound(input);
    if window == 1
        && matches!(
            input.scenario,
            Scenario::LateRepair | Scenario::PartialSalvage
        )
    {
        let target = if input.scenario == Scenario::LateRepair {
            window * 4 + 1
        } else {
            window * 4
        };
        declared.max(cutoff(target) + 1 - CODING_RESERVE_NS)
    } else {
        declared
    }
}
fn observed_by(at: u64, events: &[(u64, CodingSymbol)]) -> Vec<CodingSymbol> {
    events
        .iter()
        .filter(|(arrival, _)| *arrival <= at)
        .map(|(_, symbol)| symbol.clone())
        .collect()
}
fn missing_originals(window: usize, observed: &[CodingSymbol]) -> Vec<usize> {
    (0..SOURCE_SYMBOLS)
        .filter(|slot| !observed.iter().any(|item| item.meta.esi == *slot as u32))
        .map(|slot| window * SOURCE_SYMBOLS + slot)
        .collect()
}
#[derive(Clone, Copy)]
struct Span {
    start: u64,
    end: u64,
}
enum Task {
    Arrival {
        block: usize,
        payload: Vec<u8>,
        repair: bool,
        duplicate: bool,
        tail: bool,
    },
    Decide(usize),
}
struct Timed {
    at: u64,
    order: u8,
    task: Task,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum GateReject {
    Work,
    Deadline,
    Cancelled,
}
#[derive(Clone, Copy)]
struct WindowGate {
    used: u64,
    cancelled: bool,
}
impl WindowGate {
    fn reserve(
        &mut self,
        start: u64,
        cost: u64,
        missing: &[usize],
        enforce: bool,
    ) -> Result<u64, GateReject> {
        if self.cancelled {
            return Err(GateReject::Cancelled);
        }
        let finish = start.saturating_add(cost);
        if enforce && self.used.saturating_add(cost) > MAX_WINDOW_WORK_NS {
            return Err(GateReject::Work);
        }
        // Already-expired blocks cannot veto still-live blocks. Equality remains late.
        if enforce && !missing.iter().any(|&block| finish < cutoff(block)) {
            return Err(GateReject::Deadline);
        }
        self.used = self.used.saturating_add(cost);
        Ok(finish)
    }
}
fn rejection(error: GateReject, repair: &mut RepairAccounting) {
    match error {
        GateReject::Work => repair.work_refusals += 1,
        GateReject::Deadline => repair.deadline_refusals += 1,
        GateReject::Cancelled => repair.cancelled_windows += 1,
    }
}
fn peak_rss() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:")?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()?
                .checked_mul(1024)
        })
}
fn service_at(at: u64, spans: &[Span], last: u64) -> u64 {
    let mut now = at.max(last);
    for span in spans {
        if span.start <= now && now < span.end {
            now = span.end;
        }
    }
    now
}
fn render_served_end(start: u64, spans: &[Span]) -> u64 {
    // A conservative single-thread protected phase, including the admitted work and lead.
    let mut begin = start;
    for span in spans {
        if begin.saturating_add(RENDER_RESERVED_NS) <= span.start {
            break;
        }
        if span.end > begin {
            begin = span.end;
        }
    }
    begin.saturating_add(RENDER_RESERVED_NS)
}
fn worker_start(ready: u64, cost: u64, spans: &[Span], protect_cutoffs: bool) -> u64 {
    worker_start_with(ready, cost, spans, &[], protect_cutoffs)
}
fn worker_start_with(
    ready: u64,
    cost: u64,
    spans: &[Span],
    added: &[Span],
    protect_cutoffs: bool,
) -> u64 {
    let mut start = ready;
    loop {
        if let Some(end) = spans
            .iter()
            .chain(added)
            .filter(|span| start < span.end && span.start < start.saturating_add(cost))
            .map(|span| span.end)
            .max()
        {
            start = end;
            continue;
        }
        if protect_cutoffs
            && let Some(deadline) = (0..BLOCKS).map(cutoff).find(|&deadline| {
                start < deadline.saturating_add(RENDER_RESERVED_NS)
                    && deadline < start.saturating_add(cost)
            })
        {
            // Protect the same thread through all admitted downstream work/lead, not
            // just the decision instant. The half-open end is a permitted job start.
            start = deadline + RENDER_RESERVED_NS;
            continue;
        }
        return start;
    }
}

#[derive(Clone, Copy)]
struct TailJob {
    block: usize,
    offset: usize,
    start: u64,
    finish: u64,
    sent: u64,
}
struct TailPlan {
    jobs: [Option<TailJob>; SOURCE_SYMBOLS],
    used: u64,
    accounting: TailAccounting,
}

#[derive(Clone, Copy)]
struct RequestWindow<'a> {
    window: usize,
    ready: u64,
    recovered: &'a [usize],
    cost_ns: u64,
    return_delay_ns: u64,
    not_before_ns: u64,
    enforce: bool,
}

fn request_not_before(input: StudyInput, window: usize) -> u64 {
    if window == 1 {
        match input.scenario {
            Scenario::LateRepair => cutoff(window * SOURCE_SYMBOLS + 1) + 1,
            Scenario::PartialSalvage => cutoff(window * SOURCE_SYMBOLS) + 1,
            _ => 0,
        }
    } else {
        0
    }
}
fn request_window(
    input: StudyInput,
    window: usize,
    ready: u64,
    recovered: &[usize],
    enforce: bool,
) -> RequestWindow<'_> {
    RequestWindow {
        window,
        ready,
        recovered,
        cost_ns: if input.scenario == Scenario::WorkExhausted && window == 1 {
            PLANTED_OVERRUN_NS
        } else {
            REQUEST_COST_NS
        },
        return_delay_ns: 2_000_000 + jitter_bound(input),
        not_before_ns: request_not_before(input, window),
        enforce,
    }
}

// This is the sole event-collection/request-planning seam used by both strategies.
// The injected collector is checked against the actual observable prefix before
// any reservation; a test plants a collector which erroneously reads the suffix.
// Planning has declared bounds and observed symbols, never Scenario or arrival().
type SymbolCollector = fn(u64, &[(u64, CodingSymbol)]) -> Vec<CodingSymbol>;

fn collect_and_plan_window(
    request: RequestWindow<'_>,
    events: &[(u64, CodingSymbol)],
    gate: WindowGate,
    spans: &[Span],
    collect: SymbolCollector,
) -> Result<TailPlan, &'static str> {
    let observed = collect(request.ready, events);
    let prefix: Vec<_> = events
        .iter()
        .filter(|(at, _)| *at <= request.ready)
        .collect();
    if observed.len() != prefix.len()
        || prefix.iter().any(|(_, item)| {
            !observed
                .iter()
                .any(|candidate| candidate.meta == item.meta && candidate.payload == item.payload)
        })
        || observed.iter().any(|item| {
            !prefix.iter().any(|(_, candidate)| {
                candidate.meta == item.meta && candidate.payload == item.payload
            })
        })
    {
        return Err("request collector violated the observable prefix");
    }
    let missing: Vec<_> = missing_originals(request.window, &observed)
        .into_iter()
        .filter(|block| !request.recovered.contains(block))
        .collect();
    let mut result = TailPlan {
        jobs: [None; SOURCE_SYMBOLS],
        used: gate.used,
        accounting: TailAccounting::default(),
    };
    let mut candidate_gate = gate;
    let mut added = [Span { start: 0, end: 0 }; SOURCE_SYMBOLS];
    let mut admitted = 0;
    let mut worker_free = request.ready;
    for (offset, &block) in missing.iter().enumerate() {
        result.accounting.requested += 1;
        let cost = request.cost_ns;
        let start = worker_start_with(
            worker_free,
            cost,
            spans,
            &added[..admitted],
            request.enforce,
        );
        let mut tentative = candidate_gate;
        let finish = match tentative.reserve(start, cost, &[block], request.enforce) {
            Ok(finish) => finish,
            Err(GateReject::Work) => {
                result.accounting.refused_work += 1;
                continue;
            }
            Err(GateReject::Deadline) => {
                result.accounting.refused_deadline += 1;
                continue;
            }
            Err(GateReject::Cancelled) => {
                result.accounting.refused_cancelled += 1;
                continue;
            }
        };
        let sent = (request.ready + 20_000_000 + offset as u64 * 100_000).max(finish);
        let latest_return = sent
            .saturating_add(request.return_delay_ns)
            .max(request.not_before_ns);
        if request.enforce && latest_return >= cutoff(block) {
            result.accounting.refused_deadline += 1;
            continue; // No ledger, queue, feedback or wire mutation for a refused tail.
        }
        candidate_gate = tentative;
        worker_free = finish;
        added[admitted] = Span { start, end: finish };
        result.jobs[admitted] = Some(TailJob {
            block,
            offset,
            start,
            finish,
            sent,
        });
        admitted += 1;
        result.accounting.admitted += 1;
        result.accounting.air_bytes += BLOCK_PAYLOAD_BYTES as u64 + HEADER_BYTES;
    }
    result.used = candidate_gate.used;
    result.accounting.work_charged_ns = candidate_gate.used - gate.used;
    result.accounting.max_outstanding = admitted;
    if admitted > 0 {
        result.accounting.feedback_messages = 1;
        result.accounting.feedback_air_bytes = FEEDBACK_BYTES;
    }
    Ok(result)
}

pub fn run(input: StudyInput) -> Result<StudyResult, String> {
    run_model(input, true, 0, false)
}
/// Explicit causal controls: disabling the gate models inline monolithic overrun; an observed
/// cost floor tests that host measurement can fail its reserve without changing virtual time.
pub fn run_control(
    input: StudyInput,
    enforce_gate: bool,
    observed_cost_floor: u64,
) -> Result<StudyResult, String> {
    run_model(input, enforce_gate, observed_cost_floor, false)
}
/// Explicit channel-duplication fault, with normal work/slack admission retained.
pub fn run_tail_duplicate_control(input: StudyInput) -> Result<StudyResult, String> {
    run_model(input, true, 0, true)
}
fn run_model(
    input: StudyInput,
    enforce_gate: bool,
    observed_cost_floor: u64,
    duplicate_tail: bool,
) -> Result<StudyResult, String> {
    let mut resources = Resources {
        source_payload_bytes: (BLOCKS * BLOCK_PAYLOAD_BYTES) as u64,
        source_air_bytes: BLOCKS as u64 * (BLOCK_PAYLOAD_BYTES as u64 + HEADER_BYTES),
        work_allowance_per_window_ns: MAX_WINDOW_WORK_NS,
        ..Resources::default()
    };
    let mut repair = RepairAccounting::default();
    let mut tail = TailAccounting::default();
    let mut tasks = Vec::with_capacity(BLOCKS * 4);
    let mut spans = Vec::with_capacity(32);
    let mut trace = Sha256::new();
    let mut content = Sha256::new();
    for window in 0..BLOCKS / SOURCE_SYMBOLS {
        let ctx = context(window);
        let first = window * SOURCE_SYMBOLS;
        let source: Vec<_> = (0..SOURCE_SYMBOLS)
            .map(|slot| symbol(ctx, slot as u32, source_payload(first + slot)))
            .collect();
        let mut observed_events = Vec::with_capacity(MAX_SYMBOLS);
        for (slot, item) in source.iter().enumerate() {
            let block = first + slot;
            content.update(&item.payload);
            let at = arrival(input, window, slot, false, source_time(block));
            let duplicate = at
                .filter(|_| {
                    matches!(input.scenario, Scenario::Independent | Scenario::Burst)
                        && mix(input.seed ^ block as u64 ^ 0xdecaf).is_multiple_of(16)
                })
                .map(|at| at + 10_000);
            for value in [
                block as u64,
                source_time(block),
                at.unwrap_or(u64::MAX),
                cutoff(block),
                duplicate.unwrap_or(u64::MAX),
            ] {
                trace.update(value.to_be_bytes());
            }
            if let Some(at) = at {
                observed_events.push((at, item.clone()));
                tasks.push(Timed {
                    at,
                    order: 1,
                    task: Task::Arrival {
                        block,
                        payload: item.payload.clone(),
                        repair: false,
                        duplicate: false,
                        tail: false,
                    },
                });
                if let Some(at) = duplicate {
                    resources.source_duplicates_seen += 1;
                    tasks.push(Timed {
                        at,
                        order: 1,
                        task: Task::Arrival {
                            block,
                            payload: item.payload.clone(),
                            repair: false,
                            duplicate: true,
                            tail: false,
                        },
                    });
                }
            }
        }
        let original_collection = original_barrier(input, window);
        resources
            .original_collection_barriers
            .push((window, original_collection));
        let mut received = observed_by(original_collection, &observed_events);
        let mut missing = missing_originals(window, &received);
        if input.strategy == Strategy::Concealment {
            continue;
        }
        let mut gate = WindowGate {
            used: 0,
            cancelled: input.scenario == Scenario::Cancelled && window == 1,
        };
        let window_end = source_time(first + 4);
        let mut hybrid_ready = original_collection;
        let mut recovered = Vec::new();
        let planted = input.scenario == Scenario::WorkExhausted && window == 1;
        if input.strategy == Strategy::Retransmit {
            let plan = collect_and_plan_window(
                request_window(input, window, original_collection, &[], enforce_gate),
                &observed_events,
                gate,
                &spans,
                observed_by,
            )
            .map_err(str::to_owned)?;
            gate.used = plan.used;
            resources.repair_air_bytes += plan.accounting.air_bytes;
            resources.feedback_air_bytes += plan.accounting.feedback_air_bytes;
            repair.work_refusals += plan.accounting.refused_work;
            repair.deadline_refusals += plan.accounting.refused_deadline;
            repair.cancelled_windows += u64::from(plan.accounting.refused_cancelled > 0);
            for job in plan.jobs.into_iter().flatten() {
                spans.push(Span {
                    start: job.start,
                    end: job.finish,
                });
                // The channel is invoked AFTER planning/admission and cannot choose a request.
                if let Some(at) = arrival(input, window, job.offset, true, job.sent) {
                    let at = at.max(request_not_before(input, window));
                    resources.max_repair_latency_ns = resources
                        .max_repair_latency_ns
                        .max(at - source_time(job.block));
                    tasks.push(Timed {
                        at,
                        order: 1,
                        task: Task::Arrival {
                            block: job.block,
                            payload: source[job.block - first].payload.clone(),
                            repair: true,
                            duplicate: false,
                            tail: false,
                        },
                    });
                }
            }
        } else {
            let start = worker_start(window_end, CODING_RESERVE_NS, &spans, enforce_gate);
            let all_blocks: Vec<_> = (first..first + 4).collect();
            match gate.reserve(start, CODING_RESERVE_NS, &all_blocks, enforce_gate) {
                Err(error) => rejection(error, &mut repair),
                Ok(finish) => {
                    spans.push(Span { start, end: finish });
                    let collection = fec_barrier(input, window, finish);
                    hybrid_ready = collection;
                    resources.fec_collection_barriers.push((window, collection));
                    let clock = Instant::now();
                    let symbols =
                        encode_repairs(ctx, &source, input.seed).map_err(str::to_owned)?;
                    let cost = elapsed(clock).max(observed_cost_floor);
                    resources.sender_encode_host_elapsed_ns += cost;
                    if cost > CODING_RESERVE_NS {
                        resources.work_overruns += 1;
                    }
                    for (offset, item) in symbols.into_iter().enumerate() {
                        let sent = finish + offset as u64 * 100_000;
                        resources.repair_air_bytes += BLOCK_PAYLOAD_BYTES as u64 + HEADER_BYTES + 4;
                        if let Some(mut at) = arrival(input, window, offset, true, sent) {
                            if matches!(
                                input.scenario,
                                Scenario::LateRepair | Scenario::PartialSalvage
                            ) && window == 1
                            {
                                let block = if input.scenario == Scenario::LateRepair {
                                    *missing.last().ok_or("missing block")?
                                } else {
                                    missing[0]
                                };
                                at = cutoff(block) + 1 - CODING_RESERVE_NS;
                            }
                            observed_events.push((at, item));
                        }
                    }
                    received = observed_by(collection, &observed_events);
                    missing = missing_originals(window, &received);
                    if !missing.is_empty() {
                        if received.is_empty() {
                            repair.no_information_windows += 1;
                            repair.no_information_window_ids.push(window);
                        } else if received.len() < SOURCE_SYMBOLS {
                            repair.insufficient_information_windows += 1;
                            repair.insufficient_window_ids.push(window);
                        } else {
                            let cost = if planted {
                                PLANTED_OVERRUN_NS
                            } else {
                                CODING_RESERVE_NS
                            };
                            let decode_start = worker_start(collection, cost, &spans, enforce_gate);
                            match gate.reserve(decode_start, cost, &missing, enforce_gate) {
                                Err(error) => rejection(error, &mut repair),
                                Ok(finish) => {
                                    hybrid_ready = finish;
                                    spans.push(Span {
                                        start: decode_start,
                                        end: finish,
                                    });
                                    let clock = Instant::now();
                                    let result = decode_window(ctx, input.seed, &received);
                                    let host = elapsed(clock).max(observed_cost_floor);
                                    resources.receiver_decode_host_elapsed_ns += host;
                                    if host > CODING_RESERVE_NS {
                                        resources.work_overruns += 1;
                                    }
                                    resources.library_attempts += 1;
                                    repair.decode_window_ids.push(window);
                                    if let Ok(decoded) = result {
                                        if decoded.source
                                            != source
                                                .iter()
                                                .map(|item| item.payload.clone())
                                                .collect::<Vec<_>>()
                                        {
                                            return Err("decoded payload mismatch".into());
                                        }
                                        resources.retained_symbol_payload_peak_bytes = resources
                                            .retained_symbol_payload_peak_bytes
                                            .max(decoded.assembled_row_payload_bytes);
                                        resources.decode_work.gauss_ops += decoded.work.gauss_ops;
                                        resources.decode_work.dense_core_rows = resources
                                            .decode_work
                                            .dense_core_rows
                                            .max(decoded.work.dense_core_rows);
                                        resources.decode_work.dense_core_cols = resources
                                            .decode_work
                                            .dense_core_cols
                                            .max(decoded.work.dense_core_cols);
                                        resources.decode_work.peeled += decoded.work.peeled;
                                        resources.decode_work.pivots += decoded.work.pivots;
                                        for &block in &missing {
                                            if finish < cutoff(block) {
                                                recovered.push(block);
                                            }
                                            resources.max_repair_latency_ns = resources
                                                .max_repair_latency_ns
                                                .max(finish - source_time(block));
                                            tasks.push(Timed {
                                                at: finish,
                                                order: 1,
                                                task: Task::Arrival {
                                                    block,
                                                    payload: decoded.source[block - first].clone(),
                                                    repair: true,
                                                    duplicate: false,
                                                    tail: false,
                                                },
                                            });
                                        }
                                    } else {
                                        repair.decode_failures += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if input.strategy == Strategy::Hybrid {
            let plan = collect_and_plan_window(
                request_window(input, window, hybrid_ready, &recovered, enforce_gate),
                &observed_events,
                gate,
                &spans,
                observed_by,
            )
            .map_err(str::to_owned)?;
            if plan.accounting.requested > 0 {
                tail.decision_barriers.push((window, hybrid_ready));
            }
            gate.used = plan.used;
            resources.repair_air_bytes += plan.accounting.air_bytes;
            resources.feedback_air_bytes += plan.accounting.feedback_air_bytes;
            tail.requested += plan.accounting.requested;
            tail.admitted += plan.accounting.admitted;
            tail.refused_work += plan.accounting.refused_work;
            tail.refused_deadline += plan.accounting.refused_deadline;
            tail.refused_cancelled += plan.accounting.refused_cancelled;
            tail.feedback_messages += plan.accounting.feedback_messages;
            tail.max_outstanding = tail.max_outstanding.max(plan.accounting.max_outstanding);
            tail.air_bytes += plan.accounting.air_bytes;
            tail.feedback_air_bytes += plan.accounting.feedback_air_bytes;
            tail.work_charged_ns += plan.accounting.work_charged_ns;
            for job in plan.jobs.into_iter().flatten() {
                spans.push(Span {
                    start: job.start,
                    end: job.finish,
                });
                if let Some(at) = arrival(input, window, job.offset, true, job.sent) {
                    let at = at.max(request_not_before(input, window));
                    resources.max_repair_latency_ns = resources
                        .max_repair_latency_ns
                        .max(at - source_time(job.block));
                    tasks.push(Timed {
                        at,
                        order: 1,
                        task: Task::Arrival {
                            block: job.block,
                            payload: source[job.block - first].payload.clone(),
                            repair: true,
                            duplicate: false,
                            tail: true,
                        },
                    });
                    if duplicate_tail {
                        // Duplicate the actual delivered channel packet, preserving production gates.
                        tasks.push(Timed {
                            at: at + 1,
                            order: 1,
                            task: Task::Arrival {
                                block: job.block,
                                payload: source[job.block - first].payload.clone(),
                                repair: true,
                                duplicate: false,
                                tail: true,
                            },
                        });
                    }
                }
            }
        }
        resources.work_charged_ns += gate.used;
        resources.max_window_work_ns = resources.max_window_work_ns.max(gate.used);
    }
    for block in 0..BLOCKS {
        tasks.push(Timed {
            at: cutoff(block),
            order: 0,
            task: Task::Decide(block),
        });
    }
    tasks.sort_by_key(|task| (task.at, task.order));
    spans.sort_by_key(|span| span.start);
    let mut engine = PlayoutEngine::new(
        PlayoutProfile::MUSIC,
        PlayoutConfig {
            work_ns: WORK_NS,
            lead_ns: LEAD_NS,
            tolerance_ns: 0,
        },
    )
    .map_err(|_| "N04 config")?;
    resources.playout_resident_bytes = PlayoutEngine::resident_bytes(&PlayoutProfile::MUSIC);
    engine
        .begin_stream(1, 0, ORIGIN_NS)
        .map_err(|_| "N04 start")?;
    let mut output = Vec::with_capacity(BLOCKS);
    let mut unrecovered = Vec::new();
    let mut run = 0;
    let mut last_service = 0;
    for timed in tasks {
        let now = service_at(timed.at, &spans, last_service);
        last_service = now;
        match timed.task {
            Task::Arrival {
                block,
                payload,
                repair: is_repair,
                duplicate,
                tail: is_tail,
            } => {
                let admission = if is_repair {
                    repair.attempts += 1;
                    engine.on_repair(
                        view(now),
                        &RepairBlock {
                            epoch: 1,
                            start_frame: block as u64 * BLOCK_FRAMES,
                            frames: 256,
                            payload: &payload,
                        },
                    )
                } else {
                    engine.on_packet(
                        view(now),
                        &MediaPacket {
                            epoch: 1,
                            start_frame: block as u64 * BLOCK_FRAMES,
                            presentation_ns: presentation(block),
                            frames: 256,
                            payload: &payload,
                        },
                    )
                };
                if is_repair {
                    if is_tail {
                        tail.received += 1;
                        match admission {
                            Admission::Admitted => {
                                tail.admitted_to_playout += 1;
                                tail.recovered_blocks.push(block);
                            }
                            Admission::Late => tail.late += 1,
                            Admission::Duplicate => tail.duplicate += 1,
                            _ => return Err("unexpected tail admission".into()),
                        }
                    }
                    match admission {
                        Admission::Admitted => repair.admitted += 1,
                        Admission::Late => repair.late += 1,
                        Admission::Duplicate => repair.duplicate += 1,
                        _ => return Err("unexpected repair admission".into()),
                    }
                } else if duplicate && admission == Admission::Duplicate {
                    resources.source_duplicates_admitted_as_duplicate += 1;
                } else if !matches!(
                    admission,
                    Admission::Admitted | Admission::Duplicate | Admission::Late
                ) {
                    return Err("unexpected source admission".into());
                }
            }
            Task::Decide(block) => {
                let mut bytes = [0; BLOCK_PAYLOAD_BYTES];
                let Poll::Decision(decision) = engine.decide(view(now), &mut bytes) else {
                    return Err("N04 decision missing".into());
                };
                if decision.block != block as u64 {
                    return Err("N04 cursor".into());
                }
                if decision.outcome == Outcome::Real {
                    if bytes.as_slice() != source_payload(block) {
                        return Err("N04 output bytes".into());
                    }
                    resources.real_output_payload_bytes += BLOCK_PAYLOAD_BYTES as u64;
                    run = 0;
                } else {
                    unrecovered.push(block);
                    run += 1;
                    match decision.outcome {
                        Outcome::Concealed { .. } => resources.concealed_blocks += 1,
                        _ => resources.muted_blocks += 1,
                    }
                }
                resources.longest_nonreal_run_blocks =
                    resources.longest_nonreal_run_blocks.max(run);
                resources.max_decision_late_by_ns =
                    resources.max_decision_late_by_ns.max(decision.late_by_ns);
                let reserved_end = cutoff(block) + RENDER_RESERVED_NS;
                let served_end = render_served_end(now, &spans);
                let render_late = served_end.saturating_sub(reserved_end);
                resources.max_render_late_by_ns = resources.max_render_late_by_ns.max(render_late);
                output.push(OutputBlock {
                    block,
                    consume_by_ns: cutoff(block),
                    presentation_ns: decision.presentation_ns,
                    outcome: decision.outcome.code(),
                    payload_sha256: hash(&bytes[..usize::from(decision.frames) * 4]),
                    late_by_ns: decision.late_by_ns,
                    render_reserved_end_ns: reserved_end,
                    render_served_end_ns: served_end,
                    render_late_by_ns: render_late,
                });
            }
        }
    }
    tail.recovered_blocks.sort_unstable();
    resources.decode_process_peak_rss_bytes = peak_rss();
    resources.encoded_airtime_at_6mbps_ns =
        (resources.source_air_bytes + resources.repair_air_bytes + resources.feedback_air_bytes)
            * 8
            * 1_000_000_000
            / 6_000_000;
    Ok(StudyResult {
        schema: "n05.study.v4",
        profile: PROFILE,
        library: CODING_LIBRARY,
        evidence_class: "offline-host-synthetic",
        build_profile: BuildProfile {
            recipe: BUILD_RECIPE,
            opt_level: env!("N05_OPT_LEVEL"),
            debug: env!("N05_DEBUG"),
            cargo_profile: env!("N05_CARGO_PROFILE"),
        },
        input,
        source_trace_sha256: hex(&trace.finalize()),
        payload_sha256: hex(&content.finalize()),
        blocks: BLOCKS,
        frames_per_packet: BLOCK_FRAMES,
        source_symbols: SOURCE_SYMBOLS,
        repair_symbols: REPAIR_SYMBOLS,
        source_epoch: 1,
        repair,
        tail,
        resources,
        output,
        unrecovered_blocks: unrecovered,
        diagnostics_dropped: 0,
        promotion: "none: offline research; FEC and native integrations retained; N06 admission pending",
    })
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[test]
    fn n05_gate_deadline_and_allowance_boundaries_preserve_permitted_work() {
        for delta in [-1_i64, 0, 1] {
            let requested_finish = cutoff(4).checked_add_signed(delta).unwrap();
            let ready = requested_finish - CODING_RESERVE_NS;
            let start = worker_start(ready, CODING_RESERVE_NS, &[], true);
            let mut gate = WindowGate {
                used: 0,
                cancelled: false,
            };
            let result = gate.reserve(start, CODING_RESERVE_NS, &[4], true);
            if delta < 0 {
                assert_eq!(result.ok(), Some(cutoff(4) - 1));
                assert_eq!(gate.used, CODING_RESERVE_NS);
            } else {
                assert!(matches!(result, Err(GateReject::Deadline)));
                assert_eq!(gate.used, 0);
            }
        }
        let ready = cutoff(4) - CODING_RESERVE_NS + 1;
        let protected_start = worker_start(ready, CODING_RESERVE_NS, &[], true);
        assert_eq!(protected_start, cutoff(4) + RENDER_RESERVED_NS);
        assert_eq!(worker_start(ready, CODING_RESERVE_NS, &[], false), ready);
        assert_eq!(
            service_at(
                cutoff(4),
                &[Span {
                    start: protected_start,
                    end: protected_start + CODING_RESERVE_NS
                }],
                0
            ),
            cutoff(4)
        );
        assert_eq!(
            service_at(
                cutoff(4),
                &[Span {
                    start: ready,
                    end: ready + CODING_RESERVE_NS
                }],
                0
            ),
            cutoff(4) + 1
        );
        let mut exact = WindowGate {
            used: 0,
            cancelled: false,
        };
        assert_eq!(
            exact.reserve(0, MAX_WINDOW_WORK_NS, &[0], true).ok(),
            Some(MAX_WINDOW_WORK_NS)
        );
        assert_eq!(exact.used, MAX_WINDOW_WORK_NS);
        assert!(matches!(
            exact.reserve(0, 1, &[0], true),
            Err(GateReject::Work)
        ));
        assert_eq!(exact.used, MAX_WINDOW_WORK_NS);
        let mut above = WindowGate {
            used: 0,
            cancelled: false,
        };
        assert!(matches!(
            above.reserve(0, MAX_WINDOW_WORK_NS + 1, &[0], true),
            Err(GateReject::Work)
        ));
        assert_eq!(above.used, 0);
    }

    #[test]
    fn n05_render_work_is_protected_through_the_permitted_end_boundary() {
        let at = cutoff(4);
        for ready in [
            at - 500_000,
            at,
            at + 1,
            at + WORK_NS,
            at + RENDER_RESERVED_NS - 1,
        ] {
            assert_eq!(
                worker_start(ready, CODING_RESERVE_NS, &[], true),
                at + RENDER_RESERVED_NS
            );
        }
        let permitted = at + RENDER_RESERVED_NS;
        assert_eq!(
            worker_start(permitted, CODING_RESERVE_NS, &[], true),
            permitted
        );
        let forbidden = [Span {
            start: at + 1,
            end: at + 1 + CODING_RESERVE_NS,
        }];
        let allowed = [Span {
            start: permitted,
            end: permitted + CODING_RESERVE_NS,
        }];
        assert_eq!(
            service_at(at, &forbidden, 0),
            at,
            "decision-only protection misses this counterexample"
        );
        assert!(render_served_end(at, &forbidden) > permitted);
        assert_eq!(render_served_end(at, &allowed), permitted);
        println!(
            "N05-RENDER-OBSERVED {}",
            serde_json::json!({"schema":"n05.render-control.v1",
            "reserved_ns":RENDER_RESERVED_NS,"guarded_end_ns":render_served_end(at,&allowed),
            "reserved_end_ns":permitted,"unguarded_decision_late_ns":service_at(at,&forbidden,0)-at,
            "unguarded_render_late_ns":render_served_end(at,&forbidden)-permitted})
        );
    }

    #[test]
    fn n05_hybrid_tail_has_a_permitted_path_and_zero_side_effect_refusals() {
        let input = StudyInput {
            scenario: Scenario::Burst,
            strategy: Strategy::Hybrid,
            seed: 0x5eed05,
        };
        let ready = fec_barrier(input, 8, source_time(36) + CODING_RESERVE_NS);
        let gate = WindowGate {
            used: CODING_RESERVE_NS,
            cancelled: false,
        };
        let permitted = collect_and_plan_window(
            request_window(input, 8, ready, &[], true),
            &[],
            gate,
            &[],
            observed_by,
        )
        .unwrap();
        assert_eq!(permitted.accounting.admitted, 4);
        assert_eq!(permitted.accounting.feedback_messages, 1);
        assert_eq!(permitted.used, CODING_RESERVE_NS + 4 * REQUEST_COST_NS);
        for (state, at) in [
            (
                WindowGate {
                    used: MAX_WINDOW_WORK_NS,
                    cancelled: false,
                },
                ready,
            ),
            (
                WindowGate {
                    used: CODING_RESERVE_NS,
                    cancelled: true,
                },
                ready,
            ),
            (gate, cutoff(32)),
        ] {
            let denied = collect_and_plan_window(
                request_window(input, 8, at, &[], true),
                &[],
                state,
                &[],
                observed_by,
            )
            .unwrap();
            assert_eq!(denied.used, state.used);
            assert!(denied.jobs.iter().all(Option::is_none));
            assert_eq!(denied.accounting.air_bytes, 0);
            assert_eq!(denied.accounting.feedback_air_bytes, 0);
            assert_eq!(denied.accounting.work_charged_ns, 0);
            assert_eq!(denied.accounting.max_outstanding, 0);
            assert_eq!(denied.accounting.feedback_messages, 0);
            assert_eq!(denied.accounting.requested, 4);
            assert_eq!(denied.accounting.admitted, 0);
            if state.cancelled {
                assert_eq!(denied.accounting.refused_cancelled, 4);
            } else if state.used == MAX_WINDOW_WORK_NS {
                assert_eq!(denied.accounting.refused_work, 4);
            } else {
                assert_eq!(denied.accounting.refused_deadline, 4);
            }
        }
    }

    #[test]
    fn n05_hybrid_tail_uses_only_the_observed_prefix_not_future_deliveries() {
        let input = StudyInput {
            scenario: Scenario::Burst,
            strategy: Strategy::Hybrid,
            seed: 0x5eed05,
        };
        let barrier = fec_barrier(input, 8, source_time(36) + CODING_RESERVE_NS);
        // A real, nonempty original prefix leaves exactly three requests to admit.
        let prefix = symbol(context(8), 2, source_payload(34));
        let future = symbol(context(8), 0, source_payload(32));
        let a = vec![
            (barrier - 10_000_000, prefix.clone()),
            (barrier + 1, future.clone()),
        ];
        let b = vec![
            (barrier - 10_000_000, prefix),
            (barrier + 1_000_000, future),
        ];
        let gate = WindowGate {
            used: CODING_RESERVE_NS,
            cancelled: false,
        };
        let request = request_window(input, 8, barrier, &[], true);
        // Call the SAME collection + planning seam as run_model, not a prefiltered helper.
        let plan_a = collect_and_plan_window(request, &a, gate, &[], observed_by).unwrap();
        let plan_b = collect_and_plan_window(request, &b, gate, &[], observed_by).unwrap();
        let requests = |plan: &TailPlan| {
            plan.jobs
                .iter()
                .flatten()
                .map(|j| (j.block, j.start, j.finish, j.sent))
                .collect::<Vec<_>>()
        };
        assert_eq!(requests(&plan_a), requests(&plan_b));
        assert_eq!(plan_a.accounting.admitted, 3);
        assert_eq!(
            plan_a
                .jobs
                .iter()
                .flatten()
                .map(|j| j.block)
                .collect::<Vec<_>>(),
            [32, 33, 35]
        );
        assert_eq!(observed_by(barrier, &a).len(), 1);
        assert_eq!(observed_by(barrier + 2, &a).len(), 2);
        assert_eq!(
            observed_by(barrier + 2, &b).len(),
            1,
            "suffix delivery really differs"
        );
        fn wrong_collector(_at: u64, events: &[(u64, CodingSymbol)]) -> Vec<CodingSymbol> {
            observed_by(u64::MAX, events) // Planted bug: ignores the causal observation barrier.
        }
        for events in [&a, &b] {
            assert!(matches!(
                collect_and_plan_window(request, events, gate, &[], wrong_collector),
                Err("request collector violated the observable prefix")
            ));
        }
        println!(
            "N05-PREFIX-OBSERVED {}",
            serde_json::json!({
                "schema":"n05.prefix-control.v1", "prefix_symbols":observed_by(barrier,&a).len(),
                "admitted":plan_a.accounting.admitted, "earlier_requests_equal":requests(&plan_a)==requests(&plan_b),
                "later_prefixes_differ":observed_by(barrier+2,&a).len()!=observed_by(barrier+2,&b).len(),
                "wrong_collector_rejected":collect_and_plan_window(request,&a,gate,&[],wrong_collector).is_err()
            })
        );
    }
}
