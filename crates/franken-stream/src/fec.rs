//! N06 host-development K4/R4 hybrid. Authenticated, fixed state and cooperative
//! recovery; no board/WCET/runtime admission. See docs/contracts/n06.md.
use super::{HmacSha256, StreamId, StreamKey, tags_equal};
use crate::playout::{self, Admission, ClockView, MediaPacket, PlayoutEngine, Poll, RepairBlock};
use hmac::{KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::sync::atomic::AtomicBool;

pub mod solver;
pub use solver::{BYTES, DecodeState, GENERATOR, IncrementalDecode, K, MAX_WORK, N};
pub const PROFILE: &str = "n06.host-hybrid.k4-r4.v1";
pub const SELECTED_N05: &str = "n05.rfc6330.k4-r4.v4";
pub const CODING_REVISION: &str = "14032b8f2c832ee7ef1946404f5efb18162af045";
pub const HEADER: usize = 112;
pub const DATAGRAM: usize = HEADER + BYTES + 16;
pub const WINDOWS: usize = 8;
pub const AUTH_WORK: u64 = 8192;
pub const WINDOW_ALLOWANCE_NS: u64 = 20_000_000;
pub const WORK_UNIT_NS: u64 = 50; // Declared synthetic timebase, NOT measured CPU/WCET.
pub const AUTH_PAIR_ATTEMPTS: u8 = 2;
pub const MAX_GROUP_MEMBERS: usize = 21;
pub const QUANTUM: u64 = 512;
const _: () = assert!(QUANTUM >= 2 * solver::HASH_WORK);
pub const FEEDBACK_BYTES: usize = 96;
const _: () = assert!(
    ((MAX_GROUP_MEMBERS as u64 + 1) * AUTH_WORK + K as u64 * (AUTH_WORK + 1024 + 1000))
        * WORK_UNIT_NS
        <= WINDOW_ALLOWANCE_NS
);
const AUTH_DOMAIN: &[u8] = b"FFWR-N06-v1-auth";
const DIGEST_DOMAIN: &[u8] = b"FFWR-N06-v1-source";
const WORK_NS: u64 = 1_000_000;
const LEAD_NS: u64 = 1_000_000;
const GUARD_NS: u64 = 500_000;
// Ceiling of one 1024-frame work interval at 48 kHz.
const WORK_INTERVAL_NS: u64 = 21_333_334;
pub fn profile_view(mut view: ClockView) -> ClockView {
    view.uncertainty_ns = view.uncertainty_ns.max(GUARD_NS);
    view
}
fn work_interval(now: u64) -> u64 {
    (u128::from(now) * 48_000 / (1024 * 1_000_000_000)) as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Refusal {
    Shape,
    Authentication,
    Identity,
    Epoch,
    Future,
    Duplicate,
    Conflict,
    Storm,
    Work,
    Deadline,
    Cancelled,
    Busy,
    Clock,
    Information,
    Integrity,
    Protected { until_ns: u64 },
    TypedIngressRequired,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IngressKind {
    Source,
    Retransmit,
    RepairSymbol,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedIngress {
    pub stream: u64,
    pub origin_ns: u64,
    pub sequence: u64,
    pub epoch: u64,
    pub window: u64,
    pub esi: u8,
    pub kind: IngressKind,
    pub admission: Option<Admission>,
}
impl AuthenticatedIngress {
    pub fn credit_key(&self) -> (u64, u64, u64, IngressKind, u64) {
        (
            self.stream,
            self.epoch,
            self.origin_ns,
            self.kind,
            self.sequence,
        )
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Status {
    pub profile: &'static str,
    pub chosen_strategy: &'static str,
    pub production_fec_profile_admitted: bool,
    pub counters: Counters,
    pub retained_windows: usize,
    pub authenticated_symbols: u32,
    pub active_window: Option<u64>,
    pub remaining_work_bound: u64,
    pub charged_work: u64,
    pub reserved_work: u64,
    pub resident_bytes: usize,
    pub windows: [WindowStatus; WINDOWS],
}
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct WindowStatus {
    pub window: Option<u64>,
    pub authenticated_mask: u8,
    pub queued_or_committed_mask: u8,
    pub refusal: Option<Refusal>,
}
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct Counters {
    pub datagrams: u64,
    pub authenticated: u64,
    pub structural: u64,
    pub deferred: u64,
    pub buffered_repairs: u64,
    pub source_reoffers: u64,
    pub authentication_failed: u64,
    pub duplicates: u64,
    pub storm: u64,
    pub future: u64,
    pub conflicts: u64,
    pub work_refused: u64,
    pub deadline_refused: u64,
    pub decode_attempts: u64,
    pub decode_work: u64,
    pub auth_work: u64,
    pub cancelled: u64,
    pub fallback: u64,
    pub recovered: u64,
    pub late: u64,
    pub n04_duplicate: u64,
    pub feedback: u64,
    pub diagnostics_dropped: u64,
}
#[derive(Clone)]
pub struct SessionConfig {
    pub stream: StreamId,
    pub epoch: u64,
    pub presentation_origin_ns: u64,
    pub key: StreamKey,
}
/// Aggregate at most four original requests. Reliable control remains independent.
pub struct Feedback(pub [u8; FEEDBACK_BYTES]);
pub struct TailReplies {
    pub packets: [Option<[u8; DATAGRAM]>; K],
    pub admitted: u8,
    pub work: u64,
}

/// One bounded tail per source window, with a separate pre-MAC ingress quota.
pub struct SenderWindow {
    config: SessionConfig,
    window: u64,
    source: [[u8; BYTES]; K],
    digest: [u8; 32],
    served: bool,
    sent_mask: u8,
    checks: u8,
    check_limit: u8,
    interval: Option<u64>,
    last_clock: Option<u64>,
    charged: u64,
}
impl SenderWindow {
    pub fn new(
        config: SessionConfig,
        window: u64,
        source: [[u8; BYTES]; K],
        group_members: usize,
    ) -> Result<Self, Refusal> {
        if !(1..=MAX_GROUP_MEMBERS).contains(&group_members) {
            return Err(Refusal::Shape);
        }
        let metadata = config.metadata(window)?;
        let digest = content_digest(&metadata, &source);
        Ok(Self {
            config,
            window,
            source,
            digest,
            served: false,
            sent_mask: 0,
            checks: 0,
            check_limit: (group_members + 1) as u8,
            interval: None,
            last_clock: None,
            charged: 66 * solver::HASH_WORK + K as u64 * BYTES as u64,
        })
    }
    pub fn serve(
        &mut self,
        view: ClockView,
        feedback: &[u8],
        cancelled: &AtomicBool,
    ) -> Result<TailReplies, Refusal> {
        use std::sync::atomic::Ordering;
        if feedback.len() != FEEDBACK_BYTES || &feedback[..4] != b"FFWA" {
            return Err(Refusal::Shape);
        }
        if !view.usable {
            return Err(Refusal::Clock);
        }
        if self.last_clock.is_some_and(|last| view.group_ns < last) {
            return Err(Refusal::Clock);
        }
        self.last_clock = Some(view.group_ns);
        let interval = work_interval(view.group_ns);
        if self.interval != Some(interval) {
            self.interval = Some(interval);
            self.checks = 0;
            self.charged = 0;
        }
        if self.served {
            return Err(Refusal::Duplicate);
        }
        if self.checks >= self.check_limit {
            return Err(Refusal::Storm);
        }
        if cancelled.load(Ordering::Acquire) {
            return Err(Refusal::Cancelled);
        }
        self.checks += 1;
        self.charged += AUTH_WORK;
        if !tags_equal(&feedback[80..], &tag(&self.config.key, &feedback[..80])) {
            return Err(Refusal::Authentication);
        }
        if feedback[4..64] != self.config.metadata(self.window)?[4..]
            || feedback[64] == 0
            || feedback[64] & !15 != 0
            || feedback[65] != 1
            || feedback[66..72] != [0; 6]
            || read64(feedback, 72) > view.group_ns
        {
            return Err(Refusal::Shape);
        }
        let requested = feedback[64] & !self.sent_mask;
        if requested == 0 {
            return Err(Refusal::Duplicate);
        }
        let count = requested.count_ones() as u64;
        let cost = count * (AUTH_WORK + 1024 + 1000);
        if (self.charged + cost) * WORK_UNIT_NS > WINDOW_ALLOWANCE_NS {
            return Err(Refusal::Work);
        }
        let latest = view
            .group_ns
            .saturating_add(52_000_000 + cost * WORK_UNIT_NS);
        let mut allowed = 0_u8;
        for i in 0..K {
            let p = self.config.presentation_origin_ns
                + playout::frames_to_ns((self.window * 4 + i as u64) * 256);
            if requested & (1 << i) != 0
                && latest
                    < playout::consume_by(p, WORK_NS, LEAD_NS, view.uncertainty_ns.max(GUARD_NS))
            {
                allowed |= 1 << i;
            }
        }
        if allowed == 0 {
            return Err(Refusal::Deadline);
        }
        // Consume the single attempt and its conservative full cost before crypto;
        // cancellation cannot refund already performed work into a retry loop.
        self.sent_mask |= allowed;
        self.served = self.sent_mask == 15;
        self.charged += cost;
        let mut packets = std::array::from_fn(|_| None);
        for (i, packet) in packets.iter_mut().enumerate() {
            if allowed & (1 << i) != 0 {
                if cancelled.load(Ordering::Acquire) {
                    return Err(Refusal::Cancelled);
                }
                *packet = Some(sign_symbol(
                    &self.config,
                    self.window,
                    i,
                    1,
                    self.digest,
                    &self.source[i],
                )?);
            }
        }
        if cancelled.load(Ordering::Acquire) {
            return Err(Refusal::Cancelled);
        }
        Ok(TailReplies {
            packets,
            admitted: allowed,
            work: cost,
        })
    }
    pub fn charged_work(&self) -> u64 {
        self.charged
    }
    pub fn checks_used(&self) -> u8 {
        self.checks
    }
    pub fn check_limit(&self) -> u8 {
        self.check_limit
    }
}
impl SessionConfig {
    pub fn metadata(&self, window: u64) -> Result<[u8; 64], Refusal> {
        if self.epoch == 0 || window > u64::from(u32::MAX) {
            return Err(Refusal::Shape);
        }
        let frame = window.checked_mul(1024).ok_or(Refusal::Shape)?;
        let presentation = self
            .presentation_origin_ns
            .checked_add(playout::frames_to_ns(frame))
            .ok_or(Refusal::Shape)?;
        if presentation > super::MAX_TIMESTAMP_NS || self.presentation_origin_ns < 500_000_000 {
            return Err(Refusal::Shape);
        }
        if self
            .presentation_origin_ns
            .checked_add(playout::frames_to_ns(frame + 3 * 256))
            .is_none_or(|last| last > super::MAX_TIMESTAMP_NS)
        {
            return Err(Refusal::Shape);
        }
        let mut out = [0; 64];
        out[..4].copy_from_slice(b"FFWR");
        out[4..8].copy_from_slice(&[1, 1, 4, 4]);
        out[8..10].copy_from_slice(&1024_u16.to_be_bytes());
        out[10] = 1;
        for (at, value) in [
            (12, self.stream.get()),
            (20, self.epoch),
            (28, window),
            (36, frame),
            (44, presentation),
            (
                52,
                playout::consume_by(presentation, WORK_NS, LEAD_NS, GUARD_NS),
            ),
        ] {
            out[at..at + 8].copy_from_slice(&value.to_be_bytes());
        }
        Ok(out)
    }
}
fn read64(input: &[u8], at: usize) -> u64 {
    let mut out = [0; 8];
    out.copy_from_slice(&input[at..at + 8]);
    u64::from_be_bytes(out)
}
fn tag(key: &StreamKey, body: &[u8]) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("fixed key");
    mac.update(AUTH_DOMAIN);
    mac.update(body);
    let full = mac.finalize().into_bytes();
    let mut out = [0; 16];
    out.copy_from_slice(&full[..16]);
    out
}
pub fn content_digest(metadata: &[u8; 64], source: &[[u8; BYTES]; K]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(DIGEST_DOMAIN);
    digest.update(metadata);
    for block in source {
        digest.update(block);
    }
    digest.finalize().into()
}
pub fn encode_symbol(source: &[[u8; BYTES]; K], esi: usize) -> Result<[u8; BYTES], Refusal> {
    if esi >= N {
        return Err(Refusal::Shape);
    }
    let mut out = [0; BYTES];
    for (byte, value) in out.iter_mut().enumerate() {
        for (&coefficient, block) in GENERATOR[esi].iter().zip(source) {
            *value ^= solver::multiply(coefficient, block[byte]);
        }
    }
    Ok(out)
}
/// Fixed wire, explicit BE integers. kind0=source,1=optional retransmit,2=RFC repair.
/// Distinct magic/version/domain: the N01 XOR Repair semantic is never reinterpreted.
pub fn sign_symbol(
    config: &SessionConfig,
    window: u64,
    esi: usize,
    kind: u8,
    digest: [u8; 32],
    payload: &[u8; BYTES],
) -> Result<[u8; DATAGRAM], Refusal> {
    if esi >= N || !matches!((kind, esi), (0 | 1, 0..=3) | (2, 4..=7)) {
        return Err(Refusal::Shape);
    }
    let metadata = config.metadata(window)?;
    let mut wire = [0; DATAGRAM];
    wire[..64].copy_from_slice(&metadata);
    wire[64..72].copy_from_slice(&(window * 8 + esi as u64).to_be_bytes());
    wire[72] = esi as u8;
    wire[73] = kind;
    wire[80..112].copy_from_slice(&digest);
    wire[HEADER..HEADER + BYTES].copy_from_slice(payload);
    let mac = tag(&config.key, &wire[..HEADER + BYTES]);
    wire[HEADER + BYTES..].copy_from_slice(&mac);
    Ok(wire)
}

struct Window {
    id: Option<u64>,
    mask: u8,
    published: u8,
    symbols: [[u8; BYTES]; N],
    digest: [u8; 32],
    attempted: bool,
    feedback: bool,
    conflict: bool,
    cancelled: bool,
    refusal: Option<Refusal>,
}
impl Window {
    fn new() -> Self {
        Self {
            id: None,
            mask: 0,
            published: 0,
            symbols: [[0; BYTES]; N],
            digest: [0; 32],
            attempted: false,
            feedback: false,
            conflict: false,
            cancelled: false,
            refusal: None,
        }
    }
}
/// Fixed state: eight coding windows and one active scalar solver. The owning
/// media consumer lends its existing N04 queue. No packet/solve/stop allocation.
pub struct Receiver {
    config: SessionConfig,
    windows: [Window; WINDOWS],
    solver: IncrementalDecode,
    active: Option<usize>,
    interval: u64,
    // A control rebind may change the group clock's origin. Charge survives,
    // then the first usable reading anchors a full interval in the new domain.
    rebase_pending: bool,
    rebase_start: Option<u64>,
    auth_attempt_ids: [Option<u64>; WINDOWS],
    auth_attempts: [[u8; N]; WINDOWS],
    charged: u64,
    reserved: u64,
    stopped: bool,
    next_collection: u64,
    last_clock: Option<u64>,
    render_until: u64,
    pub counters: Counters,
}
impl std::fmt::Debug for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FecReceiver")
            .field("status", &self.status())
            .finish()
    }
}
impl Receiver {
    pub fn new(config: SessionConfig) -> Result<Self, Refusal> {
        config.metadata(0)?;
        Ok(Self {
            config,
            windows: std::array::from_fn(|_| Window::new()),
            solver: IncrementalDecode::new(),
            active: None,
            interval: 0,
            rebase_pending: false,
            rebase_start: None,
            auth_attempt_ids: [None; WINDOWS],
            auth_attempts: [[0; N]; WINDOWS],
            charged: 0,
            reserved: 0,
            stopped: false,
            next_collection: 0,
            last_clock: None,
            render_until: 0,
            counters: Counters::default(),
        })
    }
    pub fn resident_bytes() -> usize {
        std::mem::size_of::<Self>()
    }
    /// Fixed-size counter snapshot, no IO/callback/sink on the ingress/render path.
    pub fn status(&self) -> Status {
        Status {
            profile: PROFILE,
            chosen_strategy: "hybrid",
            production_fec_profile_admitted: false,
            counters: self.counters.clone(),
            retained_windows: self.windows.iter().filter(|w| w.id.is_some()).count(),
            authenticated_symbols: self.windows.iter().map(|w| w.mask.count_ones()).sum(),
            active_window: self.active.and_then(|i| self.windows[i].id),
            remaining_work_bound: if self.active.is_some()
                && self.solver.state() == DecodeState::Ready
            {
                K as u64 * solver::PUBLICATION_WORK
            } else {
                self.solver.remaining_bound()
            },
            charged_work: self.charged,
            reserved_work: self.reserved,
            resident_bytes: Self::resident_bytes(),
            windows: std::array::from_fn(|i| WindowStatus {
                window: self.windows[i].id,
                authenticated_mask: self.windows[i].mask,
                queued_or_committed_mask: self.windows[i].published,
                refusal: self.windows[i].refusal,
            }),
        }
    }
    fn source_window(&self, now: u64) -> u64 {
        let origin = self.config.presentation_origin_ns - 500_000_000;
        ((u128::from(now.saturating_sub(origin)) * 48_000) / (1024 * 1_000_000_000)) as u64
    }
    fn update_interval(&mut self, now: u64) {
        let current = work_interval(now);
        if self.rebase_pending {
            let start = *self.rebase_start.get_or_insert(now);
            if now.saturating_sub(start) < WORK_INTERVAL_NS {
                return;
            }
            self.rebase_pending = false;
            self.rebase_start = None;
            self.interval = current;
            self.auth_attempt_ids = [None; WINDOWS];
            self.auth_attempts = [[0; N]; WINDOWS];
            self.charged = 0;
            return;
        }
        if current > self.interval {
            self.interval = current;
            self.auth_attempt_ids = [None; WINDOWS];
            self.auth_attempts = [[0; N]; WINDOWS];
            self.charged = 0;
        }
    }
    fn admit_clock(&mut self, view: ClockView) -> Result<(), Refusal> {
        if !view.usable
            || view.group_ns > super::MAX_TIMESTAMP_NS
            || self.source_window(view.group_ns) > u64::from(u32::MAX)
            || self.last_clock.is_some_and(|last| view.group_ns < last)
        {
            return Err(Refusal::Clock);
        }
        self.last_clock = Some(view.group_ns);
        Ok(())
    }
    /// The owning media consumer records preparation readings through the same clock bridge.
    pub fn observe_clock(&mut self, view: ClockView) -> Result<(), Refusal> {
        if self.admit_clock(view).is_err() {
            self.cancel();
            return Err(Refusal::Clock);
        }
        Ok(())
    }
    pub fn validate_rebind(&self, epoch: u64, origin_ns: u64) -> Result<(), Refusal> {
        if self.stopped {
            return Err(Refusal::Cancelled);
        }
        if epoch != self.config.epoch {
            return Err(Refusal::Epoch);
        }
        let mut config = self.config.clone();
        config.presentation_origin_ns = origin_ns;
        config.metadata(0)?;
        Ok(())
    }
    /// Trusted same-epoch start/relock, not packet-driven profile selection.
    /// Same-context authenticated inputs are retained and can be re-offered to
    /// the reset N04 queue; a changed origin invalidates all old wire metadata.
    pub fn rebind(&mut self, engine: &PlayoutEngine, origin_ns: u64) -> Result<(), Refusal> {
        self.validate_rebind(self.config.epoch, origin_ns)?;
        if !engine.matches_fec_timeline(self.config.epoch, origin_ns) {
            return Err(Refusal::Shape);
        }
        let changed = origin_ns != self.config.presentation_origin_ns;
        self.cancel();
        self.config.presentation_origin_ns = origin_ns;
        let first_window = engine.snapshot().cursor / K as u64;
        for slot in &mut self.windows {
            if changed || slot.id.is_some_and(|window| window < first_window) {
                slot.id = None;
                slot.mask = 0;
            }
            slot.published = 0;
            slot.attempted = false;
            slot.feedback = false;
            slot.cancelled = false;
            slot.refusal = None;
            if changed {
                slot.conflict = false;
            }
        }
        // An unchanged context still uses the same group-clock timeline: a
        // backwards first reading must not start the new work interval early.
        if changed {
            self.last_clock = None;
        }
        self.rebase_pending = true;
        self.rebase_start = None;
        self.render_until = 0;
        self.next_collection = first_window;
        if changed {
            self.auth_attempt_ids = [None; WINDOWS];
            self.auth_attempts = [[0; N]; WINDOWS];
        }
        Ok(())
    }
    fn charge(&mut self, units: u64) -> Result<(), Refusal> {
        if (self.charged + self.reserved + units).saturating_mul(WORK_UNIT_NS) > WINDOW_ALLOWANCE_NS
        {
            return Err(Refusal::Work);
        }
        self.charged += units;
        Ok(())
    }
    fn cutoff(&self, block: u64, uncertainty: u64) -> u64 {
        playout::consume_by(
            self.config.presentation_origin_ns + playout::frames_to_ns(block * 256),
            WORK_NS,
            LEAD_NS,
            uncertainty.max(GUARD_NS),
        )
    }
    fn protected_until(
        &self,
        engine: &PlayoutEngine,
        now: u64,
        cost: u64,
        uncertainty: u64,
    ) -> Option<u64> {
        if now < self.render_until {
            return Some(self.render_until);
        }
        let next = self.cutoff(engine.snapshot().cursor, uncertainty);
        // An already-past fence cannot expire itself: the owner must take the
        // overdue decision and note its full render interval before retrying.
        if next <= now {
            return Some(now);
        }
        (now.saturating_add(cost) >= next).then_some(next.saturating_add(WORK_NS + LEAD_NS))
    }
    fn guard(
        &mut self,
        engine: &PlayoutEngine,
        now: u64,
        cost: u64,
        uncertainty: u64,
    ) -> Result<(), Refusal> {
        if let Some(until_ns) = self.protected_until(engine, now, cost, uncertainty) {
            self.counters.deferred += 1;
            return Err(Refusal::Protected { until_ns });
        }
        Ok(())
    }
    /// The presentation origin this receiver's wire metadata is bound to. A same-epoch start that changes it begins a new
    /// window numbering (see [`Self::rebind`]).
    pub fn origin_ns(&self) -> u64 {
        self.config.presentation_origin_ns
    }
    pub fn identity(&self) -> (u64, u64, u64) {
        (
            self.config.stream.get(),
            self.config.epoch,
            self.config.presentation_origin_ns,
        )
    }
    /// Whether [`Self::ingest`] called now would answer [`Refusal::Protected`], and until when. A pure query for the carrier:
    /// a datagram it has not read yet can stay in the socket until this is `None`. It reads no clock, counts nothing and
    /// consumes nothing. A stopped receiver, an unusable view and a timeline that does not match report `None`: ingest itself
    /// classifies and counts those.
    pub fn deferral(&self, engine: &PlayoutEngine, view: ClockView) -> Option<u64> {
        let view = profile_view(view);
        if self.stopped
            || !view.usable
            || !engine.matches_fec_timeline(self.config.epoch, self.config.presentation_origin_ns)
        {
            return None;
        }
        self.protected_until(
            engine,
            view.group_ns,
            AUTH_WORK * WORK_UNIT_NS,
            view.uncertainty_ns,
        )
    }
    fn window_order(&self) -> [usize; WINDOWS] {
        let mut order = std::array::from_fn(|i| i);
        order.sort_unstable_by_key(|i| self.windows[*i].id.unwrap_or(u64::MAX));
        order
    }
    fn reoffer_source(
        &mut self,
        engine: &mut PlayoutEngine,
        view: ClockView,
    ) -> Result<(), Refusal> {
        let cursor = engine.snapshot().cursor;
        for index in self.window_order() {
            let Some(window) = self.windows[index].id else {
                continue;
            };
            if self.windows[index].conflict {
                continue;
            }
            for esi in 0..K {
                let bit = 1 << esi;
                if self.windows[index].mask & bit == 0 || self.windows[index].published & bit != 0 {
                    continue;
                }
                let block = window * 4 + esi as u64;
                if block >= cursor + u64::from(playout::PlayoutProfile::MUSIC.horizon_blocks) {
                    continue;
                }
                self.charge(solver::PUBLICATION_WORK)?;
                let admission = engine.on_packet(
                    view,
                    &MediaPacket {
                        epoch: self.config.epoch,
                        start_frame: block * 256,
                        presentation_ns: self.config.presentation_origin_ns
                            + playout::frames_to_ns(block * 256),
                        frames: 256,
                        payload: &self.windows[index].symbols[esi],
                    },
                );
                self.counters.source_reoffers += 1;
                if matches!(
                    admission,
                    Admission::Admitted | Admission::Duplicate | Admission::Late
                ) {
                    self.windows[index].published |= bit;
                }
                match admission {
                    Admission::Late => self.counters.late += 1,
                    Admission::Duplicate => self.counters.n04_duplicate += 1,
                    _ => {}
                }
                return Ok(()); // At most one charged copy per poll.
            }
        }
        Ok(())
    }
    pub fn ingest(
        &mut self,
        engine: &mut PlayoutEngine,
        view: ClockView,
        wire: &[u8],
    ) -> Result<AuthenticatedIngress, Refusal> {
        let view = profile_view(view);
        if self.stopped {
            return Err(Refusal::Cancelled);
        }
        self.counters.datagrams += 1;
        self.observe_clock(view)?;
        self.update_interval(view.group_ns);
        if wire.len() != DATAGRAM
            || &wire[..4] != b"FFWR"
            || wire[4..12] != [1, 1, 4, 4, 4, 0, 1, 0]
        {
            self.counters.structural += 1;
            return Err(Refusal::Shape);
        }
        if !view.usable {
            return Err(Refusal::Clock);
        }
        if !engine.matches_fec_timeline(self.config.epoch, self.config.presentation_origin_ns) {
            self.cancel();
            return Err(Refusal::Shape);
        }
        self.guard(
            engine,
            view.group_ns,
            AUTH_WORK * WORK_UNIT_NS,
            view.uncertainty_ns,
        )?;
        // Untrusted hints select only a bounded anti-abuse counter/cache lookup.
        // A held published pair is discarded without claiming authentication.
        let hinted_window = read64(wire, 28);
        let hinted_esi = usize::from(wire[72]);
        let current = self.source_window(view.group_ns);
        if hinted_window > u64::from(u32::MAX) || hinted_esi >= N {
            return Err(Refusal::Shape);
        }
        if hinted_window > current + 1 || hinted_window + WINDOWS as u64 - 1 <= current {
            self.counters.future += 1;
            return Err(Refusal::Future);
        }
        let hint_index = hinted_window as usize % WINDOWS;
        if self.windows[hint_index].id == Some(hinted_window)
            && self.windows[hint_index].mask & (1 << hinted_esi) != 0
            && (hinted_esi >= K || self.windows[hint_index].published & (1 << hinted_esi) != 0)
        {
            self.counters.duplicates += 1;
            return Err(Refusal::Duplicate);
        }
        if self.windows[hint_index]
            .id
            .is_some_and(|held| held > hinted_window)
        {
            return Err(Refusal::Future);
        }
        if self.auth_attempt_ids[hint_index] != Some(hinted_window) {
            self.auth_attempt_ids[hint_index] = Some(hinted_window);
            self.auth_attempts[hint_index] = [0; N];
        }
        if self.auth_attempts[hint_index][hinted_esi] >= AUTH_PAIR_ATTEMPTS {
            self.counters.storm += 1;
            return Err(Refusal::Storm);
        }
        self.charge(AUTH_WORK)?;
        self.auth_attempts[hint_index][hinted_esi] += 1;
        self.counters.auth_work += AUTH_WORK;
        if !tags_equal(
            &wire[HEADER + BYTES..],
            &tag(&self.config.key, &wire[..HEADER + BYTES]),
        ) {
            self.counters.authentication_failed += 1;
            return Err(Refusal::Authentication);
        }
        self.counters.authenticated += 1;
        if read64(wire, 12) != self.config.stream.get() {
            return Err(Refusal::Identity);
        }
        if read64(wire, 20) != self.config.epoch {
            return Err(Refusal::Epoch);
        }
        let window = read64(wire, 28);
        let esi = usize::from(wire[72]);
        let kind = wire[73];
        let metadata = self.config.metadata(window)?;
        if esi >= N
            || !matches!((kind, esi), (0 | 1, 0..=3) | (2, 4..=7))
            || wire[74..80] != [0; 6]
            || read64(wire, 64) != window * 8 + esi as u64
            || wire[..64] != metadata
        {
            return Err(Refusal::Shape);
        }
        let current = self.source_window(view.group_ns);
        if window > current + 1 || window + WINDOWS as u64 - 1 <= current {
            self.counters.future += 1;
            return Err(Refusal::Future);
        }
        let index = window as usize % WINDOWS;
        if self.active == Some(index) {
            return Err(Refusal::Busy);
        }
        let slot = &mut self.windows[index];
        if slot.id.is_some_and(|held| held > window) {
            return Err(Refusal::Future);
        }
        if slot.id != Some(window) {
            slot.id = Some(window);
            slot.mask = 0;
            slot.published = 0;
            slot.attempted = false;
            slot.feedback = false;
            slot.conflict = false;
            slot.cancelled = false;
            slot.refusal = None;
            slot.digest.copy_from_slice(&wire[80..112]);
        }
        if slot.mask == 0 {
            slot.digest.copy_from_slice(&wire[80..112]);
        }
        if slot.conflict || slot.digest != wire[80..112] {
            slot.conflict = true;
            slot.refusal = Some(Refusal::Conflict);
            self.counters.conflicts += 1;
            return Err(Refusal::Conflict);
        }
        if slot.cancelled && esi >= K {
            return Err(Refusal::Cancelled);
        }
        if slot.mask & (1 << esi) != 0 {
            if esi >= K || slot.published & (1 << esi) != 0 {
                self.counters.duplicates += 1;
                return Err(Refusal::Duplicate);
            }
            if slot.symbols[esi] != wire[HEADER..HEADER + BYTES] {
                slot.conflict = true;
                slot.refusal = Some(Refusal::Conflict);
                self.counters.conflicts += 1;
                return Err(Refusal::Conflict);
            }
        } else {
            slot.symbols[esi].copy_from_slice(&wire[HEADER..HEADER + BYTES]);
        }
        slot.mask |= 1 << esi;
        let admission = if esi < K {
            let block = window * 4 + esi as u64;
            let payload = &slot.symbols[esi];
            let admission = if kind == 1 {
                engine.on_repair(
                    view,
                    &RepairBlock {
                        epoch: self.config.epoch,
                        start_frame: block * 256,
                        frames: 256,
                        payload,
                    },
                )
            } else {
                engine.on_packet(
                    view,
                    &MediaPacket {
                        epoch: self.config.epoch,
                        start_frame: block * 256,
                        presentation_ns: self.config.presentation_origin_ns
                            + playout::frames_to_ns(block * 256),
                        frames: 256,
                        payload,
                    },
                )
            };
            if matches!(
                admission,
                Admission::Admitted | Admission::Duplicate | Admission::Late
            ) {
                slot.published |= 1 << esi;
            } else {
                slot.refusal = Some(match admission {
                    Admission::ClockUnusable | Admission::ClockRegression => Refusal::Clock,
                    Admission::TooFarAhead => Refusal::Future,
                    _ => Refusal::Shape,
                });
                self.counters.fallback += 1;
            }
            match admission {
                Admission::Late => self.counters.late += 1,
                Admission::Duplicate => self.counters.n04_duplicate += 1,
                _ => {}
            }
            Some(admission)
        } else {
            self.counters.buffered_repairs += 1;
            None
        };
        Ok(AuthenticatedIngress {
            stream: self.config.stream.get(),
            origin_ns: self.config.presentation_origin_ns,
            sequence: read64(wire, 64),
            epoch: self.config.epoch,
            window,
            esi: esi as u8,
            kind: match kind {
                0 => IngressKind::Source,
                1 => IngressKind::Retransmit,
                _ => IngressKind::RepairSymbol,
            },
            admission,
        })
    }
    /// Polling returns between bounded scalar/hash chunks. The caller's token can
    /// cancel while poll is running; no cancellation-blind monolithic decode.
    pub fn poll(
        &mut self,
        engine: &mut PlayoutEngine,
        view: ClockView,
        cancelled: &AtomicBool,
    ) -> Result<DecodeState, Refusal> {
        let view = profile_view(view);
        if !engine.matches_fec_timeline(self.config.epoch, self.config.presentation_origin_ns) {
            self.cancel();
            return Err(Refusal::Shape);
        }
        if self.stopped {
            return Err(Refusal::Cancelled);
        }
        self.observe_clock(view)?;
        self.update_interval(view.group_ns);
        if !view.usable {
            return Err(Refusal::Clock);
        }
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            self.cancel();
            return Err(Refusal::Cancelled);
        }
        self.guard(
            engine,
            view.group_ns,
            (QUANTUM + 2 * solver::PUBLICATION_WORK) * WORK_UNIT_NS,
            view.uncertainty_ns,
        )?;
        if self.active.is_some() && self.solver.state() == DecodeState::Ready {
            return Ok(DecodeState::Ready);
        }
        if self.active.is_none() {
            self.reoffer_source(engine, view)?;
            // Trusted schedule, not a packet/end-marker oracle: a wholly erased
            // window still reaches the no-information/tail path. One slot per
            // poll, with an eight-window catch-up ceiling after a clock jump.
            let origin = self.config.presentation_origin_ns - 500_000_000;
            let completed = (u128::from(
                view.group_ns
                    .saturating_sub(origin)
                    .saturating_sub(53_300_000),
            ) * 48_000
                / (1024 * 1_000_000_000)) as u64;
            self.next_collection = self.next_collection.max(
                self.source_window(view.group_ns)
                    .saturating_sub(WINDOWS as u64 - 2),
            );
            if self.next_collection < completed {
                self.charge(16)?;
                let window = self.next_collection;
                self.next_collection += 1;
                let slot = &mut self.windows[window as usize % WINDOWS];
                if slot.id.is_none_or(|held| held < window) {
                    slot.id = Some(window);
                    slot.mask = 0;
                    slot.published = 0;
                    slot.attempted = false;
                    slot.feedback = false;
                    slot.conflict = false;
                    slot.cancelled = false;
                    slot.refusal = None;
                }
            }
            for index in self.window_order() {
                let slot = &self.windows[index];
                let Some(window) = slot.id else { continue };
                let ready = self.config.presentation_origin_ns - 500_000_000
                    + playout::frames_to_ns((window + 1) * 1024)
                    + 53_300_000;
                if slot.attempted
                    || slot.conflict
                    || slot.cancelled
                    || slot.mask & 15 == 15
                    || view.group_ns < ready
                {
                    continue;
                }
                let metadata = self.config.metadata(window)?;
                self.windows[index].attempted = true;
                if self.windows[index].mask.count_ones() < 4 {
                    self.windows[index].refusal = Some(Refusal::Information);
                    self.counters.fallback += 1;
                    continue;
                }
                let finish = view.group_ns.saturating_add(MAX_WORK * WORK_UNIT_NS);
                let live = (0..K).any(|i| {
                    self.windows[index].published & (1 << i) == 0
                        && finish < self.cutoff(window * 4 + i as u64, view.uncertainty_ns)
                });
                if !live {
                    self.windows[index].refusal = Some(Refusal::Deadline);
                    self.counters.deadline_refused += 1;
                    self.counters.fallback += 1;
                    continue;
                }
                if (self.charged + self.reserved + MAX_WORK) * WORK_UNIT_NS > WINDOW_ALLOWANCE_NS {
                    self.windows[index].refusal = Some(Refusal::Work);
                    self.counters.work_refused += 1;
                    self.counters.fallback += 1;
                    continue;
                }
                self.reserved = MAX_WORK;
                self.active = Some(index);
                self.counters.decode_attempts += 1;
                self.solver.begin(
                    self.windows[index].mask,
                    self.windows[index].digest,
                    &metadata,
                );
                let setup = self.solver.used();
                self.charged += setup;
                self.reserved -= setup;
                self.counters.decode_work += setup;
                break;
            }
        }
        let Some(index) = self.active else {
            return Ok(DecodeState::Idle);
        };
        let window = self.windows[index].id.expect("active window");
        let finish = view
            .group_ns
            .saturating_add(self.solver.remaining_bound() * WORK_UNIT_NS);
        if !(0..K).any(|i| {
            self.windows[index].published & (1 << i) == 0
                && finish < self.cutoff(window * 4 + i as u64, view.uncertainty_ns)
        }) {
            self.active = None;
            self.reserved = 0;
            self.solver.cancel();
            self.windows[index].refusal = Some(Refusal::Deadline);
            self.counters.deadline_refused += 1;
            self.counters.fallback += 1;
            return Err(Refusal::Deadline);
        }
        let before = self.solver.used();
        let state = self
            .solver
            .poll(&self.windows[index].symbols, QUANTUM, cancelled);
        let used = self.solver.used() - before;
        self.charged += used;
        self.reserved = self.reserved.saturating_sub(used);
        self.counters.decode_work += used;
        if state != DecodeState::Pending {
            self.reserved = 0;
            self.active = None;
            if state == DecodeState::Cancelled {
                self.windows[index].refusal = Some(Refusal::Cancelled);
                self.windows[index].cancelled = true;
                self.counters.cancelled += 1;
            }
            if state == DecodeState::Ready {
                // Integrity completion does NOT publish at the stale poll-start
                // timestamp. Ownership stays pending until a fresh clock grant.
                self.active = Some(index);
                self.reserved = K as u64 * solver::PUBLICATION_WORK;
            } else {
                self.windows[index].refusal = Some(match state {
                    DecodeState::Integrity => Refusal::Integrity,
                    DecodeState::Contradiction => Refusal::Conflict,
                    DecodeState::Cancelled => Refusal::Cancelled,
                    DecodeState::Exhausted => Refusal::Work,
                    _ => Refusal::Information,
                });
                self.counters.fallback += 1;
            }
        }
        Ok(state)
    }
    /// A separate publication boundary: the owner MUST obtain a fresh admitted
    /// clock reading AFTER poll returned Ready. Epoch/cancel/deadline/render checks
    /// run again before any verified bytes reach N04. No poll-start time is reused.
    pub fn publish(
        &mut self,
        engine: &mut PlayoutEngine,
        view: ClockView,
        cancelled: &AtomicBool,
    ) -> Result<DecodeState, Refusal> {
        let view = profile_view(view);
        if !engine.matches_fec_timeline(self.config.epoch, self.config.presentation_origin_ns) {
            self.cancel();
            return Err(Refusal::Shape);
        }
        if self.admit_clock(view).is_err() {
            self.cancel();
            return Err(Refusal::Clock);
        }
        if self.stopped || cancelled.load(std::sync::atomic::Ordering::Acquire) {
            self.cancel();
            return Err(Refusal::Cancelled);
        }
        let Some(index) = self.active else {
            return Ok(DecodeState::Idle);
        };
        if self.solver.state() != DecodeState::Ready {
            return Ok(DecodeState::Pending);
        }
        self.guard(
            engine,
            view.group_ns,
            K as u64 * solver::PUBLICATION_WORK * WORK_UNIT_NS,
            view.uncertainty_ns,
        )?;
        let window = self.windows[index].id.expect("owned publication window");
        let finish = view
            .group_ns
            .saturating_add(K as u64 * solver::PUBLICATION_WORK * WORK_UNIT_NS);
        if !(0..K).any(|i| {
            self.windows[index].published & (1 << i) == 0
                && finish < self.cutoff(window * 4 + i as u64, view.uncertainty_ns)
        }) {
            self.windows[index].refusal = Some(Refusal::Deadline);
            self.solver.cancel();
            self.active = None;
            self.reserved = 0;
            self.counters.deadline_refused += 1;
            self.counters.fallback += 1;
            return Err(Refusal::Deadline);
        }
        for i in 0..K {
            if self.windows[index].published & (1 << i) == 0 {
                if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                    self.cancel();
                    return Err(Refusal::Cancelled);
                }
                self.charged += solver::PUBLICATION_WORK;
                self.counters.decode_work += solver::PUBLICATION_WORK;
                let admission = engine.on_repair(
                    view,
                    &RepairBlock {
                        epoch: self.config.epoch,
                        start_frame: (window * 4 + i as u64) * 256,
                        frames: 256,
                        payload: self.solver.output(i).expect("verified output"),
                    },
                );
                if matches!(
                    admission,
                    Admission::Admitted | Admission::Late | Admission::Duplicate
                ) {
                    self.windows[index].published |= 1 << i;
                } else {
                    self.windows[index].refusal = Some(Refusal::Future);
                }
                match admission {
                    Admission::Admitted => self.counters.recovered += 1,
                    Admission::Late => self.counters.late += 1,
                    Admission::Duplicate => self.counters.n04_duplicate += 1,
                    _ => self.counters.fallback += 1,
                }
            }
        }
        self.active = None;
        self.reserved = 0;
        Ok(DecodeState::Ready)
    }
    pub fn cancel(&mut self) {
        if let Some(index) = self.active.take() {
            self.windows[index].cancelled = true;
            self.windows[index].refusal = Some(Refusal::Cancelled);
            self.solver.cancel();
            self.counters.cancelled += 1;
        }
        self.reserved = 0;
    }
    pub fn stop(&mut self) {
        self.cancel();
        self.stopped = true;
    }
    /// Control-plane-only transition; packets cannot advance epoch or profile.
    /// The same fixed backing buffers are retained. No worker join or allocation.
    pub fn transition(
        &mut self,
        engine: &mut PlayoutEngine,
        config: SessionConfig,
    ) -> Result<(), Refusal> {
        if !engine.matches_fec_timeline(self.config.epoch, self.config.presentation_origin_ns) {
            self.cancel();
            return Err(Refusal::Shape);
        }
        config.metadata(0)?;
        if config.epoch <= self.config.epoch {
            return Err(Refusal::Epoch);
        }
        engine
            .begin_stream(config.epoch, 0, config.presentation_origin_ns)
            .map_err(|_| Refusal::Shape)?;
        self.cancel();
        self.config = config;
        for slot in &mut self.windows {
            slot.id = None;
            slot.mask = 0;
            slot.published = 0;
            slot.attempted = false;
            slot.feedback = false;
            slot.conflict = false;
            slot.cancelled = false;
            slot.refusal = None;
        }
        // Epoch changes retire symbols, not CPU already spent in this trusted
        // work interval. Only update_interval may refill the shared ledger.
        self.auth_attempt_ids = [None; WINDOWS];
        self.auth_attempts = [[0; N]; WINDOWS];
        self.reserved = 0;
        self.stopped = false;
        self.next_collection = 0;
        self.last_clock = None;
        self.rebase_pending = true;
        self.rebase_start = None;
        self.render_until = 0;
        Ok(())
    }
    /// Only after FEC completes/refuses, within the same remaining work/slack ledger.
    /// No datagram amplification: one aggregate message per window, max four requests.
    pub fn feedback(
        &mut self,
        engine: &PlayoutEngine,
        view: ClockView,
    ) -> Result<Option<Feedback>, Refusal> {
        if !engine.matches_fec_timeline(self.config.epoch, self.config.presentation_origin_ns) {
            self.cancel();
            return Err(Refusal::Shape);
        }
        if self.stopped {
            return Err(Refusal::Cancelled);
        }
        self.observe_clock(view)?;
        self.update_interval(view.group_ns);
        if !view.usable {
            return Err(Refusal::Clock);
        }
        for index in self.window_order() {
            let slot = &self.windows[index];
            let Some(window) = slot.id else { continue };
            if !slot.attempted
                || slot.feedback
                || slot.conflict
                || slot.cancelled
                || self.active == Some(index)
            {
                continue;
            }
            let cost = AUTH_WORK + K as u64 * 1000;
            let finish = view
                .group_ns
                .saturating_add(72_000_000 + cost * WORK_UNIT_NS);
            let mut missing = 0_u8;
            for i in 0..K {
                if slot.published & (1 << i) == 0
                    && finish < self.cutoff(window * 4 + i as u64, view.uncertainty_ns)
                {
                    missing |= 1 << i;
                }
            }
            if missing == 0 {
                self.windows[index].feedback = true;
                continue;
            }
            self.guard(
                engine,
                view.group_ns,
                cost * WORK_UNIT_NS,
                view.uncertainty_ns,
            )?;
            self.charge(cost)?;
            let mut wire = [0; FEEDBACK_BYTES];
            wire[..64].copy_from_slice(&self.config.metadata(window)?);
            wire[..4].copy_from_slice(b"FFWA");
            wire[64] = missing;
            wire[65] = 1;
            wire[72..80].copy_from_slice(&view.group_ns.to_be_bytes());
            let mac = tag(&self.config.key, &wire[..80]);
            wire[80..].copy_from_slice(&mac);
            self.windows[index].feedback = true;
            self.counters.feedback += 1;
            return Ok(Some(Feedback(wire)));
        }
        Ok(None)
    }
    pub fn decide(
        &mut self,
        engine: &mut PlayoutEngine,
        view: ClockView,
        out: &mut [u8; BYTES],
    ) -> Poll {
        let view = profile_view(view);
        if !view.usable {
            self.cancel();
            return Poll::ClockUnusable;
        }
        if self.observe_clock(view).is_err() {
            return Poll::ClockRegression;
        }
        let result = engine.decide(view, out);
        self.note_decision(view, &result);
        result
    }
    pub fn note_decision(&mut self, view: ClockView, result: &Poll) {
        if matches!(result, Poll::Decision(_)) {
            self.render_until = self
                .render_until
                .max(view.group_ns.saturating_add(WORK_NS + LEAD_NS));
        }
    }
}

#[cfg(test)]
mod tests;
