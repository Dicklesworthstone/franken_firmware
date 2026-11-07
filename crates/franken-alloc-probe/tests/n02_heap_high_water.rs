//! The control channel's heap, measured (`N02` / `ffw-ugf`, acceptance row 17: "single-thread cooperative, bounded, no atomic64,
//! finite caps"; the profile is `P03`'s). `docs/contracts/n02.md` says the channel allocates small buffers on every request and
//! that this was "bounded but not measured". This test measures it, on the host, with the counting allocator.
//!
//! **What is measured.** Six thousand datagrams (the operation mix of the cap census in `pipeline/profile.rs`: forged requests
//! from identities nobody admitted, ordinary commands from two controllers, priority commands from the local user,
//! acknowledgements, a `step` every seventh operation, ten milliseconds of simulated time per operation) go through the real
//! `Endpoint::handle` into the real `ControlChannel` over the real `PeerDirectory`, with a log enabled. **Every `step` is the
//! product's step**: `step_then_store` over a journal (on a medium in RAM), so the figure includes the copy of the session the
//! step runs on, the ledger's undo, the floor and mark frames and the journal's compaction. (The earlier figures were taken
//! over the plain `step`, which no durable owner runs; they are history.) Three figures come out:
//!
//! * the **datagram peak**: the most live heap one `handle` call held above where it started (decode, the clone the endpoint
//!   submits, the bytes the proof covers, the log line of a refusal, the signed reply and its bytes);
//! * the **step peak**: the same for one durable `step` (up to `max_per_step` commands applied, settled, recorded and
//!   logged, on a copy of the session, with their frames written);
//! * the **retained level**: the live heap after every operation, relative to just before the first one.
//!
//! **The bound is written from the caps, not read off the run.** `Bounds::of` computes it from the configuration's queue,
//! ledger and step caps, the peer cap, the log's caps, the pending-rejection cap and the wire and field limits, and from the
//! sizes of the public request types; `n02.md` ("Heap high-water") states the same formulas and a test in `tests/n02` holds the
//! constants here to the ones there. The measured figures only have to fit under it. The session is brought to its own bounded
//! steady state (`COMMAND_DEDUP_WINDOW` applied numbers) before the first operation, so the session's own bounded memory is not
//! charged to the channel as it fills; what the session allocates while the channel steps it is inside the step peak.
//!
//! **Peak, retained-level and growth checks.** (1) The datagram and step peaks stay under their bounds. (2) The retained level
//! stays under its bound after every operation. (3) The heap does not grow with the requests already served: the lowest
//! retained level of the last quarter of the run is not above the lowest of the third quarter by more than two records. A channel
//! whose authority keeps a copy of every message it verifies breaks (2) by name; one that takes a large scratch buffer for every
//! message breaks the datagram part of (1) by name and retains nothing. The step-peak and still-growing checks have synthetic
//! plants only; all checks are judged on synthetic runs one at a time, so none is carried by another. The real channel passes
//! before each real-channel plant, so that failure is the check seeing the plant.
//!
//! **What this is not.** Host heap only, in bytes the program asked for (not what the system allocator reserved, and not
//! fragmentation); the inline sizes are those of the platform the test runs on, so a 32-bit target's are smaller, and nothing
//! here ran on a board or a guest. Not the stack. Not the thread, lock and atomic census (that is the source scan in
//! `profile.rs`). Not a latency or CPU figure. The group is the two-member fixture; a larger group makes `step` allocate more
//! inside the session. **The step bound is still the formula written from the caps before any step cloned a session; it makes no
//! allowance for the copy a durable step runs on or for the journal's compaction, and no estimate of either is admitted here.**
//! The durable-step figures are reported with their components (`N02-HEAP-DURABLE-OBSERVED`) and judged against that unchanged
//! formula; a figure over it is a finding about the formula, to be read, and is never answered by retuning a number after the
//! run. The numbers are as provisional as the caps they come from. The RAM medium is not a flash part: nothing here says
//! anything about wear, and the write rate is not admitted by this test.
//!
//! **The relative path.** The flood above is absolute commands and mutes; it never reserves a floor. The second flood
//! ([`the_durable_step_with_sixteen_identities_reserving_floors_over_a_full_journal_is_measured`]) issues **relative** commands
//! from sixteen admitted identities, one accepted step each, over a journal loaded to the device limits, so that the floors
//! record grows to its sixteen-identity size (226 bytes) and every step writes it and the mark, and the journal compacts a
//! snapshot of the largest size its limits allow again and again. It then restores the floors and the mark from the medium
//! through the restore calls and compares them with what the running channel held.
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::hint::black_box;

use franken_alloc_probe::{CountingAllocator, heap_is_tracked, live_bytes, measure_heap};
use franken_board_profile::synthetic_test_fixture_catalog;
use franken_control::channel::diag::{ChannelLog, LogConfig, LogKey};
use franken_control::channel::endpoint::{Endpoint, Handled};
use franken_control::channel::limiter::RateLimit;
use franken_control::channel::peer::{
    AuthFailure, AuthProof, Authenticated, MAX_PEER_ID_LEN, MAX_PEERS, MAX_PROOF_LEN,
    PeerAuthority, PeerDirectory, PeerId, PeerRole, ReplySigner, compute_proof,
};
use franken_control::channel::pipeline::{
    ChannelConfig, ControlChannel, MAX_PENDING_REJECTS, MemoryJournalStepper, Outcome, Restored,
    RestoredFloors, Stepper, restore_from_open, restore_seq_floors_from_open,
};
use franken_control::channel::request::{
    AckBody, AckRequest, ControlCommand, ControlRequest, MAX_MEMBER_ID_LEN, RequestBody,
};
use franken_control::channel::wire::{MAX_DATAGRAM_LEN, encode_ack, encode_request};
use franken_control::contracts::secret_store::{
    Generation, MAX_SECRETS, SecretError, SecretHandle, SecretMeta, SecretStore, SecretValue,
};
use franken_session::{
    AuthorityToken, COMMAND_DEDUP_WINDOW, ChannelRole, FencedControlCommand, GroupCommandPayload,
    UnifiedGroupSession,
};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator::new();

const EPOCH: u64 = 10;
const MS: u64 = 1_000_000;

// ------------------------------------------------------------------------------------------------ the bound, from the caps

/// The heap one authenticated request can own: the authenticated identity and the body's peer id, a member id and a proof, each
/// at its limit.
const REQUEST_HEAP: usize = 2 * MAX_PEER_ID_LEN + MAX_MEMBER_ID_LEN + MAX_PROOF_LEN;
/// Bytes a stored record carries beyond its request: times, the outcome and the second copy of its key.
const RECORD_EXTRA: usize = 64;
/// Bytes a per-peer table row carries beyond its key.
const ROW_EXTRA: usize = 64;
/// Bytes a log record carries beyond its line in the ring.
const LOG_ROW: usize = 64;
/// Bytes of fixed state the bound allows beyond its structures (the session's bounded set churning a tree node, counters).
const FIXED_SLACK: usize = 4_096;
/// How many request-sized units one `handle` may hold at its peak: decode, the clone the endpoint submits, the bytes the proof
/// covers, a log line, the reply's body, tag, signing bytes and wire bytes, and one container growing (a new block counted
/// before the old one is released).
const UNIT_COPIES: usize = 24;

/// What a record of a queue, the ledger or the pending rejections can hold: the inline authenticated identity and request, the
/// heap they can own and the fixed extras, doubled for container slack (a queue's spare capacity, a tree node's header).
fn record() -> usize {
    2 * (size_of::<Authenticated>() + size_of::<ControlRequest>() + RECORD_EXTRA + REQUEST_HEAP)
}

/// A row of the rate buckets or the ledger floors: a peer id (inline and at its limit) and the fixed extras, doubled.
fn peer_row() -> usize {
    2 * (size_of::<PeerId>() + MAX_PEER_ID_LEN + ROW_EXTRA)
}

/// One request-sized unit: the longest datagram, the inline identity and request, and the heap a request can own.
fn unit() -> usize {
    MAX_DATAGRAM_LEN + size_of::<Authenticated>() + size_of::<ControlRequest>() + REQUEST_HEAP
}

/// Everything a run is configured by, and so everything the bound is written from.
struct Caps {
    config: ChannelConfig,
    log_records: usize,
    log_bytes: usize,
    ops: u64,
}

fn caps_provisional() -> Caps {
    let mut config = ChannelConfig::provisional();
    config.ordinary_rate = RateLimit::new(100_000, MS).expect("a rate limit");
    config.priority_rate = RateLimit::new(100_000, MS).expect("a rate limit");
    config.session_seq_base = 1_000;
    Caps {
        config,
        log_records: 64,
        log_bytes: 16_384,
        ops: 6_000,
    }
}

/// A channel a fraction of the size: the bound has to shrink with the caps, and the channel has to fit the smaller bound.
fn caps_small() -> Caps {
    let mut caps = caps_provisional();
    caps.config.ordinary_capacity = 4;
    caps.config.priority_shared_capacity = 1;
    caps.config.priority_local_reserved = 1;
    caps.config.ledger_capacity = 8;
    caps.config.max_per_step = 2;
    caps.log_records = 8;
    caps.log_bytes = 2_048;
    caps.ops = 2_000;
    caps
}

struct Bounds {
    /// The most live heap one `handle` may hold above where it started.
    datagram: usize,
    /// The same for one `step`.
    step: usize,
    /// The most live heap, above the start of the run, at any moment between operations.
    retained: usize,
    /// How far the lowest retained level of the last quarter may sit above the lowest of the third.
    growth_slack: usize,
}

impl Bounds {
    fn of(caps: &Caps) -> Self {
        let cfg = &caps.config;
        let queues =
            cfg.ordinary_capacity + cfg.priority_shared_capacity + cfg.priority_local_reserved;
        // Queued commands, remembered outcomes, and requests turned away that wait for the log, one record each.
        let records = record() * (queues + cfg.ledger_capacity + MAX_PENDING_REJECTS);
        // The rate buckets (a peer in each of two lanes) and the ledger floors (a peer once).
        let rows = peer_row() * 3 * MAX_PEERS;
        // The log ring: its byte cap, doubled for spare string capacity, and a row per record.
        let log = 2 * caps.log_bytes + caps.log_records * LOG_ROW;
        Self {
            datagram: UNIT_COPIES * unit(),
            step: (cfg.max_per_step + 1) * UNIT_COPIES * unit(),
            retained: records + rows + log + FIXED_SLACK,
            growth_slack: 2 * record(),
        }
    }
}

// ----------------------------------------------------------------------------------------------------------- the verdict

/// What one run saw.
struct Run {
    datagram_peak: usize,
    step_peak: usize,
    /// The retained level after each operation, relative to just before the first.
    retained: Vec<isize>,
    /// The most the diagnostics ever showed in the ledger and the ordinary queue, to show the caps were reached.
    ledger_len: usize,
    ordinary_pending: usize,
}

impl Run {
    fn with_capacity(ops: u64) -> Self {
        Self {
            datagram_peak: 0,
            step_peak: 0,
            retained: Vec::with_capacity(usize::try_from(ops).expect("fits")),
            ledger_len: 0,
            ordinary_pending: 0,
        }
    }

    fn highest(&self) -> isize {
        self.retained.iter().copied().max().unwrap_or(0)
    }
}

fn floor_of(levels: &[isize]) -> isize {
    levels.iter().copied().min().unwrap_or(0)
}

/// `Err("HEAP: ...")` naming the first check the run breaks, `Ok` if it breaks none. The checks are taken in the order retained
/// level, growth, datagram peak, step peak, so that a channel that keeps what it is given is reported as keeping it: its own
/// container growing (a doubling `Vec` of copies) also spikes one `handle`, and that is a second symptom of the same leak.
fn verdict(run: &Run, bounds: &Bounds) -> Result<(), String> {
    let retained_bound = isize::try_from(bounds.retained).expect("fits");
    if let Some((index, level)) = run
        .retained
        .iter()
        .enumerate()
        .find(|(_, level)| **level > retained_bound)
    {
        return Err(format!(
            "HEAP: retained {level} bytes after operation {}, the bound is {retained_bound}",
            index + 1
        ));
    }
    let n = run.retained.len();
    let third = floor_of(&run.retained[n / 2..3 * n / 4]);
    let fourth = floor_of(&run.retained[3 * n / 4..]);
    let slack = isize::try_from(bounds.growth_slack).expect("fits");
    if fourth > third + slack {
        return Err(format!(
            "HEAP: still growing: the lowest retained level of the last quarter is {fourth}, of the third quarter {third}, the slack is {slack}"
        ));
    }
    if run.datagram_peak > bounds.datagram {
        return Err(format!(
            "HEAP: a datagram peaked at {} bytes above its start, the bound is {}",
            run.datagram_peak, bounds.datagram
        ));
    }
    if run.step_peak > bounds.step {
        return Err(format!(
            "HEAP: a step peaked at {} bytes above its start, the bound is {}",
            run.step_peak, bounds.step
        ));
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------------------- the rig

/// An in-memory secret store for the real `PeerDirectory` (the library's own is test-only and not visible from here).
#[derive(Default)]
struct MapStore {
    entries: BTreeMap<SecretHandle, (Generation, SecretValue)>,
}

impl SecretStore for MapStore {
    fn insert(
        &mut self,
        handle: &SecretHandle,
        value: SecretValue,
    ) -> Result<Generation, SecretError> {
        if self.entries.contains_key(handle) {
            return Err(SecretError::AlreadyExists {
                handle: handle.clone(),
            });
        }
        if self.entries.len() >= MAX_SECRETS {
            return Err(SecretError::StoreFull { max: MAX_SECRETS });
        }
        self.entries
            .insert(handle.clone(), (Generation::FIRST, value));
        Ok(Generation::FIRST)
    }

    fn replace(
        &mut self,
        handle: &SecretHandle,
        value: SecretValue,
        expected: Generation,
    ) -> Result<Generation, SecretError> {
        let entry = self
            .entries
            .get_mut(handle)
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })?;
        if entry.0 != expected {
            return Err(SecretError::StaleGeneration {
                handle: handle.clone(),
                expected: expected.get(),
                actual: entry.0.get(),
            });
        }
        let next = entry
            .0
            .successor()
            .ok_or_else(|| SecretError::GenerationExhausted {
                handle: handle.clone(),
            })?;
        entry.1 = value;
        entry.0 = next;
        Ok(next)
    }

    fn remove(&mut self, handle: &SecretHandle) -> Result<(), SecretError> {
        self.entries
            .remove(handle)
            .map(|_| ())
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })
    }

    fn generation(&self, handle: &SecretHandle) -> Result<Generation, SecretError> {
        self.entries
            .get(handle)
            .map(|entry| entry.0)
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })
    }

    fn with_secret<R>(
        &self,
        handle: &SecretHandle,
        f: impl FnOnce(Generation, &[u8]) -> R,
    ) -> Result<R, SecretError> {
        let entry = self
            .entries
            .get(handle)
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })?;
        Ok(f(entry.0, entry.1.expose()))
    }

    fn list(&self) -> Vec<SecretMeta> {
        self.entries
            .iter()
            .map(|(handle, entry)| SecretMeta {
                handle: handle.clone(),
                generation: entry.0,
                byte_len: entry.1.byte_len(),
            })
            .collect()
    }
}

/// A deterministic key for `peer`, long enough to be admitted. A fixture, not a secret.
fn key(peer: &str) -> Vec<u8> {
    format!("key-{peer}-0123456789abcdef").into_bytes()
}

/// The three peers of the cap census: two controllers bound to the epoch and the local user.
fn directory() -> PeerDirectory<MapStore> {
    let mut peers = PeerDirectory::with_store(MapStore::default());
    for (name, role, bound) in [
        ("ctl-a", PeerRole::Controller, Some(EPOCH)),
        ("ctl-b", PeerRole::Controller, Some(EPOCH)),
        ("panel", PeerRole::LocalUser, None),
    ] {
        let id = PeerId::parse(name).expect("a peer id");
        peers
            .admit(&id, role, &key(name), bound, 1)
            .expect("an admission");
    }
    peers
}

/// The two-member fixture session, then enough applied commands to fill its own bounded dedup window, so that the session's
/// memory is at its steady state before the first measured operation.
fn saturated_session() -> UnifiedGroupSession {
    let catalog = synthetic_test_fixture_catalog();
    let board = |model: &str| {
        catalog
            .iter()
            .find(|p| p.model_number == model)
            .expect("the fixture catalog has this model")
            .clone()
    };
    let mut session = UnifiedGroupSession::new("grp", "coord", EPOCH);
    for (seq, member, model) in [(1, "kitchen", "S5"), (2, "den", "S12")] {
        session
            .apply_command(FencedControlCommand {
                epoch: EPOCH,
                command_seq: seq,
                payload: GroupCommandPayload::AdmitMember {
                    member_id: member.to_string(),
                    board: board(model),
                    role: ChannelRole::Stereo,
                },
            })
            .expect("a fixture member is admissible");
    }
    let window = u64::try_from(COMMAND_DEDUP_WINDOW).expect("fits");
    for seq in 3..3 + window + 8 {
        session
            .apply_command(FencedControlCommand {
                epoch: EPOCH,
                command_seq: seq,
                payload: GroupCommandPayload::SetGroupVolume {
                    volume_0_to_100: 50,
                },
            })
            .expect("a fixture command applies");
    }
    session
}

fn request(peer: &str, seq: u64, revision: Option<u64>, command: ControlCommand) -> Vec<u8> {
    let id = PeerId::parse(peer).expect("a peer id");
    let body = RequestBody::new(id, seq, EPOCH, revision, command).expect("a valid request");
    let proof = compute_proof(&key(peer), &body.signing_bytes());
    encode_request(&ControlRequest::new(body, proof)).expect("an encodable request")
}

fn acknowledgement(seq: u64) -> Vec<u8> {
    let id = PeerId::parse("ctl-a").expect("a peer id");
    let body = AckBody::new(id, seq, EPOCH).expect("a valid acknowledgement");
    let proof = compute_proof(&key("ctl-a"), &body.signing_bytes());
    encode_ack(&AckRequest::new(body, proof)).expect("an encodable acknowledgement")
}

/// Drive the flood through the real endpoint and channel over `authority`, measuring each datagram, each step and the retained
/// level after every operation. Everything the driver allocates is dropped before the level is read.
fn flood<A: PeerAuthority + ReplySigner>(authority: A, caps: &Caps) -> Run {
    let mut session = saturated_session();
    let mut channel = ControlChannel::new(authority, caps.config).expect("a valid configuration");
    channel.enable_log(ChannelLog::new(
        LogConfig::new("run-1", "heap", caps.log_records, caps.log_bytes).expect("a log"),
        LogKey::new([7; 32]),
    ));
    channel
        .install_lease(&session, AuthorityToken::issue(&session, 1_000_000 * MS), 0)
        .expect("a lease");
    let mut endpoint = Endpoint::new();
    // The journal the steps go through is made before the baseline: its memory is fixed, and it is not the channel's.
    let mut stepper = MemoryJournalStepper::new();
    // The sample list is made before the baseline, so recording a sample never allocates.
    let mut run = Run::with_capacity(caps.ops);
    let baseline = live_bytes();
    let mut now = 0u64;
    for i in 1..=caps.ops {
        now += 10 * MS;
        let revision = Some(session.state_revision);
        let volume = 40 + u8::try_from(i % 50).expect("under fifty");
        let command = ControlCommand::SetGroupVolume { volume };
        let (forged, bytes) = match i % 4 {
            0 => (true, request(&format!("x{i}"), i, revision, command)),
            1 => (false, request("ctl-a", i, revision, command)),
            2 => (false, request("ctl-b", i, revision, command)),
            _ => {
                let mute = ControlCommand::SetMemberMute {
                    member_id: "kitchen".to_string(),
                    muted: i % 2 == 0,
                };
                (false, request("panel", i, None, mute))
            }
        };
        let (handled, window) =
            measure_heap(|| endpoint.handle(&mut channel, now, &session, &bytes));
        run.datagram_peak = run.datagram_peak.max(window.peak_above_start);
        let as_expected = match &handled {
            Handled::Request { reply, .. } => reply.is_none() == forged,
            _ => false,
        };
        assert!(as_expected, "datagram {i}: unexpected {handled:?}");
        drop(handled);
        drop(bytes);
        if i % 7 == 0 {
            let (settled, window) = measure_heap(|| {
                stepper
                    .step(&mut channel, now, &mut session)
                    .expect("a step over a healthy journal")
            });
            run.step_peak = run.step_peak.max(window.peak_above_start);
            drop(settled);
        }
        if i % 11 == 0 {
            let bytes = acknowledgement(i / 2 + 1);
            let (handled, window) =
                measure_heap(|| endpoint.handle(&mut channel, now, &session, &bytes));
            run.datagram_peak = run.datagram_peak.max(window.peak_above_start);
            assert!(
                matches!(handled, Handled::Ack(_)),
                "acknowledgement {i}: unexpected {handled:?}"
            );
            drop(handled);
            drop(bytes);
        }
        run.retained.push(live_bytes() - baseline);
        let seen = channel.diagnostics(&session);
        run.ledger_len = run.ledger_len.max(seen.ledger_len);
        run.ordinary_pending = run.ordinary_pending.max(seen.ordinary_pending);
    }
    run
}

// ------------------------------------------------------------------------------------------------------------- the plants

/// A channel whose authority keeps a copy of every message it verifies, forged ones included: the leak the bound exists for.
struct Retaining<A> {
    inner: A,
    kept: RefCell<Vec<Vec<u8>>>,
}

impl<A> Retaining<A> {
    fn new(inner: A) -> Self {
        Self {
            inner,
            kept: RefCell::new(Vec::new()),
        }
    }
}

impl<A: PeerAuthority> PeerAuthority for Retaining<A> {
    fn authenticate(
        &self,
        peer: &PeerId,
        message: &[u8],
        proof: &AuthProof,
    ) -> Result<Authenticated, AuthFailure> {
        self.kept.borrow_mut().push(message.to_vec());
        self.inner.authenticate(peer, message, proof)
    }

    fn is_current(&self, auth: &Authenticated) -> bool {
        self.inner.is_current(auth)
    }
}

impl<A: ReplySigner> ReplySigner for Retaining<A> {
    fn sign_reply(&self, peer: &PeerId, message: &[u8]) -> Option<AuthProof> {
        self.inner.sign_reply(peer, message)
    }
}

/// A channel whose authority takes a large scratch buffer for every message and gives it back: it retains nothing, and no single
/// request-sized unit is that large.
struct Hungry<A> {
    inner: A,
}

const SCRATCH: usize = 256 * 1024;

impl<A: PeerAuthority> PeerAuthority for Hungry<A> {
    fn authenticate(
        &self,
        peer: &PeerId,
        message: &[u8],
        proof: &AuthProof,
    ) -> Result<Authenticated, AuthFailure> {
        drop(black_box(vec![0u8; SCRATCH]));
        self.inner.authenticate(peer, message, proof)
    }

    fn is_current(&self, auth: &Authenticated) -> bool {
        self.inner.is_current(auth)
    }
}

impl<A: ReplySigner> ReplySigner for Hungry<A> {
    fn sign_reply(&self, peer: &PeerId, message: &[u8]) -> Option<AuthProof> {
        self.inner.sign_reply(peer, message)
    }
}

// ------------------------------------------------------------------------------------------------------------- the tests

fn observed(label: &str, run: &Run, bounds: &Bounds) {
    let n = run.retained.len();
    println!(
        "N02-HEAP-OBSERVED {{\"run\":\"{label}\",\"ops\":{n},\"datagram_peak\":{},\"step_peak\":{},\"retained_highest\":{},\"retained_floor_third\":{},\"retained_floor_fourth\":{},\"ledger_len\":{},\"ordinary_pending\":{},\"bound_datagram\":{},\"bound_step\":{},\"bound_retained\":{},\"growth_slack\":{}}}",
        run.datagram_peak,
        run.step_peak,
        run.highest(),
        floor_of(&run.retained[n / 2..3 * n / 4]),
        floor_of(&run.retained[3 * n / 4..]),
        run.ledger_len,
        run.ordinary_pending,
        bounds.datagram,
        bounds.step,
        bounds.retained,
        bounds.growth_slack,
    );
}

#[test]
fn the_heap_probe_is_installed_and_the_flood_measures_something_at_every_cap() {
    assert!(
        heap_is_tracked(),
        "the counting allocator is not this binary's allocator, so every figure below would be zero"
    );
    let caps = caps_provisional();
    let run = flood(directory(), &caps);
    assert!(
        run.datagram_peak > 0,
        "a datagram allocated nothing, so nothing was measured"
    );
    assert!(
        run.step_peak > 0,
        "a step allocated nothing, so nothing was measured"
    );
    assert!(
        run.highest() > 1_024,
        "the channel retained under a kilobyte after six thousand operations, so the retained level is not seeing it: {}",
        run.highest()
    );
    // The caps were actually reached, so the bound is checked against a channel that is full.
    assert_eq!(run.ledger_len, caps.config.ledger_capacity);
    assert_eq!(run.ordinary_pending, caps.config.ordinary_capacity);
}

#[test]
fn the_real_channel_stays_within_the_heap_bound_and_the_heap_does_not_grow_with_the_requests_served()
 {
    let caps = caps_provisional();
    let bounds = Bounds::of(&caps);
    let run = flood(directory(), &caps);
    observed("provisional", &run, &bounds);
    assert!(
        run.datagram_peak > 0 && run.step_peak > 0,
        "nothing was measured"
    );
    assert_eq!(verdict(&run, &bounds), Ok(()));
}

#[test]
fn the_same_bound_written_from_small_caps_is_smaller_and_a_small_channel_fits_it() {
    let (big, small) = (caps_provisional(), caps_small());
    let (big_bounds, small_bounds) = (Bounds::of(&big), Bounds::of(&small));
    assert!(small_bounds.retained < big_bounds.retained);
    assert!(small_bounds.step < big_bounds.step);
    assert_eq!(
        small_bounds.datagram, big_bounds.datagram,
        "one datagram is the same size in either channel"
    );
    let run = flood(directory(), &small);
    observed("small", &run, &small_bounds);
    assert!(
        run.datagram_peak > 0 && run.step_peak > 0,
        "nothing was measured"
    );
    assert_eq!(run.ledger_len, small.config.ledger_capacity);
    assert_eq!(run.ordinary_pending, small.config.ordinary_capacity);
    assert_eq!(verdict(&run, &small_bounds), Ok(()));
}

#[test]
fn a_channel_that_retains_every_request_breaks_the_retained_bound_by_name() {
    let caps = caps_provisional();
    let bounds = Bounds::of(&caps);
    // The real channel passes first, so the failure below is the check seeing the plant.
    assert_eq!(verdict(&flood(directory(), &caps), &bounds), Ok(()));
    let leaking = flood(Retaining::new(directory()), &caps);
    let verdict = verdict(&leaking, &bounds);
    assert!(
        verdict
            .as_ref()
            .is_err_and(|e| e.starts_with("HEAP: retained ")),
        "the retained bound did not catch a channel that keeps every message: {verdict:?} (highest {})",
        leaking.highest()
    );
}

#[test]
fn a_channel_that_allocates_a_large_scratch_per_request_breaks_the_datagram_peak_by_name() {
    let caps = caps_provisional();
    let bounds = Bounds::of(&caps);
    assert_eq!(verdict(&flood(directory(), &caps), &bounds), Ok(()));
    let hungry = flood(Hungry { inner: directory() }, &caps);
    assert!(
        hungry.highest() <= isize::try_from(bounds.retained).expect("fits"),
        "the plant retains nothing, so only the peak may break: {}",
        hungry.highest()
    );
    let verdict = verdict(&hungry, &bounds);
    assert!(
        verdict
            .as_ref()
            .is_err_and(|e| e.starts_with("HEAP: a datagram peaked ")),
        "the datagram peak did not catch a channel that takes {SCRATCH} bytes of scratch per message: {verdict:?}"
    );
}

#[test]
fn the_verdict_judges_each_check_on_its_own_and_lets_the_exact_bound_through() {
    let bounds = Bounds::of(&caps_provisional());
    let level = |value: usize| isize::try_from(value).expect("fits");
    let run = |retained: Vec<isize>, datagram_peak: usize, step_peak: usize| Run {
        datagram_peak,
        step_peak,
        retained,
        ledger_len: 0,
        ordinary_pending: 0,
    };
    let flat = || vec![1_000isize; 400];

    // Permitted: flat, and every figure exactly at its bound.
    assert_eq!(verdict(&run(flat(), 0, 0), &bounds), Ok(()));
    let mut at_bound = flat();
    at_bound[10] = level(bounds.retained);
    assert_eq!(
        verdict(&run(at_bound, bounds.datagram, bounds.step), &bounds),
        Ok(())
    );

    // Each check, alone.
    let starts = |verdict: Result<(), String>, prefix: &str| {
        verdict.as_ref().is_err_and(|e| e.starts_with(prefix))
    };
    assert!(starts(
        verdict(&run(flat(), bounds.datagram + 1, 0), &bounds),
        "HEAP: a datagram peaked "
    ));
    assert!(starts(
        verdict(&run(flat(), 0, bounds.step + 1), &bounds),
        "HEAP: a step peaked "
    ));
    let mut over = flat();
    over[10] = level(bounds.retained) + 1;
    assert!(starts(
        verdict(&run(over, 0, 0), &bounds),
        "HEAP: retained "
    ));

    // Growth with every level under the retained bound: the last quarter's floor sits above the third's by more than the slack.
    let mut growing = flat();
    for value in &mut growing[300..] {
        *value += level(bounds.growth_slack) + 1;
    }
    assert!(growing.iter().all(|v| *v <= level(bounds.retained)));
    assert!(starts(
        verdict(&run(growing, 0, 0), &bounds),
        "HEAP: still growing"
    ));
    // The same rise by exactly the slack is permitted, and so is a single high sample that falls back (a floor, not a spike).
    let mut within = flat();
    for value in &mut within[300..] {
        *value += level(bounds.growth_slack);
    }
    assert_eq!(verdict(&run(within, 0, 0), &bounds), Ok(()));
    let mut spike = flat();
    spike[350] = level(bounds.retained) - 1;
    assert_eq!(verdict(&run(spike, 0, 0), &bounds), Ok(()));
}

// ----------------------------------------------------------------------------------------- the relative path, sixteen identities

/// The sixteen identities of the full directory: fifteen controllers bound to the epoch and the local user.
fn directory_of_sixteen() -> (PeerDirectory<MapStore>, Vec<String>) {
    let mut peers = PeerDirectory::with_store(MapStore::default());
    let mut names = Vec::new();
    for i in 0..MAX_PEERS - 1 {
        let name = format!("ctl-{i:02}");
        let id = PeerId::parse(&name).expect("a peer id");
        peers
            .admit(&id, PeerRole::Controller, &key(&name), Some(EPOCH), 1)
            .expect("an admission");
        names.push(name);
    }
    let panel = PeerId::parse("panel").expect("a peer id");
    peers
        .admit(&panel, PeerRole::LocalUser, &key("panel"), None, 1)
        .expect("an admission");
    names.push("panel".to_string());
    assert_eq!(names.len(), MAX_PEERS);
    (peers, names)
}

/// What the relative flood saw, with the components a reader needs to judge it.
struct DurableRun {
    run: Run,
    rounds: u64,
    identities: usize,
    floor_record_bytes: usize,
    compactions: u64,
    frames: u64,
    /// The heap a copy of the saturated session holds above where the copy started, measured in this binary.
    session_copy_peak: usize,
    restored_identities: usize,
}

/// `rounds` times, each of the sixteen identities sends one relative command at the revision the session has now, the endpoint
/// handles it and one durable step applies it (so it reserves its floor, writes the floors record, applies on a copy of the
/// session, writes the mark and commits), all over a journal loaded to the device limits. Everything is measured as in `flood`.
fn relative_floor_flood(caps: &Caps, rounds: u64) -> DurableRun {
    let (authority, names) = directory_of_sixteen();
    let mut session = saturated_session();
    let mut channel = ControlChannel::new(authority, caps.config).expect("a valid configuration");
    channel.enable_log(ChannelLog::new(
        LogConfig::new("run-1", "heap", caps.log_records, caps.log_bytes).expect("a log"),
        LogKey::new([7; 32]),
    ));
    channel
        .install_lease(&session, AuthorityToken::issue(&session, 1_000_000 * MS), 0)
        .expect("a lease");
    let mut endpoint = Endpoint::new();
    // The journal is loaded before the baseline: its memory is fixed and it is not the channel's. It starts with every namespace
    // full, so each compaction writes the largest snapshot the limits allow.
    let mut stepper = MemoryJournalStepper::at_device_limits_occupancy();
    let mut run = Run::with_capacity(rounds * u64::try_from(names.len()).expect("fits"));
    // The component the staged step adds to the plain one, measured here and printed: the copy of the session.
    let (copy, window) = measure_heap(|| session.clone());
    let session_copy_peak = window.peak_above_start;
    drop(copy);
    let baseline = live_bytes();
    let mut now = 0u64;
    for round in 0..rounds {
        for (index, name) in names.iter().enumerate() {
            now += 10 * MS;
            let seq = round + 1;
            let delta = if (round + u64::try_from(index).expect("fits")) % 2 == 0 {
                1
            } else {
                -1
            };
            let command = ControlCommand::AdjustGroupVolume { delta };
            let bytes = request(name, seq, Some(session.state_revision), command);
            let (handled, window) =
                measure_heap(|| endpoint.handle(&mut channel, now, &session, &bytes));
            run.datagram_peak = run.datagram_peak.max(window.peak_above_start);
            assert!(
                matches!(&handled, Handled::Request { reply: Some(_), .. }),
                "{name} round {round}: unexpected {handled:?}"
            );
            drop(handled);
            drop(bytes);
            let (settled, window) = measure_heap(|| {
                stepper
                    .step(&mut channel, now, &mut session)
                    .expect("a step over a healthy journal")
            });
            run.step_peak = run.step_peak.max(window.peak_above_start);
            assert!(
                settled.len() == 1 && matches!(settled[0].outcome, Outcome::Committed { .. }),
                "{name} round {round}: the relative command did not commit: {settled:?}"
            );
            drop(settled);
            run.retained.push(live_bytes() - baseline);
            let seen = channel.diagnostics(&session);
            run.ledger_len = run.ledger_len.max(seen.ledger_len);
            run.ordinary_pending = run.ordinary_pending.max(seen.ordinary_pending);
        }
    }
    // What the running channel holds is what the medium holds, and a restart restores exactly that.
    let held = channel.seq_floors().encode();
    assert_eq!(stepper.stored_floors(), Some(held.as_slice()));
    assert_eq!(stepper.stored_mark(), Some(session.state_revision));
    let (fresh_authority, _) = directory_of_sixteen();
    let mut fresh =
        ControlChannel::new(fresh_authority, caps.config).expect("a valid configuration");
    let opened = stepper.reopen();
    assert_eq!(
        restore_from_open(&mut fresh, &opened),
        Ok(Restored::Mark(session.state_revision))
    );
    let restored_identities = match restore_seq_floors_from_open(&mut fresh, &opened) {
        Ok(RestoredFloors::Table { identities }) => identities,
        other => panic!("the floors were not restored: {other:?}"),
    };
    assert_eq!(fresh.seq_floors(), channel.seq_floors());
    DurableRun {
        run,
        rounds,
        identities: channel.seq_floors().len(),
        floor_record_bytes: held.len(),
        compactions: stepper.compactions(),
        frames: stepper.frames_written(),
        session_copy_peak,
        restored_identities,
    }
}

#[test]
fn the_durable_step_with_sixteen_identities_reserving_floors_over_a_full_journal_is_measured() {
    assert!(heap_is_tracked(), "the counting allocator is not installed");
    let caps = caps_provisional();
    let bounds = Bounds::of(&caps);
    let seen = relative_floor_flood(&caps, 40);
    let run = &seen.run;
    let n = run.retained.len();
    println!(
        "N02-HEAP-DURABLE-OBSERVED {{\"rounds\":{},\"steps\":{n},\"identities\":{},\"restored_identities\":{},\"floor_record_bytes\":{},\"frames\":{},\"compactions\":{},\"datagram_peak\":{},\"step_peak\":{},\"session_copy_peak\":{},\"step_peak_minus_session_copy\":{},\"retained_highest\":{},\"retained_floor_third\":{},\"retained_floor_fourth\":{},\"bound_datagram\":{},\"bound_step\":{},\"bound_retained\":{}}}",
        seen.rounds,
        seen.identities,
        seen.restored_identities,
        seen.floor_record_bytes,
        seen.frames,
        seen.compactions,
        run.datagram_peak,
        run.step_peak,
        seen.session_copy_peak,
        run.step_peak.saturating_sub(seen.session_copy_peak),
        run.highest(),
        floor_of(&run.retained[n / 2..3 * n / 4]),
        floor_of(&run.retained[3 * n / 4..]),
        bounds.datagram,
        bounds.step,
        bounds.retained,
    );
    // The traffic is what the test says it is: the floors record is full, it came back whole from the medium, the journal
    // compacted a full snapshot more than once, and every step was measured.
    assert_eq!(seen.identities, MAX_PEERS);
    assert_eq!(seen.restored_identities, MAX_PEERS);
    assert_eq!(seen.floor_record_bytes, 226);
    assert!(
        seen.compactions > 1,
        "the journal never compacted: {}",
        seen.compactions
    );
    assert!(
        run.step_peak > 0 && run.datagram_peak > 0,
        "nothing was measured"
    );
    assert!(
        seen.session_copy_peak > 0,
        "copying the saturated session allocated nothing, so the copy was not measured"
    );
    // The judgement is the same one every flood gets, against the formula written from the caps. A red here is a finding.
    assert_eq!(verdict(run, &bounds), Ok(()));
}
