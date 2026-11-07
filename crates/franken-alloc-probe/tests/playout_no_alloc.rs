//! Real allocator instrumentation: the N04 playout engine's consume path after construction (N04 section 14, item 4).
//!
//! The engine allocates once, in `PlayoutEngine::new` (its slots) and, if diagnostics are on, once in `enable_log` (its
//! ring). Everything after that, `begin_stream`, `on_packet`, `on_repair`, `decide`, `apply_change`,
//! `settle_delivery`, `advice`, `snapshot` and `drain_log`, must not touch the allocator at all: no allocation, no
//! reallocation, no free. This test measures that with the counting allocator over a seeded 400-block script (loss, jitter,
//! a 16-block burst, duplicates, a stale epoch, malformed input, a clock regression, an unusable clock, a repair that
//! lands and one that is late, a latency increase and a decrease, deliveries, and log drains into a sink that
//! sometimes says it is full), and it first proves the probe is live and that construction really is seen.
//!
//! What it shows is host allocation behaviour on the platform the test runs on. It says nothing about memory use or
//! timing on a board, and a build on another ISA would have to repeat it.
use franken_alloc_probe::{CountingAllocator, fail_next_allocation, is_active, measure};
use franken_stream::playout::{
    AdmitError, AllocationError, BLOCK_FRAMES, BLOCK_PAYLOAD_BYTES, ClockView, LatencyChange,
    LogConfig, LogSink, MediaPacket, PlayoutConfig, PlayoutEngine, PlayoutProfile, RepairBlock,
    SinkReply, consume_by, frames_to_ns,
};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator::new();

#[test]
fn n04_log_rate_admission_and_refusal_do_not_allocate() {
    assert!(
        is_active(),
        "the allocator sensor must see a real allocation"
    );
    let mut engine = PlayoutEngine::new(
        PlayoutProfile::MUSIC,
        PlayoutConfig {
            work_ns: WORK,
            lead_ns: LEAD,
            tolerance_ns: 100_000,
        },
    )
    .expect("valid engine");
    engine.enable_log(
        LogConfig::new(
            "rate",
            "probe",
            "p-0123456789abcdef",
            "p-fedcba9876543210",
            4,
        )
        .expect("valid log"),
    );
    let ((), delta) = measure(|| {
        for _ in 0..LogConfig::BURST_EVENTS_PER_CLASS + 10 {
            engine
                .begin_stream(1, 0, ANCHOR)
                .expect("a same-epoch start is permitted");
        }
    });
    assert!(
        delta.is_zero(),
        "rate admission/refusal allocated: {delta:?}"
    );
    assert_eq!(delta.bytes_requested, 0);
    let stats = engine.log_stats().expect("logging enabled");
    assert_eq!(stats.dropped_rate, 10);
    assert!(stats.accounted() && !stats.evidence_complete());
}

const ANCHOR: u64 = 2_000_000_000;
const WORK: u64 = 1_500_000;
const LEAD: u64 = 2_000_000;
const UNCERTAINTY: u64 = 200_000;
const BLOCKS: u64 = 400;
/// Effective blocks of the two latency changes: +3 blocks at 200, then -2 blocks at 300.
const INCREASE_AT: u64 = 200;
const DECREASE_AT: u64 = 300;
const INCREASE_NS: i128 = 15_999_999;
const DECREASE_NS: i128 = -10_666_666;

struct Rng(u64);

impl Rng {
    /// SplitMix64.
    fn draw(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.draw() % n
    }
}

/// Presentation time (group clock) of a block under the timeline in force for it: the increase and the decrease move
/// every block from their effective block on.
fn pres(block: u64) -> u64 {
    let mut origin = i128::from(ANCHOR);
    if block >= INCREASE_AT {
        origin += INCREASE_NS;
    }
    if block >= DECREASE_AT {
        origin += DECREASE_NS;
    }
    u64::try_from(origin + i128::from(frames_to_ns(block * BLOCK_FRAMES))).expect("positive time")
}

fn view(at: u64) -> ClockView {
    ClockView {
        group_ns: at,
        uncertainty_ns: UNCERTAINTY,
        usable: true,
    }
}

enum Op {
    Begin {
        epoch: u64,
        frame: u64,
        ns: u64,
    },
    Packet {
        view: ClockView,
        epoch: u64,
        frame: u64,
        pres: u64,
        frames: u32,
        bytes: usize,
    },
    Repair {
        view: ClockView,
        frame: u64,
        frames: u32,
        bytes: usize,
    },
    Decide(ClockView),
    Change(LatencyChange),
    Deliver {
        deadline: u64,
        at: Option<u64>,
    },
    Drain(usize),
    Advice,
    Snapshot,
}

struct Event {
    at: u64,
    seq: usize,
    op: Op,
}

fn push(events: &mut Vec<Event>, at: u64, op: Op) {
    let seq = events.len();
    events.push(Event { at, seq, op });
}

fn media(events: &mut Vec<Event>, at: u64, epoch: u64, block: u64, bytes: usize) {
    push(
        events,
        at,
        Op::Packet {
            view: view(at),
            epoch,
            frame: block * BLOCK_FRAMES,
            pres: pres(block),
            frames: 256,
            bytes,
        },
    );
}

/// The whole script, built before anything is measured (it allocates freely) and sorted by time.
fn script() -> Vec<Event> {
    let mut rng = Rng(0x4E30_3400_0000_0001);
    let mut events = Vec::new();
    push(
        &mut events,
        0,
        Op::Begin {
            epoch: 1,
            frame: 0,
            ns: ANCHOR,
        },
    );
    // Media: 8% lost, 5% duplicated, each arriving 30 ms before to 2 ms after its presentation (the cutoff is about
    // 3.7 ms before), and a 16-block burst lost outright.
    for block in 0..BLOCKS {
        let burst = (100..116).contains(&block);
        let lost = rng.below(100) < 8;
        let arrival = pres(block).saturating_sub(30_000_000) + rng.below(32_000_000);
        if !burst && !lost {
            media(&mut events, arrival, 1, block, 1024);
            if rng.below(100) < 5 {
                media(
                    &mut events,
                    arrival + 1 + rng.below(2_000_000),
                    1,
                    block,
                    1024,
                );
            }
        }
    }
    // Deliberate paths, so none depends on the seed.
    media(&mut events, pres(30) - 25_000_000, 1, 30, 1024); // a pair: the second is a duplicate
    media(&mut events, pres(30) - 24_900_000, 1, 30, 1024);
    media(&mut events, pres(60) - 10_000_000, 0, 60, 1024); // a stale epoch
    media(&mut events, pres(61) - 10_000_000, 1, 61, 10); // malformed: 10 bytes for 256 frames
    media(&mut events, pres(100) + 2_000_000, 1, 100, 1024); // after its cutoff, in the burst: late
    // A clock regression: one packet read at T - 100 sets the clock, the next claims T - 5 ms.
    let t = pres(70) - 10_000_000;
    media(&mut events, t - 100, 1, 70, 1024);
    push(
        &mut events,
        t,
        Op::Packet {
            view: view(t - 5_000_000),
            epoch: 1,
            frame: 70 * BLOCK_FRAMES,
            pres: pres(70),
            frames: 256,
            bytes: 1024,
        },
    );
    // An unusable clock.
    push(
        &mut events,
        pres(71) - 10_000_000,
        Op::Packet {
            view: ClockView {
                group_ns: pres(71) - 10_000_000,
                uncertainty_ns: 0,
                usable: false,
            },
            epoch: 1,
            frame: 71 * BLOCK_FRAMES,
            pres: pres(71),
            frames: 256,
            bytes: 1024,
        },
    );
    // Repairs: block 104 (in the burst) arrives in time; block 110 arrives after its cutoff.
    push(
        &mut events,
        pres(104) - 20_000_000,
        Op::Repair {
            view: view(pres(104) - 20_000_000),
            frame: 104 * BLOCK_FRAMES,
            frames: 256,
            bytes: 1024,
        },
    );
    push(
        &mut events,
        pres(110) + 1_000_000,
        Op::Repair {
            view: view(pres(110) + 1_000_000),
            frame: 110 * BLOCK_FRAMES,
            frames: 256,
            bytes: 1024,
        },
    );
    // Decisions in block order, each at or after its cutoff, never earlier than the one before; with the changes,
    // deliveries, advice, snapshots and log drains that go with them.
    let mut last = 0;
    for block in 0..BLOCKS + 4 {
        let cutoff = consume_by(pres(block), WORK, LEAD, UNCERTAINTY);
        let at = (cutoff + rng.below(300_000)).max(last + 1);
        last = at;
        push(&mut events, at, Op::Decide(view(at)));
        if block == INCREASE_AT - 50 {
            push(
                &mut events,
                at,
                Op::Change(LatencyChange {
                    epoch: 1,
                    change_id: 1,
                    effective_frame: INCREASE_AT * BLOCK_FRAMES,
                    new_anchor_ns: pres(INCREASE_AT),
                }),
            );
        }
        if block == DECREASE_AT - 50 {
            push(
                &mut events,
                at,
                Op::Change(LatencyChange {
                    epoch: 1,
                    change_id: 2,
                    effective_frame: DECREASE_AT * BLOCK_FRAMES,
                    new_anchor_ns: pres(DECREASE_AT),
                }),
            );
        }
        let deadline = pres(block).saturating_sub(LEAD);
        match block % 7 {
            0 => push(
                &mut events,
                at,
                Op::Deliver {
                    deadline,
                    at: Some(deadline),
                },
            ),
            3 => push(
                &mut events,
                at,
                Op::Deliver {
                    deadline,
                    at: Some(deadline + 1_000),
                },
            ),
            5 => push(&mut events, at, Op::Deliver { deadline, at: None }),
            _ => {}
        }
        if block % 5 == 4 {
            push(&mut events, at, Op::Drain(3));
        }
        if block % 10 == 9 {
            push(&mut events, at, Op::Snapshot);
        }
        if block % 20 == 19 {
            push(&mut events, at, Op::Advice);
        }
    }
    events.sort_by_key(|e| (e.at, e.seq));
    events
}

/// A sink that keeps what it counts and nothing else (it must not allocate, or the measurement would be of the sink).
/// Every fourth offer it says it is full.
struct CountingSink {
    calls: u64,
    taken: u64,
}

impl LogSink for CountingSink {
    fn offer(&mut self, line: &str) -> SinkReply {
        self.calls += 1;
        if self.calls.is_multiple_of(4) {
            SinkReply::Full
        } else {
            debug_assert!(!line.is_empty());
            self.taken += 1;
            SinkReply::Taken
        }
    }
}

fn run(eng: &mut PlayoutEngine, events: &[Event], payload: &[u8], sink: &mut dyn LogSink) {
    let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
    for event in events {
        match &event.op {
            Op::Begin { epoch, frame, ns } => {
                let _ = eng.begin_stream(*epoch, *frame, *ns);
            }
            Op::Packet {
                view,
                epoch,
                frame,
                pres,
                frames,
                bytes,
            } => {
                let packet = MediaPacket {
                    epoch: *epoch,
                    start_frame: *frame,
                    presentation_ns: *pres,
                    frames: *frames,
                    payload: &payload[..*bytes],
                };
                let _ = eng.on_packet(*view, &packet);
            }
            Op::Repair {
                view,
                frame,
                frames,
                bytes,
            } => {
                let block = RepairBlock {
                    epoch: 1,
                    start_frame: *frame,
                    frames: *frames,
                    payload: &payload[..*bytes],
                };
                let _ = eng.on_repair(*view, &block);
            }
            Op::Decide(view) => {
                let _ = eng.decide(*view, &mut out);
            }
            Op::Change(change) => {
                let _ = eng.apply_change(*change);
            }
            Op::Deliver { deadline, at } => {
                let _ = eng.settle_delivery(*deadline, *at);
            }
            Op::Drain(budget) => {
                eng.drain_log(sink, *budget);
            }
            Op::Advice => {
                let _ = eng.advice();
            }
            Op::Snapshot => {
                let _ = eng.snapshot();
            }
        }
    }
}

fn new_engine() -> PlayoutEngine {
    let cfg = PlayoutConfig {
        work_ns: WORK,
        lead_ns: LEAD,
        tolerance_ns: 100_000,
    };
    let mut eng = PlayoutEngine::new(PlayoutProfile::MUSIC, cfg).expect("valid config");
    let log = LogConfig::new(
        "n04-probe",
        "playout-no-alloc",
        "p-0123456789abcdef",
        "p-fedcba9876543210",
        64,
    )
    .expect("valid log config");
    eng.enable_log(log);
    eng
}

#[test]
fn n04_playout_engine_consume_path_does_not_allocate_after_construction() {
    assert!(
        is_active(),
        "the counting allocator must detect a real allocation"
    );
    let (_, control) = measure(|| std::hint::black_box(vec![0u8; 64]));
    assert!(
        control.allocations >= 1,
        "the probe must count a deliberate allocation: {control:?}"
    );

    // Construction is seen: the slots and the log ring are allocated here, and only here.
    let (mut eng, built) = measure(new_engine);
    assert!(
        built.allocations >= 2 && built.bytes_requested >= 150_000,
        "construction must be visible to the probe: {built:?}"
    );

    let events = script();
    let payload: Vec<u8> = (0..BLOCK_PAYLOAD_BYTES)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect();

    // A first run, unmeasured, on a twin: the script must reach every path it claims to (a measurement of a run that
    // never decided or dropped anything would be vacuous).
    let mut twin = new_engine();
    run(
        &mut twin,
        &events,
        &payload,
        &mut CountingSink { calls: 0, taken: 0 },
    );
    let s = *twin.stats();
    let log = twin.log_stats().expect("the log is on");
    let floors = [
        ("decided_real", s.decided_real > 50),
        ("decided_concealed", s.decided_concealed >= 8),
        ("decided_muted_gap", s.decided_muted_gap >= 1),
        ("decided_skipped", s.decided_skipped >= 1),
        ("late", s.late >= 1),
        ("late_repair", s.late_repair >= 1),
        ("admitted_repair", s.admitted_repair >= 1),
        ("duplicate", s.duplicate >= 1),
        ("stale_epoch", s.stale_epoch >= 1),
        ("bad_input", s.bad_input >= 1),
        ("clock_regressions", s.clock_regressions >= 1),
        ("clock_unusable", s.clock_unusable >= 1),
        ("changes_applied", s.changes_applied == 2),
        ("delivered", s.delivered >= 1),
        ("abandoned", s.abandoned >= 1),
        ("log_emitted", log.emitted >= 300),
        ("log_dropped", log.dropped() > 0),
        ("log_delivered", log.delivered > 0),
        ("log_sink_full", log.sink_full_polls > 0),
    ];
    let missed: Vec<&str> = floors.iter().filter(|f| !f.1).map(|f| f.0).collect();
    assert!(
        missed.is_empty(),
        "the script did not reach {missed:?}: {s:?} {log}"
    );

    // The measured run: same script, fresh engine, nothing allocated since construction.
    let mut sink = CountingSink { calls: 0, taken: 0 };
    let ((), delta) = measure(|| run(&mut eng, &events, &payload, &mut sink));
    assert!(
        delta.is_zero(),
        "the engine's consume path allocated after construction: {delta:?}"
    );
    assert_eq!(
        *eng.stats(),
        s,
        "the measured run is the run that was checked"
    );

    assert!(
        sink.calls > 0 && sink.taken > 0,
        "the sink was offered lines and took some"
    );

    // One JSON object, written by hand: this crate has no JSON dependency and the measurement must not need one.
    let (ops, control_allocations) = (events.len(), control.allocations);
    let (construction_allocations, construction_bytes) = (built.allocations, built.bytes_requested);
    let (allocations, reallocations, deallocations) =
        (delta.allocations, delta.reallocations, delta.deallocations);
    let decided = s.decided_real + s.decided_concealed + s.decided_muted_gap + s.decided_skipped;
    let log_emitted = log.emitted;
    println!(
        "N04-OBSERVED {{\"id\":\"n04-no-alloc\",\"probe_active\":true,\"control_allocations\":{control_allocations},\
         \"construction_allocations\":{construction_allocations},\"construction_bytes\":{construction_bytes},\
         \"measured\":{{\"allocations\":{allocations},\"reallocations\":{reallocations},\"deallocations\":{deallocations}}},\
         \"ops\":{ops},\"decided\":{decided},\"log_emitted\":{log_emitted},\"paths_reached\":true}}"
    );
}

#[test]
fn n04_playout_engine_refused_capacity_allocates_nothing() {
    assert!(
        is_active(),
        "the counting allocator must detect a real allocation"
    );
    let cfg = PlayoutConfig {
        work_ns: WORK,
        lead_ns: LEAD,
        tolerance_ns: 100_000,
    };
    let need = PlayoutEngine::resident_bytes(&PlayoutProfile::MUSIC);
    // Control: an admitted construction is seen, and requests at least the queue the profile states.
    let (admitted, built) = measure(|| PlayoutEngine::new_within(PlayoutProfile::MUSIC, cfg, need));
    assert!(admitted.is_ok());
    assert!(
        built.allocations >= 1
            && built.bytes_requested >= PlayoutProfile::MUSIC.playout_queue_bytes(),
        "an admitted construction must be visible to the probe: {built:?}"
    );
    // Refusals: one byte short, no budget, and an invalid configuration. None of them may touch the allocator at all.
    let bad = PlayoutConfig { work_ns: 0, ..cfg };
    for (label, config, budget) in [
        ("one byte short", cfg, need - 1),
        ("no budget", cfg, 0),
        ("invalid configuration", bad, usize::MAX),
    ] {
        let (refused, delta) =
            measure(|| PlayoutEngine::new_within(PlayoutProfile::MUSIC, config, budget));
        assert!(refused.is_err(), "{label}");
        assert!(delta.is_zero(), "{label}: a refusal allocated: {delta:?}");
        assert_eq!(delta.bytes_requested, 0, "{label}");
    }
}

#[test]
fn n04_playout_engine_allocator_failure_is_a_typed_refusal_and_the_permitted_allocation_succeeds() {
    assert!(
        is_active(),
        "the counting allocator must detect a real allocation"
    );
    let cfg = PlayoutConfig {
        work_ns: WORK,
        lead_ns: LEAD,
        tolerance_ns: 100_000,
    };
    let need = PlayoutEngine::resident_bytes(&PlayoutProfile::MUSIC);
    // Control: with a sufficient budget and no failure armed the engine is built, by a real allocation.
    let (built, delta) = measure(|| PlayoutEngine::new_within(PlayoutProfile::MUSIC, cfg, need));
    assert!(built.is_ok());
    assert!(delta.allocations >= 1, "{delta:?}");
    // The allocator refuses the slot queue: a typed refusal naming the bytes asked for, never an abort.
    let ((refused, fired), failed_delta) = measure(|| {
        fail_next_allocation(|| PlayoutEngine::new_within(PlayoutProfile::MUSIC, cfg, need))
    });
    assert!(fired, "the failure must have hit a real allocation");
    // Failed attempts are allocator activity too: the no-allocation oracle must never hide them.
    assert_eq!(failed_delta.allocations, 1, "{failed_delta:?}");
    assert_eq!(failed_delta.reallocations, 0, "{failed_delta:?}");
    assert_eq!(failed_delta.deallocations, 0, "{failed_delta:?}");
    assert_eq!(
        failed_delta.bytes_requested,
        PlayoutProfile::MUSIC.playout_queue_bytes(),
        "{failed_delta:?}"
    );
    assert!(!failed_delta.is_zero(), "{failed_delta:?}");
    assert!(matches!(
        refused,
        Err(AdmitError::Allocation(AllocationError { requested_bytes }))
            if requested_bytes == PlayoutProfile::MUSIC.playout_queue_bytes()
    ));
    // The failure was one-shot: the next permitted call succeeds again.
    assert!(PlayoutEngine::new_within(PlayoutProfile::MUSIC, cfg, need).is_ok());
    // A failure armed around code that never allocates proves nothing, and says so.
    let ((idle, fired_idle), idle_delta) = measure(|| fail_next_allocation(|| 1 + 1));
    assert_eq!(idle, 2);
    assert!(!fired_idle);
    assert!(idle_delta.is_zero(), "{idle_delta:?}");
    assert_eq!(idle_delta.bytes_requested, 0, "{idle_delta:?}");
}

#[test]
fn n04_playout_log_replacement_survives_an_allocator_failure_with_its_records() {
    assert!(
        is_active(),
        "the counting allocator must detect a real allocation"
    );
    let cfg = PlayoutConfig {
        work_ns: WORK,
        lead_ns: LEAD,
        tolerance_ns: 100_000,
    };
    let log = |capacity| {
        LogConfig::new(
            "n04-probe",
            "alloc",
            "p-0123456789abcdef",
            "p-fedcba9876543210",
            capacity,
        )
        .expect("valid log configuration")
    };
    let mut eng = PlayoutEngine::new(PlayoutProfile::MUSIC, cfg).expect("valid config");
    eng.enable_log(log(4));
    let _ = eng.begin_stream(1, 0, ANCHOR);
    let before = eng.log_stats().expect("diagnostics are on");
    assert!(before.queued >= 1, "{before:?}");
    let heap_before = eng.log_heap_bytes();
    let replacement = log(8);
    let budget = PlayoutEngine::log_heap_bytes_for(&replacement).expect("fits") + heap_before;
    // The allocator refuses the new ring: a typed refusal, and the old log runs on with its records.
    let (refused, fired) = fail_next_allocation(|| eng.enable_log_within(replacement, budget));
    assert!(fired, "the failure must have hit a real allocation");
    assert!(matches!(refused, Err(AdmitError::Allocation(_))));
    assert_eq!(eng.log_stats(), Some(before));
    assert_eq!(eng.log_heap_bytes(), heap_before);
    // Control: the same replacement with no failure is admitted (both logs fit while it is built) and replaces the log.
    eng.enable_log_within(log(8), budget)
        .expect("fits with both logs held");
    assert!(eng.log_heap_bytes() > heap_before);
}

#[test]
fn n04_log_config_labels_fault_and_clone_are_inline_even_at_the_label_limit() {
    assert!(
        is_active(),
        "the allocator must detect the positive allocation control"
    );
    let label_bytes = [b'x'; 64];
    let label = core::str::from_utf8(&label_bytes).expect("ASCII label");
    let too_long_bytes = [b'x'; 65];
    let too_long = core::str::from_utf8(&too_long_bytes).expect("ASCII label");
    let ((config, cloned), delta) = measure(|| {
        let config = LogConfig::new(label, label, "p-0123456789abcdef", "p-fedcba9876543210", 4)
            .expect("maximum labels are permitted")
            .with_fault(label)
            .expect("maximum fault is permitted");
        let cloned = config.clone();
        std::hint::black_box((config, cloned))
    });
    assert!(delta.is_zero(), "valid configuration allocated: {delta:?}");
    assert_eq!(delta.bytes_requested, 0);
    assert_eq!(config, cloned);
    assert_eq!(config.heap_bytes(), 0);
    assert_eq!(cloned.heap_bytes(), 0);
    let expected_debug = format!(
        "LogConfig {{ run_id: {label:?}, case_id: {label:?}, member_id: \"p-0123456789abcdef\", group_id: \"p-fedcba9876543210\", fault: Some({label:?}), capacity: 4, max_line: 1024 }}"
    );
    assert_eq!(
        format!("{config:?}"),
        expected_debug,
        "Debug retains the text representation"
    );

    let ((bad_run, bad_fault, replaced), delta) = measure(|| {
        (
            LogConfig::new(
                too_long,
                label,
                "p-0123456789abcdef",
                "p-fedcba9876543210",
                4,
            ),
            cloned.clone().with_fault(too_long),
            cloned.clone().with_fault("replacement"),
        )
    });
    assert!(
        delta.is_zero(),
        "validation or fault replacement allocated: {delta:?}"
    );
    assert_eq!(delta.bytes_requested, 0);
    assert!(matches!(
        bad_run,
        Err(franken_stream::playout::LogConfigError::InvalidLabel { field: "run_id" })
    ));
    assert!(matches!(
        bad_fault,
        Err(franken_stream::playout::LogConfigError::InvalidLabel { field: "fault" })
    ));
    assert_eq!(replaced.expect("valid replacement").heap_bytes(), 0);

    // Only the ring allocates, and a maximum-label configuration still admits the same bounded ring.
    let budget = PlayoutEngine::log_ring_bytes_for(&config).expect("ring size fits");
    assert_eq!(PlayoutEngine::log_heap_bytes_for(&config), Some(budget));
    let mut engine = PlayoutEngine::new(
        PlayoutProfile::MUSIC,
        PlayoutConfig {
            work_ns: WORK,
            lead_ns: LEAD,
            tolerance_ns: 100_000,
        },
    )
    .expect("valid engine");
    let (admitted, delta) = measure(|| engine.enable_log_within(config, budget));
    admitted.expect("the permitted ring still allocates and is admitted");
    assert!(
        delta.allocations >= 1,
        "ring allocation must remain visible: {delta:?}"
    );
    assert_eq!(engine.log_heap_bytes(), engine.log_ring_bytes());
    assert!(engine.log_heap_bytes() >= budget);
}

#[test]
fn n04_untrusted_route_hint_is_allocation_free_for_permitted_and_refused_wire() {
    use franken_stream::{
        AuthenticatedStreamPacket, MIN_DATAGRAM_BYTES, PacketKind, StreamFormat, StreamId,
        StreamKey, StreamReceiver, untrusted_route_hint,
    };

    assert!(
        is_active(),
        "the allocation probe must observe its positive control"
    );
    let key = StreamKey::from_bytes([0x42; 32]);
    let id = StreamId::new(19).expect("nonzero synthetic stream");
    let packet = AuthenticatedStreamPacket {
        stream_id: id,
        session_epoch: 1,
        seq: 7,
        kind: PacketKind::Media,
        format: StreamFormat::Pcm16BeStereo48k,
        flags: 0,
        start_frame: 0,
        presentation_time_ns: 100_000_000,
        consume_by_ns: 95_000_000,
        fec_group_id: 0,
        fec_index: 0,
        fec_group_size: 0,
        payload: vec![0; 4],
    };
    let wire = packet.encode_signed(&key).expect("valid signed media");
    let short = &wire[..MIN_DATAGRAM_BYTES - 1];
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 1;
    let ((permitted, truncated, malformed), delta) = measure(|| {
        (
            untrusted_route_hint(&wire),
            untrusted_route_hint(short),
            untrusted_route_hint(&bad_magic),
        )
    });
    assert!(delta.is_zero(), "routing hints allocated: {delta:?}");
    assert_eq!(delta.bytes_requested, 0);
    assert_eq!(
        permitted.expect("structural routing hint").stream_id,
        id.get()
    );
    assert!(truncated.is_err());
    assert!(malformed.is_err());
    let mut receiver = StreamReceiver::new(key, id, 1);
    assert_eq!(
        receiver.accept(&wire).expect("still requires admission"),
        packet
    );
}
