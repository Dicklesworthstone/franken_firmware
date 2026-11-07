//! Tests for the bounded compressed lookahead (`S03` / `ffw-mxt`, contract `docs/contracts/s03.md`).
//!
//! Every expectation is derived by hand from the contract; none was copied from running this code.
//! The scenarios use a 48 kHz rate, so one second is 48_000 frames and exactly 1_000_000_000 ns, and the
//! arithmetic is the contract's own: one second at 320 kbit/s is 40_000 bytes, at 96 kbit/s 12_000 bytes.
//! The same scenarios and the same seeded schedule run in an independent Python mirror, which is where
//! the schedule floors below come from.

use super::*;
use std::collections::BTreeSet;

const E1: SourceEpoch = SourceEpoch::new(1);
const E2: SourceEpoch = SourceEpoch::new(2);
const E3: SourceEpoch = SourceEpoch::new(3);
const E4: SourceEpoch = SourceEpoch::new(4);
const T0: TrackSerial = TrackSerial::new(0);
const T1: TrackSerial = TrackSerial::new(1);
const T2: TrackSerial = TrackSerial::new(2);
const T7: TrackSerial = TrackSerial::new(7);
/// Frames per second of the scenarios' rate.
const R: u64 = 48_000;
const RATE: u32 = 48_000;

/// The output domain of the scenarios' device session, and three that differ from it in one field each.
const DOM: OutputDomain = OutputDomain {
    session: 1,
    generation: 1,
    rate_hz: 48_000,
};
const OTHER_GENERATION: OutputDomain = OutputDomain {
    session: 1,
    generation: 2,
    rate_hz: 48_000,
};
const OTHER_SESSION: OutputDomain = OutputDomain {
    session: 2,
    generation: 1,
    rate_hz: 48_000,
};
const OTHER_RATE: OutputDomain = OutputDomain {
    session: 1,
    generation: 1,
    rate_hz: 44_100,
};
const ZERO_RATE: OutputDomain = OutputDomain {
    session: 1,
    generation: 1,
    rate_hz: 0,
};

/// 8 MiB of bytes, 300 s of media, 4096 chunks, 64 outstanding, a 5 s readiness threshold.
fn limits() -> LookaheadLimits {
    LookaheadLimits {
        max_bytes: 8 * 1024 * 1024,
        max_media_ms: 300_000,
        max_chunks: 4096,
        max_chunk_bytes: 262_144,
        max_outstanding: 64,
        ready_min_media_ms: 5_000,
    }
}

fn queue() -> LookaheadQueue {
    LookaheadQueue::new(limits(), E1, T0, 0).unwrap()
}

fn chunk_at_rate(
    epoch: SourceEpoch,
    track: TrackSerial,
    start_frame: u64,
    frames: u32,
    bytes: usize,
    rate_hz: u32,
) -> Chunk {
    Chunk {
        epoch,
        track,
        start_frame,
        frames,
        rate_hz,
        last_of_track: false,
        payload: vec![0xAB; bytes],
    }
}

fn chunk(
    epoch: SourceEpoch,
    track: TrackSerial,
    start_frame: u64,
    frames: u32,
    bytes: usize,
) -> Chunk {
    chunk_at_rate(epoch, track, start_frame, frames, bytes, RATE)
}

/// One second at 320 kbit/s in epoch 1, track 0, starting at second `sec`.
fn hi(sec: u64) -> Chunk {
    chunk(E1, T0, sec * R, RATE, 40_000)
}

/// One second at 96 kbit/s in epoch 1, track 0, starting at second `sec`.
fn lo(sec: u64) -> Chunk {
    chunk(E1, T0, sec * R, RATE, 12_000)
}

fn last_of_track(mut c: Chunk) -> Chunk {
    c.last_of_track = true;
    c
}

fn at_in(domain: OutputDomain, frame: u64) -> OutputPosition {
    OutputPosition { domain, frame }
}

fn at(frame: u64) -> OutputPosition {
    at_in(DOM, frame)
}

fn drained_in(domain: OutputDomain, tail_frame: u64, played_frame: u64) -> FenceOutcome {
    FenceOutcome::Drained {
        tail: at_in(domain, tail_frame),
        played: at_in(domain, played_frame),
    }
}

fn drained(tail_frame: u64, played_frame: u64) -> FenceOutcome {
    drained_in(DOM, tail_frame, played_frame)
}

fn flushed_in(domain: OutputDomain, waited_ticks: u64) -> FenceOutcome {
    FenceOutcome::FlushAcknowledged {
        domain,
        waited_ticks,
    }
}

fn flushed(waited_ticks: u64) -> FenceOutcome {
    flushed_in(DOM, waited_ticks)
}

fn timed_out(waited_ticks: u64) -> FenceOutcome {
    FenceOutcome::FlushTimedOut { waited_ticks }
}

/// Hand a chunk out and retire it as submitted, ending at output frame 480 of the scenarios' domain.
fn take(q: &mut LookaheadQueue) -> Handoff {
    let handoff = q.pop().unwrap().unwrap();
    q.retire(&handoff.ticket, Retirement::Submitted { end: at(480) })
        .unwrap();
    handoff
}

/// A device-session double. It answers the request it is given with the scripted outcome; a lying one
/// shifts the token or epoch it echoes. It records every request it was asked about.
struct Renderer {
    outcome: FenceOutcome,
    token_shift: u64,
    epoch_shift: u64,
    asked: Vec<FenceRequest>,
}

impl Renderer {
    fn new(outcome: FenceOutcome) -> Self {
        Self {
            outcome,
            token_shift: 0,
            epoch_shift: 0,
            asked: Vec::new(),
        }
    }

    fn lying_token(mut self, by: u64) -> Self {
        self.token_shift = by;
        self
    }

    fn lying_epoch(mut self, by: u64) -> Self {
        self.epoch_shift = by;
        self
    }
}

impl OutputFenceSource for Renderer {
    fn fence(&mut self, request: FenceRequest) -> OutputFence {
        self.asked.push(request);
        OutputFence {
            token: FenceToken::new(request.token.get() + self.token_shift),
            epoch: SourceEpoch::new(request.epoch.get() + self.epoch_shift),
            outcome: self.outcome,
        }
    }
}

/// A source that answers every request with one stored report, however stale.
struct Replay(OutputFence);

impl OutputFenceSource for Replay {
    fn fence(&mut self, _request: FenceRequest) -> OutputFence {
        self.0
    }
}

/// A queue that has handed one epoch-1 chunk out and retired it as submitted (so epoch 1 has output
/// that ends at frame 480 to fence), holds two more, and has begun a transition to epoch 2 at 60 s:
/// returns the queue and the fence request.
fn pending() -> (LookaheadQueue, FenceRequest) {
    let mut q = queue();
    for i in 0..3 {
        q.push(hi(i)).unwrap();
    }
    take(&mut q);
    let start = q.begin_transition(E2, T0, 60 * R).unwrap();
    (q, start.fence.unwrap())
}

// ---- the allowances

#[test]
fn limits_are_validated_and_the_ceilings_are_accepted() {
    assert_eq!(limits().validate(), Ok(()));
    let ceiling = LookaheadLimits {
        max_bytes: MAX_LOOKAHEAD_BYTES,
        max_media_ms: MAX_LOOKAHEAD_MEDIA_MS,
        max_chunks: MAX_LOOKAHEAD_CHUNKS,
        max_chunk_bytes: MAX_LOOKAHEAD_BYTES,
        max_outstanding: MAX_LOOKAHEAD_OUTSTANDING,
        ..limits()
    };
    assert_eq!(ceiling.validate(), Ok(()));
    let cases = [
        (
            "max_bytes",
            LookaheadLimits {
                max_bytes: 0,
                ..limits()
            },
        ),
        (
            "max_bytes",
            LookaheadLimits {
                max_bytes: MAX_LOOKAHEAD_BYTES + 1,
                ..limits()
            },
        ),
        (
            "max_media_ms",
            LookaheadLimits {
                max_media_ms: 0,
                ..limits()
            },
        ),
        (
            "max_media_ms",
            LookaheadLimits {
                max_media_ms: MAX_LOOKAHEAD_MEDIA_MS + 1,
                ..limits()
            },
        ),
        (
            "max_chunks",
            LookaheadLimits {
                max_chunks: 0,
                ..limits()
            },
        ),
        (
            "max_chunks",
            LookaheadLimits {
                max_chunks: MAX_LOOKAHEAD_CHUNKS + 1,
                ..limits()
            },
        ),
        (
            "max_chunk_bytes",
            LookaheadLimits {
                max_chunk_bytes: 0,
                ..limits()
            },
        ),
        (
            "max_chunk_bytes",
            LookaheadLimits {
                max_chunk_bytes: limits().max_bytes + 1,
                ..limits()
            },
        ),
        (
            "max_outstanding",
            LookaheadLimits {
                max_outstanding: 0,
                ..limits()
            },
        ),
        (
            "max_outstanding",
            LookaheadLimits {
                max_outstanding: MAX_LOOKAHEAD_OUTSTANDING + 1,
                ..limits()
            },
        ),
        (
            "ready_min_media_ms",
            LookaheadLimits {
                ready_min_media_ms: 300_001,
                ..limits()
            },
        ),
    ];
    for (field, bad) in cases {
        assert_eq!(
            bad.validate(),
            Err(LookaheadError::InvalidLimits { field }),
            "{field}"
        );
    }
    let refused = LookaheadQueue::new(
        LookaheadLimits {
            max_bytes: 0,
            ..limits()
        },
        E1,
        T0,
        0,
    );
    assert_eq!(refused.unwrap_err().code(), "LOOKAHEAD_INVALID_LIMITS");
}

#[test]
fn bytes_time_and_chunks_are_accounted_separately_and_the_fetch_position_follows() {
    let mut q = queue();
    q.push(hi(0)).unwrap();
    q.push(chunk(E1, T0, R, 24_000, 20_000)).unwrap();
    q.push(chunk(E1, T0, R + 24_000, RATE, 12_000)).unwrap();
    let s = q.stats();
    assert_eq!((s.bytes, s.media_ns, s.chunks), (72_000, 2_500_000_000, 3));
    assert_eq!((s.accepted_chunks, s.accepted_bytes), (3, 72_000));
    assert_eq!(q.fetch_position(), (T0, 120_000));
    let first = q.pop().unwrap().unwrap();
    assert_eq!(
        (first.chunk.start_frame, first.chunk.payload.len()),
        (0, 40_000)
    );
    let s = q.stats();
    assert_eq!((s.bytes, s.media_ns, s.chunks), (32_000, 1_500_000_000, 2));
    assert_eq!(
        q.fetch_position(),
        (T0, 120_000),
        "popping does not move the fetch position"
    );
    assert_eq!(q.pop().unwrap().unwrap().chunk.start_frame, R);
    assert_eq!(q.pop().unwrap().unwrap().chunk.start_frame, R + 24_000);
    assert_eq!(q.pop().unwrap(), None);
    let s = q.stats();
    assert_eq!((s.bytes, s.media_ns, s.chunks), (0, 0, 0));
}

#[test]
fn the_byte_cap_binds_first_at_320_kbit_and_exactly_the_cap_is_accepted() {
    let mut q = queue();
    for i in 0..209 {
        q.push(hi(i)).unwrap();
    }
    assert_eq!(
        (q.stats().bytes, q.stats().media_ns),
        (8_360_000, 209_000_000_000)
    );
    // 715 ms is 34_320 frames; 28_608 more bytes land exactly on 8 MiB
    q.push(chunk(E1, T0, 209 * R, 34_320, 28_608)).unwrap();
    assert_eq!(q.stats().bytes, limits().max_bytes);
    assert_eq!(q.stats().media_ns, 209_715_000_000);
    assert!(
        q.stats().media_ns < limits().max_media_ms * 1_000_000,
        "the time cap is nowhere near"
    );
    let before = q.stats();
    let next_start = 209 * R + 34_320;
    let over = chunk(E1, T0, next_start, 240, 100);
    assert_eq!(
        q.push(over),
        Err(LookaheadError::Full {
            cap: CapKind::Bytes
        })
    );
    assert_eq!(
        q.stats(),
        LookaheadStats {
            refused_full: 1,
            ..before
        }
    );
    assert_eq!(q.fetch_position(), (T0, next_start));
}

#[test]
fn the_time_cap_binds_first_at_96_kbit_with_the_same_byte_allowance() {
    let mut q = queue();
    for i in 0..300 {
        q.push(lo(i)).unwrap();
    }
    let s = q.stats();
    assert_eq!(
        (s.media_ns, s.bytes, s.chunks),
        (300_000_000_000, 3_600_000, 300)
    );
    assert!(s.bytes < limits().max_bytes, "the byte cap is nowhere near");
    assert_eq!(
        q.push(lo(300)),
        Err(LookaheadError::Full {
            cap: CapKind::MediaMs
        })
    );
    // handing one second out reopens exactly one second
    q.pop().unwrap().unwrap();
    q.push(lo(300)).unwrap();
    assert_eq!(q.stats().media_ns, 300_000_000_000);
}

#[test]
fn the_chunk_count_cap_binds_on_its_own() {
    let tight = LookaheadLimits {
        max_chunks: 3,
        ..limits()
    };
    let mut q = LookaheadQueue::new(tight, E1, T0, 0).unwrap();
    for i in 0..3 {
        q.push(lo(i)).unwrap();
    }
    assert_eq!(
        q.push(lo(3)),
        Err(LookaheadError::Full {
            cap: CapKind::Chunks
        })
    );
    q.pop().unwrap().unwrap();
    q.push(lo(3)).unwrap();
    assert_eq!(q.stats().chunks, 3);
}

#[test]
fn variable_bit_rate_chunks_and_bursts_are_judged_by_the_caps_alone() {
    let mut q = queue();
    // silence: 100 bytes for a whole second (800 bit/s), then a burst: 200_000 bytes for 10 ms
    q.push(chunk(E1, T0, 0, RATE, 100)).unwrap();
    q.push(chunk(E1, T0, R, 480, 200_000)).unwrap();
    let s = q.stats();
    assert_eq!((s.bytes, s.media_ns, s.chunks), (200_100, 1_010_000_000, 2));
    assert_eq!(s.refused_invalid, 0);
}

#[test]
fn a_header_chunk_of_zero_frames_carries_bytes_and_no_time_and_does_not_move_the_position() {
    let mut q = queue();
    q.push(chunk(E1, T0, 0, 0, 2_000)).unwrap();
    assert_eq!(q.fetch_position(), (T0, 0));
    q.push(chunk(E1, T0, 0, RATE, 40_000)).unwrap();
    let s = q.stats();
    assert_eq!((s.bytes, s.media_ns, s.chunks), (42_000, 1_000_000_000, 2));
    assert_eq!(q.fetch_position(), (T0, R));
    // the declared rate is part of the track's identity, and zero is not a rate
    assert_eq!(
        q.push(chunk_at_rate(E1, T0, R, RATE, 12_000, 0)),
        Err(LookaheadError::InvalidChunk {
            reason: "zero rate"
        })
    );
}

#[test]
fn a_single_chunk_is_capped_and_the_cap_itself_is_accepted() {
    let mut q = queue();
    assert_eq!(
        q.push(chunk(E1, T0, 0, 5 * RATE, 262_145)),
        Err(LookaheadError::ChunkTooLarge {
            bytes: 262_145,
            max: 262_144
        })
    );
    q.push(chunk(E1, T0, 0, 5 * RATE, 262_144)).unwrap();
    assert_eq!(q.stats().bytes, 262_144);
}

#[test]
fn positions_are_exact_frames_and_the_time_charge_is_conservative_and_bounded() {
    let mut q = queue();
    // 1152 frames at 44.1 kHz is 26.12... ms: no integer millisecond can add up to the true position
    for i in 0..2000 {
        q.push(chunk_at_rate(E1, T0, i * 1152, 1152, 400, 44_100))
            .unwrap();
    }
    assert_eq!(q.fetch_position(), (T0, 2_304_000));
    assert_eq!(duration_ns_ceil(1152, 44_100), Some(26_122_449));
    assert_eq!(q.stats().media_ns, 2000 * 26_122_449);
    // the whole run is 52_244_897_959.18 ns exactly; rounding up per chunk over-counts by under 1 ns each
    let whole = duration_ns_ceil(2_304_000, 44_100).unwrap();
    assert_eq!(whole, 52_244_897_960);
    let charged = q.stats().media_ns;
    assert!(
        (whole..=whole + 2000).contains(&charged),
        "{charged} vs {whole}"
    );
    // removing a chunk removes exactly what was added: no drift
    q.pop().unwrap().unwrap();
    assert_eq!(q.stats().media_ns, 1999 * 26_122_449);
}

#[test]
fn readiness_is_a_measured_minimum_of_media_time_not_a_full_fill() {
    let mut q = queue();
    for i in 0..4 {
        q.push(lo(i)).unwrap();
    }
    assert_eq!(
        q.readiness(),
        Readiness {
            ready: false,
            bytes: 48_000,
            media_ns: 4_000_000_000
        }
    );
    q.push(lo(4)).unwrap();
    assert_eq!(
        q.readiness(),
        Readiness {
            ready: true,
            bytes: 60_000,
            media_ns: 5_000_000_000
        }
    );
    assert!(
        q.stats().bytes * 100 < limits().max_bytes,
        "ready with the queue nearly empty"
    );
}

#[test]
fn the_duration_and_link_arithmetic_state_a_bound_and_nothing_more() {
    assert_eq!(duration_ns_ceil(44_100, 44_100), Some(1_000_000_000));
    assert_eq!(duration_ns_ceil(1, 44_100), Some(22_676), "rounded up");
    assert_eq!(duration_ns_ceil(7_938_000, 44_100), Some(180_000_000_000));
    assert_eq!(duration_ns_ceil(0, 44_100), Some(0));
    assert_eq!(duration_ns_ceil(5, 0), None);
    assert_eq!(duration_ns_ceil(u64::MAX, 1), None);
    // 3 minutes at 320 kbit/s is 7_200_000 bytes; 2 seconds for it needs 28_800_000 bit/s
    assert_eq!(required_link_bps(7_200_000, 2_000), Some(28_800_000));
    assert_eq!(required_link_bps(1, 3_000), Some(3), "rounded up");
    assert_eq!(required_link_bps(1, 0), None);
    assert_eq!(required_link_bps(u64::MAX, 1), None);
}

// ---- identity and contiguity

#[test]
fn identity_and_contiguity_refusals_leave_the_queue_unchanged() {
    let mut q = queue();
    q.push(lo(0)).unwrap();
    let before = q.stats();
    assert_eq!(
        q.push(chunk(E1, T1, R, RATE, 12_000)),
        Err(LookaheadError::TrackMismatch {
            chunk: 1,
            expected: 0
        })
    );
    assert_eq!(
        q.push(lo(2)),
        Err(LookaheadError::NotContiguous {
            start_frame: 2 * R,
            expected_frame: R
        })
    );
    assert_eq!(
        q.push(chunk(E1, T0, R / 2, RATE, 12_000)),
        Err(LookaheadError::NotContiguous {
            start_frame: R / 2,
            expected_frame: R
        })
    );
    assert_eq!(
        q.push(chunk(E2, T0, R, RATE, 12_000)),
        Err(LookaheadError::EpochAhead {
            chunk: 2,
            current: 1
        })
    );
    assert_eq!(
        q.push(chunk(E1, T0, R, RATE, 0)),
        Err(LookaheadError::InvalidChunk {
            reason: "empty payload"
        })
    );
    assert_eq!(
        q.push(chunk_at_rate(E1, T0, R, RATE, 12_000, 0)),
        Err(LookaheadError::InvalidChunk {
            reason: "zero rate"
        })
    );
    assert_eq!(
        q.push(chunk_at_rate(E1, T0, R, 44_100, 12_000, 44_100)),
        Err(LookaheadError::RateMismatch {
            chunk: 44_100,
            expected: RATE
        })
    );
    assert_eq!(
        q.stats(),
        LookaheadStats {
            refused_invalid: 7,
            ..before
        }
    );
    assert_eq!(q.fetch_position(), (T0, R));
    // control: the matching chunk is accepted
    q.push(lo(1)).unwrap();
    assert_eq!(q.stats().chunks, 2);
}

#[test]
fn a_track_advances_only_after_a_last_of_track_chunk_and_gaplessly() {
    let mut q = queue();
    q.push(last_of_track(lo(0))).unwrap();
    assert_eq!(q.fetch_position(), (T1, 0));
    assert_eq!(
        q.push(lo(1)),
        Err(LookaheadError::TrackMismatch {
            chunk: 0,
            expected: 1
        })
    );
    assert_eq!(
        q.push(chunk(E1, T1, R, RATE, 12_000)),
        Err(LookaheadError::NotContiguous {
            start_frame: R,
            expected_frame: 0
        })
    );
    assert_eq!(
        q.push(chunk(E1, T2, 0, RATE, 12_000)),
        Err(LookaheadError::TrackMismatch {
            chunk: 2,
            expected: 1
        })
    );
    // the next track may declare its own rate; within it the rate is then fixed
    q.push(chunk_at_rate(E1, T1, 0, 44_100, 12_000, 44_100))
        .unwrap();
    assert_eq!(q.fetch_position(), (T1, 44_100));
    assert_eq!(
        q.push(chunk(E1, T1, 44_100, RATE, 12_000)),
        Err(LookaheadError::RateMismatch {
            chunk: RATE,
            expected: 44_100
        })
    );
}

#[test]
fn a_gapless_queue_holds_the_old_tail_and_the_next_head_and_the_fetch_track_is_not_the_playback_head()
 {
    let mut q = queue();
    q.push(lo(0)).unwrap();
    q.push(last_of_track(lo(1))).unwrap();
    q.push(chunk(E1, T1, 0, RATE, 12_000)).unwrap();
    q.push(chunk(E1, T1, R, RATE, 12_000)).unwrap();
    // admitting the last chunk of track 0 moved only the fetch position
    assert_eq!(
        (q.head_track(), q.playback_track(), q.fetch_position()),
        (Some(T0), None, (T1, 2 * R))
    );
    assert_eq!(q.stats().chunks, 4);
    assert_eq!(q.pop().unwrap().unwrap().chunk.track, T0);
    assert_eq!((q.head_track(), q.playback_track()), (Some(T0), Some(T0)));
    // the last chunk of track 0 is still handed out after track 1's head was admitted
    assert!(q.pop().unwrap().unwrap().chunk.last_of_track);
    assert_eq!((q.head_track(), q.playback_track()), (Some(T1), Some(T0)));
    assert_eq!(q.fetch_position(), (T1, 2 * R));
    assert_eq!(q.pop().unwrap().unwrap().chunk.track, T1);
    assert_eq!((q.head_track(), q.playback_track()), (Some(T1), Some(T1)));
    // eviction across the boundary keeps the old track's tail and restores the fetch position
    let mut q = queue();
    q.push(lo(0)).unwrap();
    q.push(last_of_track(lo(1))).unwrap();
    q.push(chunk(E1, T1, 0, RATE, 12_000)).unwrap();
    let two = LookaheadLimits {
        max_bytes: 24_000,
        max_chunk_bytes: 12_000,
        ..limits()
    };
    assert_eq!(
        q.shrink_to(two).unwrap(),
        Evicted {
            chunks: 1,
            bytes: 12_000,
            media_ns: 1_000_000_000
        }
    );
    assert_eq!(
        (q.head_track(), q.fetch_position(), q.stats().chunks),
        (Some(T0), (T1, 0), 2)
    );
    // a skip drops both tracks at once
    let mut q = queue();
    q.push(lo(0)).unwrap();
    q.push(last_of_track(lo(1))).unwrap();
    q.push(chunk(E1, T1, 0, RATE, 12_000)).unwrap();
    let start = q.begin_transition(E2, T7, 0).unwrap();
    assert_eq!((start.dropped_chunks, start.dropped_bytes), (3, 36_000));
}

#[test]
fn position_and_serial_overflow_are_refused_not_wrapped_even_on_the_last_chunk_of_a_track() {
    let top = TrackSerial::new(u64::MAX);
    let mut q = LookaheadQueue::new(limits(), E1, top, 0).unwrap();
    assert_eq!(
        q.push(last_of_track(chunk(E1, top, 0, RATE, 12_000))),
        Err(LookaheadError::Overflow {
            what: "track serial"
        })
    );
    let mut q = LookaheadQueue::new(limits(), E1, T0, u64::MAX - 10).unwrap();
    assert_eq!(
        q.push(chunk(E1, T0, u64::MAX - 10, RATE, 12_000)),
        Err(LookaheadError::Overflow {
            what: "frame position"
        })
    );
    // the end of the chunk must fit even when the chunk is the last of its track
    assert_eq!(
        q.push(last_of_track(chunk(E1, T0, u64::MAX - 10, RATE, 12_000))),
        Err(LookaheadError::Overflow {
            what: "frame position"
        })
    );
    assert_eq!(q.stats().chunks, 0);
    // control: a last chunk whose end fits exactly is accepted and the next track starts at 0
    let mut q = LookaheadQueue::new(limits(), E1, T0, u64::MAX - R).unwrap();
    q.push(last_of_track(chunk(E1, T0, u64::MAX - R, RATE, 12_000)))
        .unwrap();
    assert_eq!(q.fetch_position(), (T1, 0));
}

// ---- eviction

#[test]
fn shrink_drops_the_furthest_chunks_first_and_the_fetch_position_moves_back() {
    let mut q = queue();
    for i in 0..10 {
        q.push(hi(i)).unwrap();
    }
    let smaller = LookaheadLimits {
        max_bytes: 4 * 40_000,
        max_chunk_bytes: 40_000,
        ..limits()
    };
    let gone = q.shrink_to(smaller).unwrap();
    assert_eq!(
        gone,
        Evicted {
            chunks: 6,
            bytes: 240_000,
            media_ns: 6_000_000_000
        }
    );
    let s = q.stats();
    assert_eq!((s.bytes, s.media_ns, s.chunks), (160_000, 4_000_000_000, 4));
    assert_eq!((s.evicted_chunks, s.evicted_bytes), (6, 240_000));
    assert_eq!(q.fetch_position(), (T0, 4 * R));
    assert_eq!(q.limits(), smaller);
    // the head is intact and the refetch must be contiguous
    assert_eq!(q.pop().unwrap().unwrap().chunk.start_frame, 0);
    assert_eq!(
        q.push(hi(10)),
        Err(LookaheadError::NotContiguous {
            start_frame: 10 * R,
            expected_frame: 4 * R
        })
    );
    q.push(hi(4)).unwrap();
    assert_eq!(q.stats().bytes, 160_000);
}

#[test]
fn shrink_by_time_or_count_and_to_a_larger_allowance_are_each_exact() {
    let mut q = queue();
    for i in 0..10 {
        q.push(lo(i)).unwrap();
    }
    let by_time = LookaheadLimits {
        max_media_ms: 3500,
        ready_min_media_ms: 1000,
        ..limits()
    };
    assert_eq!(
        q.shrink_to(by_time).unwrap(),
        Evicted {
            chunks: 7,
            bytes: 84_000,
            media_ns: 7_000_000_000
        }
    );
    assert_eq!((q.stats().chunks, q.stats().media_ns), (3, 3_000_000_000));
    let by_count = LookaheadLimits {
        max_chunks: 2,
        ..limits()
    };
    assert_eq!(
        q.shrink_to(by_count).unwrap(),
        Evicted {
            chunks: 1,
            bytes: 12_000,
            media_ns: 1_000_000_000
        }
    );
    assert_eq!(q.fetch_position(), (T0, 2 * R));
    // control: a larger allowance evicts nothing and is adopted
    assert_eq!(q.shrink_to(limits()).unwrap(), Evicted::default());
    assert_eq!(q.limits(), limits());
    assert_eq!(q.stats().chunks, 2);
    // invalid limits are refused and change nothing
    let bad = LookaheadLimits {
        max_bytes: 0,
        ..limits()
    };
    assert_eq!(
        q.shrink_to(bad),
        Err(LookaheadError::InvalidLimits { field: "max_bytes" })
    );
    assert_eq!(q.limits(), limits());
}

#[test]
fn shrink_across_a_track_boundary_and_down_to_empty_keeps_the_position_exact() {
    let mut q = queue();
    q.push(last_of_track(lo(0))).unwrap();
    q.push(chunk(E1, T1, 0, RATE, 12_000)).unwrap();
    q.push(chunk(E1, T1, R, RATE, 12_000)).unwrap();
    let two = LookaheadLimits {
        max_bytes: 24_000,
        max_chunk_bytes: 12_000,
        ..limits()
    };
    assert_eq!(
        q.shrink_to(two).unwrap(),
        Evicted {
            chunks: 1,
            bytes: 12_000,
            media_ns: 1_000_000_000
        }
    );
    assert_eq!(q.fetch_position(), (T1, R));
    let one = LookaheadLimits {
        max_bytes: 12_000,
        max_chunk_bytes: 12_000,
        ..limits()
    };
    q.shrink_to(one).unwrap();
    // the ended track 0 cannot be continued: the next chunk is track 1 at 0
    assert_eq!(q.fetch_position(), (T1, 0));
    assert_eq!(q.stats().chunks, 1);
    let none = LookaheadLimits {
        max_bytes: 11_999,
        max_chunk_bytes: 11_999,
        ..limits()
    };
    assert_eq!(
        q.shrink_to(none).unwrap(),
        Evicted {
            chunks: 1,
            bytes: 12_000,
            media_ns: 1_000_000_000
        }
    );
    let s = q.stats();
    assert_eq!((s.bytes, s.media_ns, s.chunks), (0, 0, 0));
    assert_eq!(q.fetch_position(), (T0, 0));
    // control: a chunk that fits the new allowance is accepted at the restored position
    q.push(chunk(E1, T0, 0, RATE, 11_000)).unwrap();
}

#[test]
fn a_reduced_chunk_limit_evicts_the_old_oversize_chunk_and_everything_after_it() {
    let mut q = queue();
    q.push(lo(0)).unwrap();
    q.push(lo(1)).unwrap();
    q.push(hi(2)).unwrap();
    q.push(lo(3)).unwrap();
    // control: a reduced per-chunk limit that every queued chunk still meets evicts nothing
    let roomy = LookaheadLimits {
        max_chunk_bytes: 50_000,
        ..limits()
    };
    assert_eq!(q.shrink_to(roomy).unwrap(), Evicted::default());
    assert_eq!(q.stats().chunks, 4);
    // the old oversize chunk and everything admitted after it go, deterministically, tail first
    let small = LookaheadLimits {
        max_chunk_bytes: 20_000,
        ..limits()
    };
    assert_eq!(
        q.shrink_to(small).unwrap(),
        Evicted {
            chunks: 2,
            bytes: 52_000,
            media_ns: 2_000_000_000
        }
    );
    let s = q.stats();
    assert_eq!((s.bytes, s.media_ns, s.chunks), (24_000, 2_000_000_000, 2));
    assert_eq!(q.fetch_position(), (T0, 2 * R));
    assert_eq!(q.limits(), small);
    // the refetch of the oversize chunk is refused, a chunk within the new limit is accepted
    assert_eq!(
        q.push(hi(2)),
        Err(LookaheadError::ChunkTooLarge {
            bytes: 40_000,
            max: 20_000
        })
    );
    q.push(lo(2)).unwrap();
    let starts: Vec<u64> = (0..3)
        .map(|_| q.pop().unwrap().unwrap().chunk.start_frame)
        .collect();
    assert_eq!(starts, [0, R, 2 * R]);
    // an oversize HEAD behind smaller future chunks: nothing behind it can stay either
    let mut q = queue();
    q.push(hi(0)).unwrap();
    q.push(lo(1)).unwrap();
    q.push(lo(2)).unwrap();
    assert_eq!(
        q.shrink_to(small).unwrap(),
        Evicted {
            chunks: 3,
            bytes: 64_000,
            media_ns: 3_000_000_000
        }
    );
    assert_eq!(q.stats().chunks, 0);
    assert_eq!(q.fetch_position(), (T0, 0));
    q.push(lo(0)).unwrap();
}

/// A payload whose Vec reserves far more than it holds.
fn roomy(len: usize, reserve: usize) -> Vec<u8> {
    let mut payload = vec![1_u8; len];
    payload.reserve_exact(reserve);
    payload
}

#[test]
fn queued_payloads_own_exactly_the_bytes_they_are_charged_for() {
    let header = Chunk {
        epoch: E1,
        track: T0,
        start_frame: 0,
        frames: 0,
        rate_hz: RATE,
        last_of_track: false,
        payload: roomy(1, 1 << 20),
    };
    assert!(header.payload.capacity() > 1 << 20);
    let mut q = queue();
    q.push(header).unwrap();
    q.push(chunk(E1, T0, 0, RATE, 40_000)).unwrap();
    let held: usize = q.chunks.iter().map(|c| c.payload.capacity()).sum();
    assert_eq!((held, q.stats().bytes), (40_001, 40_001));
    // the content is preserved and an exact-capacity payload is left alone
    assert_eq!(q.pop().unwrap().unwrap().chunk.payload, [1]);
    // many valid headers cannot hide their reservations behind a small byte count
    let mut q = queue();
    for _ in 0..1000 {
        let header = Chunk {
            epoch: E1,
            track: T0,
            start_frame: 0,
            frames: 0,
            rate_hz: RATE,
            last_of_track: false,
            payload: roomy(1, 65_536),
        };
        q.push(header).unwrap();
    }
    let held: usize = q.chunks.iter().map(|c| c.payload.capacity()).sum();
    assert_eq!((held, q.stats().bytes), (1000, 1000));
}

#[test]
fn source_frames_and_output_frames_never_compare_even_when_the_raw_counts_line_up() {
    let mut q = queue();
    // a 44.1 kHz track: one second is 44_100 SOURCE frames, which the 48 kHz output makes 48_000 OUTPUT frames
    q.push(chunk_at_rate(E1, T0, 0, 44_100, 12_000, 44_100))
        .unwrap();
    let handoff = q.pop().unwrap().unwrap();
    q.retire(&handoff.ticket, Retirement::Submitted { end: at(48_000) })
        .unwrap();
    q.begin_transition(E2, T0, 0).unwrap();
    // the source-rate count 44_100 equals itself in the wrong domain, and is refused
    assert_eq!(
        q.ack_transition(&mut Renderer::new(drained_in(OTHER_RATE, 44_100, 44_100))),
        Err(LookaheadError::FenceDomainMismatch)
    );
    // in the right domain a tail of 44_100 does not cover the 48_000 submitted
    assert_eq!(
        q.ack_transition(&mut Renderer::new(drained(44_100, 44_100))),
        Err(LookaheadError::FenceTailBehindSubmissions {
            required: 48_000,
            reported: 44_100
        })
    );
    // and a cursor at 47_000 has not drained a tail of 48_000
    assert_eq!(
        q.ack_transition(&mut Renderer::new(drained(48_000, 47_000))),
        Err(LookaheadError::OutputNotDrained {
            tail_frame: 48_000,
            played_frame: 47_000
        })
    );
    assert_eq!(
        q.ack_transition(&mut Renderer::new(drained(48_000, 48_000))),
        Ok(TransitionAck {
            epoch: E2,
            via: FenceKind::Drained
        })
    );
}

#[test]
fn chunks_are_opaque_payload_is_never_formatted_and_eviction_reports_counts_only() {
    let c = Chunk {
        epoch: E1,
        track: T0,
        start_frame: 0,
        frames: RATE,
        rate_hz: RATE,
        last_of_track: false,
        payload: vec![0xAB; 1000],
    };
    let text = format!("{c:?}");
    assert!(text.contains("payload_len: 1000"), "{text}");
    assert!(!text.contains("171"), "{text}");
    let mut q = queue();
    q.push(c).unwrap();
    q.shrink_to(LookaheadLimits {
        max_bytes: 999,
        max_chunk_bytes: 999,
        ..limits()
    })
    .unwrap();
    let text = format!("{q:?}");
    assert!(!text.contains("171"), "{text}");
}

// ---- late and future epochs

#[test]
fn a_late_chunk_of_an_old_epoch_is_refused_and_counted_and_never_acknowledges() {
    let (mut q, _req) = pending();
    for i in 0..3 {
        assert_eq!(
            q.push(hi(3 + i)),
            Err(LookaheadError::LateOldEpoch {
                chunk: 1,
                current: 2
            })
        );
    }
    assert_eq!(q.stats().refused_late_epoch, 3);
    // refusing old ingress is not an acknowledgment
    assert_eq!(q.transition_status(), TransitionStatus::AwaitingFence);
    assert_eq!(q.pop(), Err(LookaheadError::TransitionPending));
    // control: the renderer's evidence acknowledges
    assert!(q.ack_transition(&mut Renderer::new(flushed(2))).is_ok());
    assert_eq!(q.transition_status(), TransitionStatus::Idle);
}

// ---- seek and skip

#[test]
fn a_seek_before_any_output_is_acknowledged_at_once_and_the_old_timeline_cannot_return() {
    let mut q = queue();
    for i in 0..3 {
        q.push(hi(i)).unwrap();
    }
    let start = q.begin_transition(E2, T7, 60 * R).unwrap();
    assert!(start.is_acknowledged());
    assert_eq!(
        start,
        TransitionStart {
            epoch: E2,
            fence: None,
            superseded: false,
            dropped_chunks: 3,
            dropped_bytes: 120_000
        }
    );
    assert_eq!(q.transition_status(), TransitionStatus::Idle);
    let s = q.stats();
    assert_eq!((s.bytes, s.media_ns, s.chunks), (0, 0, 0));
    assert_eq!((s.invalidated_chunks, s.invalidated_bytes), (3, 120_000));
    assert_eq!((q.epoch(), q.fetch_position()), (E2, (T7, 60 * R)));
    // the new identity is enforced: the old track is refused, the new one accepted
    assert_eq!(
        q.push(chunk(E2, T0, 60 * R, RATE, 40_000)),
        Err(LookaheadError::TrackMismatch {
            chunk: 0,
            expected: 7
        })
    );
    q.push(chunk(E2, T7, 60 * R, RATE, 40_000)).unwrap();
    assert_eq!(
        q.push(hi(3)),
        Err(LookaheadError::LateOldEpoch {
            chunk: 1,
            current: 2
        })
    );
    assert!(
        q.pop().unwrap().is_some(),
        "nothing was unfenced, so output is not gated"
    );
}

#[test]
fn a_seek_after_output_waits_for_the_renderers_evidence_and_nothing_new_is_handed_out() {
    let mut q = queue();
    for i in 0..3 {
        q.push(hi(i)).unwrap();
    }
    take(&mut q);
    let start = q.begin_transition(E2, T0, 60 * R).unwrap();
    assert!(!start.is_acknowledged());
    let req = start.fence.unwrap();
    assert_eq!((req.epoch, req.token), (E1, FenceToken::new(1)));
    assert_eq!((start.dropped_chunks, start.dropped_bytes), (2, 80_000));
    assert_eq!(q.transition_status(), TransitionStatus::AwaitingFence);
    // the new timeline may be buffered, but it is not ready and not handed out
    q.push(chunk(E2, T0, 60 * R, 5 * RATE, 25_000)).unwrap();
    assert!(!q.readiness().ready);
    assert_eq!(q.pop(), Err(LookaheadError::TransitionPending));
    // not yet drained: refused, still pending, and the renderer was asked about THIS request
    let mut early = Renderer::new(drained(480, 479));
    assert_eq!(
        q.ack_transition(&mut early),
        Err(LookaheadError::OutputNotDrained {
            tail_frame: 480,
            played_frame: 479
        })
    );
    assert_eq!(early.asked, [req]);
    assert_eq!(q.transition_status(), TransitionStatus::AwaitingFence);
    assert_eq!(q.pop(), Err(LookaheadError::TransitionPending));
    // drained: acknowledged, and only now does the new timeline flow
    let mut done = Renderer::new(drained(480, 480));
    assert_eq!(
        q.ack_transition(&mut done),
        Ok(TransitionAck {
            epoch: E2,
            via: FenceKind::Drained
        })
    );
    assert_eq!(done.asked, [req]);
    assert_eq!(q.transition_status(), TransitionStatus::Idle);
    assert!(q.readiness().ready);
    assert_eq!(q.pop().unwrap().unwrap().chunk.epoch, E2);
    // a second acknowledgment finds nothing pending, and the renderer is not consulted
    let mut again = Renderer::new(drained(480, 480));
    assert_eq!(
        q.ack_transition(&mut again),
        Err(LookaheadError::NoTransition)
    );
    assert!(again.asked.is_empty());
    assert_eq!(q.stats().transitions_acked, 1);
}

#[test]
fn a_flush_the_device_acknowledged_also_acknowledges() {
    let (mut q, _req) = pending();
    assert_eq!(
        q.ack_transition(&mut Renderer::new(flushed(7))),
        Ok(TransitionAck {
            epoch: E2,
            via: FenceKind::Flushed
        })
    );
    assert_eq!(q.transition_status(), TransitionStatus::Idle);
}

#[test]
fn a_report_for_another_epoch_or_another_request_is_refused() {
    let (mut q, _req) = pending();
    assert_eq!(
        q.ack_transition(&mut Renderer::new(drained(480, 480)).lying_epoch(1)),
        Err(LookaheadError::FenceEpochMismatch {
            fence: 2,
            expected: 1
        })
    );
    assert_eq!(
        q.ack_transition(&mut Renderer::new(flushed(1)).lying_token(98)),
        Err(LookaheadError::FenceTokenStale {
            got: 99,
            expected: 1
        })
    );
    assert_eq!(q.transition_status(), TransitionStatus::AwaitingFence);
    // control: the report for this request and the epoch whose output was handed out
    assert!(
        q.ack_transition(&mut Renderer::new(drained(480, 480)))
            .is_ok()
    );
}

// ---- the barrier: decoder work the device cannot see

#[test]
fn a_device_that_reports_empty_while_old_decoder_work_is_outstanding_does_not_acknowledge() {
    let mut q = queue();
    for i in 0..3 {
        q.push(hi(i)).unwrap();
    }
    // an OLD chunk is popped and is still being decoded: nothing of it has reached the device
    let handoff = q.pop().unwrap().unwrap();
    assert_eq!(q.outstanding_count(), 1);
    assert!(q.may_submit(&handoff.ticket));
    let req = q.begin_transition(E2, T0, 60 * R).unwrap().fence.unwrap();
    // a faithful device that is empty cannot acknowledge, and is not even asked
    let mut empty = Renderer::new(drained(0, 0));
    assert_eq!(
        q.ack_transition(&mut empty),
        Err(LookaheadError::OutstandingDecoderWork { outstanding: 1 })
    );
    assert!(empty.asked.is_empty());
    assert_eq!(q.transition_status(), TransitionStatus::AwaitingFence);
    assert_eq!(q.pop(), Err(LookaheadError::TransitionPending));
    // control: the decode is cancelled and joined; then the correct output-domain fence acknowledges
    q.retire(&handoff.ticket, Retirement::Cancelled).unwrap();
    assert!(!q.may_submit(&handoff.ticket));
    let mut fenced = Renderer::new(drained(0, 0));
    assert_eq!(
        q.ack_transition(&mut fenced),
        Ok(TransitionAck {
            epoch: E2,
            via: FenceKind::Drained
        })
    );
    assert_eq!(fenced.asked, [req]);
    assert_eq!(q.outstanding_count(), 0);
}

#[test]
fn a_submission_that_retires_after_the_device_was_measured_is_covered_by_the_fence_or_refused() {
    let mut q = queue();
    for i in 0..3 {
        q.push(hi(i)).unwrap();
    }
    let handoff = q.pop().unwrap().unwrap();
    let req = q.begin_transition(E2, T0, 60 * R).unwrap().fence.unwrap();
    assert_eq!(
        q.ack_transition(&mut Renderer::new(drained(0, 0))),
        Err(LookaheadError::OutstandingDecoderWork { outstanding: 1 })
    );
    // the decode finishes and its audio is submitted ending at output frame 480; a measurement taken
    // before that submission cannot cover it, however faithful it was when it was taken
    q.retire(&handoff.ticket, Retirement::Submitted { end: at(480) })
        .unwrap();
    let mut stale = Renderer::new(drained(0, 0));
    assert_eq!(
        q.ack_transition(&mut stale),
        Err(LookaheadError::FenceTailBehindSubmissions {
            required: 480,
            reported: 0
        })
    );
    assert_eq!(stale.asked, [req]);
    assert_eq!(
        q.ack_transition(&mut Renderer::new(drained(480, 479))),
        Err(LookaheadError::OutputNotDrained {
            tail_frame: 480,
            played_frame: 479
        })
    );
    assert_eq!(q.transition_status(), TransitionStatus::AwaitingFence);
    assert_eq!(
        q.ack_transition(&mut Renderer::new(drained(480, 480))),
        Ok(TransitionAck {
            epoch: E2,
            via: FenceKind::Drained
        })
    );
    // after the acknowledgment nothing of the old epoch may submit
    assert!(!q.may_submit(&handoff.ticket));
    assert_eq!(
        q.retire(&handoff.ticket, Retirement::Submitted { end: at(900) }),
        Err(LookaheadError::UnknownHandoff {
            seq: handoff.ticket.seq()
        })
    );
}

#[test]
fn retiring_is_exact_a_ticket_retires_once_and_one_epochs_output_lives_in_one_domain() {
    let mut q = queue();
    for i in 0..3 {
        q.push(hi(i)).unwrap();
    }
    let h1 = q.pop().unwrap().unwrap();
    let h2 = q.pop().unwrap().unwrap();
    assert_eq!(q.outstanding_count(), 2);
    assert_eq!(
        q.retire(
            &h1.ticket,
            Retirement::Submitted {
                end: at_in(ZERO_RATE, 100)
            }
        ),
        Err(LookaheadError::InvalidOutputDomain {
            reason: "zero rate"
        })
    );
    assert_eq!(q.outstanding_count(), 2);
    q.retire(&h1.ticket, Retirement::Submitted { end: at(100) })
        .unwrap();
    let seq = h1.ticket.seq();
    assert_eq!(
        q.retire(&h1.ticket, Retirement::Submitted { end: at(100) }),
        Err(LookaheadError::UnknownHandoff { seq })
    );
    assert_eq!(
        q.retire(&h1.ticket, Retirement::Cancelled),
        Err(LookaheadError::UnknownHandoff { seq })
    );
    assert!(!q.may_submit(&h1.ticket));
    assert!(q.may_submit(&h2.ticket));
    // a submission in another session, generation or rate is refused and leaves the ticket outstanding
    for other in [OTHER_GENERATION, OTHER_SESSION, OTHER_RATE] {
        assert_eq!(
            q.retire(
                &h2.ticket,
                Retirement::Submitted {
                    end: at_in(other, 500)
                }
            ),
            Err(LookaheadError::OutputDomainChanged)
        );
    }
    assert_eq!(q.outstanding_count(), 1);
    // a smaller end in the same domain does not lower the required tail
    q.retire(&h2.ticket, Retirement::Submitted { end: at(50) })
        .unwrap();
    q.begin_transition(E2, T0, 0).unwrap();
    assert_eq!(
        q.ack_transition(&mut Renderer::new(drained(99, 99))),
        Err(LookaheadError::FenceTailBehindSubmissions {
            required: 100,
            reported: 99
        })
    );
    assert_eq!(
        q.ack_transition(&mut Renderer::new(drained(100, 100))),
        Ok(TransitionAck {
            epoch: E2,
            via: FenceKind::Drained
        })
    );
}

#[test]
fn outstanding_decoder_work_is_bounded_and_a_refused_hand_out_leaves_the_chunk_in_the_queue() {
    let tight = LookaheadLimits {
        max_outstanding: 2,
        ..limits()
    };
    let mut q = LookaheadQueue::new(tight, E1, T0, 0).unwrap();
    for i in 0..4 {
        q.push(lo(i)).unwrap();
    }
    let h1 = q.pop().unwrap().unwrap();
    q.pop().unwrap().unwrap();
    let before = q.stats();
    assert_eq!(q.pop(), Err(LookaheadError::OutstandingLimit { max: 2 }));
    assert_eq!(q.stats(), before);
    assert_eq!(q.stats().chunks, 2);
    // control: retiring one frees one slot, and the next chunk is the one that was refused
    q.retire(&h1.ticket, Retirement::Cancelled).unwrap();
    assert_eq!(q.pop().unwrap().unwrap().chunk.start_frame, 2 * R);
}

#[test]
fn a_ticket_belongs_to_the_queue_that_issued_it_even_when_epoch_and_sequence_collide() {
    // two queues, the same epoch, the same first sequence number
    let mut a = queue();
    let mut b = queue();
    for i in 0..3 {
        a.push(hi(i)).unwrap();
        b.push(hi(i)).unwrap();
    }
    let ha = a.pop().unwrap().unwrap();
    let hb = b.pop().unwrap().unwrap();
    assert_eq!(
        (ha.ticket.seq(), ha.ticket.epoch()),
        (hb.ticket.seq(), hb.ticket.epoch()),
        "the collision this guards against"
    );
    assert_ne!(ha.ticket, hb.ticket);
    // each queue's own ticket authorizes output through it; the other queue's authorizes nothing
    assert!(a.may_submit(&ha.ticket) && b.may_submit(&hb.ticket));
    assert!(!b.may_submit(&ha.ticket) && !a.may_submit(&hb.ticket));
    // and A's ticket retires nothing of B's: refused, B's outstanding work and submission record untouched
    let foreign = LookaheadError::ForeignHandoff {
        seq: ha.ticket.seq(),
    };
    assert_eq!(
        b.retire(&ha.ticket, Retirement::Cancelled),
        Err(foreign.clone())
    );
    assert_eq!(
        b.retire(&ha.ticket, Retirement::Submitted { end: at(480) }),
        Err(foreign.clone())
    );
    assert_eq!(b.outstanding_count(), 1);
    assert_eq!(b.submitted, None);
    assert_eq!(a.outstanding_count(), 1);
    // B's seek stays blocked by B's own outstanding work, whatever A's ticket claims
    b.begin_transition(E2, T0, 0).unwrap();
    assert_eq!(b.retire(&ha.ticket, Retirement::Cancelled), Err(foreign));
    let mut empty = Renderer::new(drained(0, 0));
    assert_eq!(
        b.ack_transition(&mut empty),
        Err(LookaheadError::OutstandingDecoderWork { outstanding: 1 })
    );
    assert!(empty.asked.is_empty());
    // control: each queue's own ticket retires and its own seek acknowledges
    a.retire(&ha.ticket, Retirement::Submitted { end: at(480) })
        .unwrap();
    b.retire(&hb.ticket, Retirement::Cancelled).unwrap();
    a.begin_transition(E2, T0, 0).unwrap();
    assert!(
        a.ack_transition(&mut Renderer::new(drained(480, 480)))
            .is_ok()
    );
    assert!(b.ack_transition(&mut Renderer::new(drained(0, 0))).is_ok());
}

#[test]
fn a_ticket_of_a_dropped_queue_stays_foreign_and_a_clone_is_the_same_ticket() {
    let ticket = {
        let mut gone = queue();
        gone.push(hi(0)).unwrap();
        gone.pop().unwrap().unwrap().ticket
    };
    // a new queue issues the same epoch and sequence number; the old identity is still alive under the ticket
    let mut q = queue();
    q.push(hi(0)).unwrap();
    let own = q.pop().unwrap().unwrap();
    assert_eq!(
        (own.ticket.seq(), own.ticket.epoch()),
        (ticket.seq(), ticket.epoch())
    );
    assert!(!q.may_submit(&ticket));
    assert_eq!(
        q.retire(&ticket, Retirement::Cancelled),
        Err(LookaheadError::ForeignHandoff { seq: ticket.seq() })
    );
    assert_eq!(q.outstanding_count(), 1);
    // a clone is the same ticket: retiring through it retires the original too
    let copy = own.ticket.clone();
    assert_eq!(copy, own.ticket);
    q.retire(&copy, Retirement::Cancelled).unwrap();
    assert!(!q.may_submit(&own.ticket));
    assert_eq!(
        q.retire(&own.ticket, Retirement::Cancelled),
        Err(LookaheadError::UnknownHandoff {
            seq: own.ticket.seq()
        })
    );
}

#[test]
fn the_evidence_must_be_in_the_domain_the_output_was_submitted_in() {
    for other in [OTHER_GENERATION, OTHER_SESSION, OTHER_RATE] {
        let (mut q, _req) = pending();
        assert_eq!(
            q.ack_transition(&mut Renderer::new(drained_in(other, 480, 480))),
            Err(LookaheadError::FenceDomainMismatch)
        );
        assert_eq!(
            q.ack_transition(&mut Renderer::new(flushed_in(other, 2))),
            Err(LookaheadError::FenceDomainMismatch)
        );
        assert_eq!(q.transition_status(), TransitionStatus::AwaitingFence);
        assert_eq!(
            q.ack_transition(&mut Renderer::new(drained(480, 480))),
            Ok(TransitionAck {
                epoch: E2,
                via: FenceKind::Drained
            })
        );
    }
    // a tail and a played position in two domains do not compare, however the numbers line up
    let (mut q, _req) = pending();
    let mixed = FenceOutcome::Drained {
        tail: at(480),
        played: at_in(OTHER_GENERATION, 480),
    };
    assert_eq!(
        q.ack_transition(&mut Renderer::new(mixed)),
        Err(LookaheadError::FenceDomainMismatch)
    );
    // control: nothing was submitted (every handoff cancelled), so there is no domain to contradict
    let mut q = queue();
    for i in 0..2 {
        q.push(hi(i)).unwrap();
    }
    let handoff = q.pop().unwrap().unwrap();
    q.begin_transition(E2, T0, 0).unwrap();
    q.retire(&handoff.ticket, Retirement::Cancelled).unwrap();
    let far = OutputDomain {
        session: 9,
        generation: 9,
        rate_hz: 96_000,
    };
    assert_eq!(
        q.ack_transition(&mut Renderer::new(drained_in(far, 5, 5))),
        Ok(TransitionAck {
            epoch: E2,
            via: FenceKind::Drained
        })
    );
}

#[test]
fn a_flush_that_times_out_fails_the_transition_and_a_new_one_supersedes_it() {
    let (mut q, req) = pending();
    q.push(chunk(E2, T0, 60 * R, RATE, 12_000)).unwrap();
    assert_eq!(
        q.ack_transition(&mut Renderer::new(timed_out(3))),
        Err(LookaheadError::FlushTimedOut)
    );
    assert_eq!(q.transition_status(), TransitionStatus::Failed);
    assert_eq!(q.stats().transitions_failed, 1);
    // no later report rescues it (the renderer is not even asked), and nothing is handed out
    let mut late = Renderer::new(drained(480, 480));
    assert_eq!(
        q.ack_transition(&mut late),
        Err(LookaheadError::TransitionFailed)
    );
    assert!(late.asked.is_empty());
    assert_eq!(q.pop(), Err(LookaheadError::TransitionFailed));
    // a new transition supersedes it, drops what was buffered, and is fenced against the SAME output
    let again = q.begin_transition(E3, T0, 90 * R).unwrap();
    assert!(again.superseded);
    assert_eq!((again.dropped_chunks, again.dropped_bytes), (1, 12_000));
    let req2 = again.fence.unwrap();
    assert_eq!((req2.epoch, req2.token), (E1, FenceToken::new(2)));
    assert_eq!(q.stats().transitions_superseded, 1);
    // a stale reply for the old request is refused; the new request's evidence acknowledges
    let mut stale = Replay(OutputFence {
        token: req.token,
        epoch: req.epoch,
        outcome: flushed(1),
    });
    assert_eq!(
        q.ack_transition(&mut stale),
        Err(LookaheadError::FenceTokenStale {
            got: 1,
            expected: 2
        })
    );
    assert_eq!(
        q.ack_transition(&mut Renderer::new(flushed(1))),
        Ok(TransitionAck {
            epoch: E3,
            via: FenceKind::Flushed
        })
    );
}

#[test]
fn the_unqualified_fence_fails_closed_so_no_seek_over_unfenced_output_is_ever_acknowledged() {
    let (mut q, _req) = pending();
    assert_eq!(
        q.ack_transition(&mut UnqualifiedFence),
        Err(LookaheadError::FlushTimedOut)
    );
    assert_eq!(q.transition_status(), TransitionStatus::Failed);
    assert_eq!(q.pop(), Err(LookaheadError::TransitionFailed));
    assert_eq!(
        q.ack_transition(&mut UnqualifiedFence),
        Err(LookaheadError::TransitionFailed)
    );
}

#[test]
fn a_second_seek_while_one_is_pending_supersedes_it_and_the_original_output_stays_fenced() {
    let (mut q, req) = pending();
    q.push(chunk(E2, T0, 60 * R, RATE, 12_000)).unwrap();
    let again = q.begin_transition(E3, T1, 5 * R).unwrap();
    assert!(again.superseded);
    assert_eq!((again.dropped_chunks, again.dropped_bytes), (1, 12_000));
    let req2 = again.fence.unwrap();
    // epoch 2 never had output: the fence still speaks for epoch 1
    assert_eq!((req2.epoch, req2.token), (E1, FenceToken::new(2)));
    assert_ne!(req.token, req2.token);
    assert_eq!(q.transition_status(), TransitionStatus::AwaitingFence);
    let mut stale = Replay(OutputFence {
        token: req.token,
        epoch: req.epoch,
        outcome: drained(480, 480),
    });
    assert_eq!(
        q.ack_transition(&mut stale),
        Err(LookaheadError::FenceTokenStale {
            got: 1,
            expected: 2
        })
    );
    // a report for epoch 2 would be for output that was never handed out
    assert_eq!(
        q.ack_transition(&mut Renderer::new(drained(480, 480)).lying_epoch(1)),
        Err(LookaheadError::FenceEpochMismatch {
            fence: 2,
            expected: 1
        })
    );
    // the original work was retired as submitted ending at 480: the superseding transition still fences it
    assert_eq!(
        q.ack_transition(&mut Renderer::new(drained(479, 479))),
        Err(LookaheadError::FenceTailBehindSubmissions {
            required: 480,
            reported: 479
        })
    );
    let mut right = Renderer::new(drained(480, 480));
    assert_eq!(
        q.ack_transition(&mut right),
        Ok(TransitionAck {
            epoch: E3,
            via: FenceKind::Drained
        })
    );
    assert_eq!(right.asked, [req2]);
    assert_eq!(q.epoch(), E3);
}

#[test]
fn a_transition_must_be_strictly_ahead_and_a_refusal_drops_nothing() {
    let mut q = queue();
    q.push(lo(0)).unwrap();
    let before = q.stats();
    assert_eq!(
        q.begin_transition(E1, T0, 0),
        Err(LookaheadError::TransitionEpochNotAhead {
            requested: 1,
            current: 1
        })
    );
    assert_eq!(q.stats(), before, "the refusal dropped nothing");
    assert_eq!(q.epoch(), E1);
    // control: a later epoch is accepted; then an earlier one is refused and the epoch stays
    q.begin_transition(E3, T0, 0).unwrap();
    assert_eq!(
        q.begin_transition(E2, T0, 0),
        Err(LookaheadError::TransitionEpochNotAhead {
            requested: 2,
            current: 3
        })
    );
    assert_eq!(q.epoch(), E3, "the refused call left the epoch alone");
}

#[test]
fn after_an_acknowledged_transition_nothing_is_left_to_fence_until_output_is_handed_out_again() {
    let (mut q, _req) = pending();
    q.ack_transition(&mut Renderer::new(flushed(1))).unwrap();
    // nothing handed out since the acknowledgment: the next seek completes at once
    let quick = q.begin_transition(E3, T0, 0).unwrap();
    assert!(quick.is_acknowledged());
    // hand output out again, and the next seek needs a fence for THAT epoch with the next token
    q.push(chunk(E3, T0, 0, RATE, 12_000)).unwrap();
    take(&mut q);
    let fenced = q.begin_transition(E4, T0, 0).unwrap();
    let req = fenced.fence.unwrap();
    assert_eq!((req.epoch, req.token), (E3, FenceToken::new(2)));
}

#[test]
fn every_refusal_has_its_own_stable_code() {
    let all = [
        LookaheadError::InvalidLimits { field: "f" },
        LookaheadError::InvalidChunk { reason: "r" },
        LookaheadError::LateOldEpoch {
            chunk: 1,
            current: 2,
        },
        LookaheadError::EpochAhead {
            chunk: 2,
            current: 1,
        },
        LookaheadError::TrackMismatch {
            chunk: 1,
            expected: 2,
        },
        LookaheadError::RateMismatch {
            chunk: 1,
            expected: 2,
        },
        LookaheadError::NotContiguous {
            start_frame: 1,
            expected_frame: 2,
        },
        LookaheadError::ChunkTooLarge { bytes: 2, max: 1 },
        LookaheadError::Full {
            cap: CapKind::Bytes,
        },
        LookaheadError::Overflow { what: "w" },
        LookaheadError::TransitionEpochNotAhead {
            requested: 1,
            current: 1,
        },
        LookaheadError::TransitionPending,
        LookaheadError::TransitionFailed,
        LookaheadError::NoTransition,
        LookaheadError::FenceTokenStale {
            got: 1,
            expected: 2,
        },
        LookaheadError::FenceEpochMismatch {
            fence: 1,
            expected: 2,
        },
        LookaheadError::OutputNotDrained {
            tail_frame: 2,
            played_frame: 1,
        },
        LookaheadError::FlushTimedOut,
        LookaheadError::OutstandingDecoderWork { outstanding: 1 },
        LookaheadError::OutstandingLimit { max: 1 },
        LookaheadError::UnknownHandoff { seq: 1 },
        LookaheadError::ForeignHandoff { seq: 1 },
        LookaheadError::InvalidOutputDomain { reason: "r" },
        LookaheadError::OutputDomainChanged,
        LookaheadError::FenceDomainMismatch,
        LookaheadError::FenceTailBehindSubmissions {
            required: 2,
            reported: 1,
        },
    ];
    let codes: BTreeSet<&str> = all.iter().map(LookaheadError::code).collect();
    assert_eq!(codes.len(), all.len());
    assert!(codes.iter().all(|c| c.starts_with("LOOKAHEAD_")));
}

// ---- a seeded schedule

/// SplitMix64, the same generator the Python mirror uses.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

fn schedule_limits() -> LookaheadLimits {
    LookaheadLimits {
        max_bytes: 100_000,
        max_media_ms: 12_000,
        max_chunks: 16,
        max_chunk_bytes: 20_000,
        max_outstanding: 4,
        ready_min_media_ms: 1_000,
    }
}

// outcome classes counted by the schedule
const PUSH_OK: usize = 0;
const PUSH_LATE: usize = 1;
const PUSH_AHEAD: usize = 2;
const PUSH_GAP: usize = 3;
const PUSH_FULL: usize = 4;
const PUSH_OTHER_REFUSED: usize = 5;
const POP_OK: usize = 6;
const POP_GATED: usize = 7;
const SHRINK_EVICTING: usize = 8;
const BEGIN_IMMEDIATE: usize = 9;
const BEGIN_FENCED: usize = 10;
const BEGIN_SUPERSEDING: usize = 11;
const ACK_DRAINED: usize = 12;
const ACK_FLUSHED: usize = 13;
const ACK_REFUSED_UNDRAINED: usize = 14;
const ACK_REFUSED_IDENTITY: usize = 15;
const ACK_TIMED_OUT: usize = 16;
const ACK_NONE_PENDING: usize = 17;
const POP_LIMIT: usize = 18;
const RETIRE_SUBMITTED: usize = 19;
const RETIRE_CANCELLED: usize = 20;
const ACK_BARRIER: usize = 21;
const CLASSES: usize = 22;

/// What the test itself knows about the queue's transition state, kept apart from the queue.
struct Shadow {
    epoch: u64,
    /// The epoch of the newest chunk handed out and not yet fenced.
    unfenced: Option<u64>,
    /// The request of the transition awaiting its fence, if any.
    request: Option<FenceRequest>,
    failed: bool,
    last_token: u64,
    /// The tickets of handed-out chunks that have not retired.
    tickets: Vec<HandoffTicket>,
    /// Where the submissions of the unfenced epoch end, in output frames.
    submitted: Option<u64>,
}

fn check_invariants(q: &LookaheadQueue, shadow: &Shadow) {
    let sum_bytes: usize = q.chunks.iter().map(|c| c.payload.len()).sum();
    let sum_ns: u64 = q.chunks.iter().map(charge_ns).sum();
    assert_eq!(
        (q.bytes, q.media_ns, q.chunks.len()),
        (sum_bytes, sum_ns, q.stats().chunks)
    );
    let lim = q.limits();
    assert!(q.bytes <= lim.max_bytes);
    assert!(q.media_ns <= lim.max_media_ms * 1_000_000);
    assert!(q.chunks.len() <= lim.max_chunks);
    // every retained chunk meets the per-chunk limit in force now, and owns exactly the bytes charged
    assert!(
        q.chunks
            .iter()
            .all(|c| c.payload.len() <= lim.max_chunk_bytes)
    );
    assert_eq!(
        q.chunks.iter().map(|c| c.payload.capacity()).sum::<usize>(),
        q.bytes
    );
    assert_eq!(q.epoch().get(), shadow.epoch);
    let mut expect: Option<(TrackSerial, u64)> = None;
    for c in &q.chunks {
        assert_eq!(c.epoch, q.epoch());
        if let Some(position) = expect {
            assert_eq!((c.track, c.start_frame), position);
        }
        expect = Some(if c.last_of_track {
            (TrackSerial::new(c.track.get() + 1), 0)
        } else {
            (c.track, c.start_frame + u64::from(c.frames))
        });
    }
    if let Some(position) = expect {
        assert_eq!(q.fetch_position(), position);
    }
    let status = q.transition_status();
    assert_eq!(status == TransitionStatus::Failed, shadow.failed);
    assert_eq!(
        status == TransitionStatus::AwaitingFence,
        shadow.request.is_some() && !shadow.failed
    );
    assert_eq!(q.outstanding.len(), shadow.tickets.len());
    assert!(q.outstanding.len() <= lim.max_outstanding);
    assert!(
        q.outstanding
            .iter()
            .all(|t| Some(t.epoch()) == q.output_epoch)
    );
    assert_eq!(q.submitted.map(|p| p.frame), shadow.submitted);
}

fn run_schedule(seed: u64) -> [u64; CLASSES] {
    let mut rng = Rng(seed);
    let mut seen = [0_u64; CLASSES];
    let mut q = LookaheadQueue::new(schedule_limits(), E1, T0, 0).unwrap();
    let mut shadow = Shadow {
        epoch: 1,
        unfenced: None,
        request: None,
        failed: false,
        last_token: 0,
        tickets: Vec::new(),
        submitted: None,
    };
    for _ in 0..600 {
        let op = rng.below(100);
        if op < 45 {
            // a chunk at the position the queue asks for, 500..2000 ms at 96 or 320 kbit/s
            let (track, start) = q.fetch_position();
            let media_ms = 500 * (1 + u32::try_from(rng.below(4)).unwrap());
            let rate = if rng.below(2) == 0 { 12 } else { 40 };
            let mut c = chunk(
                q.epoch(),
                track,
                start,
                media_ms * 48,
                media_ms as usize * rate,
            );
            c.last_of_track = rng.below(8) == 0;
            match q.push(c) {
                Ok(()) => seen[PUSH_OK] += 1,
                Err(LookaheadError::Full { .. }) => seen[PUSH_FULL] += 1,
                Err(_) => seen[PUSH_OTHER_REFUSED] += 1,
            }
        } else if op < 52 {
            // a chunk of an older epoch (or a future one when there is no older)
            let (track, start) = q.fetch_position();
            if shadow.epoch > 1 {
                let r = q.push(chunk(
                    SourceEpoch::new(shadow.epoch - 1),
                    track,
                    start,
                    RATE,
                    12_000,
                ));
                assert!(matches!(r, Err(LookaheadError::LateOldEpoch { .. })));
                seen[PUSH_LATE] += 1;
            } else {
                let r = q.push(chunk(
                    SourceEpoch::new(shadow.epoch + 1),
                    track,
                    start,
                    RATE,
                    12_000,
                ));
                assert!(matches!(r, Err(LookaheadError::EpochAhead { .. })));
                seen[PUSH_AHEAD] += 1;
            }
        } else if op < 56 {
            let (track, start) = q.fetch_position();
            let gap = 1 + rng.below(500);
            let r = q.push(chunk(q.epoch(), track, start + gap, RATE, 12_000));
            assert!(matches!(r, Err(LookaheadError::NotContiguous { .. })));
            seen[PUSH_GAP] += 1;
        } else if op < 72 {
            match q.pop() {
                Ok(Some(h)) => {
                    shadow.unfenced = Some(h.chunk.epoch.get());
                    shadow.tickets.push(h.ticket);
                    assert_eq!(q.playback_track(), Some(h.chunk.track));
                    seen[POP_OK] += 1;
                }
                Ok(None) => {}
                Err(LookaheadError::OutstandingLimit { .. }) => {
                    assert_eq!(shadow.tickets.len(), schedule_limits().max_outstanding);
                    seen[POP_LIMIT] += 1;
                }
                Err(e) => {
                    assert!(shadow.request.is_some() || shadow.failed, "{e}");
                    seen[POP_GATED] += 1;
                }
            }
        } else if op < 80 {
            // retire one outstanding handoff: submitted (ending somewhere in the output domain) or cancelled
            if !shadow.tickets.is_empty() {
                let len = u64::try_from(shadow.tickets.len()).unwrap();
                let index = usize::try_from(rng.below(len)).unwrap();
                let mode = rng.below(2);
                let ticket = shadow.tickets[index].clone();
                if mode == 0 {
                    let end = rng.below(5000);
                    q.retire(&ticket, Retirement::Submitted { end: at(end) })
                        .unwrap();
                    shadow.submitted = Some(shadow.submitted.map_or(end, |have| have.max(end)));
                    seen[RETIRE_SUBMITTED] += 1;
                } else {
                    q.retire(&ticket, Retirement::Cancelled).unwrap();
                    seen[RETIRE_CANCELLED] += 1;
                }
                shadow.tickets.remove(index);
                assert!(!q.may_submit(&ticket));
            }
        } else if op < 85 {
            let max_bytes = 20_000 + usize::try_from(rng.below(80_000)).unwrap();
            let next = LookaheadLimits {
                max_bytes,
                max_media_ms: 2_000 + rng.below(10_000),
                max_chunks: 1 + usize::try_from(rng.below(16)).unwrap(),
                max_chunk_bytes: 6_000 + usize::try_from(rng.below(14_001)).unwrap(),
                ..schedule_limits()
            };
            let gone = q.shrink_to(next).unwrap();
            if gone.chunks > 0 {
                seen[SHRINK_EVICTING] += 1;
            }
        } else if op < 90 {
            let epoch = shadow.epoch + 1 + rng.below(3);
            let before = q.transition_status();
            let start = q
                .begin_transition(SourceEpoch::new(epoch), T0, rng.below(60_000))
                .unwrap();
            shadow.epoch = epoch;
            assert_eq!(start.superseded, before != TransitionStatus::Idle);
            assert_eq!(start.fence.is_some(), shadow.unfenced.is_some());
            shadow.failed = false;
            match start.fence {
                Some(req) => {
                    assert_eq!(Some(req.epoch.get()), shadow.unfenced);
                    assert!(req.token.get() > shadow.last_token);
                    shadow.last_token = req.token.get();
                    shadow.request = Some(req);
                    seen[BEGIN_FENCED] += 1;
                    if start.superseded {
                        seen[BEGIN_SUPERSEDING] += 1;
                    }
                }
                None => {
                    shadow.request = None;
                    seen[BEGIN_IMMEDIATE] += 1;
                }
            }
            assert_eq!(q.stats().chunks, 0, "the old timeline is gone at once");
        } else {
            // an acknowledgment attempt of one of six kinds against whatever request is outstanding
            let kind = rng.below(6);
            let need = shadow.submitted.unwrap_or(0);
            // kinds 1, 3 and 4 carry a flush acknowledgment (3 and 4 under a wrong epoch or token)
            let outcome = match kind {
                0 => drained(need, need),
                2 => drained(need + 10, need + 9),
                5 => timed_out(3),
                _ => flushed(2),
            };
            let mut renderer = Renderer::new(outcome);
            if kind == 3 {
                renderer = renderer.lying_epoch(100);
            } else if kind == 4 {
                renderer = renderer.lying_token(100);
            }
            let result = q.ack_transition(&mut renderer);
            if shadow.request.is_none() {
                assert_eq!(result, Err(LookaheadError::NoTransition));
                assert!(renderer.asked.is_empty());
                seen[ACK_NONE_PENDING] += 1;
            } else if shadow.failed {
                assert_eq!(result, Err(LookaheadError::TransitionFailed));
                assert!(renderer.asked.is_empty());
            } else if !shadow.tickets.is_empty() {
                // decoder work is outstanding: the device cannot see it, so nothing may be acknowledged
                let outstanding = shadow.tickets.len();
                assert_eq!(
                    result,
                    Err(LookaheadError::OutstandingDecoderWork { outstanding })
                );
                assert!(renderer.asked.is_empty());
                seen[ACK_BARRIER] += 1;
            } else {
                assert_eq!(renderer.asked.as_slice(), shadow.request.as_slice());
                match (kind, result) {
                    (0, Ok(ack)) => {
                        assert_eq!(ack.via, FenceKind::Drained);
                        seen[ACK_DRAINED] += 1;
                        shadow.request = None;
                        shadow.unfenced = None;
                        shadow.submitted = None;
                    }
                    (1, Ok(ack)) => {
                        assert_eq!(ack.via, FenceKind::Flushed);
                        seen[ACK_FLUSHED] += 1;
                        shadow.request = None;
                        shadow.unfenced = None;
                        shadow.submitted = None;
                    }
                    (2, Err(LookaheadError::OutputNotDrained { .. })) => {
                        seen[ACK_REFUSED_UNDRAINED] += 1
                    }
                    (3, Err(LookaheadError::FenceEpochMismatch { .. }))
                    | (4, Err(LookaheadError::FenceTokenStale { .. })) => {
                        seen[ACK_REFUSED_IDENTITY] += 1
                    }
                    (5, Err(LookaheadError::FlushTimedOut)) => {
                        seen[ACK_TIMED_OUT] += 1;
                        shadow.failed = true;
                    }
                    (kind, other) => panic!("kind {kind} gave {other:?}"),
                }
            }
        }
        check_invariants(&q, &shadow);
    }
    seen
}

#[test]
fn a_seeded_schedule_keeps_every_invariant_and_never_acknowledges_without_the_renderers_evidence() {
    let mut total = [0_u64; CLASSES];
    for seed in 0..8 {
        let seen = run_schedule(seed);
        for (sum, one) in total.iter_mut().zip(seen) {
            *sum += one;
        }
    }
    // Floors are about a third of the Python mirror's totals for seeds 0..8 (474, 324, 12, 200, 70,
    // 1612, 149, 478, 35, 32, 198, 143, 18, 33, 38, 52, 24, 176, 3, 78, 64, 70).
    let floors: [(usize, &str, u64); CLASSES] = [
        (PUSH_OK, "push_ok", 158),
        (PUSH_LATE, "push_late", 108),
        (PUSH_AHEAD, "push_ahead", 4),
        (PUSH_GAP, "push_gap", 66),
        (PUSH_FULL, "push_full", 23),
        (PUSH_OTHER_REFUSED, "push_other_refused", 537),
        (POP_OK, "pop_ok", 49),
        (POP_GATED, "pop_gated", 159),
        (SHRINK_EVICTING, "shrink_evicting", 11),
        (BEGIN_IMMEDIATE, "begin_immediate", 10),
        (BEGIN_FENCED, "begin_fenced", 66),
        (BEGIN_SUPERSEDING, "begin_superseding", 47),
        (ACK_DRAINED, "ack_drained", 6),
        (ACK_FLUSHED, "ack_flushed", 11),
        (ACK_REFUSED_UNDRAINED, "ack_refused_undrained", 12),
        (ACK_REFUSED_IDENTITY, "ack_refused_identity", 17),
        (ACK_TIMED_OUT, "ack_timed_out", 8),
        (ACK_NONE_PENDING, "ack_none_pending", 58),
        (POP_LIMIT, "pop_limit", 1),
        (RETIRE_SUBMITTED, "retire_submitted", 26),
        (RETIRE_CANCELLED, "retire_cancelled", 21),
        (ACK_BARRIER, "ack_barrier", 23),
    ];
    for (class, name, floor) in floors {
        assert!(total[class] >= floor, "{name}: {} < {floor}", total[class]);
    }
}
