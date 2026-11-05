//! N04 section 14, item 3: a real N03 `GroupClock` connected to the engine through the three-integer seam
//! (`ClockView`). Until now the engine was only ever driven by scripted views; here every view is built from what a
//! locked `GroupClock` itself reports (`group_ns`, `report().uncertainty_ns`, `status`).
//!
//! What this shows, on a host with a scripted local clock and nothing else:
//! * the reading is within the clock's own stated uncertainty of the true offset (N03's claim, through the seam);
//! * the cutoff moves earlier by exactly the uncertainty the real clock reports, and that uncertainty grows with age;
//! * a block admitted at a real reading before the cutoff plays, the same arrival after the cutoff is late;
//! * Holdover is usable, and Expired, Unlocked and a clock with no samples are not (`clock_unusable`, nothing consumed).
//!
//! What it does not show: any DAC, network or board timing, and anything about a clock that is not N03's. The numbers
//! the clock reports (uncertainty, the time of expiry) are measured here, not re-derived by the Python reference.

use std::collections::BTreeMap;

use franken_clock::group::{
    ClockStatus, GroupClock, GroupClockConfig, ProbeResponse, base_uncertainty_ns,
};
use serde_json::json;

use super::*;

/// The coordinator's group clock runs this far ahead of the member's local clock, by construction.
const GOFF: u64 = 8_995_000_000_000;

/// Path delay of each exchange below: (t4 - t1) - (t3 - t2) = 450 000 - 50 000.
const DELAY_NS: u64 = 400_000;

const CFG: PlayoutConfig = PlayoutConfig {
    work_ns: 1_500_000,
    lead_ns: 2_000_000,
    tolerance_ns: 100_000,
};

fn observed(line: &serde_json::Value) {
    println!("N04-OBSERVED {line}");
}

fn standard() -> GroupClockConfig {
    GroupClockConfig::standard().expect("standard config")
}

/// A member that has taken `exchanges` exchanges (one a second, `DELAY_NS` of path delay each) with a coordinator whose
/// group clock is `GOFF` ahead of its own local clock. Returns it with the local time of the last response.
fn member_after(exchanges: u64) -> (GroupClock, u64) {
    let mut gc = GroupClock::new(standard(), 1, 7, 100).expect("member");
    let mut t4 = 0;
    for k in 0..exchanges {
        let t1 = 10_000_000_000 + k * 1_000_000_000;
        let req = gc.next_probe(t1);
        let resp = ProbeResponse {
            epoch: 1,
            leader: 7,
            seq: req.seq,
            t1_echo_ns: t1,
            t2_group_ns: t1 + GOFF + 200_000,
            t3_group_ns: t1 + GOFF + 250_000,
        };
        t4 = t1 + 450_000;
        gc.on_response(resp, t4).expect("accepted");
    }
    (gc, t4)
}

fn locked_member() -> (GroupClock, u64) {
    member_after(5)
}

/// The seam: the three integers a `ClockView` carries, from what the clock says at local time `now`. Usable exactly
/// while the status is Locked or Holdover; with no reading at all the view is unusable and says so.
fn view_of(gc: &GroupClock, now: u64) -> ClockView {
    let usable = matches!(gc.status(now), ClockStatus::Locked | ClockStatus::Holdover);
    match (gc.group_ns(now), gc.report(now).uncertainty_ns) {
        (Some(group_ns), Some(uncertainty_ns)) => ClockView {
            group_ns,
            uncertainty_ns,
            usable,
        },
        _ => ClockView {
            group_ns: 0,
            uncertainty_ns: 0,
            usable: false,
        },
    }
}

fn engine_at(anchor_group_ns: u64) -> PlayoutEngine {
    let mut eng = PlayoutEngine::new(PlayoutProfile::MUSIC, CFG).expect("valid config");
    eng.begin_stream(1, 0, anchor_group_ns).expect("binds");
    eng
}

fn block_zero(anchor: u64, payload: &[u8]) -> MediaPacket<'_> {
    MediaPacket {
        epoch: 1,
        start_frame: 0,
        presentation_ns: anchor,
        frames: 256,
        payload,
    }
}

#[test]
fn n04_group_clock_the_view_is_within_the_clocks_own_uncertainty_of_the_true_offset() {
    let (gc, t4) = locked_member();
    let now = t4 + 100_000_000;
    assert_eq!(gc.status(now), ClockStatus::Locked);
    let v = view_of(&gc, now);
    assert!(v.usable);
    let truth = now + GOFF;
    assert!(
        v.group_ns.abs_diff(truth) <= v.uncertainty_ns,
        "group {} is {} ns from the true {truth}; the clock claims {}",
        v.group_ns,
        v.group_ns.abs_diff(truth),
        v.uncertainty_ns
    );
    // The uncertainty is the clock's, not a constant: at least what one exchange cannot know about itself, and
    // within the lock threshold.
    let cfg = standard();
    assert!(
        v.uncertainty_ns >= base_uncertainty_ns(&cfg, DELAY_NS),
        "{v:?}"
    );
    assert!(v.uncertainty_ns <= cfg.lock_uncertainty_ns, "{v:?}");
}

#[test]
fn n04_group_clock_the_cutoff_moves_by_exactly_the_uncertainty_the_clock_reports() {
    let (gc, t4) = locked_member();
    let (early, later) = (t4 + 100_000_000, t4 + 2_500_000_000);
    assert_eq!(gc.status(later), ClockStatus::Locked, "still fresh");
    let (v0, v1) = (view_of(&gc, early), view_of(&gc, later));
    assert!(
        v1.uncertainty_ns > v0.uncertainty_ns,
        "uncertainty grows with age: {} then {}",
        v0.uncertainty_ns,
        v1.uncertainty_ns
    );
    let anchor = v1.group_ns + 1_000_000_000;
    let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
    let mut cutoffs = [0u64; 2];
    for (slot, v) in cutoffs.iter_mut().zip([v0, v1]) {
        let cutoff = consume_by(anchor, CFG.work_ns, CFG.lead_ns, v.uncertainty_ns);
        let mut eng = engine_at(anchor);
        let before = eng.decide(
            ClockView {
                group_ns: cutoff - 1,
                ..v
            },
            &mut out,
        );
        assert_eq!(before, Poll::Pending, "one nanosecond before the cutoff");
        let at = eng.decide(
            ClockView {
                group_ns: cutoff,
                ..v
            },
            &mut out,
        );
        assert!(
            matches!(at, Poll::Decision(d) if d.block == 0 && d.late_by_ns == 0),
            "at the cutoff: {at:?}"
        );
        *slot = cutoff;
    }
    assert_eq!(
        cutoffs[0] - cutoffs[1],
        v1.uncertainty_ns - v0.uncertainty_ns
    );
}

#[test]
fn n04_group_clock_a_block_admitted_at_a_real_reading_plays_and_the_same_arrival_after_the_cutoff_is_late()
 {
    let (gc, t4) = locked_member();
    let now = t4 + 100_000_000;
    // Block 0 is presented a second from now, by the group clock.
    let anchor = view_of(&gc, now).group_ns + 1_000_000_000;
    let payload = vec![0u8; BLOCK_PAYLOAD_BYTES];
    let local_at = |group_ns: u64| gc.local_for_group(group_ns, now).expect("a reading");

    // 500 ms before presentation: far ahead of the cutoff.
    let early = view_of(&gc, local_at(anchor - 500_000_000));
    assert!(early.usable);
    let mut eng = engine_at(anchor);
    assert_eq!(
        eng.on_packet(early, &block_zero(anchor, &payload)),
        Admission::Admitted
    );
    // 1 ms before presentation: after the cutoff (work + lead + uncertainty is at least 3.5 ms).
    let near = view_of(&gc, local_at(anchor - 1_000_000));
    let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
    let Poll::Decision(d) = eng.decide(near, &mut out) else {
        panic!("a decision was due: {near:?}");
    };
    assert_eq!(d.outcome, Outcome::Real);
    // Lateness is group time minus the cutoff: 3.5 ms - 1 ms plus the clock's own uncertainty, to rounding.
    assert!(
        d.late_by_ns.abs_diff(2_500_000 + near.uncertainty_ns) <= 1_000,
        "late by {} with uncertainty {}",
        d.late_by_ns,
        near.uncertainty_ns
    );

    // The same arrival, 1 ms before presentation, is late.
    let mut eng = engine_at(anchor);
    assert_eq!(
        eng.on_packet(near, &block_zero(anchor, &payload)),
        Admission::Late
    );
}

#[test]
fn n04_group_clock_holdover_is_usable_and_expired_unlocked_and_empty_clocks_are_not() {
    let (gc, t4) = locked_member();
    let mut first: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut now = t4;
    for _ in 0..100_000 {
        let status = gc.status(now);
        first.entry(status.code()).or_insert(now);
        if status == ClockStatus::Expired {
            break;
        }
        now += 100_000_000;
    }
    let seen: Vec<&str> = first.keys().copied().collect();
    assert_eq!(seen, ["Expired", "Holdover", "Locked"], "{first:?}");

    let payload = vec![0u8; BLOCK_PAYLOAD_BYTES];
    let mut out = [0u8; BLOCK_PAYLOAD_BYTES];

    // Holdover: usable, and the uncertainty has grown since it was Locked.
    let locked = view_of(&gc, t4);
    let hold = view_of(&gc, first["Holdover"]);
    assert!(hold.usable && locked.usable);
    assert!(hold.uncertainty_ns > locked.uncertainty_ns);
    let anchor = hold.group_ns + 1_000_000_000;
    let mut eng = engine_at(anchor);
    assert_eq!(
        eng.on_packet(hold, &block_zero(anchor, &payload)),
        Admission::Admitted
    );
    assert_eq!(eng.decide(hold, &mut out), Poll::Pending);
    assert_eq!(eng.snapshot().cursor, 0);

    // Expired: unusable. Nothing is admitted, nothing is decided, no block is consumed.
    let expired = view_of(&gc, first["Expired"]);
    assert!(!expired.usable);
    let mut eng = engine_at(anchor);
    assert_eq!(eng.decide(expired, &mut out), Poll::ClockUnusable);
    assert_eq!(
        eng.on_packet(expired, &block_zero(anchor, &payload)),
        Admission::ClockUnusable
    );
    let snap = eng.snapshot();
    assert_eq!((snap.cursor, snap.queued), (0, 0));
    assert_eq!(
        (snap.stats.clock_unusable_polls, snap.stats.clock_unusable),
        (1, 1)
    );

    // Two exchanges are not enough to lock: there is a reading, and it is unusable.
    let (young, t4_young) = member_after(2);
    let young_view = view_of(&young, t4_young + 1_000);
    assert_eq!(young.status(t4_young + 1_000), ClockStatus::Unlocked);
    assert!(young.group_ns(t4_young + 1_000).is_some() && !young_view.usable);
    let mut eng = engine_at(anchor);
    assert_eq!(eng.decide(young_view, &mut out), Poll::ClockUnusable);

    // No exchange at all: no reading, an unusable view.
    let empty = GroupClock::new(standard(), 1, 7, 1).expect("member");
    assert!(empty.group_ns(1).is_none());
    let empty_view = view_of(&empty, 1);
    assert!(!empty_view.usable);
    let mut eng = engine_at(anchor);
    assert_eq!(eng.decide(empty_view, &mut out), Poll::ClockUnusable);

    observed(&json!({
        "id": "n04-group-clock",
        "statuses_seen": seen,
        "holdover_usable": hold.usable,
        "holdover_decision": "pending",
        "expired_poll": "clock_unusable",
        "expired_admission": "clock_unusable",
        "expired_cursor": snap.cursor,
        "unlocked_with_reading_poll": "clock_unusable",
        "no_reading_poll": "clock_unusable",
        "uncertainty_locked_ns": locked.uncertainty_ns,
        "uncertainty_holdover_ns": hold.uncertainty_ns,
    }));
}
