//! Convert the admitted group clock into a monotonic playout view without hiding clock-fit steps.
//!
//! Holding a reading steady after a backwards fit adjustment increases its error bound by the
//! distance held. The adjusted bound must still satisfy the clock's admission policy; otherwise
//! the renderer receives an unusable view and remains muted. This is a clock-fit bound, not a
//! measurement of DAC or acoustic alignment.
//!
//! A usable view permits timing calculations, including buffering for a future start. It does
//! not authorize audible output: the owner must also honor [`GroupClock::tick`] and its output
//! admission, including start, authority and buffer expiry.

use franken_clock::group::{ClockStatus, GroupClock};
use franken_stream::playout::ClockView;

/// One renderer's monotonic view of its group clock. Keep this alongside its playout engine.
#[derive(Debug, Default)]
pub struct ClockViewBridge {
    epoch: Option<u64>,
    last_group_ns: u64,
    clamped: u64,
}

impl ClockViewBridge {
    /// Read using the platform's local monotonic time, in nanoseconds.
    ///
    /// An expired, unbounded or over-budget reading never advances the last usable time. In
    /// particular, a failed clock's extrapolation cannot poison subsequent recovery with a
    /// spurious far-future latch.
    pub fn at_local(&mut self, clock: &GroupClock, local_ns: u64) -> ClockView {
        // A newly admitted epoch has its own timestamp interpretation. Do not carry a latch
        // from a prior leader across it; transient loss of lock within the same epoch must
        // still preserve the latch. The owner also rebinds its playout engine for the epoch.
        if self.epoch != Some(clock.epoch()) {
            self.epoch = Some(clock.epoch());
            self.last_group_ns = 0;
        }
        let usable = matches!(
            clock.status(local_ns),
            ClockStatus::Locked | ClockStatus::Holdover
        );
        self.bounded_view(
            clock.group_ns(local_ns),
            clock.report(local_ns).uncertainty_ns,
            usable,
            clock.config().lock_uncertainty_ns,
        )
    }

    /// Readings actually raised to the previous usable group time.
    #[must_use]
    pub const fn clamped_readings(&self) -> u64 {
        self.clamped
    }

    /// An explicitly admitted new playout timeline also discards the old engine's reading.
    /// Keep the lifetime diagnostic count; only the time latch belongs to the old timeline.
    pub(crate) fn rebind(&mut self, clock: &GroupClock) {
        self.epoch = Some(clock.epoch());
        self.last_group_ns = 0;
    }

    fn bounded_view(
        &mut self,
        group_ns: Option<u64>,
        uncertainty_ns: Option<u64>,
        usable: bool,
        limit_ns: u64,
    ) -> ClockView {
        let refused = |uncertainty_ns| ClockView {
            group_ns: self.last_group_ns,
            uncertainty_ns,
            usable: false,
        };
        let (Some(group_ns), Some(uncertainty_ns)) = (group_ns, uncertainty_ns) else {
            return refused(uncertainty_ns.unwrap_or(u64::MAX));
        };
        if !usable {
            return refused(uncertainty_ns);
        }
        let held_ns = self.last_group_ns.saturating_sub(group_ns);
        let Some(adjusted_uncertainty_ns) = uncertainty_ns.checked_add(held_ns) else {
            return refused(u64::MAX);
        };
        if adjusted_uncertainty_ns > limit_ns {
            return refused(adjusted_uncertainty_ns);
        }
        ClockView {
            group_ns: self.stamp(group_ns),
            uncertainty_ns: adjusted_uncertainty_ns,
            usable: true,
        }
    }

    pub(crate) fn stamp(&mut self, group_ns: u64) -> u64 {
        if group_ns < self.last_group_ns {
            self.clamped = self.clamped.saturating_add(1);
            return self.last_group_ns;
        }
        self.last_group_ns = group_ns;
        group_ns
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use franken_clock::group::{GroupClockConfig, ProbeResponse};

    fn lock_at(clock: &mut GroupClock, local_origin_ns: u64, group_origin_ns: u64) {
        for k in 1..=4_u64 {
            let offset = k * 10_000_000;
            let t1 = local_origin_ns + offset;
            let req = clock.next_probe(t1);
            clock
                .on_response(
                    ProbeResponse {
                        epoch: clock.epoch(),
                        leader: clock.leader(),
                        seq: req.seq,
                        t1_echo_ns: req.t1_local_ns,
                        t2_group_ns: group_origin_ns + offset + 400_000,
                        t3_group_ns: group_origin_ns + offset + 450_000,
                    },
                    t1 + 850_000,
                )
                .expect("accepted exchange");
        }
    }

    #[test]
    fn clock_view_rebinds_a_new_epoch_without_inheriting_the_old_leaders_time() {
        let cfg = GroupClockConfig::standard().expect("config");
        let mut clock = GroupClock::new(cfg, 1, 7, 100).expect("clock");
        let mut bridge = ClockViewBridge::default();
        lock_at(&mut clock, 0, 100_000_000_000);
        let old = bridge.at_local(&clock, 50_000_000);
        assert!(old.usable);
        assert!(old.group_ns > 100_000_000_000);
        clock.begin_epoch(2, 8).expect("admit new epoch and leader");
        assert!(!bridge.at_local(&clock, 60_000_000).usable);
        lock_at(&mut clock, 60_000_000, 1_000_000_000);
        let new = bridge.at_local(&clock, 110_000_000);
        assert!(
            new.usable,
            "new timeline does not wait for the old leader's clock"
        );
        assert_eq!(Some(new.group_ns), clock.group_ns(110_000_000));
        assert!(new.group_ns < 2_000_000_000);
        // A backwards view in this admitted epoch must still be clamped and charged.
        let backwards = bridge.at_local(&clock, 109_900_000);
        assert!(backwards.usable);
        assert_eq!(backwards.group_ns, new.group_ns);
        assert_eq!(
            backwards.uncertainty_ns,
            clock
                .report(109_900_000)
                .uncertainty_ns
                .expect("bounded fit")
                + 100_000
        );
        assert_eq!(bridge.clamped_readings(), 1);
    }

    #[test]
    fn clock_view_clamp_preserves_the_injected_truth_interval() {
        let mut bridge = ClockViewBridge::default();
        assert!(bridge.bounded_view(Some(1_000), Some(10), true, 200).usable);
        // A refit now estimates 900 ns with a 20 ns bound: truth can be 880..=920 ns.
        let view = bridge.bounded_view(Some(900), Some(20), true, 200);
        assert_eq!(view.group_ns, 1_000);
        assert_eq!(view.uncertainty_ns, 120);
        assert!(view.usable);
        for truth in [880, 900, 920] {
            assert!(view.group_ns.abs_diff(truth) <= view.uncertainty_ns);
        }
        assert_eq!(bridge.clamped_readings(), 1);
    }

    #[test]
    fn clock_view_refuses_a_clamp_above_policy_and_recovers_without_latching_it() {
        let mut bridge = ClockViewBridge::default();
        assert!(bridge.bounded_view(Some(1_000), Some(20), true, 120).usable);
        let boundary = bridge.bounded_view(Some(900), Some(20), true, 120);
        assert!(
            boundary.usable,
            "the inclusive policy boundary is permitted"
        );
        let beyond = bridge.bounded_view(Some(899), Some(20), true, 120);
        assert!(!beyond.usable);
        assert_eq!(beyond.uncertainty_ns, 121);
        assert_eq!(
            bridge.clamped_readings(),
            1,
            "a refused clamp is not applied"
        );
        assert!(
            !bridge
                .bounded_view(Some(9_000), Some(121), true, 120)
                .usable
        );
        let recovered = bridge.bounded_view(Some(1_001), Some(20), true, 120);
        assert!(recovered.usable);
        assert_eq!(
            recovered.group_ns, 1_001,
            "over-budget future reading did not latch"
        );
    }

    #[test]
    fn clock_view_uncertainty_overflow_is_unusable_even_at_the_largest_policy_limit() {
        let mut bridge = ClockViewBridge::default();
        assert!(
            bridge
                .bounded_view(Some(100), Some(1), true, u64::MAX)
                .usable
        );
        let overflow = bridge.bounded_view(Some(99), Some(u64::MAX), true, u64::MAX);
        assert!(!overflow.usable);
        assert_eq!(overflow.uncertainty_ns, u64::MAX);
        assert_eq!(overflow.group_ns, 100);
        assert_eq!(bridge.clamped_readings(), 0);
        assert!(
            bridge
                .bounded_view(Some(101), Some(1), true, u64::MAX)
                .usable
        );
    }

    #[test]
    fn clock_view_missing_or_unusable_readings_never_move_the_latch() {
        let mut bridge = ClockViewBridge::default();
        assert!(bridge.bounded_view(Some(100), Some(1), true, 200).usable);
        for (group, uncertainty, usable) in [
            (Some(10_000), Some(1), false),
            (Some(10_000), None, true),
            (None, Some(1), true),
            (None, None, true),
        ] {
            let refused = bridge.bounded_view(group, uncertainty, usable, 200);
            assert!(!refused.usable);
            assert_eq!(refused.group_ns, 100);
        }
        let recovered = bridge.bounded_view(Some(101), Some(1), true, 200);
        assert_eq!(recovered.group_ns, 101);
        assert!(recovered.usable);
        assert_eq!(bridge.clamped_readings(), 0);
    }

    #[test]
    fn clock_view_uses_the_real_group_clock_bound_and_expires_with_it() {
        let cfg = GroupClockConfig::standard().expect("config");
        let mut clock = GroupClock::new(cfg, 1, 7, 100).expect("clock");
        let mut bridge = ClockViewBridge::default();
        assert!(!bridge.at_local(&clock, 0).usable);
        for k in 1..=4_u64 {
            let t1 = k * 10_000_000;
            let req = clock.next_probe(t1);
            clock
                .on_response(
                    ProbeResponse {
                        epoch: 1,
                        leader: 7,
                        seq: req.seq,
                        t1_echo_ns: req.t1_local_ns,
                        t2_group_ns: t1 + 400_000,
                        t3_group_ns: t1 + 450_000,
                    },
                    t1 + 850_000,
                )
                .expect("accepted exchange");
        }
        let local_ns = 50_000_000;
        let good = bridge.at_local(&clock, local_ns);
        assert!(good.usable);
        assert_eq!(Some(good.group_ns), clock.group_ns(local_ns));
        assert_eq!(
            Some(good.uncertainty_ns),
            clock.report(local_ns).uncertainty_ns
        );
        let old = bridge.at_local(&clock, 10_000_000_000_000);
        assert!(!old.usable);
        assert_eq!(old.group_ns, good.group_ns);
        let recovered = bridge.at_local(&clock, local_ns + 1_000_000);
        assert!(recovered.usable);
        assert!(recovered.group_ns < 100_000_000);
    }
}
