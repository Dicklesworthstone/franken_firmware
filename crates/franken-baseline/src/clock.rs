//! The three clock domains a capture can carry, as three unrelated types.
//!
//! * [`MonoNs`] is the monotonic clock. It never steps, so every interval, gap and rate in this crate
//!   is measured on it.
//! * [`WallNs`] is the wall clock. It can be stepped by time sync, so it is only ever compared against
//!   the monotonic span of the same interval, to detect a step. It never decides whether audio was lost.
//! * [`DeviceFrames`] counts frames on the audio device's own sample clock. It runs at its own rate and
//!   drifts against the monotonic clock; the relationship is reported, never assumed.
//!
//! The types have no arithmetic between them. Converting between domains needs one of the explicit
//! functions below, which is where a reviewer looks for a mix-up.

/// A point on the monotonic clock, in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MonoNs(pub u64);

/// A length of monotonic time, in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MonoSpanNs(pub u64);

/// A point on the wall clock, in nanoseconds since an epoch. May be stepped in either direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WallNs(pub i64);

/// A cumulative frame count on the device sample clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeviceFrames(pub u64);

impl MonoNs {
    /// The monotonic time from `earlier` to `self`, or `None` if `earlier` is later.
    pub fn since(self, earlier: MonoNs) -> Option<MonoSpanNs> {
        self.0.checked_sub(earlier.0).map(MonoSpanNs)
    }
}

impl WallNs {
    /// How far the wall clock moved beyond (positive) or short of (negative) the monotonic span of the
    /// same interval. Zero means wall time and monotonic time agreed; anything else is a step.
    pub fn step_from(self, earlier: WallNs, mono_span: MonoSpanNs) -> i128 {
        (i128::from(self.0) - i128::from(earlier.0)) - i128::from(mono_span.0)
    }
}

impl DeviceFrames {
    /// Frames a device running at exactly `rate_hz` consumes in `span` of monotonic time (rounded down).
    pub fn expected_over(rate_hz: u64, span: MonoSpanNs) -> u64 {
        let frames = u128::from(span.0) * u128::from(rate_hz) / 1_000_000_000;
        u64::try_from(frames).unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_is_none_when_the_clock_would_go_backwards() {
        assert_eq!(MonoNs(5_000).since(MonoNs(2_000)), Some(MonoSpanNs(3_000)));
        assert_eq!(MonoNs(2_000).since(MonoNs(5_000)), None);
        assert_eq!(MonoNs(7).since(MonoNs(7)), Some(MonoSpanNs(0)));
    }

    #[test]
    fn wall_step_is_the_excess_over_the_monotonic_span() {
        // One second of monotonic time with exactly one second of wall time: no step.
        let a = WallNs(10_000_000_000);
        assert_eq!(
            WallNs(11_000_000_000).step_from(a, MonoSpanNs(1_000_000_000)),
            0
        );
        // The wall clock jumped forward an hour during that second.
        assert_eq!(
            WallNs(10_000_000_000 + 3_601_000_000_000).step_from(a, MonoSpanNs(1_000_000_000)),
            3_600_000_000_000
        );
        // And backwards by 2.5 s: 1 s elapsed on the monotonic clock, wall moved -1.5 s.
        assert_eq!(
            WallNs(8_500_000_000).step_from(a, MonoSpanNs(1_000_000_000)),
            -2_500_000_000
        );
    }

    #[test]
    fn expected_frames_round_down_and_do_not_overflow() {
        // 48 kHz for 1 s is 48 000 frames; for 1.5 ms it is 72.
        assert_eq!(
            DeviceFrames::expected_over(48_000, MonoSpanNs(1_000_000_000)),
            48_000
        );
        assert_eq!(
            DeviceFrames::expected_over(48_000, MonoSpanNs(1_500_000)),
            72
        );
        // 1 ns at 48 kHz is 0.000048 of a frame.
        assert_eq!(DeviceFrames::expected_over(48_000, MonoSpanNs(1)), 0);
        assert_eq!(
            DeviceFrames::expected_over(u64::MAX, MonoSpanNs(u64::MAX)),
            u64::MAX
        );
    }
}
