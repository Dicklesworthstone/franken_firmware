//! Token-bucket rate limiting on an injected clock (N02 / `ffw-ugf`).
//!
//! The control channel limits each authenticated peer separately for each lane, so one peer's retry
//! storm cannot spend another peer's allowance, and a flood of ordinary commands cannot spend the
//! allowance a peer needs for a stop. Time is a plain `u64` of nanoseconds handed in by the caller:
//! there is no wall clock here, which keeps every test deterministic.
//!
//! A bucket starts full. It holds at most `burst` tokens and gains one token per `interval_ns`. Taking
//! a token that is not there is refused with the exact wait until the next one, never with a guess.
//! Progress toward the next token is kept across calls (half an interval of waiting is not lost when a
//! token is taken), and a clock that moves backwards is ignored rather than allowed to spend or refund
//! anything.

/// A limit: at most `burst` actions at once, then one more every `interval_ns`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    burst: u32,
    interval_ns: u64,
}

/// A limit that cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LimiterError {
    #[error("a rate limit needs a burst of at least one token")]
    ZeroBurst,
    #[error("a rate limit needs a refill interval of at least one nanosecond")]
    ZeroInterval,
}

impl RateLimit {
    /// Both parameters must be non-zero: a zero burst never admits anything and a zero interval would
    /// refill without bound.
    pub const fn new(burst: u32, interval_ns: u64) -> Result<Self, LimiterError> {
        if burst == 0 {
            return Err(LimiterError::ZeroBurst);
        }
        if interval_ns == 0 {
            return Err(LimiterError::ZeroInterval);
        }
        Ok(Self { burst, interval_ns })
    }

    #[must_use]
    pub const fn burst(&self) -> u32 {
        self.burst
    }

    #[must_use]
    pub const fn interval_ns(&self) -> u64 {
        self.interval_ns
    }
}

/// One bucket for one `(peer, lane)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenBucket {
    limit: RateLimit,
    tokens: u32,
    last_ns: u64,
}

impl TokenBucket {
    /// A full bucket as of `now_ns`.
    #[must_use]
    pub const fn new(limit: RateLimit, now_ns: u64) -> Self {
        Self {
            limit,
            tokens: limit.burst,
            last_ns: now_ns,
        }
    }

    /// Tokens currently available, as of the last call.
    #[must_use]
    pub const fn tokens(&self) -> u32 {
        self.tokens
    }

    fn refill(&mut self, now_ns: u64) {
        if now_ns <= self.last_ns {
            return;
        }
        let intervals = (now_ns - self.last_ns) / self.limit.interval_ns;
        if intervals == 0 {
            return;
        }
        let room = u64::from(self.limit.burst - self.tokens);
        if intervals >= room {
            // Full. Time spent full earns nothing, so the next token is measured from now.
            self.tokens = self.limit.burst;
            self.last_ns = now_ns;
        } else {
            self.tokens += u32::try_from(intervals).unwrap_or(self.limit.burst);
            self.last_ns += intervals * self.limit.interval_ns;
        }
    }

    /// Take one token, or learn how many nanoseconds to wait for the next one. A refused call takes
    /// nothing and changes nothing but the bookkeeping of elapsed time.
    pub fn try_take(&mut self, now_ns: u64) -> Result<(), u64> {
        self.refill(now_ns);
        if self.tokens > 0 {
            self.tokens -= 1;
            return Ok(());
        }
        let next_at = self.last_ns.saturating_add(self.limit.interval_ns);
        Err(next_at.saturating_sub(now_ns).max(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    fn limit(burst: u32, interval_ms: u64) -> RateLimit {
        RateLimit::new(burst, interval_ms * MS).unwrap()
    }

    #[test]
    fn a_limit_needs_a_burst_and_an_interval() {
        assert_eq!(RateLimit::new(0, 5), Err(LimiterError::ZeroBurst));
        assert_eq!(RateLimit::new(3, 0), Err(LimiterError::ZeroInterval));
        let ok = RateLimit::new(3, 7).unwrap();
        assert_eq!((ok.burst(), ok.interval_ns()), (3, 7));
    }

    #[test]
    fn a_new_bucket_is_full_and_spends_its_burst_then_refuses_with_the_exact_wait() {
        let mut bucket = TokenBucket::new(limit(3, 100), 0);
        assert_eq!(bucket.tokens(), 3);
        for _ in 0..3 {
            assert_eq!(bucket.try_take(0), Ok(()));
        }
        // Empty at t = 0: the next token is one full interval away.
        assert_eq!(bucket.try_take(0), Err(100 * MS));
        // 40 ms later, 60 ms remain.
        assert_eq!(bucket.try_take(40 * MS), Err(60 * MS));
        assert_eq!(bucket.tokens(), 0);
    }

    #[test]
    fn a_token_arrives_exactly_on_the_interval_and_not_a_nanosecond_before() {
        let mut bucket = TokenBucket::new(limit(1, 100), 0);
        assert_eq!(bucket.try_take(0), Ok(()));
        assert_eq!(bucket.try_take(100 * MS - 1), Err(1));
        assert_eq!(bucket.try_take(100 * MS), Ok(()));
        assert!(bucket.try_take(100 * MS).is_err());
    }

    #[test]
    fn progress_toward_the_next_token_is_kept_when_a_token_is_taken() {
        let mut bucket = TokenBucket::new(limit(2, 100), 0);
        assert_eq!(bucket.try_take(0), Ok(()));
        assert_eq!(bucket.try_take(0), Ok(()));
        // 150 ms: one token earned and 50 ms of progress toward the next.
        assert_eq!(bucket.try_take(150 * MS), Ok(()));
        // The next token is due at 200 ms, 50 ms from now, not 100.
        assert_eq!(bucket.try_take(150 * MS), Err(50 * MS));
        assert_eq!(bucket.try_take(200 * MS), Ok(()));
    }

    #[test]
    fn idle_time_never_banks_more_than_the_burst() {
        let mut bucket = TokenBucket::new(limit(3, 100), 0);
        for _ in 0..3 {
            bucket.try_take(0).unwrap();
        }
        // An hour of silence earns three tokens, not thirty-six thousand.
        let hour = 3_600_000 * MS;
        for _ in 0..3 {
            assert_eq!(bucket.try_take(hour), Ok(()));
        }
        assert!(bucket.try_take(hour).is_err());
    }

    #[test]
    fn time_spent_full_earns_no_credit_toward_the_next_token() {
        let mut bucket = TokenBucket::new(limit(2, 100), 0);
        // Idle until t = 10 s with a full bucket, then spend both.
        assert_eq!(bucket.try_take(10_000 * MS), Ok(()));
        assert_eq!(bucket.try_take(10_000 * MS), Ok(()));
        // The refill clock restarted at 10 s: the next token is a full interval after it.
        assert_eq!(bucket.try_take(10_000 * MS), Err(100 * MS));
    }

    #[test]
    fn a_clock_that_runs_backwards_neither_spends_nor_refunds() {
        let mut bucket = TokenBucket::new(limit(2, 100), 1_000 * MS);
        bucket.try_take(1_000 * MS).unwrap();
        bucket.try_take(1_000 * MS).unwrap();
        // Time goes back to t = 0: no token appears.
        assert!(bucket.try_take(0).is_err());
        // And the next real token is still measured from t = 1000 ms.
        assert_eq!(bucket.try_take(1_100 * MS), Ok(()));
    }

    #[test]
    fn a_refused_take_leaves_the_bucket_able_to_serve_later() {
        let mut bucket = TokenBucket::new(limit(1, 100), 0);
        bucket.try_take(0).unwrap();
        for t in [1, 2, 3, 50, 99] {
            assert!(bucket.try_take(t * MS).is_err(), "t = {t} ms");
        }
        assert_eq!(bucket.try_take(100 * MS), Ok(()));
    }

    #[test]
    fn the_wait_is_never_zero() {
        let mut bucket = TokenBucket::new(limit(1, 1), 0);
        bucket.try_take(0).unwrap();
        for t in 0..1_000_000 {
            if let Err(wait) = bucket.try_take(t) {
                assert!(wait >= 1, "t = {t}");
            }
        }
    }
}
