//! Authenticated wall time for credential validity, independent of audio time (P02).
//!
//! An unreliable RTC or an unauthenticated network date cannot bootstrap TLS. This
//! client instead authenticates a fresh nonce and a time interval with an explicitly
//! provisioned, dedicated time-authority key. It does not open a network connection,
//! provision that key, or establish that the authority's own clock is correct. Those
//! are integration/admission obligations; no provider is selected automatically.
//!
//! The nonce comes from the admitted platform entropy provider. A response covers
//! exactly `nonce || earliest_unix_ns_BE || latest_unix_ns_BE`, prefixed by a protocol
//! domain, with HMAC-SHA256. The full round trip widens the upper bound. Subsequent
//! estimates advance using the same platform's monotonic clock, with outward-rounded
//! drift bounds and a finite holdover. Never use these estimates for audio deadlines.
//!
//! The client binds to one platform clock epoch and refuses another, including
//! after the first is dropped. Recreate it after replacing that platform. Keys
//! and authenticated state cannot be deserialized;
//! the key is borrowed, never printed or copied into diagnostics. Physical clock,
//! secret provisioning and service/provider qualification remain separate gates.
//!
//! The Linux leaf currently uses CLOCK_MONOTONIC, which does not count suspend.
//! A runtime using that clock must call `invalidate_after_resume` before any
//! credential check after resume. Without that lifecycle integration the provider
//! is unqualified for suspend/resume; this module does not detect power events.

use crate::clock::ClockError;
use crate::entropy::EntropyError;
use crate::layer::{ClockEpoch, PlatformLayer};
use crate::ops::{KernelOps, Provenance};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

const DOMAIN: &[u8] = b"FFW-P02-TIME-V1\0";
pub const NONCE_BYTES: usize = 32;
pub const REPLY_BYTES: usize = 80;
type Authenticator = Hmac<Sha256>;

/// Explicit bounds for an admitted authority and monotonic clock. No guessed defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapPolicy {
    pub max_round_trip_ns: u64,
    pub max_holdover_ns: u64,
    pub max_uncertainty_ns: u64,
    /// Frequency error relative to real elapsed time: the monotonic counter's
    /// rate lies in `1 +/- ppm / 1_000_000`.
    pub oscillator_drift_ppm: u32,
    /// A larger disjoint correction invalidates wall-time confidence and requires
    /// a new bootstrap. It never steps the platform's monotonic audio clock.
    pub max_correction_ns: u64,
}

/// Inclusive bounds on actual Unix time; an estimate, not an exact timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeInterval {
    pub earliest_unix_ns: u64,
    pub latest_unix_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TimeError {
    #[error(
        "wall-time policy is invalid; supply finite nonzero bounds and drift below one million ppm"
    )]
    InvalidPolicy,
    #[error("no fresh authenticated wall time; bootstrap with the provisioned authority")]
    Unknown,
    #[error("simulated platform cannot authorize service authentication")]
    SimulatedPlatform,
    #[error("platform clock epoch changed; confidence withdrawn, recreate the clock client")]
    ClockEpochChanged,
    #[error("clock read uncertainty is unqualified; admit a nonzero resolution bound")]
    ClockResolutionUnavailable,
    #[error("secure bootstrap nonce unavailable: {0}")]
    Entropy(EntropyError),
    #[error("monotonic clock unavailable: {0}")]
    Clock(ClockError),
    #[error("no outstanding time challenge; begin a fresh bootstrap")]
    NoChallenge,
    #[error("invalid time-response length; expected exactly eighty bytes")]
    MalformedReply,
    #[error("time-response authentication failed")]
    Authentication,
    #[error("response belongs to another or an already consumed challenge")]
    WrongChallenge,
    #[error("time-response round trip exceeded the admitted bound")]
    RoundTripExceeded,
    #[error("time bounds are reversed, overflowed, or exceed admitted uncertainty")]
    InvalidInterval,
    #[error("authenticated time correction exceeds policy; confidence withdrawn, bootstrap again")]
    CorrectionRequiresBootstrap,
    #[error("monotonic clock regressed; confidence withdrawn, recreate the clock client")]
    MonotonicRegression,
    #[error("authenticated time holdover expired; refresh with the provisioned authority")]
    HoldoverExpired,
    #[error("credential validity window is empty or reversed")]
    InvalidCredentialWindow,
    #[error("credential is not yet valid")]
    NotYetValid,
    #[error("credential has expired")]
    Expired,
    #[error("time uncertainty overlaps credential activation; refresh time or retry later")]
    UncertainActivation,
    #[error("time uncertainty overlaps credential expiration; refresh time or renew credentials")]
    UncertainExpiration,
}

#[derive(Clone, Copy)]
struct Pending {
    nonce: [u8; NONCE_BYTES],
    sent_ns: u64,
}

#[derive(Clone, Copy)]
struct Anchor {
    interval: TimeInterval,
    mono_ns: u64,
}

/// Wall-time bootstrap and confidence. No `Debug`, `Clone`, serialization or key getter.
pub struct AuthenticatedWallClock<'key> {
    key: &'key [u8; 32],
    policy: BootstrapPolicy,
    pending: Option<Pending>,
    anchor: Option<Anchor>,
    last_mono_ns: Option<u64>,
    regressed: bool,
    epoch: Option<ClockEpoch>,
    epoch_changed: bool,
    /// Maximum quantization error of each clock read. Zero only before binding;
    /// public operations bind a nonzero admitted resolution bound first.
    read_uncertainty_ns: u64,
}

impl<'key> AuthenticatedWallClock<'key> {
    /// Select a provisioned authority. No time is trusted until a fresh response
    /// authenticates. The key must be dedicated to this device's time bootstrap.
    pub fn new(key: &'key [u8; 32], policy: BootstrapPolicy) -> Result<Self, TimeError> {
        if policy.max_round_trip_ns == 0
            || policy.max_holdover_ns == 0
            || policy.max_uncertainty_ns == 0
            || policy.oscillator_drift_ppm >= 1_000_000
        {
            return Err(TimeError::InvalidPolicy);
        }
        Ok(Self {
            key,
            policy,
            pending: None,
            anchor: None,
            last_mono_ns: None,
            regressed: false,
            epoch: None,
            epoch_changed: false,
            read_uncertainty_ns: 0,
        })
    }

    /// Start/replace one pending challenge using real admitted secure entropy.
    /// Failure leaves any still-fresh previous anchor intact. There is no RNG fallback.
    pub fn begin<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
    ) -> Result<[u8; NONCE_BYTES], TimeError> {
        let now = self.platform_now(platform)?;
        let mut nonce = [0; NONCE_BYTES];
        platform
            .fill_random(&mut nonce)
            .map_err(TimeError::Entropy)?;
        self.pending = Some(Pending {
            nonce,
            sent_ns: now,
        });
        Ok(nonce)
    }

    /// Authenticate an exact-length response to the current challenge. Unauthenticated
    /// traffic never replaces a valid anchor or consumes a pending legitimate response.
    pub fn accept<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        reply: &[u8],
    ) -> Result<TimeInterval, TimeError> {
        let now = self.platform_now(platform)?;
        self.accept_at(now, reply)
    }

    /// Current confidence from the same monotonic platform epoch used by `begin`.
    pub fn interval<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
    ) -> Result<TimeInterval, TimeError> {
        let now = self.platform_now(platform)?;
        self.interval_at(now)
    }

    /// Authorize a service credential only if the *whole* confidence interval lies
    /// inside `[not_before, expires)`. Protocol adapters still own chain/signature,
    /// hostname, revocation and protocol-specific inclusive-boundary rules.
    pub fn check_credential<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        not_before_unix_ns: u64,
        expires_unix_ns: u64,
    ) -> Result<TimeInterval, TimeError> {
        let interval = self.interval(platform)?;
        check_window(interval, not_before_unix_ns, expires_unix_ns)?;
        Ok(interval)
    }

    /// Withdraw wall-time trust after suspend/resume or an equivalent discontinuity.
    /// The owner must run this before allowing service authentication to resume.
    /// Audio's monotonic clock is untouched; a fresh authority exchange is required.
    pub fn invalidate_after_resume(&mut self) {
        self.anchor = None;
        self.pending = None;
    }

    fn platform_now<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
    ) -> Result<u64, TimeError> {
        if platform.provenance() != Provenance::Kernel {
            return Err(TimeError::SimulatedPlatform);
        }
        self.bind_epoch(platform.clock_epoch(), platform.clock_resolution_ns())?;
        let now = match platform.now_ns() {
            Ok(now) => now,
            Err(error) => {
                self.clock_failed(error);
                return Err(TimeError::Clock(error));
            }
        };
        self.observe(now)?;
        Ok(now)
    }

    fn bind_epoch(&mut self, epoch: &ClockEpoch, resolution_ns: u64) -> Result<(), TimeError> {
        if self.epoch_changed
            || self
                .epoch
                .as_ref()
                .is_some_and(|bound| !bound.same_epoch(epoch))
        {
            self.anchor = None;
            self.pending = None;
            self.epoch_changed = true;
            return Err(TimeError::ClockEpochChanged);
        }
        if resolution_ns == 0 {
            self.anchor = None;
            self.pending = None;
            return Err(TimeError::ClockResolutionUnavailable);
        }
        if self.epoch.is_none() {
            self.epoch = Some(epoch.clone());
            self.read_uncertainty_ns = resolution_ns;
        }
        Ok(())
    }

    fn clock_failed(&mut self, error: ClockError) {
        self.anchor = None;
        self.pending = None;
        if matches!(error, ClockError::WentBackwards { .. }) {
            self.regressed = true;
        }
    }

    fn elapsed_bounds(&self, measured: u64) -> Result<(u64, u64), TimeError> {
        // A slow oscillator makes real elapsed time longer. Adding measured*ppm
        // underestimates that error: invert the rate bound and round outward.
        // Each endpoint read may be wrong by at most one admitted resolution
        // quantum in either direction. A difference therefore needs two quanta.
        // This also covers same-tick reads with nonzero actual transit/age.
        let read_margin = self
            .read_uncertainty_ns
            .checked_mul(2)
            .ok_or(TimeError::InvalidInterval)?;
        let measured_lower = measured.saturating_sub(read_margin);
        let measured_upper = measured
            .checked_add(read_margin)
            .ok_or(TimeError::InvalidInterval)?;
        let ppm = u128::from(self.policy.oscillator_drift_ppm);
        Ok((
            u64::try_from(u128::from(measured_lower) * 1_000_000 / (1_000_000 + ppm))
                .map_err(|_| TimeError::InvalidInterval)?,
            u64::try_from((u128::from(measured_upper) * 1_000_000).div_ceil(1_000_000 - ppm))
                .map_err(|_| TimeError::InvalidInterval)?,
        ))
    }

    fn observe(&mut self, now: u64) -> Result<(), TimeError> {
        if self.regressed || self.last_mono_ns.is_some_and(|previous| now < previous) {
            self.anchor = None;
            self.pending = None;
            self.regressed = true;
            return Err(TimeError::MonotonicRegression);
        }
        self.last_mono_ns = Some(now);
        Ok(())
    }

    fn accept_at(&mut self, now: u64, reply: &[u8]) -> Result<TimeInterval, TimeError> {
        self.observe(now)?;
        let pending = self.pending.ok_or(TimeError::NoChallenge)?;
        if reply.len() != REPLY_BYTES {
            return Err(TimeError::MalformedReply);
        }
        let mut mac = Authenticator::new_from_slice(self.key).expect("fixed-size HMAC key");
        mac.update(DOMAIN);
        mac.update(&reply[..48]);
        mac.verify_slice(&reply[48..])
            .map_err(|_| TimeError::Authentication)?;
        if reply[..NONCE_BYTES] != pending.nonce {
            return Err(TimeError::WrongChallenge);
        }
        // A valid authenticated reply consumes this nonce, including when its time
        // bounds or transit time are refused. Replaying it cannot repair that refusal.
        self.pending = None;
        let rtt = now
            .checked_sub(pending.sent_ns)
            .ok_or(TimeError::MonotonicRegression)?;
        let (_, rtt_upper) = self.elapsed_bounds(rtt)?;
        if rtt_upper > self.policy.max_round_trip_ns {
            return Err(TimeError::RoundTripExceeded);
        }
        let earliest = u64::from_be_bytes(reply[32..40].try_into().expect("exact length checked"));
        let sent_latest =
            u64::from_be_bytes(reply[40..48].try_into().expect("exact length checked"));
        if sent_latest < earliest {
            return Err(TimeError::InvalidInterval);
        }
        let latest = sent_latest
            .checked_add(rtt_upper)
            .ok_or(TimeError::InvalidInterval)?;
        let interval = TimeInterval {
            earliest_unix_ns: earliest,
            latest_unix_ns: latest,
        };
        self.check_uncertainty(interval)?;
        if let Ok(previous) = self.interval_at(now) {
            let gap = earliest
                .saturating_sub(previous.latest_unix_ns)
                .max(previous.earliest_unix_ns.saturating_sub(latest));
            if gap > self.policy.max_correction_ns {
                self.anchor = None;
                return Err(TimeError::CorrectionRequiresBootstrap);
            }
        }
        self.anchor = Some(Anchor {
            interval,
            mono_ns: now,
        });
        Ok(interval)
    }

    fn check_uncertainty(&self, interval: TimeInterval) -> Result<(), TimeError> {
        match interval
            .latest_unix_ns
            .checked_sub(interval.earliest_unix_ns)
        {
            Some(width) if width <= self.policy.max_uncertainty_ns => Ok(()),
            _ => Err(TimeError::InvalidInterval),
        }
    }

    fn interval_at(&mut self, now: u64) -> Result<TimeInterval, TimeError> {
        self.observe(now)?;
        let anchor = self.anchor.ok_or(TimeError::Unknown)?;
        let age = now
            .checked_sub(anchor.mono_ns)
            .ok_or(TimeError::MonotonicRegression)?;
        let (age_lower, age_upper) = self.elapsed_bounds(age)?;
        if age_upper > self.policy.max_holdover_ns {
            self.anchor = None;
            return Err(TimeError::HoldoverExpired);
        }
        let earliest = anchor
            .interval
            .earliest_unix_ns
            .checked_add(age_lower)
            .ok_or(TimeError::InvalidInterval)?;
        let latest = anchor
            .interval
            .latest_unix_ns
            .checked_add(age_upper)
            .ok_or(TimeError::InvalidInterval)?;
        let interval = TimeInterval {
            earliest_unix_ns: earliest,
            latest_unix_ns: latest,
        };
        self.check_uncertainty(interval)?;
        Ok(interval)
    }
}

/// Authority-side wire encoder. Call only after the authority admits its own time
/// bounds; this authenticates supplied values and cannot determine their truth.
pub fn encode_authenticated_reply(
    key: &[u8; 32],
    nonce: &[u8; NONCE_BYTES],
    interval: TimeInterval,
) -> Result<[u8; REPLY_BYTES], TimeError> {
    if interval.latest_unix_ns < interval.earliest_unix_ns {
        return Err(TimeError::InvalidInterval);
    }
    let mut reply = [0; REPLY_BYTES];
    reply[..32].copy_from_slice(nonce);
    reply[32..40].copy_from_slice(&interval.earliest_unix_ns.to_be_bytes());
    reply[40..48].copy_from_slice(&interval.latest_unix_ns.to_be_bytes());
    let mut mac = Authenticator::new_from_slice(key).expect("fixed-size HMAC key");
    mac.update(DOMAIN);
    mac.update(&reply[..48]);
    reply[48..].copy_from_slice(&mac.finalize().into_bytes());
    Ok(reply)
}

fn check_window(interval: TimeInterval, not_before: u64, expires: u64) -> Result<(), TimeError> {
    if not_before >= expires {
        return Err(TimeError::InvalidCredentialWindow);
    }
    if interval.latest_unix_ns < not_before {
        return Err(TimeError::NotYetValid);
    }
    if interval.earliest_unix_ns < not_before {
        return Err(TimeError::UncertainActivation);
    }
    if interval.earliest_unix_ns >= expires {
        return Err(TimeError::Expired);
    }
    if interval.latest_unix_ns >= expires {
        return Err(TimeError::UncertainExpiration);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [11; 32]; // Public synthetic test key, never a device credential.
    const BASE: u64 = 1_700_000_000_000_000_000;
    const NONCE: [u8; 32] = [7; 32];

    fn client() -> AuthenticatedWallClock<'static> {
        AuthenticatedWallClock::new(
            &KEY,
            BootstrapPolicy {
                max_round_trip_ns: 10_000,
                max_holdover_ns: 1_000_000,
                max_uncertainty_ns: 100_000,
                oscillator_drift_ppm: 100,
                max_correction_ns: 100_000,
            },
        )
        .unwrap()
    }

    // Synthetic boundary injection, not a claim of kernel entropy or provider admission.
    fn pending(clock: &mut AuthenticatedWallClock<'_>, now: u64, nonce: [u8; 32]) {
        clock.observe(now).unwrap();
        clock.pending = Some(Pending {
            nonce,
            sent_ns: now,
        });
    }

    fn response(nonce: [u8; 32], earliest: u64, latest: u64) -> [u8; REPLY_BYTES] {
        encode_authenticated_reply(
            &KEY,
            &nonce,
            TimeInterval {
                earliest_unix_ns: earliest,
                latest_unix_ns: latest,
            },
        )
        .unwrap()
    }

    fn anchored() -> AuthenticatedWallClock<'static> {
        let mut clock = client();
        pending(&mut clock, 100, NONCE);
        assert_eq!(
            clock.accept_at(200, &response(NONCE, BASE, BASE + 1_000)),
            Ok(TimeInterval {
                earliest_unix_ns: BASE,
                latest_unix_ns: BASE + 1_101,
            })
        );
        clock
    }

    #[test]
    fn wall_time_starts_unknown_and_policy_has_no_guessed_defaults() {
        assert_eq!(client().interval_at(0), Err(TimeError::Unknown));
        let policy = client().policy;
        for invalid in [
            BootstrapPolicy {
                max_round_trip_ns: 0,
                ..policy
            },
            BootstrapPolicy {
                max_holdover_ns: 0,
                ..policy
            },
            BootstrapPolicy {
                max_uncertainty_ns: 0,
                ..policy
            },
            BootstrapPolicy {
                oscillator_drift_ppm: 1_000_000,
                ..policy
            },
        ] {
            assert!(matches!(
                AuthenticatedWallClock::new(&KEY, invalid),
                Err(TimeError::InvalidPolicy)
            ));
        }
    }

    #[test]
    fn wire_tag_matches_independent_python_hmac_sha256_golden() {
        let nonce = core::array::from_fn(|index| index as u8);
        let reply = response(nonce, BASE, BASE + 1_000);
        // Python stdlib hmac.new([11]*32, b"FFW-P02-TIME-V1\\0" + nonce + two BE u64, sha256).
        assert_eq!(
            &reply[48..],
            &[
                0x2f, 0xb6, 0x43, 0xf8, 0xfe, 0x60, 0x4d, 0x79, 0xf0, 0x5a, 0xc2, 0x7f, 0x12, 0x52,
                0x82, 0xab, 0xb8, 0xac, 0x38, 0x36, 0x96, 0xcf, 0x14, 0x4d, 0x5c, 0x25, 0x42, 0xe7,
                0xe7, 0x89, 0x18, 0x2d
            ]
        );
        assert_eq!(&reply[32..40], &BASE.to_be_bytes());
    }

    #[test]
    fn authenticated_time_advances_by_monotonic_age_with_outward_drift_rounding() {
        let mut clock = anchored();
        assert_eq!(
            clock.interval_at(201),
            Ok(TimeInterval {
                earliest_unix_ns: BASE,
                latest_unix_ns: BASE + 1_103,
            })
        );
        assert_eq!(
            clock.interval_at(10_200),
            Ok(TimeInterval {
                earliest_unix_ns: BASE + 9_999,
                latest_unix_ns: BASE + 11_103,
            })
        );
    }

    #[test]
    fn missing_challenge_replay_and_superseded_nonce_never_authenticate() {
        let reply = response(NONCE, BASE, BASE);
        assert_eq!(client().accept_at(100, &reply), Err(TimeError::NoChallenge));
        let mut clock = anchored();
        assert_eq!(clock.accept_at(201, &reply), Err(TimeError::NoChallenge));
        pending(&mut clock, 202, [8; 32]);
        assert_eq!(clock.accept_at(203, &reply), Err(TimeError::WrongChallenge));
        assert!(clock.pending.is_some());
    }

    #[test]
    fn every_response_byte_is_authenticated_and_bad_network_input_preserves_confidence() {
        let mut clock = anchored();
        pending(&mut clock, 201, [8; 32]);
        let reply = response([8; 32], BASE, BASE + 1_000);
        for index in 0..REPLY_BYTES {
            let mut tampered = reply;
            tampered[index] ^= 1;
            assert_eq!(
                clock.accept_at(202, &tampered),
                Err(TimeError::Authentication),
                "byte {index}"
            );
            assert!(clock.anchor.is_some());
            assert!(clock.pending.is_some());
        }
        for bytes in [&reply[..79], &[0u8; 81][..]] {
            assert_eq!(clock.accept_at(202, bytes), Err(TimeError::MalformedReply));
        }
        assert!(clock.accept_at(203, &reply).is_ok());
    }

    #[test]
    fn authenticated_but_late_or_excessively_uncertain_responses_are_consumed_and_refused() {
        let mut clock = client();
        pending(&mut clock, 0, NONCE);
        let reply = response(NONCE, BASE, BASE);
        assert_eq!(
            clock.accept_at(10_001, &reply),
            Err(TimeError::RoundTripExceeded)
        );
        assert_eq!(clock.accept_at(10_001, &reply), Err(TimeError::NoChallenge));
        pending(&mut clock, 10_002, NONCE);
        assert_eq!(
            clock.accept_at(10_003, &response(NONCE, BASE, BASE + 100_000)),
            Err(TimeError::InvalidInterval)
        );
    }

    #[test]
    fn both_large_wall_corrections_withdraw_trust_without_stepping_monotonic_time() {
        for corrected in [BASE - 1_000_000, BASE + 1_000_000] {
            let mut clock = anchored();
            pending(&mut clock, 300, [8; 32]);
            assert_eq!(
                clock.accept_at(400, &response([8; 32], corrected, corrected + 1_000)),
                Err(TimeError::CorrectionRequiresBootstrap)
            );
            assert_eq!(clock.last_mono_ns, Some(400));
            assert_eq!(clock.interval_at(401), Err(TimeError::Unknown));
            pending(&mut clock, 402, [9; 32]);
            assert!(
                clock
                    .accept_at(403, &response([9; 32], corrected, corrected + 1_000))
                    .is_ok()
            );
        }
    }

    #[test]
    fn holdover_expiry_is_exact_and_rebootstrap_is_required() {
        let mut clock = anchored();
        clock.policy.oscillator_drift_ppm = 0;
        assert!(clock.interval_at(1_000_200).is_ok());
        assert_eq!(
            clock.interval_at(1_000_201),
            Err(TimeError::HoldoverExpired)
        );
        assert_eq!(clock.interval_at(1_000_202), Err(TimeError::Unknown));
    }

    #[test]
    fn monotonic_regression_is_sticky_and_clears_authentication_state() {
        let mut clock = anchored();
        pending(&mut clock, 300, [8; 32]);
        assert_eq!(clock.interval_at(299), Err(TimeError::MonotonicRegression));
        assert!(clock.anchor.is_none() && clock.pending.is_none());
        assert_eq!(clock.interval_at(301), Err(TimeError::MonotonicRegression));
    }

    #[test]
    fn a_regression_already_caught_by_the_platform_layer_is_also_sticky() {
        let mut clock = anchored();
        clock.clock_failed(ClockError::WentBackwards {
            last_ns: 200,
            now_ns: 199,
        });
        assert!(clock.anchor.is_none() && clock.pending.is_none());
        assert_eq!(clock.interval_at(201), Err(TimeError::MonotonicRegression));
    }

    #[test]
    fn inverse_frequency_bounds_refuse_credentials_expired_on_a_slow_oscillator() {
        let mut clock = client();
        clock.policy.oscillator_drift_ppm = 500_000;
        clock.policy.max_holdover_ns = 10_000_000_000;
        clock.policy.max_uncertainty_ns = 5_000_000_000;
        pending(&mut clock, 0, NONCE);
        clock.accept_at(0, &response(NONCE, BASE, BASE)).unwrap();
        // A counter at half real speed advances 1s during 2s of real time.
        // The naive measured+50% bound would wrongly admit the 1.75s expiry.
        let interval = clock.interval_at(1_000_000_000).unwrap();
        assert_eq!(interval.earliest_unix_ns, BASE + 666_666_666);
        assert_eq!(interval.latest_unix_ns, BASE + 2_000_000_000);
        assert_eq!(
            check_window(interval, BASE, BASE + 1_750_000_000),
            Err(TimeError::UncertainExpiration)
        );
    }

    #[test]
    fn transit_and_holdover_limits_use_worst_case_real_elapsed_time() {
        let mut clock = client();
        clock.policy.oscillator_drift_ppm = 500_000;
        pending(&mut clock, 0, NONCE);
        assert_eq!(
            clock.accept_at(8_000, &response(NONCE, BASE, BASE)),
            Err(TimeError::RoundTripExceeded)
        );
        pending(&mut clock, 8_000, NONCE);
        clock
            .accept_at(8_000, &response(NONCE, BASE, BASE))
            .unwrap();
        clock.policy.max_uncertainty_ns = 5_000_000;
        assert_eq!(clock.interval_at(508_001), Err(TimeError::HoldoverExpired));
    }

    #[test]
    fn quantized_same_tick_reads_never_imply_zero_elapsed_uncertainty() {
        let mut clock = client();
        clock.policy.oscillator_drift_ppm = 0;
        clock.policy.max_round_trip_ns = 100_000_000;
        clock.policy.max_holdover_ns = 1_000_000_000;
        clock.policy.max_uncertainty_ns = 100_000_000;
        clock.bind_epoch(&ClockEpoch::new(), 10_000_000).unwrap();
        pending(&mut clock, 100_000_000, NONCE);
        clock
            .accept_at(100_000_000, &response(NONCE, BASE, BASE))
            .unwrap();
        let interval = clock.interval_at(100_000_000).unwrap();
        // A 9ms real delay can be hidden in a 10ms tick. Each read's admitted
        // error contributes to conservative RTT and then holdover bounds.
        assert_eq!(interval.earliest_unix_ns, BASE);
        assert_eq!(interval.latest_unix_ns, BASE + 40_000_000);
        assert_eq!(
            check_window(interval, BASE, BASE + 5_000_000),
            Err(TimeError::UncertainExpiration)
        );
    }

    #[test]
    fn epoch_binding_survives_moves_and_drop_and_never_silently_rebinds() {
        let mut clock = client();
        let epoch = ClockEpoch::new();
        let same = epoch.clone();
        clock.bind_epoch(&epoch, 1).unwrap();
        drop(epoch);
        clock.bind_epoch(&same, 1).unwrap();
        let mut clock = Box::new(clock);
        clock.bind_epoch(&same, 1).unwrap();
        pending(&mut clock, 100, NONCE);
        let other = ClockEpoch::new();
        assert_eq!(
            clock.bind_epoch(&other, 1),
            Err(TimeError::ClockEpochChanged)
        );
        assert!(clock.anchor.is_none() && clock.pending.is_none());
        assert_eq!(
            clock.bind_epoch(&same, 1),
            Err(TimeError::ClockEpochChanged)
        );
    }

    #[test]
    fn unknown_resolution_cannot_bind_a_trusted_clock() {
        let mut clock = client();
        assert_eq!(
            clock.bind_epoch(&ClockEpoch::new(), 0),
            Err(TimeError::ClockResolutionUnavailable)
        );
        assert!(clock.epoch.is_none());
    }

    #[test]
    fn resume_invalidation_withdraws_wall_trust_without_modifying_audio_time() {
        let mut clock = anchored();
        pending(&mut clock, 300, [8; 32]);
        clock.invalidate_after_resume();
        assert_eq!(clock.last_mono_ns, Some(300));
        assert!(clock.pending.is_none());
        assert_eq!(clock.interval_at(301), Err(TimeError::Unknown));
        assert_eq!(
            clock.accept_at(301, &response([8; 32], BASE, BASE)),
            Err(TimeError::NoChallenge)
        );
    }

    #[test]
    fn every_public_entrypoint_rejects_simulated_provenance_before_reading_clock_or_entropy() {
        use crate::CapabilityStatus::Supported;
        use crate::KernelCapabilityMatrix;
        use crate::sim::ScriptedOps;
        // Gate-only fixture, never a guest observation. No clock or entropy call
        // is scripted: accidental use would panic as well as violate the log.
        let matrix = KernelCapabilityMatrix {
            profile_id: "wall-time-gate-fixture".into(),
            target_triple: "powerpc-unknown-linux-musl".into(),
            nominal_kernel_version: "4.9-fixture".into(),
            guest_kernel_observed: Some("4.9-fixture".into()),
            static_elf_startup: Supported,
            clock_monotonic: Supported,
            clock_monotonic_res_ns: 1,
            nonblocking_pipe_io: Supported,
            poll_syscall: Supported,
            epoll_syscall: Supported,
            udp_socket_io: Supported,
            urandom_entropy: Supported,
            getrandom_syscall: Supported,
            atomics_32bit: Supported,
            atomics_64bit_fallback: Supported,
            eventfd_syscall: Supported,
        };
        let ops = ScriptedOps::new().eventfd(7);
        let log = ops.log_handle();
        let mut platform = PlatformLayer::admit(&matrix, ops).unwrap();
        let before = log.borrow().clone();
        let mut clock = client();
        assert_eq!(
            clock.begin(&mut platform),
            Err(TimeError::SimulatedPlatform)
        );
        assert_eq!(
            clock.accept(&mut platform, &response(NONCE, BASE, BASE)),
            Err(TimeError::SimulatedPlatform)
        );
        assert_eq!(
            clock.interval(&mut platform),
            Err(TimeError::SimulatedPlatform)
        );
        assert_eq!(
            clock.check_credential(&mut platform, 0, u64::MAX),
            Err(TimeError::SimulatedPlatform)
        );
        assert_eq!(*log.borrow(), before);
        assert!(clock.anchor.is_none() && clock.pending.is_none() && clock.epoch.is_none());
    }

    #[test]
    fn overflow_and_reversed_intervals_cannot_authorize_a_time() {
        assert_eq!(
            encode_authenticated_reply(
                &KEY,
                &NONCE,
                TimeInterval {
                    earliest_unix_ns: 2,
                    latest_unix_ns: 1,
                }
            ),
            Err(TimeError::InvalidInterval)
        );
        let mut clock = client();
        pending(&mut clock, 1, NONCE);
        assert_eq!(
            clock.accept_at(2, &response(NONCE, u64::MAX, u64::MAX)),
            Err(TimeError::InvalidInterval)
        );
        pending(&mut clock, 3, NONCE);
        assert!(
            clock
                .accept_at(3, &response(NONCE, u64::MAX, u64::MAX))
                .is_ok()
        );
        assert_eq!(clock.interval_at(4), Err(TimeError::InvalidInterval));
    }

    #[test]
    fn credential_check_requires_the_entire_interval_and_expiration_is_exclusive() {
        let interval = TimeInterval {
            earliest_unix_ns: 100,
            latest_unix_ns: 110,
        };
        for (not_before, expires, expected) in [
            (100, 111, Ok(())),
            (99, 200, Ok(())),
            (111, 200, Err(TimeError::NotYetValid)),
            (101, 200, Err(TimeError::UncertainActivation)),
            (0, 100, Err(TimeError::Expired)),
            (0, 110, Err(TimeError::UncertainExpiration)),
            (0, 105, Err(TimeError::UncertainExpiration)),
            (200, 200, Err(TimeError::InvalidCredentialWindow)),
            (201, 200, Err(TimeError::InvalidCredentialWindow)),
        ] {
            assert_eq!(check_window(interval, not_before, expires), expected);
        }
    }
}
