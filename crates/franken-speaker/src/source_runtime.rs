//! Owned finite-source host composition. Decoder preparation can block and must
//! be scheduled away from protected rendering. This module does not provision a
//! provider, qualify a board, or establish a fleet clock.

use std::io::{Read, Seek};
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use franken_codec::{Caps, SourceCodec, SourceReaderLimits};
use franken_session::{
    Admitted, AuthorityToken, CommandClass, FencedControlCommand, GroupCommandPayload,
    MembershipError, SessionError, SourceArbiter, SourceCommand, SourceError as PolicyError,
    UnifiedGroupSession,
};
use franken_stream::carrier::{
    AllPeerAdmissionError, CarrierError, CarrierSender, DatagramPort, Lane, N01IsolatedOutcome,
    PeerView, PortFault, PumpReport,
};
use franken_stream::playout::ClockView;

use crate::source_media::{
    IsolatedProgress, PrepareProgress, SourceAuthority, SourceCounters, SourceError,
    SourceIdentity, SourceInputs, SourceMedia, SourceOpen, TransportEpoch,
};

/// One independently observed local and admitted group-clock reading.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeObservation {
    pub interface_now_ns: u64,
    pub group_clock: ClockView,
}

/// A clock implementation must observe time on each call; it must not cache a
/// reading across blocking source preparation. Its group view is an external
/// authority, not authenticated or synchronized by this owner.
pub trait RuntimeClock {
    fn observe(&mut self) -> Result<RuntimeObservation, RuntimeError>;
}

/// Fixture-local monotonic clock. `group_origin_ns` is a caller-provisioned
/// mapping for this process and does not establish a shared fleet clock.
pub struct MonotonicClock {
    origin: Instant,
    group_origin_ns: u64,
    uncertainty_ns: u64,
}

impl MonotonicClock {
    #[must_use]
    pub fn new(group_origin_ns: u64, uncertainty_ns: u64) -> Self {
        Self::from_anchor(Instant::now(), group_origin_ns, uncertainty_ns)
    }

    /// Map an existing monotonic instant to the caller's admitted group-time
    /// reading. The caller owns uncertainty and cross-process provisioning.
    #[must_use]
    pub const fn from_anchor(origin: Instant, group_origin_ns: u64, uncertainty_ns: u64) -> Self {
        Self {
            origin,
            group_origin_ns,
            uncertainty_ns,
        }
    }
}

impl RuntimeClock for MonotonicClock {
    fn observe(&mut self) -> Result<RuntimeObservation, RuntimeError> {
        let elapsed =
            u64::try_from(self.origin.elapsed().as_nanos()).map_err(|_| RuntimeError::Clock)?;
        let group_ns = self
            .group_origin_ns
            .checked_add(elapsed)
            .ok_or(RuntimeError::Clock)?;
        Ok(RuntimeObservation {
            interface_now_ns: elapsed,
            group_clock: ClockView {
                group_ns,
                uncertainty_ns: self.uncertainty_ns,
                usable: true,
            },
        })
    }
}

/// All ownership and resource inputs are explicit; no carrier or authority
/// mutation may bypass the runtime after construction.
pub struct RuntimeConfig<P: DatagramPort, C: RuntimeClock> {
    pub caps: Caps,
    pub reader_limits: SourceReaderLimits,
    pub transport: TransportEpoch,
    pub identity: SourceIdentity,
    pub peers: Vec<u32>,
    pub work_and_lead_ns: u64,
    pub overlap_budget_bytes: usize,
    /// Maximum presentation lead admitted by the receiving profile, including
    /// any desired safety margin. It is supplied by the caller, not negotiated
    /// or verified by this local source owner.
    pub max_ahead_ns: u64,
    /// Admitted source authority in the same group-time domain as the clock
    /// view. This is supplied by the trusted controller, not minted here.
    /// The arbiter's configured authority margin, this clock's uncertainty
    /// and the work/lead budget are accumulated conservatively at each gate.
    pub authority: AuthorityToken,
    pub session: UnifiedGroupSession,
    pub arbiter: SourceArbiter,
    pub carrier: CarrierSender<P>,
    pub clock: C,
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("invalid runtime configuration")]
    Configuration,
    #[error("clock unavailable, unusable, or regressed")]
    Clock,
    #[error("source runtime stopped")]
    Stopped,
    #[error("source authority: {0}")]
    Authority(#[from] MembershipError),
    #[error("a source authority renewal cannot shorten its current lease")]
    AuthorityShortened,
    #[error("the new seek presentation anchor expired")]
    SeekAnchorExpired,
    #[error("source requires a new format epoch")]
    FormatEpochRequired,
    #[error("carrier transition: {0}")]
    Carrier(#[from] CarrierError),
    #[error("source: {0}")]
    Source(#[from] SourceError),
    #[error("source policy command: {0}")]
    Policy(#[from] PolicyError),
    #[error("group command: {0}")]
    Group(#[from] SessionError),
}

/// One bounded source decision. `Drained` means source EOF, no carrier queue
/// or in-flight packets and no observed source skips or carrier drops in the
/// current transport epoch. It says nothing about delivery of an earlier epoch
/// discarded by an explicit seek. Lifetime loss counters remain available. It does
/// not establish receiver playout, sample integrity or network delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeProgress {
    Published {
        frames: usize,
    },
    Expired {
        frames: usize,
    },
    Waiting,
    Draining,
    Drained,
    /// EOF and carrier drain completed, but an expiry, skip, fence or drop was observed.
    Incomplete,
}

#[derive(Debug)]
pub struct RuntimeStep {
    pub progress: RuntimeProgress,
    pub pump: Option<PumpReport>,
}

/// The sole owner of source, carrier and canonical authority for one epoch.
pub struct SourceRuntime<P: DatagramPort, C: RuntimeClock> {
    source: SourceMedia,
    carrier: CarrierSender<P>,
    clock: C,
    authority: AuthorityToken,
    session: UnifiedGroupSession,
    arbiter: SourceArbiter,
    identity: SourceIdentity,
    transport: TransportEpoch,
    peers: Vec<u32>,
    work_and_lead_ns: u64,
    overlap_budget_bytes: usize,
    max_ahead_ns: u64,
    consumed_frames: u64,
    cancelled: AtomicBool,
    last_observation: Option<RuntimeObservation>,
    selected: bool,
    eof: bool,
    stopped: bool,
    buffer_transient_credit: bool,
    epoch_loss_baseline: u128,
}

impl<P: DatagramPort, C: RuntimeClock> SourceRuntime<P, C> {
    /// Open and probe a real finite reader outside the protected path. The
    /// reader limits and codec caps apply before any runtime step is attempted.
    pub fn open_reader<R: Read + Seek + Send + Sync + 'static>(
        reader: R,
        len: u64,
        codec: SourceCodec,
        config: RuntimeConfig<P, C>,
    ) -> Result<Self, RuntimeError> {
        let RuntimeConfig {
            caps,
            reader_limits,
            transport,
            identity,
            peers,
            work_and_lead_ns,
            overlap_budget_bytes,
            max_ahead_ns,
            authority,
            session,
            arbiter,
            carrier,
            clock,
        } = config;
        if peers.is_empty()
            || peers.len() > 64
            || max_ahead_ns <= transport.admitted_lifetime_margin_ns
            || peers
                .iter()
                .enumerate()
                .any(|(i, p)| peers[..i].contains(p))
            || carrier
                .group_view(transport.group)
                .is_none_or(|g| g.epoch != transport.epoch || g.peers != peers.len())
            || peers.iter().any(|peer| carrier.peer_view(*peer).is_none())
        {
            return Err(RuntimeError::Configuration);
        }
        // Validate identity before opening a potentially blocking reader.
        // Actual expiry is checked from each fresh clock observation, not a
        // guessed construction-time reading or the interface pacing clock.
        authority.check(&session, 0)?;
        let source = SourceMedia::open_reader(
            codec,
            reader,
            len,
            SourceOpen {
                caps,
                reader_limits,
                transport,
                identity: identity.clone(),
                authority: SourceAuthority {
                    arbiter: &arbiter,
                    session: &session,
                },
            },
        )?;
        Ok(Self {
            source,
            carrier,
            clock,
            authority,
            session,
            arbiter,
            identity,
            transport,
            peers,
            work_and_lead_ns,
            overlap_budget_bytes,
            max_ahead_ns,
            consumed_frames: 0,
            cancelled: AtomicBool::new(false),
            last_observation: None,
            selected: false,
            eof: false,
            stopped: false,
            buffer_transient_credit: false,
            epoch_loss_baseline: 0,
        })
    }

    /// Select bounded queueing for transient receiver-credit backpressure.
    /// The existing isolated publication policy remains the default. This
    /// reuses the admitted carrier's exact budgets and send-time safeguards;
    /// a permanently unavailable peer still cannot block healthy members.
    #[must_use]
    pub fn with_buffered_credit(mut self) -> Self {
        self.buffer_transient_credit = true;
        self
    }

    /// Actual local address, for explicit host-loopback setup. This does not
    /// give the caller mutable access to the transport.
    pub fn local_addr(&self, lane: Lane) -> Result<SocketAddr, PortFault> {
        self.carrier.port().local_addr(lane)
    }

    /// Current bounded transport accounting for a configured peer. Counters
    /// are carrier-lifetime totals, not a proof of receiver presentation.
    #[must_use]
    pub fn peer_view(&self, peer: u32) -> Option<PeerView> {
        self.peers
            .contains(&peer)
            .then(|| self.carrier.peer_view(peer))
            .flatten()
    }

    /// Cumulative isolated publication, expiration and peer-skip accounting.
    #[must_use]
    pub const fn source_counters(&self) -> SourceCounters {
        self.source.counters()
    }

    fn observe(&mut self) -> Result<RuntimeObservation, RuntimeError> {
        let observed = self.clock.observe()?;
        if !observed.group_clock.usable
            || self
                .work_and_lead_ns
                .checked_add(observed.group_clock.uncertainty_ns)
                .is_none_or(|margin| margin > self.transport.admitted_lifetime_margin_ns)
            || self.last_observation.is_some_and(|last| {
                observed.interface_now_ns < last.interface_now_ns
                    || observed.group_clock.group_ns < last.group_clock.group_ns
            })
        {
            return Err(RuntimeError::Clock);
        }
        self.check_authority(&self.authority, observed)?;
        self.last_observation = Some(observed);
        Ok(observed)
    }

    fn check_authority(
        &self,
        token: &AuthorityToken,
        observed: RuntimeObservation,
    ) -> Result<(), RuntimeError> {
        self.arbiter
            .check_authority(
                &self.session,
                token,
                observed.group_clock.group_ns,
                observed
                    .group_clock
                    .uncertainty_ns
                    .saturating_add(self.work_and_lead_ns),
            )
            .map_err(|error| match error {
                PolicyError::Authority(error) => RuntimeError::Authority(error),
                error => RuntimeError::Policy(error),
            })
    }

    fn next_presentation_ns(&self) -> Result<u64, RuntimeError> {
        let frame = self
            .transport
            .start_frame
            .checked_add(self.consumed_frames)
            .ok_or(RuntimeError::Configuration)?;
        let base = u128::from(self.transport.start_frame) * 62_500 / 3;
        let offset = u128::from(frame) * 62_500 / 3 - base;
        let offset = u64::try_from(offset).map_err(|_| RuntimeError::Configuration)?;
        self.transport
            .presentation_ns
            .checked_add(offset)
            .ok_or(RuntimeError::Configuration)
    }

    fn within_lookahead(&self, observation: RuntimeObservation) -> Result<bool, RuntimeError> {
        let earliest_group = observation
            .group_clock
            .group_ns
            .saturating_sub(observation.group_clock.uncertainty_ns);
        let admitted_until = earliest_group
            .checked_add(self.max_ahead_ns)
            .ok_or(RuntimeError::Clock)?;
        Ok(self.next_presentation_ns()? <= admitted_until)
    }

    /// Stop is terminal for this owner. Its private carrier cannot be pumped or
    /// handed to an unfenced caller afterwards, including when work is queued.
    pub fn stop(&mut self) {
        self.stopped = true;
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Install an already-admitted same-session renewal while the old lease
    /// is still live. A rejected candidate leaves the existing lease intact;
    /// an observed expiry is terminal and cannot be repaired by a renewal.
    /// This does not acquire a lease or validate a quorum on the caller's
    /// behalf, and never changes receiver output grants or recalls sent audio.
    pub fn renew_authority(&mut self, token: AuthorityToken) -> Result<(), RuntimeError> {
        if self.stopped {
            return Err(RuntimeError::Stopped);
        }
        let now = match self.observe() {
            Ok(now) => now,
            Err(error) => {
                self.stop();
                return Err(error);
            }
        };
        self.check_authority(&token, now)?;
        if token.expires_at_ns < self.authority.expires_at_ns {
            return Err(RuntimeError::AuthorityShortened);
        }
        self.authority = token;
        Ok(())
    }

    /// Judge a command against this owner's canonical session and arbiter.
    /// A successful replacement/stop makes this owner terminal before another
    /// pump can run. A rejected command leaves its source and carrier intact.
    pub fn submit_source_command(
        &mut self,
        token: &AuthorityToken,
        command: &SourceCommand,
    ) -> Result<Admitted, RuntimeError> {
        if self.stopped {
            return Err(RuntimeError::Stopped);
        }
        let now = match self.observe() {
            Ok(v) => v,
            Err(e) => {
                self.stop();
                return Err(e);
            }
        };
        self.check_authority(token, now)?;
        let latest = now
            .group_clock
            .group_ns
            .checked_add(now.group_clock.uncertainty_ns)
            .ok_or(RuntimeError::Clock)?;
        let admitted = self.arbiter.submit(&self.session, token, latest, command)?;
        if self
            .arbiter
            .check_publish(
                &self.session,
                &self.identity.source,
                self.identity.policy_epoch,
            )
            .is_err()
        {
            self.stop();
        }
        Ok(admitted)
    }

    /// Seek the finite decoder into a caller-admitted new transport timeline.
    /// The native source frame and 48 kHz transport start frame are independent.
    /// Seeking beyond a known track length retains the decoder's EOF saturation.
    ///
    /// This can block on the reader and must run outside protected rendering.
    /// The caller must already resolve old receiver output and admit the new
    /// receiver epoch under its existing output-grant/fencing contract. This
    /// method discards queued old sender media, but cannot recall sent datagrams
    /// or establish a receiver/HAL acknowledgement or audible seek completion.
    /// Returned admission describes source policy, not an exact landed frame.
    ///
    /// Deterministic candidate validation happens before transition. Once the
    /// carrier or decoder may have changed, any error makes this owner terminal;
    /// neither the old timeline nor an expired authority can be resurrected.
    pub fn seek_source_new_epoch(
        &mut self,
        token: &AuthorityToken,
        target_native_frame: u64,
        next: TransportEpoch,
    ) -> Result<Admitted, RuntimeError> {
        if self.stopped {
            return Err(RuntimeError::Stopped);
        }
        let before = match self.observe() {
            Ok(now) => now,
            Err(error) => {
                self.stop();
                return Err(error);
            }
        };
        self.check_authority(token, before)?;
        SourceMedia::validate_epoch(next)?;
        if next.group != self.transport.group
            || next.epoch <= self.transport.epoch
            || self.max_ahead_ns <= next.admitted_lifetime_margin_ns
            || self
                .work_and_lead_ns
                .checked_add(before.group_clock.uncertainty_ns)
                .is_none_or(|margin| margin > next.admitted_lifetime_margin_ns)
            || self
                .carrier
                .group_view(self.transport.group)
                .is_none_or(|group| {
                    group.epoch != self.transport.epoch || group.peers != self.peers.len()
                })
        {
            return Err(RuntimeError::Configuration);
        }
        let latest = before
            .group_clock
            .group_ns
            .checked_add(before.group_clock.uncertainty_ns)
            .ok_or(RuntimeError::Clock)?;
        let cutoff = next
            .presentation_ns
            .checked_sub(next.admitted_lifetime_margin_ns)
            .ok_or(RuntimeError::Configuration)?;
        if latest >= cutoff {
            return Err(RuntimeError::SeekAnchorExpired);
        }
        self.arbiter.check_publish(
            &self.session,
            &self.identity.source,
            self.identity.policy_epoch,
        )?;
        let admitted = self.arbiter.submit(
            &self.session,
            token,
            latest,
            &SourceCommand {
                source: self.identity.source.clone(),
                class: CommandClass::Seek,
                expected_epoch: self.identity.policy_epoch,
            },
        )?;
        let transitioned = (|| {
            self.carrier.advance_group_epoch(next.group, next.epoch)?;
            self.source.seek_new_epoch(
                &mut self.carrier,
                target_native_frame,
                next,
                SourceAuthority {
                    arbiter: &self.arbiter,
                    session: &self.session,
                },
            )?;
            self.transport = next;
            self.consumed_frames = 0;
            self.selected = false;
            self.eof = false;
            let after = self.observe()?;
            self.check_authority(token, after)?;
            let latest = after
                .group_clock
                .group_ns
                .checked_add(after.group_clock.uncertainty_ns)
                .ok_or(RuntimeError::Clock)?;
            if latest >= cutoff {
                return Err(RuntimeError::SeekAnchorExpired);
            }
            // Epoch transition intentionally purges old queued/held packets.
            // Preserve lifetime counters, excluding only pre-transition losses
            // from this epoch's drain decision. Saturation/fences remain unknown.
            self.epoch_loss_baseline = self.loss_tally()?.0;
            Ok::<(), RuntimeError>(())
        })();
        if let Err(error) = transitioned {
            self.stop();
            return Err(error);
        }
        Ok(admitted)
    }

    /// Apply the current session's fenced group command. A successful stop,
    /// topology change or epoch advance makes this owner terminal before old
    /// queued media can be pumped. A topology change requires a newly bound
    /// owner and carrier. Rejected commands leave its custody untouched.
    pub fn submit_group_command(
        &mut self,
        command: FencedControlCommand,
    ) -> Result<u64, RuntimeError> {
        if self.stopped {
            return Err(RuntimeError::Stopped);
        }
        if let Err(error) = self.observe() {
            self.stop();
            return Err(error);
        }
        let old_epoch = self.session.current_epoch;
        let invalidates = matches!(
            &command.payload,
            GroupCommandPayload::StopGroupPlayback { .. }
                | GroupCommandPayload::AdmitMember { .. }
                | GroupCommandPayload::RemoveMember { .. }
        );
        let revision = self.session.apply_command(command)?;
        if invalidates || self.session.current_epoch != old_epoch {
            self.stop();
        }
        Ok(revision)
    }

    /// Advance at most one source frame and one bounded carrier pump. On retry,
    /// pending PCM remains owned by SourceMedia. `report` is replaced only by
    /// successful isolated admission; callers must inspect the returned result.
    pub fn step(
        &mut self,
        report: &mut Option<N01IsolatedOutcome>,
    ) -> Result<RuntimeStep, RuntimeError> {
        if self.stopped {
            return Err(RuntimeError::Stopped);
        }
        match self.step_inner(report) {
            Ok(step) => Ok(step),
            Err(error) => {
                self.stop();
                Err(error)
            }
        }
    }

    /// Lifetime loss totals cannot reset through this exclusive owner. Use a
    /// wider checked sum so multiple independent u64 counters cannot overflow
    /// together; saturation is permanently unknown, never a clean delta.
    fn loss_tally(&self) -> Result<(u128, bool), RuntimeError> {
        let source = self.source.counters();
        let mut total = 0u128;
        let mut unknown = source.saturated;
        let mut add = |count: u64| -> Result<(), RuntimeError> {
            unknown |= count == u64::MAX;
            total = total
                .checked_add(u128::from(count))
                .ok_or(RuntimeError::Configuration)?;
            Ok(())
        };
        for count in [
            source.expired_blocks,
            source.skipped_fenced,
            source.skipped_mtu,
            source.skipped_stalled,
            source.skipped_capacity,
            source.skipped_sequence,
        ] {
            add(count)?;
        }
        let mut fenced = false;
        for peer in &self.peers {
            let view = self
                .carrier
                .peer_view(*peer)
                .ok_or(RuntimeError::Configuration)?;
            fenced |= view.fence.is_some();
            let counts = view.counters;
            for count in [
                counts.media_dropped_overflow_packets,
                counts.media_dropped_aggregate_packets,
                counts.media_dropped_late_packets,
                counts.media_dropped_fenced_packets,
                counts.media_dropped_send_error_packets,
            ] {
                add(count)?;
            }
        }
        Ok((total, unknown || fenced))
    }

    fn step_inner(
        &mut self,
        report: &mut Option<N01IsolatedOutcome>,
    ) -> Result<RuntimeStep, RuntimeError> {
        self.carrier.poll_reports();
        let mut progress = RuntimeProgress::Draining;
        if !self.eof {
            let before = self.observe()?;
            if !self.within_lookahead(before)? {
                progress = RuntimeProgress::Waiting;
            } else {
                let inputs = SourceInputs {
                    interface_now_ns: before.interface_now_ns,
                    group_clock: before.group_clock,
                    work_and_lead_ns: self.work_and_lead_ns,
                    overlap_budget_bytes: self.overlap_budget_bytes,
                    cancelled: &self.cancelled,
                    authority: SourceAuthority {
                        arbiter: &self.arbiter,
                        session: &self.session,
                    },
                };
                let prepared = if self.buffer_transient_credit {
                    self.source
                        .prepare_buffered(&mut self.carrier, &self.peers, inputs)
                } else {
                    self.source.prepare(&mut self.carrier, &self.peers, inputs)
                };
                match prepared {
                    Ok(PrepareProgress::Ready) => {
                        self.selected = true;
                        let after = self.observe()?;
                        if !self.within_lookahead(after)? {
                            // A usable wider interval can move the earliest
                            // possible time backwards. Keep the prepared PCM
                            // and retry without decoding or publishing it again.
                            progress = RuntimeProgress::Waiting;
                        } else {
                            let inputs = SourceInputs {
                                interface_now_ns: after.interface_now_ns,
                                group_clock: after.group_clock,
                                work_and_lead_ns: self.work_and_lead_ns,
                                overlap_budget_bytes: self.overlap_budget_bytes,
                                cancelled: &self.cancelled,
                                authority: SourceAuthority {
                                    arbiter: &self.arbiter,
                                    session: &self.session,
                                },
                            };
                            let published = if self.buffer_transient_credit {
                                self.source.publish_buffered_isolated(
                                    &mut self.carrier,
                                    &self.peers,
                                    Some(inputs),
                                    report,
                                )
                            } else {
                                self.source.publish_isolated(
                                    &mut self.carrier,
                                    &self.peers,
                                    Some(inputs),
                                    report,
                                )
                            };
                            progress = match published {
                                Ok(IsolatedProgress::Published { frames }) => {
                                    RuntimeProgress::Published { frames }
                                }
                                Ok(IsolatedProgress::Expired { frames }) => {
                                    RuntimeProgress::Expired { frames }
                                }
                                Err(SourceError::Admission(AllPeerAdmissionError::Retry(_))) => {
                                    RuntimeProgress::Waiting
                                }
                                Ok(
                                    IsolatedProgress::End | IsolatedProgress::FormatEpochRequired,
                                ) => {
                                    return Err(RuntimeError::FormatEpochRequired);
                                }
                                Err(error) => return Err(error.into()),
                            };
                        }
                    }
                    Ok(PrepareProgress::End) => {
                        self.eof = true;
                    }
                    Ok(PrepareProgress::FormatEpochRequired) => {
                        return Err(RuntimeError::FormatEpochRequired);
                    }
                    Err(SourceError::Admission(AllPeerAdmissionError::Retry(_))) => {
                        self.selected = true;
                        progress = RuntimeProgress::Waiting;
                    }
                    Err(error) => return Err(error.into()),
                }
                match progress {
                    RuntimeProgress::Published { frames } | RuntimeProgress::Expired { frames } => {
                        self.consumed_frames = self
                            .consumed_frames
                            .checked_add(
                                u64::try_from(frames).map_err(|_| RuntimeError::Configuration)?,
                            )
                            .ok_or(RuntimeError::Configuration)?;
                    }
                    _ => {}
                }
            }
        }
        let pump = if self.selected {
            let now = self.observe()?;
            let inputs = SourceInputs {
                interface_now_ns: now.interface_now_ns,
                group_clock: now.group_clock,
                work_and_lead_ns: self.work_and_lead_ns,
                overlap_budget_bytes: self.overlap_budget_bytes,
                cancelled: &self.cancelled,
                authority: SourceAuthority {
                    arbiter: &self.arbiter,
                    session: &self.session,
                },
            };
            Some(
                self.source
                    .pump_with_lookahead(&mut self.carrier, inputs, self.max_ahead_ns)?,
            )
        } else {
            None
        };
        if self.eof {
            let group = self
                .carrier
                .group_view(self.transport.group)
                .ok_or(RuntimeError::Configuration)?;
            let mut in_flight = 0u64;
            let (losses, unknown) = self.loss_tally()?;
            let lost = unknown || losses != self.epoch_loss_baseline;
            for peer in &self.peers {
                let view = self
                    .carrier
                    .peer_view(*peer)
                    .ok_or(RuntimeError::Configuration)?;
                in_flight = in_flight
                    .checked_add(view.in_flight)
                    .ok_or(RuntimeError::Configuration)?;
            }
            progress = if group.queued_packets == 0 && in_flight == 0 {
                if lost {
                    RuntimeProgress::Incomplete
                } else {
                    RuntimeProgress::Drained
                }
            } else {
                RuntimeProgress::Draining
            };
        }
        Ok(RuntimeStep { progress, pump })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use franken_session::{CommandClass, SourceConfig, SourceEpoch, SourceId, SourceKind};
    use franken_stream::carrier::{
        CarrierLimits, CarrierReceiver, PRIMARY_GROUP, Received, ReceiverLimits,
    };
    use franken_stream::{StreamId, StreamKey, StreamReceiver};

    const MP3: &[u8] = include_bytes!("../../franken-codec/tests/vectors/mp3_48000.mp3");
    const REFERENCE: &[u8] = include_bytes!("../../franken-codec/tests/vectors/mp3_48000.ref.s16");

    struct ScriptClock(VecDeque<u64>);
    impl RuntimeClock for ScriptClock {
        fn observe(&mut self) -> Result<RuntimeObservation, RuntimeError> {
            let n = if self.0.len() > 1 {
                self.0.pop_front().unwrap()
            } else {
                *self.0.front().ok_or(RuntimeError::Clock)?
            };
            Ok(RuntimeObservation {
                interface_now_ns: n,
                group_clock: ClockView {
                    group_ns: n,
                    uncertainty_ns: 0,
                    usable: true,
                },
            })
        }
    }

    type SentDatagrams = Arc<Mutex<Vec<Vec<u8>>>>;

    struct Port {
        blocked: Arc<AtomicBool>,
        sent: SentDatagrams,
    }
    impl DatagramPort for Port {
        fn send_to(&mut self, lane: Lane, data: &[u8], _: SocketAddr) -> Result<(), PortFault> {
            if self.blocked.load(Ordering::Relaxed) {
                return Err(PortFault::WouldBlock);
            }
            if lane == Lane::Media {
                self.sent.lock().unwrap().push(data.to_vec());
            }
            Ok(())
        }
        fn recv(&mut self, _: Lane, _: &mut [u8]) -> Result<Received, PortFault> {
            Err(PortFault::WouldBlock)
        }
        fn local_addr(&self, lane: Lane) -> Result<SocketAddr, PortFault> {
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                if lane == Lane::Media { 31000 } else { 31001 },
            ))
        }
        fn rebind(&mut self, _: IpAddr) -> Result<(), PortFault> {
            Ok(())
        }
    }

    fn make_owner(
        times: &[u64],
        blocked: bool,
    ) -> (
        SourceRuntime<Port, ScriptClock>,
        Arc<AtomicBool>,
        SentDatagrams,
    ) {
        let blocked = Arc::new(AtomicBool::new(blocked));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let port = Port {
            blocked: Arc::clone(&blocked),
            sent: Arc::clone(&sent),
        };
        let mut carrier = CarrierSender::with_port(
            StreamKey::from_bytes([0x61; 32]),
            StreamId::new(0x1234).unwrap(),
            1,
            CarrierLimits {
                pace_burst_bytes: 65_536,
                window_packets: 256,
                ..CarrierLimits::baseline()
            },
            port,
        )
        .unwrap();
        carrier
            .add_peer(
                7,
                "127.0.0.1:32000".parse().unwrap(),
                "127.0.0.1:32001".parse().unwrap(),
                1500,
            )
            .unwrap();
        let owner = owner_with_carrier(carrier, ScriptClock(times.iter().copied().collect()));
        (owner, blocked, sent)
    }

    fn owner_with_carrier<P: DatagramPort, C: RuntimeClock>(
        carrier: CarrierSender<P>,
        clock: C,
    ) -> SourceRuntime<P, C> {
        owner_with_reader(carrier, clock, Cursor::new(MP3), 20_000_000_000)
    }

    fn owner_with_reader<
        P: DatagramPort,
        C: RuntimeClock,
        R: Read + Seek + Send + Sync + 'static,
    >(
        carrier: CarrierSender<P>,
        clock: C,
        reader: R,
        max_ahead_ns: u64,
    ) -> SourceRuntime<P, C> {
        owner_with_reader_expiry(carrier, clock, reader, max_ahead_ns, u64::MAX)
    }

    fn owner_with_reader_expiry<
        P: DatagramPort,
        C: RuntimeClock,
        R: Read + Seek + Send + Sync + 'static,
    >(
        carrier: CarrierSender<P>,
        clock: C,
        reader: R,
        max_ahead_ns: u64,
        expires_at_ns: u64,
    ) -> SourceRuntime<P, C> {
        let session = UnifiedGroupSession::new("test-group", "test-leader", 1);
        let token = AuthorityToken::issue(&session, expires_at_ns);
        let mut arbiter = SourceArbiter::new(SourceConfig::default());
        let source = SourceId::new(SourceKind::Spotify, "fixture").unwrap();
        let admitted = arbiter
            .submit(
                &session,
                &token,
                0,
                &SourceCommand {
                    source: source.clone(),
                    class: CommandClass::Start,
                    expected_epoch: SourceEpoch::new(0),
                },
            )
            .unwrap();
        SourceRuntime::open_reader(
            reader,
            MP3.len() as u64,
            SourceCodec::Mp3,
            RuntimeConfig {
                caps: Caps::default(),
                reader_limits: SourceReaderLimits {
                    max_read_calls: 100_000,
                    max_reads_per_operation: 100_000,
                    max_seek_calls: 1000,
                    max_read_chunk_bytes: 17,
                },
                transport: TransportEpoch {
                    group: PRIMARY_GROUP,
                    epoch: 1,
                    start_frame: 0,
                    presentation_ns: 10_000_000_000,
                    admitted_lifetime_margin_ns: 1_000_000,
                    partial_final_allowed: true,
                },
                identity: SourceIdentity {
                    source,
                    policy_epoch: admitted.epoch,
                },
                peers: vec![7],
                work_and_lead_ns: 1_000_000,
                overlap_budget_bytes: usize::MAX,
                max_ahead_ns,
                authority: token,
                session,
                arbiter,
                carrier,
                clock,
            },
        )
        .unwrap()
    }

    struct SharedClock(Arc<Mutex<u64>>);
    impl RuntimeClock for SharedClock {
        fn observe(&mut self) -> Result<RuntimeObservation, RuntimeError> {
            let now = *self.0.lock().unwrap();
            Ok(RuntimeObservation {
                interface_now_ns: now,
                group_clock: ClockView {
                    group_ns: now,
                    uncertainty_ns: 0,
                    usable: true,
                },
            })
        }
    }

    struct CountingReader {
        inner: Cursor<&'static [u8]>,
        reads: Arc<AtomicUsize>,
    }
    impl Read for CountingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.inner.read(buf)
        }
    }
    impl Seek for CountingReader {
        fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(position)
        }
    }

    #[test]
    fn lookahead_waits_before_decode_then_pumps_held_work_and_resumes() {
        let blocked = Arc::new(AtomicBool::new(true));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let port = Port {
            blocked: Arc::clone(&blocked),
            sent: Arc::clone(&sent),
        };
        let mut carrier = CarrierSender::with_port(
            StreamKey::from_bytes([0x61; 32]),
            StreamId::new(0x1234).unwrap(),
            1,
            CarrierLimits {
                pace_burst_bytes: 65_536,
                window_packets: 256,
                ..CarrierLimits::baseline()
            },
            port,
        )
        .unwrap();
        carrier
            .add_peer(
                7,
                "127.0.0.1:32000".parse().unwrap(),
                "127.0.0.1:32001".parse().unwrap(),
                1500,
            )
            .unwrap();
        let now = Arc::new(Mutex::new(9_749_999_999));
        let reads = Arc::new(AtomicUsize::new(0));
        let reader = CountingReader {
            inner: Cursor::new(MP3),
            reads: Arc::clone(&reads),
        };
        let mut owner =
            owner_with_reader(carrier, SharedClock(Arc::clone(&now)), reader, 250_000_000);
        let before = reads.load(Ordering::Relaxed);
        assert!(before > 0, "opening probes the real reader");
        assert_eq!(
            owner.step(&mut None).unwrap().progress,
            RuntimeProgress::Waiting
        );
        assert_eq!(reads.load(Ordering::Relaxed), before);
        assert_eq!(owner.consumed_frames, 0);
        assert!(sent.lock().unwrap().is_empty());

        *now.lock().unwrap() = 9_750_000_000;
        assert_eq!(
            owner.step(&mut None).unwrap().progress,
            RuntimeProgress::Published { frames: 256 }
        );
        assert_eq!(
            owner
                .carrier
                .group_view(PRIMARY_GROUP)
                .unwrap()
                .queued_packets,
            1
        );
        let after_first = reads.load(Ordering::Relaxed);
        blocked.store(false, Ordering::Relaxed);
        *now.lock().unwrap() = 9_750_000_001;
        let waiting = owner.step(&mut None).unwrap();
        assert_eq!(waiting.progress, RuntimeProgress::Waiting);
        assert_eq!(waiting.pump.unwrap().media_sent, 1);
        assert_eq!(reads.load(Ordering::Relaxed), after_first);
        assert_eq!(owner.consumed_frames, 256);
        *now.lock().unwrap() = 9_755_333_333;
        assert_eq!(
            owner.step(&mut None).unwrap().progress,
            RuntimeProgress::Published { frames: 256 }
        );
        assert_eq!(owner.consumed_frames, 512);
    }

    struct BusPacket {
        to: SocketAddr,
        from: SocketAddr,
        bytes: Vec<u8>,
    }
    struct BusPort {
        media: SocketAddr,
        control: SocketAddr,
        bus: Arc<Mutex<VecDeque<BusPacket>>>,
        send_failures: Arc<AtomicUsize>,
        sender: bool,
    }
    impl DatagramPort for BusPort {
        fn send_to(&mut self, lane: Lane, bytes: &[u8], to: SocketAddr) -> Result<(), PortFault> {
            if self.sender
                && lane == Lane::Media
                && self
                    .send_failures
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                    .is_ok()
            {
                return Err(PortFault::Other("injected send failure".into()));
            }
            let from = self.local_addr(lane)?;
            self.bus.lock().unwrap().push_back(BusPacket {
                to,
                from,
                bytes: bytes.to_vec(),
            });
            Ok(())
        }
        fn recv(&mut self, lane: Lane, out: &mut [u8]) -> Result<Received, PortFault> {
            let addr = self.local_addr(lane)?;
            let mut bus = self.bus.lock().unwrap();
            let index = bus
                .iter()
                .position(|packet| packet.to == addr)
                .ok_or(PortFault::WouldBlock)?;
            let packet = bus.remove(index).unwrap();
            let len = packet.bytes.len().min(out.len());
            out[..len].copy_from_slice(&packet.bytes[..len]);
            Ok(Received {
                len,
                from: Some(packet.from),
            })
        }
        fn local_addr(&self, lane: Lane) -> Result<SocketAddr, PortFault> {
            Ok(if lane == Lane::Media {
                self.media
            } else {
                self.control
            })
        }
        fn rebind(&mut self, _: IpAddr) -> Result<(), PortFault> {
            Ok(())
        }
    }

    fn reported_fixture(failures: usize) -> (RuntimeProgress, PeerView, usize) {
        let bus = Arc::new(Mutex::new(VecDeque::new()));
        let failures = Arc::new(AtomicUsize::new(failures));
        let sender_port = BusPort {
            media: "127.0.0.1:31000".parse().unwrap(),
            control: "127.0.0.1:31001".parse().unwrap(),
            bus: Arc::clone(&bus),
            send_failures: Arc::clone(&failures),
            sender: true,
        };
        let receiver_port = BusPort {
            media: "127.0.0.1:32000".parse().unwrap(),
            control: "127.0.0.1:32001".parse().unwrap(),
            bus,
            send_failures: failures,
            sender: false,
        };
        let key = StreamKey::from_bytes([0x61; 32]);
        let stream = StreamId::new(0x1234).unwrap();
        let mut carrier = CarrierSender::with_port(
            key.clone(),
            stream,
            1,
            CarrierLimits {
                pace_burst_bytes: 65_536,
                window_packets: 256,
                ..CarrierLimits::baseline()
            },
            sender_port,
        )
        .unwrap();
        carrier
            .add_peer(7, receiver_port.media, receiver_port.control, 1500)
            .unwrap();
        let mut receiver = CarrierReceiver::with_port(
            key,
            stream,
            1,
            ReceiverLimits::baseline(),
            receiver_port,
            "127.0.0.1:31001".parse().unwrap(),
        )
        .unwrap()
        .with_peer_id(7)
        .unwrap();
        let now = Arc::new(Mutex::new(1));
        let mut owner = owner_with_carrier(carrier, SharedClock(Arc::clone(&now)));
        let mut received_frames = 0usize;
        for tick in 0..200u64 {
            *now.lock().unwrap() = if tick < 3 {
                tick + 1
            } else {
                250_000_010 + (tick - 3) * 10_000_000
            };
            let result = owner.step(&mut None).unwrap();
            receiver.poll();
            let packets = receiver.take_media(256);
            if !packets.is_empty() {
                received_frames += packets.iter().map(|p| p.payload.len() / 4).sum::<usize>();
                receiver.send_report().unwrap();
            }
            if matches!(
                result.progress,
                RuntimeProgress::Drained | RuntimeProgress::Incomplete
            ) {
                return (
                    result.progress,
                    owner.peer_view(7).unwrap(),
                    received_frames,
                );
            }
        }
        panic!("fixture failed to drain")
    }

    #[test]
    fn clean_authenticated_reports_drain_but_a_drop_before_later_ack_is_incomplete() {
        let (clean, clean_peer, clean_frames) = reported_fixture(0);
        assert_eq!(clean, RuntimeProgress::Drained);
        assert_eq!(clean_frames, 24_000);
        assert_eq!(clean_peer.counters.media_dropped_send_error_packets, 0);
        assert_eq!(clean_peer.in_flight, 0);
        assert!(clean_peer.counters.reports_accepted > 0);

        let (loss, peer, frames) = reported_fixture(3);
        assert_eq!(loss, RuntimeProgress::Incomplete);
        assert_eq!(peer.counters.media_dropped_send_error_packets, 1);
        assert_eq!(frames, 24_000 - 256);
        assert_eq!(peer.in_flight, 0);
        assert!(
            peer.reported_next > 1,
            "later authenticated ACK covered the skipped sequence"
        );
        assert!(peer.counters.reports_accepted > 0);
    }

    #[test]
    fn finite_reader_publishes_authentic_pcm_and_not_yet_drained() {
        let (mut owner, _, sent) = make_owner(&[1], false);
        let mut report = None;
        let result = owner.step(&mut report).unwrap();
        assert_eq!(result.progress, RuntimeProgress::Published { frames: 256 });
        assert_eq!(result.pump.unwrap().media_sent, 1);
        assert_eq!(report.unwrap().peer_count, 1);
        let wire = sent.lock().unwrap();
        assert_eq!(wire.len(), 1);
        let mut receiver = StreamReceiver::new(
            StreamKey::from_bytes([0x61; 32]),
            StreamId::new(0x1234).unwrap(),
            1,
        );
        let packet = receiver.accept(&wire[0]).unwrap();
        assert_eq!(packet.start_frame, 0);
        assert_eq!(packet.payload.len(), 1024);
        let (samples, _) = packet.payload.as_chunks::<2>();
        let (expected, _) = REFERENCE[..1024].as_chunks::<2>();
        assert!(samples.iter().zip(expected).all(|(a, b)| {
            (i32::from(i16::from_be_bytes(*a)) - i32::from(i16::from_le_bytes(*b))).abs() <= 4
        }));
        assert_eq!(owner.carrier.peer_view(7).unwrap().in_flight, 1);
    }

    #[test]
    fn finite_source_eof_waits_for_real_receiver_credit() {
        // Time advances so the real byte pacer can refill; all readings stay
        // before the fixture's first presentation deadline.
        let times: Vec<u64> = (1..=1000).map(|n| n * 1_000_000).collect();
        let (mut owner, _, sent) = make_owner(&times, false);
        let mut frames = 0usize;
        let mut reached_eof = false;
        for _ in 0..200 {
            match owner.step(&mut None).unwrap().progress {
                RuntimeProgress::Published { frames: count } => frames += count,
                RuntimeProgress::Draining => {
                    reached_eof = true;
                    break;
                }
                other => panic!("unexpected progress: {other:?}"),
            }
        }
        assert!(reached_eof);
        assert_eq!(frames, 24_000);
        assert!(!sent.lock().unwrap().is_empty());
        assert_eq!(
            owner
                .carrier
                .group_view(PRIMARY_GROUP)
                .unwrap()
                .queued_packets,
            0
        );
        assert!(owner.carrier.peer_view(7).unwrap().in_flight > 0);
        assert_eq!(
            owner.step(&mut None).unwrap().progress,
            RuntimeProgress::Draining
        );
    }

    #[test]
    fn buffered_credit_profile_retains_pcm_and_reader_at_capacity() {
        for buffered in [false, true] {
            let reads = Arc::new(AtomicUsize::new(0));
            let sent = Arc::new(Mutex::new(Vec::new()));
            let port = Port {
                blocked: Arc::new(AtomicBool::new(false)),
                sent: Arc::clone(&sent),
            };
            let mut carrier = CarrierSender::with_port(
                StreamKey::from_bytes([0x61; 32]),
                StreamId::new(0x1234).unwrap(),
                1,
                CarrierLimits {
                    window_packets: 1,
                    peer_queue_packets: 1,
                    aggregate_queue_packets: 1,
                    pace_burst_bytes: 65_536,
                    ..CarrierLimits::baseline()
                },
                port,
            )
            .unwrap();
            carrier
                .add_peer(
                    7,
                    "127.0.0.1:32000".parse().unwrap(),
                    "127.0.0.1:32001".parse().unwrap(),
                    1500,
                )
                .unwrap();
            let mut owner = owner_with_reader(
                carrier,
                ScriptClock(VecDeque::from([1])),
                CountingReader {
                    inner: Cursor::new(MP3),
                    reads: Arc::clone(&reads),
                },
                20_000_000_000,
            );
            if buffered {
                owner = owner.with_buffered_credit();
            }
            assert_eq!(
                owner.step(&mut None).unwrap().progress,
                RuntimeProgress::Published { frames: 256 }
            );
            assert_eq!(owner.peer_view(7).unwrap().in_flight, 1);
            let second = owner.step(&mut None).unwrap();
            if buffered {
                assert_eq!(second.progress, RuntimeProgress::Published { frames: 256 });
                assert_eq!(second.pump.unwrap().media_sent, 0);
                assert_eq!(owner.peer_view(7).unwrap().queued_packets, 1);
                assert_eq!(owner.consumed_frames, 512);
            } else {
                assert_eq!(second.progress, RuntimeProgress::Waiting);
                assert_eq!(owner.peer_view(7).unwrap().queued_packets, 0);
                assert_eq!(owner.consumed_frames, 256);
            }
            let before = reads.load(Ordering::Relaxed);
            let counters = owner.source_counters();
            for _ in 0..20 {
                assert_eq!(
                    owner.step(&mut None).unwrap().progress,
                    RuntimeProgress::Waiting
                );
            }
            assert_eq!(reads.load(Ordering::Relaxed), before);
            assert_eq!(owner.source_counters(), counters);
            assert_eq!(counters.skipped_stalled, 0);
            assert_eq!(
                sent.lock().unwrap().len(),
                1,
                "queued PCM must not bypass credit"
            );
            // Stop fences this private owner; it preserves bounded accounting
            // until drop instead of inventing a new epoch or receiver credit.
            let retained_at_stop = owner.peer_view(7).unwrap();
            owner.stop();
            assert_eq!(owner.peer_view(7).unwrap(), retained_at_stop);
            assert!(matches!(owner.step(&mut None), Err(RuntimeError::Stopped)));
            assert_eq!(
                sent.lock().unwrap().len(),
                1,
                "stop must not flush held old PCM"
            );
        }
    }

    #[test]
    fn fresh_post_prepare_expiry_skips_without_wire_output() {
        let (mut owner, _, sent) = make_owner(&[1, 9_999_000_000, 9_999_000_001], false);
        let mut report = None;
        let result = owner.step(&mut report).unwrap();
        assert_eq!(result.progress, RuntimeProgress::Expired { frames: 256 });
        assert_eq!(result.pump.unwrap().media_sent, 0);
        assert_eq!(
            report.unwrap().status,
            franken_stream::carrier::N01IsolatedStatus::Expired
        );
        assert!(sent.lock().unwrap().is_empty());
    }

    #[test]
    fn takeover_and_stop_never_flush_held_old_audio() {
        let (mut owner, blocked, sent) = make_owner(&[1], true);
        let mut report = None;
        let result = owner.step(&mut report).unwrap();
        assert_eq!(result.progress, RuntimeProgress::Published { frames: 256 });
        assert_eq!(result.pump.unwrap().media_sent, 0);
        assert_eq!(
            owner
                .carrier
                .group_view(PRIMARY_GROUP)
                .unwrap()
                .queued_packets,
            1
        );
        let token = AuthorityToken::issue(&owner.session, u64::MAX);
        owner
            .submit_source_command(
                &token,
                &SourceCommand {
                    source: SourceId::new(SourceKind::AirPlay2, "replacement").unwrap(),
                    class: CommandClass::Start,
                    expected_epoch: SourceEpoch::new(1),
                },
            )
            .unwrap();
        blocked.store(false, Ordering::Relaxed);
        assert!(matches!(
            owner.step(&mut report),
            Err(RuntimeError::Stopped)
        ));
        assert!(sent.lock().unwrap().is_empty());

        let (mut other, blocked, sent) = make_owner(&[1], true);
        other.step(&mut None).unwrap();
        other.stop();
        blocked.store(false, Ordering::Relaxed);
        assert!(matches!(other.step(&mut None), Err(RuntimeError::Stopped)));
        assert!(sent.lock().unwrap().is_empty());
    }

    #[test]
    fn backward_post_prepare_clock_is_terminal_before_send() {
        let (mut owner, _, sent) = make_owner(&[2, 1], false);
        assert!(matches!(owner.step(&mut None), Err(RuntimeError::Clock)));
        assert!(matches!(owner.step(&mut None), Err(RuntimeError::Stopped)));
        assert!(sent.lock().unwrap().is_empty());
    }

    #[test]
    fn group_epoch_advance_never_flushes_held_old_audio() {
        let (mut owner, blocked, sent) = make_owner(&[1], true);
        owner.step(&mut None).unwrap();
        assert_eq!(
            owner
                .carrier
                .group_view(PRIMARY_GROUP)
                .unwrap()
                .queued_packets,
            1
        );
        owner
            .submit_group_command(FencedControlCommand {
                epoch: 2,
                command_seq: 1,
                payload: GroupCommandPayload::SetGroupVolume {
                    volume_0_to_100: 50,
                },
            })
            .unwrap();
        blocked.store(false, Ordering::Relaxed);
        assert!(matches!(owner.step(&mut None), Err(RuntimeError::Stopped)));
        assert!(sent.lock().unwrap().is_empty());
    }

    fn fixture_member(member_id: &str) -> GroupCommandPayload {
        let board = franken_board_profile::synthetic_test_fixture_catalog()
            .into_iter()
            .find(|board| board.model_number == "S5")
            .unwrap();
        GroupCommandPayload::AdmitMember {
            member_id: member_id.to_owned(),
            board,
            role: franken_session::ChannelRole::Stereo,
        }
    }

    #[test]
    fn same_epoch_topology_changes_stop_owner_with_held_media() {
        let (mut add_owner, blocked, sent) = make_owner(&[1], true);
        add_owner.step(&mut None).unwrap();
        assert_eq!(
            add_owner
                .carrier
                .group_view(PRIMARY_GROUP)
                .unwrap()
                .queued_packets,
            1
        );
        add_owner
            .submit_group_command(FencedControlCommand {
                epoch: 1,
                command_seq: 1,
                payload: fixture_member("new-peer"),
            })
            .unwrap();
        assert_eq!(add_owner.session.current_epoch, 1);
        assert!(add_owner.session.members.contains_key("new-peer"));
        blocked.store(false, Ordering::Relaxed);
        assert!(matches!(
            add_owner.step(&mut None),
            Err(RuntimeError::Stopped)
        ));
        assert!(sent.lock().unwrap().is_empty());

        let (mut remove_owner, blocked, sent) = make_owner(&[1], true);
        // Establish an actual member in the canonical session before carrier
        // selection; the public command below must apply the actual removal.
        remove_owner
            .session
            .apply_command(FencedControlCommand {
                epoch: 1,
                command_seq: 1,
                payload: fixture_member("peer-7"),
            })
            .unwrap();
        remove_owner.step(&mut None).unwrap();
        assert_eq!(
            remove_owner
                .carrier
                .group_view(PRIMARY_GROUP)
                .unwrap()
                .queued_packets,
            1
        );
        remove_owner
            .submit_group_command(FencedControlCommand {
                epoch: 1,
                command_seq: 2,
                payload: GroupCommandPayload::RemoveMember {
                    member_id: "peer-7".to_owned(),
                },
            })
            .unwrap();
        assert_eq!(remove_owner.session.current_epoch, 1);
        assert!(!remove_owner.session.members.contains_key("peer-7"));
        blocked.store(false, Ordering::Relaxed);
        assert!(matches!(
            remove_owner.step(&mut None),
            Err(RuntimeError::Stopped)
        ));
        assert!(sent.lock().unwrap().is_empty());
    }

    #[test]
    fn rejected_topology_and_same_epoch_volume_leave_valid_source_running() {
        let (mut owner, blocked, sent) = make_owner(&[1, 1, 1, 2], true);
        owner.step(&mut None).unwrap();
        assert!(matches!(
            owner.submit_group_command(FencedControlCommand {
                epoch: 1,
                command_seq: 1,
                payload: GroupCommandPayload::RemoveMember {
                    member_id: "missing".to_owned()
                },
            }),
            Err(RuntimeError::Group(SessionError::UnknownMember { .. }))
        ));
        owner
            .submit_group_command(FencedControlCommand {
                epoch: 1,
                command_seq: 1,
                payload: GroupCommandPayload::SetGroupVolume {
                    volume_0_to_100: 60,
                },
            })
            .unwrap();
        assert_eq!(owner.session.group_master_volume, 60);
        blocked.store(false, Ordering::Relaxed);
        let progress = owner.step(&mut None).unwrap();
        assert!(matches!(
            progress.progress,
            RuntimeProgress::Published { frames: 256 }
        ));
        assert!(progress.pump.unwrap().media_sent >= 1);
        assert!(!sent.lock().unwrap().is_empty());
    }
    mod uncertainty {
        include!("source_runtime/uncertainty_tests.rs");
    }
    mod authority {
        include!("source_runtime/authority_tests.rs");
    }
    mod seek {
        include!("source_runtime/seek_tests.rs");
    }
}
