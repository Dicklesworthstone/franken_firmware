//! Finite container to N01 source composition.
//!
//! Decoding and rate conversion happen outside protected rendering. A carrier
//! snapshot is taken before pulling source data, and an unadmitted frame and
//! that snapshot remain owned here until an isolated or all-peer outcome.
//! The caller supplies trusted membership, clock observations and an admitted
//! 48 kHz timeline; none is authenticated by this adapter. The runtime owner
//! must supply the current canonical arbiter and session for the captured
//! group and serialize their mutation; copied or stale in-process views are
//! not authority and this component cannot detect a fabricated clone.
//! Finite-reader opening/probing is setup with bounded I/O and allocation,
//! separately admitted outside protected rendering; it may occur before a
//! source selection. No-eligible-peer prevents subsequent decoder advancement,
//! not initial setup. This is neither nonblocking nor long-track streaming.
//! At 44.1 kHz,
//! end-of-format flush feeds exactly 64 zero input frames through the existing
//! rate bridge once; 48 kHz has no added tail. Format change requires a new
//! epoch after the old tail drains; seek explicitly discards old pending data.

use std::io::{Read, Seek};
use std::sync::atomic::{AtomicBool, Ordering};

use franken_codec::{
    BlockInfo, Caps, CodecError, ContainerDecoder, PcmFormat, RateAdapter, RateError, SourceCodec,
    SourceReaderLimits, Step, q23_to_s16,
};
use franken_session::{
    SourceArbiter, SourceEpoch as PolicyEpoch, SourceError as PolicyError, SourceId,
    UnifiedGroupSession,
};
use franken_stream::carrier::{
    AllPeerAdmissionError, AllPeerRetry, CarrierSender, DatagramPort, GroupId, N01AdmissionInputs,
    N01GroupClock, N01GroupSnapshot, N01IsolatedOutcome, N01IsolatedStatus, N01PeerDisposition,
    PumpReport,
};
use franken_stream::playout::ClockView;
use franken_stream::{MAX_TIMESTAMP_NS, OutboundFrame};

const BLOCK: usize = 256;
const CHANNELS: usize = 2;
const MAX_DECODE_FRAMES: usize = 16_384;
const MAX_PULLS_PER_PREPARE: usize = 1024;
// The existing group control wire accepts nonempty group identities up to 64 bytes.
const MAX_POLICY_GROUP_BYTES: usize = 64;

/// Caller-admitted N01 transport epoch and 48 kHz timeline. This epoch is
/// independent of both source-policy epoch and session group epoch.
#[derive(Debug, Clone, Copy)]
pub struct TransportEpoch {
    pub group: GroupId,
    pub epoch: u64,
    /// Must be 256-aligned in the new epoch, independent of native source position.
    pub start_frame: u64,
    pub presentation_ns: u64,
    /// Conservative downstream work, submission lead and maximum uncertainty
    /// throughout the entire queued lifetime. The caller must fence sending
    /// before the admitted bound becomes invalid.
    pub admitted_lifetime_margin_ns: u64,
    /// True only when all required peers negotiated partial final blocks.
    pub partial_final_allowed: bool,
}

/// Existing source-policy identity and its independently minted source epoch.
#[derive(Debug, Clone)]
pub struct SourceIdentity {
    pub source: SourceId,
    pub policy_epoch: PolicyEpoch,
}

/// The trusted owner's current canonical source policy and group session.
/// The owner serializes mutations and supplies the actual live view on every
/// call; a copied or stale clone is not an authoritative view.
#[derive(Clone, Copy)]
pub struct SourceAuthority<'a> {
    pub arbiter: &'a SourceArbiter,
    pub session: &'a UnifiedGroupSession,
}

/// Source limits, admitted transport timeline and existing policy authority.
pub struct SourceOpen<'a> {
    pub caps: Caps,
    pub reader_limits: SourceReaderLimits,
    pub transport: TransportEpoch,
    pub identity: SourceIdentity,
    pub authority: SourceAuthority<'a>,
}

/// Fresh admitted clock and work observations for a source or pump operation.
#[derive(Clone, Copy)]
pub struct SourceInputs<'a> {
    pub interface_now_ns: u64,
    pub group_clock: ClockView,
    pub work_and_lead_ns: u64,
    pub overlap_budget_bytes: usize,
    pub cancelled: &'a AtomicBool,
    pub authority: SourceAuthority<'a>,
}

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    #[error("rate conversion: {0}")]
    Rate(#[from] RateError),
    #[error("carrier admission: {0:?}")]
    Admission(AllPeerAdmissionError),
    #[error("invalid or exhausted source timeline")]
    Timeline,
    #[error("source block exceeds the admitted format or resource cap")]
    Block,
    #[error("source position is discontinuous")]
    Discontinuity,
    #[error("partial final block was not negotiated")]
    PartialNotNegotiated,
    #[error("source operation budget exhausted; retry the same epoch")]
    WorkLimit,
    #[error("epoch transition is required")]
    EpochRequired,
    #[error("source decoder failed and must be replaced")]
    Faulted,
    #[error("the decoder reported a truncated container")]
    Truncated,
    #[error("lifetime cutoff bound is invalid; group fenced")]
    BoundExceeded,
    #[error("source policy: {0}")]
    Policy(PolicyError),
    #[error("a newly observed publication clock is required")]
    ObservationRequired,
    #[error("no source frame has been prepared")]
    NotPrepared,
    #[error("invalid policy group identity")]
    InvalidPolicyGroup,
    #[error("source policy view belongs to a different group")]
    WrongPolicyGroup,
    #[error("source policy group epoch changed from {captured} to {observed}")]
    PolicyGroupEpoch { captured: u64, observed: u64 },
}

/// Preparation may decode and block; it never publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrepareProgress {
    Ready,
    End,
    FormatEpochRequired,
}

/// Result of a single bounded submit attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceProgress {
    /// A single frame entered every required carrier queue.
    Admitted {
        frames: usize,
        /// Carrier-reported observed queue/temporary overlap; the caller must
        /// continue to account for live queues after admission.
        accounted_overlap_bytes: usize,
    },
    /// The source and the one-shot rate tail have ended.
    End,
    /// Previous-format tail has drained; admit a fresh epoch before continuing.
    FormatEpochRequired,
}

/// Isolated steady-state source decision. Per-peer outcomes are carrier queue
/// admissions or skips, never delivery or playback claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolatedProgress {
    Published { frames: usize },
    Expired { frames: usize },
    End,
    FormatEpochRequired,
}

/// Bounded aggregate source-side outcomes; individual peers are in each result.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SourceCounters {
    pub published_blocks: u64,
    pub expired_blocks: u64,
    pub expired_frames: u64,
    pub skipped_fenced: u64,
    pub skipped_mtu: u64,
    pub skipped_stalled: u64,
    pub skipped_capacity: u64,
    pub skipped_sequence: u64,
    /// At least one saturating counter overflowed; totals then become lower bounds.
    pub saturated: bool,
}

struct Pending {
    frame: OutboundFrame,
    frames: usize,
}

/// Source ownership and bounded packetization for one stream.
pub struct SourceMedia {
    decoder: ContainerDecoder,
    epoch: TransportEpoch,
    identity: SourceIdentity,
    policy_group: String,
    policy_group_epoch: u64,
    adapter: Option<RateAdapter>,
    format: Option<PcmFormat>,
    next_native: Option<i64>,
    input: Vec<f32>,
    rate_output: Vec<i32>,
    // Stereo frames awaiting admission; an unadmitted prefix is never removed.
    ready: Vec<i16>,
    snapshot: Option<N01GroupSnapshot>,
    pending: Option<Pending>,
    deferred: Option<(BlockInfo, Vec<f32>)>,
    boundary: bool,
    eof: bool,
    sent_frames: u64,
    faulted: bool,
    bound_failed: bool,
    counters: SourceCounters,
}

impl SourceMedia {
    /// Open an immutable finite reader using the real codec/demuxer path.
    /// This synchronous, separately budgeted setup may seek, read and allocate
    /// before carrier selection; schedule it off the protected render path.
    /// The no-eligible-peer guarantee starts after this setup succeeds.
    pub fn open_reader<R: Read + Seek + Send + Sync + 'static>(
        codec: SourceCodec,
        input: R,
        len: u64,
        options: SourceOpen<'_>,
    ) -> Result<Self, SourceError> {
        let SourceOpen {
            caps,
            reader_limits: limits,
            transport: epoch,
            identity,
            authority,
        } = options;
        Self::validate_epoch(epoch)?;
        if authority.session.group_id.is_empty()
            || authority.session.group_id.len() > MAX_POLICY_GROUP_BYTES
            || authority.session.current_epoch == 0
        {
            return Err(SourceError::InvalidPolicyGroup);
        }
        authority
            .arbiter
            .check_publish(authority.session, &identity.source, identity.policy_epoch)
            .map_err(SourceError::Policy)?;
        let policy_group = authority.session.group_id.clone();
        let policy_group_epoch = authority.session.current_epoch;
        if caps.max_block_frames == 0
            || caps.max_block_frames > MAX_DECODE_FRAMES
            || caps.max_channels == 0
            || caps.max_channels > CHANNELS
        {
            return Err(SourceError::Block);
        }
        let decoder = ContainerDecoder::open_reader(codec, input, len, caps, limits)?;
        Ok(Self {
            decoder,
            epoch,
            identity,
            policy_group,
            policy_group_epoch,
            adapter: None,
            format: None,
            next_native: None,
            input: Vec::new(),
            rate_output: Vec::new(),
            ready: Vec::new(),
            snapshot: None,
            pending: None,
            deferred: None,
            boundary: false,
            eof: false,
            sent_frames: 0,
            faulted: false,
            bound_failed: false,
            counters: SourceCounters::default(),
        })
    }

    fn validate_epoch(epoch: TransportEpoch) -> Result<(), SourceError> {
        let frame_offset = u128::from(epoch.start_frame) * 62_500 / 3;
        if !epoch.start_frame.is_multiple_of(BLOCK as u64)
            || epoch.presentation_ns > MAX_TIMESTAMP_NS
            || u128::from(epoch.presentation_ns) < frame_offset
            || epoch.admitted_lifetime_margin_ns > epoch.presentation_ns
        {
            return Err(SourceError::Timeline);
        }
        Ok(())
    }

    fn fail<T>(&mut self, error: SourceError) -> Result<T, SourceError> {
        self.faulted = true;
        Err(error)
    }

    fn append_rate_output(&mut self, channels: usize) {
        if channels == 1 {
            for &sample in &self.rate_output {
                let sample = q23_to_s16(sample);
                self.ready.extend_from_slice(&[sample, sample]);
            }
        } else {
            self.ready
                .extend(self.rate_output.iter().map(|&sample| q23_to_s16(sample)));
        }
    }

    fn process_block(&mut self, block: BlockInfo) -> Result<(), SourceError> {
        let channels = usize::from(block.format.channels);
        if channels == 0
            || channels > CHANNELS
            || block.frames > MAX_DECODE_FRAMES
            || self.input.len() != block.frames * channels
        {
            return self.fail(SourceError::Block);
        }
        if self
            .next_native
            .is_some_and(|expected| expected != block.position)
        {
            return self.fail(SourceError::Discontinuity);
        }
        let Some(next) = block.position.checked_add(block.frames as i64) else {
            return self.fail(SourceError::Timeline);
        };
        if self.adapter.is_none() {
            match RateAdapter::new(block.format.rate_hz, channels) {
                Ok(adapter) => self.adapter = Some(adapter),
                Err(error) => return self.fail(error.into()),
            }
            self.format = Some(block.format);
        }
        if self.format != Some(block.format) {
            return self.fail(SourceError::Block);
        }
        if let Err(error) = self
            .adapter
            .as_mut()
            .expect("adapter initialized")
            .process_f32(&self.input, &mut self.rate_output)
        {
            return self.fail(error.into());
        }
        self.next_native = Some(next);
        self.append_rate_output(channels);
        Ok(())
    }

    fn finish_format(&mut self) -> Result<(), SourceError> {
        if let Some(adapter) = self.adapter.as_mut() {
            let channels = adapter.channels();
            if let Err(error) = adapter.flush(&mut self.rate_output) {
                return self.fail(error.into());
            }
            self.append_rate_output(channels);
        }
        self.boundary = true;
        Ok(())
    }

    fn fill(&mut self) -> Result<(), SourceError> {
        for _ in 0..MAX_PULLS_PER_PREPARE {
            if self.ready.len() >= BLOCK * CHANNELS || self.boundary {
                return Ok(());
            }
            if let Some((block, input)) = self.deferred.take() {
                self.input = input;
                self.process_block(block)?;
                continue;
            }
            let step = match self.decoder.next_block(&mut self.input) {
                Ok(step) => step,
                Err(error) => return self.fail(error.into()),
            };
            match step {
                Step::End => {
                    if self.decoder.truncated() {
                        return self.fail(SourceError::Truncated);
                    }
                    self.eof = true;
                    self.finish_format()?;
                }
                Step::Block(block)
                    if self.format.is_some()
                        && (block.format_changed || self.format != Some(block.format)) =>
                {
                    self.deferred = Some((block, std::mem::take(&mut self.input)));
                    self.finish_format()?;
                }
                Step::Block(block) => self.process_block(block)?,
            }
        }
        Err(SourceError::WorkLimit)
    }

    fn make_frame(&self, frames: usize) -> Result<OutboundFrame, SourceError> {
        let frame = self
            .epoch
            .start_frame
            .checked_add(self.sent_frames)
            .ok_or(SourceError::Timeline)?;
        if !frame.is_multiple_of(BLOCK as u64) {
            return Err(SourceError::Timeline);
        }
        // N04 anchors at floor(start * 62500 / 3), then maps the absolute
        // frame. Subtracting the separately rounded offsets preserves phase.
        let base = u128::from(self.epoch.start_frame) * 62_500 / 3;
        let elapsed = u128::from(frame) * 62_500 / 3 - base;
        let elapsed = u64::try_from(elapsed).map_err(|_| SourceError::Timeline)?;
        let presentation = self
            .epoch
            .presentation_ns
            .checked_add(elapsed)
            .ok_or(SourceError::Timeline)?;
        if presentation > MAX_TIMESTAMP_NS {
            return Err(SourceError::Timeline);
        }
        let deadline = presentation
            .checked_sub(self.epoch.admitted_lifetime_margin_ns)
            .ok_or(SourceError::Timeline)?;
        let mut payload = Vec::with_capacity(frames * 4);
        for sample in &self.ready[..frames * CHANNELS] {
            payload.extend_from_slice(&sample.to_be_bytes());
        }
        Ok(OutboundFrame::media(frame, presentation, deadline, payload))
    }

    fn invalidate_policy<P: DatagramPort>(
        &mut self,
        carrier: &mut CarrierSender<P>,
    ) -> Result<(), SourceError> {
        self.faulted = true;
        let fenced = match self.snapshot.as_ref() {
            Some(snapshot)
                if carrier
                    .group_view(self.epoch.group)
                    .is_some_and(|group| group.epoch == self.epoch.epoch) =>
            {
                carrier
                    .fence_n01_group(self.epoch.group, self.epoch.epoch, snapshot)
                    .map_err(SourceError::Admission)
            }
            _ => Ok(()),
        };
        self.pending = None;
        self.ready.clear();
        self.deferred = None;
        fenced
    }

    fn check_policy<P: DatagramPort>(
        &mut self,
        carrier: &mut CarrierSender<P>,
        authority: SourceAuthority<'_>,
    ) -> Result<(), SourceError> {
        if self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| !carrier.owns_n01_snapshot(snapshot))
        {
            return Err(SourceError::Admission(
                AllPeerAdmissionError::MembershipChanged,
            ));
        }
        if authority.session.group_id != self.policy_group {
            return Err(SourceError::WrongPolicyGroup);
        }
        let observed = authority.session.current_epoch;
        if observed != self.policy_group_epoch {
            let captured = self.policy_group_epoch;
            if observed > captured {
                self.invalidate_policy(carrier)?;
            }
            return Err(SourceError::PolicyGroupEpoch { captured, observed });
        }
        if let Err(error) = authority.arbiter.check_publish(
            authority.session,
            &self.identity.source,
            self.identity.policy_epoch,
        ) {
            self.invalidate_policy(carrier)?;
            return Err(SourceError::Policy(error));
        }
        Ok(())
    }

    fn check_observation<P: DatagramPort>(
        &mut self,
        carrier: &mut CarrierSender<P>,
        inputs: &SourceInputs<'_>,
    ) -> Result<(), SourceError> {
        if self.faulted {
            return Err(SourceError::Faulted);
        }
        self.check_policy(carrier, inputs.authority)?;
        let total = inputs
            .work_and_lead_ns
            .checked_add(inputs.group_clock.uncertainty_ns);
        if !inputs.group_clock.usable
            || total.is_none_or(|n| n > self.epoch.admitted_lifetime_margin_ns)
        {
            self.faulted = true;
            self.bound_failed = true;
            let fenced = match self.snapshot.as_ref() {
                Some(snapshot) => carrier
                    .fence_n01_group(self.epoch.group, self.epoch.epoch, snapshot)
                    .map_err(SourceError::Admission),
                None => Ok(()),
            };
            self.pending = None;
            self.ready.clear();
            self.deferred = None;
            fenced?;
            return Err(SourceError::BoundExceeded);
        }
        Ok(())
    }

    /// Prepare one source frame without publishing. This operation may block
    /// on the finite reader and must execute outside protected rendering.
    pub fn prepare<P: DatagramPort>(
        &mut self,
        carrier: &mut CarrierSender<P>,
        peers: &[u32],
        inputs: SourceInputs<'_>,
    ) -> Result<PrepareProgress, SourceError> {
        self.check_observation(carrier, &inputs)?;
        if inputs.cancelled.load(Ordering::Acquire) {
            return Err(SourceError::Admission(AllPeerAdmissionError::Cancelled));
        }
        if self.pending.is_some() {
            return Ok(PrepareProgress::Ready);
        }
        if self.boundary && self.ready.is_empty() {
            return Ok(if self.eof {
                PrepareProgress::End
            } else {
                PrepareProgress::FormatEpochRequired
            });
        }
        if self.snapshot.is_none() {
            self.snapshot = Some(
                carrier
                    .claim_n01_source(self.epoch.group, self.epoch.epoch, peers)
                    .map_err(SourceError::Admission)?,
            );
        }
        if !self.boundary
            && !carrier
                .has_n01_eligible_peer(
                    self.epoch.group,
                    self.epoch.epoch,
                    self.snapshot.as_ref().expect("source claim"),
                    peers,
                    inputs.interface_now_ns,
                )
                .map_err(SourceError::Admission)?
        {
            return Err(SourceError::Admission(AllPeerAdmissionError::Retry(
                AllPeerRetry::NoEligiblePeers,
            )));
        }
        self.fill()?;
        if self.ready.is_empty() && self.boundary {
            return Ok(if self.eof {
                PrepareProgress::End
            } else {
                PrepareProgress::FormatEpochRequired
            });
        }
        let frames = (self.ready.len() / CHANNELS).min(BLOCK);
        if frames < BLOCK && !self.boundary {
            return Err(SourceError::WorkLimit);
        }
        if frames < BLOCK && !self.epoch.partial_final_allowed {
            return Err(SourceError::PartialNotNegotiated);
        }
        self.pending = Some(Pending {
            frame: self.make_frame(frames)?,
            frames,
        });
        Ok(PrepareProgress::Ready)
    }

    /// Publish an already prepared frame using a newly observed trusted clock.
    /// This phase performs no reader, decoder or rate-bridge work.
    pub fn publish_all_peers<P: DatagramPort>(
        &mut self,
        carrier: &mut CarrierSender<P>,
        peers: &[u32],
        inputs: Option<SourceInputs<'_>>,
    ) -> Result<SourceProgress, SourceError> {
        let inputs = inputs.ok_or(SourceError::ObservationRequired)?;
        self.check_observation(carrier, &inputs)?;
        let pending = self.pending.as_ref().ok_or(SourceError::NotPrepared)?;
        let next_sent = self
            .sent_frames
            .checked_add(pending.frames as u64)
            .ok_or(SourceError::Timeline)?;
        let admission = carrier
            .try_submit_group_media_all(
                self.epoch.group,
                self.epoch.epoch,
                self.snapshot.as_ref().expect("snapshot before decoding"),
                peers,
                &pending.frame,
                N01AdmissionInputs {
                    interface_now_ns: inputs.interface_now_ns,
                    trusted_group_now_ns: inputs.group_clock.group_ns,
                    overlap_budget_bytes: inputs.overlap_budget_bytes,
                    cancelled: inputs.cancelled,
                },
            )
            .map_err(SourceError::Admission)?;
        let frames = pending.frames;
        self.ready.drain(..frames * CHANNELS);
        self.sent_frames = next_sent;
        self.pending = None;
        // Keep one snapshot for the whole epoch: even with no staged PCM, the
        // decoder and rate bridge can retain source history. Only an explicit
        // epoch reset may rebind that state to a new membership incarnation.
        Ok(SourceProgress::Admitted {
            frames,
            accounted_overlap_bytes: admission.accounted_overlap_bytes,
        })
    }

    /// Source outcomes are cumulative across explicit epoch transitions.
    #[must_use]
    pub const fn counters(&self) -> SourceCounters {
        self.counters
    }

    fn count(counter: &mut u64, saturated: &mut bool, amount: u64) {
        if let Some(next) = counter.checked_add(amount) {
            *counter = next;
        } else {
            *counter = u64::MAX;
            *saturated = true;
        }
    }

    /// Publish once to eligible peers; skipped peer outcomes are returned to
    /// the owner, and an expired frame is explicitly counted and skipped once.
    /// No eligible peer leaves pending frame and source custody unchanged.
    /// On a successful publication or expiration, `report` is replaced with
    /// the corresponding bounded carrier outcome. On error it is unchanged;
    /// callers must check the result before reading a possibly stale report.
    pub fn publish_isolated<P: DatagramPort>(
        &mut self,
        carrier: &mut CarrierSender<P>,
        peers: &[u32],
        inputs: Option<SourceInputs<'_>>,
        report: &mut Option<N01IsolatedOutcome>,
    ) -> Result<IsolatedProgress, SourceError> {
        let inputs = inputs.ok_or(SourceError::ObservationRequired)?;
        self.check_observation(carrier, &inputs)?;
        let pending = self.pending.as_ref().ok_or(SourceError::NotPrepared)?;
        let next_sent = self
            .sent_frames
            .checked_add(pending.frames as u64)
            .ok_or(SourceError::Timeline)?;
        let outcome = carrier
            .try_submit_group_media_isolated(
                self.epoch.group,
                self.epoch.epoch,
                self.snapshot.as_ref().expect("snapshot before decoding"),
                peers,
                &pending.frame,
                N01AdmissionInputs {
                    interface_now_ns: inputs.interface_now_ns,
                    trusted_group_now_ns: inputs.group_clock.group_ns,
                    overlap_budget_bytes: inputs.overlap_budget_bytes,
                    cancelled: inputs.cancelled,
                },
            )
            .map_err(SourceError::Admission)?;
        let frames = pending.frames;
        self.ready.drain(..frames * CHANNELS);
        self.sent_frames = next_sent;
        self.pending = None;
        let progress = match outcome.status {
            N01IsolatedStatus::Expired => {
                Self::count(
                    &mut self.counters.expired_blocks,
                    &mut self.counters.saturated,
                    1,
                );
                Self::count(
                    &mut self.counters.expired_frames,
                    &mut self.counters.saturated,
                    frames as u64,
                );
                IsolatedProgress::Expired { frames }
            }
            N01IsolatedStatus::Published => {
                Self::count(
                    &mut self.counters.published_blocks,
                    &mut self.counters.saturated,
                    1,
                );
                for entry in outcome.peers.iter().flatten() {
                    let slot = match entry.disposition {
                        N01PeerDisposition::Queued => continue,
                        N01PeerDisposition::Fenced => &mut self.counters.skipped_fenced,
                        N01PeerDisposition::PathMtu => &mut self.counters.skipped_mtu,
                        N01PeerDisposition::Stalled => &mut self.counters.skipped_stalled,
                        N01PeerDisposition::Capacity => &mut self.counters.skipped_capacity,
                        N01PeerDisposition::SequenceExhausted => {
                            &mut self.counters.skipped_sequence
                        }
                    };
                    Self::count(slot, &mut self.counters.saturated, 1);
                }
                IsolatedProgress::Published { frames }
            }
        };
        *report = Some(outcome);
        Ok(progress)
    }

    // Existing tests use a fixed trusted clock that cannot change during the
    // operation. Production has no combined prepare-and-publish entry point.
    #[cfg(test)]
    fn submit_all_peers<P: DatagramPort>(
        &mut self,
        carrier: &mut CarrierSender<P>,
        peers: &[u32],
        inputs: SourceInputs<'_>,
    ) -> Result<SourceProgress, SourceError> {
        match self.prepare(carrier, peers, inputs)? {
            PrepareProgress::Ready => self.publish_all_peers(carrier, peers, Some(inputs)),
            PrepareProgress::End => Ok(SourceProgress::End),
            PrepareProgress::FormatEpochRequired => Ok(SourceProgress::FormatEpochRequired),
        }
    }

    #[cfg(test)]
    fn submit_isolated<P: DatagramPort>(
        &mut self,
        carrier: &mut CarrierSender<P>,
        peers: &[u32],
        inputs: SourceInputs<'_>,
        report: &mut Option<N01IsolatedOutcome>,
    ) -> Result<IsolatedProgress, SourceError> {
        match self.prepare(carrier, peers, inputs)? {
            PrepareProgress::Ready => self.publish_isolated(carrier, peers, Some(inputs), report),
            PrepareProgress::End => Ok(IsolatedProgress::End),
            PrepareProgress::FormatEpochRequired => Ok(IsolatedProgress::FormatEpochRequired),
        }
    }

    /// Pump this source's protected N01 group only after rechecking its admitted
    /// lifetime bound. The owner must route every protected pump through this
    /// gate and retain exclusive carrier/backend custody.
    pub fn pump<P: DatagramPort>(
        &mut self,
        carrier: &mut CarrierSender<P>,
        inputs: SourceInputs<'_>,
    ) -> Result<PumpReport, SourceError> {
        if self.snapshot.is_none() {
            return Err(SourceError::Admission(
                AllPeerAdmissionError::MembershipChanged,
            ));
        }
        self.check_observation(carrier, &inputs)?;
        let group = N01GroupClock {
            group: self.epoch.group,
            epoch: self.epoch.epoch,
            view: inputs.group_clock,
        };
        carrier
            .pump_n01_selected(
                inputs.interface_now_ns,
                group,
                self.snapshot.as_ref().expect("claimed source"),
                inputs.cancelled,
            )
            .map_err(SourceError::Admission)
    }

    /// Start a new format epoch after the old format and tail are admitted.
    pub fn begin_format_epoch<P: DatagramPort>(
        &mut self,
        carrier: &mut CarrierSender<P>,
        epoch: TransportEpoch,
        authority: SourceAuthority<'_>,
    ) -> Result<(), SourceError> {
        Self::validate_epoch(epoch)?;
        if self.faulted {
            return Err(SourceError::Faulted);
        }
        self.check_policy(carrier, authority)?;
        if self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| !carrier.owns_n01_snapshot(snapshot))
        {
            return Err(SourceError::Admission(
                AllPeerAdmissionError::MembershipChanged,
            ));
        }
        if !self.boundary
            || self.eof
            || self.deferred.is_none()
            || !self.ready.is_empty()
            || self.pending.is_some()
            || epoch.epoch <= self.epoch.epoch
            || epoch.group != self.epoch.group
            || carrier
                .group_view(epoch.group)
                .is_none_or(|group| group.epoch != epoch.epoch)
        {
            return Err(SourceError::EpochRequired);
        }
        self.epoch = epoch;
        self.adapter = None;
        self.format = None;
        self.next_native = None;
        self.snapshot = None;
        self.boundary = false;
        self.sent_frames = 0;
        Ok(())
    }

    /// Seek starts a fresh epoch and discards old pending samples and filter history.
    /// It deliberately does not claim phase continuity with the previous epoch.
    pub fn seek_new_epoch<P: DatagramPort>(
        &mut self,
        carrier: &mut CarrierSender<P>,
        target: u64,
        epoch: TransportEpoch,
        authority: SourceAuthority<'_>,
    ) -> Result<(), SourceError> {
        Self::validate_epoch(epoch)?;
        if self.faulted && !self.bound_failed {
            return Err(SourceError::Faulted);
        }
        self.check_policy(carrier, authority)?;
        if self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| !carrier.owns_n01_snapshot(snapshot))
        {
            return Err(SourceError::Admission(
                AllPeerAdmissionError::MembershipChanged,
            ));
        }
        if epoch.epoch <= self.epoch.epoch
            || epoch.group != self.epoch.group
            || carrier
                .group_view(epoch.group)
                .is_none_or(|group| group.epoch != epoch.epoch)
        {
            return Err(SourceError::EpochRequired);
        }
        self.ready.clear();
        self.pending = None;
        self.snapshot = None;
        self.deferred = None;
        self.faulted = false;
        self.bound_failed = false;
        if let Err(error) = self.decoder.seek(target) {
            return self.fail(error.into());
        }
        self.epoch = epoch;
        self.adapter = None;
        self.format = None;
        self.next_native = None;
        self.boundary = false;
        self.eof = false;
        self.sent_frames = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use franken_session::{
        AuthorityToken, CommandClass, SourceCommand, SourceConfig, SourceKind, SourcePolicy,
        SourcePolicyTable,
    };
    use franken_stream::carrier::{
        AllPeerRetry, CarrierLimits, CarrierReceiver, Lane, PRIMARY_GROUP, PortFault, Received,
        ReceiverLimits,
    };
    use franken_stream::playout::{
        Admission, BLOCK_PAYLOAD_BYTES, ClockView, MediaPacket, Outcome, PlayoutConfig,
        PlayoutEngine, PlayoutProfile, Poll,
    };
    use franken_stream::{StreamId, StreamKey, StreamReceiver};
    use std::collections::VecDeque;
    use std::io::{self, Cursor, SeekFrom};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex, OnceLock};

    const MP3: &[u8] = include_bytes!("../../franken-codec/tests/vectors/mp3_48000.mp3");
    const REFERENCE: &[u8] = include_bytes!("../../franken-codec/tests/vectors/mp3_48000.ref.s16");
    const MP3_441: &[u8] = include_bytes!("../../franken-codec/tests/vectors/mp3_44100.mp3");
    const REF_441: &[u8] = include_bytes!("../../franken-codec/tests/vectors/mp3_44100.ref.s16");
    const RATE_TABLE: &str = include_str!("../../franken-codec/src/rate_table.rs");
    const CHAIN: &[u8] =
        include_bytes!("../../franken-codec/tests/vectors/chain_mp3_44100_48000.mp3");

    struct FixtureAuthority {
        session: UnifiedGroupSession,
        arbiter: SourceArbiter,
        identity: SourceIdentity,
    }
    fn fixture_authority() -> &'static FixtureAuthority {
        static VALUE: OnceLock<FixtureAuthority> = OnceLock::new();
        VALUE.get_or_init(|| {
            let session = UnifiedGroupSession::new("test-group", "test-leader", 1);
            let token = AuthorityToken::issue(&session, u64::MAX);
            // Explicit test-only all-reject policy; no owner approval implied.
            let mut table = SourcePolicyTable::STANDARD;
            for kind in SourceKind::ALL {
                for class in CommandClass::ALL {
                    table = table.with(kind, class, SourcePolicy::Reject);
                }
            }
            let mut arbiter = SourceArbiter::new(SourceConfig {
                policy: table,
                clock_uncertainty_ns: 0,
            });
            let source = SourceId::new(SourceKind::Spotify, "fixture").unwrap();
            let admitted = arbiter
                .submit(
                    &session,
                    &token,
                    1,
                    &SourceCommand {
                        source: source.clone(),
                        class: CommandClass::Start,
                        expected_epoch: PolicyEpoch::new(0),
                    },
                )
                .unwrap();
            FixtureAuthority {
                session,
                arbiter,
                identity: SourceIdentity {
                    source,
                    policy_epoch: admitted.epoch,
                },
            }
        })
    }
    fn authority() -> SourceAuthority<'static> {
        let fixture = fixture_authority();
        SourceAuthority {
            arbiter: &fixture.arbiter,
            session: &fixture.session,
        }
    }
    fn identity() -> SourceIdentity {
        fixture_authority().identity.clone()
    }

    #[derive(Default)]
    struct MemoryPort {
        sent: Vec<(Lane, Vec<u8>, SocketAddr)>,
    }
    impl DatagramPort for MemoryPort {
        fn send_to(&mut self, lane: Lane, bytes: &[u8], to: SocketAddr) -> Result<(), PortFault> {
            self.sent.push((lane, bytes.to_vec(), to));
            Ok(())
        }
        fn recv(&mut self, _: Lane, _: &mut [u8]) -> Result<Received, PortFault> {
            Err(PortFault::WouldBlock)
        }
        fn local_addr(&self, lane: Lane) -> Result<SocketAddr, PortFault> {
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                match lane {
                    Lane::Media => 31000,
                    Lane::Control => 31001,
                },
            ))
        }
        fn rebind(&mut self, _: IpAddr) -> Result<(), PortFault> {
            Ok(())
        }
    }

    struct CooldownPort {
        failing: Arc<AtomicBool>,
        sent: Vec<Vec<u8>>,
    }
    impl DatagramPort for CooldownPort {
        fn send_to(&mut self, lane: Lane, bytes: &[u8], _: SocketAddr) -> Result<(), PortFault> {
            if lane == Lane::Media && self.failing.load(Ordering::Relaxed) {
                return Err(PortFault::PathUnavailable);
            }
            self.sent.push(bytes.to_vec());
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

    struct BusPacket {
        to: SocketAddr,
        from: SocketAddr,
        data: Vec<u8>,
    }
    #[derive(Clone)]
    struct BusPort {
        media: SocketAddr,
        control: SocketAddr,
        network: Arc<Mutex<VecDeque<BusPacket>>>,
    }
    impl DatagramPort for BusPort {
        fn send_to(&mut self, lane: Lane, bytes: &[u8], to: SocketAddr) -> Result<(), PortFault> {
            self.network.lock().unwrap().push_back(BusPacket {
                to,
                from: self.local_addr(lane)?,
                data: bytes.to_vec(),
            });
            Ok(())
        }
        fn recv(&mut self, lane: Lane, out: &mut [u8]) -> Result<Received, PortFault> {
            let addr = self.local_addr(lane)?;
            let mut bus = self.network.lock().unwrap();
            let index = bus
                .iter()
                .position(|packet| packet.to == addr)
                .ok_or(PortFault::WouldBlock)?;
            let packet = bus.remove(index).expect("located packet");
            let len = packet.data.len().min(out.len());
            out[..len].copy_from_slice(&packet.data[..len]);
            Ok(Received {
                len,
                from: Some(packet.from),
            })
        }
        fn local_addr(&self, lane: Lane) -> Result<SocketAddr, PortFault> {
            Ok(match lane {
                Lane::Media => self.media,
                Lane::Control => self.control,
            })
        }
        fn rebind(&mut self, _: IpAddr) -> Result<(), PortFault> {
            Ok(())
        }
    }

    fn reported_carriers() -> (CarrierSender<BusPort>, CarrierReceiver<BusPort>) {
        let network = Arc::new(Mutex::new(VecDeque::new()));
        let sender_port = BusPort {
            media: "127.0.0.1:31000".parse().unwrap(),
            control: "127.0.0.1:31001".parse().unwrap(),
            network: Arc::clone(&network),
        };
        let receiver_port = BusPort {
            media: "127.0.0.1:32000".parse().unwrap(),
            control: "127.0.0.1:32001".parse().unwrap(),
            network,
        };
        let limits = CarrierLimits {
            pace_burst_bytes: 65_536,
            window_packets: 2,
            ..CarrierLimits::baseline()
        };
        let mut sender = CarrierSender::with_port(key(), stream(), 1, limits, sender_port).unwrap();
        sender
            .add_peer(7, receiver_port.media, receiver_port.control, 1500)
            .unwrap();
        let receiver = CarrierReceiver::with_port(
            key(),
            stream(),
            1,
            ReceiverLimits::baseline(),
            receiver_port,
            "127.0.0.1:31001".parse().unwrap(),
        )
        .unwrap()
        .with_peer_id(7)
        .unwrap();
        (sender, receiver)
    }

    fn fixture_source(data: &'static [u8]) -> SourceMedia {
        SourceMedia::open_reader(
            SourceCodec::Mp3,
            Cursor::new(data),
            data.len() as u64,
            SourceOpen {
                caps: Caps::default(),
                reader_limits: SourceReaderLimits {
                    max_read_calls: 100_000,
                    max_reads_per_operation: 100_000,
                    max_seek_calls: 1000,
                    max_read_chunk_bytes: 17,
                },
                transport: epoch(1),
                identity: identity(),
                authority: authority(),
            },
        )
        .expect("fixture source")
    }

    struct CountedReader {
        inner: Cursor<&'static [u8]>,
        reads: Arc<AtomicUsize>,
        seeks: Arc<AtomicUsize>,
    }
    impl Read for CountedReader {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.inner.read(out)
        }
    }
    impl Seek for CountedReader {
        fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
            self.seeks.fetch_add(1, Ordering::Relaxed);
            self.inner.seek(from)
        }
    }
    fn counted_source() -> (SourceMedia, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let reads = Arc::new(AtomicUsize::new(0));
        let seeks = Arc::new(AtomicUsize::new(0));
        let reader = CountedReader {
            inner: Cursor::new(MP3),
            reads: Arc::clone(&reads),
            seeks: Arc::clone(&seeks),
        };
        let source = SourceMedia::open_reader(
            SourceCodec::Mp3,
            reader,
            MP3.len() as u64,
            SourceOpen {
                caps: Caps::default(),
                reader_limits: SourceReaderLimits {
                    max_read_calls: 100_000,
                    max_reads_per_operation: 100_000,
                    max_seek_calls: 1000,
                    max_read_chunk_bytes: 17,
                },
                transport: epoch(1),
                identity: identity(),
                authority: authority(),
            },
        )
        .expect("counted real encoded fixture");
        (source, reads, seeks)
    }

    struct ClockMovingReader {
        inner: Cursor<&'static [u8]>,
        clock: Arc<AtomicUsize>,
        armed: Arc<AtomicBool>,
        reads: Arc<AtomicUsize>,
    }
    impl Read for ClockMovingReader {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            if self.armed.swap(false, Ordering::Relaxed) {
                self.clock.store(101, Ordering::Relaxed);
            }
            self.inner.read(out)
        }
    }
    impl Seek for ClockMovingReader {
        fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
            self.inner.seek(from)
        }
    }
    fn moving_clock_source() -> (
        SourceMedia,
        Arc<AtomicUsize>,
        Arc<AtomicBool>,
        Arc<AtomicUsize>,
    ) {
        let clock = Arc::new(AtomicUsize::new(99));
        let armed = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicUsize::new(0));
        let reader = ClockMovingReader {
            inner: Cursor::new(MP3),
            clock: Arc::clone(&clock),
            armed: Arc::clone(&armed),
            reads: Arc::clone(&reads),
        };
        let source = SourceMedia::open_reader(
            SourceCodec::Mp3,
            reader,
            MP3.len() as u64,
            SourceOpen {
                caps: Caps::default(),
                reader_limits: SourceReaderLimits {
                    max_read_calls: 100_000,
                    max_reads_per_operation: 100_000,
                    max_seek_calls: 1000,
                    max_read_chunk_bytes: 17,
                },
                transport: TransportEpoch {
                    presentation_ns: 102,
                    admitted_lifetime_margin_ns: 2,
                    ..epoch(1)
                },
                identity: identity(),
                authority: authority(),
            },
        )
        .expect("moving-clock MP3 source");
        (source, clock, armed, reads)
    }

    fn short_inputs<'a>(
        interface_now_ns: u64,
        group_ns: u64,
        cancelled: &'a AtomicBool,
    ) -> SourceInputs<'a> {
        SourceInputs {
            interface_now_ns,
            group_clock: view(group_ns),
            work_and_lead_ns: 2,
            overlap_budget_bytes: usize::MAX,
            cancelled,
            authority: authority(),
        }
    }

    fn epoch(epoch: u64) -> TransportEpoch {
        TransportEpoch {
            group: PRIMARY_GROUP,
            epoch,
            start_frame: 0,
            presentation_ns: 10_000_000_000,
            admitted_lifetime_margin_ns: 1_000_000,
            partial_final_allowed: true,
        }
    }

    fn key() -> StreamKey {
        StreamKey::from_bytes([0x61; 32])
    }
    fn stream() -> StreamId {
        StreamId::new(0x1234).unwrap()
    }
    fn carrier() -> CarrierSender<MemoryPort> {
        let limits = CarrierLimits {
            pace_burst_bytes: 65_536,
            window_packets: 256,
            ..CarrierLimits::baseline()
        };
        let mut sender =
            CarrierSender::with_port(key(), stream(), 1, limits, MemoryPort::default()).unwrap();
        sender
            .add_peer(
                7,
                "127.0.0.1:32000".parse().unwrap(),
                "127.0.0.1:32001".parse().unwrap(),
                1500,
            )
            .unwrap();
        sender
    }
    fn view(group_ns: u64) -> ClockView {
        ClockView {
            group_ns,
            uncertainty_ns: 0,
            usable: true,
        }
    }

    fn inputs(
        interface_now_ns: u64,
        group_ns: u64,
        budget: usize,
        cancelled: &AtomicBool,
    ) -> SourceInputs<'_> {
        SourceInputs {
            interface_now_ns,
            group_clock: view(group_ns),
            work_and_lead_ns: 1_000_000,
            overlap_budget_bytes: budget,
            cancelled,
            authority: authority(),
        }
    }

    #[test]
    fn s02_real_fixture_retry_then_authenticated_wire_to_n04_pcm() {
        let mut source = fixture_source(MP3);
        let mut sender = carrier();
        let cancel = AtomicBool::new(false);
        assert!(matches!(
            source.submit_all_peers(&mut sender, &[7], inputs(1, 1, 0, &cancel)),
            Err(SourceError::Admission(AllPeerAdmissionError::Retry(
                AllPeerRetry::Budget
            )))
        ));
        let frame_before = source
            .pending
            .as_ref()
            .expect("retained frame")
            .frame
            .clone();
        let stats_before = source.decoder.stats();
        assert!(matches!(
            source.submit_all_peers(&mut sender, &[7], inputs(2, 2, 0, &cancel)),
            Err(SourceError::Admission(AllPeerAdmissionError::Retry(
                AllPeerRetry::Budget
            )))
        ));
        assert_eq!(source.pending.as_ref().unwrap().frame, frame_before);
        assert_eq!(source.decoder.stats(), stats_before);
        assert!(matches!(
            source.submit_all_peers(&mut sender, &[7], inputs(3, 3, usize::MAX, &cancel)),
            Ok(SourceProgress::Admitted { frames: 256, .. })
        ));
        assert!(source.pending.is_none());
        assert_eq!(
            source
                .pump(&mut sender, inputs(4, 3, usize::MAX, &cancel))
                .unwrap()
                .media_sent,
            1
        );
        let wire = &sender.port().sent[0].1;
        let mut receiver = StreamReceiver::new(key(), stream(), 1);
        let packet = receiver.accept(wire).expect("authenticated packet");
        assert_eq!(packet.start_frame, 0);
        assert_eq!(packet.presentation_time_ns, 10_000_000_000);
        let mut engine = PlayoutEngine::new(
            PlayoutProfile::MUSIC,
            PlayoutConfig {
                work_ns: 500_000,
                lead_ns: 500_000,
                tolerance_ns: 0,
            },
        )
        .unwrap();
        engine.begin_stream(1, 0, 10_000_000_000).unwrap();
        assert_eq!(
            engine.on_packet(view(3), &MediaPacket::from_authenticated(&packet).unwrap()),
            Admission::Admitted
        );
        let mut output = [0u8; BLOCK_PAYLOAD_BYTES];
        assert!(matches!(engine.decide(view(9_999_000_000), &mut output),
            Poll::Decision(decision) if decision.outcome == Outcome::Real && decision.frames == 256));
        assert_eq!(&output[..], packet.payload.as_slice());
        let (actual, _) = output.as_chunks::<2>();
        let (reference, _) = REFERENCE[..BLOCK_PAYLOAD_BYTES].as_chunks::<2>();
        let mut max = 0i32;
        let mut sum = 0f64;
        for (a, b) in actual.iter().zip(reference) {
            let error =
                (i32::from(i16::from_be_bytes(*a)) - i32::from(i16::from_le_bytes(*b))).abs();
            max = max.max(error);
            sum += f64::from(error) * f64::from(error);
        }
        let rms = (sum / actual.len() as f64).sqrt();
        assert!(max <= 4, "peak LSB {max}");
        assert!(rms <= 1.5, "RMS LSB {rms}");
    }

    #[test]
    fn s02_rate_tail_once_and_partial_refusal_preserve_data() {
        let mut source = fixture_source(MP3_441);
        let mut total = 0usize;
        for _ in 0..1000 {
            source.fill().unwrap();
            let frames = (source.ready.len() / 2).min(BLOCK);
            total += frames;
            source.ready.drain(..frames * 2);
            if source.boundary && source.ready.is_empty() {
                break;
            }
        }
        assert!(source.eof);
        assert_eq!(total as u64, franken_codec::outputs_after(22_050 + 64));
        source.fill().unwrap();
        assert!(source.ready.is_empty(), "tail may be flushed only once");

        let mut source = fixture_source(MP3);
        source.epoch.partial_final_allowed = false;
        source.ready = vec![1, -1];
        source.boundary = true;
        source.eof = true;
        let mut sender = carrier();
        let cancel = AtomicBool::new(false);
        assert!(matches!(
            source.submit_all_peers(&mut sender, &[7], inputs(1, 1, usize::MAX, &cancel)),
            Err(SourceError::PartialNotNegotiated)
        ));
        assert_eq!(source.ready, [1, -1]);
        assert!(source.pending.is_none());
        source.epoch.partial_final_allowed = true;
        assert!(matches!(
            source.submit_all_peers(&mut sender, &[7], inputs(2, 2, usize::MAX, &cancel)),
            Ok(SourceProgress::Admitted { frames: 1, .. })
        ));
    }

    #[test]
    fn s02_seek_discards_pending_and_starts_fresh_epoch() {
        let mut source = fixture_source(MP3);
        let mut sender = carrier();
        let cancel = AtomicBool::new(false);
        assert!(
            source
                .submit_all_peers(&mut sender, &[7], inputs(1, 1, 0, &cancel))
                .is_err()
        );
        assert!(source.pending.is_some());
        assert!(matches!(
            source.seek_new_epoch(&mut sender, 1000, epoch(2), authority()),
            Err(SourceError::EpochRequired)
        ));
        let mut foreign = carrier();
        foreign.advance_epoch(2).unwrap();
        let pending = source.pending.as_ref().unwrap().frame.clone();
        let stats = source.decoder.stats();
        assert!(matches!(
            source.seek_new_epoch(&mut foreign, 1000, epoch(2), authority()),
            Err(SourceError::Admission(
                AllPeerAdmissionError::MembershipChanged
            ))
        ));
        assert_eq!(source.pending.as_ref().unwrap().frame, pending);
        assert_eq!(source.decoder.stats(), stats);
        sender.advance_epoch(2).unwrap();
        source
            .seek_new_epoch(&mut sender, 1000, epoch(2), authority())
            .unwrap();
        assert!(source.pending.is_none());
        assert!(source.ready.is_empty());
        assert!(source.adapter.is_none());
        assert!(matches!(
            source.submit_all_peers(&mut sender, &[7], inputs(2, 2, usize::MAX, &cancel)),
            Ok(SourceProgress::Admitted { frames: 256, .. })
        ));
        assert_eq!(
            source
                .pump(&mut sender, inputs(3, 2, usize::MAX, &cancel))
                .unwrap()
                .media_sent,
            1
        );
        let mut receiver = StreamReceiver::new(key(), stream(), 2);
        let packet = receiver.accept(&sender.port().sent[0].1).unwrap();
        assert_eq!(
            packet.start_frame, 0,
            "new wire epoch has its own 48 kHz origin"
        );
        let (samples, _) = packet.payload.as_chunks::<2>();
        let (expected, _) = REFERENCE[1000 * 4..1000 * 4 + BLOCK_PAYLOAD_BYTES].as_chunks::<2>();
        let max = samples
            .iter()
            .zip(expected)
            .map(|(a, b)| {
                (i32::from(i16::from_be_bytes(*a)) - i32::from(i16::from_le_bytes(*b))).abs()
            })
            .max()
            .unwrap();
        assert!(
            max <= 4,
            "seek samples differ from independent reference: {max}"
        );
    }

    #[test]
    fn s02_nonzero_anchor_uses_absolute_frame_rounding() {
        let mut source = fixture_source(MP3);
        source.epoch.start_frame = 256;
        source.sent_frames = 512;
        source.ready = vec![0; 512];
        let frame = source.make_frame(256).unwrap();
        assert_eq!(frame.start_frame, 768);
        assert_eq!(frame.presentation_time_ns, 10_010_666_667);
        assert_eq!(frame.consume_by_ns, 10_009_666_667);
    }

    #[test]
    fn s02_format_change_drains_old_tail_before_new_epoch() {
        let mut source = fixture_source(CHAIN);
        let mut old_frames = 0usize;
        for _ in 0..1000 {
            source.fill().unwrap();
            let frames = (source.ready.len() / 2).min(BLOCK);
            old_frames += frames;
            source.ready.drain(..frames * 2);
            if source.boundary && source.ready.is_empty() {
                break;
            }
        }
        assert!(source.boundary);
        assert!(!source.eof);
        assert_eq!(old_frames as u64, franken_codec::outputs_after(22_050 + 64));
        assert!(source.deferred.is_some());
        let mut sender = carrier();
        assert!(matches!(
            source.begin_format_epoch(&mut sender, epoch(1), authority()),
            Err(SourceError::EpochRequired)
        ));
        sender.advance_epoch(2).unwrap();
        source
            .begin_format_epoch(&mut sender, epoch(2), authority())
            .unwrap();
        source.fill().unwrap();
        assert_eq!(source.format.unwrap().rate_hz, 48_000);
        assert!(!source.ready.is_empty());
    }

    #[test]
    fn s02_mono_is_duplicated_to_both_wire_channels() {
        let mut source = fixture_source(MP3);
        source.rate_output = vec![0, 256, -256];
        source.append_rate_output(1);
        assert_eq!(source.ready, [0, 0, 1, 1, -1, -1]);
    }

    #[test]
    fn s02_buffered_pcm_retains_decode_snapshot_across_member_aba() {
        let mut source = fixture_source(MP3);
        let mut sender = carrier();
        let cancel = AtomicBool::new(false);
        assert!(matches!(
            source.submit_all_peers(&mut sender, &[7], inputs(1, 1, usize::MAX, &cancel)),
            Ok(SourceProgress::Admitted { frames: 256, .. })
        ));
        assert!(
            source.ready.len() >= BLOCK * CHANNELS,
            "decoded block must span N01 frames"
        );
        assert!(source.snapshot.is_some());
        assert_eq!(
            source
                .prepare(&mut sender, &[7], inputs(2, 2, usize::MAX, &cancel))
                .unwrap(),
            PrepareProgress::Ready
        );
        let pending = source.pending.as_ref().unwrap();
        let pending_frame = pending.frame.clone();
        let pending_frames = pending.frames;
        let ready = source.ready.clone();
        let stats = source.decoder.stats();
        sender.remove_peer(7).unwrap();
        sender
            .add_peer(
                7,
                "127.0.0.1:33000".parse().unwrap(),
                "127.0.0.1:33001".parse().unwrap(),
                1500,
            )
            .unwrap();
        assert!(matches!(
            source.submit_all_peers(&mut sender, &[7], inputs(2, 2, usize::MAX, &cancel)),
            Err(SourceError::Admission(
                AllPeerAdmissionError::MembershipChanged
            ))
        ));
        assert_eq!(source.ready, ready);
        assert_eq!(source.decoder.stats(), stats);
        assert!(source.pending.is_some());
        let pending = source.pending.as_ref().unwrap();
        assert_eq!(pending.frame, pending_frame);
        assert_eq!(pending.frames, pending_frames);
    }

    #[test]
    fn s02_same_snapshot_allows_unchanged_membership_continuation() {
        let mut source = fixture_source(MP3);
        let mut sender = carrier();
        let cancel = AtomicBool::new(false);
        assert!(matches!(
            source.submit_all_peers(&mut sender, &[7], inputs(1, 1, usize::MAX, &cancel)),
            Ok(SourceProgress::Admitted { frames: 256, .. })
        ));
        assert!(source.ready.len() >= BLOCK * CHANNELS);
        let stats = source.decoder.stats();
        assert!(matches!(
            source.submit_all_peers(&mut sender, &[7], inputs(2, 2, usize::MAX, &cancel)),
            Ok(SourceProgress::Admitted { frames: 256, .. })
        ));
        assert_eq!(
            source.decoder.stats(),
            stats,
            "buffered frame must not advance decoder"
        );
    }

    #[test]
    fn s02_lifetime_bound_exceeded_fences_queued_media_before_pump() {
        let mut source = fixture_source(MP3);
        let mut sender = carrier();
        let cancel = AtomicBool::new(false);
        assert!(matches!(
            source.submit_all_peers(&mut sender, &[7], inputs(1, 1, usize::MAX, &cancel)),
            Ok(SourceProgress::Admitted { frames: 256, .. })
        ));
        let mut exceeded = inputs(2, 2, usize::MAX, &cancel);
        exceeded.group_clock.uncertainty_ns = 1;
        assert!(matches!(
            source.pump(&mut sender, exceeded),
            Err(SourceError::BoundExceeded)
        ));
        assert!(source.pending.is_none());
        assert!(source.ready.is_empty());
        assert!(sender.port().sent.is_empty());
        let clock = N01GroupClock {
            group: PRIMARY_GROUP,
            epoch: 1,
            view: view(2),
        };
        assert_eq!(sender.pump_n01_clocked(3, &[clock], &cancel).media_sent, 0);
        assert!(sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]).is_err());
        sender.advance_epoch(2).unwrap();
        source
            .seek_new_epoch(&mut sender, 0, epoch(2), authority())
            .unwrap();
        assert!(matches!(
            source.submit_all_peers(&mut sender, &[7], inputs(4, 4, usize::MAX, &cancel)),
            Ok(SourceProgress::Admitted { frames: 256, .. })
        ));
        assert_eq!(
            source
                .pump(&mut sender, inputs(5, 4, usize::MAX, &cancel))
                .unwrap()
                .media_sent,
            1
        );
    }

    #[test]
    fn s02_stale_or_foreign_source_cannot_fence_current_carrier_epoch() {
        for foreign in [false, true] {
            let mut source = fixture_source(MP3);
            let mut owner = carrier();
            let cancel = AtomicBool::new(false);
            assert!(matches!(
                source.submit_all_peers(&mut owner, &[7], inputs(1, 1, 0, &cancel)),
                Err(SourceError::Admission(AllPeerAdmissionError::Retry(
                    AllPeerRetry::Budget
                )))
            ));
            let mut other = carrier();
            let target = if foreign {
                &mut other
            } else {
                owner.advance_epoch(2).unwrap();
                &mut owner
            };
            let expected_epoch = if foreign { 1 } else { 2 };
            let mut invalid = inputs(2, 2, usize::MAX, &cancel);
            invalid.group_clock.uncertainty_ns = 1;
            assert!(matches!(
                source.pump(target, invalid),
                Err(SourceError::Admission(
                    AllPeerAdmissionError::MembershipChanged
                ))
            ));
            assert!(
                target
                    .snapshot_n01_group(PRIMARY_GROUP, expected_epoch, &[7])
                    .is_ok()
            );
        }
    }

    #[test]
    fn s02_source_cannot_pump_an_unrelated_carrier() {
        let mut source = fixture_source(MP3);
        let mut owner = carrier();
        let mut foreign = carrier();
        let cancel = AtomicBool::new(false);
        assert!(matches!(
            source.submit_all_peers(&mut owner, &[7], inputs(1, 1, 0, &cancel)),
            Err(SourceError::Admission(AllPeerAdmissionError::Retry(
                AllPeerRetry::Budget
            )))
        ));
        let frame = source.pending.as_ref().unwrap().frame.clone();
        assert!(matches!(
            source.pump(&mut foreign, inputs(2, 2, usize::MAX, &cancel)),
            Err(SourceError::Admission(
                AllPeerAdmissionError::MembershipChanged
            ))
        ));
        assert_eq!(source.pending.as_ref().unwrap().frame, frame);
        assert!(foreign.port().sent.is_empty());
    }

    #[test]
    fn s02_unbound_source_cannot_pump_queued_protected_media() {
        let mut owner = fixture_source(MP3);
        let mut unbound = fixture_source(MP3);
        let mut sender = carrier();
        let cancel = AtomicBool::new(false);
        assert!(matches!(
            owner.submit_all_peers(&mut sender, &[7], inputs(1, 1, usize::MAX, &cancel)),
            Ok(SourceProgress::Admitted { frames: 256, .. })
        ));
        let before = sender.group_view(PRIMARY_GROUP).unwrap();
        assert!(matches!(
            unbound.pump(&mut sender, inputs(2, 2, usize::MAX, &cancel)),
            Err(SourceError::Admission(
                AllPeerAdmissionError::MembershipChanged
            ))
        ));
        assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before);
        assert!(sender.port().sent.is_empty());
        assert_eq!(
            owner
                .pump(&mut sender, inputs(3, 2, usize::MAX, &cancel))
                .unwrap()
                .media_sent,
            1
        );
    }

    #[test]
    fn s02_isolated_two_peer_slow_peer_does_not_stop_healthy_pcm() {
        assert!(std::mem::size_of::<IsolatedProgress>() <= 2 * std::mem::size_of::<usize>());
        let mut source = fixture_source(MP3);
        let mut sender = carrier();
        sender
            .add_peer(
                8,
                "127.0.0.1:32002".parse().unwrap(),
                "127.0.0.1:32003".parse().unwrap(),
                1500,
            )
            .unwrap();
        sender.set_path_mtu(8, 500).unwrap();
        let cancel = AtomicBool::new(false);
        let mut receiver = StreamReceiver::new(key(), stream(), 1);
        let mut packets = Vec::new();
        let mut report = None;
        for index in 0..3u64 {
            let result = source
                .submit_isolated(
                    &mut sender,
                    &[7, 8],
                    inputs(index * 10_000_000 + 1, index + 1, usize::MAX, &cancel),
                    &mut report,
                )
                .unwrap();
            let IsolatedProgress::Published { frames } = result else {
                panic!("publication expected")
            };
            assert_eq!(frames, 256);
            let outcome = report.as_ref().expect("publication report");
            assert_eq!(outcome.status, N01IsolatedStatus::Published);
            assert_eq!(outcome.peer_count, 2);
            assert!(
                outcome
                    .peers
                    .iter()
                    .flatten()
                    .any(|p| p.peer == 7 && p.disposition == N01PeerDisposition::Queued)
            );
            assert!(
                outcome
                    .peers
                    .iter()
                    .flatten()
                    .any(|p| p.peer == 8 && p.disposition == N01PeerDisposition::Fenced)
            );
            assert_eq!(
                source
                    .pump(
                        &mut sender,
                        inputs(index * 10_000_000 + 2, index + 1, usize::MAX, &cancel),
                    )
                    .unwrap()
                    .media_sent,
                1
            );
            let wire = &sender.port().sent.last().unwrap().1;
            let packet = receiver.accept(wire).unwrap();
            assert_eq!(packet.start_frame, index * 256);
            assert_eq!(packet.seq, index);
            packets.push(packet);
        }
        let previous_report = report.clone();
        assert!(matches!(
            source.publish_isolated(&mut sender, &[7, 8], None, &mut report),
            Err(SourceError::ObservationRequired)
        ));
        assert_eq!(report, previous_report);
        assert_eq!(source.counters().published_blocks, 3);
        assert_eq!(source.counters().skipped_fenced, 3);
        let mut engine = n04();
        for (i, packet) in packets.iter().enumerate() {
            assert_eq!(
                engine.on_packet(
                    view(i as u64 + 1),
                    &MediaPacket::from_authenticated(packet).unwrap()
                ),
                Admission::Admitted
            );
        }
        for (i, packet) in packets.iter().enumerate() {
            let presentation = 10_000_000_000 + (i as u64 * 256 * 62_500 / 3);
            let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
            assert!(
                matches!(engine.decide(view(presentation - 1_000_000), &mut out),
                Poll::Decision(decision) if decision.outcome == Outcome::Real && decision.frames == 256)
            );
            assert_eq!(&out[..], packet.payload.as_slice());
            let (pairs, _) = packet.payload.as_chunks::<2>();
            let reference = &REFERENCE[i * BLOCK_PAYLOAD_BYTES..(i + 1) * BLOCK_PAYLOAD_BYTES];
            let (expected, _) = reference.as_chunks::<2>();
            assert!(pairs.iter().zip(expected).all(|(a, b)| {
                (i32::from(i16::from_be_bytes(*a)) - i32::from(i16::from_le_bytes(*b))).abs() <= 4
            }));
        }
        sender.set_path_mtu(8, 1500).unwrap();
        let rejoin_group_ns = 10_010_000_000;
        let result = source
            .submit_isolated(
                &mut sender,
                &[7, 8],
                inputs(31_000_001, rejoin_group_ns, usize::MAX, &cancel),
                &mut report,
            )
            .unwrap();
        let IsolatedProgress::Published { .. } = result else {
            panic!("rejoin publication")
        };
        let outcome = report.as_ref().expect("rejoin report");
        assert_eq!(outcome.status, N01IsolatedStatus::Published);
        assert!(
            outcome
                .peers
                .iter()
                .flatten()
                .any(|p| p.peer == 8 && p.disposition == N01PeerDisposition::Queued)
        );
        assert_eq!(
            source
                .pump(
                    &mut sender,
                    inputs(31_000_002, rejoin_group_ns, usize::MAX, &cancel),
                )
                .unwrap()
                .media_sent,
            2
        );
        let peer8 = "127.0.0.1:32002".parse::<SocketAddr>().unwrap();
        let peer8_wires: Vec<_> = sender
            .port()
            .sent
            .iter()
            .filter(|(_, _, to)| *to == peer8)
            .collect();
        assert_eq!(peer8_wires.len(), 1, "rejoin must not replay missed audio");
        let mut peer8_receiver = StreamReceiver::new(key(), stream(), 1);
        let packet = peer8_receiver.accept(&peer8_wires[0].1).unwrap();
        assert_eq!(packet.start_frame, 768);
        assert_eq!(packet.seq, 0);
        let mut slow_playout = n04();
        let mut output = [0u8; BLOCK_PAYLOAD_BYTES];
        for index in 0..3u64 {
            let presentation = 10_000_000_000 + index * 256 * 62_500 / 3;
            assert!(matches!(
                slow_playout.decide(view(presentation - 1_000_000), &mut output),
                Poll::Decision(decision) if decision.outcome == Outcome::MutedNoHistory
            ));
        }
        assert_eq!(
            slow_playout.on_packet(
                view(rejoin_group_ns),
                &MediaPacket::from_authenticated(&packet).unwrap()
            ),
            Admission::Admitted
        );
        assert!(matches!(
            slow_playout.decide(view(packet.presentation_time_ns - 1_000_000), &mut output),
            Poll::Decision(decision) if decision.outcome == Outcome::Real && decision.frames == 256
        ));
        assert_eq!(&output[..], packet.payload.as_slice());
    }

    #[test]
    fn s02_isolated_no_peer_does_not_decode_and_expired_pending_skips_once() {
        let mut unavailable = fixture_source(MP3);
        let mut sender = carrier();
        let cancel = AtomicBool::new(false);
        let mut report = None;
        sender.set_path_mtu(7, 500).unwrap();
        let before = unavailable.decoder.stats();
        assert!(matches!(
            unavailable.submit_isolated(
                &mut sender,
                &[7],
                inputs(1, 1, usize::MAX, &cancel),
                &mut report
            ),
            Err(SourceError::Admission(AllPeerAdmissionError::Retry(
                AllPeerRetry::NoEligiblePeers
            )))
        ));
        assert!(report.is_none());
        assert_eq!(unavailable.decoder.stats(), before);
        assert!(unavailable.ready.is_empty());
        assert!(unavailable.pending.is_none());
        sender.set_path_mtu(7, 1500).unwrap();
        assert!(matches!(
            unavailable.submit_isolated(&mut sender, &[7], inputs(2, 2, 0, &cancel), &mut report),
            Err(SourceError::Admission(AllPeerAdmissionError::Retry(
                AllPeerRetry::Budget
            )))
        ));
        let expired_frame = unavailable.pending.as_ref().unwrap().frame.clone();
        let stats = unavailable.decoder.stats();
        let deadline = expired_frame.consume_by_ns;
        assert!(matches!(
            unavailable.submit_isolated(
                &mut sender,
                &[7],
                inputs(3, deadline, usize::MAX, &cancel),
                &mut report
            ),
            Ok(IsolatedProgress::Expired { frames: 256 })
        ));
        assert_eq!(report.as_ref().unwrap().status, N01IsolatedStatus::Expired);
        assert_eq!(unavailable.decoder.stats(), stats);
        assert_eq!(unavailable.counters().expired_blocks, 1);
        assert_eq!(unavailable.counters().expired_frames, 256);
        assert!(unavailable.pending.is_none());
        assert!(sender.port().sent.is_empty());
        let expired_report = report.clone();
        assert!(matches!(
            unavailable.submit_isolated(
                &mut sender,
                &[7],
                inputs(4, deadline, 0, &cancel),
                &mut report
            ),
            Err(SourceError::Admission(AllPeerAdmissionError::Retry(
                AllPeerRetry::Budget
            )))
        ));
        assert_eq!(report, expired_report);
        assert!(matches!(
            unavailable.submit_isolated(
                &mut sender,
                &[7],
                inputs(4, deadline, usize::MAX, &cancel),
                &mut report
            ),
            Ok(IsolatedProgress::Published { frames: 256, .. })
        ));
        assert_eq!(
            report.as_ref().unwrap().status,
            N01IsolatedStatus::Published
        );
        assert_eq!(unavailable.counters().expired_blocks, 1);
        assert_eq!(
            unavailable
                .pump(&mut sender, inputs(5, deadline, usize::MAX, &cancel),)
                .unwrap()
                .media_sent,
            1
        );
        let mut receiver = StreamReceiver::new(key(), stream(), 1);
        let packet = receiver.accept(&sender.port().sent[0].1).unwrap();
        assert_eq!(packet.start_frame, 256, "expired frame must not replay");
        assert_eq!(packet.seq, 0);
    }

    fn small_floor_carrier(path_mtu: usize, aggregate_bytes: usize) -> CarrierSender<MemoryPort> {
        let limits = CarrierLimits {
            required_payload_bytes: 4,
            aggregate_queue_bytes: aggregate_bytes,
            pace_burst_bytes: 65_536,
            ..CarrierLimits::baseline()
        };
        let mut sender =
            CarrierSender::with_port(key(), stream(), 1, limits, MemoryPort::default())
                .expect("legitimate small-payload carrier");
        sender
            .add_peer(
                7,
                "127.0.0.1:32000".parse().unwrap(),
                "127.0.0.1:32001".parse().unwrap(),
                path_mtu,
            )
            .expect("admit small floor");
        assert!(sender.peer_view(7).unwrap().fence.is_none());
        sender
    }

    #[test]
    fn s02_predecode_undersized_mtu_leaves_real_reader_and_decoder_untouched() {
        // 1000-byte MTU carries the configured four-byte floor, but not the
        // actual 1024-byte N01 payload plus wire/IP/UDP overhead.
        let mut sender = small_floor_carrier(1000, 147_456);
        let (mut source, reads, seeks) = counted_source();
        let cancel = AtomicBool::new(false);
        let before_stats = source.decoder.stats();
        let before_reads = reads.load(Ordering::Relaxed);
        let before_seeks = seeks.load(Ordering::Relaxed);
        assert!(
            before_reads > 0,
            "finite source setup already probed the reader"
        );
        assert!(
            before_seeks >= 2,
            "finite source setup validated seekable length"
        );
        assert!(matches!(
            source.submit_isolated(
                &mut sender,
                &[7],
                inputs(1, 1, usize::MAX, &cancel),
                &mut None
            ),
            Err(SourceError::Admission(AllPeerAdmissionError::Retry(
                AllPeerRetry::NoEligiblePeers
            )))
        ));
        assert_eq!(source.decoder.stats(), before_stats);
        assert_eq!(reads.load(Ordering::Relaxed), before_reads);
        assert_eq!(seeks.load(Ordering::Relaxed), before_seeks);
        assert!(source.ready.is_empty());
        assert!(source.pending.is_none());
        assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 0);

        // MTU recovery is not a membership change; the same snapshot can
        // now decode and publish a complete real fixture block.
        sender.set_path_mtu(7, 1500).unwrap();
        assert!(matches!(
            source.submit_isolated(
                &mut sender,
                &[7],
                inputs(2, 2, usize::MAX, &cancel),
                &mut None
            ),
            Ok(IsolatedProgress::Published { frames: 256, .. })
        ));
        assert!(source.decoder.stats().packets > before_stats.packets);
        assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 1);
    }

    #[test]
    fn s02_all_cooldown_does_not_advance_real_decoder_then_recovers() {
        let failing = Arc::new(AtomicBool::new(true));
        let port = CooldownPort {
            failing: Arc::clone(&failing),
            sent: Vec::new(),
        };
        let mut sender =
            CarrierSender::with_port(key(), stream(), 1, CarrierLimits::baseline(), port).unwrap();
        sender
            .add_peer(
                7,
                "127.0.0.1:32000".parse().unwrap(),
                "127.0.0.1:32001".parse().unwrap(),
                1500,
            )
            .unwrap();
        let (mut source, reads, seeks) = counted_source();
        let cancel = AtomicBool::new(false);
        assert_eq!(
            source
                .prepare(&mut sender, &[7], inputs(1, 1, usize::MAX, &cancel))
                .unwrap(),
            PrepareProgress::Ready
        );
        assert!(matches!(
            source.publish_isolated(
                &mut sender,
                &[7],
                Some(inputs(1, 1, usize::MAX, &cancel)),
                &mut None
            ),
            Ok(IsolatedProgress::Published { .. })
        ));
        assert_eq!(
            source
                .pump(&mut sender, inputs(2, 2, usize::MAX, &cancel))
                .unwrap()
                .media_sent,
            0
        );
        let before_stats = source.decoder.stats();
        let before_reads = reads.load(Ordering::Relaxed);
        let before_seeks = seeks.load(Ordering::Relaxed);
        assert!(matches!(
            source.prepare(&mut sender, &[7], inputs(2, 2, usize::MAX, &cancel)),
            Err(SourceError::Admission(AllPeerAdmissionError::Retry(
                AllPeerRetry::NoEligiblePeers
            )))
        ));
        assert_eq!(source.decoder.stats(), before_stats);
        assert_eq!(reads.load(Ordering::Relaxed), before_reads);
        assert_eq!(seeks.load(Ordering::Relaxed), before_seeks);
        assert!(source.pending.is_none());
        failing.store(false, Ordering::Relaxed);
        assert_eq!(
            source
                .prepare(&mut sender, &[7], inputs(4, 4, usize::MAX, &cancel))
                .unwrap(),
            PrepareProgress::Ready
        );
        assert!(matches!(
            source.publish_isolated(
                &mut sender,
                &[7],
                Some(inputs(4, 4, usize::MAX, &cancel)),
                &mut None
            ),
            Ok(IsolatedProgress::Published { .. })
        ));
        assert!(
            source
                .pump(&mut sender, inputs(5, 4, usize::MAX, &cancel))
                .unwrap()
                .media_sent
                >= 1
        );
    }

    #[test]
    fn s02_postdecode_fresh_time_expires_once_without_publication_or_reads() {
        let (mut source, clock, armed, reads) = moving_clock_source();
        let mut sender = carrier();
        let cancel = AtomicBool::new(false);
        let before_reads = reads.load(Ordering::Relaxed);
        armed.store(true, Ordering::Relaxed);
        assert_eq!(
            source
                .prepare(&mut sender, &[7], short_inputs(1, 99, &cancel))
                .unwrap(),
            PrepareProgress::Ready
        );
        assert_eq!(
            clock.load(Ordering::Relaxed),
            101,
            "real reader moved the trusted time"
        );
        assert!(reads.load(Ordering::Relaxed) > before_reads);
        let pending = source.pending.as_ref().unwrap().frame.clone();
        assert_eq!(pending.consume_by_ns, 100);
        let after_prepare = reads.load(Ordering::Relaxed);
        let decoder_stats = source.decoder.stats();
        assert!(matches!(
            source.publish_isolated(&mut sender, &[7], None, &mut None),
            Err(SourceError::ObservationRequired)
        ));
        assert_eq!(source.pending.as_ref().unwrap().frame, pending);
        assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 0);
        assert!(matches!(
            source.publish_isolated(
                &mut sender,
                &[7],
                Some(short_inputs(
                    2,
                    clock.load(Ordering::Relaxed) as u64,
                    &cancel
                )),
                &mut None
            ),
            Ok(IsolatedProgress::Expired { frames: 256 })
        ));
        assert_eq!(source.counters().expired_blocks, 1);
        assert_eq!(source.counters().expired_frames, 256);
        assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 0);
        assert!(source.pending.is_none());
        assert!(matches!(
            source.publish_isolated(
                &mut sender,
                &[7],
                Some(short_inputs(3, 101, &cancel)),
                &mut None
            ),
            Err(SourceError::NotPrepared)
        ));
        assert_eq!(source.counters().expired_blocks, 1);
        assert_eq!(reads.load(Ordering::Relaxed), after_prepare);
        assert_eq!(source.decoder.stats(), decoder_stats);
    }

    #[test]
    fn s02_same_policy_identity_cannot_claim_a_second_source_selection() {
        let mut first = fixture_source(MP3);
        let (mut second, reads, seeks) = counted_source();
        let mut sender = carrier();
        let cancel = AtomicBool::new(false);
        assert_eq!(
            first
                .prepare(&mut sender, &[7], inputs(1, 1, usize::MAX, &cancel))
                .unwrap(),
            PrepareProgress::Ready
        );
        let before_reads = reads.load(Ordering::Relaxed);
        let before_seeks = seeks.load(Ordering::Relaxed);
        let before_stats = second.decoder.stats();
        assert!(matches!(
            second.prepare(&mut sender, &[7], inputs(2, 2, usize::MAX, &cancel)),
            Err(SourceError::Admission(
                AllPeerAdmissionError::MembershipChanged
            ))
        ));
        assert_eq!(reads.load(Ordering::Relaxed), before_reads);
        assert_eq!(seeks.load(Ordering::Relaxed), before_seeks);
        assert_eq!(second.decoder.stats(), before_stats);
        assert!(matches!(
            first.publish_isolated(
                &mut sender,
                &[7],
                Some(inputs(3, 3, usize::MAX, &cancel)),
                &mut None
            ),
            Ok(IsolatedProgress::Published { frames: 256, .. })
        ));
    }

    #[test]
    fn s02_equal_epoch_foreign_policy_group_cannot_touch_selection() {
        let mut source = fixture_source(MP3);
        let mut sender = carrier();
        let cancel = AtomicBool::new(false);
        let good = inputs(1, 1, usize::MAX, &cancel);
        assert_eq!(
            source.prepare(&mut sender, &[7], good).unwrap(),
            PrepareProgress::Ready
        );
        assert!(matches!(
            source.publish_isolated(&mut sender, &[7], Some(good), &mut None),
            Ok(IsolatedProgress::Published { frames: 256, .. })
        ));
        assert_eq!(
            source.prepare(&mut sender, &[7], good).unwrap(),
            PrepareProgress::Ready
        );
        let before_frame = source.pending.as_ref().unwrap().frame.clone();
        let before_ready = source.ready.clone();
        let before_stats = source.decoder.stats();
        let before_queue = sender.group_view(PRIMARY_GROUP).unwrap();
        let before_counts = source.counters();

        // Same numeric session epoch and same source label/epoch: the original
        // arbiter check alone would accept this other group's session.
        let fixture = fixture_authority();
        let foreign =
            UnifiedGroupSession::new("different-group", "leader", fixture.session.current_epoch);
        assert!(
            fixture
                .arbiter
                .check_publish(
                    &foreign,
                    &fixture.identity.source,
                    fixture.identity.policy_epoch
                )
                .is_ok()
        );
        let mut wrong = inputs(2, 2, usize::MAX, &cancel);
        wrong.authority = SourceAuthority {
            arbiter: &fixture.arbiter,
            session: &foreign,
        };
        assert!(matches!(
            source.prepare(&mut sender, &[7], wrong),
            Err(SourceError::WrongPolicyGroup)
        ));
        assert!(matches!(
            source.publish_isolated(&mut sender, &[7], Some(wrong), &mut None),
            Err(SourceError::WrongPolicyGroup)
        ));
        assert!(matches!(
            source.pump(&mut sender, wrong),
            Err(SourceError::WrongPolicyGroup)
        ));
        assert_eq!(source.pending.as_ref().unwrap().frame, before_frame);
        assert_eq!(source.ready, before_ready);
        assert_eq!(source.decoder.stats(), before_stats);
        assert_eq!(source.counters(), before_counts);
        assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before_queue);
        assert!(sender.port().sent.is_empty());

        let valid = inputs(3, 3, usize::MAX, &cancel);
        assert!(matches!(
            source.publish_isolated(&mut sender, &[7], Some(valid), &mut None),
            Ok(IsolatedProgress::Published { frames: 256, .. })
        ));
        assert_eq!(source.pump(&mut sender, valid).unwrap().media_sent, 2);
    }

    #[test]
    fn s02_older_same_group_view_leaves_pending_and_queue_intact() {
        use franken_session::{FencedControlCommand, GroupCommandPayload};
        let fixture = fixture_authority();
        let mut session = fixture.session.clone();
        session
            .apply_command(FencedControlCommand {
                epoch: 2,
                command_seq: 1,
                payload: GroupCommandPayload::SetGroupVolume {
                    volume_0_to_100: 50,
                },
            })
            .unwrap();
        let mut arbiter = fixture.arbiter.clone();
        let token = AuthorityToken::issue(&session, u64::MAX);
        let source_epoch = arbiter.view(&session).epoch;
        let admitted = arbiter
            .submit(
                &session,
                &token,
                1,
                &SourceCommand {
                    source: fixture.identity.source.clone(),
                    class: CommandClass::Start,
                    expected_epoch: source_epoch,
                },
            )
            .unwrap();
        let reads = Arc::new(AtomicUsize::new(0));
        let seeks = Arc::new(AtomicUsize::new(0));
        let reader = CountedReader {
            inner: Cursor::new(MP3),
            reads: Arc::clone(&reads),
            seeks: Arc::clone(&seeks),
        };
        let mut source = SourceMedia::open_reader(
            SourceCodec::Mp3,
            reader,
            MP3.len() as u64,
            SourceOpen {
                caps: Caps::default(),
                reader_limits: SourceReaderLimits {
                    max_read_calls: 100_000,
                    max_reads_per_operation: 100_000,
                    max_seek_calls: 1000,
                    max_read_chunk_bytes: 17,
                },
                transport: epoch(1),
                identity: SourceIdentity {
                    source: fixture.identity.source.clone(),
                    policy_epoch: admitted.epoch,
                },
                authority: SourceAuthority {
                    arbiter: &arbiter,
                    session: &session,
                },
            },
        )
        .unwrap();
        let mut sender = carrier();
        let cancel = AtomicBool::new(false);
        let mut current = inputs(1, 1, usize::MAX, &cancel);
        current.authority = SourceAuthority {
            arbiter: &arbiter,
            session: &session,
        };
        assert_eq!(
            source.prepare(&mut sender, &[7], current).unwrap(),
            PrepareProgress::Ready
        );
        assert!(matches!(
            source.publish_isolated(&mut sender, &[7], Some(current), &mut None),
            Ok(IsolatedProgress::Published { frames: 256, .. })
        ));
        assert_eq!(
            source.prepare(&mut sender, &[7], current).unwrap(),
            PrepareProgress::Ready
        );
        assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 1);
        let before_frame = source.pending.as_ref().unwrap().frame.clone();
        let before_ready = source.ready.clone();
        let before_stats = source.decoder.stats();
        let before_counts = source.counters();
        let before_queue = sender.group_view(PRIMARY_GROUP).unwrap();
        let before_reads = reads.load(Ordering::Relaxed);
        let before_seeks = seeks.load(Ordering::Relaxed);

        // A stale view has the SAME group id but an earlier group epoch.
        let older = UnifiedGroupSession::new(&session.group_id, &session.coordinator_id, 1);
        assert_eq!(older.group_id, session.group_id);
        let mut stale = inputs(2, 2, usize::MAX, &cancel);
        stale.authority = SourceAuthority {
            arbiter: &arbiter,
            session: &older,
        };
        assert!(matches!(
            source.prepare(&mut sender, &[7], stale),
            Err(SourceError::PolicyGroupEpoch {
                captured: 2,
                observed: 1
            })
        ));
        assert!(matches!(
            source.publish_isolated(&mut sender, &[7], Some(stale), &mut None),
            Err(SourceError::PolicyGroupEpoch {
                captured: 2,
                observed: 1
            })
        ));
        assert!(matches!(
            source.pump(&mut sender, stale),
            Err(SourceError::PolicyGroupEpoch {
                captured: 2,
                observed: 1
            })
        ));
        assert_eq!(source.pending.as_ref().unwrap().frame, before_frame);
        assert_eq!(source.ready, before_ready);
        assert_eq!(source.decoder.stats(), before_stats);
        assert_eq!(source.counters(), before_counts);
        assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before_queue);
        assert_eq!(reads.load(Ordering::Relaxed), before_reads);
        assert_eq!(seeks.load(Ordering::Relaxed), before_seeks);
        assert!(!source.faulted);
        assert!(sender.port().sent.is_empty());

        let mut valid = inputs(3, 3, usize::MAX, &cancel);
        valid.authority = SourceAuthority {
            arbiter: &arbiter,
            session: &session,
        };
        assert!(matches!(
            source.publish_isolated(&mut sender, &[7], Some(valid), &mut None),
            Ok(IsolatedProgress::Published { frames: 256, .. })
        ));
        assert_eq!(source.pump(&mut sender, valid).unwrap().media_sent, 2);
        let mut receiver = StreamReceiver::new(key(), stream(), 1);
        let packets: Vec<_> = sender
            .port()
            .sent
            .iter()
            .map(|(_, wire, _)| receiver.accept(wire).unwrap())
            .collect();
        assert_eq!(packets.len(), 2);
        let mut engine = n04();
        for (index, packet) in packets.iter().enumerate() {
            assert_eq!(packet.seq, index as u64);
            assert_eq!(packet.start_frame, index as u64 * 256);
            assert_eq!(
                engine.on_packet(view(3), &MediaPacket::from_authenticated(packet).unwrap()),
                Admission::Admitted
            );
        }
        for (index, packet) in packets.iter().enumerate() {
            let presentation = 10_000_000_000 + index as u64 * 256 * 62_500 / 3;
            let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
            assert!(
                matches!(engine.decide(view(presentation - 1_000_000), &mut out),
                Poll::Decision(decision) if decision.outcome == Outcome::Real && decision.frames == 256)
            );
            assert_eq!(&out[..], packet.payload.as_slice());
        }
        assert_eq!(
            source.counters().published_blocks,
            before_counts.published_blocks + 1
        );
    }

    #[test]
    fn s02_policy_group_identity_is_bounded_before_reader_setup() {
        let fixture = fixture_authority();
        for name in [String::new(), "x".repeat(65)] {
            let session = UnifiedGroupSession::new(&name, "leader", 1);
            let reads = Arc::new(AtomicUsize::new(0));
            let seeks = Arc::new(AtomicUsize::new(0));
            let reader = CountedReader {
                inner: Cursor::new(MP3),
                reads: Arc::clone(&reads),
                seeks: Arc::clone(&seeks),
            };
            let result = SourceMedia::open_reader(
                SourceCodec::Mp3,
                reader,
                MP3.len() as u64,
                SourceOpen {
                    caps: Caps::default(),
                    reader_limits: SourceReaderLimits {
                        max_read_calls: 100_000,
                        max_reads_per_operation: 100_000,
                        max_seek_calls: 1000,
                        max_read_chunk_bytes: 17,
                    },
                    transport: epoch(1),
                    identity: identity(),
                    authority: SourceAuthority {
                        arbiter: &fixture.arbiter,
                        session: &session,
                    },
                },
            );
            assert!(matches!(result, Err(SourceError::InvalidPolicyGroup)));
            assert_eq!(reads.load(Ordering::Relaxed), 0);
            assert_eq!(seeks.load(Ordering::Relaxed), 0);
        }
        let name = "x".repeat(64);
        let session = UnifiedGroupSession::new(&name, "leader", 1);
        let reads = Arc::new(AtomicUsize::new(0));
        let seeks = Arc::new(AtomicUsize::new(0));
        let reader = CountedReader {
            inner: Cursor::new(MP3),
            reads: Arc::clone(&reads),
            seeks: Arc::clone(&seeks),
        };
        assert!(
            SourceMedia::open_reader(
                SourceCodec::Mp3,
                reader,
                MP3.len() as u64,
                SourceOpen {
                    caps: Caps::default(),
                    reader_limits: SourceReaderLimits {
                        max_read_calls: 100_000,
                        max_reads_per_operation: 100_000,
                        max_seek_calls: 1000,
                        max_read_chunk_bytes: 17,
                    },
                    transport: epoch(1),
                    identity: identity(),
                    authority: SourceAuthority {
                        arbiter: &fixture.arbiter,
                        session: &session
                    }
                }
            )
            .is_ok()
        );
        assert!(reads.load(Ordering::Relaxed) > 0);
        assert!(seeks.load(Ordering::Relaxed) >= 2);
    }

    #[test]
    fn s02_actual_policy_group_epoch_advance_fences_old_queued_and_pending() {
        use franken_session::{FencedControlCommand, GroupCommandPayload};
        let fixture = fixture_authority();
        let mut session = fixture.session.clone();
        let arbiter = fixture.arbiter.clone();
        let mut source = SourceMedia::open_reader(
            SourceCodec::Mp3,
            Cursor::new(MP3),
            MP3.len() as u64,
            SourceOpen {
                caps: Caps::default(),
                reader_limits: SourceReaderLimits {
                    max_read_calls: 100_000,
                    max_reads_per_operation: 100_000,
                    max_seek_calls: 1000,
                    max_read_chunk_bytes: 17,
                },
                transport: epoch(1),
                identity: fixture.identity.clone(),
                authority: SourceAuthority {
                    arbiter: &arbiter,
                    session: &session,
                },
            },
        )
        .unwrap();
        let mut sender = carrier();
        let cancel = AtomicBool::new(false);
        let mut good = inputs(1, 1, usize::MAX, &cancel);
        good.authority = SourceAuthority {
            arbiter: &arbiter,
            session: &session,
        };
        assert_eq!(
            source.prepare(&mut sender, &[7], good).unwrap(),
            PrepareProgress::Ready
        );
        assert!(matches!(
            source.publish_isolated(&mut sender, &[7], Some(good), &mut None),
            Ok(IsolatedProgress::Published { .. })
        ));
        assert_eq!(
            source.prepare(&mut sender, &[7], good).unwrap(),
            PrepareProgress::Ready
        );
        assert!(source.pending.is_some());
        assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 1);

        session
            .apply_command(FencedControlCommand {
                epoch: 2,
                command_seq: 1,
                payload: GroupCommandPayload::SetGroupVolume {
                    volume_0_to_100: 50,
                },
            })
            .unwrap();
        let mut advanced = inputs(2, 2, usize::MAX, &cancel);
        advanced.authority = SourceAuthority {
            arbiter: &arbiter,
            session: &session,
        };
        assert!(matches!(
            source.publish_isolated(&mut sender, &[7], Some(advanced), &mut None),
            Err(SourceError::PolicyGroupEpoch {
                captured: 1,
                observed: 2
            })
        ));
        assert!(source.pending.is_none());
        assert!(source.ready.is_empty());
        assert!(sender.port().sent.is_empty());
        let claim = source.snapshot.as_ref().unwrap();
        let clock = N01GroupClock {
            group: PRIMARY_GROUP,
            epoch: 1,
            view: view(2),
        };
        assert!(sender.pump_n01_selected(3, clock, claim, &cancel).is_err());
        assert!(sender.port().sent.is_empty());
    }

    #[test]
    fn s02_arbiter_replacement_fences_pending_and_queued_then_new_owner_continues() {
        let session = UnifiedGroupSession::new("replace-test", "leader", 1);
        let token = AuthorityToken::issue(&session, u64::MAX);
        let mut table = SourcePolicyTable::STANDARD;
        for kind in SourceKind::ALL {
            for class in CommandClass::ALL {
                table = table.with(kind, class, SourcePolicy::Reject);
            }
        }
        table = table.with(
            SourceKind::AirPlay2,
            CommandClass::Start,
            SourcePolicy::Replace,
        );
        let mut arbiter = SourceArbiter::new(SourceConfig {
            policy: table,
            clock_uncertainty_ns: 0,
        });
        let old = SourceId::new(SourceKind::Spotify, "old").unwrap();
        let new = SourceId::new(SourceKind::AirPlay2, "new").unwrap();
        let started = arbiter
            .submit(
                &session,
                &token,
                1,
                &SourceCommand {
                    source: old.clone(),
                    class: CommandClass::Start,
                    expected_epoch: PolicyEpoch::new(0),
                },
            )
            .unwrap();
        let mut source = SourceMedia::open_reader(
            SourceCodec::Mp3,
            Cursor::new(MP3),
            MP3.len() as u64,
            SourceOpen {
                caps: Caps::default(),
                reader_limits: SourceReaderLimits {
                    max_read_calls: 100_000,
                    max_reads_per_operation: 100_000,
                    max_seek_calls: 1000,
                    max_read_chunk_bytes: 17,
                },
                transport: epoch(1),
                identity: SourceIdentity {
                    source: old.clone(),
                    policy_epoch: started.epoch,
                },
                authority: SourceAuthority {
                    arbiter: &arbiter,
                    session: &session,
                },
            },
        )
        .unwrap();
        let mut sender = carrier();
        let cancel = AtomicBool::new(false);
        let mut call = inputs(1, 1, usize::MAX, &cancel);
        call.authority = SourceAuthority {
            arbiter: &arbiter,
            session: &session,
        };
        assert_eq!(
            source.prepare(&mut sender, &[7], call).unwrap(),
            PrepareProgress::Ready
        );
        assert!(matches!(
            source.publish_isolated(&mut sender, &[7], Some(call), &mut None),
            Ok(IsolatedProgress::Published { frames: 256, .. })
        ));
        assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 1);
        assert_eq!(
            source.prepare(&mut sender, &[7], call).unwrap(),
            PrepareProgress::Ready
        );
        assert!(source.pending.is_some());
        let replaced = arbiter
            .submit(
                &session,
                &token,
                2,
                &SourceCommand {
                    source: new.clone(),
                    class: CommandClass::Start,
                    expected_epoch: started.epoch,
                },
            )
            .unwrap();
        assert_eq!(replaced.replaced, Some(old));
        let mut changed = inputs(2, 2, usize::MAX, &cancel);
        changed.authority = SourceAuthority {
            arbiter: &arbiter,
            session: &session,
        };
        assert!(matches!(
            source.publish_isolated(&mut sender, &[7], Some(changed), &mut None),
            Err(SourceError::Policy(PolicyError::SourceReplaced { .. }))
        ));
        assert!(source.pending.is_none());
        assert!(sender.port().sent.is_empty());
        let old_claim = source.snapshot.as_ref().unwrap();
        let clock = N01GroupClock {
            group: PRIMARY_GROUP,
            epoch: 1,
            view: view(2),
        };
        assert!(
            sender
                .pump_n01_selected(3, clock, old_claim, &cancel)
                .is_err()
        );
        assert!(sender.port().sent.is_empty());

        sender.advance_epoch(2).unwrap();
        let mut fresh = SourceMedia::open_reader(
            SourceCodec::Mp3,
            Cursor::new(MP3),
            MP3.len() as u64,
            SourceOpen {
                caps: Caps::default(),
                reader_limits: SourceReaderLimits {
                    max_read_calls: 100_000,
                    max_reads_per_operation: 100_000,
                    max_seek_calls: 1000,
                    max_read_chunk_bytes: 17,
                },
                transport: epoch(2),
                identity: SourceIdentity {
                    source: new,
                    policy_epoch: replaced.epoch,
                },
                authority: SourceAuthority {
                    arbiter: &arbiter,
                    session: &session,
                },
            },
        )
        .unwrap();
        let mut next = inputs(4, 4, usize::MAX, &cancel);
        next.authority = SourceAuthority {
            arbiter: &arbiter,
            session: &session,
        };
        assert_eq!(
            fresh.prepare(&mut sender, &[7], next).unwrap(),
            PrepareProgress::Ready
        );
        assert!(matches!(
            fresh.publish_isolated(&mut sender, &[7], Some(next), &mut None),
            Ok(IsolatedProgress::Published { frames: 256, .. })
        ));
        assert_eq!(fresh.pump(&mut sender, next).unwrap().media_sent, 1);
    }

    #[test]
    fn s02_postdecode_live_clock_publishes_real_pcm_through_n04() {
        let (mut source, clock, _armed, reads) = moving_clock_source();
        let mut sender = carrier();
        let cancel = AtomicBool::new(false);
        assert_eq!(
            source
                .prepare(&mut sender, &[7], short_inputs(1, 99, &cancel))
                .unwrap(),
            PrepareProgress::Ready
        );
        assert_eq!(clock.load(Ordering::Relaxed), 99);
        let before_publish = reads.load(Ordering::Relaxed);
        let stats = source.decoder.stats();
        assert!(matches!(
            source.publish_isolated(
                &mut sender,
                &[7],
                Some(short_inputs(2, 99, &cancel)),
                &mut None
            ),
            Ok(IsolatedProgress::Published { frames: 256, .. })
        ));
        assert_eq!(reads.load(Ordering::Relaxed), before_publish);
        assert_eq!(source.decoder.stats(), stats);
        assert_eq!(
            source
                .pump(&mut sender, short_inputs(3, 99, &cancel))
                .unwrap()
                .media_sent,
            1
        );
        let mut receiver = StreamReceiver::new(key(), stream(), 1);
        let packet = receiver.accept(&sender.port().sent[0].1).unwrap();
        assert_eq!(packet.consume_by_ns, 100);
        let mut engine = PlayoutEngine::new(
            PlayoutProfile::MUSIC,
            PlayoutConfig {
                work_ns: 1,
                lead_ns: 1,
                tolerance_ns: 0,
            },
        )
        .unwrap();
        engine.begin_stream(1, 0, 102).unwrap();
        assert_eq!(
            engine.on_packet(view(99), &MediaPacket::from_authenticated(&packet).unwrap()),
            Admission::Admitted
        );
        let mut output = [0u8; BLOCK_PAYLOAD_BYTES];
        assert!(matches!(engine.decide(view(100), &mut output),
            Poll::Decision(decision) if decision.outcome == Outcome::Real && decision.frames == 256));
        assert_eq!(&output[..], packet.payload.as_slice());
        let (actual, _) = output.as_chunks::<2>();
        let (reference, _) = REFERENCE[..BLOCK_PAYLOAD_BYTES].as_chunks::<2>();
        let mut max = 0i32;
        let mut sum = 0f64;
        for (a, b) in actual.iter().zip(reference) {
            let error =
                (i32::from(i16::from_be_bytes(*a)) - i32::from(i16::from_le_bytes(*b))).abs();
            max = max.max(error);
            sum += f64::from(error) * f64::from(error);
        }
        assert!(max <= 4);
        assert!((sum / actual.len() as f64).sqrt() <= 1.5);
    }

    #[test]
    fn s02_strict_publication_also_uses_fresh_postdecode_clock() {
        let (mut source, clock, armed, reads) = moving_clock_source();
        let mut sender = carrier();
        let cancel = AtomicBool::new(false);
        armed.store(true, Ordering::Relaxed);
        assert_eq!(
            source
                .prepare(&mut sender, &[7], short_inputs(1, 99, &cancel))
                .unwrap(),
            PrepareProgress::Ready
        );
        assert_eq!(clock.load(Ordering::Relaxed), 101);
        let pending = source.pending.as_ref().unwrap().frame.clone();
        let after = reads.load(Ordering::Relaxed);
        assert!(matches!(
            source.publish_all_peers(&mut sender, &[7], Some(short_inputs(2, 101, &cancel))),
            Err(SourceError::Admission(AllPeerAdmissionError::Invalid(_)))
        ));
        assert_eq!(source.pending.as_ref().unwrap().frame, pending);
        assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 0);
        assert_eq!(reads.load(Ordering::Relaxed), after);
    }

    #[test]
    fn s02_predecode_aggregate_byte_headroom_preserves_real_decoder_until_drain() {
        let mut sender = small_floor_carrier(1500, franken_stream::MAX_DATAGRAM_BYTES);
        let other_stream = StreamId::new(0x5678).unwrap();
        let other = sender.add_group(key(), other_stream, 1).unwrap();
        sender
            .add_peer_in_group(
                other,
                8,
                "127.0.0.1:32002".parse().unwrap(),
                "127.0.0.1:32003".parse().unwrap(),
                1500,
            )
            .unwrap();
        // This legitimate legacy one-frame packet consumes 84 of the 1104
        // allowed wire bytes. Remaining room fits the four-byte admission
        // floor, but not one full source packet.
        let short = OutboundFrame::media(0, 10_000_000_000, 9_999_000_000, vec![0; 4]);
        assert_eq!(
            sender
                .submit_group_media(other, 1, &short, 0)
                .unwrap()
                .queued,
            1
        );
        let initial = sender.group_view(other).unwrap();
        assert_eq!(initial.queued_packets, 1);
        assert_eq!(
            initial.queued_bytes,
            franken_stream::MAX_DATAGRAM_BYTES - 1024 + 4
        );
        let (mut source, reads, seeks) = counted_source();
        let cancel = AtomicBool::new(false);
        let before_stats = source.decoder.stats();
        let before_reads = reads.load(Ordering::Relaxed);
        let before_seeks = seeks.load(Ordering::Relaxed);
        assert!(
            before_reads > 0,
            "finite source setup already probed the reader"
        );
        assert!(
            before_seeks >= 2,
            "finite source setup validated seekable length"
        );
        assert!(matches!(
            source.submit_isolated(
                &mut sender,
                &[7],
                inputs(1, 1, usize::MAX, &cancel),
                &mut None
            ),
            Err(SourceError::Admission(AllPeerAdmissionError::Retry(
                AllPeerRetry::NoEligiblePeers
            )))
        ));
        assert_eq!(source.decoder.stats(), before_stats);
        assert_eq!(reads.load(Ordering::Relaxed), before_reads);
        assert_eq!(seeks.load(Ordering::Relaxed), before_seeks);
        assert!(source.ready.is_empty());
        assert!(source.pending.is_none());
        assert_eq!(sender.group_view(other).unwrap(), initial);
        assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 0);

        // Clear capacity through the existing legacy pump, without editing a
        // queue or manufacturing receiver credit; then publish actual PCM.
        assert_eq!(sender.pump(1).media_sent, 1);
        assert_eq!(sender.group_view(other).unwrap().queued_packets, 0);
        assert!(matches!(
            source.submit_isolated(
                &mut sender,
                &[7],
                inputs(2, 2, usize::MAX, &cancel),
                &mut None
            ),
            Ok(IsolatedProgress::Published { frames: 256, .. })
        ));
        assert!(source.decoder.stats().packets > before_stats.packets);
        assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 1);
    }

    // Separately decode the real encoded fixture with the existing Vec path;
    // check its native samples against the committed independent PCM reference.
    fn independently_checked_mp3_441_q23() -> Vec<i32> {
        let mut decoder =
            ContainerDecoder::open(SourceCodec::Mp3, MP3_441.to_vec(), Caps::default()).unwrap();
        let mut samples = Vec::new();
        let mut block = Vec::new();
        for _ in 0..10_000 {
            match decoder.next_block(&mut block).unwrap() {
                Step::Block(_) => samples.extend_from_slice(&block),
                Step::End => break,
            }
        }
        assert_eq!(samples.len(), 22_050 * 2);
        let (reference, rest) = REF_441.as_chunks::<2>();
        assert!(rest.is_empty());
        assert_eq!(reference.len(), samples.len());
        let mut max = 0i32;
        let mut sum = 0f64;
        for (&a, &b) in samples.iter().zip(reference) {
            let difference =
                (i32::from(franken_codec::f32_to_s16(a)) - i32::from(i16::from_le_bytes(b))).abs();
            max = max.max(difference);
            sum += f64::from(difference) * f64::from(difference);
        }
        assert!(max <= 4);
        assert!((sum / samples.len() as f64).sqrt() <= 1.5);
        samples.into_iter().map(franken_codec::f32_to_q23).collect()
    }

    // Closed-form oracle from tests/s02/bridge_reference.py. It shares only
    // the committed coefficients with the incremental production bridge.
    fn reference_441_bridge(input: &[i32]) -> Vec<i16> {
        let body = RATE_TABLE
            .split_once("COEFFS: [i32; 10240] = [")
            .unwrap()
            .1
            .split_once("];")
            .unwrap()
            .0;
        let coeff: Vec<i64> = body
            .split(',')
            .filter_map(|x| {
                let x = x.trim();
                if x.is_empty() {
                    None
                } else {
                    Some(x.parse().expect("Q30 coefficient"))
                }
            })
            .collect();
        assert_eq!(coeff.len(), 160 * 64);
        assert_eq!(input.len() % 2, 0);
        let input_frames = input.len() / 2;
        let output_frames = ((input_frames + 64) * 160).div_ceil(147);
        let mut expected = Vec::with_capacity(output_frames * 2);
        for n in 0..output_frames {
            let source = n * 147 / 160;
            let phase = n * 147 % 160;
            for channel in 0..2 {
                let mut acc = 0i64;
                for k in 0..64 {
                    if let Some(frame) = source.checked_sub(k)
                        && frame < input_frames
                    {
                        acc += coeff[phase * 64 + k] * i64::from(input[frame * 2 + channel]);
                    }
                }
                let q23 = ((acc + (1 << 29)) >> 30).clamp(-8_388_608, 8_388_607);
                let pcm = ((q23 + 128) >> 8).clamp(i64::from(i16::MIN), i64::from(i16::MAX));
                expected.push(i16::try_from(pcm).unwrap());
            }
        }
        expected
    }

    fn n04() -> PlayoutEngine {
        let mut engine = PlayoutEngine::new(
            PlayoutProfile::MUSIC,
            PlayoutConfig {
                work_ns: 500_000,
                lead_ns: 500_000,
                tolerance_ns: 0,
            },
        )
        .unwrap();
        engine.begin_stream(1, 0, 10_000_000_000).unwrap();
        engine
    }

    #[test]
    fn s02_441_fixture_full_carrier_n04_matches_closed_form_pcm_and_tail() {
        let expected = reference_441_bridge(&independently_checked_mp3_441_q23());
        let mut source = fixture_source(MP3_441);
        let (mut sender, mut receiver) = reported_carriers();
        let cancel = AtomicBool::new(false);
        let mut playout = n04();
        let mut pcm = Vec::new();
        let mut ended = false;
        let mut reports = 0usize;
        let mut prepare_stalls = 0usize;
        for index in 0..200u64 {
            let presentation = 10_000_000_000 + (index * 256 * 62_500 / 3);
            let arrival = presentation - 1_000_001;
            let interface = index * 10_000_000 + 1;
            let stats_before = source.decoder.stats();
            let ready_before = source.ready.clone();
            let pending_before = source
                .pending
                .as_ref()
                .map(|pending| (pending.frame.clone(), pending.frames));
            let sent_before = source.sent_frames;
            let attempt = source.submit_all_peers(
                &mut sender,
                &[7],
                inputs(interface, arrival, usize::MAX, &cancel),
            );
            let progress = match attempt {
                Err(SourceError::Admission(AllPeerAdmissionError::Retry(
                    AllPeerRetry::NoEligiblePeers,
                ))) => {
                    assert!(pending_before.is_none(), "refusal must precede preparation");
                    assert_eq!(sender.peer_view(7).unwrap().in_flight, 2);
                    assert_eq!(source.decoder.stats(), stats_before);
                    assert_eq!(source.ready, ready_before);
                    assert_eq!(
                        source
                            .pending
                            .as_ref()
                            .map(|pending| (&pending.frame, pending.frames)),
                        pending_before
                            .as_ref()
                            .map(|(frame, frames)| (frame, *frames))
                    );
                    assert_eq!(source.sent_frames, sent_before);
                    receiver.send_report().unwrap();
                    assert_eq!(
                        sender.poll_reports(),
                        1,
                        "authenticated consumption report applied"
                    );
                    assert_eq!(sender.peer_view(7).unwrap().in_flight, 0);
                    reports += 1;
                    prepare_stalls += 1;
                    source
                        .submit_all_peers(
                            &mut sender,
                            &[7],
                            inputs(interface, arrival, usize::MAX, &cancel),
                        )
                        .unwrap()
                }
                result => result.unwrap(),
            };
            let frames = match progress {
                SourceProgress::End => {
                    ended = true;
                    break;
                }
                SourceProgress::Admitted { frames, .. } => frames,
                SourceProgress::FormatEpochRequired => panic!("unexpected format boundary"),
            };
            let first_pump = source
                .pump(
                    &mut sender,
                    inputs(interface + 1, arrival, usize::MAX, &cancel),
                )
                .unwrap();
            if first_pump.media_sent == 0 {
                assert!(
                    first_pump.window_stalled_peers > 0,
                    "stall must be due to receiver credit"
                );
                receiver.send_report().unwrap();
                assert_eq!(
                    sender.poll_reports(),
                    1,
                    "authenticated consumption report applied"
                );
                reports += 1;
                assert_eq!(
                    source
                        .pump(
                            &mut sender,
                            inputs(interface + 2, arrival, usize::MAX, &cancel),
                        )
                        .unwrap()
                        .media_sent,
                    1
                );
            } else {
                assert_eq!(first_pump.media_sent, 1);
            }
            assert_eq!(receiver.poll().media_accepted, 1);
            let mut packets = receiver.take_media(2);
            assert_eq!(packets.len(), 1);
            let packet = packets.remove(0);
            assert_eq!(packet.start_frame, index * 256);
            assert_eq!(packet.presentation_time_ns, presentation);
            assert_eq!(packet.payload.len(), frames * 4);
            assert_eq!(
                playout.on_packet(
                    view(arrival),
                    &MediaPacket::from_authenticated(&packet).unwrap()
                ),
                Admission::Admitted
            );
            let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
            assert!(
                matches!(playout.decide(view(presentation - 1_000_000), &mut out),
                Poll::Decision(decision) if decision.outcome == Outcome::Real && usize::from(decision.frames) == frames)
            );
            assert_eq!(&out[..frames * 4], packet.payload.as_slice());
            let (pairs, rest) = packet.payload.as_chunks::<2>();
            assert!(rest.is_empty());
            pcm.extend(pairs.iter().map(|&pair| i16::from_be_bytes(pair)));
        }
        assert!(ended, "finite source must reach EOF");
        assert!(prepare_stalls > 0, "the full window must refuse a prepare");
        assert!(
            reports > 0,
            "the two-packet window must require real receiver reports"
        );
        assert_eq!(
            pcm, expected,
            "actual authenticated N04 PCM including one bridge tail"
        );
        assert_eq!(
            pcm.len() / 2,
            franken_codec::outputs_after(22_050 + 64) as usize
        );
    }

    #[test]
    fn s02_chain_drains_old_tail_then_sends_new_epoch_to_n04() {
        let mut reference_decoder =
            ContainerDecoder::open(SourceCodec::Mp3, CHAIN.to_vec(), Caps::default()).unwrap();
        let mut block = Vec::new();
        let expected_new = loop {
            match reference_decoder.next_block(&mut block).unwrap() {
                Step::Block(info) if info.format_changed => {
                    assert_eq!(info.format.rate_hz, 48_000);
                    assert!(block.len() >= 512);
                    break block[..512]
                        .iter()
                        .map(|&sample| franken_codec::q23_to_s16(franken_codec::f32_to_q23(sample)))
                        .collect::<Vec<_>>();
                }
                Step::Block(_) => {}
                Step::End => panic!("chain did not change format"),
            }
        };
        let expected_old = reference_441_bridge(&independently_checked_mp3_441_q23());
        let mut source = fixture_source(CHAIN);
        let mut sender = carrier();
        let cancel = AtomicBool::new(false);
        let mut receiver = StreamReceiver::new(key(), stream(), 1);
        let mut playout = n04();
        let mut old = Vec::new();
        let mut reached_boundary = false;
        let mut interface = 1u64;
        for index in 0..200u64 {
            let presentation = 10_000_000_000 + index * 256 * 62_500 / 3;
            let arrival = presentation - 1_000_001;
            interface = index * 10_000_000 + 1;
            match source
                .submit_all_peers(
                    &mut sender,
                    &[7],
                    inputs(interface, arrival, usize::MAX, &cancel),
                )
                .unwrap()
            {
                SourceProgress::FormatEpochRequired => {
                    reached_boundary = true;
                    break;
                }
                SourceProgress::End => panic!("chain ended before format change"),
                SourceProgress::Admitted { frames, .. } => {
                    assert_eq!(
                        source
                            .pump(
                                &mut sender,
                                inputs(interface + 1, arrival, usize::MAX, &cancel)
                            )
                            .unwrap()
                            .media_sent,
                        1
                    );
                    let packet = receiver
                        .accept(&sender.port().sent.last().unwrap().1)
                        .unwrap();
                    assert_eq!(packet.start_frame, index * 256);
                    assert_eq!(packet.presentation_time_ns, presentation);
                    assert_eq!(
                        playout.on_packet(
                            view(arrival),
                            &MediaPacket::from_authenticated(&packet).unwrap()
                        ),
                        Admission::Admitted
                    );
                    let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
                    assert!(
                        matches!(playout.decide(view(presentation - 1_000_000), &mut out),
                        Poll::Decision(decision) if decision.outcome == Outcome::Real && usize::from(decision.frames) == frames)
                    );
                    assert_eq!(&out[..frames * 4], packet.payload.as_slice());
                    let (pairs, rest) = packet.payload.as_chunks::<2>();
                    assert!(rest.is_empty());
                    old.extend(pairs.iter().map(|&pair| i16::from_be_bytes(pair)));
                }
            }
        }
        assert!(reached_boundary);
        assert_eq!(
            old, expected_old,
            "old epoch includes precisely one complete bridge tail"
        );
        assert!(source.deferred.is_some());
        let last_old_end = 10_000_000_000 + (old.len() as u64 / 2) * 62_500 / 3;
        let new_presentation = 11_000_000_000;
        let arrival = new_presentation - 1_000_001;
        assert!(
            arrival > last_old_end,
            "the new epoch must follow the old tail on one group clock"
        );
        let next_epoch = TransportEpoch {
            presentation_ns: new_presentation,
            ..epoch(2)
        };
        let mut foreign = carrier();
        foreign.advance_epoch(2).unwrap();
        let deferred_len = source.deferred.as_ref().unwrap().1.len();
        let stats = source.decoder.stats();
        assert!(matches!(
            source.begin_format_epoch(&mut foreign, next_epoch, authority()),
            Err(SourceError::Admission(
                AllPeerAdmissionError::MembershipChanged
            ))
        ));
        assert_eq!(source.deferred.as_ref().unwrap().1.len(), deferred_len);
        assert_eq!(source.decoder.stats(), stats);
        sender.advance_epoch(2).unwrap();
        source
            .begin_format_epoch(&mut sender, next_epoch, authority())
            .unwrap();
        assert!(matches!(
            source.submit_all_peers(
                &mut sender,
                &[7],
                inputs(interface + 1, arrival, usize::MAX, &cancel)
            ),
            Ok(SourceProgress::Admitted { frames: 256, .. })
        ));
        assert_eq!(
            source
                .pump(
                    &mut sender,
                    inputs(interface + 2, arrival, usize::MAX, &cancel)
                )
                .unwrap()
                .media_sent,
            1
        );
        let mut receiver = StreamReceiver::new(key(), stream(), 2);
        let packet = receiver
            .accept(&sender.port().sent.last().unwrap().1)
            .unwrap();
        assert_eq!(packet.start_frame, 0);
        assert_eq!(packet.presentation_time_ns, new_presentation);
        let (pairs, rest) = packet.payload.as_chunks::<2>();
        assert!(rest.is_empty());
        assert_eq!(
            pairs
                .iter()
                .map(|&pair| i16::from_be_bytes(pair))
                .collect::<Vec<_>>(),
            expected_new
        );
        let mut next_playout = PlayoutEngine::new(
            PlayoutProfile::MUSIC,
            PlayoutConfig {
                work_ns: 500_000,
                lead_ns: 500_000,
                tolerance_ns: 0,
            },
        )
        .unwrap();
        next_playout.begin_stream(2, 0, new_presentation).unwrap();
        assert_eq!(
            next_playout.on_packet(
                view(arrival),
                &MediaPacket::from_authenticated(&packet).unwrap()
            ),
            Admission::Admitted
        );
        let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
        assert!(
            matches!(next_playout.decide(view(new_presentation - 1_000_000), &mut out),
            Poll::Decision(decision) if decision.outcome == Outcome::Real && decision.frames == 256)
        );
        assert_eq!(&out[..], packet.payload.as_slice());
    }
}
