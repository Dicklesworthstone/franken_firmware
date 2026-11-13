//! Explicit local-process source-playback development endpoint.
//!
//! This uses a caller-provisioned local fixture key and loopback sockets. It does
//! not discover peers, contact a provider, present to a device, or qualify N03.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use franken_codec::{Caps, SourceCodec, SourceReaderLimits};
use franken_session::{
    AuthorityToken, CommandClass, SourceArbiter, SourceCommand, SourceConfig, SourceEpoch,
    SourceId, SourceKind, UnifiedGroupSession,
};
use franken_speaker::source_media::{SourceIdentity, TransportEpoch};
use franken_speaker::source_runtime::{
    RuntimeClock, RuntimeConfig, RuntimeError, RuntimeObservation, RuntimeProgress, SourceRuntime,
};
use franken_stream::carrier::{
    CarrierError, CarrierLimits, CarrierReceiver, CarrierSender, DatagramPort, Lane, MediaSink,
    N01IsolatedOutcome, N01IsolatedStatus, N01PeerDisposition, PRIMARY_GROUP, PeerView,
    ReceiverLimits, STALL_PROBE_NS, SinkVerdict,
};
use franken_stream::playout::{
    Admission, BLOCK_FRAMES, BLOCK_PAYLOAD_BYTES, ClockView, Decision, MediaPacket, Outcome,
    PlayoutConfig, PlayoutEngine, PlayoutProfile, Poll,
};
use franken_stream::{StreamId, StreamKey, StreamReceiver};

// This is an explicitly provisioned host-clock uncertainty, not a measurement
// or a claim about a distributed group clock.
const HOST_UNCERTAINTY_NS: u64 = 1_000_000;
const MAX_SAMPLE_SPAN_NS: u64 = 1_000_000;
const MAX_TIMEOUT_MS: u64 = 60_000;
const MAX_CONTROL_LINE: u64 = 256;
const MAX_PEER_LIST_BYTES: usize = 4096;
const MAX_CAPTURE_FRAMES: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LoopbackPeer {
    id: u32,
    media: SocketAddr,
    control: SocketAddr,
}

fn peer_id(text: &str) -> Result<u32, String> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid peer id".into());
    }
    let id: u32 = text.parse().map_err(|_| "invalid peer id")?;
    if id == 0 || id > franken_stream::carrier::MAX_ATTRIBUTABLE_PEER_ID {
        return Err("peer id outside bound".into());
    }
    Ok(id)
}

fn validate_peers(peers: &[LoopbackPeer]) -> Result<(), String> {
    if peers.is_empty() || peers.len() > CarrierLimits::baseline().max_peers {
        return Err("peer count outside bound".into());
    }
    for (index, peer) in peers.iter().enumerate() {
        peer_id(&peer.id.to_string())?;
        for endpoint in [peer.media, peer.control] {
            if endpoint.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) || endpoint.port() == 0 {
                return Err("peer endpoint must be nonzero IPv4 loopback".into());
            }
        }
        if peer.media == peer.control
            || peers[..index].iter().any(|other| {
                other.id == peer.id
                    || [other.media, other.control].contains(&peer.media)
                    || [other.media, other.control].contains(&peer.control)
            })
        {
            return Err("duplicate peer id or aliased endpoint".into());
        }
    }
    Ok(())
}

/// Explicit local provisioning, not discovery or distributed group negotiation.
/// Every entry is ID@MEDIA@CONTROL; the carrier's existing interface cap applies.
fn peer_list(text: &str) -> Result<Vec<LoopbackPeer>, String> {
    if text.is_empty() || text.len() > MAX_PEER_LIST_BYTES {
        return Err("peer list outside bound".into());
    }
    let mut peers = Vec::with_capacity(CarrierLimits::baseline().max_peers);
    for entry in text.split(',') {
        if peers.len() == CarrierLimits::baseline().max_peers {
            return Err("peer count outside bound".into());
        }
        let mut fields = entry.split('@');
        let id = peer_id(fields.next().ok_or("missing peer id")?)?;
        let media = loopback_addr(fields.next().ok_or("missing peer media endpoint")?)?;
        let control = loopback_addr(fields.next().ok_or("missing peer control endpoint")?)?;
        if fields.next().is_some() {
            return Err("extra peer field".into());
        }
        peers.push(LoopbackPeer { id, media, control });
    }
    validate_peers(&peers)?;
    Ok(peers)
}

/// Traversal is fair carrier order, not provisioning order. Every admitted peer
/// must be accounted exactly once; one stalled peer need not stop healthy ones.
fn all_peers_queued(outcome: &N01IsolatedOutcome, peers: &[LoopbackPeer]) -> Result<bool, String> {
    if peers.is_empty()
        || outcome.status != N01IsolatedStatus::Published
        || outcome.peer_count != peers.len()
        || outcome.peer_count > outcome.peers.len()
        || outcome.peers[outcome.peer_count..]
            .iter()
            .any(Option::is_some)
    {
        return Err("incomplete peer admission outcome".into());
    }
    let mut all_queued = true;
    for (index, outcome_peer) in outcome.peers[..outcome.peer_count].iter().enumerate() {
        let entry = outcome_peer.ok_or("missing peer admission outcome")?;
        if !peers.iter().any(|peer| peer.id == entry.peer)
            || outcome.peers[..index]
                .iter()
                .flatten()
                .any(|earlier| earlier.peer == entry.peer)
        {
            return Err("unknown or duplicate peer admission outcome".into());
        }
        all_queued &= entry.disposition == N01PeerDisposition::Queued;
    }
    Ok(all_queued)
}

struct HostClock {
    instant: Instant,
    host_ns: u64,
    uncertainty_ns: u64,
}

impl HostClock {
    fn sample() -> Result<Self, String> {
        let before = unix_ns()?;
        let instant = Instant::now();
        let after = unix_ns()?;
        let span = after
            .checked_sub(before)
            .ok_or("host clock moved backward during sampling")?;
        if span > MAX_SAMPLE_SPAN_NS {
            return Err("host clock sample was too uncertain".into());
        }
        Ok(Self {
            instant,
            host_ns: before + span / 2,
            uncertainty_ns: HOST_UNCERTAINTY_NS + span.div_ceil(2),
        })
    }

    fn now(&self) -> Result<u64, String> {
        let elapsed =
            u64::try_from(self.instant.elapsed().as_nanos()).map_err(|_| "clock overflow")?;
        self.host_ns
            .checked_add(elapsed)
            .ok_or_else(|| "clock overflow".into())
    }

    fn view(&self) -> Result<ClockView, String> {
        Ok(ClockView {
            group_ns: self.now()?,
            uncertainty_ns: self.uncertainty_ns,
            usable: true,
        })
    }
}

impl RuntimeClock for HostClock {
    fn observe(&mut self) -> Result<RuntimeObservation, RuntimeError> {
        let elapsed =
            u64::try_from(self.instant.elapsed().as_nanos()).map_err(|_| RuntimeError::Clock)?;
        let group_ns = self
            .host_ns
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

fn unix_ns() -> Result<u64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "host time before epoch")?;
    u64::try_from(duration.as_nanos()).map_err(|_| "host time overflow".into())
}

fn control_input() -> Receiver<Result<String, String>> {
    let (tx, rx) = mpsc::sync_channel(8);
    thread::spawn(move || {
        let mut input = BufReader::new(io::stdin());
        loop {
            let mut line = String::new();
            let result = (&mut input).take(MAX_CONTROL_LINE).read_line(&mut line);
            match result {
                Ok(0) => break,
                Ok(_) if line.ends_with('\n') => {
                    if tx
                        .send(Ok(line.trim_end_matches(['\r', '\n']).to_owned()))
                        .is_err()
                    {
                        break;
                    }
                }
                _ => {
                    let _ = tx.send(Err("invalid or overlong control line".into()));
                    break;
                }
            }
        }
    });
    rx
}

fn next_control(
    rx: &Receiver<Result<String, String>>,
    deadline: Instant,
) -> Result<String, String> {
    let left = deadline
        .checked_duration_since(Instant::now())
        .ok_or("control timeout")?;
    rx.recv_timeout(left)
        .map_err(|_| "control timeout or closed input".to_string())?
}

fn fixture_key(line: &str) -> Result<StreamKey, String> {
    let hex = line
        .strip_prefix("KEY ")
        .ok_or("expected KEY control line")?;
    if hex.len() != 64 || !hex.is_ascii() {
        return Err("invalid fixture key".into());
    }
    let mut key = [0_u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid fixture key")?;
    }
    Ok(StreamKey::from_bytes(key))
}

fn loopback_addr(text: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = text.parse().map_err(|_| "invalid address")?;
    if addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) || addr.port() == 0 {
        return Err("address must be a nonzero IPv4 loopback endpoint".into());
    }
    Ok(addr)
}

fn event(value: serde_json::Value) -> Result<(), String> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, &value).map_err(|e| e.to_string())?;
    writeln!(out)
        .and_then(|()| out.flush())
        .map_err(|e| e.to_string())
}

struct CaptureSink {
    receiver: StreamReceiver,
    engine: PlayoutEngine,
    view: ClockView,
    rejected_playout: u64,
    expected_frames: u64,
}

/// The finite file boundary is provisioned before playback. It is distinct
/// from END, the controller permission to finish. Normal positive controllers
/// wait for sender drain; a negative group may finish only its healthy members.
/// N04 itself intentionally models a continuous stream, including after EOF.
struct FiniteCapture {
    expected_frames: u64,
    next_block: u64,
    finish_permitted: bool,
    captured_frames: u64,
    real_blocks: u64,
    concealed: u64,
    muted: u64,
    first_non_real: Option<Decision>,
    raw_pcm: Vec<u8>,
    real_decisions: Vec<Decision>,
    serialization_attempted: bool,
}

impl FiniteCapture {
    fn new(expected_frames: u64) -> Result<Self, String> {
        if expected_frames == 0 || expected_frames > MAX_CAPTURE_FRAMES {
            return Err("finite frame count outside bound".into());
        }
        // Host-only fixture bounds: at most four raw bytes per frame and one
        // record per 256-frame block, allocated before deadline decisions.
        let pcm_bytes = usize::try_from(expected_frames)
            .map_err(|_| "finite frame count outside bound")?
            .checked_mul(4)
            .ok_or("capture limit")?;
        let block_count =
            usize::try_from(expected_frames.div_ceil(BLOCK_FRAMES)).map_err(|_| "capture limit")?;
        let mut raw_pcm = Vec::new();
        raw_pcm
            .try_reserve_exact(pcm_bytes)
            .map_err(|e| e.to_string())?;
        let mut real_decisions = Vec::new();
        real_decisions
            .try_reserve_exact(block_count)
            .map_err(|e| e.to_string())?;
        Ok(Self {
            expected_frames,
            next_block: 0,
            finish_permitted: false,
            captured_frames: 0,
            real_blocks: 0,
            concealed: 0,
            muted: 0,
            first_non_real: None,
            raw_pcm,
            real_decisions,
            serialization_attempted: false,
        })
    }

    fn permit_end(&mut self, frames: u64) -> Result<(), String> {
        if self.finish_permitted || frames != self.expected_frames {
            return Err("END does not match the admitted finite stream".into());
        }
        self.finish_permitted = true;
        Ok(())
    }

    fn decisions_complete(&self) -> bool {
        self.next_block >= self.expected_frames.div_ceil(BLOCK_FRAMES)
    }

    fn finished(&self) -> Result<bool, String> {
        if !self.finish_permitted || !self.decisions_complete() {
            return Ok(false);
        }
        if self.captured_frames != self.expected_frames || self.concealed != 0 || self.muted != 0 {
            return Err("finite capture contains missing or non-real audio".into());
        }
        Ok(true)
    }

    fn observation(&self) -> serde_json::Value {
        let first = self.first_non_real.map(|d| {
            serde_json::json!({
                "block":d.block, "start_frame":d.block * BLOCK_FRAMES,
                "outcome":d.outcome.code(), "presentation_ns":d.presentation_ns,
                "late_by_ns":d.late_by_ns,
            })
        });
        serde_json::json!({"event":"capture_state", "expected_frames":self.expected_frames,
            "decided_blocks":self.next_block, "captured_frames":self.captured_frames,
            "real_blocks":self.real_blocks, "concealed_blocks":self.concealed,
            "muted_blocks":self.muted, "first_non_real":first})
    }

    fn drain(
        &mut self,
        engine: &mut PlayoutEngine,
        mut clock: impl FnMut() -> Result<ClockView, String>,
    ) -> Result<(), String> {
        let mut pcm = [0_u8; BLOCK_PAYLOAD_BYTES];
        // Never ask a continuous engine to synthesize blocks outside the
        // admitted file. Loss within the file still advances by block position,
        // independently of how many real frames have been captured.
        while !self.decisions_complete() {
            let decision = match engine.decide(clock()?, &mut pcm) {
                Poll::Pending => break,
                Poll::Decision(decision) => decision,
                Poll::ClockUnusable => return Err("playout unavailable: ClockUnusable".into()),
                Poll::ClockRegression => return Err("playout unavailable: ClockRegression".into()),
                Poll::NotBound => return Err("playout unavailable: NotBound".into()),
            };
            if decision.block != self.next_block {
                return Err("noncontiguous finite playout decision".into());
            }
            let start_frame = decision
                .block
                .checked_mul(BLOCK_FRAMES)
                .ok_or("frame overflow")?;
            if decision.outcome != Outcome::Real && self.first_non_real.is_none() {
                self.first_non_real = Some(decision);
            }
            match decision.outcome {
                Outcome::Real => {
                    let frames = (self.expected_frames - start_frame).min(BLOCK_FRAMES);
                    if u64::from(decision.frames) != frames {
                        return Err("real block does not match the admitted finite horizon".into());
                    }
                    let bytes = &pcm[..usize::from(decision.frames) * 4];
                    if self.raw_pcm.capacity().saturating_sub(self.raw_pcm.len()) < bytes.len()
                        || self.real_decisions.len() == self.real_decisions.capacity()
                    {
                        return Err("preallocated capture capacity exhausted".into());
                    }
                    self.raw_pcm.extend_from_slice(bytes);
                    self.real_decisions.push(decision);
                    self.captured_frames += frames;
                    self.real_blocks += 1;
                }
                Outcome::Concealed { .. } => self.concealed += 1,
                _ => self.muted += 1,
            }
            self.next_block += 1;
        }
        Ok(())
    }

    /// Serialize actual captured blocks once, only outside N04's decision loop.
    fn serialize_once(&mut self, output: &mut impl Write) -> Result<(), String> {
        if self.serialization_attempted {
            return Err("capture serialization already attempted".into());
        }
        self.serialization_attempted = true;
        let mut output_bytes = 0_usize;
        let mut offset = 0_usize;
        for decision in &self.real_decisions {
            let end = offset
                .checked_add(usize::from(decision.frames) * 4)
                .ok_or("capture limit")?;
            let bytes = self
                .raw_pcm
                .get(offset..end)
                .ok_or("capture data mismatch")?;
            let mut hex = String::with_capacity(bytes.len() * 2);
            use std::fmt::Write as _;
            for byte in bytes {
                write!(&mut hex, "{byte:02x}").map_err(|e| e.to_string())?;
            }
            let row = serde_json::json!({"start_frame":decision.block * BLOCK_FRAMES,
                "presentation_ns":decision.presentation_ns,"frames":decision.frames,"pcm_be16_hex":hex});
            let mut line = serde_json::to_vec(&row).map_err(|e| e.to_string())?;
            line.push(b'\n');
            output_bytes = output_bytes
                .checked_add(line.len())
                .ok_or("capture limit")?;
            if output_bytes > 4 * 1024 * 1024 {
                return Err("capture limit".into());
            }
            output.write_all(&line).map_err(|e| e.to_string())?;
            offset = end;
        }
        Ok(())
    }
}

fn receiver_start(line: &str) -> Result<(SocketAddr, u64, FiniteCapture), String> {
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() != 4 || fields[0] != "START" {
        return Err("expected START address anchor finite_frames".into());
    }
    let sender = loopback_addr(fields[1])?;
    let anchor = fields[2]
        .parse()
        .map_err(|_| "invalid presentation anchor")?;
    let frames = fields[3]
        .parse()
        .map_err(|_| "invalid finite frame count")?;
    Ok((sender, anchor, FiniteCapture::new(frames)?))
}

/// Re-advertise already-consumed authenticated credit even when no more media
/// arrives. A lost last report must not strand the sender at end of stream.
#[derive(Default)]
struct CreditRefresh {
    last_sent: Option<Instant>,
}

impl CreditRefresh {
    fn send_if_due<P: DatagramPort>(
        &mut self,
        carrier: &mut CarrierReceiver<P>,
        accepted: u32,
        now: Instant,
    ) -> Result<bool, CarrierError> {
        if carrier.consumed_next() == 0 {
            return Ok(false);
        }
        if accepted == 0
            && self.last_sent.is_some_and(|last| {
                now.saturating_duration_since(last) < Duration::from_nanos(STALL_PROBE_NS)
            })
        {
            return Ok(false);
        }
        carrier.send_report()?;
        self.last_sent = Some(now);
        Ok(true)
    }
}

impl MediaSink for CaptureSink {
    fn offer(&mut self, datagram: &[u8]) -> SinkVerdict {
        let Ok(packet) = self.receiver.accept(datagram) else {
            return SinkVerdict::Refused;
        };
        let Some(media) = MediaPacket::from_authenticated(&packet) else {
            return SinkVerdict::Refused;
        };
        let expected = self
            .expected_frames
            .saturating_sub(media.start_frame)
            .min(BLOCK_FRAMES);
        if expected == 0
            || u64::from(media.frames) != expected
            || self.engine.on_packet(self.view, &media) != Admission::Admitted
        {
            self.rejected_playout += 1;
        }
        // Authentication consumed the number even if N04 found the PCM late.
        SinkVerdict::Admitted { seq: packet.seq }
    }
}

fn receive(
    output: &str,
    timeout_ms: u64,
    stream: StreamId,
    epoch: u64,
    peer: u32,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let input = control_input();
    let key = fixture_key(&next_control(&input, deadline)?)?;
    let mut carrier = CarrierReceiver::bind(
        key.clone(),
        stream,
        epoch,
        ReceiverLimits::baseline(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
    )
    .map_err(|e| e.to_string())?
    .with_peer_id(peer)
    .map_err(|e| e.to_string())?;
    event(
        serde_json::json!({"event":"ready", "media":carrier.media_addr().map_err(|e| e.to_string())?.to_string(),
        "control":carrier.control_addr().map_err(|e| e.to_string())?.to_string(), "peer_id":peer}),
    )?;
    let start = next_control(&input, deadline)?;
    let (sender, anchor, mut capture) = receiver_start(&start)?;
    let expected_frames = capture.expected_frames;
    carrier.set_sender_control(sender);
    let clock = HostClock::sample()?;
    if anchor <= clock.now()?.saturating_add(100_000_000)
        || anchor > franken_stream::MAX_TIMESTAMP_NS
    {
        return Err("presentation anchor is unavailable or too close".into());
    }
    let mut engine = PlayoutEngine::new(
        PlayoutProfile::MUSIC,
        PlayoutConfig {
            work_ns: 20_000_000,
            lead_ns: 20_000_000,
            tolerance_ns: 0,
        },
    )
    .map_err(|e| format!("playout config: {e:?}"))?;
    engine
        .begin_stream(epoch, 0, anchor)
        .map_err(|e| format!("playout start: {e:?}"))?;
    let mut sink = CaptureSink {
        receiver: StreamReceiver::new(key, stream, epoch),
        engine,
        view: clock.view()?,
        rejected_playout: 0,
        expected_frames,
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|e| e.to_string())?;
    event(serde_json::json!({"event":"started", "anchor_ns":anchor,
        "host_ns":clock.now()?, "uncertainty_ns":clock.uncertainty_ns,
        "expected_frames":expected_frames}))?;
    let mut credit = CreditRefresh::default();
    let mut reported_capture_state = false;
    let mut result: Result<(), String> = (|| loop {
        match input.try_recv() {
            Ok(Ok(command)) if command == "STOP" => return Ok(()),
            Ok(Ok(command)) if command.starts_with("END ") => {
                let frames: u64 = command[4..]
                    .parse()
                    .map_err(|_| "invalid END frame count")?;
                capture.permit_end(frames)?;
            }
            Ok(Ok(_)) => return Err("unexpected receiver control".into()),
            Ok(Err(e)) => return Err(e),
            Err(TryRecvError::Disconnected) => return Err("control input closed".into()),
            Err(TryRecvError::Empty) => {}
        }
        if Instant::now() >= deadline {
            return Err("receiver timeout".into());
        }
        sink.view = clock.view()?;
        let polled = carrier.poll_into(&mut sink);
        credit
            .send_if_due(&mut carrier, polled.media_accepted, Instant::now())
            .map_err(|e| e.to_string())?;
        if sink.rejected_playout != 0 {
            return Err("authenticated media was rejected by N04 playout".into());
        }
        capture.drain(&mut sink.engine, || clock.view())?;
        if capture.decisions_complete() && !reported_capture_state {
            capture.serialize_once(&mut file)?;
            file.flush().map_err(|e| e.to_string())?;
            event(capture.observation())?;
            reported_capture_state = true;
        }
        if capture.finished()? {
            return Ok(());
        }
        thread::sleep(Duration::from_micros(250));
    })();
    if !capture.serialization_attempted
        && let Err(error) = capture.serialize_once(&mut file)
    {
        result = Err(match result {
            Ok(()) => error,
            Err(previous) => format!("{previous}; capture serialization: {error}"),
        });
    }
    file.flush().map_err(|e| e.to_string())?;
    event(
        serde_json::json!({"event": if result.is_ok() { "done" } else { "summary" },
        "captured_frames":capture.captured_frames, "real_blocks":capture.real_blocks,
        "concealed_blocks":capture.concealed, "muted_blocks":capture.muted,
        "expected_frames":capture.expected_frames, "finish_permitted":capture.finish_permitted,
        "media_read":carrier.stats().media_read, "media_accepted":carrier.stats().media_accepted,
        "media_rejected":carrier.stats().media_rejected,
        "rejected_authentication":sink.receiver.counters().rejected_authentication,
        "playout_rejected":sink.rejected_playout, "peer_id":peer}),
    )?;
    result
}

/// Reports only retired sender-side final credit after EOF to the local
/// controller. N01 feedback is a high-water mark; this does not establish
/// receipt of every packet or sample preparation.
fn peer_final_credit_retired(view: &PeerView, frames: u64) -> bool {
    let blocks = frames.div_ceil(BLOCK_FRAMES);
    frames != 0
        && view.fence.is_none()
        && view.queued_packets == 0
        && view.in_flight == 0
        && view.sent_next == blocks
        && view.reported_next == blocks
        && view.counters.media_submitted_packets == blocks
        && view.counters.media_sent_packets == blocks
        && view.counters.media_dropped_overflow_packets == 0
        && view.counters.media_dropped_aggregate_packets == 0
        && view.counters.media_dropped_late_packets == 0
        && view.counters.media_dropped_fenced_packets == 0
        && view.counters.media_dropped_send_error_packets == 0
}

fn send(
    path: &str,
    codec: SourceCodec,
    peers: Vec<LoopbackPeer>,
    timeout_ms: u64,
    stream: StreamId,
    epoch: u64,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let input = control_input();
    let key = fixture_key(&next_control(&input, deadline)?)?;
    let mut carrier = CarrierSender::bind(
        key,
        stream,
        epoch,
        CarrierLimits::baseline(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    )
    .map_err(|e| e.to_string())?;
    for peer in &peers {
        carrier
            .add_peer(peer.id, peer.media, peer.control, 1500)
            .map_err(|e| e.to_string())?;
    }
    event(
        serde_json::json!({"event":"ready", "control":carrier.port().local_addr(Lane::Control)
        .map_err(|e| format!("control address: {e:?}"))?.to_string(),
        "peer_ids":peers.iter().map(|peer| peer.id).collect::<Vec<_>>()}),
    )?;
    let command = next_control(&input, deadline)?;
    if command == "STOP" {
        event(serde_json::json!({"event":"stopped"}))?;
        return Ok(());
    }
    let fields: Vec<_> = command.split_whitespace().collect();
    if fields.len() != 2 || fields[0] != "GO" {
        return Err("expected GO anchor".into());
    }
    let anchor: u64 = fields[1]
        .parse()
        .map_err(|_| "invalid presentation anchor")?;
    let clock = HostClock::sample()?;
    if anchor <= clock.now()?.saturating_add(100_000_000)
        || anchor > franken_stream::MAX_TIMESTAMP_NS
    {
        return Err("presentation anchor is unavailable or too close".into());
    }
    if !std::fs::metadata(path)
        .map_err(|e| e.to_string())?
        .is_file()
    {
        return Err("source must be a regular finite file".into());
    }
    let source_file = File::open(path).map_err(|e| e.to_string())?;
    let metadata = source_file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("source must be a regular finite file".into());
    }
    let session = UnifiedGroupSession::new("local-fixture", "local-owner", 1);
    let token = AuthorityToken::issue(&session, u64::MAX);
    let source =
        SourceId::new(SourceKind::Spotify, "local-file").map_err(|e| format!("source: {e:?}"))?;
    let mut arbiter = SourceArbiter::new(SourceConfig::default());
    let admitted = arbiter
        .submit(
            &session,
            &token,
            clock.now()?,
            &SourceCommand {
                source: source.clone(),
                class: CommandClass::Start,
                expected_epoch: SourceEpoch::new(0),
            },
        )
        .map_err(|e| format!("source policy: {e:?}"))?;
    let mut runtime = SourceRuntime::open_reader(
        source_file,
        metadata.len(),
        codec,
        RuntimeConfig {
            caps: Caps::default(),
            reader_limits: SourceReaderLimits {
                max_read_calls: 100_000,
                max_reads_per_operation: 100_000,
                max_seek_calls: 1000,
                max_read_chunk_bytes: 32 * 1024,
            },
            transport: TransportEpoch {
                group: PRIMARY_GROUP,
                epoch,
                start_frame: 0,
                presentation_ns: anchor,
                admitted_lifetime_margin_ns: 50_000_000,
                partial_final_allowed: true,
            },
            identity: SourceIdentity {
                source,
                policy_epoch: admitted.epoch,
            },
            peers: peers.iter().map(|peer| peer.id).collect(),
            work_and_lead_ns: 40_000_000,
            // N04 MUSIC holds 94 blocks (about 501 ms). Keep the source
            // comfortably inside that window, including our admitted margin.
            max_ahead_ns: 250_000_000,
            overlap_budget_bytes: usize::MAX,
            session,
            arbiter,
            carrier,
            clock,
        },
    )
    .map_err(|e| e.to_string())?
    .with_buffered_credit();
    let mut published_frames = 0_u64;
    let mut reported_drained = [false; 8];
    loop {
        match input.try_recv() {
            Ok(Ok(command)) if command == "STOP" => {
                runtime.stop();
                event(serde_json::json!({"event":"stopped", "published_frames":published_frames}))?;
                return Ok(());
            }
            Ok(Ok(_)) => return Err("unexpected sender control".into()),
            Ok(Err(e)) => return Err(e),
            Err(TryRecvError::Disconnected) => return Err("control input closed".into()),
            Err(TryRecvError::Empty) => {}
        }
        if Instant::now() >= deadline {
            runtime.stop();
            sender_summary("summary", &runtime, &peers, published_frames, anchor)?;
            return Err("sender timeout".into());
        }
        let mut outcomes = None;
        let step = runtime.step(&mut outcomes).map_err(|e| e.to_string())?;
        // Draining/Drained/Incomplete are EOF states, so no new source blocks
        // can appear after this observation. Each peer gets at most one event.
        // A bad peer cannot withhold the controller's good-peer completion.
        if matches!(
            step.progress,
            RuntimeProgress::Draining | RuntimeProgress::Drained | RuntimeProgress::Incomplete
        ) {
            for (index, peer) in peers.iter().enumerate() {
                let view = runtime.peer_view(peer.id).ok_or("missing peer view")?;
                if !reported_drained[index] && peer_final_credit_retired(&view, published_frames) {
                    event(
                        serde_json::json!({"event":"peer_drained", "peer_id":peer.id,
                        "published_frames":published_frames, "anchor_ns":anchor, "peer":view}),
                    )?;
                    reported_drained[index] = true;
                }
            }
        }
        match step.progress {
            RuntimeProgress::Published { frames } => {
                let outcome = outcomes.ok_or("missing peer admission outcome")?;
                let queued = all_peers_queued(&outcome, &peers)?;
                if peers.len() == 1 && !queued {
                    runtime.stop();
                    return Err("peer did not accept source frame".into());
                }
                published_frames += u64::try_from(frames).map_err(|_| "frame count overflow")?;
            }
            RuntimeProgress::Expired { .. } => {
                runtime.stop();
                return Err("source frame expired".into());
            }
            RuntimeProgress::Incomplete => {
                runtime.stop();
                sender_summary("summary", &runtime, &peers, published_frames, anchor)?;
                return Err("source transport drained with loss".into());
            }
            RuntimeProgress::Drained => {
                sender_summary("done", &runtime, &peers, published_frames, anchor)?;
                return Ok(());
            }
            RuntimeProgress::Waiting | RuntimeProgress::Draining => {}
        }
        thread::sleep(Duration::from_micros(250));
    }
}

fn sender_summary<P: DatagramPort, C: RuntimeClock>(
    event_name: &str,
    runtime: &SourceRuntime<P, C>,
    peers: &[LoopbackPeer],
    published_frames: u64,
    anchor: u64,
) -> Result<(), String> {
    let views: Vec<_> = peers
        .iter()
        .map(|peer| runtime.peer_view(peer.id).ok_or("missing peer view"))
        .collect::<Result<_, _>>()?;
    let counts = runtime.source_counters();
    // Keep the original first-peer field for the existing single-peer caller.
    // A multi-peer success still requires the runtime's complete all-peer drain.
    event(
        serde_json::json!({"event":event_name, "published_frames":published_frames,
        "anchor_ns":anchor, "peer":views.first(), "peers":views,
        "expired_blocks":counts.expired_blocks,
        "skipped_fenced":counts.skipped_fenced, "skipped_mtu":counts.skipped_mtu,
        "skipped_stalled":counts.skipped_stalled, "skipped_capacity":counts.skipped_capacity,
        "skipped_sequence":counts.skipped_sequence, "saturated":counts.saturated}),
    )
}

pub fn main(mode: &str, args: &[String]) -> std::process::ExitCode {
    match run(mode, args) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("local source loopback: {error}");
            std::process::ExitCode::from(2)
        }
    }
}

fn run(mode: &str, args: &[String]) -> Result<(), String> {
    let mut options = std::collections::BTreeMap::new();
    let (pairs, remainder) = args.as_chunks::<2>();
    for pair in pairs {
        if !pair[0].starts_with("--")
            || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err("invalid or repeated option".into());
        }
    }
    if !remainder.is_empty() {
        return Err("option without value".into());
    }
    let required = |key| {
        options
            .get(key)
            .copied()
            .ok_or_else(|| format!("missing {key}"))
    };
    let timeout: u64 = required("--timeout-ms")?
        .parse()
        .map_err(|_| "invalid timeout")?;
    if timeout == 0 || timeout > MAX_TIMEOUT_MS {
        return Err("timeout outside bound".into());
    }
    let stream = StreamId::new(
        required("--stream-id")?
            .parse()
            .map_err(|_| "invalid stream")?,
    )
    .map_err(|e| e.to_string())?;
    let epoch = required("--epoch")?.parse().map_err(|_| "invalid epoch")?;
    match mode {
        "--source-loopback-receive"
            if options.len() == 4 || (options.len() == 5 && options.contains_key("--peer-id")) =>
        {
            let peer = peer_id(options.get("--peer-id").copied().unwrap_or("1"))?;
            receive(required("--output")?, timeout, stream, epoch, peer)
        }
        "--source-loopback-send"
            if (options.len() == 6 && options.contains_key("--peers"))
                || (options.len() == 7 && !options.contains_key("--peers")) =>
        {
            let codec = match required("--codec")? {
                "mp3" => SourceCodec::Mp3,
                "ogg-vorbis" => SourceCodec::OggVorbis,
                _ => return Err("unsupported local codec".into()),
            };
            let peers = if let Some(list) = options.get("--peers") {
                peer_list(list)?
            } else {
                let peers = vec![LoopbackPeer {
                    id: 1,
                    media: loopback_addr(required("--media")?)?,
                    control: loopback_addr(required("--control")?)?,
                }];
                validate_peers(&peers)?;
                peers
            };
            send(required("--input")?, codec, peers, timeout, stream, epoch)
        }
        _ => Err("invalid local source loopback options".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINITE_ANCHOR: u64 = 1_000_000_000;

    fn finite_view(group_ns: u64) -> ClockView {
        ClockView {
            group_ns,
            uncertainty_ns: 1_000_000,
            usable: true,
        }
    }

    fn finite_sink(frames: u64) -> CaptureSink {
        let mut engine = PlayoutEngine::new(
            PlayoutProfile::MUSIC,
            PlayoutConfig {
                work_ns: 20_000_000,
                lead_ns: 20_000_000,
                tolerance_ns: 0,
            },
        )
        .unwrap();
        engine.begin_stream(1, 0, FINITE_ANCHOR).unwrap();
        CaptureSink {
            receiver: StreamReceiver::new(
                StreamKey::from_bytes([7; 32]),
                StreamId::new(7).unwrap(),
                1,
            ),
            engine,
            view: finite_view(0),
            rejected_playout: 0,
            expected_frames: frames,
        }
    }

    fn finite_wire(sender: &mut franken_stream::StreamSender, start: u64, frames: u64) -> Vec<u8> {
        sender
            .send(franken_stream::OutboundFrame::media(
                start,
                FINITE_ANCHOR + franken_stream::playout::frames_to_ns(start),
                FINITE_ANCHOR + franken_stream::playout::frames_to_ns(start) - 50_000_000,
                (0..frames)
                    .flat_map(|n| {
                        let sample = ((start + n) as u16).to_be_bytes();
                        [sample[0], sample[1], 0x12, 0x34]
                    })
                    .collect(),
            ))
            .unwrap()
    }

    fn admit_finite(frames: u64, missing_block: Option<u64>) -> CaptureSink {
        let mut sink = finite_sink(frames);
        let mut sender = franken_stream::StreamSender::new(
            StreamKey::from_bytes([7; 32]),
            StreamId::new(7).unwrap(),
            1,
        );
        for start in (0..frames).step_by(BLOCK_FRAMES as usize) {
            // Generate even a dropped packet, so the actual authenticated
            // sequence has the gap a real carrier would observe.
            let packet = finite_wire(&mut sender, start, (frames - start).min(BLOCK_FRAMES));
            if missing_block != Some(start / BLOCK_FRAMES) {
                assert!(matches!(sink.offer(&packet), SinkVerdict::Admitted { .. }));
            }
        }
        assert_eq!(sink.rejected_playout, 0);
        sink
    }

    fn capture_rows(bytes: &[u8]) -> Vec<serde_json::Value> {
        std::str::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn finite_capture_defers_stalling_writer_until_actual_n04_decisions_finish() {
        use std::cell::Cell;

        // The test clock advances on every observation. A scripted writer
        // models 80 ms of blocked I/O without depending on host scheduling.
        fn next_view(now: &Cell<u64>) -> ClockView {
            let current = now.get();
            now.set(current + 1_000);
            finite_view(current)
        }

        struct SlowWriter<'a> {
            bytes: Vec<u8>,
            writes: usize,
            now: &'a Cell<u64>,
        }
        impl Write for SlowWriter<'_> {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.writes += 1;
                if self.writes == 1 {
                    self.now.set(self.now.get() + 80_000_000);
                }
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        // Counterexample for the previous interleaved writer: scripted time
        // advances during its callback and the actual N04 decision is overdue.
        let mut old = admit_finite(512, None);
        let mut pcm = [0_u8; BLOCK_PAYLOAD_BYTES];
        let now = Cell::new(965_000_000);
        assert!(
            matches!(old.engine.decide(next_view(&now), &mut pcm), Poll::Decision(d)
            if d.block == 0 && d.outcome == Outcome::Real)
        );
        let mut old_writer = SlowWriter {
            bytes: Vec::new(),
            writes: 0,
            now: &now,
        };
        old_writer.write_all(&pcm).unwrap();
        assert!(
            matches!(old.engine.decide(next_view(&now), &mut pcm), Poll::Decision(d)
            if d.block == 1 && d.outcome == Outcome::MutedOverdue)
        );

        let mut sink = admit_finite(512, None);
        let mut capture = FiniteCapture::new(512).unwrap();
        let reserved = (
            capture.raw_pcm.capacity(),
            capture.real_decisions.capacity(),
        );
        let now = Cell::new(965_000_000);
        let mut writer = SlowWriter {
            bytes: Vec::new(),
            writes: 0,
            now: &now,
        };
        capture
            .drain(&mut sink.engine, || Ok(next_view(&now)))
            .unwrap();
        assert_eq!(writer.writes, 0, "no write occurs during N04 decisions");
        assert_eq!(
            now.get(),
            965_002_000,
            "the clock advanced for both decisions"
        );
        assert_eq!(
            (
                capture.captured_frames,
                capture.real_blocks,
                capture.concealed,
                capture.muted
            ),
            (512, 2, 0, 0)
        );
        assert_eq!(
            (
                capture.raw_pcm.capacity(),
                capture.real_decisions.capacity()
            ),
            reserved
        );
        capture.serialize_once(&mut writer).unwrap();
        assert!(writer.writes > 0);
        assert_eq!(
            now.get(),
            1_045_002_000,
            "the scripted I/O stall advances time"
        );
        let rows = capture_rows(&writer.bytes);
        let actual: String = rows
            .iter()
            .map(|row| row["pcm_be16_hex"].as_str().unwrap())
            .collect();
        let expected: String = (0..512).map(|n| format!("{n:04x}1234")).collect();
        assert_eq!(actual, expected);
        assert_eq!(
            rows.iter()
                .map(|row| row["start_frame"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            vec![0, 256]
        );
    }

    #[test]
    fn finite_capture_partial_error_serializes_once_without_duplicate_retry() {
        let mut sink = admit_finite(600, None);
        let mut capture = FiniteCapture::new(600).unwrap();
        let mut reads = 0;
        let error = capture.drain(&mut sink.engine, || {
            reads += 1;
            if reads == 1 {
                Ok(finite_view(975_500_000))
            } else {
                Err("clock failed".into())
            }
        });
        assert_eq!(error, Err("clock failed".into()));
        assert_eq!(capture.captured_frames, 256);
        assert!(!capture.decisions_complete());

        // A different partial capture writes its one real block on the error
        // path, without inventing the unvisited later decisions.
        let mut partial_sink = admit_finite(600, None);
        let mut partial = FiniteCapture::new(600).unwrap();
        let mut calls = 0;
        assert!(
            partial
                .drain(&mut partial_sink.engine, || {
                    calls += 1;
                    if calls == 1 {
                        Ok(finite_view(975_500_000))
                    } else {
                        Err("clock failed".into())
                    }
                })
                .is_err()
        );
        let mut partial_output = Vec::new();
        partial.serialize_once(&mut partial_output).unwrap();
        let partial_rows = capture_rows(&partial_output);
        assert_eq!(partial_rows.len(), 1);
        assert_eq!(partial_rows[0]["start_frame"], 0);
        assert_eq!(partial_rows[0]["frames"], 256);
        let expected: String = (0..256).map(|n| format!("{n:04x}1234")).collect();
        assert_eq!(partial_rows[0]["pcm_be16_hex"], expected);

        struct PartialFailure {
            bytes: Vec<u8>,
            calls: usize,
        }
        impl Write for PartialFailure {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                if self.calls > 1 {
                    return Err(io::Error::other("injected write failure"));
                }
                let count = bytes.len().min(16);
                self.bytes.extend_from_slice(&bytes[..count]);
                Ok(count)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = PartialFailure {
            bytes: Vec::new(),
            calls: 0,
        };
        assert!(capture.serialize_once(&mut writer).is_err());
        assert_eq!(writer.bytes.len(), 16);
        let calls = writer.calls;
        assert!(capture.serialize_once(&mut writer).is_err());
        assert_eq!(writer.calls, calls, "failed output is never retried");
        assert_eq!(writer.bytes.len(), 16);
    }

    #[test]
    fn finite_capture_prevents_real_engine_post_end_concealment_without_trimming_pcm() {
        let view = finite_view(975_500_000); // Block 3 is due, but still before presentation.
        let mut unbounded = admit_finite(600, None);
        let mut pcm = [0; BLOCK_PAYLOAD_BYTES];
        for (block, frames) in [(0, 256), (1, 256), (2, 88)] {
            assert!(
                matches!(unbounded.engine.decide(view, &mut pcm), Poll::Decision(d)
                if d.block == block && d.frames == frames && d.outcome == Outcome::Real)
            );
        }
        // Planted old consumer: a continuous engine really does produce a
        // fourth conceal decision. This is not a hand-written oracle model.
        assert!(
            matches!(unbounded.engine.decide(view, &mut pcm), Poll::Decision(d)
            if d.block == 3 && matches!(d.outcome, Outcome::Concealed { .. }))
        );

        for frames in [1, 256, 512, 600] {
            let mut sink = admit_finite(frames, None);
            let mut capture = FiniteCapture::new(frames).unwrap();
            let mut output = Vec::new();
            capture.drain(&mut sink.engine, || Ok(view)).unwrap();
            assert_eq!(capture.captured_frames, frames);
            assert_eq!((capture.concealed, capture.muted), (0, 0));
            assert_eq!(capture.real_blocks, frames.div_ceil(BLOCK_FRAMES));
            assert!(capture.observation()["first_non_real"].is_null());
            assert_eq!(sink.engine.snapshot().cursor, frames.div_ceil(BLOCK_FRAMES));
            capture.serialize_once(&mut output).unwrap();
            let rows = capture_rows(&output);
            let mut actual_pcm = String::new();
            for (index, row) in rows.iter().enumerate() {
                let start = index as u64 * BLOCK_FRAMES;
                assert_eq!(row["start_frame"], start);
                assert_eq!(row["frames"], (frames - start).min(BLOCK_FRAMES));
                assert_eq!(
                    row["presentation_ns"],
                    FINITE_ANCHOR + start * 1_000_000_000 / 48000
                );
                actual_pcm.push_str(row["pcm_be16_hex"].as_str().unwrap());
            }
            let expected_pcm: String = (0..frames).map(|n| format!("{n:04x}1234")).collect();
            assert_eq!(actual_pcm, expected_pcm);
            let original = output.clone();
            capture
                .drain(&mut sink.engine, || {
                    Ok(finite_view(FINITE_ANCHOR + 1_000_000_000))
                })
                .unwrap();
            assert_eq!(output, original);
            assert!(
                !capture.finished().unwrap(),
                "PCM completion cannot grant transport completion"
            );
            capture.permit_end(frames).unwrap();
            assert!(capture.finished().unwrap());
        }
    }

    #[test]
    fn finite_capture_keeps_actual_missing_middle_and_final_partial_as_failures() {
        for missing in [0, 1, 2] {
            let mut sink = admit_finite(600, Some(missing));
            let mut capture = FiniteCapture::new(600).unwrap();
            capture.permit_end(600).unwrap(); // Early controller permission is no success proof.
            let mut output = Vec::new();
            capture
                .drain(&mut sink.engine, || Ok(finite_view(975_500_000)))
                .unwrap();
            assert_eq!(capture.concealed + capture.muted, 1);
            assert_eq!(capture.next_block, 3);
            let observed = capture.observation();
            assert_eq!(
                observed["first_non_real"]["start_frame"],
                missing * BLOCK_FRAMES
            );
            assert_eq!(observed["decided_blocks"], 3);
            assert!(capture.finished().is_err());
            capture.serialize_once(&mut output).unwrap();
            let rows = capture_rows(&output);
            assert_eq!(rows.len(), 2);
            assert!(
                rows.iter()
                    .all(|row| row["start_frame"] != missing * BLOCK_FRAMES)
            );
            assert!(capture.captured_frames < 600);
        }
    }

    #[test]
    fn finite_capture_rejects_invalid_declarations_and_mismatched_or_duplicate_end() {
        for line in [
            "START 127.0.0.1:9 1000000000",
            "START 127.0.0.1:9 1000000000 0",
            "START 127.0.0.1:9 1000000000 1000001",
            "START 127.0.0.1:9 1000000000 invalid",
            "START 192.0.2.1:9 1000000000 600",
            "START 127.0.0.1:9 invalid 600",
            "START 127.0.0.1:9 1000000000 600 extra",
        ] {
            assert!(receiver_start(line).is_err(), "accepted {line}");
        }
        let (sender, anchor, mut capture) =
            receiver_start("START 127.0.0.1:9 1000000000 600").unwrap();
        assert_eq!(sender, "127.0.0.1:9".parse().unwrap());
        assert_eq!(anchor, FINITE_ANCHOR);
        assert!(capture.permit_end(599).is_err());
        assert!(!capture.finish_permitted);
        capture.permit_end(600).unwrap();
        assert!(!capture.finished().unwrap());
        assert!(capture.permit_end(600).is_err());
        assert!(FiniteCapture::new(MAX_CAPTURE_FRAMES).is_ok());
    }

    #[test]
    fn finite_capture_rejects_authenticated_extra_and_short_blocks_without_hiding_credit() {
        for (start, frames) in [(0, 255), (512, 89), (768, 256)] {
            let mut sink = finite_sink(600);
            let mut sender = franken_stream::StreamSender::new(
                StreamKey::from_bytes([7; 32]),
                StreamId::new(7).unwrap(),
                1,
            );
            assert_eq!(
                sink.offer(&finite_wire(&mut sender, start, frames)),
                SinkVerdict::Admitted { seq: 0 }
            );
            assert_eq!(sink.receiver.counters().accepted, 1);
            assert_eq!(
                sink.rejected_playout, 1,
                "authenticated consumption is not successful preparation"
            );
            assert_eq!(sink.engine.stats().admitted, 0);
        }
        let mut sink = finite_sink(600);
        let mut sender = franken_stream::StreamSender::new(
            StreamKey::from_bytes([7; 32]),
            StreamId::new(7).unwrap(),
            1,
        );
        let packet = finite_wire(&mut sender, 512, 88);
        assert_eq!(sink.offer(&packet), SinkVerdict::Admitted { seq: 0 });
        assert_eq!(sink.rejected_playout, 0);
        assert_eq!(sink.offer(&packet), SinkVerdict::Refused);
        assert_eq!(sink.receiver.counters().rejected_replay, 1);
        assert_eq!(sink.engine.stats().admitted, 1);
    }

    fn three_peers() -> Vec<LoopbackPeer> {
        peer_list("7@127.0.0.1:11001@127.0.0.1:11002,42@127.0.0.1:11003@127.0.0.1:11004,65535@127.0.0.1:11005@127.0.0.1:11006").unwrap()
    }

    fn outcome_for(peers: &[LoopbackPeer]) -> N01IsolatedOutcome {
        let mut result = N01IsolatedOutcome {
            status: N01IsolatedStatus::Published,
            peers: [None; 64],
            peer_count: peers.len(),
            accounted_overlap_bytes: 0,
        };
        // The carrier rotates its fair traversal order; configuration order is
        // deliberately different from report order in this permitted control.
        for (slot, peer) in result.peers.iter_mut().zip(peers.iter().rev()) {
            *slot = Some(franken_stream::carrier::N01PeerOutcome {
                peer: peer.id,
                disposition: N01PeerDisposition::Queued,
            });
        }
        result
    }

    #[test]
    fn explicit_peer_map_preserves_ids_and_accepts_the_existing_eight_peer_bound() {
        let peers = three_peers();
        assert_eq!(
            peers.iter().map(|p| p.id).collect::<Vec<_>>(),
            [7, 42, 65535]
        );
        assert_eq!(peers[1].control.port(), 11004);
        let entries: Vec<_> = (0..8)
            .map(|n| {
                format!(
                    "{}@127.0.0.1:{}@127.0.0.1:{}",
                    n + 1,
                    12001 + n * 2,
                    12002 + n * 2
                )
            })
            .collect();
        assert_eq!(peer_list(&entries.join(",")).unwrap().len(), 8);
        assert!(
            peer_list(&format!(
                "{},9@127.0.0.1:13001@127.0.0.1:13002",
                entries.join(",")
            ))
            .is_err()
        );
    }

    #[test]
    fn peer_map_rejects_duplicates_cross_lane_aliases_and_nonlocal_endpoints() {
        for bad in [
            "1@127.0.0.1:11001@127.0.0.1:11002,1@127.0.0.1:11003@127.0.0.1:11004",
            "1@127.0.0.1:11001@127.0.0.1:11002,2@127.0.0.1:11001@127.0.0.1:11004",
            "1@127.0.0.1:11001@127.0.0.1:11002,2@127.0.0.1:11002@127.0.0.1:11004",
            "1@127.0.0.1:11001@127.0.0.1:11002,2@127.0.0.1:11003@127.0.0.1:11001",
            "1@127.0.0.1:11001@127.0.0.1:11001",
            "1@192.0.2.1:11001@127.0.0.1:11002",
            "1@127.0.0.1:11001@192.0.2.1:11002",
            "1@[::1]:11001@127.0.0.1:11002",
            "1@127.0.0.1:0@127.0.0.1:11002",
        ] {
            assert!(peer_list(bad).is_err(), "accepted {bad}");
        }
        assert!(
            peer_list("1@127.0.0.1:11001@127.0.0.1:11002,2@127.0.0.1:11003@127.0.0.1:11004")
                .is_ok()
        );
    }

    #[test]
    fn peer_ids_and_list_grammar_are_bounded_before_opening_source_or_sockets() {
        for bad in ["", "0", "+1", " 1", "1 ", "-1", "16777216", "4294967296"] {
            assert!(peer_id(bad).is_err(), "accepted id {bad:?}");
        }
        assert_eq!(peer_id("16777215").unwrap(), 0x00ff_ffff);
        for bad in [
            "",
            "1",
            "1@127.0.0.1:11001",
            "1@127.0.0.1:11001@127.0.0.1:11002@extra",
            "1@127.0.0.1:11001@127.0.0.1:11002,",
        ] {
            assert!(peer_list(bad).is_err(), "accepted map {bad:?}");
        }
        assert!(peer_list(&"1".repeat(MAX_PEER_LIST_BYTES + 1)).is_err());
    }

    #[test]
    fn all_peer_accounting_accepts_fair_order_and_keeps_a_stalled_member_separate() {
        let peers = three_peers();
        let mut outcome = outcome_for(&peers);
        assert_eq!(all_peers_queued(&outcome, &peers), Ok(true));
        outcome.peers[1].as_mut().unwrap().disposition = N01PeerDisposition::Stalled;
        assert_eq!(all_peers_queued(&outcome, &peers), Ok(false));
        outcome.peers[1].as_mut().unwrap().disposition = N01PeerDisposition::Queued;
        assert_eq!(all_peers_queued(&outcome, &peers), Ok(true));
    }

    #[test]
    fn all_peer_accounting_rejects_missing_duplicate_unknown_and_unexpected_rows() {
        let peers = three_peers();
        let good = outcome_for(&peers);
        let mut bad = good.clone();
        bad.peer_count = 2;
        assert!(all_peers_queued(&bad, &peers).is_err());
        bad = good.clone();
        bad.peers[1] = None;
        assert!(all_peers_queued(&bad, &peers).is_err());
        bad = good.clone();
        bad.peers[1] = bad.peers[0];
        assert!(all_peers_queued(&bad, &peers).is_err());
        bad = good.clone();
        bad.peers[1].as_mut().unwrap().peer = 99;
        assert!(all_peers_queued(&bad, &peers).is_err());
        bad = good.clone();
        bad.peers[3] = bad.peers[0];
        assert!(all_peers_queued(&bad, &peers).is_err());
        bad = good.clone();
        bad.status = N01IsolatedStatus::Expired;
        assert!(all_peers_queued(&bad, &peers).is_err());
        bad = good.clone();
        bad.peer_count = usize::MAX;
        assert!(all_peers_queued(&bad, &peers).is_err());
        assert!(all_peers_queued(&outcome_for(&[]), &[]).is_err());
        assert_eq!(all_peers_queued(&good, &peers), Ok(true));
    }

    #[test]
    fn host_udp_lost_last_report_recovers_without_replaying_pcm_or_trusting_wrong_address() {
        use franken_stream::{OutboundFrame, StreamSender};
        use std::net::UdpSocket;

        fn wait(mut predicate: impl FnMut() -> bool) {
            let until = Instant::now() + Duration::from_secs(2);
            while !predicate() {
                assert!(Instant::now() < until, "loopback delivery timed out");
                thread::sleep(Duration::from_millis(1));
            }
        }

        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let key = StreamKey::from_bytes([7; 32]);
        let stream = StreamId::new(7).unwrap();
        let blackhole = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        blackhole
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut sender =
            CarrierSender::bind(key.clone(), stream, 1, CarrierLimits::baseline(), ip).unwrap();
        let mut receiver = CarrierReceiver::bind(
            key.clone(),
            stream,
            1,
            ReceiverLimits::baseline(),
            ip,
            blackhole.local_addr().unwrap(),
        )
        .unwrap()
        .with_peer_id(1)
        .unwrap();
        sender
            .add_peer(
                1,
                receiver.media_addr().unwrap(),
                receiver.control_addr().unwrap(),
                1500,
            )
            .unwrap();
        let mut engine = PlayoutEngine::new(
            PlayoutProfile::MUSIC,
            PlayoutConfig {
                work_ns: 20_000_000,
                lead_ns: 20_000_000,
                tolerance_ns: 0,
            },
        )
        .unwrap();
        let anchor = 1_000_000_000;
        engine.begin_stream(1, 0, anchor).unwrap();
        let mut sink = CaptureSink {
            receiver: StreamReceiver::new(key.clone(), stream, 1),
            engine,
            view: ClockView {
                group_ns: 0,
                uncertainty_ns: 1_000_000,
                usable: true,
            },
            rejected_playout: 0,
            expected_frames: MAX_CAPTURE_FRAMES,
        };
        let frame = OutboundFrame::media(
            0,
            anchor,
            anchor - 50_000_000,
            vec![0x11; BLOCK_PAYLOAD_BYTES],
        );
        sender.submit_media(1, &frame, 0).unwrap();
        assert_eq!(sender.pump(0).media_sent, 1);
        wait(|| {
            receiver.poll_into(&mut sink);
            receiver.consumed_next() == 1
        });
        assert_eq!(sink.receiver.counters().accepted, 1);
        let start = Instant::now();
        let mut credit = CreditRefresh::default();
        assert!(credit.send_if_due(&mut receiver, 1, start).unwrap());
        let mut report = [0_u8; 128];
        let (len, _) = blackhole.recv_from(&mut report).unwrap(); // first genuine report was lost
        assert_eq!(sender.peer_view(1).unwrap().in_flight, 1);
        assert!(!peer_final_credit_retired(
            &sender.peer_view(1).unwrap(),
            BLOCK_FRAMES
        ));

        // The finite PCM is fully prepared while the real last credit is lost.
        // Do not exit here: the sender still has a live in-flight packet.
        let mut capture = FiniteCapture::new(BLOCK_FRAMES).unwrap();
        let mut output = Vec::new();
        let view = ClockView {
            group_ns: anchor - 40_000_000,
            uncertainty_ns: 1_000_000,
            usable: true,
        };
        capture.drain(&mut sink.engine, || Ok(view)).unwrap();
        assert!(capture.decisions_complete());
        assert!(!capture.finished().unwrap());
        capture.serialize_once(&mut output).unwrap();
        let rows = capture_rows(&output);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["pcm_be16_hex"], "11".repeat(BLOCK_PAYLOAD_BYTES));
        let mut same_clock_pcm = [0; BLOCK_PAYLOAD_BYTES];
        assert_eq!(sink.engine.decide(view, &mut same_clock_pcm), Poll::Pending);

        // Replaying authentic report bytes from the wrong control address cannot mint credit.
        blackhole
            .send_to(&report[..len], sender.control_addr().unwrap())
            .unwrap();
        wait(|| {
            sender.poll_reports();
            sender.stats().reports_unknown_source == 1
        });
        assert_eq!(sender.peer_view(1).unwrap().reported_next, 0);
        sender.pump(STALL_PROBE_NS + 1);
        assert_eq!(sender.control_stats().probes_sent, 0); // no queued head and window not full

        // An authenticated media duplicate remains a replay: it earns no new PCM or credit.
        let mut duplicate = StreamSender::new(key, stream, 1);
        blackhole
            .send_to(
                &duplicate.send(frame).unwrap(),
                receiver.media_addr().unwrap(),
            )
            .unwrap();
        wait(|| {
            receiver.poll_into(&mut sink);
            sink.receiver.counters().rejected_replay == 1
        });
        assert_eq!(sink.receiver.counters().accepted, 1);
        receiver.set_sender_control(sender.control_addr().unwrap());
        assert!(
            !credit
                .send_if_due(
                    &mut receiver,
                    0,
                    start + Duration::from_nanos(STALL_PROBE_NS - 1)
                )
                .unwrap()
        );
        assert!(
            credit
                .send_if_due(
                    &mut receiver,
                    0,
                    start + Duration::from_nanos(STALL_PROBE_NS)
                )
                .unwrap()
        );
        wait(|| {
            sender.poll_reports();
            sender.peer_view(1).unwrap().reported_next == 1
        });
        assert_eq!(sender.peer_view(1).unwrap().in_flight, 0);
        assert_eq!(sender.peer_view(1).unwrap().queued_packets, 0);
        assert!(peer_final_credit_retired(
            &sender.peer_view(1).unwrap(),
            BLOCK_FRAMES
        ));
        assert_eq!(receiver.stats().reports_sent, 2);
        let original = output.clone();
        capture
            .drain(&mut sink.engine, || Ok(finite_view(anchor + 1_000_000_000)))
            .unwrap();
        assert_eq!(
            output, original,
            "no extra PCM or concealment while refreshing credit"
        );
        assert_eq!((capture.concealed, capture.muted), (0, 0));
        capture.permit_end(BLOCK_FRAMES).unwrap();
        assert!(capture.finished().unwrap());
    }

    #[test]
    fn fixture_provisioning_rejects_nonloopback_and_bad_keys() {
        assert!(fixture_key(&format!("KEY {}", "ab".repeat(32))).is_ok());
        assert!(fixture_key("KEY not-a-key").is_err());
        assert!(loopback_addr("127.0.0.1:1234").is_ok());
        assert!(loopback_addr("127.0.0.1:0").is_err());
        assert!(loopback_addr("192.0.2.1:1234").is_err());
    }

    #[test]
    fn host_clock_maps_to_monotonic_time_with_declared_uncertainty() {
        let clock = HostClock::sample().unwrap();
        let first = clock.view().unwrap();
        let second = clock.view().unwrap();
        assert!(second.group_ns >= first.group_ns);
        assert!(first.uncertainty_ns >= HOST_UNCERTAINTY_NS);
        assert!(first.uncertainty_ns <= HOST_UNCERTAINTY_NS + MAX_SAMPLE_SPAN_NS);
    }

    #[test]
    fn malformed_and_wrong_key_refusals_have_distinct_real_n01_counters() {
        use franken_stream::{OutboundFrame, StreamSender};
        let key = StreamKey::from_bytes([7; 32]);
        let stream = StreamId::new(7).unwrap();
        let mut engine = PlayoutEngine::new(
            PlayoutProfile::MUSIC,
            PlayoutConfig {
                work_ns: 20_000_000,
                lead_ns: 20_000_000,
                tolerance_ns: 0,
            },
        )
        .unwrap();
        engine.begin_stream(1, 0, 1_000_000_000).unwrap();
        let mut sink = CaptureSink {
            receiver: StreamReceiver::new(key.clone(), stream, 1),
            engine,
            view: ClockView {
                group_ns: 0,
                uncertainty_ns: 1_000_000,
                usable: true,
            },
            rejected_playout: 0,
            expected_frames: MAX_CAPTURE_FRAMES,
        };
        assert_eq!(sink.offer(&[0]), SinkVerdict::Refused);
        assert_eq!(sink.receiver.counters().rejected_structure, 1);
        assert_eq!(sink.receiver.counters().rejected_authentication, 0);
        assert_eq!(sink.receiver.counters().mac_verifications, 0);
        let frame =
            || OutboundFrame::media(0, 1_000_000_000, 950_000_000, vec![1; BLOCK_PAYLOAD_BYTES]);
        let mut wrong = StreamSender::new(StreamKey::from_bytes([8; 32]), stream, 1);
        assert_eq!(
            sink.offer(&wrong.send(frame()).unwrap()),
            SinkVerdict::Refused
        );
        assert_eq!(sink.receiver.counters().rejected_structure, 1);
        assert_eq!(sink.receiver.counters().rejected_authentication, 1);
        assert_eq!(sink.receiver.counters().mac_verifications, 1);
        assert_eq!(sink.receiver.counters().accepted, 0);
        let mut correct = StreamSender::new(key, stream, 1);
        assert_eq!(
            sink.offer(&correct.send(frame()).unwrap()),
            SinkVerdict::Admitted { seq: 0 }
        );
        assert_eq!(sink.receiver.counters().accepted, 1);
        assert_eq!(sink.rejected_playout, 0);
    }

    #[test]
    fn authenticated_future_packet_is_credited_but_n04_rejection_is_visible() {
        use franken_stream::{OutboundFrame, StreamSender};
        let key = StreamKey::from_bytes([7; 32]);
        let stream = StreamId::new(7).unwrap();
        let mut wire_sender = StreamSender::new(key.clone(), stream, 1);
        let anchor = 1_000_000_000;
        let mut engine = PlayoutEngine::new(
            PlayoutProfile::MUSIC,
            PlayoutConfig {
                work_ns: 20_000_000,
                lead_ns: 20_000_000,
                tolerance_ns: 0,
            },
        )
        .unwrap();
        engine.begin_stream(1, 0, anchor).unwrap();
        let mut sink = CaptureSink {
            receiver: StreamReceiver::new(key, stream, 1),
            engine,
            view: ClockView {
                group_ns: 0,
                uncertainty_ns: 1_000_000,
                usable: true,
            },
            rejected_playout: 0,
            expected_frames: MAX_CAPTURE_FRAMES,
        };
        let first = wire_sender
            .send(OutboundFrame::media(
                0,
                anchor,
                anchor - 50_000_000,
                vec![1; BLOCK_PAYLOAD_BYTES],
            ))
            .unwrap();
        assert!(matches!(
            sink.offer(&first),
            SinkVerdict::Admitted { seq: 0 }
        ));
        assert_eq!(sink.rejected_playout, 0);
        let frame = u64::from(PlayoutProfile::MUSIC.horizon_blocks) * BLOCK_FRAMES;
        let presentation = anchor + franken_stream::playout::frames_to_ns(frame);
        let too_far = wire_sender
            .send(OutboundFrame::media(
                frame,
                presentation,
                presentation - 50_000_000,
                vec![2; BLOCK_PAYLOAD_BYTES],
            ))
            .unwrap();
        assert!(matches!(
            sink.offer(&too_far),
            SinkVerdict::Admitted { seq: 1 }
        ));
        assert_eq!(sink.rejected_playout, 1);
    }
}
