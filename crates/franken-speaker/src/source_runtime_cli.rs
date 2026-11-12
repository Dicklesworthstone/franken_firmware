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
    N01PeerDisposition, PRIMARY_GROUP, ReceiverLimits, STALL_PROBE_NS, SinkVerdict,
};
use franken_stream::playout::{
    Admission, BLOCK_FRAMES, BLOCK_PAYLOAD_BYTES, ClockView, MediaPacket, Outcome, PlayoutConfig,
    PlayoutEngine, PlayoutProfile, Poll,
};
use franken_stream::{StreamId, StreamKey, StreamReceiver};

// This is an explicitly provisioned host-clock uncertainty, not a measurement
// or a claim about a distributed group clock.
const HOST_UNCERTAINTY_NS: u64 = 1_000_000;
const MAX_SAMPLE_SPAN_NS: u64 = 1_000_000;
const MAX_TIMEOUT_MS: u64 = 60_000;
const MAX_CONTROL_LINE: u64 = 256;

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
        if self.engine.on_packet(self.view, &media) != Admission::Admitted {
            self.rejected_playout += 1;
        }
        // Authentication consumed the number even if N04 found the PCM late.
        SinkVerdict::Admitted { seq: packet.seq }
    }
}

fn receive(output: &str, timeout_ms: u64, stream: StreamId, epoch: u64) -> Result<(), String> {
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
    .with_peer_id(1)
    .map_err(|e| e.to_string())?;
    event(
        serde_json::json!({"event":"ready", "media":carrier.media_addr().map_err(|e| e.to_string())?.to_string(),
        "control":carrier.control_addr().map_err(|e| e.to_string())?.to_string()}),
    )?;
    let start = next_control(&input, deadline)?;
    let fields: Vec<_> = start.split_whitespace().collect();
    if fields.len() != 3 || fields[0] != "START" {
        return Err("expected START address anchor".into());
    }
    carrier.set_sender_control(loopback_addr(fields[1])?);
    let anchor: u64 = fields[2]
        .parse()
        .map_err(|_| "invalid presentation anchor")?;
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
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|e| e.to_string())?;
    event(serde_json::json!({"event":"started", "anchor_ns":anchor,
        "host_ns":clock.now()?, "uncertainty_ns":clock.uncertainty_ns}))?;
    let mut captured_frames = 0_u64;
    let mut concealed = 0_u64;
    let mut muted = 0_u64;
    let mut output_bytes = 0_usize;
    let mut real_blocks = 0_u64;
    let mut expected_frames = None;
    let mut credit = CreditRefresh::default();
    let result: Result<(), String> = (|| loop {
        match input.try_recv() {
            Ok(Ok(command)) if command == "STOP" => return Ok(()),
            Ok(Ok(command)) if command.starts_with("END ") && expected_frames.is_none() => {
                let frames: u64 = command[4..]
                    .parse()
                    .map_err(|_| "invalid END frame count")?;
                if frames == 0 || frames > 1_000_000 {
                    return Err("END frame count outside bound".into());
                }
                expected_frames = Some(frames);
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
        let mut pcm = [0_u8; BLOCK_PAYLOAD_BYTES];
        loop {
            match sink.engine.decide(clock.view()?, &mut pcm) {
                Poll::Pending => break,
                Poll::Decision(decision) if decision.outcome == Outcome::Real => {
                    let bytes = &pcm[..usize::from(decision.frames) * 4];
                    let mut hex = String::with_capacity(bytes.len() * 2);
                    use std::fmt::Write as _;
                    for byte in bytes {
                        write!(&mut hex, "{byte:02x}").map_err(|e| e.to_string())?;
                    }
                    let row = serde_json::json!({"start_frame":decision.block * BLOCK_FRAMES,
                        "presentation_ns":decision.presentation_ns,"frames":decision.frames,"pcm_be16_hex":hex});
                    let mut bytes = serde_json::to_vec(&row).map_err(|e| e.to_string())?;
                    bytes.push(b'\n');
                    output_bytes = output_bytes
                        .checked_add(bytes.len())
                        .ok_or("capture limit")?;
                    if output_bytes > 4 * 1024 * 1024 {
                        return Err("capture limit".into());
                    }
                    file.write_all(&bytes).map_err(|e| e.to_string())?;
                    captured_frames += u64::from(decision.frames);
                    real_blocks += 1;
                }
                Poll::Decision(decision) => match decision.outcome {
                    Outcome::Concealed { .. } => concealed += 1,
                    _ => muted += 1,
                },
                other => return Err(format!("playout unavailable: {other:?}")),
            }
        }
        if let Some(expected) = expected_frames {
            if captured_frames > expected {
                return Err("capture exceeds expected frames".into());
            }
            if captured_frames == expected {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_micros(250));
    })();
    file.flush().map_err(|e| e.to_string())?;
    event(
        serde_json::json!({"event": if result.is_ok() { "done" } else { "summary" },
        "captured_frames":captured_frames, "real_blocks":real_blocks,
        "concealed_blocks":concealed, "muted_blocks":muted,
        "media_read":carrier.stats().media_read, "media_accepted":carrier.stats().media_accepted,
        "media_rejected":carrier.stats().media_rejected,
        "rejected_authentication":sink.receiver.counters().rejected_authentication,
        "playout_rejected":sink.rejected_playout}),
    )?;
    result
}

fn send(
    path: &str,
    codec: SourceCodec,
    media: SocketAddr,
    control: SocketAddr,
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
    carrier
        .add_peer(1, media, control, 1500)
        .map_err(|e| e.to_string())?;
    event(
        serde_json::json!({"event":"ready", "control":carrier.port().local_addr(Lane::Control)
        .map_err(|e| format!("control address: {e:?}"))?.to_string()}),
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
            peers: vec![1],
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
    .map_err(|e| e.to_string())?;
    let mut published_frames = 0_u64;
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
            return Err("sender timeout".into());
        }
        let mut outcomes = None;
        let step = runtime.step(&mut outcomes).map_err(|e| e.to_string())?;
        match step.progress {
            RuntimeProgress::Published { frames } => {
                let outcome = outcomes.ok_or("missing peer admission outcome")?;
                if outcome.peer_count != 1
                    || outcome.peers[0]
                        .is_none_or(|p| p.peer != 1 || p.disposition != N01PeerDisposition::Queued)
                {
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
                let counts = runtime.source_counters();
                event(
                    serde_json::json!({"event":"summary", "published_frames":published_frames,
                    "peer":runtime.peer_view(1), "expired_blocks":counts.expired_blocks,
                    "skipped_fenced":counts.skipped_fenced, "skipped_mtu":counts.skipped_mtu,
                    "skipped_stalled":counts.skipped_stalled, "skipped_capacity":counts.skipped_capacity,
                    "skipped_sequence":counts.skipped_sequence, "saturated":counts.saturated}),
                )?;
                runtime.stop();
                return Err("source transport drained with loss".into());
            }
            RuntimeProgress::Drained => {
                let counts = runtime.source_counters();
                event(
                    serde_json::json!({"event":"done", "published_frames":published_frames,
                    "anchor_ns":anchor, "peer":runtime.peer_view(1), "expired_blocks":counts.expired_blocks,
                    "skipped_fenced":counts.skipped_fenced, "skipped_mtu":counts.skipped_mtu,
                    "skipped_stalled":counts.skipped_stalled, "skipped_capacity":counts.skipped_capacity,
                    "skipped_sequence":counts.skipped_sequence, "saturated":counts.saturated}),
                )?;
                return Ok(());
            }
            RuntimeProgress::Waiting | RuntimeProgress::Draining => {}
        }
        thread::sleep(Duration::from_micros(250));
    }
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
        "--source-loopback-receive" if options.len() == 4 => {
            receive(required("--output")?, timeout, stream, epoch)
        }
        "--source-loopback-send" if options.len() == 7 => {
            let codec = match required("--codec")? {
                "mp3" => SourceCodec::Mp3,
                "ogg-vorbis" => SourceCodec::OggVorbis,
                _ => return Err("unsupported local codec".into()),
            };
            send(
                required("--input")?,
                codec,
                loopback_addr(required("--media")?)?,
                loopback_addr(required("--control")?)?,
                timeout,
                stream,
                epoch,
            )
        }
        _ => Err("invalid local source loopback options".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(receiver.stats().reports_sent, 2);

        let mut pcm = [0_u8; BLOCK_PAYLOAD_BYTES];
        let view = ClockView {
            group_ns: anchor - 40_000_000,
            uncertainty_ns: 1_000_000,
            usable: true,
        };
        assert!(
            matches!(sink.engine.decide(view, &mut pcm), Poll::Decision(d) if d.outcome == Outcome::Real)
        );
        assert_eq!(pcm, [0x11; BLOCK_PAYLOAD_BYTES]);
        assert_eq!(sink.engine.decide(view, &mut pcm), Poll::Pending);
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
