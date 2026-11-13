//! Actual finite decode -> authenticated localhost carrier -> managed protected
//! owner. Time and the retained HAL are explicit host models, not hardware.
use super::*;
use crate::network_render::{FinalFeedbackConfig, FinalFeedbackOutcome};
use crate::source_media::{SourceIdentity, TransportEpoch};
use crate::source_runtime::{
    RuntimeClock, RuntimeConfig, RuntimeError, RuntimeObservation, RuntimeProgress, SourceRuntime,
};
use franken_codec::{Caps, SourceCodec, SourceReaderLimits};
use franken_session::{
    CommandClass, ProposalStatus, SourceArbiter, SourceCommand, SourceConfig, SourceEpoch,
    SourceId, SourceKind,
};
use franken_stream::carrier::{
    CarrierLimits, CarrierSender, DatagramPort, Lane, PRIMARY_GROUP, PortFault, Received,
};
use franken_stream::playout::{ClockView, MediaPacket};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

const ENCODED: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../franken-codec/tests/vectors/mp3_48000.mp3"
));
const REFERENCE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../franken-codec/tests/vectors/mp3_48000.ref.s16"
));
const FRAMES: u64 = 24_000;
const PACKETS: usize = 94;
const INTERVAL: u64 = 10_000_000;

struct CountedReader {
    inner: Cursor<&'static [u8]>,
    reads: Arc<AtomicUsize>,
}
impl Read for CountedReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.read(out)
    }
}
impl Seek for CountedReader {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(position)
    }
}

// Capture only successful actual UDP media sends, bounded by the admitted
// finite fixture. The independent decoder reference is never a source input.
struct ObservedPort {
    inner: HostUdp,
    media: Arc<Mutex<Vec<Vec<u8>>>>,
}
impl DatagramPort for ObservedPort {
    fn send_to(&mut self, lane: Lane, bytes: &[u8], to: SocketAddr) -> Result<(), PortFault> {
        self.inner.send_to(lane, bytes, to)?;
        if lane == Lane::Media {
            let mut media = self.media.lock().unwrap();
            assert!(media.len() < PACKETS, "no retransmitted or extra media");
            media.push(bytes.to_vec());
        }
        Ok(())
    }
    fn recv(&mut self, lane: Lane, out: &mut [u8]) -> Result<Received, PortFault> {
        self.inner.recv(lane, out)
    }
    fn local_addr(&self, lane: Lane) -> Result<SocketAddr, PortFault> {
        self.inner.local_addr(lane)
    }
    fn rebind(&mut self, ip: IpAddr) -> Result<(), PortFault> {
        self.inner.rebind(ip)
    }
}

struct FixtureClock(Rc<Cell<u64>>);
impl RuntimeClock for FixtureClock {
    fn observe(&mut self) -> Result<RuntimeObservation, RuntimeError> {
        let local = self.0.get();
        Ok(RuntimeObservation {
            interface_now_ns: local,
            // The parent fixture's four actual N03 exchanges admit exactly
            // this zero-rate-offset mapping; this is not a fleet clock.
            group_clock: ClockView {
                group_ns: CLOCK_ORIGIN + local,
                uncertainty_ns: 0,
                usable: true,
            },
        })
    }
}

struct Scenario {
    rig: ControllerRig,
    source: SourceRuntime<ObservedPort, FixtureClock>,
    relay: UdpSocket,
    receiver_control: SocketAddr,
    sender_control: SocketAddr,
    media: Arc<Mutex<Vec<Vec<u8>>>>,
    reads: Arc<AtomicUsize>,
    clock_advance: Rc<Cell<u64>>,
    dropped_reports: usize,
}
impl Scenario {
    fn new() -> Self {
        Self::with_control_lease(u64::MAX)
    }

    fn with_control_lease(expires_at_ns: u64) -> Self {
        let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        relay.set_nonblocking(true).unwrap();
        let media = Arc::new(Mutex::new(Vec::with_capacity(PACKETS)));
        let port = ObservedPort {
            inner: HostUdp::bind(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap(),
            media: Arc::clone(&media),
        };
        let mut carrier = CarrierSender::with_port(
            StreamKey::from_bytes([0x42; 32]),
            StreamId::new(0x5EED_5EED_0000_0001).unwrap(),
            1,
            CarrierLimits::baseline(),
            port,
        )
        .unwrap();
        let sender_control = carrier.control_addr().unwrap();
        // Real receiver reports go through an explicitly provisioned localhost
        // relay, which can drop bytes but never synthesizes or edits a report.
        let parts = prepared_parts_for_feedback(true, 2, FRAMES, Some(relay.local_addr().unwrap()));
        let receiver_control = parts.network.endpoint.carrier().control_addr().unwrap();
        let clock_advance = Rc::clone(&parts.network.platform.ops().advance_after_read_ns);
        carrier
            .add_peer(1, parts.address, relay.local_addr().unwrap(), 1500)
            .unwrap();
        let session = UnifiedGroupSession::new("grp", "coord", 1);
        let token = AuthorityToken::issue(&session, u64::MAX);
        let mut arbiter = SourceArbiter::new(SourceConfig::default());
        let source = SourceId::new(SourceKind::Spotify, "finite-host-fixture").unwrap();
        let admitted = arbiter
            .submit(
                &session,
                &token,
                CLOCK_ORIGIN + parts.local_now.get(),
                &SourceCommand {
                    source: source.clone(),
                    class: CommandClass::Start,
                    expected_epoch: SourceEpoch::new(0),
                },
            )
            .unwrap();
        let reads = Arc::new(AtomicUsize::new(0));
        let source = SourceRuntime::open_reader(
            CountedReader {
                inner: Cursor::new(ENCODED),
                reads: Arc::clone(&reads),
            },
            ENCODED.len() as u64,
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
                    presentation_ns: parts.start_group_ns,
                    admitted_lifetime_margin_ns: 12_000_000,
                    partial_final_allowed: true,
                },
                identity: SourceIdentity {
                    source,
                    policy_epoch: admitted.epoch,
                },
                peers: vec![1],
                work_and_lead_ns: 11_000_000,
                overlap_budget_bytes: 1_048_576,
                max_ahead_ns: 250_000_000,
                session,
                arbiter,
                carrier,
                clock: FixtureClock(Rc::clone(&parts.local_now)),
            },
        )
        .unwrap()
        .with_buffered_credit();
        let session = UnifiedGroupSession::new("grp", "coord", TEST_EPOCH);
        let token = AuthorityToken::issue(&session, expires_at_ns);
        let (control, soap, storage_fail) = test_fleet_unleased();
        let bundle = provision_bundle(control, token.clone()).unwrap();
        let mut owner =
            SettledRender::admit_fresh_group(bundle, soap, parts.network, pending_member(), 7)
                .unwrap();
        owner
            .enable_final_feedback(FinalFeedbackConfig {
                interval_ns: INTERVAL,
                grace_ns: 100_000_000,
                max_reports: 3,
            })
            .unwrap();
        let mut rig = ControllerRig {
            owner,
            clock_fail: parts.clock_fail,
            local_now: parts.local_now,
            suppress_flush: parts.suppress_flush,
            flush_requests: parts.flush_requests,
            storage_fail,
            token,
            probe: parts.probe,
            socket: parts.socket,
            address: parts.address,
            sender: parts.sender,
            start_group_ns: parts.start_group_ns,
            start_local_ns: parts.start_local_ns,
        };
        rig.probe.capture_submissions(1024);
        let cutover = ((CLOCK_ORIGIN + 500_000_000) * 48_000) / 1_000_000_000;
        let join = rig
            .owner
            .propose_join(
                rig.token.clone(),
                profile(),
                cutover,
                CLOCK_ORIGIN + 300_000_000,
            )
            .unwrap();
        rig.owner.ack_local(join).unwrap();
        assert!(matches!(
            rig.owner.commit_join(join).unwrap(),
            ProposalStatus::Committed { .. }
        ));
        rig.local_now.set(600_000_000);
        let activation = rig.owner.tick_membership(join).unwrap();
        assert!(
            activation
                .settled
                .iter()
                .any(|(_, s)| matches!(s, ProposalStatus::Activated { .. }))
        );
        Self {
            rig,
            source,
            relay,
            receiver_control,
            sender_control,
            media,
            reads,
            clock_advance,
            dropped_reports: 0,
        }
    }

    fn relay_reports(&mut self, drop: bool) -> usize {
        let mut count = 0;
        let mut bytes = [0; 2048];
        for _ in 0..8 {
            match self.relay.recv_from(&mut bytes) {
                Ok((len, from)) => {
                    assert_eq!(from, self.receiver_control);
                    count += 1;
                    if drop {
                        self.dropped_reports += 1;
                    } else {
                        assert_eq!(
                            self.relay
                                .send_to(&bytes[..len], self.sender_control)
                                .unwrap(),
                            len
                        );
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("actual report relay: {error}"),
            }
        }
        count
    }

    fn natural_end_without_final_credit(&mut self) {
        let mut accepted = 0_u64;
        let mut published = 0_usize;
        let mut timing = ScriptedTiming {
            default_cost: 1,
            ..ScriptedTiming::default()
        };
        for step in 0..10_000_u64 {
            self.rig
                .local_now
                .set(self.rig.start_local_ns - 200_000_000 + step * 100_000);
            let progress = self.source.step(&mut None).unwrap().progress;
            if let RuntimeProgress::Published { frames } = progress {
                published += frames;
            }
            assert_ne!(progress, RuntimeProgress::Incomplete);
            assert_ne!(
                progress,
                RuntimeProgress::Drained,
                "final credit is still lost"
            );
            let ingress = self.rig.owner.poll_media().unwrap();
            accepted += u64::from(ingress.media_accepted);
            self.rig.owner.report_media().unwrap();
            self.relay_reports(accepted == PACKETS as u64);
            self.rig.owner.render_step(&mut timing).unwrap();
            if self.rig.owner.render_state() == RenderState::Draining {
                assert_eq!(accepted, PACKETS as u64);
                assert_eq!(published, FRAMES as usize);
                assert_eq!(self.rig.owner.received_frames_pulled(), FRAMES);
                assert!(self.dropped_reports > 0);
                let peer = self.source.peer_view(1).unwrap();
                assert_eq!(peer.queued_packets, 0);
                assert!(peer.in_flight > 0);
                assert!(
                    self.rig
                        .probe
                        .captured_submissions()
                        .iter()
                        .skip(1)
                        .flatten()
                        .any(|b| *b != 0)
                );
                return;
            }
        }
        panic!("natural EOF did not reach the actual managed drain");
    }
}

fn assert_complete_reference(media: &[Vec<u8>], origin: u64) {
    assert_eq!(media.len(), PACKETS);
    let mut receiver = StreamReceiver::new(
        StreamKey::from_bytes([0x42; 32]),
        StreamId::new(0x5EED_5EED_0000_0001).unwrap(),
        1,
    );
    let mut frames = 0_u64;
    let mut sample_index = 0;
    let mut last_frames = 0;
    let mut peak = 0_i32;
    let mut squared = 0_u64;
    for wire in media {
        let packet = receiver.accept(wire).unwrap();
        let packet = MediaPacket::from_authenticated(&packet).unwrap();
        assert_eq!(packet.start_frame, frames);
        assert_eq!(packet.presentation_ns, origin + frames_to_ns(frames));
        for sample in packet.payload.as_chunks::<2>().0 {
            let actual = i16::from_be_bytes([sample[0], sample[1]]);
            let expected =
                i16::from_le_bytes([REFERENCE[sample_index], REFERENCE[sample_index + 1]]);
            let difference = i32::from(actual) - i32::from(expected);
            peak = peak.max(difference.abs());
            squared += (i64::from(difference) * i64::from(difference)) as u64;
            sample_index += 2;
        }
        frames += u64::from(packet.frames);
        last_frames = packet.frames;
    }
    assert_eq!(frames, FRAMES);
    assert_eq!(sample_index, REFERENCE.len());
    assert_eq!(last_frames, 192, "actual finite final partial block");
    assert!(peak <= 4, "unchanged source reference tolerance: {peak}");
    let rms = (squared as f64 / (REFERENCE.len() / 2) as f64).sqrt();
    assert!(rms <= 1.5, "unchanged source reference RMS: {rms}");
    println!(
        "FFW_FINAL_FEEDBACK_PCM frames={frames} samples={} packets={} peak_lsb={peak} rms_lsb={rms}",
        REFERENCE.len() / 2,
        media.len()
    );
}

#[test]
fn real_decoded_source_retires_lost_final_credit_while_managed_hal_still_drains() {
    let mut scenario = Scenario::new();
    scenario.natural_end_without_final_credit();
    let before_reads = scenario.reads.load(Ordering::Relaxed);
    let before_pcm = scenario.rig.probe.captured_submissions();
    let mut sent = false;
    for _ in 0..4 {
        match scenario.rig.owner.final_feedback().unwrap() {
            FinalFeedbackOutcome::Sent => {
                sent = true;
                break;
            }
            FinalFeedbackOutcome::NotDue => {
                scenario
                    .rig
                    .local_now
                    .set(scenario.rig.local_now.get() + INTERVAL);
            }
            other => panic!("usable natural completion must allow final feedback: {other:?}"),
        }
    }
    assert!(sent);
    assert!(scenario.relay_reports(false) > 0);
    assert_eq!(
        scenario.source.step(&mut None).unwrap().progress,
        RuntimeProgress::Drained
    );
    assert_eq!(scenario.source.peer_view(1).unwrap().in_flight, 0);
    assert_eq!(scenario.rig.owner.render_state(), RenderState::Draining);
    assert_eq!(scenario.reads.load(Ordering::Relaxed), before_reads);
    assert_eq!(scenario.rig.probe.captured_submissions(), before_pcm);
    assert_complete_reference(&scenario.media.lock().unwrap(), scenario.rig.start_group_ns);
    assert!(finish_drain(&mut scenario.rig.owner).acknowledged);
    assert_eq!(scenario.rig.probe.use_after_free(), 0);
    assert_eq!(scenario.rig.probe.modified_while_owned(), 0);
    assert_eq!(scenario.rig.probe.captured_submissions(), before_pcm);
}

#[test]
fn explicit_stop_after_natural_completion_permanently_revokes_managed_final_feedback() {
    let mut scenario = Scenario::new();
    scenario.natural_end_without_final_credit();
    assert_eq!(scenario.rig.owner.render_state(), RenderState::Draining);
    scenario.rig.owner.request_stop().unwrap();
    scenario
        .rig
        .local_now
        .set(scenario.rig.local_now.get() + INTERVAL);
    assert_eq!(
        scenario.rig.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Disabled
    );
    assert_eq!(scenario.relay_reports(false), 0);
    assert_eq!(
        scenario.source.step(&mut None).unwrap().progress,
        RuntimeProgress::Draining
    );
    assert!(finish_drain(&mut scenario.rig.owner).acknowledged);
    assert_eq!(
        scenario.rig.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Disabled
    );
}

#[test]
fn clock_fault_after_natural_completion_revokes_feedback_without_fake_credit_or_pcm() {
    let mut scenario = Scenario::new();
    scenario.natural_end_without_final_credit();
    let submitted = scenario.rig.probe.captured_submissions();
    scenario.rig.clock_fail.set(true);
    assert!(matches!(
        scenario.rig.owner.final_feedback(),
        Err(OwnerError::Render(NetworkRenderError::Clock))
    ));
    assert_eq!(
        scenario.rig.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Disabled
    );
    assert_eq!(scenario.relay_reports(false), 0);
    assert_eq!(scenario.rig.probe.captured_submissions(), submitted);
    assert!(finish_drain(&mut scenario.rig.owner).acknowledged);
}

#[test]
fn committed_authenticated_stop_during_natural_drain_revokes_final_feedback() {
    let mut scenario = Scenario::new();
    scenario.natural_end_without_final_credit();
    let stop = stop_wire(TEST_CONTROLLER, 1);
    assert!(matches!(
        scenario.rig.owner.receive(&stop).unwrap(),
        FecHandled::Control(Handled::Request {
            result: SubmitResult::Queued { .. },
            ..
        })
    ));
    let result = scenario.rig.owner.step_control().unwrap();
    assert!(
        result
            .control
            .unwrap()
            .iter()
            .any(|settled| { matches!(settled.outcome, Outcome::Committed { .. }) })
    );
    // Natural drain's early return must not hide the new canonical stop marker.
    assert!(matches!(
        scenario.rig.owner.final_feedback(),
        Err(OwnerError::Binding)
    ));
    assert_eq!(
        scenario.rig.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Disabled
    );
    assert_eq!(scenario.relay_reports(false), 0);
    assert!(finish_drain(&mut scenario.rig.owner).acknowledged);
}

#[test]
fn managed_final_feedback_checks_control_lease_at_its_single_actual_send_clock_sample() {
    let expiry = CLOCK_ORIGIN + 1_600_000_000;
    let mut scenario = Scenario::with_control_lease(expiry);
    scenario.natural_end_without_final_credit();
    let submitted = scenario.rig.probe.captured_submissions();
    let reads = scenario.reads.load(Ordering::Relaxed);
    // The old wrapper sampled before this lease boundary, then its core sampled
    // after it. The new operation makes exactly one actual kernel clock read.
    let before = 1_595_000_000;
    assert!(5_000_000 > GroupClockConfig::standard().unwrap().lock_uncertainty_ns);
    scenario.rig.local_now.set(before);
    scenario.clock_advance.set(20_000_000);
    assert_eq!(
        scenario.rig.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Sent
    );
    assert_eq!(scenario.rig.local_now.get(), before + 20_000_000);
    assert_eq!(scenario.relay_reports(false), 1);
    assert_eq!(
        scenario.source.step(&mut None).unwrap().progress,
        RuntimeProgress::Drained
    );
    // A later eligible retry has a fresh sampled bound beyond the canonical
    // lease, while the independent N03 authority and finite grace remain live.
    scenario.rig.local_now.set(before + 35_000_000);
    assert!(matches!(
        scenario.rig.owner.final_feedback(),
        Err(OwnerError::LeaseExpired)
    ));
    assert_eq!(scenario.relay_reports(false), 0);
    assert_eq!(
        scenario.rig.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Disabled
    );
    assert_eq!(scenario.rig.probe.captured_submissions(), submitted);
    assert_eq!(scenario.reads.load(Ordering::Relaxed), reads);
    scenario.clock_advance.set(0);
    assert!(finish_drain(&mut scenario.rig.owner).acknowledged);
}

#[test]
fn expired_canonical_lease_refuses_first_final_feedback_without_retiring_source_credit() {
    let expiry = CLOCK_ORIGIN + 1_600_000_000;
    let mut scenario = Scenario::with_control_lease(expiry);
    scenario.natural_end_without_final_credit();
    let submitted = scenario.rig.probe.captured_submissions();
    let before = scenario.source.peer_view(1).unwrap();
    assert!(before.in_flight > 0);
    scenario.rig.local_now.set(1_615_000_000);
    assert!(matches!(
        scenario.rig.owner.final_feedback(),
        Err(OwnerError::LeaseExpired)
    ));
    assert_eq!(scenario.relay_reports(false), 0);
    assert_eq!(
        scenario.rig.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Disabled
    );
    assert_eq!(
        scenario.source.step(&mut None).unwrap().progress,
        RuntimeProgress::Draining
    );
    assert_eq!(
        scenario.source.peer_view(1).unwrap().in_flight,
        before.in_flight
    );
    assert_eq!(scenario.rig.probe.captured_submissions(), submitted);
    assert!(finish_drain(&mut scenario.rig.owner).acknowledged);
}
