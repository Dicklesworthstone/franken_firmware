use super::*;

// These observations drive the actual source owner; they do not claim a live
// synchronized group clock. Each replacement is scoped to one owner step.
struct ObservationClock(Arc<Mutex<VecDeque<RuntimeObservation>>>);

impl RuntimeClock for ObservationClock {
    fn observe(&mut self) -> Result<RuntimeObservation, RuntimeError> {
        let mut script = self.0.lock().unwrap();
        if script.len() > 1 {
            Ok(script.pop_front().unwrap())
        } else {
            script.front().copied().ok_or(RuntimeError::Clock)
        }
    }
}

fn view(interface: u64, group: u64, uncertainty: u64, usable: bool) -> RuntimeObservation {
    RuntimeObservation {
        interface_now_ns: interface,
        group_clock: ClockView {
            group_ns: group,
            uncertainty_ns: uncertainty,
            usable,
        },
    }
}

fn at(now: u64, uncertainty: u64) -> RuntimeObservation {
    view(now, now, uncertainty, true)
}

// Record attempted bytes even on WouldBlock so the retry can be compared to
// the already signed datagram, independently of successful deliveries.
struct RecordingPort {
    blocked: Arc<AtomicBool>,
    attempts: SentDatagrams,
    delivered: SentDatagrams,
}

impl DatagramPort for RecordingPort {
    fn send_to(&mut self, lane: Lane, bytes: &[u8], _: SocketAddr) -> Result<(), PortFault> {
        if lane == Lane::Media {
            self.attempts.lock().unwrap().push(bytes.to_vec());
        }
        if self.blocked.load(Ordering::Relaxed) {
            return Err(PortFault::WouldBlock);
        }
        if lane == Lane::Media {
            self.delivered.lock().unwrap().push(bytes.to_vec());
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

struct Fixture {
    owner: SourceRuntime<RecordingPort, ObservationClock>,
    script: Arc<Mutex<VecDeque<RuntimeObservation>>>,
    blocked: Arc<AtomicBool>,
    attempts: SentDatagrams,
    delivered: SentDatagrams,
    reads: Arc<AtomicUsize>,
}

impl Fixture {
    fn new(initial: &[RuntimeObservation], blocked: bool) -> Self {
        let blocked = Arc::new(AtomicBool::new(blocked));
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let port = RecordingPort {
            blocked: Arc::clone(&blocked),
            attempts: Arc::clone(&attempts),
            delivered: Arc::clone(&delivered),
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
        let script = Arc::new(Mutex::new(initial.iter().copied().collect()));
        let reads = Arc::new(AtomicUsize::new(0));
        let reader = CountingReader {
            inner: Cursor::new(MP3),
            reads: Arc::clone(&reads),
        };
        let mut owner = owner_with_reader(
            carrier,
            ObservationClock(Arc::clone(&script)),
            reader,
            250_000_000,
        );
        // Existing transport margin is 1 ms, leaving 500 us for uncertainty.
        owner.work_and_lead_ns = 500_000;
        Self {
            owner,
            script,
            blocked,
            attempts,
            delivered,
            reads,
        }
    }

    fn set_script(&self, observations: &[RuntimeObservation]) {
        *self.script.lock().unwrap() = observations.iter().copied().collect();
    }

    fn assert_first_frame(&self) {
        let wires = self.delivered.lock().unwrap();
        assert_eq!(wires.len(), 1);
        let mut receiver = StreamReceiver::new(
            StreamKey::from_bytes([0x61; 32]),
            StreamId::new(0x1234).unwrap(),
            1,
        );
        let packet = receiver.accept(&wires[0]).unwrap();
        assert_eq!(packet.seq, 0);
        assert_eq!(packet.start_frame, 0);
        assert_eq!(packet.presentation_time_ns, 10_000_000_000);
        assert_eq!(packet.payload.len(), 1024);
        let (samples, _) = packet.payload.as_chunks::<2>();
        let (expected, _) = REFERENCE[..1024].as_chunks::<2>();
        assert!(samples.iter().zip(expected).all(|(a, b)| {
            (i32::from(i16::from_be_bytes(*a)) - i32::from(i16::from_le_bytes(*b))).abs() <= 4
        }));
    }
}

#[test]
fn widening_within_lookahead_publishes_reference_pcm() {
    let mut fixture = Fixture::new(
        &[
            at(9_800_000_000, 0),
            at(9_800_000_100, 1_000),
            at(9_800_000_200, 1_000),
        ],
        false,
    );
    let mut report = None;
    let result = fixture.owner.step(&mut report).unwrap();
    assert_eq!(result.progress, RuntimeProgress::Published { frames: 256 });
    assert_eq!(result.pump.unwrap().media_sent, 1);
    assert_eq!(report.unwrap().peer_count, 1);
    assert_eq!(fixture.owner.consumed_frames, 256);
    fixture.assert_first_frame();
}

#[test]
fn widening_after_decode_waits_and_reuses_the_prepared_pcm() {
    let mut fixture = Fixture::new(&[at(9_750_000_000, 0), at(9_750_000_100, 1_000)], false);
    let mut report = None;
    let first = fixture.owner.step(&mut report).unwrap();
    assert_eq!(first.progress, RuntimeProgress::Waiting);
    assert!(report.is_none());
    assert_eq!(fixture.owner.consumed_frames, 0);
    assert!(fixture.delivered.lock().unwrap().is_empty());
    assert!(fixture.attempts.lock().unwrap().is_empty());
    let prepared_reads = fixture.reads.load(Ordering::Relaxed);

    fixture.set_script(&[at(9_750_002_000, 1_000)]);
    let resumed = fixture.owner.step(&mut report).unwrap();
    assert_eq!(resumed.progress, RuntimeProgress::Published { frames: 256 });
    assert_eq!(resumed.pump.unwrap().media_sent, 1);
    assert_eq!(fixture.reads.load(Ordering::Relaxed), prepared_reads);
    assert_eq!(fixture.owner.consumed_frames, 256);
    assert_eq!(report.unwrap().peer_count, 1);
    fixture.assert_first_frame();
}

#[test]
fn widened_horizon_holds_signed_retry_then_sends_identical_wire() {
    let mut fixture = Fixture::new(&[at(9_750_000_000, 0)], true);
    let first = fixture.owner.step(&mut None).unwrap();
    assert_eq!(first.progress, RuntimeProgress::Published { frames: 256 });
    assert_eq!(first.pump.unwrap().media_sent, 0);
    assert_eq!(fixture.owner.peer_view(7).unwrap().queued_packets, 1);
    assert_eq!(fixture.attempts.lock().unwrap().len(), 1);
    let held_wire = fixture.attempts.lock().unwrap()[0].clone();

    fixture.blocked.store(false, Ordering::Relaxed);
    fixture.set_script(&[at(9_750_000_100, 1_000)]);
    let held = fixture.owner.step(&mut None).unwrap();
    assert_eq!(held.progress, RuntimeProgress::Waiting);
    assert_eq!(held.pump.unwrap().media_sent, 0);
    assert_eq!(fixture.owner.peer_view(7).unwrap().queued_packets, 1);
    assert_eq!(fixture.attempts.lock().unwrap().len(), 1);
    assert!(fixture.delivered.lock().unwrap().is_empty());

    fixture.set_script(&[at(9_750_002_000, 1_000)]);
    let resumed = fixture.owner.step(&mut None).unwrap();
    assert_eq!(resumed.progress, RuntimeProgress::Waiting);
    assert_eq!(resumed.pump.unwrap().media_sent, 1);
    let attempts = fixture.attempts.lock().unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[1], held_wire);
    drop(attempts);
    assert_eq!(fixture.delivered.lock().unwrap()[0], held_wire);
    fixture.assert_first_frame();
}

#[test]
fn widening_only_at_pump_does_not_send_newly_queued_frame_early() {
    let mut fixture = Fixture::new(
        &[
            at(9_750_000_000, 0),
            at(9_750_000_000, 0),
            at(9_750_000_100, 1_000),
        ],
        false,
    );
    let first = fixture.owner.step(&mut None).unwrap();
    assert_eq!(first.progress, RuntimeProgress::Published { frames: 256 });
    assert_eq!(first.pump.unwrap().media_sent, 0);
    assert_eq!(fixture.owner.peer_view(7).unwrap().queued_packets, 1);
    assert!(fixture.attempts.lock().unwrap().is_empty());
    assert!(fixture.delivered.lock().unwrap().is_empty());

    fixture.set_script(&[at(9_750_002_000, 1_000)]);
    let resumed = fixture.owner.step(&mut None).unwrap();
    assert_eq!(resumed.progress, RuntimeProgress::Waiting);
    assert_eq!(resumed.pump.unwrap().media_sent, 1);
    fixture.assert_first_frame();
}

#[test]
fn unsafe_post_decode_observations_stop_without_wire_or_resurrection() {
    let start = 9_800_000_000;
    for bad in [
        view(start - 1, start + 1, 0, true),
        view(start + 1, start - 1, 0, true),
        view(start + 1, start + 1, 0, false),
        view(start + 1, start + 1, 500_001, true),
        view(start + 1, start + 1, u64::MAX, true),
    ] {
        let mut fixture = Fixture::new(&[at(start, 0), bad], false);
        let mut report = None;
        assert!(matches!(
            fixture.owner.step(&mut report),
            Err(RuntimeError::Clock)
        ));
        assert!(report.is_none());
        assert_eq!(fixture.owner.consumed_frames, 0);
        assert!(fixture.attempts.lock().unwrap().is_empty());
        assert!(fixture.delivered.lock().unwrap().is_empty());
        fixture.set_script(&[at(start + 2, 0)]);
        assert!(matches!(
            fixture.owner.step(&mut report),
            Err(RuntimeError::Stopped)
        ));
        assert!(fixture.delivered.lock().unwrap().is_empty());
    }
}

#[test]
fn unsafe_pre_pump_observation_fences_admitted_media() {
    let start = 9_800_000_000;
    for bad in [
        view(start + 1, start + 1, 0, false),
        view(start + 1, start + 1, 500_001, true),
        view(start + 1, start + 1, u64::MAX, true),
    ] {
        let mut fixture = Fixture::new(&[at(start, 0), at(start, 0), bad], false);
        let mut report = None;
        assert!(matches!(
            fixture.owner.step(&mut report),
            Err(RuntimeError::Clock)
        ));
        assert_eq!(fixture.owner.consumed_frames, 256);
        assert!(fixture.attempts.lock().unwrap().is_empty());
        assert!(fixture.delivered.lock().unwrap().is_empty());
        fixture.set_script(&[at(start + 2, 0)]);
        assert!(matches!(
            fixture.owner.step(&mut report),
            Err(RuntimeError::Stopped)
        ));
        assert!(fixture.delivered.lock().unwrap().is_empty());
    }
}

#[test]
fn stop_and_takeover_do_not_flush_held_media_after_widening() {
    for takeover in [false, true] {
        let mut fixture = Fixture::new(&[at(9_750_000_000, 0)], true);
        assert_eq!(
            fixture.owner.step(&mut None).unwrap().progress,
            RuntimeProgress::Published { frames: 256 }
        );
        assert_eq!(fixture.owner.peer_view(7).unwrap().queued_packets, 1);
        assert!(fixture.delivered.lock().unwrap().is_empty());
        fixture.set_script(&[at(9_750_000_100, 1_000)]);
        if takeover {
            let token = AuthorityToken::issue(&fixture.owner.session, u64::MAX);
            fixture
                .owner
                .submit_source_command(
                    &token,
                    &SourceCommand {
                        source: SourceId::new(SourceKind::AirPlay2, "replacement").unwrap(),
                        class: CommandClass::Start,
                        expected_epoch: SourceEpoch::new(1),
                    },
                )
                .unwrap();
        } else {
            fixture.owner.stop();
        }
        fixture.blocked.store(false, Ordering::Relaxed);
        fixture.set_script(&[at(9_750_002_000, 1_000)]);
        assert!(matches!(
            fixture.owner.step(&mut None),
            Err(RuntimeError::Stopped)
        ));
        assert_eq!(fixture.attempts.lock().unwrap().len(), 1);
        assert!(fixture.delivered.lock().unwrap().is_empty());
    }
}

#[test]
fn widening_actual_loopback_udp_finishes_reference_mp3_and_credit() {
    use franken_stream::carrier::HostUdp;

    let key = StreamKey::from_bytes([0x61; 32]);
    let stream = StreamId::new(0x1234).unwrap();
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut carrier = CarrierSender::with_port(
        key.clone(),
        stream,
        1,
        CarrierLimits {
            pace_burst_bytes: 65_536,
            window_packets: 256,
            ..CarrierLimits::baseline()
        },
        HostUdp::bind(ip).unwrap(),
    )
    .unwrap();
    let mut receiver = CarrierReceiver::bind(
        key,
        stream,
        1,
        ReceiverLimits::baseline(),
        ip,
        carrier.control_addr().unwrap(),
    )
    .unwrap()
    .with_peer_id(7)
    .unwrap();
    carrier
        .add_peer(
            7,
            receiver.media_addr().unwrap(),
            receiver.control_addr().unwrap(),
            1500,
        )
        .unwrap();
    let script = Arc::new(Mutex::new(VecDeque::from([at(9_800_000_000, 0)])));
    let mut owner = owner_with_reader(
        carrier,
        ObservationClock(Arc::clone(&script)),
        Cursor::new(MP3),
        250_000_000,
    );
    owner.work_and_lead_ns = 500_000;
    let mut published = 0_usize;
    let mut frames = 0_u64;
    let mut packets = 0_u64;
    let mut sample_index = 0_usize;
    let mut peak = 0_i32;
    let mut squared = 0_u64;
    let mut last_frames = 0_usize;
    let mut reports_sent = 0_u64;
    let mut drained = false;

    for tick in 0..200_u64 {
        let now = 9_800_000_000 + tick * 6_000_000;
        *script.lock().unwrap() =
            VecDeque::from([at(now, 0), at(now + 100, 1_000), at(now + 200, 1_000)]);
        let step = owner.step(&mut None).unwrap();
        if let RuntimeProgress::Published { frames } = step.progress {
            published += frames;
        }
        assert_ne!(step.progress, RuntimeProgress::Incomplete);
        receiver.poll();
        let received = receiver.take_media(256);
        for packet in &received {
            assert_eq!(packet.seq, packets);
            assert_eq!(packet.start_frame, frames);
            assert_eq!(
                packet.presentation_time_ns,
                10_000_000_000 + franken_stream::playout::frames_to_ns(frames)
            );
            assert_eq!(packet.payload.len() % 4, 0);
            for sample in packet.payload.as_chunks::<2>().0 {
                assert!(sample_index + 2 <= REFERENCE.len());
                let actual = i16::from_be_bytes(*sample);
                let expected =
                    i16::from_le_bytes([REFERENCE[sample_index], REFERENCE[sample_index + 1]]);
                let difference = i32::from(actual) - i32::from(expected);
                peak = peak.max(difference.abs());
                squared += (i64::from(difference) * i64::from(difference)) as u64;
                sample_index += 2;
            }
            last_frames = packet.payload.len() / 4;
            frames += u64::try_from(last_frames).unwrap();
            packets += 1;
        }
        if !received.is_empty() {
            receiver.send_report().unwrap();
            reports_sent += 1;
        }
        if step.progress == RuntimeProgress::Drained {
            drained = true;
            break;
        }
    }

    assert!(drained, "bounded loopback source did not drain");
    assert_eq!(published, 24_000);
    assert_eq!(frames, 24_000);
    assert_eq!(packets, 94);
    assert_eq!(last_frames, 192);
    assert_eq!(sample_index, REFERENCE.len());
    assert!(peak <= 4, "unchanged source reference tolerance: {peak}");
    let rms = (squared as f64 / (REFERENCE.len() / 2) as f64).sqrt();
    assert!(rms <= 1.5, "unchanged source reference RMS: {rms}");
    let peer = owner.peer_view(7).unwrap();
    assert_eq!(peer.queued_packets, 0);
    assert_eq!(peer.in_flight, 0);
    assert_eq!(peer.reported_next, 94);
    assert!(peer.counters.reports_accepted > 0);
    assert!(reports_sent > 0);
    assert_eq!(receiver.stats().media_accepted, 94);
    println!(
        "FFW_SOURCE_UNCERTAINTY_UDP frames={frames} packets={packets} tail_frames={last_frames} peak_lsb={peak} rms_lsb={rms} reports_sent={reports_sent} reports_accepted={}",
        peer.counters.reports_accepted
    );
}
