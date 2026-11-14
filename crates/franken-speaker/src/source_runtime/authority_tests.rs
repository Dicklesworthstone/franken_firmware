use super::*;

// The local interface clock is deliberately nine seconds behind the admitted
// group clock. These scripted readings are not live clock or quorum evidence.
const OFFSET: u64 = 9_000_000_000;
const EXPIRY: u64 = 9_850_000_000;

fn observation(group: u64, uncertainty: u64) -> RuntimeObservation {
    RuntimeObservation {
        interface_now_ns: group - OFFSET,
        group_clock: ClockView {
            group_ns: group,
            uncertainty_ns: uncertainty,
            usable: true,
        },
    }
}

struct LeaseClock(Arc<Mutex<VecDeque<RuntimeObservation>>>);
impl RuntimeClock for LeaseClock {
    fn observe(&mut self) -> Result<RuntimeObservation, RuntimeError> {
        let mut script = self.0.lock().unwrap();
        if script.len() > 1 {
            Ok(script.pop_front().unwrap())
        } else {
            script.front().copied().ok_or(RuntimeError::Clock)
        }
    }
}

struct LeasePort {
    blocked: Arc<AtomicBool>,
    attempts: SentDatagrams,
    delivered: SentDatagrams,
}
impl DatagramPort for LeasePort {
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

struct LeaseFixture {
    owner: SourceRuntime<LeasePort, LeaseClock>,
    clock: Arc<Mutex<VecDeque<RuntimeObservation>>>,
    blocked: Arc<AtomicBool>,
    attempts: SentDatagrams,
    delivered: SentDatagrams,
    reads: Arc<AtomicUsize>,
}
impl LeaseFixture {
    fn new(expiry: u64, initial: &[RuntimeObservation], blocked: bool) -> Self {
        let blocked = Arc::new(AtomicBool::new(blocked));
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let mut carrier = CarrierSender::with_port(
            StreamKey::from_bytes([0x61; 32]),
            StreamId::new(0x1234).unwrap(),
            1,
            CarrierLimits {
                pace_burst_bytes: 65_536,
                window_packets: 256,
                ..CarrierLimits::baseline()
            },
            LeasePort {
                blocked: Arc::clone(&blocked),
                attempts: Arc::clone(&attempts),
                delivered: Arc::clone(&delivered),
            },
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
        let clock = Arc::new(Mutex::new(initial.iter().copied().collect()));
        let reads = Arc::new(AtomicUsize::new(0));
        let reader = CountingReader {
            inner: Cursor::new(MP3),
            reads: Arc::clone(&reads),
        };
        let mut owner = owner_with_reader_expiry(
            carrier,
            LeaseClock(Arc::clone(&clock)),
            reader,
            250_000_000,
            expiry,
        );
        owner.work_and_lead_ns = 500_000;
        Self {
            owner,
            clock,
            blocked,
            attempts,
            delivered,
            reads,
        }
    }

    fn set(&self, observations: &[RuntimeObservation]) {
        *self.clock.lock().unwrap() = observations.iter().copied().collect();
    }

    fn token(&self, expiry: u64) -> AuthorityToken {
        AuthorityToken::issue(&self.owner.session, expiry)
    }

    fn assert_first_reference_frame(&self) {
        let wire = self.delivered.lock().unwrap();
        assert_eq!(wire.len(), 1);
        let mut receiver = StreamReceiver::new(
            StreamKey::from_bytes([0x61; 32]),
            StreamId::new(0x1234).unwrap(),
            1,
        );
        let packet = receiver.accept(&wire[0]).unwrap();
        assert_eq!(packet.seq, 0);
        assert_eq!(packet.start_frame, 0);
        assert_eq!(packet.payload.len(), 1024);
        let (samples, _) = packet.payload.as_chunks::<2>();
        let (expected, _) = REFERENCE[..1024].as_chunks::<2>();
        assert!(samples.iter().zip(expected).all(|(actual, reference)| {
            (i32::from(i16::from_be_bytes(*actual)) - i32::from(i16::from_le_bytes(*reference)))
                .abs()
                <= 4
        }));
    }
}

#[test]
fn source_authority_live_and_upper_bound_equality_before_decode() {
    let mut live = LeaseFixture::new(EXPIRY, &[observation(EXPIRY - 501_001, 1_000)], false);
    let result = live.owner.step(&mut None).unwrap();
    assert_eq!(result.progress, RuntimeProgress::Published { frames: 256 });
    assert_eq!(result.pump.unwrap().media_sent, 1);
    live.assert_first_reference_frame();

    for (group, uncertainty) in [(EXPIRY - 500_000, 0), (EXPIRY - 501_000, 1_000)] {
        let mut expired = LeaseFixture::new(EXPIRY, &[observation(group, uncertainty)], false);
        let reads_before = expired.reads.load(Ordering::Relaxed);
        assert!(matches!(
            expired.owner.step(&mut None),
            Err(RuntimeError::Authority(_))
        ));
        assert_eq!(expired.reads.load(Ordering::Relaxed), reads_before);
        assert_eq!(expired.owner.consumed_frames, 0);
        assert!(expired.attempts.lock().unwrap().is_empty());
        expired.set(&[observation(group + 1, 0)]);
        assert!(matches!(
            expired.owner.step(&mut None),
            Err(RuntimeError::Stopped)
        ));
        assert_eq!(expired.reads.load(Ordering::Relaxed), reads_before);
    }
}

#[test]
fn source_authority_expiring_across_decode_or_before_pump_stops_wire() {
    let live = observation(EXPIRY - 502_000, 1_000);
    let expired = observation(EXPIRY - 501_000, 1_000);
    for at_pump in [false, true] {
        let script = if at_pump {
            vec![live, live, expired]
        } else {
            vec![live, expired]
        };
        let mut fixture = LeaseFixture::new(EXPIRY, &script, false);
        let mut report = None;
        assert!(matches!(
            fixture.owner.step(&mut report),
            Err(RuntimeError::Authority(_))
        ));
        if at_pump {
            assert_eq!(fixture.owner.consumed_frames, 256);
            assert!(report.is_some(), "admission preceded the failing pump");
        } else {
            assert_eq!(fixture.owner.consumed_frames, 0);
            assert!(report.is_none(), "post-decode expiry forbids publication");
        }
        assert!(fixture.attempts.lock().unwrap().is_empty());
        assert!(fixture.delivered.lock().unwrap().is_empty());
        let reads = fixture.reads.load(Ordering::Relaxed);
        fixture.set(&[observation(EXPIRY + 1, 0)]);
        assert!(matches!(
            fixture.owner.step(&mut report),
            Err(RuntimeError::Stopped)
        ));
        assert_eq!(fixture.reads.load(Ordering::Relaxed), reads);
    }
}

#[test]
fn source_authority_renewal_rejects_bad_candidates_and_cannot_resurrect() {
    let live = observation(EXPIRY - 2_000_000, 1_000);
    let mut fixture = LeaseFixture::new(EXPIRY, &[live], false);
    let original = fixture.owner.authority.clone();
    let mut wrong_group = fixture.token(EXPIRY + 1_000_000);
    wrong_group.group_id = "another-group".into();
    let mut wrong_issuer = fixture.token(EXPIRY + 1_000_000);
    wrong_issuer.issuer_id = "another-issuer".into();
    let mut stale = fixture.token(EXPIRY + 1_000_000);
    stale.epoch = 0;
    let mut future = fixture.token(EXPIRY + 1_000_000);
    future.epoch = 2;
    for token in [wrong_group, wrong_issuer, stale, future] {
        assert!(matches!(
            fixture.owner.renew_authority(token),
            Err(RuntimeError::Authority(_))
        ));
        assert_eq!(fixture.owner.authority, original);
    }
    let shorter = fixture.token(EXPIRY - 1);
    assert!(matches!(
        fixture.owner.renew_authority(shorter),
        Err(RuntimeError::AuthorityShortened)
    ));
    assert_eq!(fixture.owner.authority, original);
    let equal = fixture.token(EXPIRY);
    fixture.owner.renew_authority(equal).unwrap();
    assert_eq!(fixture.owner.authority, original);
    assert_eq!(
        fixture.owner.step(&mut None).unwrap().progress,
        RuntimeProgress::Published { frames: 256 }
    );
    fixture.assert_first_reference_frame();

    let mut expired = LeaseFixture::new(EXPIRY, &[observation(EXPIRY, 0)], false);
    let longer = expired.token(EXPIRY + 1_000_000);
    assert!(matches!(
        expired.owner.renew_authority(longer),
        Err(RuntimeError::Authority(_))
    ));
    assert!(matches!(
        expired.owner.step(&mut None),
        Err(RuntimeError::Stopped)
    ));
    assert!(expired.attempts.lock().unwrap().is_empty());
}

#[test]
fn source_command_candidate_is_checked_at_current_conservative_bound() {
    let now = observation(EXPIRY - 501_000, 1_000);
    let mut fixture = LeaseFixture::new(EXPIRY + 1_000_000, &[now], false);
    let candidate = fixture.token(EXPIRY);
    let command = SourceCommand {
        source: fixture.owner.identity.source.clone(),
        class: CommandClass::Seek,
        expected_epoch: fixture.owner.identity.policy_epoch,
    };
    assert!(matches!(
        fixture.owner.submit_source_command(&candidate, &command),
        Err(RuntimeError::Authority(_))
    ));
    // A bad command token must not replace the still-live owner's authority.
    assert_eq!(
        fixture.owner.step(&mut None).unwrap().progress,
        RuntimeProgress::Published { frames: 256 }
    );
    fixture.assert_first_reference_frame();
}

#[test]
fn group_command_requires_live_source_authority_without_mutation_on_expiry() {
    let command = || FencedControlCommand {
        epoch: 1,
        command_seq: 1,
        payload: GroupCommandPayload::SetGroupVolume {
            volume_0_to_100: 31,
        },
    };
    let mut live = LeaseFixture::new(EXPIRY, &[observation(EXPIRY - 1_000_000, 0)], false);
    let prior_revision = live.owner.session.state_revision;
    assert_eq!(
        live.owner.submit_group_command(command()).unwrap(),
        prior_revision + 1
    );
    assert_eq!(live.owner.session.group_master_volume, 31);

    let mut expired = LeaseFixture::new(EXPIRY, &[observation(EXPIRY - 500_000, 0)], false);
    let old_revision = expired.owner.session.state_revision;
    let old_volume = expired.owner.session.group_master_volume;
    let old_epoch = expired.owner.session.current_epoch;
    assert!(matches!(
        expired.owner.submit_group_command(command()),
        Err(RuntimeError::Authority(_))
    ));
    assert_eq!(expired.owner.session.state_revision, old_revision);
    assert_eq!(expired.owner.session.group_master_volume, old_volume);
    assert_eq!(expired.owner.session.current_epoch, old_epoch);
    assert!(matches!(
        expired.owner.submit_group_command(command()),
        Err(RuntimeError::Stopped)
    ));
    assert!(expired.delivered.lock().unwrap().is_empty());
}

#[test]
fn source_authority_static_margin_and_upper_overflow_fail_closed() {
    for (group, allowed) in [(EXPIRY - 551_001, true), (EXPIRY - 551_000, false)] {
        let mut fixture = LeaseFixture::new(EXPIRY, &[observation(group, 1_000)], false);
        let mut arbiter = SourceArbiter::new(SourceConfig {
            clock_uncertainty_ns: 50_000,
            ..SourceConfig::default()
        });
        let admitted = arbiter
            .submit(
                &fixture.owner.session,
                &fixture.token(EXPIRY),
                0,
                &SourceCommand {
                    source: fixture.owner.identity.source.clone(),
                    class: CommandClass::Start,
                    expected_epoch: SourceEpoch::new(0),
                },
            )
            .unwrap();
        assert_eq!(admitted.epoch, fixture.owner.identity.policy_epoch);
        fixture.owner.arbiter = arbiter;
        if allowed {
            assert_eq!(
                fixture.owner.step(&mut None).unwrap().progress,
                RuntimeProgress::Published { frames: 256 }
            );
            fixture.assert_first_reference_frame();
        } else {
            assert!(matches!(
                fixture.owner.step(&mut None),
                Err(RuntimeError::Authority(_))
            ));
            assert!(fixture.attempts.lock().unwrap().is_empty());
        }
    }
    let mut overflow = LeaseFixture::new(u64::MAX, &[observation(u64::MAX - 500, 1_000)], false);
    assert!(matches!(
        overflow.owner.step(&mut None),
        Err(RuntimeError::Authority(_))
    ));
    assert!(overflow.attempts.lock().unwrap().is_empty());
    assert!(matches!(
        overflow.owner.step(&mut None),
        Err(RuntimeError::Stopped)
    ));
}

#[test]
fn source_authority_expiry_cannot_flush_held_tail_after_eof() {
    let expiry = 10_360_000_000;
    let mut fixture = LeaseFixture::new(expiry, &[observation(9_800_000_000, 0)], false);
    for tick in 0..94_u64 {
        let now = 9_800_000_000 + tick * 6_000_000;
        fixture.set(&[observation(now, 0)]);
        if tick == 93 {
            fixture.blocked.store(true, Ordering::Relaxed);
        }
        let expected = if tick == 93 { 192 } else { 256 };
        assert_eq!(
            fixture.owner.step(&mut None).unwrap().progress,
            RuntimeProgress::Published { frames: expected }
        );
    }
    assert_eq!(fixture.owner.consumed_frames, 24_000);
    assert_eq!(fixture.delivered.lock().unwrap().len(), 93);
    assert_eq!(fixture.owner.peer_view(7).unwrap().queued_packets, 1);
    let (attempts_before_eof, held_tail) = {
        let attempts = fixture.attempts.lock().unwrap();
        (attempts.len(), attempts.last().unwrap().clone())
    };
    let mut receiver = StreamReceiver::new(
        StreamKey::from_bytes([0x61; 32]),
        StreamId::new(0x1234).unwrap(),
        1,
    );
    let packet = receiver.accept(&held_tail).unwrap();
    assert_eq!(packet.seq, 93);
    assert_eq!(packet.start_frame, 93 * 256);
    assert_eq!(packet.payload.len(), 192 * 4);
    fixture.set(&[observation(10_359_000_000, 0)]);
    assert_eq!(
        fixture.owner.step(&mut None).unwrap().progress,
        RuntimeProgress::Draining
    );
    assert!(fixture.owner.eof);
    assert_eq!(fixture.owner.peer_view(7).unwrap().queued_packets, 1);
    assert_eq!(fixture.delivered.lock().unwrap().len(), 93);
    {
        let attempts = fixture.attempts.lock().unwrap();
        assert_eq!(attempts.len(), attempts_before_eof + 1);
        assert_eq!(attempts.last().unwrap(), &held_tail);
    }
    let attempts_before = fixture.attempts.lock().unwrap().len();
    fixture.blocked.store(false, Ordering::Relaxed);
    fixture.set(&[observation(expiry, 0)]);
    assert!(matches!(
        fixture.owner.step(&mut None),
        Err(RuntimeError::Authority(_))
    ));
    assert_eq!(fixture.attempts.lock().unwrap().len(), attempts_before);
    assert_eq!(fixture.delivered.lock().unwrap().len(), 93);
    assert!(matches!(
        fixture.owner.step(&mut None),
        Err(RuntimeError::Stopped)
    ));
    assert_eq!(fixture.delivered.lock().unwrap().len(), 93);
}

#[test]
fn timely_renewal_completes_actual_udp_mp3_and_receiver_credit() {
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
    let clock = Arc::new(Mutex::new(VecDeque::from([observation(
        9_800_000_000,
        1_000,
    )])));
    let old_expiry = 9_900_000_000;
    let mut owner = owner_with_reader_expiry(
        carrier,
        LeaseClock(Arc::clone(&clock)),
        Cursor::new(MP3),
        250_000_000,
        old_expiry,
    );
    owner.work_and_lead_ns = 500_000;
    let mut published = 0_usize;
    let mut frames = 0_u64;
    let mut packets = 0_u64;
    let mut samples = 0_usize;
    let mut tail = 0_usize;
    let mut peak = 0_i32;
    let mut squared = 0_u64;
    let mut reports = 0_u64;
    let mut passed_old_expiry = false;
    let mut drained = false;
    for tick in 0..200_u64 {
        let now = 9_800_000_000 + tick * 6_000_000;
        *clock.lock().unwrap() = VecDeque::from([observation(now, 1_000)]);
        if tick == 5 {
            // This fixture supplies a token; it does not establish a quorum or
            // authenticate a deployed renewal provider.
            let renewed = AuthorityToken::issue(&owner.session, 11_000_000_000);
            owner.renew_authority(renewed).unwrap();
        }
        passed_old_expiry |= now >= old_expiry;
        let result = owner.step(&mut None).unwrap();
        if let RuntimeProgress::Published { frames } = result.progress {
            published += frames;
        }
        assert_ne!(result.progress, RuntimeProgress::Incomplete);
        receiver.poll();
        let incoming = receiver.take_media(256);
        for packet in &incoming {
            assert_eq!(packet.seq, packets);
            assert_eq!(packet.start_frame, frames);
            assert_eq!(
                packet.presentation_time_ns,
                10_000_000_000 + franken_stream::playout::frames_to_ns(frames)
            );
            assert_eq!(packet.payload.len() % 4, 0);
            for sample in packet.payload.as_chunks::<2>().0 {
                assert!(samples + 2 <= REFERENCE.len());
                let expected = i16::from_le_bytes([REFERENCE[samples], REFERENCE[samples + 1]]);
                let difference = i32::from(i16::from_be_bytes(*sample)) - i32::from(expected);
                peak = peak.max(difference.abs());
                squared += (i64::from(difference) * i64::from(difference)) as u64;
                samples += 2;
            }
            tail = packet.payload.len() / 4;
            frames += u64::try_from(tail).unwrap();
            packets += 1;
        }
        if !incoming.is_empty() {
            receiver.send_report().unwrap();
            reports += 1;
        }
        if result.progress == RuntimeProgress::Drained {
            drained = true;
            break;
        }
    }
    assert!(passed_old_expiry && drained);
    assert_eq!(published, 24_000);
    assert_eq!(frames, 24_000);
    assert_eq!(packets, 94);
    assert_eq!(tail, 192);
    assert_eq!(samples, REFERENCE.len());
    assert!(peak <= 4, "unchanged source reference tolerance: {peak}");
    let rms = (squared as f64 / (REFERENCE.len() / 2) as f64).sqrt();
    assert!(rms <= 1.5, "unchanged source reference RMS: {rms}");
    let peer = owner.peer_view(7).unwrap();
    assert_eq!(peer.queued_packets, 0);
    assert_eq!(peer.in_flight, 0);
    assert_eq!(peer.reported_next, 94);
    assert!(peer.counters.reports_accepted > 0 && reports > 0);
    assert_eq!(receiver.stats().media_accepted, 94);
    println!(
        "FFW_SOURCE_LEASE_UDP frames={frames} packets={packets} tail_frames={tail} peak_lsb={peak} rms_lsb={rms} reports_sent={reports} reports_accepted={}",
        peer.counters.reports_accepted
    );
}
