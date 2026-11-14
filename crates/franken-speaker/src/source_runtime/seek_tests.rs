use super::*;
use franken_stream::carrier::HostUdp;
use std::io::{self, SeekFrom};

// This fixture explicitly supplies its new receiver epoch. Neither this clock
// nor localhost UDP is evidence of fleet timing, renderer drain, or a device.
struct SeekClock(Arc<Mutex<VecDeque<RuntimeObservation>>>);
impl RuntimeClock for SeekClock {
    fn observe(&mut self) -> Result<RuntimeObservation, RuntimeError> {
        let mut clock = self.0.lock().unwrap();
        if clock.len() > 1 {
            Ok(clock.pop_front().unwrap())
        } else {
            clock.front().copied().ok_or(RuntimeError::Clock)
        }
    }
}

fn at(now: u64) -> RuntimeObservation {
    RuntimeObservation {
        interface_now_ns: now,
        group_clock: ClockView {
            group_ns: now,
            uncertainty_ns: 0,
            usable: true,
        },
    }
}

fn epoch(number: u64, presentation_ns: u64) -> TransportEpoch {
    TransportEpoch {
        group: PRIMARY_GROUP,
        epoch: number,
        start_frame: 0,
        presentation_ns,
        admitted_lifetime_margin_ns: 1_000_000,
        partial_final_allowed: true,
    }
}

struct SeekReader {
    inner: Cursor<&'static [u8]>,
    fail: Arc<AtomicBool>,
    seeks: Arc<AtomicUsize>,
}
impl Read for SeekReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.fail.load(Ordering::Relaxed) {
            return Err(io::Error::other("injected reader failure"));
        }
        self.inner.read(out)
    }
}
impl Seek for SeekReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.seeks.fetch_add(1, Ordering::Relaxed);
        if self.fail.load(Ordering::Relaxed) {
            return Err(io::Error::other("injected seek failure"));
        }
        self.inner.seek(from)
    }
}

struct ObservedUdp {
    inner: HostUdp,
    blocked: Arc<AtomicBool>,
    failures: Arc<AtomicUsize>,
    attempts: SentDatagrams,
}
impl DatagramPort for ObservedUdp {
    fn send_to(&mut self, lane: Lane, bytes: &[u8], to: SocketAddr) -> Result<(), PortFault> {
        if lane == Lane::Media {
            self.attempts.lock().unwrap().push(bytes.to_vec());
            if self.blocked.load(Ordering::Relaxed) {
                return Err(PortFault::WouldBlock);
            }
            if self
                .failures
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err(PortFault::Other("injected datagram failure".into()));
            }
        }
        self.inner.send_to(lane, bytes, to)
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

struct Fixture {
    owner: SourceRuntime<ObservedUdp, SeekClock>,
    receiver: CarrierReceiver<HostUdp>,
    clock: Arc<Mutex<VecDeque<RuntimeObservation>>>,
    blocked: Arc<AtomicBool>,
    failures: Arc<AtomicUsize>,
    attempts: SentDatagrams,
    fail_reader: Arc<AtomicBool>,
    seeks: Arc<AtomicUsize>,
}
impl Fixture {
    fn new(expiry: u64) -> Self {
        Self::with_credit(expiry, false)
    }

    fn with_credit(expiry: u64, buffered: bool) -> Self {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let key = StreamKey::from_bytes([0x61; 32]);
        let stream = StreamId::new(0x1234).unwrap();
        let blocked = Arc::new(AtomicBool::new(false));
        let failures = Arc::new(AtomicUsize::new(0));
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let port = ObservedUdp {
            inner: HostUdp::bind(ip).unwrap(),
            blocked: Arc::clone(&blocked),
            failures: Arc::clone(&failures),
            attempts: Arc::clone(&attempts),
        };
        let mut carrier = CarrierSender::with_port(
            key.clone(),
            stream,
            1,
            CarrierLimits {
                pace_burst_bytes: 65_536,
                window_packets: 256,
                ..CarrierLimits::baseline()
            },
            port,
        )
        .unwrap();
        let receiver = CarrierReceiver::bind(
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
        let clock = Arc::new(Mutex::new(VecDeque::from([at(9_800_000_000)])));
        let fail_reader = Arc::new(AtomicBool::new(false));
        let seeks = Arc::new(AtomicUsize::new(0));
        let reader = SeekReader {
            inner: Cursor::new(MP3),
            fail: Arc::clone(&fail_reader),
            seeks: Arc::clone(&seeks),
        };
        let mut owner = owner_with_reader_expiry(
            carrier,
            SeekClock(Arc::clone(&clock)),
            reader,
            250_000_000,
            expiry,
        );
        owner.work_and_lead_ns = 500_000;
        if buffered {
            owner = owner.with_buffered_credit();
        }
        Self {
            owner,
            receiver,
            clock,
            blocked,
            failures,
            attempts,
            fail_reader,
            seeks,
        }
    }

    fn set(&self, readings: &[RuntimeObservation]) {
        *self.clock.lock().unwrap() = readings.iter().copied().collect();
    }

    fn seek(&mut self, target: u64, next: TransportEpoch) -> Result<Admitted, RuntimeError> {
        let token = self.owner.authority.clone();
        self.owner.seek_source_new_epoch(&token, target, next)
    }
}

#[test]
fn seek_after_eof_fences_held_tail_and_delivers_full_reference_suffix_over_udp() {
    let mut fixture = Fixture::new(u64::MAX);
    let mut old_received = 0_usize;
    for tick in 0..94_u64 {
        fixture.set(&[at(9_800_000_000 + tick * 6_000_000)]);
        if tick == 93 {
            fixture.blocked.store(true, Ordering::Relaxed);
        }
        let expected = if tick == 93 { 192 } else { 256 };
        assert_eq!(
            fixture.owner.step(&mut None).unwrap().progress,
            RuntimeProgress::Published { frames: expected }
        );
        fixture.receiver.poll();
        let packets = fixture.receiver.take_media(256);
        old_received += packets.len();
        if !packets.is_empty() && old_received < 93 {
            fixture.receiver.send_report().unwrap();
        }
    }
    assert_eq!(old_received, 93);
    assert_eq!(fixture.owner.peer_view(7).unwrap().queued_packets, 1);
    let old_wire = fixture.attempts.lock().unwrap().last().unwrap().clone();
    let mut old_parser = StreamReceiver::new(
        StreamKey::from_bytes([0x61; 32]),
        StreamId::new(0x1234).unwrap(),
        1,
    );
    let old_tail = old_parser.accept(&old_wire).unwrap();
    assert_eq!(
        (old_tail.seq, old_tail.start_frame, old_tail.payload.len()),
        (93, 93 * 256, 192 * 4)
    );
    fixture.set(&[at(10_359_000_000)]);
    assert_eq!(
        fixture.owner.step(&mut None).unwrap().progress,
        RuntimeProgress::Draining
    );
    assert!(fixture.owner.eof);
    assert_eq!(fixture.owner.peer_view(7).unwrap().queued_packets, 1);
    assert_eq!(fixture.owner.peer_view(7).unwrap().in_flight, 1);
    let prior_attempts = fixture.attempts.lock().unwrap().len();
    assert_eq!(fixture.attempts.lock().unwrap().last().unwrap(), &old_wire);
    let old_counters = fixture.owner.source_counters();

    // The test caller pre-admits the replacement carrier epoch. This is not
    // a receiver control-plane or output-fence acknowledgment.
    fixture.receiver.advance_epoch(2);
    let admitted = fixture.seek(1_000, epoch(2, 10_550_000_000)).unwrap();
    assert_eq!(admitted.class, CommandClass::Seek);
    assert!(!admitted.minted);
    assert_eq!(fixture.owner.consumed_frames, 0);
    assert!(!fixture.owner.eof);
    assert_eq!(fixture.owner.peer_view(7).unwrap().queued_packets, 0);
    assert_eq!(fixture.owner.peer_view(7).unwrap().sent_next, 0);
    assert_eq!(fixture.owner.peer_view(7).unwrap().in_flight, 0);
    assert_eq!(fixture.owner.source_counters(), old_counters);
    // The caller-admitted receiver must reject old signed wire even if it is
    // delivered late by the network; no sender retry or credit is invented.
    let relay = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    assert_eq!(
        relay
            .send_to(&old_wire, fixture.receiver.media_addr().unwrap())
            .unwrap(),
        old_wire.len()
    );
    fixture.receiver.poll();
    assert!(fixture.receiver.take_media(2).is_empty());
    assert!(fixture.receiver.stats().media_rejected > 0);
    fixture.blocked.store(false, Ordering::Relaxed);

    let mut published = 0_usize;
    let mut frames = 0_u64;
    let mut packets = 0_u64;
    let mut offset = 4_000_usize;
    let mut tail = 0_usize;
    let mut peak = 0_i32;
    let mut squared = 0_u64;
    let mut reports = 0_u64;
    let mut drained = false;
    for tick in 0..200_u64 {
        fixture.set(&[at(10_359_000_000 + tick * 6_000_000)]);
        let result = fixture.owner.step(&mut None).unwrap();
        if let RuntimeProgress::Published { frames } = result.progress {
            published += frames;
        }
        assert_ne!(result.progress, RuntimeProgress::Incomplete);
        fixture.receiver.poll();
        let incoming = fixture.receiver.take_media(256);
        for packet in &incoming {
            assert_eq!(packet.session_epoch, 2);
            assert_eq!(packet.seq, packets);
            assert_eq!(packet.start_frame, frames);
            assert_eq!(
                packet.presentation_time_ns,
                10_550_000_000 + franken_stream::playout::frames_to_ns(frames)
            );
            assert_eq!(packet.payload.len() % 4, 0);
            for sample in packet.payload.as_chunks::<2>().0 {
                assert!(offset + 2 <= REFERENCE.len());
                let expected = i16::from_le_bytes([REFERENCE[offset], REFERENCE[offset + 1]]);
                let diff = i32::from(i16::from_be_bytes(*sample)) - i32::from(expected);
                peak = peak.max(diff.abs());
                squared += (i64::from(diff) * i64::from(diff)) as u64;
                offset += 2;
            }
            tail = packet.payload.len() / 4;
            frames += u64::try_from(tail).unwrap();
            packets += 1;
        }
        if !incoming.is_empty() {
            fixture.receiver.send_report().unwrap();
            reports += 1;
        }
        if result.progress == RuntimeProgress::Drained {
            drained = true;
            break;
        }
    }
    assert!(drained);
    assert_eq!(published, 23_000);
    assert_eq!(frames, 23_000);
    assert_eq!(packets, 90);
    assert_eq!(tail, 216);
    assert_eq!(offset, REFERENCE.len());
    assert!(peak <= 4, "unchanged source reference tolerance: {peak}");
    let rms = (squared as f64 / (23_000 * 2) as f64).sqrt();
    assert!(rms <= 1.5, "unchanged source reference RMS: {rms}");
    let peer = fixture.owner.peer_view(7).unwrap();
    assert_eq!(peer.queued_packets, 0);
    assert_eq!(peer.in_flight, 0);
    assert_eq!(peer.reported_next, 90);
    assert!(reports > 0 && peer.counters.reports_accepted > 0);
    assert!(peer.counters.media_dropped_fenced_packets > 0);
    assert!(
        fixture.attempts.lock().unwrap()[prior_attempts..]
            .iter()
            .all(|wire| wire != &old_wire)
    );
    println!(
        "FFW_SOURCE_SEEK_UDP frames={frames} packets={packets} tail_frames={tail} peak_lsb={peak} rms_lsb={rms} reports_sent={reports}"
    );
}

#[test]
fn repeated_seeks_preserve_source_policy_and_reset_each_wire_epoch() {
    let mut fixture = Fixture::new(u64::MAX);
    let policy_epoch = fixture.owner.identity.policy_epoch;
    for (number, target) in [(2_u64, 1_000_usize), (3, 5_000), (4, 0)] {
        fixture.receiver.advance_epoch(number);
        let admitted = fixture
            .seek(target as u64, epoch(number, 10_000_000_000))
            .unwrap();
        assert_eq!(admitted.class, CommandClass::Seek);
        assert!(!admitted.minted);
        assert_eq!(admitted.epoch, policy_epoch);
        assert_eq!(fixture.owner.identity.policy_epoch, policy_epoch);
        assert_eq!(fixture.owner.transport.epoch, number);
        assert_eq!(fixture.owner.consumed_frames, 0);
        assert_eq!(
            fixture.owner.step(&mut None).unwrap().progress,
            RuntimeProgress::Published { frames: 256 }
        );
        fixture.receiver.poll();
        let packets = fixture.receiver.take_media(2);
        assert_eq!(packets.len(), 1);
        let packet = &packets[0];
        assert_eq!(
            (packet.session_epoch, packet.seq, packet.start_frame),
            (number, 0, 0)
        );
        let (samples, _) = packet.payload.as_chunks::<2>();
        let (expected, _) = REFERENCE[target * 4..target * 4 + 1024].as_chunks::<2>();
        assert_eq!(samples.len(), expected.len());
        assert!(samples.iter().zip(expected).all(|(actual, expected)| {
            (i32::from(i16::from_be_bytes(*actual)) - i32::from(i16::from_le_bytes(*expected)))
                .abs()
                <= 4
        }));
    }
    assert_eq!(fixture.owner.source_counters().published_blocks, 3);
}

#[test]
fn seek_keeps_buffered_credit_and_independent_nonzero_transport_anchor() {
    let mut fixture = Fixture::with_credit(u64::MAX, true);
    assert!(fixture.owner.buffer_transient_credit);
    fixture.receiver.advance_epoch(2);
    let mut next = epoch(2, 10_000_000_000);
    next.start_frame = 256;
    fixture.seek(1_000, next).unwrap();
    assert!(fixture.owner.buffer_transient_credit);
    assert_eq!(fixture.owner.transport.start_frame, 256);
    assert_eq!(fixture.owner.consumed_frames, 0);
    assert_eq!(
        fixture.owner.step(&mut None).unwrap().progress,
        RuntimeProgress::Published { frames: 256 }
    );
    fixture.receiver.poll();
    let packets = fixture.receiver.take_media(2);
    assert_eq!(packets.len(), 1);
    let packet = &packets[0];
    assert_eq!(
        (packet.session_epoch, packet.seq, packet.start_frame),
        (2, 0, 256)
    );
    assert_eq!(packet.presentation_time_ns, 10_000_000_000);
    let (samples, _) = packet.payload.as_chunks::<2>();
    let (expected, _) = REFERENCE[4_000..5_024].as_chunks::<2>();
    assert_eq!(samples.len(), expected.len());
    assert!(samples.iter().zip(expected).all(|(actual, expected)| {
        (i32::from(i16::from_be_bytes(*actual)) - i32::from(i16::from_le_bytes(*expected))).abs()
            <= 4
    }));
}

#[test]
fn seek_retains_clock_latch_and_rejects_post_seek_regression() {
    let mut fixture = Fixture::new(u64::MAX);
    fixture.set(&[at(9_800_000_000), at(9_799_999_999)]);
    fixture.receiver.advance_epoch(2);
    assert!(matches!(
        fixture.seek(1_000, epoch(2, 10_000_000_000)),
        Err(RuntimeError::Clock)
    ));
    fixture.set(&[at(9_800_000_001)]);
    assert!(matches!(
        fixture.owner.step(&mut None),
        Err(RuntimeError::Stopped)
    ));
    assert!(fixture.attempts.lock().unwrap().is_empty());
}

#[test]
fn invalid_seek_preflight_preserves_old_epoch_and_live_media() {
    let mut fixture = Fixture::new(u64::MAX);
    let original_policy = fixture.owner.identity.policy_epoch;
    let before = fixture.owner.source_counters();
    let before_seeks = fixture.seeks.load(Ordering::Relaxed);
    let mut wrong_group = epoch(2, 10_000_000_000);
    wrong_group.group = PRIMARY_GROUP + 1;
    let old_epoch = epoch(1, 10_000_000_000);
    let mut invalid_frame = epoch(2, 10_000_000_000);
    invalid_frame.start_frame = 1;
    let mut too_small_margin = epoch(2, 10_000_000_000);
    too_small_margin.admitted_lifetime_margin_ns = 499_999;
    let mut too_large_margin = epoch(2, 10_000_000_000);
    too_large_margin.admitted_lifetime_margin_ns = fixture.owner.max_ahead_ns;
    let past_cutoff = epoch(2, 9_801_000_000);
    for next in [
        wrong_group,
        old_epoch,
        invalid_frame,
        too_small_margin,
        too_large_margin,
        past_cutoff,
    ] {
        assert!(fixture.seek(1_000, next).is_err());
        assert_eq!(fixture.owner.transport.epoch, 1);
        assert_eq!(fixture.owner.identity.policy_epoch, original_policy);
        assert_eq!(fixture.owner.consumed_frames, 0);
        assert_eq!(fixture.owner.source_counters(), before);
        assert_eq!(fixture.seeks.load(Ordering::Relaxed), before_seeks);
        assert_eq!(fixture.owner.peer_view(7).unwrap().queued_packets, 0);
        assert!(fixture.attempts.lock().unwrap().is_empty());
    }
    let mut wrong_issuer = fixture.owner.authority.clone();
    wrong_issuer.issuer_id = "wrong-issuer".into();
    let mut wrong_group = fixture.owner.authority.clone();
    wrong_group.group_id = "wrong-group".into();
    let mut stale_epoch = fixture.owner.authority.clone();
    stale_epoch.epoch = 0;
    for token in [wrong_issuer, wrong_group, stale_epoch] {
        assert!(matches!(
            fixture
                .owner
                .seek_source_new_epoch(&token, 1_000, epoch(2, 10_000_000_000)),
            Err(RuntimeError::Authority(_))
        ));
        assert_eq!(fixture.owner.transport.epoch, 1);
        assert_eq!(fixture.owner.identity.policy_epoch, original_policy);
        assert_eq!(fixture.seeks.load(Ordering::Relaxed), before_seeks);
    }
    assert_eq!(
        fixture.owner.step(&mut None).unwrap().progress,
        RuntimeProgress::Published { frames: 256 }
    );
    fixture.receiver.poll();
    let packets = fixture.receiver.take_media(2);
    assert_eq!(packets.len(), 1);
    assert_eq!(
        (
            packets[0].session_epoch,
            packets[0].seq,
            packets[0].start_frame
        ),
        (1, 0, 0)
    );
    let (samples, _) = packets[0].payload.as_chunks::<2>();
    let (expected, _) = REFERENCE[..1024].as_chunks::<2>();
    assert!(samples.iter().zip(expected).all(|(actual, expected)| {
        (i32::from(i16::from_be_bytes(*actual)) - i32::from(i16::from_le_bytes(*expected))).abs()
            <= 4
    }));
}

#[test]
fn authority_expiry_during_seek_is_terminal_without_new_wire() {
    let expiry = 9_900_000_000;
    let mut fixture = Fixture::new(expiry);
    fixture.blocked.store(true, Ordering::Relaxed);
    assert_eq!(
        fixture.owner.step(&mut None).unwrap().progress,
        RuntimeProgress::Published { frames: 256 }
    );
    let old_attempts = fixture.attempts.lock().unwrap().len();
    assert!(old_attempts > 0);
    fixture.set(&[at(expiry - 1_000_000), at(expiry - 500_000)]);
    fixture.receiver.advance_epoch(2);
    let seek_calls = fixture.seeks.load(Ordering::Relaxed);
    assert!(matches!(
        fixture.seek(0, epoch(2, 10_000_000_000)),
        Err(RuntimeError::Authority(_))
    ));
    assert!(fixture.seeks.load(Ordering::Relaxed) > seek_calls);
    assert_eq!(fixture.attempts.lock().unwrap().len(), old_attempts);
    fixture.blocked.store(false, Ordering::Relaxed);
    fixture.set(&[at(expiry + 1)]);
    assert!(matches!(
        fixture.owner.step(&mut None),
        Err(RuntimeError::Stopped)
    ));
    assert!(matches!(
        fixture.seek(0, epoch(3, 10_000_000_000)),
        Err(RuntimeError::Stopped)
    ));
    assert_eq!(fixture.attempts.lock().unwrap().len(), old_attempts);
}

#[test]
fn candidate_authority_expiring_during_seek_fences_even_with_live_retained_token() {
    let expiry = 9_900_000_000;
    let mut fixture = Fixture::new(u64::MAX);
    fixture.blocked.store(true, Ordering::Relaxed);
    assert_eq!(
        fixture.owner.step(&mut None).unwrap().progress,
        RuntimeProgress::Published { frames: 256 }
    );
    let attempts = fixture.attempts.lock().unwrap().len();
    assert!(attempts > 0);
    let seeks = fixture.seeks.load(Ordering::Relaxed);
    let candidate = AuthorityToken::issue(&fixture.owner.session, expiry);
    fixture.set(&[at(expiry - 1_000_000), at(expiry - 500_000)]);
    fixture.receiver.advance_epoch(2);
    assert!(matches!(
        fixture
            .owner
            .seek_source_new_epoch(&candidate, 0, epoch(2, 10_000_000_000)),
        Err(RuntimeError::Authority(_))
    ));
    assert!(fixture.seeks.load(Ordering::Relaxed) > seeks);
    assert_eq!(fixture.attempts.lock().unwrap().len(), attempts);
    fixture.blocked.store(false, Ordering::Relaxed);
    fixture.set(&[at(expiry + 1)]);
    assert!(matches!(
        fixture.owner.step(&mut None),
        Err(RuntimeError::Stopped)
    ));
    assert_eq!(fixture.attempts.lock().unwrap().len(), attempts);
}

#[test]
fn seek_post_decode_anchor_crossing_is_terminal_but_inside_sends() {
    let cutoff = 9_999_000_000;
    for after in [cutoff - 1, cutoff, cutoff + 1] {
        let mut fixture = Fixture::new(u64::MAX);
        fixture.set(&[at(cutoff - 100), at(after)]);
        fixture.receiver.advance_epoch(2);
        let outcome = fixture.seek(1_000, epoch(2, 10_000_000_000));
        if after < cutoff {
            assert_eq!(outcome.unwrap().class, CommandClass::Seek);
            assert_eq!(
                fixture.owner.step(&mut None).unwrap().progress,
                RuntimeProgress::Published { frames: 256 }
            );
            fixture.receiver.poll();
            let packets = fixture.receiver.take_media(2);
            assert_eq!(packets.len(), 1);
            assert_eq!((packets[0].session_epoch, packets[0].seq), (2, 0));
            let (samples, _) = packets[0].payload.as_chunks::<2>();
            let (expected, _) = REFERENCE[4_000..5_024].as_chunks::<2>();
            assert_eq!(samples.len(), expected.len());
            assert!(samples.iter().zip(expected).all(|(actual, expected)| {
                (i32::from(i16::from_be_bytes(*actual)) - i32::from(i16::from_le_bytes(*expected)))
                    .abs()
                    <= 4
            }));
        } else {
            assert!(matches!(outcome, Err(RuntimeError::SeekAnchorExpired)));
            assert!(matches!(
                fixture.owner.step(&mut None),
                Err(RuntimeError::Stopped)
            ));
            assert!(fixture.attempts.lock().unwrap().is_empty());
            fixture.receiver.poll();
            assert!(fixture.receiver.take_media(2).is_empty());
        }
    }
}

#[test]
fn actual_reader_seek_failure_stays_terminal_and_never_flushes_old_wire() {
    let mut fixture = Fixture::new(u64::MAX);
    fixture.blocked.store(true, Ordering::Relaxed);
    assert_eq!(
        fixture.owner.step(&mut None).unwrap().progress,
        RuntimeProgress::Published { frames: 256 }
    );
    assert_eq!(fixture.owner.peer_view(7).unwrap().queued_packets, 1);
    let attempts = fixture.attempts.lock().unwrap().len();
    let seeks = fixture.seeks.load(Ordering::Relaxed);
    fixture.fail_reader.store(true, Ordering::Relaxed);
    fixture.receiver.advance_epoch(2);
    assert!(matches!(
        fixture.seek(0, epoch(2, 10_000_000_000)),
        Err(RuntimeError::Source(_))
    ));
    assert!(fixture.seeks.load(Ordering::Relaxed) > seeks);
    fixture.fail_reader.store(false, Ordering::Relaxed);
    fixture.blocked.store(false, Ordering::Relaxed);
    assert!(matches!(
        fixture.owner.step(&mut None),
        Err(RuntimeError::Stopped)
    ));
    assert!(matches!(
        fixture.seek(0, epoch(3, 10_000_000_000)),
        Err(RuntimeError::Stopped)
    ));
    assert_eq!(fixture.attempts.lock().unwrap().len(), attempts);
    fixture.receiver.poll();
    assert!(fixture.receiver.take_media(2).is_empty());
}

#[test]
fn explicit_stop_prevents_later_seek_or_media() {
    let mut fixture = Fixture::new(u64::MAX);
    fixture.owner.stop();
    assert!(matches!(
        fixture.seek(1_000, epoch(2, 10_000_000_000)),
        Err(RuntimeError::Stopped)
    ));
    assert!(matches!(
        fixture.owner.step(&mut None),
        Err(RuntimeError::Stopped)
    ));
    assert!(fixture.attempts.lock().unwrap().is_empty());
}

#[test]
fn new_epoch_real_send_loss_remains_incomplete() {
    let mut fixture = Fixture::new(u64::MAX);
    fixture.receiver.advance_epoch(2);
    fixture.seek(1_000, epoch(2, 10_000_000_000)).unwrap();
    fixture.failures.store(3, Ordering::Relaxed);
    let mut incomplete = false;
    for tick in 0..1_000_u64 {
        fixture.set(&[at(9_800_000_000 + tick * 6_000_000)]);
        let result = fixture.owner.step(&mut None).unwrap();
        fixture.receiver.poll();
        let packets = fixture.receiver.take_media(256);
        if !packets.is_empty() {
            fixture.receiver.send_report().unwrap();
        }
        assert_ne!(result.progress, RuntimeProgress::Drained);
        if result.progress == RuntimeProgress::Incomplete {
            incomplete = true;
            break;
        }
    }
    assert!(incomplete, "a new-epoch send loss must remain incomplete");
    let prior_drops = fixture
        .owner
        .peer_view(7)
        .unwrap()
        .counters
        .media_dropped_send_error_packets;
    assert!(prior_drops > 0);
    assert_eq!(fixture.failures.load(Ordering::Relaxed), 0);
    let before = fixture.owner.source_counters();
    let start = fixture
        .clock
        .lock()
        .unwrap()
        .front()
        .unwrap()
        .group_clock
        .group_ns;
    fixture.receiver.advance_epoch(3);
    fixture.seek(1_000, epoch(3, start + 200_000_000)).unwrap();
    assert_eq!(fixture.owner.source_counters(), before);
    assert_eq!(
        fixture
            .owner
            .peer_view(7)
            .unwrap()
            .counters
            .media_dropped_send_error_packets,
        prior_drops
    );
    let mut fresh_drained = false;
    for tick in 0..200_u64 {
        fixture.set(&[at(start + tick * 6_000_000)]);
        let result = fixture.owner.step(&mut None).unwrap();
        fixture.receiver.poll();
        let packets = fixture.receiver.take_media(256);
        if !packets.is_empty() {
            fixture.receiver.send_report().unwrap();
        }
        assert_ne!(result.progress, RuntimeProgress::Incomplete);
        if result.progress == RuntimeProgress::Drained {
            fresh_drained = true;
            break;
        }
    }
    assert!(fresh_drained, "only new-epoch loss status is reset");
    assert_eq!(
        fixture
            .owner
            .peer_view(7)
            .unwrap()
            .counters
            .media_dropped_send_error_packets,
        prior_drops
    );
    assert_eq!(
        fixture.owner.source_counters().expired_blocks,
        before.expired_blocks
    );
}

#[test]
fn seek_beyond_known_mp3_end_saturates_and_emits_no_media() {
    let decoder = franken_codec::ContainerDecoder::open_reader(
        SourceCodec::Mp3,
        Cursor::new(MP3),
        MP3.len() as u64,
        Caps::default(),
        SourceReaderLimits {
            max_read_calls: 100_000,
            max_reads_per_operation: 100_000,
            max_seek_calls: 1_000,
            max_read_chunk_bytes: 17,
        },
    )
    .unwrap();
    let total = decoder
        .track_frames()
        .expect("the test MP3 must declare its length");
    assert_eq!(total, 24_000);
    let mut fixture = Fixture::new(u64::MAX);
    fixture.receiver.advance_epoch(2);
    let admitted = fixture
        .seek(total + 12_345, epoch(2, 10_000_000_000))
        .unwrap();
    assert_eq!(admitted.class, CommandClass::Seek);
    assert_eq!(
        fixture.owner.step(&mut None).unwrap().progress,
        RuntimeProgress::Drained
    );
    assert_eq!(fixture.owner.consumed_frames, 0);
    assert!(fixture.attempts.lock().unwrap().is_empty());
    fixture.receiver.poll();
    assert!(fixture.receiver.take_media(2).is_empty());
}
