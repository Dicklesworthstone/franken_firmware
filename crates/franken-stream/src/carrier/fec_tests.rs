use super::*;
use crate::{fec, playout};
use std::sync::atomic::AtomicBool;

#[derive(Default)]
struct Port {
    sent: Vec<(Lane, Vec<u8>, SocketAddr)>,
    control: VecDeque<(Vec<u8>, Option<SocketAddr>)>,
    fault: Option<PortFault>,
}
fn addr(port: u16) -> SocketAddr {
    ([127, 0, 0, 1], port).into()
}
impl DatagramPort for Port {
    fn send_to(&mut self, lane: Lane, bytes: &[u8], to: SocketAddr) -> Result<(), PortFault> {
        if let Some(fault) = &self.fault {
            return Err(fault.clone());
        }
        self.sent.push((lane, bytes.to_vec(), to));
        Ok(())
    }
    fn recv(&mut self, lane: Lane, buf: &mut [u8]) -> Result<Received, PortFault> {
        if lane != Lane::Control {
            return Err(PortFault::WouldBlock);
        }
        let Some((wire, from)) = self.control.pop_front() else {
            return Err(PortFault::WouldBlock);
        };
        let len = wire.len().min(buf.len());
        buf[..len].copy_from_slice(&wire[..len]);
        Ok(Received { len, from })
    }
    fn local_addr(&self, lane: Lane) -> Result<SocketAddr, PortFault> {
        Ok(addr(if lane == Lane::Media { 41000 } else { 41001 }))
    }
    fn rebind(&mut self, _: IpAddr) -> Result<(), PortFault> {
        Ok(())
    }
}
fn key() -> StreamKey {
    StreamKey::from_bytes([0x66; 32])
}
fn stream() -> StreamId {
    StreamId::new(0x60601).unwrap()
}
fn view(group_ns: u64) -> playout::ClockView {
    playout::ClockView {
        group_ns,
        uncertainty_ns: 500_000,
        usable: true,
    }
}
fn config(epoch: u64) -> fec::SessionConfig {
    fec::SessionConfig {
        stream: stream(),
        epoch,
        presentation_origin_ns: 500_000_000,
        key: key(),
    }
}
fn samples() -> [[u8; fec::BYTES]; fec::K] {
    std::array::from_fn(|i| std::array::from_fn(|b| ((i * 37 + b * 11) % 251) as u8))
}
fn sender(limits: CarrierLimits) -> CarrierSender<Port> {
    let mut sender = CarrierSender::with_port(key(), stream(), 1, limits, Port::default()).unwrap();
    sender.add_peer(7, addr(42000), addr(42001), 1500).unwrap();
    sender
}
fn generous() -> CarrierLimits {
    CarrierLimits {
        pace_burst_bytes: 100_000,
        ..CarrierLimits::baseline()
    }
}

#[test]
fn n06_paced_sender_lost_source_feedback_and_actual_pcm() {
    let mut sender = sender(generous());
    sender
        .select_group_fec(PRIMARY_GROUP, 2, 500_000_000, &[7])
        .unwrap();
    let source = samples();
    assert_eq!(
        sender
            .submit_group_fec_window(PRIMARY_GROUP, 2, 0, source, 0)
            .unwrap()
            .queued,
        8
    );
    let cancel = AtomicBool::new(false);
    assert_eq!(
        sender
            .pump_fec(1, &[(PRIMARY_GROUP, view(20_000_000))], &cancel)
            .media_sent,
        8
    );
    let initial = sender.port.sent.clone();
    assert_eq!(initial.iter().filter(|(_, w, _)| w[73] == 0).count(), 4);
    assert_eq!(initial.iter().filter(|(_, w, _)| w[73] == 2).count(), 4);
    assert_eq!(
        sender.peer_view(7).unwrap().in_flight,
        0,
        "FEC never spends N01 dense credit"
    );

    let mut receiver = fec::Receiver::new(config(2)).unwrap();
    let mut engine = playout::PlayoutEngine::new(
        playout::PlayoutProfile::MUSIC,
        playout::PlayoutConfig {
            work_ns: 1_000_000,
            lead_ns: 1_000_000,
            tolerance_ns: 0,
        },
    )
    .unwrap();
    engine.begin_stream(2, 0, 500_000_000).unwrap();
    // Drop source 3 and all parity on the link. The real receiver asks for it.
    for (_, wire, _) in &initial {
        if wire[72] < 3 {
            receiver
                .ingest(&mut engine, view(20_000_000), wire)
                .unwrap();
        }
    }
    assert_eq!(
        receiver
            .poll(&mut engine, view(80_000_000), &cancel)
            .unwrap(),
        fec::DecodeState::Idle
    );
    let feedback = receiver
        .feedback(&engine, view(80_000_000))
        .unwrap()
        .unwrap();
    let mut corrupt = feedback.0;
    corrupt[95] ^= 1;
    let mut stale = feedback.0;
    stale[27] = 1;
    sender
        .port
        .control
        .push_back((stale.to_vec(), Some(addr(42001))));
    sender
        .port
        .control
        .push_back((corrupt.to_vec(), Some(addr(42001))));
    sender
        .port
        .control
        .push_back((feedback.0.to_vec(), Some(addr(42002))));
    assert_eq!(
        sender
            .pump_fec(2, &[(PRIMARY_GROUP, view(90_000_000))], &cancel)
            .media_sent,
        0
    );
    // A corrupt request cannot occupy the single no-clock retention slot.
    sender
        .port
        .control
        .push_back((corrupt.to_vec(), Some(addr(42001))));
    sender
        .port
        .control
        .push_back((feedback.0.to_vec(), Some(addr(42001))));
    // A second request cannot grow the bounded slot or displace the first.
    sender
        .port
        .control
        .push_back((feedback.0.to_vec(), Some(addr(42001))));
    assert_eq!(sender.pump(3).media_sent, 0);
    assert_eq!(sender.poll_reports(), 0);
    assert_eq!(sender.stats().fec_feedback_deferred, 1);
    assert_eq!(sender.stats().fec_feedback_overflow, 1);
    let remaining = fec::WINDOW_ALLOWANCE_NS / fec::WORK_UNIT_NS - sender.fec_work_charged();
    assert!(sender.reserve_fec_work(3, remaining));
    assert_eq!(
        sender
            .pump_fec(4, &[(PRIMARY_GROUP, view(100_000_000))], &cancel)
            .media_sent,
        0
    );
    assert!(sender.peer_view(7).unwrap().fec_feedback_pending);
    let result = sender.pump_fec(21_333_334, &[(PRIMARY_GROUP, view(101_000_000))], &cancel);
    assert_eq!(result.media_sent, 1);
    let tail = &sender.port.sent.last().unwrap().1;
    assert_eq!((tail[72], tail[73]), (3, 1));
    assert_eq!(
        receiver
            .ingest(&mut engine, view(105_000_000), tail)
            .unwrap()
            .admission,
        Some(playout::Admission::Admitted)
    );
    assert_eq!(
        sender.peer_view(7).unwrap().counters.fec_feedback_accepted,
        1
    );
    assert_eq!(
        sender.peer_view(7).unwrap().counters.fec_feedback_refused,
        2
    );
    assert_eq!(
        (
            sender.stats().fec_feedback_accepted,
            sender.stats().fec_feedback_refused
        ),
        (1, 5)
    );
    sender
        .port
        .control
        .push_back((feedback.0.to_vec(), Some(addr(42001))));
    assert_eq!(
        sender
            .pump_fec(21_333_335, &[(PRIMARY_GROUP, view(110_000_000))], &cancel)
            .media_sent,
        0
    );
    for (i, expected) in source.iter().enumerate() {
        let presentation = 500_000_000 + playout::frames_to_ns(i as u64 * 256);
        let cutoff = playout::consume_by(presentation, 1_000_000, 1_000_000, 500_000);
        let mut out = [0; fec::BYTES];
        let playout::Poll::Decision(decision) =
            receiver.decide(&mut engine, view(cutoff), &mut out)
        else {
            panic!("missing playout decision");
        };
        assert_eq!(decision.outcome, playout::Outcome::Real);
        assert_eq!(&out, expected);
    }
}

#[test]
fn n06_paced_sender_admission_clock_deadline_and_cancel_are_bounded() {
    let mut ring = sender(generous());
    ring.select_group_fec(PRIMARY_GROUP, 2, 500_000_000, &[7])
        .unwrap();
    for window in 0..=fec::WINDOWS as u64 {
        let now = window * 21_333_334;
        ring.submit_group_fec_window(PRIMARY_GROUP, 2, window, samples(), now)
            .unwrap();
    }
    assert_eq!(
        ring.group_view(PRIMARY_GROUP).unwrap().fec_retained_windows,
        fec::WINDOWS
    );
    let peer_index = ring.index_of(7).expect("current carrier peer 7");
    assert!(!ring.feedback_relevant(peer_index, &{
        let mut old = [0; fec::FEEDBACK_BYTES];
        old[64] = 1;
        old
    }));
    let mut exact_ipv4 = sender(CarrierLimits {
        pace_burst_bytes: (fec::DATAGRAM + IPV4_UDP_OVERHEAD_BYTES) as u64,
        ..CarrierLimits::baseline()
    });
    exact_ipv4
        .select_group_fec(PRIMARY_GROUP, 2, 500_000_000, &[7])
        .unwrap();
    exact_ipv4
        .submit_group_fec_window(PRIMARY_GROUP, 2, 0, samples(), 0)
        .unwrap();
    assert_eq!(
        exact_ipv4
            .pump_fec(
                1,
                &[(PRIMARY_GROUP, view(20_000_000))],
                &AtomicBool::new(false)
            )
            .media_sent,
        1
    );
    let mut budget = sender(generous());
    let other = budget
        .add_group(key(), StreamId::new(0x60602).unwrap(), 1)
        .unwrap();
    budget
        .add_peer_in_group(other, 8, addr(44000), addr(44001), 1500)
        .unwrap();
    budget
        .select_group_fec(PRIMARY_GROUP, 2, 500_000_000, &[7])
        .unwrap();
    budget
        .select_group_fec(other, 2, 500_000_000, &[8])
        .unwrap();
    budget
        .submit_group_fec_window(PRIMARY_GROUP, 2, 0, samples(), 0)
        .unwrap();
    budget
        .submit_group_fec_window(PRIMARY_GROUP, 2, 1, samples(), 1)
        .unwrap();
    assert!(
        budget
            .submit_group_fec_window(other, 2, 0, samples(), 2)
            .is_err()
    );
    assert!(budget.stats().fec_work_refused > 0);
    assert!(
        budget
            .submit_group_fec_window(other, 2, 0, samples(), 21_333_334)
            .is_ok()
    );
    let mut tiny = sender(generous());
    tiny.set_path_mtu(7, fec::DATAGRAM + IPV4_UDP_OVERHEAD_BYTES - 1)
        .unwrap();
    assert!(
        tiny.select_group_fec(PRIMARY_GROUP, 2, 500_000_000, &[7])
            .is_err()
    );
    assert_eq!(tiny.epoch(), 1);
    let mut low = sender(CarrierLimits {
        pace_bytes_per_sec: 220_000,
        ..generous()
    });
    assert!(
        low.select_group_fec(PRIMARY_GROUP, 2, 500_000_000, &[7])
            .is_err()
    );
    assert_eq!(low.epoch(), 1);
    let mut s = sender(CarrierLimits {
        peer_queue_packets: 2,
        aggregate_queue_packets: 2,
        ..generous()
    });
    assert!(
        s.select_group_fec(PRIMARY_GROUP, 2, 500_000_000, &[])
            .is_err()
    );
    s.select_group_fec(PRIMARY_GROUP, 2, 500_000_000, &[7])
        .unwrap();
    let report = s
        .submit_group_fec_window(PRIMARY_GROUP, 2, 0, samples(), 0)
        .unwrap();
    assert_eq!((report.queued, report.evicted), (8, 6));
    assert_eq!(s.peer_view(7).unwrap().queued_packets, 2);
    let cancel = AtomicBool::new(false);
    assert_eq!(s.pump(0).media_sent, 0, "no group clock means no FEC send");
    assert_eq!(
        s.pump_fec(1, &[(PRIMARY_GROUP, view(600_000_000))], &cancel)
            .media_sent,
        0
    );
    assert!(s.peer_view(7).unwrap().counters.media_dropped_late_packets > 0);
    s.advance_epoch(3).unwrap();
    s.select_group_fec(PRIMARY_GROUP, 4, 500_000_000, &[7])
        .unwrap();
    s.submit_group_fec_window(PRIMARY_GROUP, 4, 0, samples(), 2)
        .unwrap();
    cancel.store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(
        s.pump_fec(3, &[(PRIMARY_GROUP, view(20_000_000))], &cancel)
            .media_sent,
        0
    );
    assert_eq!(s.peer_view(7).unwrap().queued_packets, 0);
    assert!(
        s.submit_group_fec_window(PRIMARY_GROUP, 4, 1, samples(), 4)
            .is_err()
    );
}

#[test]
fn n06_feedback_send_checks_receiver_identity_and_transport_fault() {
    let mut receiver = CarrierReceiver::with_port(
        key(),
        stream(),
        2,
        ReceiverLimits::baseline(),
        Port::default(),
        addr(42001),
    )
    .unwrap();
    let mut wire = [0; fec::FEEDBACK_BYTES];
    wire[..4].copy_from_slice(b"FFWA");
    wire[12..20].copy_from_slice(&stream().get().to_be_bytes());
    wire[20..28].copy_from_slice(&2_u64.to_be_bytes());
    let feedback = fec::Feedback(wire);
    receiver.send_fec_feedback(&feedback).unwrap();
    assert_eq!(
        receiver.port.sent[0],
        (Lane::Control, wire.to_vec(), addr(42001))
    );
    let mut wrong = wire;
    wrong[27] = 3;
    assert!(receiver.send_fec_feedback(&fec::Feedback(wrong)).is_err());
    assert_eq!(receiver.port.sent.len(), 1);
    receiver.port.fault = Some(PortFault::WouldBlock);
    assert!(receiver.send_fec_feedback(&feedback).is_err());
    assert_eq!(receiver.port.sent.len(), 1);
}

#[test]
fn n06_pacer_attempt_limit_retry_and_backward_clock_fence() {
    let mut s = sender(CarrierLimits {
        max_sends_per_pump: 1,
        ..generous()
    });
    s.select_group_fec(PRIMARY_GROUP, 2, 500_000_000, &[7])
        .unwrap();
    s.submit_group_fec_window(PRIMARY_GROUP, 2, 0, samples(), 0)
        .unwrap();
    s.port.fault = Some(PortFault::WouldBlock);
    let cancel = AtomicBool::new(false);
    for now in 1..=3 {
        let out = s.pump_fec(now, &[(PRIMARY_GROUP, view(20_000_000))], &cancel);
        assert_eq!(out.media_sent, 0);
        assert!(out.send_cap_hit);
    }
    assert_eq!(
        s.peer_view(7)
            .unwrap()
            .counters
            .media_dropped_send_error_packets,
        1
    );
    s.port.fault = None;
    assert_eq!(
        s.pump_fec(250_000_004, &[(PRIMARY_GROUP, view(100_000_000))], &cancel)
            .media_sent,
        1
    );
    assert_eq!(s.port.sent.len(), 1);
    assert_eq!(
        s.pump_fec(250_000_005, &[(PRIMARY_GROUP, view(99_000_000))], &cancel)
            .media_sent,
        0
    );
    assert_eq!(
        s.pump_fec(250_000_006, &[(PRIMARY_GROUP, view(101_000_000))], &cancel)
            .media_sent,
        0
    );
    s.advance_epoch(3).unwrap();
    s.select_group_fec(PRIMARY_GROUP, 4, 500_000_000, &[7])
        .unwrap();
    s.submit_group_fec_window(PRIMARY_GROUP, 4, 0, samples(), 250_000_007)
        .unwrap();
    assert_eq!(
        s.pump_fec(250_000_008, &[(PRIMARY_GROUP, view(20_000_000))], &cancel)
            .media_sent,
        1
    );
}

#[test]
fn n06_rebind_clears_fec_authority_and_old_queued_symbols() {
    let mut s = sender(generous());
    s.select_group_fec(PRIMARY_GROUP, 2, 500_000_000, &[7])
        .unwrap();
    s.submit_group_fec_window(PRIMARY_GROUP, 2, 0, samples(), 0)
        .unwrap();
    let cancel = AtomicBool::new(false);
    assert_eq!(
        s.pump_fec(1, &[(PRIMARY_GROUP, view(20_000_000))], &cancel)
            .media_sent,
        8
    );
    let mut receiver = fec::Receiver::new(config(2)).unwrap();
    let mut engine = playout::PlayoutEngine::new(
        playout::PlayoutProfile::MUSIC,
        playout::PlayoutConfig {
            work_ns: 1_000_000,
            lead_ns: 1_000_000,
            tolerance_ns: 0,
        },
    )
    .unwrap();
    engine.begin_stream(2, 0, 500_000_000).unwrap();
    for (_, wire, _) in &s.port.sent {
        if matches!(wire[72], 1..=3) {
            receiver
                .ingest(&mut engine, view(20_000_000), wire)
                .unwrap();
        }
    }
    assert_eq!(
        receiver
            .poll(&mut engine, view(80_000_000), &cancel)
            .unwrap(),
        fec::DecodeState::Idle
    );
    let feedback = receiver
        .feedback(&engine, view(80_000_000))
        .unwrap()
        .unwrap();
    s.port
        .control
        .push_back((feedback.0.to_vec(), Some(addr(42001))));
    s.pump(2);
    assert!(s.peer_view(7).unwrap().fec_feedback_pending);
    s.submit_group_fec_window(PRIMARY_GROUP, 2, 1, samples(), 3)
        .unwrap();
    assert!(s.peer_view(7).unwrap().queued_packets > 0);
    s.peer_address_changed(7, addr(43000), addr(43001)).unwrap();
    assert_eq!(s.peer_view(7).unwrap().queued_packets, 0);
    assert!(!s.peer_view(7).unwrap().fec_feedback_pending);
    let n01 = OutboundFrame::media(0, 500_000_000, 497_500_000, vec![0; 1024]);
    assert!(s.submit_group_media(PRIMARY_GROUP, 2, &n01, 0).is_err());
    assert_eq!(
        s.group_view(PRIMARY_GROUP).unwrap().selected_strategy,
        "transition-required"
    );
    assert!(
        s.submit_group_fec_window(PRIMARY_GROUP, 2, 1, samples(), 0)
            .is_err()
    );
    s.select_group_fec(PRIMARY_GROUP, 3, 500_000_000, &[7])
        .unwrap();
    s.submit_group_fec_window(PRIMARY_GROUP, 3, 0, samples(), 21_333_334)
        .unwrap();
    let old_sent = s.port.sent.len();
    assert_eq!(
        s.pump_fec(
            21_333_335,
            &[(PRIMARY_GROUP, view(20_000_000))],
            &AtomicBool::new(false)
        )
        .media_sent,
        8
    );
    assert!(
        s.port.sent[old_sent..]
            .iter()
            .all(|(_, _, to)| *to == addr(43000))
    );
    let mut receiver = fec::Receiver::new(config(3)).unwrap();
    let mut engine = playout::PlayoutEngine::new(
        playout::PlayoutProfile::MUSIC,
        playout::PlayoutConfig {
            work_ns: 1_000_000,
            lead_ns: 1_000_000,
            tolerance_ns: 0,
        },
    )
    .unwrap();
    engine.begin_stream(3, 0, 500_000_000).unwrap();
    for (_, wire, _) in &s.port.sent[old_sent..] {
        if matches!(wire[72], 1..=3) {
            receiver
                .ingest(&mut engine, view(20_000_000), wire)
                .unwrap();
        }
    }
    assert_eq!(
        receiver
            .poll(&mut engine, view(80_000_000), &cancel)
            .unwrap(),
        fec::DecodeState::Idle
    );
    let feedback = receiver
        .feedback(&engine, view(80_000_000))
        .unwrap()
        .unwrap();
    s.port
        .control
        .push_back((feedback.0.to_vec(), Some(addr(43001))));
    s.pump(21_333_336);
    assert!(s.peer_view(7).unwrap().fec_feedback_pending);
    cancel.store(true, std::sync::atomic::Ordering::Release);
    s.pump_fec(21_333_337, &[(PRIMARY_GROUP, view(90_000_000))], &cancel);
    assert!(!s.peer_view(7).unwrap().fec_feedback_pending);
}

#[test]
fn n06_paced_parity_after_first_cutoff_recovers_later_live_pcm() {
    assert_held_live_alias_quotas();
    let mut sender = sender(CarrierLimits {
        max_sends_per_pump: 1,
        ..generous()
    });
    sender
        .select_group_fec(PRIMARY_GROUP, 2, 500_000_000, &[7])
        .unwrap();
    let source = samples();
    sender
        .submit_group_fec_window(PRIMARY_GROUP, 2, 0, source, 0)
        .unwrap();
    let cancel = AtomicBool::new(false);
    for now in 1..=5 {
        assert_eq!(
            sender
                .pump_fec(now, &[(PRIMARY_GROUP, view(20_000_000))], &cancel)
                .media_sent,
            1
        );
    }
    let mut receiver = fec::Receiver::new(config(2)).unwrap();
    let mut engine = playout::PlayoutEngine::new(
        playout::PlayoutProfile::MUSIC,
        playout::PlayoutConfig {
            work_ns: 1_000_000,
            lead_ns: 1_000_000,
            tolerance_ns: 0,
        },
    )
    .unwrap();
    engine.begin_stream(2, 0, 500_000_000).unwrap();
    // Sources 0 and 3 are lost; source 1, 2 and the first repair arrive.
    for (_, wire, _) in &sender.port.sent {
        if matches!(wire[72], 1 | 2 | 4) {
            receiver
                .ingest(&mut engine, view(20_000_000), wire)
                .unwrap();
        }
    }
    let first = playout::consume_by(500_000_000, 1_000_000, 1_000_000, 500_000);
    let mut committed = [0; fec::BYTES];
    let playout::Poll::Decision(first_decision) =
        receiver.decide(&mut engine, view(first), &mut committed)
    else {
        panic!("missing first decision");
    };
    assert_ne!(first_decision.outcome, playout::Outcome::Real);
    assert_eq!(committed, [0; fec::BYTES]);
    let after_render = first + 2_000_001;
    assert_eq!(
        sender
            .pump_fec(6, &[(PRIMARY_GROUP, view(after_render))], &cancel)
            .media_sent,
        1
    );
    let late_parity = &sender.port.sent.last().unwrap().1;
    assert_eq!((late_parity[72], late_parity[73]), (5, 2));
    // The exact old wire may not create a missing slot after the replay horizon.
    let mut empty = fec::Receiver::new(config(2)).unwrap();
    let mut empty_engine = playout::PlayoutEngine::new(
        playout::PlayoutProfile::MUSIC,
        playout::PlayoutConfig {
            work_ns: 1_000_000,
            lead_ns: 1_000_000,
            tolerance_ns: 0,
        },
    )
    .unwrap();
    empty_engine.begin_stream(2, 0, 500_000_000).unwrap();
    assert!(matches!(
        empty.decide(&mut empty_engine, view(first), &mut [0; fec::BYTES]),
        playout::Poll::Decision(_)
    ));
    assert_eq!(
        empty.ingest(&mut empty_engine, view(after_render), late_parity),
        Err(fec::Refusal::Future)
    );
    assert_eq!(empty.status().retained_windows, 0);
    // A newer window in the same modulo slot cannot be evicted by old wire.
    let mut alias = fec::Receiver::new(config(2)).unwrap();
    let mut alias_engine = playout::PlayoutEngine::new(
        playout::PlayoutProfile::MUSIC,
        playout::PlayoutConfig {
            work_ns: 1_000_000,
            lead_ns: 1_000_000,
            tolerance_ns: 0,
        },
    )
    .unwrap();
    alias_engine.begin_stream(2, 0, 500_000_000).unwrap();
    let cfg = config(2);
    let newer = fec::sign_symbol(
        &cfg,
        8,
        0,
        0,
        fec::content_digest(&cfg.metadata(8).unwrap(), &source),
        &source[0],
    )
    .unwrap();
    alias
        .ingest(&mut alias_engine, view(160_000_000), &newer)
        .unwrap();
    assert!(matches!(
        alias.decide(&mut alias_engine, view(first), &mut [0; fec::BYTES]),
        playout::Poll::Decision(_)
    ));
    assert_eq!(
        alias.ingest(&mut alias_engine, view(after_render), late_parity),
        Err(fec::Refusal::Future)
    );
    assert_eq!(alias.status().windows[0].window, Some(8));
    assert_eq!(alias.status().windows[0].authenticated_mask, 1);
    receiver
        .ingest(&mut engine, view(after_render), late_parity)
        .unwrap();
    let mut ready = false;
    for _ in 0..1000 {
        match receiver.poll(&mut engine, view(after_render), &cancel) {
            Ok(fec::DecodeState::Pending) => {}
            Ok(fec::DecodeState::Ready) => {
                assert_eq!(
                    receiver.publish(&mut engine, view(after_render), &cancel),
                    Ok(fec::DecodeState::Ready)
                );
                ready = true;
                break;
            }
            other => panic!("later-block decode: {other:?}"),
        }
    }
    assert!(ready, "actual scalar decode must complete");
    assert_eq!(receiver.status().counters.late, 1);
    assert_eq!(receiver.status().counters.recovered, 1);
    assert_eq!(
        committed,
        [0; fec::BYTES],
        "already returned PCM cannot change"
    );
    for (index, expected) in source.iter().enumerate().skip(1) {
        let presentation = 500_000_000 + playout::frames_to_ns(index as u64 * 256);
        let cutoff = playout::consume_by(presentation, 1_000_000, 1_000_000, 500_000);
        let mut out = [0; fec::BYTES];
        let playout::Poll::Decision(decision) =
            receiver.decide(&mut engine, view(cutoff), &mut out)
        else {
            panic!("missing later decision");
        };
        assert_eq!(decision.outcome, playout::Outcome::Real);
        assert_eq!(&out, expected);
    }
    let cfg = config(2);
    let late = fec::sign_symbol(
        &cfg,
        0,
        6,
        2,
        fec::content_digest(&cfg.metadata(0).unwrap(), &source),
        &fec::encode_symbol(&source, 6).unwrap(),
    )
    .unwrap();
    let last = playout::consume_by(
        500_000_000 + playout::frames_to_ns(3 * 256),
        1_000_000,
        1_000_000,
        500_000,
    );
    assert_eq!(
        receiver.ingest(&mut engine, view(last + 2_000_001), &late),
        Err(fec::Refusal::Future)
    );
}

#[test]
fn n06_retired_feedback_cannot_displace_live_window_recovery() {
    let mut sender = sender(generous());
    sender
        .select_group_fec(PRIMARY_GROUP, 2, 500_000_000, &[7])
        .unwrap();
    let cancel = AtomicBool::new(false);
    for window in 0..=4 {
        let now = window * 21_333_334;
        sender
            .submit_group_fec_window(PRIMARY_GROUP, 2, window, samples(), now)
            .unwrap();
        assert_eq!(
            sender
                .pump_fec(now + 1, &[(PRIMARY_GROUP, view(20_000_000))], &cancel)
                .media_sent,
            8
        );
    }
    let make_receiver = || {
        let mut engine = playout::PlayoutEngine::new(
            playout::PlayoutProfile::MUSIC,
            playout::PlayoutConfig {
                work_ns: 1_000_000,
                lead_ns: 1_000_000,
                tolerance_ns: 0,
            },
        )
        .unwrap();
        engine.begin_stream(2, 0, 500_000_000).unwrap();
        (fec::Receiver::new(config(2)).unwrap(), engine)
    };
    let (mut old_receiver, mut old_engine) = make_receiver();
    let (mut live_receiver, mut live_engine) = make_receiver();
    for (_, wire, _) in &sender.port.sent {
        let window = be_u64(wire, 28);
        if matches!(wire[72], 1..=3) && window == 0 {
            old_receiver
                .ingest(&mut old_engine, view(20_000_000), wire)
                .unwrap();
        }
        if matches!(wire[72], 1..=3) && window == 4 {
            live_receiver
                .ingest(&mut live_engine, view(80_000_000), wire)
                .unwrap();
        }
    }
    assert_eq!(
        old_receiver
            .poll(&mut old_engine, view(80_000_000), &cancel)
            .unwrap(),
        fec::DecodeState::Idle
    );
    let old = old_receiver
        .feedback(&old_engine, view(80_000_000))
        .unwrap()
        .unwrap();
    assert_eq!(be_u64(&old.0, 28), 0);
    assert_eq!(
        live_receiver
            .poll(&mut live_engine, view(160_000_000), &cancel)
            .unwrap(),
        fec::DecodeState::Idle
    );
    let mut live = None;
    for _ in 0..fec::WINDOWS {
        let Some(feedback) = live_receiver
            .feedback(&live_engine, view(160_000_000))
            .unwrap()
        else {
            break;
        };
        if be_u64(&feedback.0, 28) == 4 {
            live = Some(feedback);
            break;
        }
    }
    let live = live.expect("actual current-window feedback");
    // Window zero has expired, while window four still has transit slack.
    sender.pump_fec(110_000_000, &[(PRIMARY_GROUP, view(514_000_000))], &cancel);
    sender
        .port
        .control
        .push_back((old.0.to_vec(), Some(addr(42001))));
    sender
        .port
        .control
        .push_back((live.0.to_vec(), Some(addr(42001))));
    sender.pump(110_000_001);
    assert!(sender.peer_view(7).unwrap().fec_feedback_pending);
    assert_eq!(sender.stats().fec_feedback_overflow, 0);
    assert_eq!(
        sender
            .pump_fec(110_000_002, &[(PRIMARY_GROUP, view(515_000_000))], &cancel)
            .media_sent,
        1
    );
    let repair = &sender.port.sent.last().unwrap().1;
    assert_eq!((be_u64(repair, 28), repair[72], repair[73]), (4, 0, 1));
    // Advance the real N04 cursor through prior cutoffs before the repair arrives.
    for block in 0..4 {
        let cutoff = playout::consume_by(
            500_000_000 + playout::frames_to_ns(block * 256),
            1_000_000,
            1_000_000,
            500_000,
        );
        assert!(matches!(
            live_receiver.decide(&mut live_engine, view(cutoff), &mut [0; fec::BYTES]),
            playout::Poll::Decision(_)
        ));
    }
    assert_eq!(
        live_receiver
            .ingest(&mut live_engine, view(516_000_000), repair)
            .unwrap()
            .admission,
        Some(playout::Admission::Admitted)
    );
    for block in 4..16 {
        let cutoff = playout::consume_by(
            500_000_000 + playout::frames_to_ns(block * 256),
            1_000_000,
            1_000_000,
            500_000,
        );
        assert!(matches!(
            live_receiver.decide(&mut live_engine, view(cutoff), &mut [0; fec::BYTES]),
            playout::Poll::Decision(_)
        ));
    }
    let cutoff = playout::consume_by(
        500_000_000 + playout::frames_to_ns(16 * 256),
        1_000_000,
        1_000_000,
        500_000,
    );
    let mut out = [0; fec::BYTES];
    let playout::Poll::Decision(decision) =
        live_receiver.decide(&mut live_engine, view(cutoff), &mut out)
    else {
        panic!("missing live-window decision");
    };
    assert_eq!(decision.outcome, playout::Outcome::Real);
    assert_eq!(out, samples()[0]);
}

fn assert_held_live_alias_quotas() {
    let cfg = config(2);
    let source = samples();
    let make = |window, esi| {
        let digest = fec::content_digest(&cfg.metadata(window).unwrap(), &source);
        fec::sign_symbol(
            &cfg,
            window,
            esi,
            0,
            digest,
            &fec::encode_symbol(&source, esi).unwrap(),
        )
        .unwrap()
    };
    let mut receiver = fec::Receiver::new(cfg.clone()).unwrap();
    let mut engine = playout::PlayoutEngine::new(
        playout::PlayoutProfile::MUSIC,
        playout::PlayoutConfig {
            work_ns: 1_000_000,
            lead_ns: 1_000_000,
            tolerance_ns: 0,
        },
    )
    .unwrap();
    engine.begin_stream(2, 0, 500_000_000).unwrap();
    receiver
        .ingest(&mut engine, view(20_000_000), &make(0, 1))
        .unwrap();
    let mut old = make(0, 0);
    let mut future = make(8, 0);
    old[fec::DATAGRAM - 1] ^= 1;
    future[fec::DATAGRAM - 1] ^= 1;
    for attempt in 0..3 {
        let expected = if attempt < 2 {
            fec::Refusal::Authentication
        } else {
            fec::Refusal::Storm
        };
        assert_eq!(
            receiver.ingest(&mut engine, view(160_000_000), &old),
            Err(expected)
        );
        assert_eq!(
            receiver.ingest(&mut engine, view(160_000_000), &future),
            Err(expected)
        );
    }
    assert_eq!(receiver.status().windows[0].window, Some(0));
    assert_eq!(receiver.status().windows[0].authenticated_mask, 2);
    assert!(receiver.status().charged_work * fec::WORK_UNIT_NS <= fec::WINDOW_ALLOWANCE_NS);
    assert_eq!(
        receiver
            .ingest(&mut engine, view(160_000_000), &make(0, 2))
            .unwrap()
            .admission,
        Some(playout::Admission::Admitted)
    );
    for (index, expected) in source.iter().enumerate().take(3) {
        let cutoff = playout::consume_by(
            500_000_000 + playout::frames_to_ns(index as u64 * 256),
            1_000_000,
            1_000_000,
            500_000,
        );
        let mut out = [0; fec::BYTES];
        let playout::Poll::Decision(decision) =
            receiver.decide(&mut engine, view(cutoff), &mut out)
        else {
            panic!("missing decision");
        };
        if index == 0 {
            assert_ne!(decision.outcome, playout::Outcome::Real);
        } else {
            assert_eq!(decision.outcome, playout::Outcome::Real);
            assert_eq!(&out, expected);
        }
    }
}

fn two_target_bindings() -> [TargetFecBinding; 2] {
    let a = config(2);
    let mut b = config(2);
    b.stream = StreamId::new(stream().get() + 1).unwrap();
    b.key = StreamKey::from_bytes([0x77; 32]);
    [
        TargetFecBinding {
            peer_id: 7,
            config: a,
        },
        TargetFecBinding {
            peer_id: 8,
            config: b,
        },
    ]
}

fn two_target_sender() -> CarrierSender<Port> {
    let mut sender = sender(generous());
    sender.add_peer(8, addr(42100), addr(42101), 1500).unwrap();
    sender
}

fn target_engine() -> playout::PlayoutEngine {
    let mut engine = playout::PlayoutEngine::new(
        playout::PlayoutProfile::MUSIC,
        playout::PlayoutConfig {
            work_ns: 1_000_000,
            lead_ns: 1_000_000,
            tolerance_ns: 0,
        },
    )
    .unwrap();
    engine.begin_stream(2, 0, 500_000_000).unwrap();
    engine
}

#[test]
fn n06_target_sender_delivers_two_distinct_streams_and_repairs_actual_pcm() {
    let mut sender = two_target_sender();
    let bindings = two_target_bindings();
    sender
        .select_group_target_fec(PRIMARY_GROUP, 2, 500_000_000, &bindings, 2 * 1024 * 1024)
        .unwrap();
    assert!(matches!(
        sender.add_group(key(), bindings[1].config.stream, 2),
        Err(CarrierError::StreamIdInUse(_))
    ));
    let source = samples();
    assert_eq!(
        sender
            .submit_group_fec_window(PRIMARY_GROUP, 2, 0, source, 0)
            .unwrap()
            .queued,
        16
    );
    assert!(
        sender.fec_retained_bytes()
            >= 2 * fec::WINDOWS * std::mem::size_of::<(u64, fec::SenderWindow)>()
    );
    let cancel = AtomicBool::new(false);
    assert_eq!(
        sender
            .pump_fec(1, &[(PRIMARY_GROUP, view(20_000_000))], &cancel)
            .media_sent,
        16
    );
    let initial = sender.port.sent.clone();
    assert_eq!(
        initial
            .iter()
            .filter(|(_, _, dest)| *dest == addr(42000))
            .count(),
        8
    );
    assert_eq!(
        initial
            .iter()
            .filter(|(_, _, dest)| *dest == addr(42100))
            .count(),
        8
    );
    let mut receiver_a = fec::Receiver::new(bindings[0].config.clone()).unwrap();
    let mut receiver_b = fec::Receiver::new(bindings[1].config.clone()).unwrap();
    let mut engine_a = target_engine();
    let mut engine_b = target_engine();
    let a_wire = &initial
        .iter()
        .find(|(_, wire, dest)| *dest == addr(42000) && wire[72] == 0)
        .unwrap()
        .1;
    let mut probe_a = fec::Receiver::new(bindings[0].config.clone()).unwrap();
    let mut probe_b = fec::Receiver::new(bindings[1].config.clone()).unwrap();
    let mut probe_engine_a = target_engine();
    let mut probe_engine_b = target_engine();
    assert!(matches!(
        probe_b.ingest(&mut probe_engine_b, view(20_000_000), a_wire),
        Err(fec::Refusal::Authentication)
    ));
    let mut wrong_key = bindings[0].config.clone();
    wrong_key.key = bindings[1].config.key.clone();
    let digest = fec::content_digest(&wrong_key.metadata(0).unwrap(), &source);
    let bad = fec::sign_symbol(&wrong_key, 0, 0, 0, digest, &source[0]).unwrap();
    assert!(matches!(
        probe_a.ingest(&mut probe_engine_a, view(20_000_000), &bad),
        Err(fec::Refusal::Authentication)
    ));
    let mut wrong_stream = bindings[0].config.clone();
    wrong_stream.stream = bindings[1].config.stream;
    let digest = fec::content_digest(&wrong_stream.metadata(0).unwrap(), &source);
    let bad_stream = fec::sign_symbol(&wrong_stream, 0, 0, 0, digest, &source[0]).unwrap();
    assert!(matches!(
        probe_a.ingest(&mut probe_engine_a, view(20_000_000), &bad_stream),
        Err(fec::Refusal::Identity)
    ));
    for (_, wire, dest) in &initial {
        if wire[72] < 3 && *dest == addr(42000) {
            receiver_a
                .ingest(&mut engine_a, view(20_000_000), wire)
                .unwrap();
        } else if wire[72] < 3 && *dest == addr(42100) {
            receiver_b
                .ingest(&mut engine_b, view(20_000_000), wire)
                .unwrap();
        }
    }
    assert_eq!(
        receiver_a
            .poll(&mut engine_a, view(80_000_000), &cancel)
            .unwrap(),
        fec::DecodeState::Idle
    );
    assert_eq!(
        receiver_b
            .poll(&mut engine_b, view(80_000_000), &cancel)
            .unwrap(),
        fec::DecodeState::Idle
    );
    let feedback_a = receiver_a
        .feedback(&engine_a, view(80_000_000))
        .unwrap()
        .unwrap();
    let feedback_b = receiver_b
        .feedback(&engine_b, view(80_000_000))
        .unwrap()
        .unwrap();
    // A correctly signed report from the wrong peer/stream cannot be re-routed.
    sender
        .port
        .control
        .push_back((feedback_a.0.to_vec(), Some(addr(42101))));
    sender
        .port
        .control
        .push_back((feedback_b.0.to_vec(), Some(addr(42001))));
    let mut wrong_key = feedback_a.0;
    wrong_key[95] ^= 1;
    sender
        .port
        .control
        .push_back((wrong_key.to_vec(), Some(addr(42001))));
    sender
        .port
        .control
        .push_back((feedback_a.0.to_vec(), Some(addr(42001))));
    sender
        .port
        .control
        .push_back((feedback_b.0.to_vec(), Some(addr(42101))));
    let initial_len = sender.port.sent.len();
    let result = sender.pump_fec(21_333_334, &[(PRIMARY_GROUP, view(100_000_000))], &cancel);
    assert_eq!(result.media_sent, 2);
    let repairs = &sender.port.sent[initial_len..];
    assert_eq!(repairs.len(), 2);
    for (_, wire, dest) in repairs {
        assert_eq!((wire[72], wire[73]), (3, 1));
        if *dest == addr(42000) {
            receiver_a
                .ingest(&mut engine_a, view(105_000_000), wire)
                .unwrap();
        } else {
            assert_eq!(*dest, addr(42100));
            receiver_b
                .ingest(&mut engine_b, view(105_000_000), wire)
                .unwrap();
        }
    }
    assert_eq!(
        sender.peer_view(7).unwrap().counters.fec_feedback_accepted,
        1
    );
    assert_eq!(
        sender.peer_view(8).unwrap().counters.fec_feedback_accepted,
        1
    );
    assert!(sender.stats().fec_feedback_refused >= 3);
    let before_refused = sender.stats().fec_feedback_refused;
    let before_peer = sender.peer_view(7).unwrap().counters.fec_feedback_refused;
    sender
        .port
        .control
        .push_back((feedback_a.0.to_vec(), Some(addr(42001))));
    let mut stale_epoch = feedback_b.0;
    stale_epoch[27] = 3;
    sender
        .port
        .control
        .push_back((stale_epoch.to_vec(), Some(addr(42101))));
    assert_eq!(
        sender
            .pump_fec(21_333_335, &[(PRIMARY_GROUP, view(110_000_000))], &cancel)
            .media_sent,
        0
    );
    assert_eq!(sender.stats().fec_feedback_refused, before_refused + 2);
    assert_eq!(
        sender.peer_view(7).unwrap().counters.fec_feedback_refused,
        before_peer + 1
    );
    for (receiver, engine) in [
        (&mut receiver_a, &mut engine_a),
        (&mut receiver_b, &mut engine_b),
    ] {
        for (i, expected) in source.iter().enumerate() {
            let presentation = 500_000_000 + playout::frames_to_ns(i as u64 * 256);
            let cutoff = playout::consume_by(presentation, 1_000_000, 1_000_000, 500_000);
            let mut out = [0; fec::BYTES];
            let playout::Poll::Decision(decision) = receiver.decide(engine, view(cutoff), &mut out)
            else {
                panic!("missing target PCM decision");
            };
            assert_eq!(decision.outcome, playout::Outcome::Real);
            assert_eq!(&out, expected);
        }
    }
}

#[test]
fn n06_target_selection_rejects_invalid_bindings_and_keeps_n01_live() {
    let mut sender = two_target_sender();
    let valid = two_target_bindings();
    let before = sender.group_view(PRIMARY_GROUP).unwrap();
    let mut wrong = valid.clone();
    wrong[1].peer_id = wrong[0].peer_id;
    assert!(
        sender
            .select_group_target_fec(PRIMARY_GROUP, 2, 500_000_000, &wrong, usize::MAX)
            .is_err()
    );
    wrong = valid.clone();
    wrong[1].config.stream = wrong[0].config.stream;
    assert!(
        sender
            .select_group_target_fec(PRIMARY_GROUP, 2, 500_000_000, &wrong, usize::MAX)
            .is_err()
    );
    wrong = valid.clone();
    wrong[1].config.epoch = 3;
    assert!(
        sender
            .select_group_target_fec(PRIMARY_GROUP, 2, 500_000_000, &wrong, usize::MAX)
            .is_err()
    );
    wrong = valid.clone();
    wrong[1].config.presentation_origin_ns += 1;
    assert!(
        sender
            .select_group_target_fec(PRIMARY_GROUP, 2, 500_000_000, &wrong, usize::MAX)
            .is_err()
    );
    assert!(
        sender
            .select_group_target_fec(PRIMARY_GROUP, 3, 500_000_000, &valid, usize::MAX)
            .is_err()
    );
    assert!(
        sender
            .select_group_target_fec(PRIMARY_GROUP, 2, 500_000_000, &valid, 1)
            .is_err()
    );
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before);
    assert_eq!(sender.fec_retained_bytes(), 0);
    let target_work = std::hint::black_box(FEC_TARGET_WORK);
    assert!(target_work * 2 <= fec::WINDOW_ALLOWANCE_NS / fec::WORK_UNIT_NS);
    assert!(target_work * 3 > fec::WINDOW_ALLOWANCE_NS / fec::WORK_UNIT_NS);
    let mut excess = two_target_sender();
    excess.add_peer(9, addr(42200), addr(42201), 1500).unwrap();
    let mut third = valid[0].clone();
    third.peer_id = 9;
    third.config.stream = StreamId::new(stream().get() + 2).unwrap();
    let three = [valid[0].clone(), valid[1].clone(), third];
    assert!(matches!(
        excess.select_group_target_fec(PRIMARY_GROUP, 2, 500_000_000, &three, usize::MAX),
        Err(CarrierError::InvalidLimits("per-target FEC work cap"))
    ));
    assert_eq!(excess.epoch(), 1);
    let frame = OutboundFrame::media(0, 500_000_000, 497_500_000, vec![0x37; 1024]);
    assert_eq!(sender.submit_media(1, &frame, 0).unwrap().queued, 2);
    assert_eq!(sender.pump(1).media_sent, 2);
    for (_, wire, _) in &sender.port.sent {
        let mut receiver = crate::StreamReceiver::new(key(), stream(), 1);
        assert_eq!(receiver.accept(wire).unwrap().payload, vec![0x37; 1024]);
    }
    sender
        .select_group_target_fec(PRIMARY_GROUP, 2, 500_000_000, &valid, 2 * 1024 * 1024)
        .unwrap();
    assert_eq!(
        sender.group_view(PRIMARY_GROUP).unwrap().selected_strategy,
        fec::PROFILE
    );
}

#[test]
fn n06_target_sender_bounds_work_and_fences_restart_and_cancellation() {
    let mut sender = two_target_sender();
    let bindings = two_target_bindings();
    sender
        .select_group_target_fec(PRIMARY_GROUP, 2, 500_000_000, &bindings, 2 * 1024 * 1024)
        .unwrap();
    assert_eq!(
        sender
            .submit_group_fec_window(PRIMARY_GROUP, 2, 0, samples(), 0)
            .unwrap()
            .queued,
        16
    );
    let queued = sender.group_view(PRIMARY_GROUP).unwrap();
    assert!(
        sender
            .submit_group_fec_window(PRIMARY_GROUP, 2, 0, samples(), 0)
            .is_err()
    );
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), queued);
    assert!(
        sender
            .submit_group_fec_window(PRIMARY_GROUP, 2, 1, samples(), 0)
            .is_err()
    );
    assert!(sender.fec_work_charged() <= fec::WINDOW_ALLOWANCE_NS / fec::WORK_UNIT_NS);
    let cancel = AtomicBool::new(true);
    assert_eq!(
        sender
            .pump_fec(1, &[(PRIMARY_GROUP, view(20_000_000))], &cancel)
            .media_sent,
        0
    );
    assert_eq!(sender.fec_retained_bytes(), 0);
    assert_eq!(
        sender.group_view(PRIMARY_GROUP).unwrap().selected_strategy,
        "transition-required"
    );
    assert!(
        sender
            .submit_group_fec_window(PRIMARY_GROUP, 2, 1, samples(), 0)
            .is_err()
    );
    sender
        .restart_group(
            PRIMARY_GROUP,
            StreamId::new(stream().get() + 10).unwrap(),
            3,
        )
        .unwrap();
    assert_eq!(
        sender.group_view(PRIMARY_GROUP).unwrap().selected_strategy,
        "n01"
    );
    assert!(
        sender
            .submit_group_fec_window(PRIMARY_GROUP, 2, 0, samples(), 0)
            .is_err()
    );
    let frame = OutboundFrame::media(0, 500_000_000, 497_500_000, vec![0x37; 1024]);
    assert_eq!(sender.submit_media(3, &frame, 0).unwrap().queued, 2);

    let mut stale = two_target_sender();
    stale
        .select_group_target_fec(PRIMARY_GROUP, 2, 500_000_000, &bindings, 2 * 1024 * 1024)
        .unwrap();
    stale
        .submit_group_fec_window(PRIMARY_GROUP, 2, 0, samples(), 0)
        .unwrap();
    assert_eq!(
        stale
            .pump_fec(
                1,
                &[(PRIMARY_GROUP, view(100_000_000))],
                &AtomicBool::new(false)
            )
            .media_sent,
        16
    );
    stale
        .submit_group_fec_window(PRIMARY_GROUP, 2, 1, samples(), 21_333_334)
        .unwrap();
    assert_eq!(
        stale
            .pump_fec(
                21_333_335,
                &[(PRIMARY_GROUP, view(90_000_000))],
                &AtomicBool::new(false)
            )
            .media_sent,
        0
    );
    assert_eq!(
        stale.group_view(PRIMARY_GROUP).unwrap().selected_strategy,
        "transition-required"
    );
    assert_eq!(
        stale
            .pump_fec(
                21_333_336,
                &[(PRIMARY_GROUP, view(110_000_000))],
                &AtomicBool::new(false)
            )
            .media_sent,
        0
    );
}

#[test]
fn n06_missing_feedback_window_counts_refusal_then_repairs_in_both_modes() {
    for targeted in [false, true] {
        let mut sender = sender(generous());
        let bindings = two_target_bindings();
        if targeted {
            sender
                .select_group_target_fec(
                    PRIMARY_GROUP,
                    2,
                    500_000_000,
                    &bindings[..1],
                    2 * 1024 * 1024,
                )
                .unwrap();
        } else {
            sender
                .select_group_fec(PRIMARY_GROUP, 2, 500_000_000, &[7])
                .unwrap();
        }
        let source = samples();
        assert_eq!(
            sender
                .submit_group_fec_window(PRIMARY_GROUP, 2, 0, source, 0)
                .unwrap()
                .queued,
            8
        );
        let cancel = AtomicBool::new(false);
        assert_eq!(
            sender
                .pump_fec(1, &[(PRIMARY_GROUP, view(20_000_000))], &cancel)
                .media_sent,
            8
        );
        let mut receiver = fec::Receiver::new(config(2)).unwrap();
        let mut engine = target_engine();
        for (_, wire, _) in &sender.port.sent {
            if wire[72] < 3 {
                receiver
                    .ingest(&mut engine, view(20_000_000), wire)
                    .unwrap();
            }
        }
        assert_eq!(
            receiver
                .poll(&mut engine, view(80_000_000), &cancel)
                .unwrap(),
            fec::DecodeState::Idle
        );
        let feedback = receiver
            .feedback(&engine, view(80_000_000))
            .unwrap()
            .unwrap();
        let mut absent = feedback.0;
        absent[28..36].copy_from_slice(&5_u64.to_be_bytes());
        let before_group = sender.stats().fec_feedback_refused;
        let before_peer = sender.peer_view(7).unwrap().counters.fec_feedback_refused;
        sender
            .port
            .control
            .push_back((absent.to_vec(), Some(addr(42001))));
        sender
            .port
            .control
            .push_back((feedback.0.to_vec(), Some(addr(42001))));
        let before_sent = sender.port.sent.len();
        assert_eq!(
            sender
                .pump_fec(21_333_334, &[(PRIMARY_GROUP, view(100_000_000))], &cancel)
                .media_sent,
            1
        );
        assert_eq!(sender.stats().fec_feedback_refused, before_group + 1);
        assert_eq!(
            sender.peer_view(7).unwrap().counters.fec_feedback_refused,
            before_peer + 1
        );
        assert_eq!(
            sender.peer_view(7).unwrap().counters.fec_feedback_accepted,
            1
        );
        let repair = &sender.port.sent[before_sent].1;
        assert_eq!((repair[72], repair[73]), (3, 1));
        receiver
            .ingest(&mut engine, view(105_000_000), repair)
            .unwrap();
        for (i, expected) in source.iter().enumerate() {
            let presentation = 500_000_000 + playout::frames_to_ns(i as u64 * 256);
            let cutoff = playout::consume_by(presentation, 1_000_000, 1_000_000, 500_000);
            let mut out = [0; fec::BYTES];
            let playout::Poll::Decision(decision) =
                receiver.decide(&mut engine, view(cutoff), &mut out)
            else {
                panic!("missing repaired PCM");
            };
            assert_eq!(decision.outcome, playout::Outcome::Real);
            assert_eq!(&out, expected);
        }
    }
}

#[test]
fn n06_target_exact_capacity_accepts_two_and_one_byte_less_preserves_n01() {
    let bindings = two_target_bindings();
    let mut probe = two_target_sender();
    probe
        .select_group_target_fec(PRIMARY_GROUP, 2, 500_000_000, &bindings, usize::MAX)
        .unwrap();
    let exact = probe
        .fec_retained_bytes()
        .checked_add(FEC_TARGET_SCRATCH_BYTES)
        .unwrap();
    assert!(exact > FEC_TARGET_SCRATCH_BYTES);
    let mut sender = two_target_sender();
    let before = sender.group_view(PRIMARY_GROUP).unwrap();
    assert!(matches!(
        sender.select_group_target_fec(PRIMARY_GROUP, 2, 500_000_000, &bindings, exact - 1),
        Err(CarrierError::InvalidLimits("target FEC memory cap"))
    ));
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before);
    assert_eq!(sender.fec_retained_bytes(), 0);
    sender
        .select_group_target_fec(PRIMARY_GROUP, 2, 500_000_000, &bindings, exact)
        .unwrap();
    assert_eq!(
        sender.fec_retained_bytes() + FEC_TARGET_SCRATCH_BYTES,
        exact
    );
    assert_eq!(
        sender
            .submit_group_fec_window(PRIMARY_GROUP, 2, 0, samples(), 0)
            .unwrap()
            .queued,
        16
    );
    assert_eq!(
        sender
            .pump_fec(
                1,
                &[(PRIMARY_GROUP, view(20_000_000))],
                &AtomicBool::new(false)
            )
            .media_sent,
        16
    );
}
