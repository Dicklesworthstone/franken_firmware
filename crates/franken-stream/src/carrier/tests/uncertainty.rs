//! The selected N01 pump's conservative presentation horizon.

use super::*;

const P: u64 = 4_000_000_000;
const GROUP_NOW: u64 = 1_000;
const UNCERTAINTY: u64 = 100;
const LOWER: u64 = GROUP_NOW - UNCERTAINTY;

fn clock(group_ns: u64, uncertainty_ns: u64) -> N01GroupClock {
    N01GroupClock {
        group: PRIMARY_GROUP,
        epoch: 1,
        view: crate::playout::ClockView {
            group_ns,
            uncertainty_ns,
            usable: true,
        },
    }
}

fn rig(ids: &[u32]) -> (CarrierSender<ScriptPort>, N01GroupSnapshot) {
    let limits = CarrierLimits {
        window_packets: 1,
        pace_burst_bytes: 65_536,
        ..CarrierLimits::baseline()
    };
    let mut sender =
        CarrierSender::with_port(key(), stream(), 1, limits, ScriptPort::new()).unwrap();
    for id in ids {
        let (media, control) = match id {
            7 => ("127.0.0.1:42001", "127.0.0.1:42002"),
            8 => ("127.0.0.1:42011", "127.0.0.1:42012"),
            _ => panic!("unexpected test peer"),
        };
        sender
            .add_peer(*id, addr(media), addr(control), 1500)
            .unwrap();
    }
    let claim = sender.claim_n01_source(PRIMARY_GROUP, 1, ids).unwrap();
    (sender, claim)
}

fn frame(index: u64, presentation: u64, deadline: u64) -> OutboundFrame {
    OutboundFrame::media(
        index * 256,
        presentation,
        deadline,
        vec![0x11; MAX_PAYLOAD_BYTES],
    )
}

fn submit(
    sender: &mut CarrierSender<ScriptPort>,
    claim: &N01GroupSnapshot,
    ids: &[u32],
    frame: &OutboundFrame,
    now: u64,
    buffered: bool,
) {
    let cancel = AtomicBool::new(false);
    let inputs = N01AdmissionInputs {
        interface_now_ns: now,
        trusted_group_now_ns: GROUP_NOW,
        overlap_budget_bytes: usize::MAX,
        cancelled: &cancel,
    };
    let result = if buffered {
        sender.try_submit_group_media_buffered_isolated(PRIMARY_GROUP, 1, claim, ids, frame, inputs)
    } else {
        sender.try_submit_group_media_isolated(PRIMARY_GROUP, 1, claim, ids, frame, inputs)
    };
    assert_eq!(result.unwrap().status, N01IsolatedStatus::Published);
}

fn report(sender: &mut CarrierSender<ScriptPort>, receiver: &mut CarrierReceiver<ScriptPort>) {
    sender
        .port
        .inbound_control
        .push_back((report_of(receiver), None));
    assert_eq!(sender.poll_reports(), 1);
}

#[test]
fn n01_lookahead_queued_head_waits_until_conservative_equality() {
    let (mut sender, claim) = rig(&[7]);
    let cancel = AtomicBool::new(false);
    let frame = frame(0, P, 2_000_000_000);
    submit(&mut sender, &claim, &[7], &frame, 0, false);
    let before = view(&sender, 7);
    let early = sender
        .pump_n01_selected_with_lookahead(
            1,
            clock(GROUP_NOW, UNCERTAINTY),
            &claim,
            P - LOWER - 1,
            &cancel,
        )
        .unwrap();
    assert_eq!(early.media_sent, 0);
    assert_eq!(view(&sender, 7), before);
    assert!(sender.port.sent.is_empty());
    let due = sender
        .pump_n01_selected_with_lookahead(
            2,
            clock(GROUP_NOW, UNCERTAINTY),
            &claim,
            P - LOWER,
            &cancel,
        )
        .unwrap();
    assert_eq!(due.media_sent, 1);
    let mut receiver = StreamReceiver::new(key(), stream(), 1);
    let packet = receiver.accept(&sender.port.sent[0].1).unwrap();
    assert_eq!((packet.seq, packet.presentation_time_ns), (0, P));
    assert_eq!(packet.payload, frame.payload);
    assert_eq!(view(&sender, 7).sent_next, 1);
}

#[test]
fn n01_lookahead_allows_older_peer_while_future_peer_waits() {
    let (mut sender, claim) = rig(&[7, 8]);
    let cancel = AtomicBool::new(false);
    let c = clock(GROUP_NOW, UNCERTAINTY);
    let mut slow = real_receiver();
    let mut fast = real_receiver().with_peer_id(8).unwrap();
    submit(
        &mut sender,
        &claim,
        &[7, 8],
        &frame(0, P, 2_000_000_000),
        0,
        false,
    );
    assert_eq!(
        sender
            .pump_n01_selected_with_lookahead(1, c, &claim, P - LOWER, &cancel)
            .unwrap()
            .media_sent,
        2
    );
    let slow_wire = sender
        .port
        .sent
        .iter()
        .find(|x| x.2 == addr("127.0.0.1:42001"))
        .unwrap()
        .1
        .clone();
    let fast_wire = sender
        .port
        .sent
        .iter()
        .find(|x| x.2 == addr("127.0.0.1:42011"))
        .unwrap()
        .1
        .clone();
    assert_eq!(deliver(&mut slow, &[slow_wire]).len(), 1);
    assert_eq!(deliver(&mut fast, &[fast_wire]).len(), 1);
    report(&mut sender, &mut fast);
    submit(
        &mut sender,
        &claim,
        &[7, 8],
        &frame(1, P + 100, 2_000_000_000),
        2,
        true,
    );
    assert_eq!(
        sender
            .pump_n01_selected_with_lookahead(3, c, &claim, P + 100 - LOWER, &cancel)
            .unwrap()
            .media_sent,
        1
    );
    let fast_b = sender.port.sent.last().unwrap().1.clone();
    assert_eq!(deliver(&mut fast, &[fast_b]).len(), 1);
    report(&mut sender, &mut fast);
    submit(
        &mut sender,
        &claim,
        &[7, 8],
        &frame(2, P + 200, 2_000_000_000),
        4,
        false,
    );
    report(&mut sender, &mut slow);
    let fast_before = view(&sender, 8);
    let sent_before = sender.port.sent.len();
    assert_eq!(
        sender
            .pump_n01_selected_with_lookahead(5, c, &claim, P + 100 - LOWER, &cancel)
            .unwrap()
            .media_sent,
        1
    );
    assert_eq!(sender.port.sent.len(), sent_before + 1);
    assert_eq!(sender.port.sent.last().unwrap().2, addr("127.0.0.1:42001"));
    let old = deliver(
        &mut slow,
        std::slice::from_ref(&sender.port.sent.last().unwrap().1),
    );
    assert_eq!((old[0].seq, old[0].presentation_time_ns), (1, P + 100));
    assert_eq!(view(&sender, 8), fast_before);
    assert_eq!(
        sender
            .pump_n01_selected_with_lookahead(6, c, &claim, P + 200 - LOWER, &cancel)
            .unwrap()
            .media_sent,
        1
    );
    let next = deliver(
        &mut fast,
        std::slice::from_ref(&sender.port.sent.last().unwrap().1),
    );
    assert_eq!((next[0].seq, next[0].presentation_time_ns), (2, P + 200));
}

#[test]
fn n01_lookahead_preserves_signed_would_block_retry() {
    let (mut sender, claim) = rig(&[7]);
    let cancel = AtomicBool::new(false);
    let c = clock(GROUP_NOW, UNCERTAINTY);
    submit(
        &mut sender,
        &claim,
        &[7],
        &frame(0, P, 2_000_000_000),
        0,
        false,
    );
    sender.port.send_fault = Some(PortFault::WouldBlock);
    assert_eq!(
        sender
            .pump_n01_selected_with_lookahead(1, c, &claim, P - LOWER, &cancel)
            .unwrap()
            .media_sent,
        0
    );
    let held = sender.peers[0].held.as_ref().expect("signed datagram held");
    let original = held.wire.clone();
    assert_eq!((held.seq, held.attempts), (0, 1));
    sender.port.send_fault = None;
    let before = view(&sender, 7);
    assert_eq!(
        sender
            .pump_n01_selected_with_lookahead(2, c, &claim, P - LOWER - 1, &cancel)
            .unwrap()
            .media_sent,
        0
    );
    assert_eq!(view(&sender, 7), before);
    let held = sender.peers[0].held.as_ref().unwrap();
    assert_eq!((held.seq, held.attempts), (0, 1));
    assert_eq!(held.wire, original);
    assert!(sender.port.sent.is_empty());
    assert_eq!(
        sender
            .pump_n01_selected_with_lookahead(3, c, &claim, P - LOWER, &cancel)
            .unwrap()
            .media_sent,
        1
    );
    assert_eq!(sender.port.sent[0].1, original);
    let mut receiver = StreamReceiver::new(key(), stream(), 1);
    assert_eq!(receiver.accept(&original).unwrap().seq, 0);
    assert_eq!(view(&sender, 7).sent_next, 1);
}

#[test]
fn n01_lookahead_probe_obeys_horizon_credit_and_cancel_but_keeps_late_exception() {
    let (mut sender, claim) = rig(&[7]);
    let cancel = AtomicBool::new(false);
    submit(
        &mut sender,
        &claim,
        &[7],
        &frame(0, P, 2_000_000_000),
        0,
        false,
    );
    submit(
        &mut sender,
        &claim,
        &[7],
        &frame(1, P + 1_000, 3_000_000_000),
        0,
        false,
    );
    assert_eq!(
        sender
            .pump_n01_selected_with_lookahead(
                1,
                clock(GROUP_NOW, UNCERTAINTY),
                &claim,
                P - LOWER,
                &cancel
            )
            .unwrap()
            .media_sent,
        1
    );
    let original = sender.port.sent[0].1.clone();
    let mut receiver = real_receiver();
    assert_eq!(
        deliver(&mut receiver, std::slice::from_ref(&original)).len(),
        1
    );
    let now = STALL_PROBE_NS + 2;
    let late_group = 2_000_000_001;
    let lower = late_group - UNCERTAINTY;
    let c = clock(late_group, UNCERTAINTY);
    let mut expected = view(&sender, 7);
    expected.counters.window_stalled_pumps += 1;
    assert_eq!(
        sender
            .pump_n01_selected_with_lookahead(now, c, &claim, P - lower - 1, &cancel)
            .unwrap()
            .media_sent,
        0
    );
    assert_eq!(sender.port.sent.len(), 1);
    assert_eq!(view(&sender, 7), expected);
    cancel.store(true, Ordering::Release);
    assert!(matches!(
        sender.pump_n01_selected_with_lookahead(now + 1, c, &claim, P - lower, &cancel),
        Err(AllPeerAdmissionError::Cancelled)
    ));
    assert_eq!(sender.port.sent.len(), 1);
    cancel.store(false, Ordering::Release);
    sender
        .pump_n01_selected_with_lookahead(now + 2, c, &claim, P - lower, &cancel)
        .unwrap();
    assert_eq!(
        sender.port.sent.len(),
        2,
        "late recovery probe remains permitted"
    );
    assert_eq!(sender.port.sent[1].1, original);
    assert!(
        deliver(&mut receiver, std::slice::from_ref(&sender.port.sent[1].1)).is_empty(),
        "probe must not replay PCM"
    );
    assert_eq!(view(&sender, 7).sent_next, 1);
    let valid_report = report_of(&mut receiver);
    let mut bad_report = valid_report.clone();
    *bad_report.last_mut().unwrap() ^= 1;
    sender.port.inbound_control.push_back((bad_report, None));
    assert_eq!(sender.poll_reports(), 0);
    assert_eq!(
        (view(&sender, 7).reported_next, view(&sender, 7).in_flight),
        (0, 1)
    );
    sender.port.inbound_control.push_back((valid_report, None));
    assert_eq!(sender.poll_reports(), 1);
    assert_eq!(
        (view(&sender, 7).reported_next, view(&sender, 7).in_flight),
        (1, 0)
    );
    assert_eq!(
        sender
            .pump_n01_selected_with_lookahead(now + 3, c, &claim, P + 999 - lower, &cancel)
            .unwrap()
            .media_sent,
        0
    );
    assert_eq!(
        sender
            .pump_n01_selected_with_lookahead(now + 4, c, &claim, P + 1_000 - lower, &cancel)
            .unwrap()
            .media_sent,
        1
    );
    let delivered = deliver(
        &mut receiver,
        std::slice::from_ref(&sender.port.sent.last().unwrap().1),
    );
    assert_eq!(
        (delivered[0].seq, delivered[0].presentation_time_ns),
        (1, P + 1_000)
    );
}

#[test]
fn n01_lookahead_keeps_last_sequence_held_even_after_its_deadline() {
    let (mut sender, claim) = rig(&[7]);
    let cancel = AtomicBool::new(false);
    let c = clock(GROUP_NOW, UNCERTAINTY);
    sender.port.send_fault = Some(PortFault::WouldBlock);
    let mut now = 1;
    // Reach the real receiver's sequence budget through the ordinary retry and
    // cooldown path, rather than fabricating a sender sequence or held wire.
    for index in 0..SEQ_AHEAD_LIMIT {
        submit(
            &mut sender,
            &claim,
            &[7],
            &frame(index, P, 2_000_000_000),
            now,
            false,
        );
        for offset in 0..u64::from(SEND_RETRY_ATTEMPTS) {
            sender
                .pump_n01_selected_with_lookahead(now + offset, c, &claim, P - LOWER, &cancel)
                .unwrap();
        }
        now += STALL_PROBE_NS + u64::from(SEND_RETRY_ATTEMPTS);
    }
    assert!(sender.port.sent.is_empty());
    let held = sender.peers[0].held.as_ref().expect("last sequence held");
    assert_eq!(held.seq, SEQ_AHEAD_LIMIT - 1);
    let original = held.wire.clone();
    let late_group = 2_000_000_001;
    let lower = late_group - UNCERTAINTY;
    let late_clock = clock(late_group, UNCERTAINTY);
    sender.port.send_fault = None;
    assert_eq!(
        sender
            .pump_n01_selected_with_lookahead(now, late_clock, &claim, P - lower - 1, &cancel)
            .unwrap()
            .media_sent,
        0
    );
    assert_eq!(sender.peers[0].held.as_ref().unwrap().wire, original);
    assert_eq!(
        sender
            .pump_n01_selected_with_lookahead(now + 1, late_clock, &claim, P - lower, &cancel)
            .unwrap()
            .media_sent,
        1
    );
    assert_eq!(sender.port.sent[0].1, original);
    let mut receiver = real_receiver();
    let packets = deliver(&mut receiver, &[original]);
    assert_eq!(packets[0].seq, SEQ_AHEAD_LIMIT - 1);
    report(&mut sender, &mut receiver);
    assert_eq!(view(&sender, 7).reported_next, SEQ_AHEAD_LIMIT);
}

#[test]
fn n01_lookahead_overflow_refuses_without_mutation_and_unbounded_api_remains_compatible() {
    let (mut sender, claim) = rig(&[7]);
    let cancel = AtomicBool::new(false);
    submit(
        &mut sender,
        &claim,
        &[7],
        &frame(0, P, 2_000_000_000),
        0,
        false,
    );
    let before = view(&sender, 7);
    assert!(matches!(
        sender.pump_n01_selected_with_lookahead(1, clock(u64::MAX, 0), &claim, 1, &cancel),
        Err(AllPeerAdmissionError::Invalid(CarrierError::InvalidLimits(
            _
        )))
    ));
    assert_eq!(view(&sender, 7), before);
    assert!(sender.port.sent.is_empty());
    assert_eq!(
        sender
            .pump_n01_selected(2, clock(GROUP_NOW, UNCERTAINTY), &claim, &cancel)
            .unwrap()
            .media_sent,
        1
    );
    let mut receiver = StreamReceiver::new(key(), stream(), 1);
    assert_eq!(receiver.accept(&sender.port.sent[0].1).unwrap().seq, 0);
}

#[test]
fn n01_lookahead_preserves_source_epoch_checks_and_saturates_clock_lower_bound() {
    let (mut sender, claim) = rig(&[7]);
    let (_other_sender, foreign_claim) = rig(&[7]);
    let cancel = AtomicBool::new(false);
    submit(
        &mut sender,
        &claim,
        &[7],
        &frame(0, P, 2_000_000_000),
        0,
        false,
    );
    let before = view(&sender, 7);
    let c = clock(GROUP_NOW, GROUP_NOW + 1);
    assert!(matches!(
        sender.pump_n01_selected_with_lookahead(1, c, &foreign_claim, P, &cancel),
        Err(AllPeerAdmissionError::MembershipChanged)
    ));
    let wrong_epoch = N01GroupClock { epoch: 2, ..c };
    assert!(matches!(
        sender.pump_n01_selected_with_lookahead(1, wrong_epoch, &claim, P, &cancel),
        Err(AllPeerAdmissionError::MembershipChanged)
    ));
    assert_eq!(view(&sender, 7), before);
    assert_eq!(
        sender
            .pump_n01_selected_with_lookahead(1, c, &claim, P - 1, &cancel)
            .unwrap()
            .media_sent,
        0
    );
    assert!(sender.port.sent.is_empty());
    assert_eq!(
        sender
            .pump_n01_selected_with_lookahead(2, c, &claim, P, &cancel)
            .unwrap()
            .media_sent,
        1
    );
    let mut receiver = StreamReceiver::new(key(), stream(), 1);
    assert_eq!(
        receiver
            .accept(&sender.port.sent[0].1)
            .unwrap()
            .presentation_time_ns,
        P
    );
}
