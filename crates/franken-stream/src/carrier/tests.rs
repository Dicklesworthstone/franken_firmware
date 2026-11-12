//! Unit tests of the carrier's pure parts: path sizing, the pacer, the report codec and the limit checks. The socket
//! behaviour is tested over real loopback sockets in `tests/n07_carrier.rs`.

use super::*;

fn key() -> StreamKey {
    StreamKey::from_bytes([0x37; 32])
}

fn stream() -> StreamId {
    StreamId::new(0x0700_0000_0000_0001).expect("nonzero stream id")
}

#[test]
fn n07_payload_sizing_accounts_for_every_header_and_never_exceeds_a_block() {
    // (path MTU, IPv6) -> payload bytes that fit one datagram, in whole frames
    let cases: [(usize, bool, Option<usize>); 11] = [
        (1500, false, Some(1024)),
        (1132, false, Some(1024)), // 1024 + 64 + 16 + 20 + 8 exactly
        (1131, false, Some(1020)), // one byte short of a full block: 1023 bytes of room round down to 1020
        (1108, false, Some(1000)),
        (112, false, Some(4)),
        (111, false, None),
        (0, false, None),
        (1500, true, Some(1024)),
        (1152, true, Some(1024)), // 1024 + 64 + 16 + 40 + 8 exactly
        (1151, true, Some(1020)),
        (131, true, None),
    ];
    for (mtu, ipv6, want) in cases {
        assert_eq!(
            max_payload_for_path_mtu(mtu, ipv6),
            want,
            "mtu {mtu} ipv6 {ipv6}"
        );
    }
    // a path just too small for a block is refused by a carrier that needs the whole block
    let required = MAX_PAYLOAD_BYTES;
    assert!(max_payload_for_path_mtu(1131, false).is_some_and(|n| n < required));
    assert!(max_payload_for_path_mtu(1132, false).is_some_and(|n| n >= required));
}

#[test]
fn n07_the_pacer_starts_full_spends_exactly_and_names_its_next_deadline() {
    let mut pacer = Pacer::new(1_000_000, 4096);
    let cost = 1132u64;
    pacer.refill(10);
    for _ in 0..3 {
        assert!(pacer.can_afford(cost));
        pacer.spend(cost);
    }
    // 4096 - 3 * 1132 = 700 bytes left: one more datagram needs 432 bytes more, 432 microseconds at 1 MB/s
    assert!(!pacer.can_afford(cost));
    assert_eq!(pacer.wait_ns(cost), 432_000);
    pacer.refill(10 + 431_999);
    assert!(
        !pacer.can_afford(cost),
        "one nanosecond early is still early"
    );
    pacer.refill(10 + 432_000);
    assert!(
        pacer.can_afford(cost),
        "the named deadline is the first instant it can"
    );
    // a long stall credits at most the burst, and at most the capped elapsed time
    pacer.refill(10 + 432_000 + 900 * NANOS_PER_SEC);
    assert_eq!(pacer.tokens_nb, pacer.cap_nb);
    let mut paused = Pacer::new(1, 2048);
    paused.refill(0);
    paused.spend(2048);
    paused.refill(900 * NANOS_PER_SEC);
    assert_eq!(
        paused.tokens_nb, MAX_REFILL_ELAPSED_NS,
        "a rate of 1 B/s credits 4 s of elapsed time, no more, as nano-bytes"
    );
}

#[test]
fn n07_a_report_round_trips_and_every_flaw_is_named() {
    let wire = encode_report(&key(), stream(), 7, 41, 0);
    assert_eq!(wire.len(), REPORT_LEN_BYTES);
    assert_eq!(
        parse_report(&key(), &wire),
        Ok(Report {
            stream_id: stream().get(),
            epoch: 7,
            consumed_next: 41,
            peer: 0
        })
    );
    // the permitted positive above; each flaw below changes one thing
    let other = StreamKey::from_bytes([0x38; 32]);
    assert_eq!(parse_report(&other, &wire), Err(ReportError::BadTag));
    // the three peer bytes (5..8) are covered by the tag like every other body byte
    for index in [5usize, 6, 7, 8, 16, 24, 32, 47] {
        let mut tampered = wire;
        tampered[index] ^= 0x01;
        assert_eq!(
            parse_report(&key(), &tampered),
            Err(ReportError::BadTag),
            "byte {index}"
        );
    }
    for index in [0usize, 4] {
        let mut tampered = wire;
        tampered[index] ^= 0x01;
        assert_eq!(
            parse_report(&key(), &tampered),
            Err(ReportError::Malformed),
            "byte {index}"
        );
    }
    assert_eq!(
        parse_report(&key(), &wire[..REPORT_LEN_BYTES - 1]),
        Err(ReportError::Malformed)
    );
    let mut longer = wire.to_vec();
    longer.push(0);
    assert_eq!(parse_report(&key(), &longer), Err(ReportError::Malformed));
    assert_eq!(parse_report(&key(), &[]), Err(ReportError::Malformed));
}

#[test]
fn n07_the_baseline_limits_are_valid_and_each_bound_is_checked() {
    let base = CarrierLimits::baseline();
    assert_eq!(base.validate(), Ok(()));
    let breakages: [(&str, CarrierLimits); 12] = [
        (
            "payload 0",
            CarrierLimits {
                required_payload_bytes: 0,
                ..base.clone()
            },
        ),
        (
            "payload 1026",
            CarrierLimits {
                required_payload_bytes: 1026,
                ..base.clone()
            },
        ),
        (
            "payload not whole frames",
            CarrierLimits {
                required_payload_bytes: 1022,
                ..base.clone()
            },
        ),
        (
            "no peers",
            CarrierLimits {
                max_peers: 0,
                ..base.clone()
            },
        ),
        (
            "pace 0",
            CarrierLimits {
                pace_bytes_per_sec: 0,
                ..base.clone()
            },
        ),
        (
            "pace over 1e9",
            CarrierLimits {
                pace_bytes_per_sec: 1_000_000_001,
                ..base.clone()
            },
        ),
        (
            "burst below a datagram",
            CarrierLimits {
                pace_burst_bytes: 1000,
                ..base.clone()
            },
        ),
        (
            "peer queue of 0",
            CarrierLimits {
                peer_queue_packets: 0,
                ..base.clone()
            },
        ),
        (
            "peer queue bytes below a datagram",
            CarrierLimits {
                peer_queue_bytes: 1000,
                ..base.clone()
            },
        ),
        (
            "aggregate bytes below a datagram",
            CarrierLimits {
                aggregate_queue_bytes: 1000,
                ..base.clone()
            },
        ),
        (
            "window 0",
            CarrierLimits {
                window_packets: 0,
                ..base.clone()
            },
        ),
        (
            "control budget 0",
            CarrierLimits {
                control_per_pump: 0,
                ..base.clone()
            },
        ),
    ];
    for (what, limits) in breakages {
        assert!(
            matches!(limits.validate(), Err(CarrierError::InvalidLimits(_))),
            "{what} must be refused"
        );
    }
}

#[test]
fn n07_addresses_outside_the_declared_profile_are_refused_before_any_socket_is_used() {
    let limits = CarrierLimits::baseline();
    let lan: SocketAddr = "192.0.2.7:9000".parse().expect("address");
    let v6: SocketAddr = "[::1]:9000".parse().expect("address");
    let local: SocketAddr = "127.0.0.1:9000".parse().expect("address");
    assert_eq!(check_address(&limits, local), Ok(()));
    assert_eq!(
        check_address(&limits, lan),
        Err(CarrierError::NotLoopback(lan))
    );
    assert_eq!(
        check_address(&limits, v6),
        Err(CarrierError::UnsupportedAddressFamily(v6))
    );
    let declared = CarrierLimits {
        allow_ipv6: true,
        ..limits
    };
    assert_eq!(
        check_address(&declared, v6),
        Ok(()),
        "a declared family is allowed, still loopback only"
    );
}

// ---- the port seam: an in-memory port, so the carrier's logic runs without a socket ---------------------------------------

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("socket address")
}

/// An in-memory port: it records every send, answers receives from a script and fails sends or rebinds on request. A
/// datagram longer than the caller's buffer is cut to the buffer, which is what the P02 port reports for one.
struct ScriptPort {
    sent: Vec<(Lane, Vec<u8>, SocketAddr)>,
    inbound_control: VecDeque<(Vec<u8>, Option<SocketAddr>)>,
    inbound_media: VecDeque<(Vec<u8>, Option<SocketAddr>)>,
    send_fault: Option<PortFault>,
    rebind_fault: Option<PortFault>,
    /// Faults the next receives answer with, in order, before any queued datagram.
    recv_faults: VecDeque<PortFault>,
    media_local: SocketAddr,
    control_local: SocketAddr,
}

impl ScriptPort {
    fn new() -> Self {
        Self {
            sent: Vec::new(),
            inbound_control: VecDeque::new(),
            inbound_media: VecDeque::new(),
            send_fault: None,
            rebind_fault: None,
            recv_faults: VecDeque::new(),
            media_local: addr("127.0.0.1:41000"),
            control_local: addr("127.0.0.1:41001"),
        }
    }
}

impl DatagramPort for ScriptPort {
    fn send_to(&mut self, lane: Lane, bytes: &[u8], to: SocketAddr) -> Result<(), PortFault> {
        if let Some(fault) = self.send_fault.clone() {
            return Err(fault);
        }
        self.sent.push((lane, bytes.to_vec(), to));
        Ok(())
    }

    fn recv(&mut self, lane: Lane, buf: &mut [u8]) -> Result<Received, PortFault> {
        if let Some(fault) = self.recv_faults.pop_front() {
            return Err(fault);
        }
        let queue = match lane {
            Lane::Media => &mut self.inbound_media,
            Lane::Control => &mut self.inbound_control,
        };
        let Some((bytes, from)) = queue.pop_front() else {
            return Err(PortFault::WouldBlock);
        };
        let len = bytes.len().min(buf.len());
        buf[..len].copy_from_slice(&bytes[..len]);
        Ok(Received { len, from })
    }

    fn local_addr(&self, lane: Lane) -> Result<SocketAddr, PortFault> {
        Ok(match lane {
            Lane::Media => self.media_local,
            Lane::Control => self.control_local,
        })
    }

    fn rebind(&mut self, ip: IpAddr) -> Result<(), PortFault> {
        if let Some(fault) = self.rebind_fault.clone() {
            return Err(fault);
        }
        self.media_local = SocketAddr::new(ip, self.media_local.port() + 10);
        self.control_local = SocketAddr::new(ip, self.control_local.port() + 10);
        Ok(())
    }
}

fn sender_over(port: ScriptPort) -> CarrierSender<ScriptPort> {
    CarrierSender::with_port(key(), stream(), 1, CarrierLimits::baseline(), port)
        .expect("a sender over the script port")
}

/// A full block `index` whose own deadline is two seconds after `now_ns`: long enough that only the pacer and the window decide.
fn long_block(index: u64, now_ns: u64) -> OutboundFrame {
    OutboundFrame::media(
        index * 256,
        now_ns + 4_000_000_000,
        now_ns + 2_000_000_000,
        vec![0x11; MAX_PAYLOAD_BYTES],
    )
}

/// A full block `index` (start frame `256 * index`) whose own deadline is 10 ms after `now_ns`.
fn full_block(index: u64, now_ns: u64) -> OutboundFrame {
    OutboundFrame::media(
        index * 256,
        now_ns + 20_000_000,
        now_ns + 10_000_000,
        vec![0x11; MAX_PAYLOAD_BYTES],
    )
}

#[test]
fn n07_a_sender_over_any_port_signs_with_the_n01_sender_and_the_n01_receiver_admits_it() {
    let media = addr("127.0.0.1:42001");
    let control = addr("127.0.0.1:42002");
    let mut sender = sender_over(ScriptPort::new());
    sender.add_peer(7, media, control, 1500).expect("peer 7");
    sender
        .submit_media(1, &full_block(0, 0), 0)
        .expect("queued");
    sender
        .submit_media(1, &full_block(1, 0), 0)
        .expect("queued");
    assert_eq!(sender.pump(0).media_sent, 2);
    let sent = &sender.port.sent;
    assert_eq!(sent.len(), 2);
    let mut receiver = StreamReceiver::new(key(), stream(), 1);
    for (index, (lane, wire, to)) in sent.iter().enumerate() {
        assert_eq!((*lane, *to), (Lane::Media, media));
        let packet = receiver.accept(wire).expect("the N01 receiver admits it");
        assert_eq!(packet.seq, index as u64, "sequence numbers are dense");
        assert_eq!(packet.start_frame, index as u64 * 256);
        assert_eq!(packet.payload, vec![0x11; MAX_PAYLOAD_BYTES]);
    }
    // conservation, in packets and wire bytes
    let counters = sender.peer_view(7).expect("peer").counters;
    assert_eq!(counters.media_submitted_packets, 2);
    assert_eq!(counters.media_sent_packets, 2);
    assert_eq!(
        counters.media_sent_bytes,
        2 * (WIRE_OVERHEAD_BYTES + MAX_PAYLOAD_BYTES) as u64
    );
}

#[test]
fn n07_a_report_that_names_its_peer_needs_no_source_address_and_an_unnamed_one_is_refused() {
    let media = addr("127.0.0.1:42001");
    let control = addr("127.0.0.1:42002");
    let mut sender = sender_over(ScriptPort::new());
    sender.add_peer(7, media, control, 1500).expect("peer 7");
    sender
        .submit_media(1, &full_block(0, 0), 0)
        .expect("queued");
    sender
        .submit_media(1, &full_block(1, 0), 0)
        .expect("queued");
    assert_eq!(sender.pump(0).media_sent, 2);

    // no peer number and no source address: never guessed
    let unnamed = encode_report(&key(), stream(), 1, 1, 0);
    sender
        .port
        .inbound_control
        .push_back((unnamed.to_vec(), None));
    assert_eq!(sender.poll_reports(), 0);
    assert_eq!(sender.stats().reports_unknown_source, 1);
    assert_eq!(sender.peer_view(7).expect("peer").reported_next, 0);

    // the same position, naming the peer: attributed without a source address
    let named = encode_report(&key(), stream(), 1, 2, 7);
    sender
        .port
        .inbound_control
        .push_back((named.to_vec(), None));
    assert_eq!(sender.poll_reports(), 1);
    assert_eq!(sender.peer_view(7).expect("peer").reported_next, 2);

    // named, but from an address that is not the peer's registered control address: refused
    let wrong = addr("127.0.0.1:42999");
    sender
        .port
        .inbound_control
        .push_back((named.to_vec(), Some(wrong)));
    assert_eq!(sender.poll_reports(), 0);
    assert_eq!(sender.stats().reports_unknown_source, 2);

    // named and from the registered address: the permitted positive
    sender
        .port
        .inbound_control
        .push_back((named.to_vec(), Some(control)));
    assert_eq!(sender.poll_reports(), 1);

    // a number that is no peer's: refused
    let ghost = encode_report(&key(), stream(), 1, 0, 9);
    sender
        .port
        .inbound_control
        .push_back((ghost.to_vec(), None));
    assert_eq!(sender.poll_reports(), 0);
    assert_eq!(sender.stats().reports_unknown_source, 3);
}

#[test]
fn n07_a_send_fault_is_classified_counted_and_a_refused_datagram_is_retried_then_given_up_on() {
    let media = addr("127.0.0.1:42001");
    let control = addr("127.0.0.1:42002");
    let mut port = ScriptPort::new();
    port.send_fault = Some(PortFault::MessageTooLong);
    let mut sender = sender_over(port);
    sender.add_peer(7, media, control, 1500).expect("peer 7");
    sender
        .submit_media(1, &full_block(0, 0), 0)
        .expect("queued");
    assert_eq!(sender.pump(0).media_sent, 0);
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(view.counters.media_dropped_send_error_packets, 1);
    assert_eq!(view.queued_packets, 0, "\"too long\" is not retried");
    assert_eq!(sender.faults().send_message_too_long, 1);
    assert_eq!(sender.faults().send_path_unavailable, 0);
    // "too long" says the path cannot carry a block: the peer is fenced. Number 0 was allocated to that datagram and is spent.
    assert_eq!(view.fence, Some(FenceReason::PathMtuTooSmall));
    assert_eq!((view.sent_next, view.in_flight), (1, 0));
    // the fence is lifted only by the MTU's word; the other faults below are then judged on a carrying path
    assert_eq!(sender.set_path_mtu(7, 1500), Ok(PathOutcome::Carrying));

    // any other fault: the same signed datagram (number 1) is held and tried again at the next pump, not re-signed
    sender.port.send_fault = Some(PortFault::PathUnavailable);
    sender
        .submit_media(1, &full_block(1, 0), 0)
        .expect("queued");
    assert_eq!(sender.pump(1).media_sent, 0);
    assert_eq!(sender.faults().send_path_unavailable, 1);
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(
        (view.fence, view.queued_packets, view.sent_next),
        (None, 1, 2)
    );

    // control faults are counted the same way (and the held datagram's second attempt is at this pump)
    sender.submit_control(7, b"stop").expect("queued control");
    assert_eq!(sender.pump(2).control_sent, 0);
    assert_eq!(sender.faults().send_path_unavailable, 3);
    assert_eq!(
        sender
            .peer_view(7)
            .expect("peer")
            .counters
            .control_dropped_send_error,
        1
    );
    // the third attempt gives up on it: one more number spent, the peer left alone for a full interval
    assert_eq!(sender.pump(3).media_sent, 0);
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(
        (
            view.counters.media_dropped_send_error_packets,
            view.queued_packets
        ),
        (2, 0)
    );

    // the permitted positive: with the fault gone, after the interval, the next block goes under number 2 and
    // no number is ever reused
    sender.port.send_fault = None;
    let later = 3 + STALL_PROBE_NS;
    sender
        .submit_media(1, &full_block(2, later), later)
        .expect("queued");
    assert_eq!(sender.pump(later).media_sent, 1);
    let view = sender.peer_view(7).expect("peer");
    assert_eq!((view.sent_next, view.in_flight), (3, 1));
    let counters = view.counters;
    assert_eq!(
        counters.media_submitted_packets,
        counters.media_sent_packets + counters.media_dropped_send_error_packets
    );
    let packet = StreamReceiver::new(key(), stream(), 1)
        .accept(&sender.port.sent[0].1)
        .expect("admitted");
    assert_eq!(
        packet.seq, 2,
        "numbers 0 and 1 were spent on the refused datagrams and never reused"
    );
}

#[test]
fn n07_a_rebind_is_checked_against_the_profile_and_is_all_or_nothing() {
    let mut sender = sender_over(ScriptPort::new());
    let before = (
        sender.media_addr().expect("media"),
        sender.control_addr().expect("control"),
    );
    // outside the declared profile: refused before the port is touched
    let lan: IpAddr = "192.0.2.7".parse().expect("ip");
    assert_eq!(
        sender.rebind(lan),
        Err(CarrierError::NotLoopback(SocketAddr::new(lan, 0)))
    );
    assert_eq!(sender.faults().rebinds, 0);
    // a port that cannot rebind keeps the old sockets
    sender.port.rebind_fault = Some(PortFault::PathUnavailable);
    let next: IpAddr = "127.0.0.2".parse().expect("ip");
    assert!(matches!(sender.rebind(next), Err(CarrierError::Io(_))));
    assert_eq!(sender.faults().rebind_failures, 1);
    assert_eq!(
        (
            sender.media_addr().expect("media"),
            sender.control_addr().expect("control")
        ),
        before
    );
    // the permitted positive
    sender.port.rebind_fault = None;
    let (media, control) = sender.rebind(next).expect("rebound");
    assert_eq!((media.ip(), control.ip()), (next, next));
    assert_ne!((media, control), before);
    assert_eq!(sender.faults().rebinds, 1);
}

#[test]
fn n07_a_receiver_over_any_port_names_its_peer_and_follows_a_new_sender_address() {
    let first = addr("127.0.0.1:43001");
    let second = addr("127.0.0.1:43002");
    let build = |peer: u32| {
        CarrierReceiver::with_port(
            key(),
            stream(),
            1,
            ReceiverLimits::baseline(),
            ScriptPort::new(),
            first,
        )
        .expect("receiver")
        .with_peer_id(peer)
    };
    assert!(matches!(
        build(MAX_ATTRIBUTABLE_PEER_ID + 1),
        Err(CarrierError::PeerIdTooLarge(_))
    ));
    let mut receiver = build(7).expect("peer id 7");

    // a datagram longer than any legal one is cut to the buffer by the port and rejected by the N01 structure check
    receiver
        .port
        .inbound_media
        .push_back((vec![0xAA; 5000], Some(first)));
    assert_eq!(receiver.poll().media_read, 1);
    assert_eq!(receiver.stats().media_rejected, 1);
    assert_eq!(receiver.stream_counters().rejected_structure, 1);

    // a real signed block is admitted, consumed, and reported with this receiver's peer number
    let mut n01 = StreamSender::new(key(), stream(), 1);
    let wire = n01.send(full_block(0, 0)).expect("signed");
    receiver.port.inbound_media.push_back((wire, None));
    assert_eq!(receiver.poll().media_accepted, 1);
    assert_eq!(receiver.take_media(8).len(), 1);
    receiver.send_report().expect("report");
    let (lane, bytes, to) = receiver.port.sent.pop().expect("a report was sent");
    assert_eq!((lane, to), (Lane::Control, first));
    assert_eq!(
        parse_report(&key(), &bytes),
        Ok(Report {
            stream_id: stream().get(),
            epoch: 1,
            consumed_next: 1,
            peer: 7
        })
    );

    // the sender announced a new control address: the next report follows it, and a rebind keeps the stream's state
    receiver.set_sender_control(second);
    let (media, control) = receiver
        .rebind("127.0.0.3".parse().expect("ip"))
        .expect("rebound");
    assert_eq!(media.ip().to_string(), "127.0.0.3");
    assert_eq!(control.ip().to_string(), "127.0.0.3");
    assert_eq!(receiver.consumed_next(), 1);
    receiver.send_report().expect("report");
    let (_, _, to) = receiver.port.sent.pop().expect("a report was sent");
    assert_eq!(to, second);
}

struct ScriptSink {
    verdicts: VecDeque<SinkVerdict>,
    seen: Vec<usize>,
}

impl MediaSink for ScriptSink {
    fn offer(&mut self, datagram: &[u8]) -> SinkVerdict {
        self.seen.push(datagram.len());
        self.verdicts.pop_front().unwrap_or(SinkVerdict::Refused)
    }
}

#[test]
fn n07_a_media_sink_that_admits_names_the_sequence_and_a_refusal_or_backpressure_earns_no_credit() {
    let sender_control = addr("127.0.0.1:43001");
    let mut receiver = CarrierReceiver::with_port(
        key(),
        stream(),
        1,
        ReceiverLimits::baseline(),
        ScriptPort::new(),
        sender_control,
    )
    .expect("receiver")
    .with_peer_id(7)
    .expect("peer id");
    let mut n01 = StreamSender::new(key(), stream(), 1);
    let first = n01.send(full_block(0, 0)).expect("signed");
    let second = n01.send(full_block(1, 0)).expect("signed");
    let third = n01.send(full_block(2, 0)).expect("signed");
    for wire in [&first, &second, &third] {
        receiver.port.inbound_media.push_back((wire.clone(), None));
    }
    let mut sink = ScriptSink {
        verdicts: VecDeque::from([
            SinkVerdict::Admitted { seq: 0 },
            SinkVerdict::Backpressure,
            SinkVerdict::Admitted { seq: 2 },
        ]),
        seen: Vec::new(),
    };
    let report = receiver.poll_into(&mut sink);
    assert_eq!((report.media_read, report.media_accepted), (3, 2));
    assert_eq!(
        receiver.sink_counters(),
        &SinkCounters {
            admitted: 2,
            refused: 0,
            backpressure: 1
        }
    );
    assert_eq!(
        receiver.consumed_next(),
        3,
        "highest admitted sequence, plus one"
    );
    assert_eq!(sink.seen, vec![first.len(), second.len(), third.len()]);
    assert_eq!(
        receiver.stream_counters().datagrams_seen,
        0,
        "the sink admits; the carrier's own N01 admission did not run, so nothing is admitted twice"
    );

    // a refusal earns no credit
    let fourth = n01.send(full_block(3, 0)).expect("signed");
    receiver.port.inbound_media.push_back((fourth, None));
    sink.verdicts.push_back(SinkVerdict::Refused);
    receiver.poll_into(&mut sink);
    assert_eq!(receiver.sink_counters().refused, 1);
    assert_eq!(receiver.consumed_next(), 3);

    // the sequence a sink reads from an admitted datagram, and the structure check in front of it
    assert_eq!(crate::untrusted_sequence(&second), Ok(1));
    assert!(crate::untrusted_sequence(&second[..10]).is_err());
}

#[test]
fn n07_a_consumed_unusable_datagram_is_counted_and_reading_goes_on() {
    let media = addr("127.0.0.1:42001");
    let control = addr("127.0.0.1:42002");
    let mut sender = sender_over(ScriptPort::new());
    sender.add_peer(7, media, control, 1500).expect("peer 7");
    sender
        .submit_media(1, &full_block(0, 0), 0)
        .expect("queued");
    assert_eq!(sender.pump(0).media_sent, 1);
    // a datagram the kernel consumed but whose sender could not be decoded, then the peer's own report
    sender.port.recv_faults.push_back(PortFault::Discarded);
    sender
        .port
        .inbound_control
        .push_back((encode_report(&key(), stream(), 1, 1, 7).to_vec(), None));
    assert_eq!(
        sender.poll_reports(),
        1,
        "the report behind the discarded datagram was still read"
    );
    assert_eq!(sender.faults().recv_discarded, 1);
    assert_eq!(
        sender.stats().recv_errors,
        0,
        "a discard is not an I/O error"
    );

    // the same on the receiving side, for control and for media
    let mut receiver = CarrierReceiver::with_port(
        key(),
        stream(),
        1,
        ReceiverLimits::baseline(),
        ScriptPort::new(),
        addr("127.0.0.1:43001"),
    )
    .expect("receiver");
    receiver.port.recv_faults.push_back(PortFault::Discarded);
    receiver.port.recv_faults.push_back(PortFault::Discarded);
    let mut n01 = StreamSender::new(key(), stream(), 1);
    let wire = n01.send(full_block(0, 0)).expect("signed");
    receiver.port.inbound_media.push_back((wire, None));
    let report = receiver.poll();
    assert_eq!(report.media_accepted, 1, "media behind a discard is read");
    assert_eq!(receiver.faults().recv_discarded, 2);
    assert_eq!(receiver.stats().io_errors, 0);
    // an ordinary fault does stop the read, and is an I/O error
    receiver
        .port
        .recv_faults
        .push_back(PortFault::Other("boom".to_owned()));
    receiver.poll();
    assert_eq!(receiver.stats().io_errors, 1);
}

#[test]
fn n07_a_message_too_long_send_fences_that_peers_path_and_recovers_when_the_mtu_does() {
    let (media_a, control_a) = (addr("127.0.0.1:42001"), addr("127.0.0.1:42002"));
    let (media_b, control_b) = (addr("127.0.0.1:42003"), addr("127.0.0.1:42004"));
    let mut port = ScriptPort::new();
    port.send_fault = Some(PortFault::MessageTooLong);
    let mut sender = sender_over(port);
    sender
        .add_peer(7, media_a, control_a, 1500)
        .expect("peer 7");
    sender
        .add_peer(8, media_b, control_b, 1500)
        .expect("peer 8");
    sender
        .submit_media(1, &full_block(0, 0), 0)
        .expect("queued");
    sender
        .submit_media(1, &full_block(1, 0), 0)
        .expect("queued");
    assert_eq!(sender.pump(0).media_sent, 0);
    // the first send to a peer said "too long": that peer is fenced and its queue dropped, never retried
    let seven = sender.peer_view(7).expect("peer 7");
    assert_eq!(seven.fence, Some(FenceReason::PathMtuTooSmall));
    assert_eq!(seven.queued_packets, 0);
    assert_eq!(
        sender.faults().send_message_too_long,
        2,
        "one send per peer"
    );
    assert_eq!(sender.stats().mtu_fences, 2);

    // the fault clears; a fenced peer is skipped until its path recovers, and recovery is the MTU's word, not a retry
    sender.port.send_fault = None;
    sender
        .submit_media(1, &full_block(2, 0), 0)
        .expect("queued");
    assert_eq!(sender.pump(1).media_sent, 0, "still fenced");
    assert_eq!(
        sender.set_path_mtu(7, 1500),
        Ok(PathOutcome::Carrying),
        "the path carries a block again"
    );
    sender
        .submit_media(1, &full_block(3, 0), 0)
        .expect("queued");
    assert_eq!(sender.pump(2).media_sent, 1, "only peer 7 recovered");
    assert_eq!(sender.stats().mtu_unfences, 1);
    assert_eq!(sender.port.sent.len(), 1);
    assert_eq!(sender.port.sent[0].2, media_a);
}

#[test]
fn n07_control_is_charged_to_the_interface_pacer_and_to_its_own_share_however_often_pump_is_called()
{
    let (media, control) = (addr("127.0.0.1:42001"), addr("127.0.0.1:42002"));
    let mut sender = sender_over(ScriptPort::new());
    sender.add_peer(7, media, control, 1500).expect("peer 7");
    let big = vec![0xC0; MAX_CONTROL_BYTES];
    let mut control_sent = 0;
    for _ in 0..50 {
        for _ in 0..8 {
            // a refusal is the control queue's own bound; the totals below are what is measured
            let _ = sender.submit_control(7, &big);
        }
        control_sent += sender.pump(0).control_sent;
    }
    // fifty pumps at the same instant: control spends its burst (four datagrams, 512 + 28 each) and nothing more
    assert_eq!(
        control_sent, 4,
        "control_per_pump alone does not bound it in time"
    );
    assert_eq!(sender.control_stats().spent_bytes, 4 * 540);
    assert!(sender.control_stats().pace_limited_pumps > 0);
    // the same bytes came out of the interface bucket: media sees 8192 - 2160 B, five datagrams of 1132 and not seven
    for block in 0..8 {
        sender
            .submit_media(1, &full_block(block, 0), 0)
            .expect("queued");
    }
    assert_eq!(sender.pump(0).media_sent, 5);
    // the permitted positive: control's share refills with time (220,000 B/s, so 10 ms is 2,200 B) and so does the bucket
    assert_eq!(sender.pump(10_000_000).control_sent, 4);
}

#[test]
fn n07_a_control_flood_cannot_starve_media_and_media_saturation_cannot_starve_a_stop() {
    let (media, control) = (addr("127.0.0.1:42001"), addr("127.0.0.1:42002"));
    let mut limits = CarrierLimits::baseline();
    limits.pace_bytes_per_sec = 100_000;
    limits.peer_load_bytes_per_sec = 100_000;
    limits.window_packets = 1000;
    let build = || {
        let mut sender =
            CarrierSender::with_port(key(), stream(), 1, limits.clone(), ScriptPort::new())
                .expect("sender");
        sender.add_peer(7, media, control, 1500).expect("peer 7");
        sender
    };

    // media saturates the pacer; a stop still goes out in the very next pump
    let mut sender = build();
    let mut now = 0;
    for index in 0..50 {
        now += 1_000_000;
        sender
            .submit_media(1, &long_block(index, now), now)
            .expect("queued");
        sender.pump(now);
    }
    assert!(sender.peer_view(7).expect("peer").queued_packets > 4);
    sender.submit_control(7, b"STOP").expect("queued");
    now += 1_000_000;
    assert_eq!(sender.pump(now).control_sent, 1);

    // a control flood, every pump, for 100 ms: control spends no more than its burst plus its share of the rate, and media
    // keeps the rest of the interface
    let mut sender = build();
    let flood = vec![0xC0; MAX_CONTROL_BYTES];
    let (mut now, mut media_sent) = (0, 0_u32);
    for index in 0..100 {
        now += 1_000_000;
        sender
            .submit_media(1, &long_block(index, now), now)
            .expect("queued");
        for _ in 0..4 {
            let _ = sender.submit_control(7, &flood);
        }
        media_sent += sender.pump(now).media_sent;
    }
    let spent = sender.control_stats().spent_bytes;
    // burst: 4 x (512 + 48); share: 1/8 of 100,000 B/s over 100 ms
    assert!(
        (2160..=2240 + 1250).contains(&spent),
        "control spent {spent} B"
    );
    // supply: the 8192 B burst plus 99 refills of 100 B; media gets what control did not take, less one datagram of slack
    let media_bytes = u64::from(media_sent) * 1132;
    assert!(
        media_bytes + spent + 1132 > 8192 + 99 * 100,
        "media {media_bytes} B, control {spent} B"
    );
    assert!(media_sent >= 12, "media sent {media_sent}");
    assert!(
        sender
            .peer_view(7)
            .expect("peer")
            .counters
            .control_rejected_full
            > 0
    );
}

#[test]
fn n07_a_refused_send_never_burns_the_window_and_cannot_run_the_sequence_ahead() {
    let (media, control) = (addr("127.0.0.1:42001"), addr("127.0.0.1:42002"));
    let mut port = ScriptPort::new();
    port.send_fault = Some(PortFault::WouldBlock);
    let mut sender = sender_over(port);
    sender.add_peer(7, media, control, 1500).expect("peer 7");
    // a transport that refuses for 1.1 s of pumps, a block every millisecond: a window of 16 and a receiver forward gap of
    // 1024 would both be gone if every refusal spent a number and a place in the window
    let mut now = 0;
    for index in 0..1100 {
        now += 1_000_000;
        sender
            .submit_media(1, &long_block(index, now), now)
            .expect("queued");
        sender.pump(now);
    }
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(
        (view.in_flight, view.stalled),
        (0, false),
        "nothing was transmitted, so nothing waits for a report"
    );
    assert_eq!(view.counters.media_sent_packets, 0);
    assert!(
        view.sent_next <= 6,
        "a datagram is retried, then given up on, then the peer is left alone for an interval: {} numbers spent",
        view.sent_next
    );
    let c = &view.counters;
    assert_eq!(
        c.media_submitted_packets,
        c.media_sent_packets + dropped_media(c) + view.queued_packets as u64,
        "the books balance, the held datagram counted as queued"
    );
    // the permitted positive: the fault clears, the interval passes, and a held datagram or the next block goes out, as
    // one of the first few numbers, which a receiver that saw nothing admits
    sender.port.send_fault = None;
    now += 2 * STALL_PROBE_NS;
    sender
        .submit_media(1, &long_block(1100, now), now)
        .expect("queued");
    assert!(
        sender.pump(now).media_sent >= 1,
        "the peer was never stalled"
    );
    let packet = StreamReceiver::new(key(), stream(), 1)
        .accept(&sender.port.sent[0].1)
        .expect("admitted");
    assert!(packet.seq <= 6, "sequence {}", packet.seq);
}

/// Everything a peer's media counters say was dropped, in packets.
fn dropped_media(c: &PeerCounters) -> u64 {
    c.media_dropped_overflow_packets
        + c.media_dropped_aggregate_packets
        + c.media_dropped_late_packets
        + c.media_dropped_fenced_packets
        + c.media_dropped_send_error_packets
}

#[test]
fn n07_a_refused_datagram_keeps_its_bytes_and_number_until_it_goes_or_is_given_up_on() {
    let (media, control) = (addr("127.0.0.1:42001"), addr("127.0.0.1:42002"));
    let mut port = ScriptPort::new();
    port.send_fault = Some(PortFault::WouldBlock);
    let mut sender = sender_over(port);
    sender.add_peer(7, media, control, 1500).expect("peer 7");
    for index in 0..2 {
        sender
            .submit_media(1, &long_block(index, 0), 0)
            .expect("queued");
    }
    assert_eq!(sender.pump(0).media_sent, 0);
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(
        (view.sent_next, view.queued_packets),
        (1, 2),
        "one number allocated; the held datagram still counts as queued"
    );
    assert_eq!(sender.pump(0).media_sent, 0);
    assert_eq!(
        sender.faults().send_other,
        1,
        "no second attempt at the same instant"
    );
    // the transport recovers: the held datagram goes first, with its own number, and the next block follows
    sender.port.send_fault = None;
    assert_eq!(sender.pump(1).media_sent, 2);
    let mut receiver = StreamReceiver::new(key(), stream(), 1);
    for (index, (_, wire, _)) in sender.port.sent.iter().enumerate() {
        assert_eq!(
            receiver.accept(wire).expect("admitted").seq,
            index as u64,
            "no gap, no reuse"
        );
    }

    // a transport that keeps refusing: three attempts, then one number spent and the peer left alone for an interval
    let mut port = ScriptPort::new();
    port.send_fault = Some(PortFault::WouldBlock);
    let mut sender = sender_over(port);
    sender.add_peer(7, media, control, 1500).expect("peer 7");
    for index in 0..3 {
        sender
            .submit_media(1, &long_block(index, 0), 0)
            .expect("queued");
    }
    for now in [0, 1, 2] {
        assert_eq!(sender.pump(now).media_sent, 0);
    }
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(
        (
            view.counters.media_dropped_send_error_packets,
            view.sent_next,
            view.queued_packets
        ),
        (1, 1, 2)
    );
    assert_eq!(
        sender.pump(1_000_000).media_sent,
        0,
        "left alone for the interval"
    );
    sender.port.send_fault = None;
    assert_eq!(
        sender.pump(2 + STALL_PROBE_NS).media_sent,
        3 - 1,
        "then the rest go"
    );
    assert_eq!(
        StreamReceiver::new(key(), stream(), 1)
            .accept(&sender.port.sent[0].1)
            .expect("admitted")
            .seq,
        1,
        "number 0 stayed spent"
    );
}

/// A genuine receiver over its own script port: the real N01 admission and the real report. Whatever it reports it has admitted.
fn real_receiver() -> CarrierReceiver<ScriptPort> {
    CarrierReceiver::with_port(
        key(),
        stream(),
        1,
        ReceiverLimits::baseline(),
        ScriptPort::new(),
        addr("127.0.0.1:42002"),
    )
    .expect("a receiver")
    .with_peer_id(7)
    .expect("a peer id that fits")
}

/// Hand `wires` to the receiver as they arrived and take what its N01 admission let through.
fn deliver(
    receiver: &mut CarrierReceiver<ScriptPort>,
    wires: &[Vec<u8>],
) -> Vec<AuthenticatedStreamPacket> {
    for wire in wires {
        receiver.port.inbound_media.push_back((wire.clone(), None));
    }
    receiver.poll();
    receiver.take_media(4096)
}

/// The report the receiver sends now, from what it has itself consumed.
fn report_of(receiver: &mut CarrierReceiver<ScriptPort>) -> Vec<u8> {
    receiver.send_report().expect("the receiver reports");
    receiver.port.sent.pop().expect("a report was sent").1
}

/// The wires the sender's port has been handed since index `from`.
fn wires_since(sender: &CarrierSender<ScriptPort>, from: usize) -> Vec<Vec<u8>> {
    sender.port.sent[from..]
        .iter()
        .map(|(_, wire, _)| wire.clone())
        .collect()
}

fn stalled_sender() -> CarrierSender<ScriptPort> {
    let (media, control) = (addr("127.0.0.1:42001"), addr("127.0.0.1:42002"));
    let mut limits = CarrierLimits::baseline();
    limits.pace_burst_bytes = 65_536;
    let mut sender =
        CarrierSender::with_port(key(), stream(), 1, limits, ScriptPort::new()).expect("sender");
    sender.add_peer(7, media, control, 1500).expect("peer 7");
    for index in 0..20 {
        sender
            .submit_media(1, &long_block(index, 0), 0)
            .expect("queued");
    }
    assert_eq!(
        sender.pump(0).media_sent,
        16,
        "the window is 16 unreported datagrams"
    );
    sender
}

#[test]
fn n07_a_window_full_of_lost_datagrams_is_probed_once_per_interval_and_reopens_on_the_answer() {
    let mut sender = stalled_sender();
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(
        (
            view.in_flight,
            view.stalled,
            view.queued_packets,
            view.sent_next
        ),
        (16, true, 4, 16)
    );
    // a peer that never answers costs one probe per interval, not a stream: its newest datagram again, byte for byte and
    // under the same number, with no number allocated and no media counter moved
    assert_eq!(
        sender.pump(249_999_999).media_sent,
        0,
        "one nanosecond early is early"
    );
    assert_eq!(sender.control_stats().probes_sent, 0);
    assert_eq!(
        sender.pump(250_000_000).media_sent,
        0,
        "a probe is not media"
    );
    assert_eq!(sender.control_stats().probes_sent, 1, "the first probe");
    assert_eq!(sender.port.sent.len(), 17);
    assert_eq!(
        sender.port.sent[16].1, sender.port.sent[15].1,
        "the sixteenth datagram again"
    );
    sender.pump(250_000_001);
    sender.pump(499_999_999);
    assert_eq!(
        sender.control_stats().probes_sent,
        1,
        "not before the interval"
    );
    sender.pump(500_000_000);
    assert_eq!(
        sender.control_stats().probes_sent,
        2,
        "the next interval, the next probe"
    );
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(
        (
            view.sent_next,
            view.in_flight,
            view.counters.media_sent_packets
        ),
        (16, 16, 16),
        "probes allocate nothing, hold no place and are not counted as media"
    );

    // the permitted positive: the probe reaches a genuine receiver that saw none of the window; N01 admits number 15 (within
    // its forward gap), the consumer takes it, and the receiver's own report moves the sender
    let mut receiver = real_receiver();
    let probe = sender.port.sent.last().expect("a probe").1.clone();
    let packets = deliver(&mut receiver, &[probe]);
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].seq, 15);
    sender
        .port
        .inbound_control
        .push_back((report_of(&mut receiver), None));
    assert_eq!(sender.poll_reports(), 1);
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(
        (view.in_flight, view.stalled, view.reported_next),
        (0, false, 16)
    );
    assert_eq!(
        sender.pump(500_000_001).media_sent,
        4,
        "the rest goes at once"
    );
}

#[test]
fn n07_an_address_change_invents_no_credit_and_the_probe_finds_the_new_path() {
    let mut sender = stalled_sender();
    let (new_media, new_control) = (addr("127.0.0.1:42011"), addr("127.0.0.1:42012"));
    sender
        .peer_address_changed(7, new_media, new_control)
        .expect("moved");
    assert_eq!(
        sender.pump(1).media_sent,
        0,
        "datagrams sent to the old path are not forgiven"
    );
    assert!(sender.peer_view(7).expect("peer").stalled);
    sender.pump(STALL_PROBE_NS);
    assert_eq!(sender.control_stats().probes_sent, 1, "the probe is due");
    assert_eq!(sender.port.sent.last().expect("the probe").2, new_media);
    // a genuine receiver admits the probe and reports; the old control address no longer speaks for the peer, the new one does
    let mut receiver = real_receiver();
    let probe = sender.port.sent.last().expect("a probe").1.clone();
    assert_eq!(deliver(&mut receiver, &[probe]).len(), 1);
    let report = report_of(&mut receiver);
    sender
        .port
        .inbound_control
        .push_back((report.clone(), Some(addr("127.0.0.1:42002"))));
    assert_eq!(sender.poll_reports(), 0);
    sender
        .port
        .inbound_control
        .push_back((report, Some(new_control)));
    assert_eq!(sender.poll_reports(), 1);
    assert!(!sender.peer_view(7).expect("peer").stalled);
}

#[test]
fn n07_the_window_limit_is_bounded_so_the_unreported_list_is() {
    let limits = CarrierLimits {
        window_packets: MAX_WINDOW_PACKETS + 1,
        ..CarrierLimits::baseline()
    };
    assert!(matches!(
        limits.validate(),
        Err(CarrierError::InvalidLimits(_))
    ));
    let limits = CarrierLimits {
        window_packets: MAX_WINDOW_PACKETS,
        ..CarrierLimits::baseline()
    };
    assert_eq!(
        limits.validate(),
        Ok(()),
        "a window of 4096 stays a supported setting"
    );
    assert_eq!(MAX_WINDOW_PACKETS, 4096);
}

#[test]
fn n07_a_window_larger_than_the_sequence_budget_is_supported_and_the_budget_is_what_holds() {
    let (media, control) = (addr("127.0.0.1:42001"), addr("127.0.0.1:42002"));
    let limits = CarrierLimits {
        window_packets: MAX_WINDOW_PACKETS,
        pace_bytes_per_sec: 1_000_000_000,
        pace_burst_bytes: 1_000_000,
        ..CarrierLimits::baseline()
    };
    assert_eq!(limits.validate(), Ok(()));
    let mut sender =
        CarrierSender::with_port(key(), stream(), 1, limits, ScriptPort::new()).expect("sender");
    sender.add_peer(7, media, control, 1500).expect("peer 7");
    let mut now = 0;
    for index in 0..1_100 {
        now += 1_000_000;
        sender
            .submit_media(1, &long_block(index, now), now)
            .expect("queued");
        sender.pump(now);
    }
    // nothing was refused and the window of 4096 is nowhere near full, yet the sender stops at the budget: the unreported list
    // is bounded by the smaller of the two
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(
        (
            view.sent_next,
            view.in_flight,
            view.counters.media_sent_packets
        ),
        (SEQ_AHEAD_LIMIT, SEQ_AHEAD_LIMIT, SEQ_AHEAD_LIMIT)
    );
    assert!(!view.stalled, "the window is not what holds");
    assert!(sender.sequence_blocked(7), "the budget is");
    // a genuine receiver admits every one of the 1000 numbers (the last is within N01's gap of nothing), and its report reopens
    // the budget
    let wires = wires_since(&sender, 0);
    assert_eq!(wires.len() as u64, SEQ_AHEAD_LIMIT);
    let mut receiver = real_receiver();
    let mut admitted = 0;
    for start in (0..wires.len()).step_by(32) {
        let end = (start + 32).min(wires.len());
        admitted += deliver(&mut receiver, &wires[start..end]).len();
    }
    assert_eq!(admitted as u64, SEQ_AHEAD_LIMIT);
    assert_eq!(receiver.stream_counters().rejected_future_sequence, 0);
    sender
        .port
        .inbound_control
        .push_back((report_of(&mut receiver), None));
    assert_eq!(sender.poll_reports(), 1);
    assert!(!sender.sequence_blocked(7));
    now += 1_000_000;
    let sent_before = sender.port.sent.len();
    assert!(sender.pump(now).media_sent >= 1, "audio flows again");
    let packets = deliver(&mut receiver, &wires_since(&sender, sent_before));
    assert_eq!(packets[0].seq, SEQ_AHEAD_LIMIT);
}

// ---- long outages: the sequence budget, the probe and the datagram that holds the last number -------------------------------

/// A sender whose transport refuses everything, a block every 100 ms for `pumps` pumps: each datagram is tried three times and
/// given up on, a number at a time. Returns the sender and its clock.
fn refused_for_a_long_outage(pumps: u64) -> (CarrierSender<ScriptPort>, u64) {
    let (media, control) = (addr("127.0.0.1:42001"), addr("127.0.0.1:42002"));
    let mut port = ScriptPort::new();
    port.send_fault = Some(PortFault::WouldBlock);
    let mut sender = sender_over(port);
    sender.add_peer(7, media, control, 1500).expect("peer 7");
    let mut now = 0;
    for index in 0..pumps {
        now += 100_000_000;
        sender
            .submit_media(1, &long_block(index, now), now)
            .expect("queued");
        sender.pump(now);
    }
    (sender, now)
}

#[test]
fn n07_a_long_refusal_cannot_run_the_sequence_out_of_the_receivers_reach_and_the_peer_recovers_against_n01()
 {
    // The fence is N01's and stays as it is: a receiver that has admitted nothing admits number 1024 and refuses 1025. This is
    // the negative control for everything below: without a bound on allocation, a long enough refusal ends beyond it.
    let mut framer = StreamSender::new(key(), stream(), 1);
    let wires: Vec<Vec<u8>> = (0..=1025)
        .map(|index| framer.send(long_block(index, 0)).expect("signed"))
        .collect();
    let mut fresh = StreamReceiver::new(key(), stream(), 1);
    assert!(matches!(
        fresh.accept(&wires[1025]),
        Err(StreamError::SequenceBeyondFutureWindow { .. })
    ));
    assert!(fresh.accept(&wires[1024]).is_ok());

    // 800 seconds of refusals, far more than 1,025 numbers' worth if every refusal spent one without limit
    let (mut sender, mut now) = refused_for_a_long_outage(8_000);
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(
        view.sent_next, SEQ_AHEAD_LIMIT,
        "the allocation stops at the budget"
    );
    assert!(sender.port.sent.is_empty(), "nothing ever left");
    assert_eq!(view.counters.media_sent_packets, 0);
    assert!(
        view.queued_packets >= 1,
        "the last number is held, not given up on"
    );
    assert!(
        !sender.sequence_blocked(7),
        "a held datagram is still to be tried"
    );
    let before = view.counters.clone();
    // a hundred seconds more change nothing about the numbers: none is burned, and the held datagram is neither aged out nor dropped
    for index in 0..1_000 {
        now += 100_000_000;
        sender
            .submit_media(1, &long_block(10_000 + index, now), now)
            .expect("queued");
        sender.pump(now);
    }
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(view.sent_next, SEQ_AHEAD_LIMIT);
    assert_eq!(
        view.counters.media_dropped_send_error_packets, before.media_dropped_send_error_packets,
        "no further datagram was given up on"
    );
    let c = &view.counters;
    assert_eq!(
        c.media_submitted_packets,
        c.media_sent_packets + dropped_media(c) + view.queued_packets as u64,
        "the books balance, the held datagram counted as queued"
    );

    // The transport recovers. The held datagram goes under its own number, 999; a genuine receiver that saw nothing admits it,
    // and its own report moves the budget.
    sender.port.send_fault = None;
    now += STALL_PROBE_NS;
    assert_eq!(sender.pump(now).media_sent, 1);
    let mut receiver = real_receiver();
    let packets = deliver(&mut receiver, &wires_since(&sender, 0));
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].seq, SEQ_AHEAD_LIMIT - 1);
    assert_eq!(receiver.consumed_next(), SEQ_AHEAD_LIMIT);
    sender
        .port
        .inbound_control
        .push_back((report_of(&mut receiver), None));
    assert_eq!(sender.poll_reports(), 1);
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(
        (view.reported_next, view.in_flight, view.sent_next),
        (SEQ_AHEAD_LIMIT, 0, SEQ_AHEAD_LIMIT)
    );
    assert!(!sender.sequence_blocked(7));

    // fresh audio then flows under numbers 1000 and up, which the same receiver admits
    now += 1_000_000;
    sender
        .submit_media(1, &long_block(20_000, now), now)
        .expect("queued");
    let sent_before = sender.port.sent.len();
    let flowed = sender.pump(now).media_sent;
    assert!(flowed >= 1, "fresh audio flows again");
    let packets = deliver(&mut receiver, &wires_since(&sender, sent_before));
    assert_eq!(packets.len() as u32, flowed);
    assert_eq!(packets[0].seq, SEQ_AHEAD_LIMIT);
    assert_eq!(
        receiver.consumed_next(),
        SEQ_AHEAD_LIMIT + u64::from(flowed)
    );
    assert_eq!(receiver.stream_counters().rejected_future_sequence, 0);
    assert_eq!(receiver.stream_counters().rejected_replay, 0);
}

#[test]
fn n07_a_peer_that_never_answers_costs_one_probe_per_interval_through_a_thousand_intervals_and_then_recovers()
 {
    let media = addr("127.0.0.1:42001");
    let mut sender = stalled_sender();
    let mut now = 0;
    // 275 seconds of a silent peer, a block arriving every interval so that something is always waiting to go
    for index in 0..1_100_u64 {
        now += STALL_PROBE_NS;
        sender
            .submit_media(1, &long_block(20 + index, now), now)
            .expect("queued");
        assert_eq!(sender.pump(now).media_sent, 0);
    }
    assert_eq!(
        sender.control_stats().probes_sent,
        1_100,
        "one per interval"
    );
    assert_eq!(sender.control_stats().probe_bytes, 1_100 * 1132);
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(
        (
            view.sent_next,
            view.in_flight,
            view.counters.media_sent_packets
        ),
        (16, 16, 16),
        "no number burned, no place taken, no media counted"
    );
    assert!(!sender.sequence_blocked(7));
    // every probe is the sixteenth datagram again, to the peer's media address
    let newest = sender.port.sent[15].1.clone();
    assert!(
        sender.port.sent[16..]
            .iter()
            .all(|(lane, wire, to)| *lane == Lane::Media && *wire == newest && *to == media)
    );
    assert_eq!(sender.port.sent.len(), 16 + 1_100);

    // the receiver comes back: the next probe is admitted by a receiver that saw nothing (number 15 is within N01's gap),
    // its report reopens the window, and the queued audio goes out under the next numbers
    now += STALL_PROBE_NS;
    sender
        .submit_media(1, &long_block(2_000, now), now)
        .expect("queued");
    sender.pump(now);
    assert_eq!(sender.control_stats().probes_sent, 1_101);
    let mut receiver = real_receiver();
    let probe = sender.port.sent.last().expect("the probe").1.clone();
    assert_eq!(deliver(&mut receiver, &[probe]).len(), 1);
    sender
        .port
        .inbound_control
        .push_back((report_of(&mut receiver), None));
    assert_eq!(sender.poll_reports(), 1);
    assert_eq!(sender.peer_view(7).expect("peer").in_flight, 0);
    now += 1;
    let sent_before = sender.port.sent.len();
    let flowed = sender.pump(now).media_sent;
    assert!(flowed >= 1);
    let packets = deliver(&mut receiver, &wires_since(&sender, sent_before));
    assert_eq!(packets.len() as u32, flowed);
    assert_eq!(packets[0].seq, 16);
    assert_eq!(receiver.stream_counters().rejected_future_sequence, 0);
}

#[test]
fn n07_the_datagram_that_holds_the_last_number_is_never_dropped_aged_evicted_or_fenced_away() {
    let (mut sender, mut now) = refused_for_a_long_outage(6_000);
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(view.sent_next, SEQ_AHEAD_LIMIT);
    assert!(view.queued_packets >= 1);

    // aged: a day passes; everything queued is late and gone, the held datagram is not
    now += 86_400_000_000_000;
    sender
        .submit_media(1, &long_block(40_000, now), now)
        .expect("queued");
    sender.pump(now);
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(view.sent_next, SEQ_AHEAD_LIMIT);
    assert_eq!(
        view.queued_packets, 2,
        "the held datagram and the one fresh block; the day-old queue is gone"
    );

    // evicted: a flood of newcomers fills the peer's queue, and the oldest queued make room; the held datagram is not among them
    let overflow_before = view.counters.media_dropped_overflow_packets;
    for index in 0..100 {
        sender
            .submit_media(1, &long_block(41_000 + index, now), now)
            .expect("queued");
    }
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(
        view.queued_packets, 32,
        "the peer's cap, held datagram included"
    );
    assert_eq!(
        view.counters.media_dropped_overflow_packets - overflow_before,
        70,
        "101 arrived into 31 free places"
    );

    // fenced: a path that cannot carry a block drops the queue and keeps the held datagram
    assert_eq!(sender.set_path_mtu(7, 1000), Ok(PathOutcome::Fenced));
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(
        (view.fence, view.queued_packets),
        (Some(FenceReason::PathMtuTooSmall), 1)
    );
    assert_eq!(sender.set_path_mtu(7, 1500), Ok(PathOutcome::Carrying));

    // and a kernel that says "too long" for it fences the path but keeps the datagram too
    sender.port.send_fault = Some(PortFault::MessageTooLong);
    now += STALL_PROBE_NS;
    sender.pump(now);
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(
        (view.fence, view.queued_packets, view.sent_next),
        (Some(FenceReason::PathMtuTooSmall), 1, SEQ_AHEAD_LIMIT)
    );
    assert_eq!(sender.set_path_mtu(7, 1500), Ok(PathOutcome::Carrying));

    // the permitted positive: the path carries it, the kernel takes it, a genuine receiver admits it as number 999 and the
    // peer's budget reopens
    sender.port.send_fault = None;
    now += STALL_PROBE_NS;
    assert_eq!(sender.pump(now).media_sent, 1);
    let mut receiver = real_receiver();
    let packets = deliver(&mut receiver, &wires_since(&sender, 0));
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].seq, SEQ_AHEAD_LIMIT - 1);
    sender
        .port
        .inbound_control
        .push_back((report_of(&mut receiver), None));
    assert_eq!(sender.poll_reports(), 1);
    assert!(!sender.sequence_blocked(7));
    assert_eq!(
        sender.peer_view(7).expect("peer").reported_next,
        SEQ_AHEAD_LIMIT
    );
}

#[test]
fn n07_a_refused_probe_burns_no_number_and_a_too_long_probe_fences_the_peer() {
    let mut sender = stalled_sender();
    sender.port.send_fault = Some(PortFault::WouldBlock);
    sender.pump(STALL_PROBE_NS);
    assert_eq!(
        sender.control_stats().probes_sent,
        0,
        "refused, so not sent"
    );
    let view = sender.peer_view(7).expect("peer");
    assert_eq!((view.sent_next, view.in_flight), (16, 16));
    // it is not tried again at once: the next attempt is an interval later
    sender.port.send_fault = None;
    sender.pump(STALL_PROBE_NS + 1);
    assert_eq!(sender.control_stats().probes_sent, 0);
    sender.pump(2 * STALL_PROBE_NS);
    assert_eq!(sender.control_stats().probes_sent, 1);
    // a kernel that says "too long" fences the peer; its queue goes, its in-flight record stays
    sender.port.send_fault = Some(PortFault::MessageTooLong);
    sender.pump(3 * STALL_PROBE_NS);
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(
        (view.fence, view.queued_packets, view.in_flight),
        (Some(FenceReason::PathMtuTooSmall), 0, 16)
    );
    assert_eq!(sender.stats().mtu_fences, 1);
}

// ---- one bound on the work of a pump: every attempt on the media lane counts ---------------------------------------------------

fn two_peer_sender(
    cap: usize,
    port: ScriptPort,
) -> (CarrierSender<ScriptPort>, SocketAddr, SocketAddr) {
    let (m1, c1) = (addr("127.0.0.1:42001"), addr("127.0.0.1:42002"));
    let (m2, c2) = (addr("127.0.0.1:42003"), addr("127.0.0.1:42004"));
    let limits = CarrierLimits {
        window_packets: 1,
        max_sends_per_pump: cap,
        pace_burst_bytes: 65_536,
        ..CarrierLimits::baseline()
    };
    let mut sender = CarrierSender::with_port(key(), stream(), 1, limits, port).expect("sender");
    sender.add_peer(7, m1, c1, 1500).expect("peer 7");
    sender.add_peer(8, m2, c2, 1500).expect("peer 8");
    for index in 0..4 {
        sender
            .submit_media(1, &long_block(index, 0), 0)
            .expect("queued");
    }
    (sender, m1, m2)
}

#[test]
fn n07_every_media_lane_attempt_counts_against_the_pump_cap_probes_and_refusals_included() {
    // Two peers whose windows hold one datagram, a cap of one attempt per pump. Each pump makes exactly one attempt.
    let (mut sender, m1, m2) = two_peer_sender(1, ScriptPort::new());
    let first = sender.pump(0);
    assert_eq!((first.media_sent, first.send_cap_hit), (1, true));
    let second = sender.pump(0);
    assert_eq!((second.media_sent, second.send_cap_hit), (1, true));
    assert_eq!(sender.port.sent.len(), 2, "one datagram to each peer");
    assert!(sender.peer_view(7).expect("peer 7").stalled);
    assert!(sender.peer_view(8).expect("peer 8").stalled);
    // both probes fall due at 250 ms. Before the fix a pump sent both and reported media_sent 0 with the cap untouched; now the
    // probe is an attempt like any other
    let probe_one = sender.pump(250_000_000);
    assert_eq!(
        (probe_one.media_sent, probe_one.send_cap_hit),
        (0, true),
        "a probe is not media, and it is one attempt"
    );
    assert_eq!(sender.control_stats().probes_sent, 1, "not two");
    // the next pump makes progress with the other peer; no peer is probed twice
    let probe_two = sender.pump(250_000_001);
    assert!(probe_two.send_cap_hit);
    assert_eq!(sender.control_stats().probes_sent, 2);
    let idle = sender.pump(250_000_002);
    assert_eq!(
        (idle.send_cap_hit, sender.control_stats().probes_sent),
        (false, 2)
    );
    let destinations: Vec<SocketAddr> = sender.port.sent[2..].iter().map(|sent| sent.2).collect();
    assert_eq!(destinations, vec![m1, m2], "one probe each, in turn");
    assert_eq!(sender.port.sent[2].1, sender.port.sent[0].1);
    assert_eq!(sender.port.sent[3].1, sender.port.sent[1].1);
    // the permitted positive: a cap of two lets both probes go in one pump, and says the cap was reached
    let (mut sender, _, _) = two_peer_sender(2, ScriptPort::new());
    assert_eq!(sender.pump(0).media_sent, 2);
    let both = sender.pump(250_000_000);
    assert_eq!((both.media_sent, both.send_cap_hit), (0, true));
    assert_eq!(sender.control_stats().probes_sent, 2);

    // A refused attempt costs the same work: one attempt per pump however many peers are refused, and the next pump moves on.
    let mut port = ScriptPort::new();
    port.send_fault = Some(PortFault::WouldBlock);
    let (mut sender, _, _) = two_peer_sender(1, port);
    let refused = sender.pump(0);
    assert_eq!((refused.media_sent, refused.send_cap_hit), (0, true));
    assert_eq!(sender.faults().send_other, 1, "one attempt, not two");
    sender.pump(0);
    assert_eq!(
        sender.faults().send_other,
        2,
        "the next pump tried the other peer"
    );
    // and recovery progresses one attempt per pump too, the held datagrams going first under their own numbers
    sender.port.send_fault = None;
    assert_eq!(sender.pump(1).media_sent, 1);
    assert_eq!(sender.pump(1).media_sent, 1);
    let numbers: Vec<u64> = sender
        .port
        .sent
        .iter()
        .map(|(_, wire, _)| {
            StreamReceiver::new(key(), stream(), 1)
                .accept(wire)
                .expect("admitted")
                .seq
        })
        .collect();
    assert_eq!(numbers, vec![0, 0], "each peer's first datagram, number 0");
}

// ---- retained bytes and the address-change MTU ------------------------------------------------------------------------------------

#[test]
fn n07_retained_totals_saturate_at_extreme_valid_limits_without_allocating() {
    let ordinary = RetainedBytes {
        queued: 3,
        cached: 5,
        unreported: 7,
        control: 11,
        queue_slots: usize::MAX,
    };
    assert_eq!(
        ordinary.total(),
        26,
        "queue slots are counts, not payload bytes"
    );
    let limits = CarrierLimits {
        peer_queue_bytes: usize::MAX,
        aggregate_queue_bytes: usize::MAX,
        control_queue_packets: usize::MAX,
        ..CarrierLimits::baseline()
    };
    assert_eq!(limits.validate(), Ok(()));
    let bound = limits.max_retained_bytes();
    assert_eq!(bound.queued, usize::MAX);
    assert_eq!(bound.control, usize::MAX);
    assert_eq!(
        bound.total(),
        usize::MAX,
        "an unrepresentable bound must not panic or wrap into a small budget"
    );
    let invalid = CarrierLimits {
        max_peers: 0,
        ..limits
    };
    assert!(
        invalid.validate().is_err(),
        "saturating accounting must not relax configuration validation"
    );
}

#[test]
fn n07_the_cached_datagram_and_every_other_retained_byte_is_accounted_and_bounded() {
    let limits = CarrierLimits {
        window_packets: MAX_WINDOW_PACKETS,
        pace_bytes_per_sec: 1_000_000_000,
        pace_burst_bytes: 1_000_000,
        ..CarrierLimits::baseline()
    };
    let mut sender =
        CarrierSender::with_port(key(), stream(), 1, limits.clone(), ScriptPort::new())
            .expect("sender");
    for id in 1..=8_u32 {
        let media = addr(&format!("127.0.0.1:{}", 42_100 + 2 * id));
        let control = addr(&format!("127.0.0.1:{}", 42_101 + 2 * id));
        sender.add_peer(id, media, control, 1500).expect("peer");
    }
    // nothing is held yet but the sequence list, which is allocated at its bound when a peer is admitted
    let empty = sender.retained_bytes();
    assert_eq!((empty.queued, empty.cached, empty.control), (0, 0, 0));
    assert_eq!(empty.unreported, limits.max_retained_bytes().unreported);
    // eight peers, a window of 4096, no report ever: every peer sends until its sequence budget is spent, caches its newest
    // datagram, and then its queue fills (and probes go out from the cache)
    let mut now = 0;
    for index in 0..1_300 {
        now += 1_000_000;
        sender
            .submit_media(1, &long_block(index, now), now)
            .expect("queued");
        sender.pump(now);
    }
    for id in 1..=8_u32 {
        for _ in 0..8 {
            sender
                .submit_control(id, &[0xC0; MAX_CONTROL_BYTES])
                .expect("queued control");
        }
    }
    assert!(
        sender.control_stats().probes_sent > 0,
        "probes ran from the cache"
    );
    let held = sender.retained_bytes();
    let bound = limits.max_retained_bytes();
    // each kind, exactly: a datagram cached per peer, the budget (not the window of 4096) bounding the list, a full control
    // queue, and the aggregate packet cap binding the queue
    assert_eq!(held.cached, 8 * MAX_DATAGRAM_BYTES);
    // every byte vector here is built to its exact length, so capacity is length and the report equals the logical bytes
    for peer in &sender.peers {
        let sent = peer.last_sent.as_ref().expect("a cached datagram");
        assert_eq!(sent.wire.capacity(), sent.wire.len());
        assert!(peer.control_q.iter().all(|m| m.capacity() == m.len()));
    }
    assert_eq!(held.unreported, 8 * SEQ_AHEAD_LIMIT as usize * 8);
    assert_eq!(held.control, 8 * 8 * MAX_CONTROL_BYTES);
    assert_eq!(
        held.queued,
        limits.aggregate_queue_packets * (WIRE_OVERHEAD_BYTES + MAX_PAYLOAD_BYTES)
    );
    // the mismatch the accounting closes: the aggregate byte cap alone does not bound what the sender retains for media, because
    // the cached datagrams sit outside it
    assert!(held.queued <= limits.aggregate_queue_bytes);
    assert!(
        held.queued + held.cached > limits.aggregate_queue_bytes,
        "{held:?} against an aggregate cap of {}",
        limits.aggregate_queue_bytes
    );
    // and the closed form bounds every kind and the total
    assert!(held.queued <= bound.queued);
    assert!(held.cached <= bound.cached);
    assert!(held.unreported <= bound.unreported);
    assert!(held.control <= bound.control);
    assert!(held.total() <= bound.total());
    assert_eq!(bound.cached, limits.max_peers * MAX_DATAGRAM_BYTES);
}

#[test]
fn n07_retained_allocation_stays_in_the_report_when_only_the_logical_length_shrinks() {
    let (media, control) = (addr("127.0.0.1:42001"), addr("127.0.0.1:42002"));
    let limits = CarrierLimits {
        window_packets: MAX_WINDOW_PACKETS,
        pace_bytes_per_sec: 1_000_000_000,
        pace_burst_bytes: 1_000_000,
        ..CarrierLimits::baseline()
    };
    let mut sender =
        CarrierSender::with_port(key(), stream(), 1, limits.clone(), ScriptPort::new())
            .expect("sender");
    sender.add_peer(7, media, control, 1500).expect("peer 7");
    // the list is allocated at its bound (the sequence budget, under a window of 4096) when the peer is admitted
    let bound = SEQ_AHEAD_LIMIT as usize * std::mem::size_of::<u64>();
    assert_eq!(sender.retained_bytes().unreported, bound);
    assert_eq!(
        sender.peers[0].in_flight.capacity(),
        SEQ_AHEAD_LIMIT as usize
    );
    let mut now = 0;
    for index in 0..1_050 {
        now += 1_000_000;
        sender
            .submit_media(1, &long_block(index, now), now)
            .expect("queued");
        sender.pump(now);
    }
    let full = sender.peer_view(7).expect("peer");
    assert_eq!(full.in_flight, SEQ_AHEAD_LIMIT);
    assert_eq!(
        sender.retained_bytes().unreported,
        bound,
        "filling the list to its bound allocated nothing more"
    );
    assert_eq!(sender.retained_bytes().cached, MAX_DATAGRAM_BYTES);

    // a report covering everything: the logical length goes to zero and the allocation does not
    sender.port.inbound_control.push_back((
        encode_report(&key(), stream(), 1, SEQ_AHEAD_LIMIT, 7).to_vec(),
        None,
    ));
    assert_eq!(sender.poll_reports(), 1);
    let cleared = sender.peer_view(7).expect("peer");
    assert_eq!(cleared.in_flight, 0);
    assert_eq!(
        cleared.in_flight as usize * std::mem::size_of::<u64>(),
        0,
        "a figure taken from the length would now say that nothing is held"
    );
    assert_eq!(
        sender.retained_bytes().unreported,
        bound,
        "the allocation is still held, and the report says so"
    );

    // a move changes nothing about it
    sender
        .peer_address_changed(7, addr("127.0.0.1:42011"), addr("127.0.0.1:42012"))
        .expect("moved");
    assert_eq!(sender.retained_bytes().unreported, bound);

    // an epoch restart clears every count, drops the cached datagram (it cannot be probed under the new numbering), and keeps
    // the allocation
    sender.advance_epoch(2).expect("a newer epoch");
    let restarted = sender.peer_view(7).expect("peer");
    assert_eq!((restarted.in_flight, restarted.sent_next), (0, 0));
    let after = sender.retained_bytes();
    assert_eq!(after.unreported, bound);
    assert_eq!(
        after.cached, 0,
        "the cached datagram is gone and leaves the report"
    );
    assert!(after.total() <= limits.max_retained_bytes().total());
    // the permitted positive: the list serves the new epoch's numbers without growing
    for index in 0..30 {
        now += 1_000_000;
        sender
            .submit_media(2, &long_block(index, now), now)
            .expect("queued");
        sender.pump(now);
    }
    assert_eq!(sender.peer_view(7).expect("peer").in_flight, 30);
    assert_eq!(sender.retained_bytes().unreported, bound);
}

#[test]
fn n07_a_move_onto_a_family_with_more_header_overhead_is_checked_against_the_path_mtu() {
    let limits = CarrierLimits {
        allow_ipv6: true,
        ..CarrierLimits::baseline()
    };
    let (media, control) = (addr("127.0.0.1:42001"), addr("127.0.0.1:42002"));
    let (media8, control8) = (addr("127.0.0.1:42003"), addr("127.0.0.1:42004"));
    let (media6, control6) = (addr("[::1]:42011"), addr("[::1]:42012"));
    let mut sender =
        CarrierSender::with_port(key(), stream(), 1, limits, ScriptPort::new()).expect("sender");
    // a path MTU of 1140 carries a block over IPv4 (1140 - 28 - 80 = 1032) and not over IPv6 (1140 - 48 - 80 = 1012)
    sender
        .add_peer(7, media, control, 1140)
        .expect("peer 7 over IPv4");
    sender
        .add_peer(8, media8, control8, 1500)
        .expect("peer 8 over IPv4");
    assert_eq!(
        sender.peer_address_changed(7, media6, control6),
        Err(CarrierError::PathMtuTooSmall {
            path_mtu: 1140,
            capacity: 1012,
            required: 1024
        }),
        "a move the new path cannot carry a block over is refused, as at admission"
    );
    assert_eq!(sender.stats().path_changes, 0);
    sender
        .submit_media(1, &long_block(0, 0), 0)
        .expect("queued");
    sender.pump(0);
    assert!(sender.port.sent.iter().any(|sent| sent.2 == media));
    assert!(sender.port.sent.iter().all(|sent| sent.2 != media6));

    // the permitted positive: a path of 1500 carries a block over IPv6 (1500 - 48 - 80 = 1372), and the move takes effect
    assert_eq!(sender.peer_address_changed(8, media6, control6), Ok(()));
    assert_eq!(sender.stats().path_changes, 1);
    sender
        .submit_media(1, &long_block(1, 1), 1)
        .expect("queued");
    sender.pump(1);
    assert!(sender.port.sent.iter().any(|sent| sent.2 == media6));
    // and the refused peer moves once its path is known to carry the block
    assert_eq!(sender.set_path_mtu(7, 1500), Ok(PathOutcome::Carrying));
    assert_eq!(
        sender.peer_address_changed(7, addr("[::1]:42021"), addr("[::1]:42022")),
        Ok(())
    );
    assert_eq!(sender.stats().path_changes, 2);
}

// ---- the held datagram is part of every queue bound ----------------------------------------------------------------------

fn refusing_sender(limits: CarrierLimits, peers: &[u32]) -> CarrierSender<ScriptPort> {
    let mut port = ScriptPort::new();
    port.send_fault = Some(PortFault::WouldBlock);
    let mut sender = CarrierSender::with_port(key(), stream(), 1, limits, port).expect("sender");
    for &id in peers {
        let (media, control) = (
            addr(&format!("127.0.0.1:{}", 42_100 + 2 * id)),
            addr(&format!("127.0.0.1:{}", 42_101 + 2 * id)),
        );
        sender.add_peer(id, media, control, 1500).expect("peer");
    }
    sender
}

#[test]
fn n07_a_held_datagram_counts_in_the_peer_cap_and_is_never_the_one_evicted() {
    let mut sender = refusing_sender(CarrierLimits::baseline(), &[7]);
    // exactly the cap, none signed yet: all fit, nothing is evicted
    for index in 0..32 {
        let report = sender
            .submit_media(1, &long_block(index, 0), 0)
            .expect("queued");
        assert_eq!((report.queued, report.evicted), (1, 0));
    }
    // the first is signed and held: it still counts, so the peer is at its cap and no more
    assert_eq!(sender.pump(0).media_sent, 0);
    let view = sender.peer_view(7).expect("peer");
    assert_eq!((view.queued_packets, view.sent_next), (32, 1));
    assert_eq!(
        view.queued_bytes,
        32 * (WIRE_OVERHEAD_BYTES + MAX_PAYLOAD_BYTES)
    );
    // one over: the oldest QUEUED block makes room, never the held datagram, however many come
    let report = sender
        .submit_media(1, &long_block(32, 0), 0)
        .expect("queued");
    assert_eq!((report.queued, report.evicted), (1, 1));
    for index in 33..200 {
        sender
            .submit_media(1, &long_block(index, 0), 0)
            .expect("queued");
        let view = sender.peer_view(7).expect("peer");
        assert!(view.queued_packets <= 32, "{} packets", view.queued_packets);
        assert!(view.queued_bytes <= 36_864, "{} bytes", view.queued_bytes);
    }
    // the transport recovers: the held datagram goes first under its own number (0, block 0), then the queue in order
    sender.port.send_fault = None;
    let flowed = sender.pump(1).media_sent;
    assert!(flowed >= 1);
    let mut receiver = StreamReceiver::new(key(), stream(), 1);
    let first = receiver
        .accept(&sender.port.sent[0].1)
        .expect("the held datagram is admitted");
    assert_eq!((first.seq, first.start_frame), (0, 0));
    let view = sender.peer_view(7).expect("peer");
    let c = &view.counters;
    assert_eq!(c.media_submitted_packets, 200);
    assert_eq!(
        c.media_submitted_packets,
        c.media_sent_packets + dropped_media(c) + view.queued_packets as u64
    );
}

#[test]
fn n07_the_byte_cap_counts_the_held_datagram_too_and_a_peer_holding_only_that_refuses_the_newcomer()
{
    let mut limits = CarrierLimits::baseline();
    limits.peer_queue_bytes = 2 * (WIRE_OVERHEAD_BYTES + MAX_PAYLOAD_BYTES);
    let mut sender = refusing_sender(limits.clone(), &[7]);
    for index in 0..2 {
        sender
            .submit_media(1, &long_block(index, 0), 0)
            .expect("queued");
    }
    sender.pump(0);
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(
        (view.queued_packets, view.queued_bytes),
        (2, limits.peer_queue_bytes)
    );
    let report = sender
        .submit_media(1, &long_block(2, 0), 0)
        .expect("queued");
    assert_eq!(
        (report.queued, report.evicted),
        (1, 1),
        "exactly the byte cap, then one over"
    );
    assert_eq!(
        sender.peer_view(7).expect("peer").queued_bytes,
        limits.peer_queue_bytes
    );

    // one datagram's worth of room, and it is held: nothing queued can make room, so the newcomer is what is refused
    let mut limits = CarrierLimits::baseline();
    limits.peer_queue_bytes = WIRE_OVERHEAD_BYTES + MAX_PAYLOAD_BYTES;
    let mut sender = refusing_sender(limits, &[7]);
    sender
        .submit_media(1, &long_block(0, 0), 0)
        .expect("queued");
    sender.pump(0);
    let report = sender
        .submit_media(1, &long_block(1, 0), 0)
        .expect("accepted for accounting");
    assert_eq!((report.queued, report.evicted), (0, 0));
    let view = sender.peer_view(7).expect("peer");
    assert_eq!(
        (
            view.queued_packets,
            view.counters.media_dropped_overflow_packets
        ),
        (1, 1)
    );
    sender.port.send_fault = None;
    assert_eq!(
        sender.pump(1).media_sent,
        1,
        "the held datagram was not lost"
    );
    assert_eq!(
        StreamReceiver::new(key(), stream(), 1)
            .accept(&sender.port.sent[0].1)
            .expect("admitted")
            .seq,
        0
    );
}

#[test]
fn n07_held_datagrams_count_in_the_aggregate_cap_and_the_longest_queue_pays_for_a_newcomer() {
    let mut limits = CarrierLimits::baseline();
    limits.aggregate_queue_packets = 3;
    let mut sender = refusing_sender(limits, &[7, 8]);
    sender
        .submit_media(1, &long_block(0, 0), 0)
        .expect("queued");
    sender.pump(0);
    let total = |sender: &CarrierSender<ScriptPort>| {
        sender.peer_view(7).expect("peer 7").queued_packets
            + sender.peer_view(8).expect("peer 8").queued_packets
    };
    assert_eq!(total(&sender), 2, "one held datagram per peer");
    // room for exactly one more in the aggregate: both peers want it, so one queued block pays for the other's
    let report = sender
        .submit_media(1, &long_block(1, 0), 0)
        .expect("queued");
    assert_eq!((report.queued, report.evicted), (2, 1));
    assert_eq!(total(&sender), 3);
    for index in 2..60 {
        sender
            .submit_media(1, &long_block(index, 0), 0)
            .expect("queued");
        assert!(total(&sender) <= 3, "aggregate {} packets", total(&sender));
    }
    // the held datagrams survived all of it: both peers' number 0 are still theirs to send
    sender.port.send_fault = None;
    let flowed = sender.pump(1).media_sent;
    assert!(flowed >= 2);
    for (_, wire, to) in &sender.port.sent[..2] {
        let packet = StreamReceiver::new(key(), stream(), 1)
            .accept(wire)
            .expect("admitted");
        assert_eq!((packet.seq, packet.start_frame), (0, 0), "{to}");
    }
}

#[test]
fn n07_an_aggregate_full_of_held_datagrams_refuses_the_newcomer_and_loses_nothing() {
    let mut limits = CarrierLimits::baseline();
    limits.aggregate_queue_packets = 2;
    let mut sender = refusing_sender(limits, &[7, 8]);
    sender
        .submit_media(1, &long_block(0, 0), 0)
        .expect("queued");
    assert_eq!(sender.pump(0).media_sent, 0);
    for id in [7, 8] {
        let view = sender.peer_view(id).expect("peer");
        assert_eq!(
            (view.queued_packets, view.sent_next),
            (1, 1),
            "peer {id} holds its datagram"
        );
    }
    // the aggregate holds two and both are held: nothing is evictable, so the newcomer is refused for both peers
    let report = sender
        .submit_media(1, &long_block(1, 0), 0)
        .expect("accepted for accounting");
    assert_eq!(
        (report.queued, report.evicted, report.rejected_aggregate),
        (0, 0, 2)
    );
    for id in [7, 8] {
        let view = sender.peer_view(id).expect("peer");
        assert_eq!(
            (
                view.queued_packets,
                view.counters.media_dropped_aggregate_packets
            ),
            (1, 1)
        );
        let c = &view.counters;
        assert_eq!(
            c.media_submitted_packets,
            c.media_sent_packets + dropped_media(c) + view.queued_packets as u64
        );
    }
    // the permitted positive: the transport recovers and both held datagrams go, each under its own number 0
    sender.port.send_fault = None;
    assert_eq!(sender.pump(1).media_sent, 2);
    assert_eq!(sender.port.sent.len(), 2);
    // room again: the next block is taken
    let report = sender
        .submit_media(1, &long_block(2, 2), 2)
        .expect("queued");
    assert_eq!(report.queued, 2);
}

// ---- several streams on one interface -------------------------------------------------------------------------------------

fn other_key() -> StreamKey {
    StreamKey::from_bytes([0x48; 32])
}

fn other_stream() -> StreamId {
    StreamId::new(0x0700_0000_0000_0002).expect("nonzero stream id")
}

fn third_stream() -> StreamId {
    StreamId::new(0x0700_0000_0000_0003).expect("nonzero stream id")
}

fn fourth_stream() -> StreamId {
    StreamId::new(0x0700_0000_0000_0004).expect("nonzero stream id")
}

/// The second group's epoch: not the primary group's, so a check that confuses the two is caught.
const SECOND_EPOCH: u64 = 5;

/// Two streams on one interface over one script port: the primary group (key, stream 1, epoch 1) with peer 7, and a second group
/// (another key, stream 2, epoch 5) with peer 8.
fn two_group_sender(limits: CarrierLimits) -> (CarrierSender<ScriptPort>, GroupId) {
    let mut sender =
        CarrierSender::with_port(key(), stream(), 1, limits, ScriptPort::new()).expect("sender");
    let second = sender
        .add_group(other_key(), other_stream(), SECOND_EPOCH)
        .expect("a second group");
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .expect("peer 7");
    sender
        .add_peer_in_group(
            second,
            8,
            addr("127.0.0.1:42003"),
            addr("127.0.0.1:42004"),
            1500,
        )
        .expect("peer 8");
    (sender, second)
}

/// One block for each group's peers at `now_ns`: `index` is the block number.
fn submit_both(sender: &mut CarrierSender<ScriptPort>, second: GroupId, index: u64, now_ns: u64) {
    sender
        .submit_media(1, &long_block(index, now_ns), now_ns)
        .expect("queued for the primary group");
    sender
        .submit_group_media(second, SECOND_EPOCH, &long_block(index, now_ns), now_ns)
        .expect("queued for the second group");
}

fn view(sender: &CarrierSender<ScriptPort>, id: u32) -> PeerView {
    sender.peer_view(id).expect("a peer")
}

/// Give the sender one report datagram as it arrived, and apply it. Returns how many reports moved a peer.
fn feed(sender: &mut CarrierSender<ScriptPort>, report: &[u8]) -> u32 {
    sender
        .port
        .inbound_control
        .push_back((report.to_vec(), None));
    sender.poll_reports()
}

#[test]
fn n07_two_groups_draw_on_one_interface_bucket_and_one_work_cap() {
    // a bucket that affords exactly three datagrams, however many groups ask for them: a bucket for each group would send four
    let cost = (MAX_DATAGRAM_BYTES + IPV4_UDP_OVERHEAD_BYTES) as u64;
    let limits = CarrierLimits {
        pace_bytes_per_sec: 1_000_000,
        pace_burst_bytes: 3 * cost,
        ..CarrierLimits::baseline()
    };
    let (mut sender, second) = two_group_sender(limits);
    for index in 0..2 {
        submit_both(&mut sender, second, index, 0);
    }
    let report = sender.pump(0);
    assert_eq!((report.media_sent, report.pace_limited), (3, true));
    let (seven, eight) = (addr("127.0.0.1:42001"), addr("127.0.0.1:42003"));
    let sent_to = |sender: &CarrierSender<ScriptPort>, to: SocketAddr| {
        sender
            .port
            .sent
            .iter()
            .filter(|(lane, _, dest)| *lane == Lane::Media && *dest == to)
            .count()
    };
    assert_eq!(
        (sent_to(&sender, seven), sent_to(&sender, eight)),
        (2, 1),
        "round robin over peers, whatever group they are in: 7, 8, 7"
    );
    assert_eq!(
        report.next_send_ns,
        Some(cost * 1_000),
        "one bucket, one deadline"
    );
    // the instant it affords one more, the peer that is still waiting gets it
    let later = sender.pump(cost * 1_000);
    assert_eq!(later.media_sent, 1);
    assert_eq!(sent_to(&sender, eight), 2);

    // one bound on a pump's media-lane attempts for the whole interface, not one for each group
    let capped = CarrierLimits {
        max_sends_per_pump: 2,
        pace_burst_bytes: 65_536,
        ..CarrierLimits::baseline()
    };
    let (mut sender, second) = two_group_sender(capped);
    for index in 0..2 {
        submit_both(&mut sender, second, index, 0);
    }
    let first = sender.pump(0);
    assert_eq!((first.media_sent, first.send_cap_hit), (2, true));
    assert_eq!(
        sender.pump(0).media_sent,
        2,
        "the cap is per pump, so the rest goes in the next"
    );
}

#[test]
fn n07_a_group_is_admitted_against_the_budget_every_group_shares_and_leaving_returns_it() {
    let base = CarrierLimits::baseline();
    // the pacing budget carries two peers
    let limits = CarrierLimits {
        pace_bytes_per_sec: 2 * base.peer_load_bytes_per_sec,
        ..base.clone()
    };
    let (mut sender, second) = two_group_sender(limits);
    let third = sender
        .add_group(other_key(), third_stream(), 9)
        .expect("a third group, which holds no budget until it has a peer");
    sender
        .submit_group_media(second, SECOND_EPOCH, &long_block(0, 0), 0)
        .expect("queued");
    let playing = |sender: &CarrierSender<ScriptPort>| (sender.peer_view(7), sender.peer_view(8));
    let before = playing(&sender);
    // a third peer is refused whichever group asks, and the two that are playing are exactly as they were
    let refused = sender.add_peer_in_group(
        third,
        9,
        addr("127.0.0.1:42005"),
        addr("127.0.0.1:42006"),
        1500,
    );
    assert_eq!(
        refused,
        Err(CarrierError::OverBudget {
            peer: 9,
            needed: 3 * base.peer_load_bytes_per_sec,
            budget: 2 * base.peer_load_bytes_per_sec,
        })
    );
    assert_eq!(sender.stats().admissions_rejected, 1);
    assert_eq!(sender.peer_ids(), vec![7, 8]);
    assert_eq!(playing(&sender), before);
    // the second group leaves: what its peer had queued is counted, and the budget it held is the third group's
    sender
        .remove_group(second)
        .expect("the second group leaves");
    assert_eq!(sender.stats().removed_peer_dropped_packets, 1);
    assert_eq!(sender.group_ids(), vec![PRIMARY_GROUP, third]);
    assert_eq!(sender.peer_ids(), vec![7]);
    sender
        .add_peer_in_group(
            third,
            9,
            addr("127.0.0.1:42005"),
            addr("127.0.0.1:42006"),
            1500,
        )
        .expect("the budget the second group held is free");
    assert_eq!(sender.peer_ids(), vec![7, 9]);
}

#[test]
fn n07_the_aggregate_cap_is_the_interfaces_and_the_longest_queue_pays_in_whichever_group_it_is() {
    let limits = CarrierLimits {
        aggregate_queue_packets: 4,
        ..CarrierLimits::baseline()
    };
    let (mut sender, second) = two_group_sender(limits);
    for index in 0..4 {
        sender
            .submit_media(1, &long_block(index, 0), 0)
            .expect("queued");
    }
    assert_eq!(
        (
            view(&sender, 7).queued_packets,
            view(&sender, 8).queued_packets
        ),
        (4, 0)
    );
    // the second group's frame finds the interface full: the longest queue, which is the other group's, gives up its oldest
    let report = sender
        .submit_group_media(second, SECOND_EPOCH, &long_block(9, 0), 0)
        .expect("queued");
    assert_eq!((report.queued, report.evicted), (1, 1));
    assert_eq!(
        (
            view(&sender, 7).queued_packets,
            view(&sender, 8).queued_packets
        ),
        (3, 1)
    );
    let dropped = |sender: &CarrierSender<ScriptPort>, id: u32| {
        view(sender, id).counters.media_dropped_aggregate_packets
    };
    assert_eq!((dropped(&sender, 7), dropped(&sender, 8)), (1, 0));
    // bounded over a long run that alternates groups, with neither peer starved of room
    for index in 10..60 {
        submit_both(&mut sender, second, index, 0);
        let total = view(&sender, 7).queued_packets + view(&sender, 8).queued_packets;
        assert!(total <= 4, "aggregate {total} packets");
    }
    assert!(view(&sender, 7).queued_packets > 0 && view(&sender, 8).queued_packets > 0);
}

#[test]
fn n07_advancing_one_groups_epoch_fences_only_that_group_and_a_stale_submit_is_refused_by_group() {
    let (mut sender, second) = two_group_sender(CarrierLimits::baseline());
    for index in 0..2 {
        submit_both(&mut sender, second, index, 0);
    }
    assert_eq!(sender.pump(0).media_sent, 4);
    submit_both(&mut sender, second, 2, 0);
    let (a_before, b_before) = (view(&sender, 7), view(&sender, 8));
    assert_eq!(
        (
            a_before.sent_next,
            a_before.queued_packets,
            b_before.sent_next,
            b_before.queued_packets
        ),
        (2, 1, 2, 1)
    );
    sender
        .advance_group_epoch(second, SECOND_EPOCH + 1)
        .expect("the second group moves");
    // the first group is exactly as it was; the second group's peer lost its queue, counted, and numbers again from 0
    assert_eq!(view(&sender, 7), a_before);
    let b = view(&sender, 8);
    assert_eq!(
        (b.queued_packets, b.sent_next, b.reported_next, b.in_flight),
        (0, 0, 0, 0)
    );
    assert_eq!(b.counters.media_dropped_fenced_packets, 1);
    assert_eq!(
        (
            sender.epoch(),
            sender.group_view(second).expect("a group").epoch
        ),
        (1, SECOND_EPOCH + 1)
    );
    // a submit under the epoch a group left, or under another group's epoch, or for no group, is refused and queues nothing
    assert_eq!(
        sender.submit_group_media(second, SECOND_EPOCH, &long_block(3, 0), 0),
        Err(CarrierError::StaleEpoch {
            submitted: SECOND_EPOCH,
            current: SECOND_EPOCH + 1
        })
    );
    assert_eq!(
        sender.submit_media(SECOND_EPOCH, &long_block(3, 0), 0),
        Err(CarrierError::StaleEpoch {
            submitted: SECOND_EPOCH,
            current: 1
        })
    );
    assert_eq!(
        sender.submit_group_media(99, 1, &long_block(3, 0), 0),
        Err(CarrierError::UnknownGroup(99))
    );
    assert_eq!(sender.stats().stale_submits, 2);
    assert!(matches!(
        sender.advance_group_epoch(second, SECOND_EPOCH + 1),
        Err(CarrierError::Stream(StreamError::EpochNotAdvancing { .. }))
    ));
    assert_eq!(
        sender.advance_group_epoch(99, 7),
        Err(CarrierError::UnknownGroup(99))
    );
    // the permitted positives: the second group sends again from 0 under its new epoch, the first carries on from 2
    let now = 1_000_000;
    sender
        .submit_group_media(second, SECOND_EPOCH + 1, &long_block(4, now), now)
        .expect("queued");
    sender
        .submit_media(1, &long_block(3, now), now)
        .expect("queued");
    let from = sender.port.sent.len();
    sender.pump(now);
    let mut first_rx = StreamReceiver::new(key(), stream(), 1);
    let mut second_rx = StreamReceiver::new(other_key(), other_stream(), SECOND_EPOCH + 1);
    let (mut first_seqs, mut second_seqs) = (Vec::new(), Vec::new());
    for (_, wire, to) in &sender.port.sent[from..] {
        if *to == addr("127.0.0.1:42003") {
            second_seqs.push(
                second_rx
                    .accept(wire)
                    .expect("the second group's N01 receiver")
                    .seq,
            );
        } else {
            first_seqs.push(
                first_rx
                    .accept(wire)
                    .expect("the first group's N01 receiver")
                    .seq,
            );
        }
    }
    assert_eq!((first_seqs, second_seqs), (vec![2, 3], vec![0]));
}

#[test]
fn n07_a_report_is_checked_with_the_key_of_the_stream_it_names_and_credits_only_that_streams_peer()
{
    let (mut sender, second) = two_group_sender(CarrierLimits::baseline());
    for index in 0..2 {
        submit_both(&mut sender, second, index, 0);
    }
    assert_eq!(sender.pump(0).media_sent, 4);
    let reported = |sender: &CarrierSender<ScriptPort>, id: u32| view(sender, id).reported_next;

    // peer 7 under the second group's stream and key, and peer 8 under the first's: neither is a member, nothing is credited
    let a_as_b = encode_report(&other_key(), other_stream(), SECOND_EPOCH, 2, 7);
    assert_eq!(feed(&mut sender, &a_as_b), 0);
    let b_as_a = encode_report(&key(), stream(), 1, 2, 8);
    assert_eq!(feed(&mut sender, &b_as_a), 0);
    assert_eq!(sender.stats().reports_unknown_source, 2);
    assert_eq!((reported(&sender, 7), reported(&sender, 8)), (0, 0));
    // the first stream's identity under the second group's key: the tag is checked with the first group's key and fails
    let wrong_key = encode_report(&other_key(), stream(), 1, 2, 7);
    assert_eq!(feed(&mut sender, &wrong_key), 0);
    assert_eq!(sender.stats().reports_bad_tag, 1);
    // a stream no group carries, signed with the primary key (authentic, so a wrong stream), or with the second group's (a bad tag)
    let unknown_primary = encode_report(&key(), third_stream(), 1, 2, 7);
    assert_eq!(feed(&mut sender, &unknown_primary), 0);
    assert_eq!(sender.stats().reports_wrong_stream, 1);
    let unknown_other = encode_report(&other_key(), third_stream(), 1, 2, 8);
    assert_eq!(feed(&mut sender, &unknown_other), 0);
    assert_eq!(sender.stats().reports_bad_tag, 2);
    // the second group's stream under the first group's epoch is stale, and a position beyond what was sent is invalid
    let stale = encode_report(&other_key(), other_stream(), 1, 2, 8);
    assert_eq!(feed(&mut sender, &stale), 0);
    assert_eq!(sender.stats().reports_stale_epoch, 1);
    let beyond = encode_report(&other_key(), other_stream(), SECOND_EPOCH, 3, 8);
    assert_eq!(feed(&mut sender, &beyond), 0);
    assert_eq!(sender.stats().reports_invalid, 1);
    assert_eq!((reported(&sender, 7), reported(&sender, 8)), (0, 0));

    // the permitted positives: each group's genuine report credits its own peer and nobody else's
    let genuine_b = encode_report(&other_key(), other_stream(), SECOND_EPOCH, 2, 8);
    assert_eq!(feed(&mut sender, &genuine_b), 1);
    assert_eq!((reported(&sender, 7), reported(&sender, 8)), (0, 2));
    let genuine_a = encode_report(&key(), stream(), 1, 2, 7);
    assert_eq!(feed(&mut sender, &genuine_a), 1);
    assert_eq!((reported(&sender, 7), reported(&sender, 8)), (2, 2));
    assert_eq!(sender.stats().control_datagrams_in, 9);
}

#[test]
fn n07_a_source_restart_takes_a_fresh_stream_and_a_newer_epoch_and_touches_nothing_else() {
    let (mut sender, second) = two_group_sender(CarrierLimits::baseline());
    for index in 0..2 {
        submit_both(&mut sender, second, index, 0);
    }
    assert_eq!(sender.pump(0).media_sent, 4);
    // peer 7's receiver consumed both and reported, so the restart has a position and a credit to forget
    let seven = addr("127.0.0.1:42001");
    let old_wires: Vec<Vec<u8>> = sender
        .port
        .sent
        .iter()
        .filter(|(_, _, to)| *to == seven)
        .map(|(_, wire, _)| wire.clone())
        .collect();
    let mut receiver = real_receiver();
    assert_eq!(deliver(&mut receiver, &old_wires).len(), 2);
    let old_report = report_of(&mut receiver);
    assert_eq!(feed(&mut sender, &old_report), 1);
    assert_eq!(view(&sender, 7).reported_next, 2);
    sender
        .submit_media(1, &long_block(2, 0), 0)
        .expect("one block still queued at the restart");
    let (b_before, second_before) = (view(&sender, 8), sender.group_view(second));

    sender
        .restart_group(PRIMARY_GROUP, third_stream(), 2)
        .expect("a fresh stream under a newer epoch");
    let a = view(&sender, 7);
    assert_eq!(
        (a.queued_packets, a.sent_next, a.reported_next, a.in_flight),
        (0, 0, 0, 0)
    );
    assert_eq!(a.counters.media_dropped_fenced_packets, 1);
    let primary = sender.group_view(PRIMARY_GROUP).expect("a group");
    assert_eq!(
        (primary.stream_id, primary.epoch),
        (third_stream().get(), 2)
    );
    assert_eq!(
        (view(&sender, 8), sender.group_view(second)),
        (b_before, second_before),
        "the other group is exactly as it was"
    );
    // the old stream's report earns nothing, and a submit under the old epoch is stale
    assert_eq!(feed(&mut sender, &old_report), 0);
    assert_eq!(sender.stats().reports_wrong_stream, 1);
    assert_eq!(view(&sender, 7).reported_next, 0);
    assert_eq!(
        sender.submit_media(1, &long_block(3, 0), 0),
        Err(CarrierError::StaleEpoch {
            submitted: 1,
            current: 2
        })
    );
    // numbering restarted under the new stream: a receiver bound to it admits 0 and 1, and refuses an old-stream wire as a wrong stream
    let now = 1_000_000;
    for index in 3..5 {
        sender
            .submit_media(2, &long_block(index, now), now)
            .expect("queued under the new epoch");
    }
    let from = sender.port.sent.len();
    sender.pump(now);
    let mut bound = StreamReceiver::new(key(), third_stream(), 2);
    let seqs: Vec<u64> = wires_since(&sender, from)
        .iter()
        .map(|wire| {
            bound
                .accept(wire)
                .expect("admitted under the new stream")
                .seq
        })
        .collect();
    assert_eq!(seqs, vec![0, 1]);
    assert!(matches!(
        bound.accept(&old_wires[0]),
        Err(StreamError::WrongStream { .. })
    ));

    // a refusal changes nothing: another group's identity, its own, a stream with no newer epoch, a group that is not there
    let held = (
        sender.group_view(PRIMARY_GROUP),
        sender.peer_view(7),
        sender.stats().epoch_advances,
    );
    assert_eq!(
        sender.restart_group(PRIMARY_GROUP, other_stream(), 3),
        Err(CarrierError::StreamIdInUse(other_stream().get()))
    );
    assert_eq!(
        sender.restart_group(PRIMARY_GROUP, third_stream(), 3),
        Err(CarrierError::StreamIdInUse(third_stream().get()))
    );
    assert!(matches!(
        sender.restart_group(PRIMARY_GROUP, fourth_stream(), 2),
        Err(CarrierError::Stream(StreamError::EpochNotAdvancing {
            requested: 2,
            current: 2
        }))
    ));
    assert_eq!(
        sender.restart_group(77, fourth_stream(), 9),
        Err(CarrierError::UnknownGroup(77))
    );
    assert_eq!(
        (
            sender.group_view(PRIMARY_GROUP),
            sender.peer_view(7),
            sender.stats().epoch_advances
        ),
        held
    );
    // the permitted positive: a fresh identity under a newer epoch is taken again, and a peer fenced for its path stays fenced
    assert_eq!(sender.set_path_mtu(7, 1000), Ok(PathOutcome::Fenced));
    sender
        .restart_group(PRIMARY_GROUP, fourth_stream(), 3)
        .expect("a second restart");
    assert_eq!(
        sender.group_view(PRIMARY_GROUP).expect("a group").stream_id,
        fourth_stream().get()
    );
    assert_eq!(view(&sender, 7).fence, Some(FenceReason::PathMtuTooSmall));
}

#[test]
fn n07_a_receiver_follows_a_source_restart_reports_the_new_stream_from_zero_and_refuses_the_old() {
    let (media, control) = (addr("127.0.0.1:42001"), addr("127.0.0.1:42002"));
    let mut sender = sender_over(ScriptPort::new());
    sender.add_peer(7, media, control, 1500).expect("peer 7");
    let mut receiver = real_receiver();
    for index in 0..4 {
        sender
            .submit_media(1, &full_block(index, 0), 0)
            .expect("queued");
    }
    assert_eq!(sender.pump(0).media_sent, 4);
    let old_wires = wires_since(&sender, 0);
    assert_eq!(deliver(&mut receiver, &old_wires[..3]).len(), 3);
    assert_eq!(receiver.consumed_next(), 3);
    // a fourth datagram of the old stream is read but not yet taken: the restart drops it
    receiver
        .port
        .inbound_media
        .push_back((old_wires[3].clone(), None));
    receiver.poll();
    assert_eq!(receiver.inbound_len(), 1);

    sender
        .restart_group(PRIMARY_GROUP, third_stream(), 2)
        .expect("a fresh stream under a newer epoch");
    receiver.restart_stream(third_stream(), 2);
    assert_eq!((receiver.inbound_len(), receiver.consumed_next()), (0, 0));
    // the old stream's datagrams are refused as a wrong stream, and nothing is taken from them
    let before = receiver.stream_counters().rejected_wrong_stream;
    assert!(deliver(&mut receiver, &old_wires).is_empty());
    assert_eq!(receiver.stream_counters().rejected_wrong_stream, before + 4);
    // the new stream's first datagram is admitted from 0 under the new epoch
    let now = 1_000_000;
    sender
        .submit_media(2, &full_block(5, now), now)
        .expect("queued under the new epoch");
    let from = sender.port.sent.len();
    sender.pump(now);
    let packets = deliver(&mut receiver, &wires_since(&sender, from));
    assert_eq!(packets.len(), 1);
    assert_eq!(
        (
            packets[0].seq,
            packets[0].stream_id,
            packets[0].session_epoch
        ),
        (0, third_stream(), 2)
    );
    // the receiver's report names the new stream at its own position, and the restarted peer takes it as credit
    let report = report_of(&mut receiver);
    assert_eq!(
        parse_report(&key(), &report),
        Ok(Report {
            stream_id: third_stream().get(),
            epoch: 2,
            consumed_next: 1,
            peer: 7
        })
    );
    assert_eq!(feed(&mut sender, &report), 1);
    assert_eq!(view(&sender, 7).reported_next, 1);
}

#[test]
fn n07_group_membership_is_bounded_and_each_refusal_changes_nothing() {
    let limits = CarrierLimits {
        max_peers: 2,
        ..CarrierLimits::baseline()
    };
    let table = limits.max_group_table_bytes();
    let mut sender =
        CarrierSender::with_port(key(), stream(), 1, limits, ScriptPort::new()).expect("sender");
    // the group table is allocated at its bound when the sender is built, with the primary group in it
    assert!(table > 0);
    assert_eq!(sender.group_table_bytes(), table);
    // a stream identity is one group's: the primary's cannot be reused, and neither can another's
    assert_eq!(
        sender.add_group(other_key(), stream(), 3),
        Err(CarrierError::StreamIdInUse(stream().get()))
    );
    let second = sender
        .add_group(other_key(), other_stream(), 3)
        .expect("a second group");
    assert_eq!(
        sender.add_group(key(), other_stream(), 4),
        Err(CarrierError::StreamIdInUse(other_stream().get()))
    );
    // the groups are bounded by the peer cap, because each group that matters holds a peer
    assert_eq!(
        sender.add_group(key(), third_stream(), 4),
        Err(CarrierError::TooManyGroups { max: 2 })
    );
    assert_eq!(sender.group_ids(), vec![PRIMARY_GROUP, second]);
    // the primary group is fixed, and a group that is not there is refused wherever it is named
    assert_eq!(
        sender.remove_group(PRIMARY_GROUP),
        Err(CarrierError::PrimaryGroupIsFixed)
    );
    assert_eq!(sender.remove_group(40), Err(CarrierError::UnknownGroup(40)));
    let (media, control) = (addr("127.0.0.1:42001"), addr("127.0.0.1:42002"));
    assert_eq!(
        sender.add_peer_in_group(40, 7, media, control, 1500),
        Err(CarrierError::UnknownGroup(40))
    );
    // a peer id is the interface's: the same id in another group is a duplicate
    sender.add_peer(7, media, control, 1500).expect("peer 7");
    assert_eq!(
        sender.add_peer_in_group(
            second,
            7,
            addr("127.0.0.1:42003"),
            addr("127.0.0.1:42004"),
            1500
        ),
        Err(CarrierError::DuplicatePeer(7))
    );
    assert_eq!(sender.stats().admissions_rejected, 2);
    assert_eq!(sender.peer_ids(), vec![7]);
    // leaving gives the room back, and a group id is never reused
    sender
        .remove_group(second)
        .expect("the second group leaves");
    let third = sender
        .add_group(key(), third_stream(), 4)
        .expect("room again");
    assert!(third > second);
    assert_eq!(sender.group_ids(), vec![PRIMARY_GROUP, third]);
    // groups came, were refused and left, and the table neither grew nor shrank
    assert_eq!(sender.group_table_bytes(), table);
}

fn clocked_n01_pump(
    sender: &mut CarrierSender<ScriptPort>,
    interface_now: u64,
    group_now: u64,
) -> PumpReport {
    let view = N01GroupClock {
        group: PRIMARY_GROUP,
        epoch: 1,
        view: crate::playout::ClockView {
            group_ns: group_now,
            uncertainty_ns: 500_000,
            usable: true,
        },
    };
    sender.pump_n01_clocked(interface_now, &[view], &AtomicBool::new(false))
}

#[allow(clippy::too_many_arguments)]
fn attempt_n01(
    sender: &mut CarrierSender<ScriptPort>,
    group: GroupId,
    epoch: u64,
    required: &[u32],
    frame: &OutboundFrame,
    interface_now: u64,
    group_now: u64,
    budget: usize,
    cancel: &AtomicBool,
) -> Result<AllPeerAdmission, AllPeerAdmissionError> {
    let current = sender
        .group_view(group)
        .ok_or(AllPeerAdmissionError::Invalid(CarrierError::UnknownGroup(
            group,
        )))?;
    let ids: Vec<_> = sender
        .peers
        .iter()
        .filter(|p| p.group == group)
        .map(|p| p.id)
        .collect();
    let snapshot = sender.snapshot_n01_group(group, current.epoch, &ids)?;
    sender.try_submit_group_media_all(
        group,
        epoch,
        &snapshot,
        required,
        frame,
        N01AdmissionInputs {
            interface_now_ns: interface_now,
            trusted_group_now_ns: group_now,
            overlap_budget_bytes: budget,
            cancelled: cancel,
        },
    )
}

#[test]
fn n07_all_peer_n01_backpressure_preserves_queues_then_delivers_each_pcm_once() {
    let limits = CarrierLimits {
        window_packets: 1,
        peer_queue_packets: 1,
        pace_burst_bytes: 65_536,
        ..CarrierLimits::baseline()
    };
    let mut sender =
        CarrierSender::with_port(key(), stream(), 1, limits, ScriptPort::new()).unwrap();
    let m1 = addr("127.0.0.1:42001");
    let c1 = addr("127.0.0.1:42002");
    let m2 = addr("127.0.0.1:42003");
    let c2 = addr("127.0.0.1:42004");
    sender.add_peer(7, m1, c1, 1500).unwrap();
    sender.add_peer(8, m2, c2, 1500).unwrap();
    let mut first = long_block(0, 0);
    first.payload.fill(0x21);
    let mut queued = long_block(1, 0);
    queued.payload.fill(0x42);
    let mut pending = long_block(2, 0);
    pending.payload.fill(0x63);
    let pending_copy = pending.clone();
    let cancel = AtomicBool::new(false);
    assert_eq!(sender.submit_media(1, &first, 0).unwrap().queued, 2);
    assert_eq!(sender.pump(1).media_sent, 2);
    sender
        .port
        .inbound_control
        .push_back((encode_report(&key(), stream(), 1, 1, 7).to_vec(), Some(c1)));
    assert_eq!(sender.poll_reports(), 1);
    assert_eq!(sender.submit_media(1, &queued, 2).unwrap().queued, 2);
    assert_eq!(sender.pump(3).media_sent, 1);
    assert_eq!(sender.peer_view(7).unwrap().queued_packets, 0);
    assert_eq!(sender.peer_view(8).unwrap().queued_packets, 1);
    let before_group = sender.group_view(PRIMARY_GROUP).unwrap();
    let before_7 = sender.peer_view(7).unwrap();
    let before_8 = sender.peer_view(8).unwrap();
    assert_eq!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[7, 8],
            &pending,
            4,
            0,
            usize::MAX,
            &cancel
        )
        .map(|_| ()),
        Err(AllPeerAdmissionError::Retry(AllPeerRetry::Capacity))
    );
    assert_eq!(pending, pending_copy);
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before_group);
    assert_eq!(sender.peer_view(7).unwrap(), before_7);
    assert_eq!(sender.peer_view(8).unwrap(), before_8);
    sender
        .port
        .inbound_control
        .push_back((encode_report(&key(), stream(), 1, 2, 7).to_vec(), Some(c1)));
    sender
        .port
        .inbound_control
        .push_back((encode_report(&key(), stream(), 1, 1, 8).to_vec(), Some(c2)));
    assert_eq!(sender.poll_reports(), 2);
    assert_eq!(sender.pump(5).media_sent, 1);
    sender
        .port
        .inbound_control
        .push_back((encode_report(&key(), stream(), 1, 2, 8).to_vec(), Some(c2)));
    assert_eq!(sender.poll_reports(), 1);
    assert_eq!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[8, 7],
            &pending,
            6,
            0,
            usize::MAX,
            &cancel
        )
        .map(|_| ()),
        Ok(())
    );
    assert_eq!(pending, pending_copy);
    assert_eq!(clocked_n01_pump(&mut sender, 7, 7).media_sent, 2);
    for destination in [m1, m2] {
        let mut receiver = StreamReceiver::new(key(), stream(), 1);
        let packets: Vec<_> = sender
            .port
            .sent
            .iter()
            .filter(|(lane, _, to)| *lane == Lane::Media && *to == destination)
            .map(|(_, wire, _)| receiver.accept(wire).unwrap())
            .collect();
        assert_eq!(packets.len(), 3);
        assert_eq!(
            packets.iter().map(|p| p.seq).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(packets[0].payload, first.payload);
        assert_eq!(packets[1].payload, queued.payload);
        assert_eq!(packets[2].payload, pending.payload);
    }
}

#[test]
fn n07_all_peer_n01_invalid_stale_cancel_and_membership_refuse_before_mutation() {
    let mut sender = sender_over(ScriptPort::new());
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    sender
        .add_peer(8, addr("127.0.0.1:42003"), addr("127.0.0.1:42004"), 1500)
        .unwrap();
    let cancel = AtomicBool::new(false);
    let good = long_block(0, 0);
    let before = sender.group_view(PRIMARY_GROUP).unwrap();
    let first = sender.peer_view(7).unwrap();
    let second = sender.peer_view(8).unwrap();
    assert_eq!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[7, 7],
            &good,
            0,
            0,
            usize::MAX,
            &cancel
        )
        .map(|_| ()),
        Err(AllPeerAdmissionError::MembershipChanged)
    );
    assert_eq!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[7],
            &good,
            0,
            0,
            usize::MAX,
            &cancel
        )
        .map(|_| ()),
        Err(AllPeerAdmissionError::MembershipChanged)
    );
    assert!(matches!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            2,
            &[7, 8],
            &good,
            0,
            0,
            usize::MAX,
            &cancel
        )
        .map(|_| ()),
        Err(AllPeerAdmissionError::Invalid(
            CarrierError::StaleEpoch { .. }
        ))
    ));
    cancel.store(true, Ordering::Release);
    assert_eq!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[7, 8],
            &good,
            0,
            0,
            usize::MAX,
            &cancel
        )
        .map(|_| ()),
        Err(AllPeerAdmissionError::Cancelled)
    );
    cancel.store(false, Ordering::Release);
    for malformed in [
        {
            let mut f = good.clone();
            f.start_frame = 1;
            f
        },
        {
            let mut f = good.clone();
            f.flags = 0x80;
            f
        },
        {
            let mut f = good.clone();
            f.consume_by_ns = f.presentation_time_ns + 1;
            f
        },
        {
            let mut f = good.clone();
            f.fec_index = 1;
            f
        },
        {
            let mut f = good.clone();
            f.payload.pop();
            f
        },
    ] {
        assert!(matches!(
            attempt_n01(
                &mut sender,
                PRIMARY_GROUP,
                1,
                &[7, 8],
                &malformed,
                0,
                0,
                usize::MAX,
                &cancel
            )
            .map(|_| ()),
            Err(AllPeerAdmissionError::Invalid(_))
        ));
    }
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before);
    assert_eq!(sender.peer_view(7).unwrap(), first);
    assert_eq!(sender.peer_view(8).unwrap(), second);
    assert_eq!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[7, 8],
            &good,
            0,
            0,
            usize::MAX,
            &cancel
        )
        .map(|_| ()),
        Ok(())
    );
    assert_eq!(clocked_n01_pump(&mut sender, 1, 1).media_sent, 2);
    for (_, wire, _) in &sender.port.sent {
        assert_eq!(
            StreamReceiver::new(key(), stream(), 1)
                .accept(wire)
                .unwrap()
                .payload,
            good.payload
        );
    }
}

#[test]
fn n07_all_peer_n01_respects_profile_sequence_headroom_and_live_path() {
    let mut sender = sender_over(ScriptPort::new());
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    sender
        .add_peer(8, addr("127.0.0.1:42003"), addr("127.0.0.1:42004"), 1500)
        .unwrap();
    let cancel = AtomicBool::new(false);
    let good = long_block(0, 0);
    let mut partial = good.clone();
    partial.payload.truncate(512);
    let idx = sender.index_of(8).unwrap();
    sender.peers[idx].counters.media_submitted_packets = u64::MAX;
    assert!(matches!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[7, 8],
            &good,
            0,
            0,
            usize::MAX,
            &cancel
        ),
        Err(AllPeerAdmissionError::Invalid(_))
    ));
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 0);
    sender.peers[idx].counters.media_submitted_packets = 0;
    sender.peers[idx].sender.profile = crate::StreamProfile {
        repair_allowed: true,
        partial_blocks_allowed: false,
    };
    assert!(matches!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[7, 8],
            &partial,
            0,
            0,
            usize::MAX,
            &cancel
        )
        .map(|_| ()),
        Err(AllPeerAdmissionError::Invalid(CarrierError::Stream(
            StreamError::FeatureNotNegotiated { .. }
        )))
    ));
    sender.peers[idx].sender.profile = crate::StreamProfile::BASELINE;
    sender.peers[idx].sender.epoch = 2;
    assert!(matches!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[7, 8],
            &good,
            0,
            0,
            usize::MAX,
            &cancel
        )
        .map(|_| ()),
        Err(AllPeerAdmissionError::Invalid(
            CarrierError::StaleEpoch { .. }
        ))
    ));
    sender.peers[idx].sender.epoch = 1;
    sender.set_link_up(false);
    assert_eq!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[7, 8],
            &good,
            0,
            0,
            usize::MAX,
            &cancel
        )
        .map(|_| ()),
        Err(AllPeerAdmissionError::Retry(AllPeerRetry::LinkDown))
    );
    sender.set_link_up(true);
    sender.set_path_mtu(8, 1000).unwrap();
    assert_eq!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[7, 8],
            &good,
            0,
            0,
            usize::MAX,
            &cancel
        )
        .map(|_| ()),
        Err(AllPeerAdmissionError::Retry(AllPeerRetry::PeerFenced(8)))
    );
    sender.set_path_mtu(8, 1500).unwrap();
    sender.peers[idx].sender.next_seq = u64::MAX - 1;
    assert_eq!(sender.submit_media(1, &good, 0).unwrap().queued, 2);
    let before = sender.group_view(PRIMARY_GROUP).unwrap();
    assert_eq!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[7, 8],
            &good,
            0,
            0,
            usize::MAX,
            &cancel
        )
        .map(|_| ()),
        Err(AllPeerAdmissionError::Invalid(CarrierError::Stream(
            StreamError::SequenceExhausted
        )))
    );
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before);
    sender.peers[idx].sender.next_seq = 0;
    assert_eq!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[7, 8],
            &good,
            0,
            0,
            usize::MAX,
            &cancel
        )
        .map(|_| ()),
        Ok(())
    );
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 4);
}

#[test]
fn n07_all_peer_n01_membership_change_and_unfenced_small_mtu_are_checked() {
    let limits = CarrierLimits {
        required_payload_bytes: 4,
        ..CarrierLimits::baseline()
    };
    let mut sender =
        CarrierSender::with_port(key(), stream(), 1, limits, ScriptPort::new()).unwrap();
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    sender
        .add_peer(8, addr("127.0.0.1:42003"), addr("127.0.0.1:42004"), 900)
        .unwrap();
    let cancel = AtomicBool::new(false);
    let full = long_block(0, 0);
    let before = sender.group_view(PRIMARY_GROUP).unwrap();
    assert_eq!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[7, 8],
            &full,
            0,
            0,
            usize::MAX,
            &cancel
        )
        .map(|_| ()),
        Err(AllPeerAdmissionError::Retry(AllPeerRetry::PathMtu(8)))
    );
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before);
    let mut partial = full.clone();
    partial.payload.truncate(512);
    assert_eq!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[7, 8],
            &partial,
            0,
            0,
            usize::MAX,
            &cancel
        )
        .map(|_| ()),
        Ok(())
    );
    assert_eq!(clocked_n01_pump(&mut sender, 1, 1).media_sent, 2);
    for (_, wire, _) in &sender.port.sent {
        assert_eq!(
            StreamReceiver::new(key(), stream(), 1)
                .accept(wire)
                .unwrap()
                .payload,
            partial.payload
        );
    }
    sender.remove_peer(8).unwrap();
    let changed = sender.group_view(PRIMARY_GROUP).unwrap();
    assert_eq!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[7, 8],
            &partial,
            2,
            0,
            usize::MAX,
            &cancel
        )
        .map(|_| ()),
        Err(AllPeerAdmissionError::MembershipChanged)
    );
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), changed);
    sender.advance_epoch(2).unwrap();
    assert_eq!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            2,
            &[7],
            &partial,
            2,
            2,
            usize::MAX,
            &cancel
        )
        .map(|_| ()),
        Ok(())
    );
    let clock = N01GroupClock {
        group: PRIMARY_GROUP,
        epoch: 2,
        view: crate::playout::ClockView {
            group_ns: 3,
            uncertainty_ns: 0,
            usable: true,
        },
    };
    assert_eq!(sender.pump_n01_clocked(3, &[clock], &cancel).media_sent, 1);
}

#[test]
fn n07_all_peer_n01_repair_refused_and_overlap_capacity_exact_boundary() {
    let mut sender = sender_over(ScriptPort::new());
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    sender
        .add_peer(8, addr("127.0.0.1:42003"), addr("127.0.0.1:42004"), 1500)
        .unwrap();
    assert_eq!(
        sender.submit_media(1, &long_block(0, 0), 0).unwrap().queued,
        2
    );
    let snapshot = sender
        .snapshot_n01_group(PRIMARY_GROUP, 1, &[7, 8])
        .unwrap();
    let cancel = AtomicBool::new(false);
    let good = long_block(1, 0);
    let good_copy = good.clone();
    let before = sender.group_view(PRIMARY_GROUP).unwrap();
    let first = sender.peer_view(7).unwrap();
    let second = sender.peer_view(8).unwrap();
    let mut repair = good.clone();
    repair.kind = crate::PacketKind::Repair;
    repair.fec_group_size = 1;
    assert!(matches!(
        sender.try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &repair,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel
            }
        ),
        Err(AllPeerAdmissionError::Invalid(_))
    ));
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before);
    assert_eq!(sender.peer_view(7).unwrap(), first);
    assert_eq!(sender.peer_view(8).unwrap(), second);
    // Observe trusted time on the actual public rejection path before the same-allocation test.
    assert_eq!(
        sender.try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &good,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: 0,
                cancelled: &cancel
            }
        ),
        Err(AllPeerAdmissionError::Retry(AllPeerRetry::Budget))
    );
    let mut staged = Some(
        sender
            .prepare_n01_queues(PRIMARY_GROUP, &[7, 8], &good, 0, usize::MAX)
            .unwrap(),
    );
    let exact = staged.as_ref().unwrap().accounted_bytes;
    assert!(exact > good.payload.len() * 2);
    assert_eq!(
        sender.commit_n01_queues(
            PRIMARY_GROUP,
            1,
            &snapshot,
            0,
            exact - 1,
            &cancel,
            &mut staged
        ),
        Err(AllPeerAdmissionError::Retry(AllPeerRetry::Budget))
    );
    assert!(staged.is_some());
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before);
    assert_eq!(sender.peer_view(7).unwrap(), first);
    assert_eq!(sender.peer_view(8).unwrap(), second);
    assert_eq!(good, good_copy);
    assert_eq!(
        sender.commit_n01_queues_inner(
            PRIMARY_GROUP,
            1,
            &snapshot,
            0,
            exact,
            &cancel,
            &mut staged,
            || cancel.store(true, Ordering::Release)
        ),
        Err(AllPeerAdmissionError::Cancelled)
    );
    assert!(staged.is_some());
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before);
    assert_eq!(sender.peer_view(7).unwrap(), first);
    assert_eq!(sender.peer_view(8).unwrap(), second);
    cancel.store(false, Ordering::Release);
    cancel.store(true, Ordering::Release);
    assert_eq!(
        sender.commit_n01_queues(PRIMARY_GROUP, 1, &snapshot, 0, exact, &cancel, &mut staged),
        Err(AllPeerAdmissionError::Cancelled)
    );
    cancel.store(false, Ordering::Release);
    sender.set_link_up(false);
    assert_eq!(
        sender.commit_n01_queues(PRIMARY_GROUP, 1, &snapshot, 0, exact, &cancel, &mut staged),
        Err(AllPeerAdmissionError::Retry(AllPeerRetry::LinkDown))
    );
    sender.set_link_up(true);
    assert!(staged.is_some());
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before);
    let admitted = sender
        .commit_n01_queues(PRIMARY_GROUP, 1, &snapshot, 0, exact, &cancel, &mut staged)
        .unwrap();
    assert_eq!(admitted.accounted_overlap_bytes, exact);
    assert!(staged.is_none());
    assert_eq!(clocked_n01_pump(&mut sender, 1, 1).media_sent, 4);
    for destination in [addr("127.0.0.1:42001"), addr("127.0.0.1:42003")] {
        let mut receiver = StreamReceiver::new(key(), stream(), 1);
        let packets: Vec<_> = sender
            .port
            .sent
            .iter()
            .filter(|(_, _, to)| *to == destination)
            .map(|(_, wire, _)| receiver.accept(wire).unwrap())
            .collect();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[1].payload, good.payload);
    }
}

#[test]
fn n07_all_peer_n01_deadline_uses_separate_group_and_interface_clocks() {
    let mut sender = sender_over(ScriptPort::new());
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    let cancel = AtomicBool::new(false);
    let mut frame = long_block(0, 0);
    frame.consume_by_ns =
        crate::playout::consume_by(frame.presentation_time_ns, 1_000_000, 1_000_000, 500_000);
    let interface_now = frame.consume_by_ns + 1_000_000_000;
    assert!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[7],
            &frame,
            interface_now,
            frame.consume_by_ns - 1,
            usize::MAX,
            &cancel
        )
        .is_ok()
    );
    let before = sender.group_view(PRIMARY_GROUP).unwrap();
    assert!(matches!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[7],
            &frame,
            interface_now,
            frame.consume_by_ns,
            usize::MAX,
            &cancel
        ),
        Err(AllPeerAdmissionError::Invalid(_))
    ));
    assert!(matches!(
        attempt_n01(
            &mut sender,
            PRIMARY_GROUP,
            1,
            &[7],
            &frame,
            interface_now,
            frame.consume_by_ns + 1,
            usize::MAX,
            &cancel
        ),
        Err(AllPeerAdmissionError::Invalid(_))
    ));
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before);
    let queued = sender.peers[sender.index_of(7).unwrap()]
        .media_q
        .front()
        .unwrap();
    assert_eq!(queued.enqueued_ns, interface_now);
    assert_eq!(queued.frame.consume_by_ns, frame.consume_by_ns);
}

#[test]
fn n07_all_peer_snapshot_fences_foreign_sender_and_same_id_aba() {
    fn fixture() -> CarrierSender<ScriptPort> {
        let mut sender = sender_over(ScriptPort::new());
        sender
            .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
            .unwrap();
        sender
            .add_peer(8, addr("127.0.0.1:42003"), addr("127.0.0.1:42004"), 1500)
            .unwrap();
        sender
    }
    let mut sender = fixture();
    let mut foreign = fixture();
    let snapshot = sender
        .snapshot_n01_group(PRIMARY_GROUP, 1, &[7, 8])
        .unwrap();
    let frame = long_block(0, 0);
    let cancel = AtomicBool::new(false);
    let other_before = foreign.group_view(PRIMARY_GROUP).unwrap();
    assert!(sender.owns_n01_snapshot(&snapshot));
    assert!(!foreign.owns_n01_snapshot(&snapshot));
    assert_eq!(
        foreign.fence_n01_group(PRIMARY_GROUP, 1, &snapshot),
        Err(AllPeerAdmissionError::MembershipChanged)
    );
    assert_eq!(foreign.group_view(PRIMARY_GROUP).unwrap(), other_before);
    assert_eq!(
        foreign.try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel
            }
        ),
        Err(AllPeerAdmissionError::MembershipChanged)
    );
    assert_eq!(foreign.group_view(PRIMARY_GROUP).unwrap(), other_before);
    assert_eq!(
        sender.try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: 0,
                cancelled: &cancel
            }
        ),
        Err(AllPeerAdmissionError::Retry(AllPeerRetry::Budget))
    );
    assert!(
        sender
            .try_submit_group_media_all(
                PRIMARY_GROUP,
                1,
                &snapshot,
                &[7, 8],
                &frame,
                N01AdmissionInputs {
                    interface_now_ns: 0,
                    trusted_group_now_ns: 0,
                    overlap_budget_bytes: usize::MAX,
                    cancelled: &cancel
                }
            )
            .is_ok()
    );
    let before_aba = sender
        .snapshot_n01_group(PRIMARY_GROUP, 1, &[7, 8])
        .unwrap();
    sender.remove_peer(8).unwrap();
    sender
        .add_peer(8, addr("127.0.0.1:42003"), addr("127.0.0.1:42004"), 1500)
        .unwrap();
    let before = sender.group_view(PRIMARY_GROUP).unwrap();
    assert_eq!(
        sender.try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &before_aba,
            &[7, 8],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel
            }
        ),
        Err(AllPeerAdmissionError::MembershipChanged)
    );
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before);
    assert_eq!(clocked_n01_pump(&mut sender, 1, 1).media_sent, 0);
    assert!(matches!(
        sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7, 8]),
        Err(AllPeerAdmissionError::MembershipChanged)
    ));
    sender.advance_epoch(2).unwrap();
    assert!(sender.owns_n01_snapshot(&before_aba));
    assert!(!foreign.owns_n01_snapshot(&before_aba));
    let route = sender
        .snapshot_n01_group(PRIMARY_GROUP, 2, &[7, 8])
        .unwrap();
    sender
        .peer_address_changed(8, addr("127.0.0.1:42103"), addr("127.0.0.1:42104"))
        .unwrap();
    sender
        .peer_address_changed(8, addr("127.0.0.1:42003"), addr("127.0.0.1:42004"))
        .unwrap();
    assert_eq!(
        sender.try_submit_group_media_all(
            PRIMARY_GROUP,
            2,
            &route,
            &[7, 8],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel
            }
        ),
        Err(AllPeerAdmissionError::MembershipChanged)
    );
    let fresh = sender
        .snapshot_n01_group(PRIMARY_GROUP, 2, &[7, 8])
        .unwrap();
    assert!(
        sender
            .try_submit_group_media_all(
                PRIMARY_GROUP,
                2,
                &fresh,
                &[7, 8],
                &frame,
                N01AdmissionInputs {
                    interface_now_ns: 0,
                    trusted_group_now_ns: 0,
                    overlap_budget_bytes: usize::MAX,
                    cancelled: &cancel
                }
            )
            .is_ok()
    );
    sender.n01_binding_generation = u64::MAX;
    assert!(matches!(
        sender.snapshot_n01_group(PRIMARY_GROUP, 2, &[7, 8]),
        Err(AllPeerAdmissionError::MembershipChanged)
    ));
    assert_eq!(
        sender.try_submit_group_media_all(
            PRIMARY_GROUP,
            2,
            &fresh,
            &[7, 8],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel
            }
        ),
        Err(AllPeerAdmissionError::MembershipChanged)
    );
}

#[test]
fn n07_clocked_n01_pump_uses_group_deadline_and_delivers_real_pcm() {
    use crate::playout::{
        Admission, ClockView, MediaPacket, Outcome, PlayoutConfig, PlayoutEngine, PlayoutProfile,
        Poll,
    };
    for (interface_now, group_now) in [
        (5_000_000_000, 1_000_000_000),
        (1_000_000_000, 3_000_000_000),
    ] {
        let mut sender = sender_over(ScriptPort::new());
        sender
            .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
            .unwrap();
        let snapshot = sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]).unwrap();
        let mut frame = long_block(0, 0);
        frame.consume_by_ns =
            crate::playout::consume_by(frame.presentation_time_ns, 1_000_000, 1_000_000, 500_000);
        let cancel = AtomicBool::new(false);
        sender
            .try_submit_group_media_all(
                PRIMARY_GROUP,
                1,
                &snapshot,
                &[7],
                &frame,
                N01AdmissionInputs {
                    interface_now_ns: interface_now,
                    trusted_group_now_ns: group_now,
                    overlap_budget_bytes: usize::MAX,
                    cancelled: &cancel,
                },
            )
            .unwrap();
        // Legacy pumping cannot consume or expire a group-clock-required frame.
        assert_eq!(sender.pump(interface_now).media_sent, 0);
        assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 1);
        assert_eq!(
            clocked_n01_pump(&mut sender, interface_now + 1, group_now).media_sent,
            1
        );
        let wire = &sender.port.sent[0].1;
        let packet = StreamReceiver::new(key(), stream(), 1)
            .accept(wire)
            .unwrap();
        let mut playout = PlayoutEngine::new(
            PlayoutProfile::MUSIC,
            PlayoutConfig {
                work_ns: 1_000_000,
                lead_ns: 1_000_000,
                tolerance_ns: 0,
            },
        )
        .unwrap();
        playout
            .begin_stream(1, 0, frame.presentation_time_ns)
            .unwrap();
        let view = ClockView {
            group_ns: group_now,
            uncertainty_ns: 500_000,
            usable: true,
        };
        assert_eq!(
            playout.on_packet(view, &MediaPacket::from_authenticated(&packet).unwrap()),
            Admission::Admitted
        );
        let mut pcm = [0_u8; crate::playout::BLOCK_PAYLOAD_BYTES];
        let cutoff = ClockView {
            group_ns: frame.consume_by_ns,
            ..view
        };
        let Poll::Decision(decision) = playout.decide(cutoff, &mut pcm) else {
            panic!("missing real playout decision");
        };
        assert_eq!(decision.outcome, Outcome::Real);
        assert_eq!(&pcm[..], &frame.payload[..]);
    }
}

#[test]
fn n07_clocked_n01_rejects_missing_wrong_duplicate_and_late_views() {
    let mut sender = sender_over(ScriptPort::new());
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    let snapshot = sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]).unwrap();
    let frame = long_block(0, 0);
    let cancel = AtomicBool::new(false);
    sender
        .try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    let good = N01GroupClock {
        group: PRIMARY_GROUP,
        epoch: 1,
        view: crate::playout::ClockView {
            group_ns: frame.consume_by_ns - 1,
            uncertainty_ns: 0,
            usable: true,
        },
    };
    let wrong = N01GroupClock { epoch: 2, ..good };
    let unusable = N01GroupClock {
        view: crate::playout::ClockView {
            usable: false,
            ..good.view
        },
        ..good
    };
    for clocks in [&[][..], &[wrong][..], &[unusable][..], &[good, good][..]] {
        assert_eq!(
            sender
                .pump_n01_clocked(3_000_000_000, clocks, &cancel)
                .media_sent,
            0
        );
        assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 1);
    }
    cancel.store(true, Ordering::Release);
    assert_eq!(
        sender
            .pump_n01_clocked(3_000_000_000, &[good], &cancel)
            .media_sent,
        0
    );
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 1);
    cancel.store(false, Ordering::Release);
    let equal = N01GroupClock {
        view: crate::playout::ClockView {
            group_ns: frame.consume_by_ns,
            ..good.view
        },
        ..good
    };
    let out = sender.pump_n01_clocked(3_000_000_001, &[equal], &cancel);
    assert_eq!((out.media_sent, out.late_dropped), (0, 1));
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 0);
    assert!(sender.port.sent.is_empty());
}

#[test]
fn n07_clocked_n01_held_retry_respects_group_cutoff() {
    for expire in [false, true] {
        let mut sender = sender_over(ScriptPort::new());
        sender
            .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
            .unwrap();
        let snapshot = sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]).unwrap();
        let frame = long_block(0, 0);
        let cancel = AtomicBool::new(false);
        sender
            .try_submit_group_media_all(
                PRIMARY_GROUP,
                1,
                &snapshot,
                &[7],
                &frame,
                N01AdmissionInputs {
                    interface_now_ns: 0,
                    trusted_group_now_ns: 0,
                    overlap_budget_bytes: usize::MAX,
                    cancelled: &cancel,
                },
            )
            .unwrap();
        sender.port.send_fault = Some(PortFault::WouldBlock);
        assert_eq!(
            clocked_n01_pump(&mut sender, 1, frame.consume_by_ns - 2).media_sent,
            0
        );
        assert!(sender.peers[sender.index_of(7).unwrap()].held.is_some());
        sender.port.send_fault = None;
        let group_now = if expire {
            frame.consume_by_ns
        } else {
            frame.consume_by_ns - 1
        };
        let result = clocked_n01_pump(&mut sender, 2, group_now);
        if expire {
            assert_eq!((result.media_sent, result.late_dropped), (0, 1));
            assert!(sender.port.sent.is_empty());
        } else {
            assert_eq!(result.media_sent, 1);
            let packet = StreamReceiver::new(key(), stream(), 1)
                .accept(&sender.port.sent[0].1)
                .unwrap();
            assert_eq!(packet.payload, frame.payload);
        }
    }
}

#[test]
fn n07_clocked_n01_backward_view_fences_until_fresh_epoch() {
    let mut sender = sender_over(ScriptPort::new());
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    let snapshot = sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]).unwrap();
    let frame = long_block(0, 0);
    let cancel = AtomicBool::new(false);
    sender
        .try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    sender.port.send_fault = Some(PortFault::WouldBlock);
    assert_eq!(clocked_n01_pump(&mut sender, 1, 1000).media_sent, 0);
    sender.port.send_fault = None;
    assert_eq!(clocked_n01_pump(&mut sender, 2, 999).media_sent, 0);
    assert_eq!(clocked_n01_pump(&mut sender, 3, 1001).media_sent, 0);
    assert!(sender.port.sent.is_empty());
    assert!(matches!(
        sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]),
        Err(AllPeerAdmissionError::MembershipChanged)
    ));
    sender.advance_epoch(2).unwrap();
    let fresh = sender.snapshot_n01_group(PRIMARY_GROUP, 2, &[7]).unwrap();
    sender
        .try_submit_group_media_all(
            PRIMARY_GROUP,
            2,
            &fresh,
            &[7],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 4,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    let clock = N01GroupClock {
        group: PRIMARY_GROUP,
        epoch: 2,
        view: crate::playout::ClockView {
            group_ns: 1,
            uncertainty_ns: 0,
            usable: true,
        },
    };
    assert_eq!(sender.pump_n01_clocked(5, &[clock], &cancel).media_sent, 1);
    assert_eq!(
        StreamReceiver::new(key(), stream(), 2)
            .accept(&sender.port.sent[0].1)
            .unwrap()
            .payload,
        frame.payload
    );
}

#[test]
fn n07_all_peer_admission_observes_retry_time_and_latches_rollback() {
    for first_budget in [usize::MAX, 0] {
        let mut sender = sender_over(ScriptPort::new());
        sender
            .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
            .unwrap();
        let snapshot = sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]).unwrap();
        let cancel = AtomicBool::new(false);
        let mut frame = long_block(0, 0);
        frame.consume_by_ns = 250;
        let first = sender.try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 200,
                overlap_budget_bytes: first_budget,
                cancelled: &cancel,
            },
        );
        if first_budget == 0 {
            assert_eq!(
                first,
                Err(AllPeerAdmissionError::Retry(AllPeerRetry::Budget))
            );
        } else {
            assert!(first.is_ok());
        }
        let before = sender.group_view(PRIMARY_GROUP).unwrap();
        let counters = sender.peer_view(7).unwrap();
        frame.consume_by_ns = 150;
        let backwards = if first_budget == 0 { 150 } else { 100 };
        assert!(matches!(
            sender.try_submit_group_media_all(
                PRIMARY_GROUP,
                1,
                &snapshot,
                &[7],
                &frame,
                N01AdmissionInputs {
                    interface_now_ns: 0,
                    trusted_group_now_ns: backwards,
                    overlap_budget_bytes: usize::MAX,
                    cancelled: &cancel
                }
            ),
            Err(AllPeerAdmissionError::Invalid(_))
        ));
        assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before);
        assert_eq!(sender.peer_view(7).unwrap(), counters);
        frame.consume_by_ns = 300;
        assert_eq!(
            sender.try_submit_group_media_all(
                PRIMARY_GROUP,
                1,
                &snapshot,
                &[7],
                &frame,
                N01AdmissionInputs {
                    interface_now_ns: 0,
                    trusted_group_now_ns: 201,
                    overlap_budget_bytes: usize::MAX,
                    cancelled: &cancel
                }
            ),
            Err(AllPeerAdmissionError::MembershipChanged)
        );
        assert_eq!(clocked_n01_pump(&mut sender, 1, 201).media_sent, 0);
        sender.advance_epoch(2).unwrap();
        let fresh = sender.snapshot_n01_group(PRIMARY_GROUP, 2, &[7]).unwrap();
        assert!(
            sender
                .try_submit_group_media_all(
                    PRIMARY_GROUP,
                    2,
                    &fresh,
                    &[7],
                    &frame,
                    N01AdmissionInputs {
                        interface_now_ns: 0,
                        trusted_group_now_ns: 201,
                        overlap_budget_bytes: usize::MAX,
                        cancelled: &cancel
                    }
                )
                .is_ok()
        );
    }
}

#[test]
fn n07_clocked_n01_after_cutoff_never_sends_queued_media() {
    let mut sender = sender_over(ScriptPort::new());
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    let snapshot = sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]).unwrap();
    let frame = long_block(0, 0);
    let cancel = AtomicBool::new(false);
    sender
        .try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    let result = clocked_n01_pump(&mut sender, 1, frame.consume_by_ns + 1);
    assert_eq!((result.media_sent, result.late_dropped), (0, 1));
    assert!(sender.port.sent.is_empty());
}

#[test]
fn n07_clocked_n01_last_sequence_recovery_is_not_stale_playback() {
    use crate::playout::{
        Admission, ClockView, MediaPacket, PlayoutConfig, PlayoutEngine, PlayoutProfile,
    };
    let mut sender = sender_over(ScriptPort::new());
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    let snapshot = sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]).unwrap();
    let mut frame = long_block(0, 0);
    frame.consume_by_ns =
        crate::playout::consume_by(frame.presentation_time_ns, 1_000_000, 1_000_000, 500_000);
    let cancel = AtomicBool::new(false);
    let index = sender.index_of(7).unwrap();
    sender.peers[index].sender.next_seq = SEQ_AHEAD_LIMIT - 1;
    sender
        .try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    sender.port.send_fault = Some(PortFault::WouldBlock);
    assert_eq!(
        clocked_n01_pump(&mut sender, 1, frame.consume_by_ns - 1).media_sent,
        0
    );
    assert!(sender.peers[index].held.is_some());
    sender.port.send_fault = None;
    assert_eq!(
        clocked_n01_pump(&mut sender, 2, frame.consume_by_ns).media_sent,
        1
    );
    let packet = StreamReceiver::new(key(), stream(), 1)
        .accept(&sender.port.sent[0].1)
        .unwrap();
    let mut playout = PlayoutEngine::new(
        PlayoutProfile::MUSIC,
        PlayoutConfig {
            work_ns: 1_000_000,
            lead_ns: 1_000_000,
            tolerance_ns: 0,
        },
    )
    .unwrap();
    playout
        .begin_stream(1, 0, frame.presentation_time_ns)
        .unwrap();
    let view = ClockView {
        group_ns: frame.consume_by_ns,
        uncertainty_ns: 500_000,
        usable: true,
    };
    assert_eq!(
        playout.on_packet(view, &MediaPacket::from_authenticated(&packet).unwrap()),
        Admission::Late
    );
}

#[test]
fn n07_clocked_n01_missing_view_allows_only_existing_stall_probe() {
    let limits = CarrierLimits {
        window_packets: 1,
        pace_burst_bytes: 65_536,
        ..CarrierLimits::baseline()
    };
    let mut sender =
        CarrierSender::with_port(key(), stream(), 1, limits, ScriptPort::new()).unwrap();
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    let snapshot = sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]).unwrap();
    let cancel = AtomicBool::new(false);
    let first = long_block(0, 0);
    sender
        .try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7],
            &first,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    assert_eq!(clocked_n01_pump(&mut sender, 1, 1).media_sent, 1);
    let second = long_block(1, 0);
    sender
        .try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7],
            &second,
            N01AdmissionInputs {
                interface_now_ns: 2,
                trusted_group_now_ns: 2,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    let first_wire = sender.port.sent[0].1.clone();
    assert_eq!(
        sender
            .pump_n01_clocked(STALL_PROBE_NS + 1, &[], &cancel)
            .media_sent,
        0
    );
    assert_eq!(sender.port.sent.len(), 2);
    assert_eq!(sender.port.sent[1].1, first_wire);
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 1);
    sender.fence_n01_group(PRIMARY_GROUP, 1, &snapshot).unwrap();
    sender.pump_n01_clocked(2 * STALL_PROBE_NS + 1, &[], &cancel);
    assert_eq!(
        sender.port.sent.len(),
        2,
        "fenced group cannot emit even a protected probe"
    );
}

#[test]
fn n07_n01_unrelated_group_change_retains_lifetime_fence_authority() {
    let (mut sender, second) = two_group_sender(CarrierLimits::baseline());
    let snapshot = sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]).unwrap();
    let cancel = AtomicBool::new(false);
    let frame = long_block(0, 0);
    sender
        .try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    sender
        .peer_address_changed(8, addr("127.0.0.1:42005"), addr("127.0.0.1:42006"))
        .unwrap();
    assert!(
        sender
            .has_n01_eligible_peer(PRIMARY_GROUP, 1, &snapshot, &[7], 0)
            .is_err()
    );
    sender.fence_n01_group(PRIMARY_GROUP, 1, &snapshot).unwrap();
    assert_eq!(clocked_n01_pump(&mut sender, 1, 1).media_sent, 0);
    assert!(sender.port.sent.is_empty());
    sender
        .submit_group_media(second, SECOND_EPOCH, &frame, 1)
        .unwrap();
    assert_eq!(
        sender.pump(2).media_sent,
        1,
        "other group legacy remains live"
    );
    let foreign = sender_over(ScriptPort::new());
    assert!(!foreign.owns_n01_snapshot(&snapshot));
    sender.advance_epoch(2).unwrap();
    assert_eq!(
        sender.fence_n01_group(PRIMARY_GROUP, 1, &snapshot),
        Err(AllPeerAdmissionError::MembershipChanged)
    );
    let fresh = sender.snapshot_n01_group(PRIMARY_GROUP, 2, &[7]).unwrap();
    sender
        .try_submit_group_media_all(
            PRIMARY_GROUP,
            2,
            &fresh,
            &[7],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 3,
                trusted_group_now_ns: 3,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    let clock = N01GroupClock {
        group: PRIMARY_GROUP,
        epoch: 2,
        view: crate::playout::ClockView {
            group_ns: 4,
            uncertainty_ns: 500_000,
            usable: true,
        },
    };
    assert_eq!(sender.pump_n01_clocked(4, &[clock], &cancel).media_sent, 1);
}

#[test]
fn n07_n01_predecode_eligibility_tracks_live_capacity_and_snapshot() {
    let mut sender = sender_over(ScriptPort::new());
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    sender
        .add_peer(8, addr("127.0.0.1:42003"), addr("127.0.0.1:42004"), 1500)
        .unwrap();
    let snapshot = sender
        .snapshot_n01_group(PRIMARY_GROUP, 1, &[7, 8])
        .unwrap();
    assert_eq!(
        sender.has_n01_eligible_peer(PRIMARY_GROUP, 1, &snapshot, &[7, 8], 0),
        Ok(true)
    );
    sender.set_path_mtu(7, 1000).unwrap();
    sender.set_path_mtu(8, 1000).unwrap();
    assert_eq!(
        sender.has_n01_eligible_peer(PRIMARY_GROUP, 1, &snapshot, &[7, 8], 0),
        Ok(false)
    );
    sender.set_path_mtu(8, 1500).unwrap();
    assert_eq!(
        sender.has_n01_eligible_peer(PRIMARY_GROUP, 1, &snapshot, &[7, 8], 0),
        Ok(true)
    );
    sender.set_link_up(false);
    assert_eq!(
        sender.has_n01_eligible_peer(PRIMARY_GROUP, 1, &snapshot, &[7, 8], 0),
        Ok(false)
    );
    sender.set_link_up(true);
    assert!(
        sender
            .has_n01_eligible_peer(PRIMARY_GROUP, 1, &snapshot, &[7], 0)
            .is_err()
    );
    sender
        .peer_address_changed(8, addr("127.0.0.1:42005"), addr("127.0.0.1:42006"))
        .unwrap();
    assert!(
        sender
            .has_n01_eligible_peer(PRIMARY_GROUP, 1, &snapshot, &[7, 8], 0)
            .is_err()
    );
    let fresh = sender
        .snapshot_n01_group(PRIMARY_GROUP, 1, &[7, 8])
        .unwrap();
    assert_eq!(
        sender.has_n01_eligible_peer(PRIMARY_GROUP, 1, &fresh, &[7, 8], 0),
        Ok(true)
    );
}

#[test]
fn n07_n01_predecode_checks_actual_full_block_not_configured_floor() {
    let limits = CarrierLimits {
        required_payload_bytes: 4,
        aggregate_queue_bytes: MAX_DATAGRAM_BYTES,
        ..CarrierLimits::baseline()
    };
    let mut sender =
        CarrierSender::with_port(key(), stream(), 1, limits, ScriptPort::new()).unwrap();
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1000)
        .unwrap();
    let snapshot = sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]).unwrap();
    assert_eq!(
        sender.has_n01_eligible_peer(PRIMARY_GROUP, 1, &snapshot, &[7], 0),
        Ok(false)
    );
    sender.set_path_mtu(7, 1500).unwrap();
    assert_eq!(
        sender.has_n01_eligible_peer(PRIMARY_GROUP, 1, &snapshot, &[7], 0),
        Ok(true)
    );
    let mut small = long_block(0, 0);
    small.payload.truncate(4);
    assert_eq!(sender.submit_media(1, &small, 0).unwrap().queued, 1);
    assert_eq!(
        sender.has_n01_eligible_peer(PRIMARY_GROUP, 1, &snapshot, &[7], 0),
        Ok(false)
    );
    assert_eq!(sender.pump(1).media_sent, 1);
    assert_eq!(
        sender.has_n01_eligible_peer(PRIMARY_GROUP, 1, &snapshot, &[7], 0),
        Ok(true)
    );
}

#[test]
fn n07_n01_exclusive_source_blocks_competitors_and_pump_bypass() {
    let limits = CarrierLimits {
        window_packets: 1,
        ..CarrierLimits::baseline()
    };
    let mut sender =
        CarrierSender::with_port(key(), stream(), 1, limits, ScriptPort::new()).unwrap();
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    let unclaimed = sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]).unwrap();
    let selection = sender.claim_n01_source(PRIMARY_GROUP, 1, &[7]).unwrap();
    assert!(matches!(
        sender.claim_n01_source(PRIMARY_GROUP, 1, &[7]),
        Err(AllPeerAdmissionError::MembershipChanged)
    ));
    assert!(matches!(
        sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]),
        Err(AllPeerAdmissionError::MembershipChanged)
    ));
    let cancel = AtomicBool::new(false);
    let frame = long_block(0, 0);
    assert_eq!(
        sender.try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &unclaimed,
            &[7],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel
            }
        ),
        Err(AllPeerAdmissionError::MembershipChanged)
    );
    sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &selection,
            &[7],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &selection,
            &[7],
            &long_block(1, 0),
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    assert_eq!(clocked_n01_pump(&mut sender, 1, 1).media_sent, 0);
    assert_eq!(sender.pump(2).media_sent, 0);
    let clock = N01GroupClock {
        group: PRIMARY_GROUP,
        epoch: 1,
        view: crate::playout::ClockView {
            group_ns: 3,
            uncertainty_ns: 0,
            usable: true,
        },
    };
    assert_eq!(
        sender
            .pump_n01_selected(3, clock, &selection, &cancel)
            .unwrap()
            .media_sent,
        1
    );
    let original_wire = sender.port.sent[0].1.clone();
    sender.pump(STALL_PROBE_NS + 4);
    assert_eq!(
        sender.port.sent.len(),
        1,
        "ordinary pump cannot send selected probe"
    );
    let probe_clock = N01GroupClock {
        view: crate::playout::ClockView {
            group_ns: STALL_PROBE_NS + 4,
            uncertainty_ns: 0,
            usable: true,
        },
        ..clock
    };
    sender
        .pump_n01_selected(STALL_PROBE_NS + 4, probe_clock, &selection, &cancel)
        .unwrap();
    assert_eq!(sender.port.sent.len(), 2);
    assert_eq!(sender.port.sent[1].1, original_wire);
    let mut receiver = StreamReceiver::new(key(), stream(), 1);
    receiver.accept(&original_wire).unwrap();
    assert!(
        receiver.accept(&sender.port.sent[1].1).is_err(),
        "probe is recovery traffic, not a second playable frame"
    );
    let mut foreign = sender_over(ScriptPort::new());
    foreign
        .add_peer(7, addr("127.0.0.1:42011"), addr("127.0.0.1:42012"), 1500)
        .unwrap();
    let foreign_claim = foreign.claim_n01_source(PRIMARY_GROUP, 1, &[7]).unwrap();
    assert!(matches!(
        sender.pump_n01_selected(STALL_PROBE_NS + 5, probe_clock, &foreign_claim, &cancel),
        Err(AllPeerAdmissionError::MembershipChanged)
    ));
    sender.advance_epoch(2).unwrap();
    assert!(matches!(
        sender.pump_n01_selected(STALL_PROBE_NS + 6, probe_clock, &selection, &cancel),
        Err(AllPeerAdmissionError::MembershipChanged)
    ));
    assert!(sender.claim_n01_source(PRIMARY_GROUP, 2, &[7]).is_ok());
}

#[test]
fn n07_n01_claim_blocks_legacy_queue_held_and_cached_probe_bypass() {
    for old_state in 0..3 {
        let (mut sender, other) = two_group_sender(CarrierLimits::baseline());
        let frame = long_block(0, 0);
        sender.submit_media(1, &frame, 0).unwrap();
        if old_state == 1 {
            sender.port.send_fault = Some(PortFault::WouldBlock);
            sender.pump(1);
            sender.port.send_fault = None;
            assert!(sender.peers[sender.index_of(7).unwrap()].held.is_some());
        } else if old_state == 2 {
            assert_eq!(sender.pump(1).media_sent, 1);
            assert!(
                sender.peers[sender.index_of(7).unwrap()]
                    .last_sent
                    .is_some()
            );
        }
        assert!(matches!(
            sender.claim_n01_source(PRIMARY_GROUP, 1, &[7]),
            Err(AllPeerAdmissionError::MembershipChanged)
        ));
        sender.advance_epoch(2).unwrap();
        let claim = sender.claim_n01_source(PRIMARY_GROUP, 2, &[7]).unwrap();
        assert!(matches!(
            sender.submit_media(2, &frame, 2),
            Err(CarrierError::InvalidLimits(_))
        ));
        assert!(matches!(
            sender.submit_group_media(PRIMARY_GROUP, 2, &frame, 2),
            Err(CarrierError::InvalidLimits(_))
        ));
        sender
            .submit_group_media(other, SECOND_EPOCH, &frame, 2)
            .unwrap();
        let before = sender.port.sent.len();
        assert_eq!(sender.pump(3).media_sent, 1);
        assert_eq!(sender.port.sent[before].2, addr("127.0.0.1:42003"));
        let cancel = AtomicBool::new(false);
        sender
            .try_submit_group_media_all(
                PRIMARY_GROUP,
                2,
                &claim,
                &[7],
                &frame,
                N01AdmissionInputs {
                    interface_now_ns: 4,
                    trusted_group_now_ns: 4,
                    overlap_budget_bytes: usize::MAX,
                    cancelled: &cancel,
                },
            )
            .unwrap();
        let clock = N01GroupClock {
            group: PRIMARY_GROUP,
            epoch: 2,
            view: crate::playout::ClockView {
                group_ns: 5,
                uncertainty_ns: 0,
                usable: true,
            },
        };
        assert_eq!(
            sender
                .pump_n01_selected(5, clock, &claim, &cancel)
                .unwrap()
                .media_sent,
            1
        );
    }
}

#[test]
fn n07_n01_selected_pump_never_sends_other_selected_group() {
    let (mut sender, second) = two_group_sender(CarrierLimits::baseline());
    let a = sender.claim_n01_source(PRIMARY_GROUP, 1, &[7]).unwrap();
    let b = sender.claim_n01_source(second, SECOND_EPOCH, &[8]).unwrap();
    let cancel = AtomicBool::new(false);
    let frame = long_block(0, 0);
    for (group, epoch, claim, peers) in [
        (PRIMARY_GROUP, 1, &a, &[7][..]),
        (second, SECOND_EPOCH, &b, &[8][..]),
    ] {
        sender
            .try_submit_group_media_isolated(
                group,
                epoch,
                claim,
                peers,
                &frame,
                N01AdmissionInputs {
                    interface_now_ns: 0,
                    trusted_group_now_ns: 0,
                    overlap_budget_bytes: usize::MAX,
                    cancelled: &cancel,
                },
            )
            .unwrap();
    }
    let clock_b = N01GroupClock {
        group: second,
        epoch: SECOND_EPOCH,
        view: crate::playout::ClockView {
            group_ns: 1,
            uncertainty_ns: 0,
            usable: true,
        },
    };
    assert_eq!(
        sender
            .pump_n01_selected(1, clock_b, &b, &cancel)
            .unwrap()
            .media_sent,
        1
    );
    assert_eq!(sender.port.sent[0].2, addr("127.0.0.1:42003"));
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 1);
    let clock_a = N01GroupClock {
        group: PRIMARY_GROUP,
        epoch: 1,
        view: crate::playout::ClockView {
            group_ns: 2,
            uncertainty_ns: 0,
            usable: true,
        },
    };
    assert_eq!(
        sender
            .pump_n01_selected(2, clock_a, &a, &cancel)
            .unwrap()
            .media_sent,
        1
    );
    assert_eq!(sender.port.sent[1].2, addr("127.0.0.1:42001"));
}

#[test]
fn n07_n01_selected_source_continues_after_unrelated_group_changes_and_rollback() {
    let (mut sender, second) = two_group_sender(CarrierLimits::baseline());
    let a = sender.claim_n01_source(PRIMARY_GROUP, 1, &[7]).unwrap();
    let cancel = AtomicBool::new(false);
    let first = long_block(0, 0);
    sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &a,
            &[7],
            &first,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    sender
        .peer_address_changed(8, addr("127.0.0.1:42005"), addr("127.0.0.1:42006"))
        .unwrap();
    sender
        .add_peer_in_group(
            second,
            9,
            addr("127.0.0.1:42007"),
            addr("127.0.0.1:42008"),
            1500,
        )
        .unwrap();
    sender
        .advance_group_epoch(second, SECOND_EPOCH + 1)
        .unwrap();
    assert_eq!(
        sender.has_n01_eligible_peer(PRIMARY_GROUP, 1, &a, &[7], 1),
        Ok(true)
    );
    let next = long_block(1, 0);
    sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &a,
            &[7],
            &next,
            N01AdmissionInputs {
                interface_now_ns: 1,
                trusted_group_now_ns: 1,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    let clock_a = N01GroupClock {
        group: PRIMARY_GROUP,
        epoch: 1,
        view: crate::playout::ClockView {
            group_ns: 2,
            uncertainty_ns: 0,
            usable: true,
        },
    };
    assert_eq!(
        sender
            .pump_n01_selected(2, clock_a, &a, &cancel)
            .unwrap()
            .media_sent,
        2
    );
    let b = sender
        .claim_n01_source(second, SECOND_EPOCH + 1, &[8, 9])
        .unwrap();
    let clock_b = N01GroupClock {
        group: second,
        epoch: SECOND_EPOCH + 1,
        view: crate::playout::ClockView {
            group_ns: 10,
            uncertainty_ns: 0,
            usable: true,
        },
    };
    sender.pump_n01_selected(3, clock_b, &b, &cancel).unwrap();
    let last = long_block(2, 0);
    sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &a,
            &[7],
            &last,
            N01AdmissionInputs {
                interface_now_ns: 3,
                trusted_group_now_ns: 3,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 1);
    let backward_b = N01GroupClock {
        view: crate::playout::ClockView {
            group_ns: 9,
            ..clock_b.view
        },
        ..clock_b
    };
    sender
        .pump_n01_selected(4, backward_b, &b, &cancel)
        .unwrap();
    assert!(sender.groups[sender.group_index(second).unwrap()].n01_clock_failed);
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 1);
    let latest = N01GroupClock {
        view: crate::playout::ClockView {
            group_ns: 4,
            ..clock_a.view
        },
        ..clock_a
    };
    assert_eq!(
        sender
            .pump_n01_selected(6, latest, &a, &cancel)
            .unwrap()
            .media_sent,
        1
    );
    let fresh = long_block(3, 0);
    sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &a,
            &[7],
            &fresh,
            N01AdmissionInputs {
                interface_now_ns: 7,
                trusted_group_now_ns: 5,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    let fresh_clock = N01GroupClock {
        view: crate::playout::ClockView {
            group_ns: 6,
            ..clock_a.view
        },
        ..clock_a
    };
    assert_eq!(
        sender
            .pump_n01_selected(8, fresh_clock, &a, &cancel)
            .unwrap()
            .media_sent,
        1
    );
    let mut receiver = StreamReceiver::new(key(), stream(), 1);
    let received: Vec<_> = sender
        .port
        .sent
        .iter()
        .map(|(_, wire, _)| receiver.accept(wire).unwrap().start_frame)
        .collect();
    assert_eq!(
        received,
        vec![
            first.start_frame,
            next.start_frame,
            last.start_frame,
            fresh.start_frame
        ]
    );
}

#[test]
fn n07_selected_pump_cannot_emit_unclaimed_other_group_protected_probe() {
    let limits = CarrierLimits {
        window_packets: 1,
        ..CarrierLimits::baseline()
    };
    let (mut sender, second) = two_group_sender(limits);
    let a = sender.claim_n01_source(PRIMARY_GROUP, 1, &[7]).unwrap();
    let b = sender
        .snapshot_n01_group(second, SECOND_EPOCH, &[8])
        .unwrap();
    let cancel = AtomicBool::new(false);
    for index in 0..2 {
        sender
            .try_submit_group_media_all(
                second,
                SECOND_EPOCH,
                &b,
                &[8],
                &long_block(index, 0),
                N01AdmissionInputs {
                    interface_now_ns: 0,
                    trusted_group_now_ns: 0,
                    overlap_budget_bytes: usize::MAX,
                    cancelled: &cancel,
                },
            )
            .unwrap();
    }
    let b_clock = N01GroupClock {
        group: second,
        epoch: SECOND_EPOCH,
        view: crate::playout::ClockView {
            group_ns: 1,
            uncertainty_ns: 0,
            usable: true,
        },
    };
    assert_eq!(
        sender.pump_n01_clocked(1, &[b_clock], &cancel).media_sent,
        1
    );
    let b_wire = sender.port.sent[0].1.clone();
    assert_eq!(sender.group_view(second).unwrap().queued_packets, 1);
    sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &a,
            &[7],
            &long_block(0, 0),
            N01AdmissionInputs {
                interface_now_ns: 2,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    let a_clock = N01GroupClock {
        group: PRIMARY_GROUP,
        epoch: 1,
        view: crate::playout::ClockView {
            group_ns: 2,
            uncertainty_ns: 0,
            usable: true,
        },
    };
    assert_eq!(
        sender
            .pump_n01_selected(STALL_PROBE_NS + 2, a_clock, &a, &cancel)
            .unwrap()
            .media_sent,
        1
    );
    assert_eq!(
        sender.port.sent.len(),
        2,
        "selected A pump did not send B's due probe"
    );
    assert_eq!(sender.port.sent[1].2, addr("127.0.0.1:42001"));
    let recovery = N01GroupClock {
        view: crate::playout::ClockView {
            group_ns: STALL_PROBE_NS + 3,
            ..b_clock.view
        },
        ..b_clock
    };
    sender.pump_n01_clocked(STALL_PROBE_NS + 3, &[recovery], &cancel);
    assert_eq!(sender.port.sent.len(), 3);
    assert_eq!(sender.port.sent[2].2, addr("127.0.0.1:42003"));
    assert_eq!(
        sender.port.sent[2].1, b_wire,
        "unclaimed B recovery retains its ordinary probe"
    );
}

#[test]
fn n07_n01_selected_same_group_route_change_invalidates_and_fences() {
    let mut sender = sender_over(ScriptPort::new());
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    let claim = sender.claim_n01_source(PRIMARY_GROUP, 1, &[7]).unwrap();
    let cancel = AtomicBool::new(false);
    sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &claim,
            &[7],
            &long_block(0, 0),
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    sender
        .peer_address_changed(7, addr("127.0.0.1:42005"), addr("127.0.0.1:42006"))
        .unwrap();
    let clock = N01GroupClock {
        group: PRIMARY_GROUP,
        epoch: 1,
        view: crate::playout::ClockView {
            group_ns: 1,
            uncertainty_ns: 0,
            usable: true,
        },
    };
    assert!(matches!(
        sender.pump_n01_selected(1, clock, &claim, &cancel),
        Err(AllPeerAdmissionError::MembershipChanged)
    ));
    assert!(
        sender
            .has_n01_eligible_peer(PRIMARY_GROUP, 1, &claim, &[7], 1)
            .is_err()
    );
    assert_eq!(sender.pump(2).media_sent, 0);
    assert!(sender.port.sent.is_empty());
    sender.advance_epoch(2).unwrap();
    assert!(sender.claim_n01_source(PRIMARY_GROUP, 2, &[7]).is_ok());
}

#[test]
fn n07_n01_selected_fence_survives_unrelated_group_mutation() {
    let (mut sender, second) = two_group_sender(CarrierLimits::baseline());
    let a = sender.claim_n01_source(PRIMARY_GROUP, 1, &[7]).unwrap();
    let cancel = AtomicBool::new(false);
    sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &a,
            &[7],
            &long_block(0, 0),
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    sender
        .peer_address_changed(8, addr("127.0.0.1:42005"), addr("127.0.0.1:42006"))
        .unwrap();
    sender.fence_n01_group(PRIMARY_GROUP, 1, &a).unwrap();
    assert_eq!(clocked_n01_pump(&mut sender, 1, 1).media_sent, 0);
    let clock = N01GroupClock {
        group: PRIMARY_GROUP,
        epoch: 1,
        view: crate::playout::ClockView {
            group_ns: 2,
            uncertainty_ns: 0,
            usable: true,
        },
    };
    assert!(matches!(
        sender.pump_n01_selected(2, clock, &a, &cancel),
        Err(AllPeerAdmissionError::MembershipChanged)
    ));
    sender
        .submit_group_media(second, SECOND_EPOCH, &long_block(0, 0), 2)
        .unwrap();
    assert_eq!(sender.pump(3).media_sent, 1);
}

#[test]
fn n07_n01_source_claim_rejects_old_protected_state() {
    let mut sender = sender_over(ScriptPort::new());
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    let snapshot = sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]).unwrap();
    let cancel = AtomicBool::new(false);
    sender
        .try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7],
            &long_block(0, 0),
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    assert!(matches!(
        sender.claim_n01_source(PRIMARY_GROUP, 1, &[7]),
        Err(AllPeerAdmissionError::MembershipChanged)
    ));
    assert_eq!(clocked_n01_pump(&mut sender, 1, 1).media_sent, 1);
    assert!(
        matches!(
            sender.claim_n01_source(PRIMARY_GROUP, 1, &[7]),
            Err(AllPeerAdmissionError::MembershipChanged)
        ),
        "cached protected probe also blocks claim"
    );
    sender.advance_epoch(2).unwrap();
    assert!(sender.claim_n01_source(PRIMARY_GROUP, 2, &[7]).is_ok());
}

#[test]
fn n07_isolated_retry_cooldown_cannot_steal_healthy_peer_capacity() {
    let limits = CarrierLimits {
        aggregate_queue_packets: 1,
        max_sends_per_pump: 1,
        ..CarrierLimits::baseline()
    };
    let mut sender =
        CarrierSender::with_port(key(), stream(), 1, limits, ScriptPort::new()).unwrap();
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    sender
        .add_peer(8, addr("127.0.0.1:42003"), addr("127.0.0.1:42004"), 1500)
        .unwrap();
    let snapshot = sender
        .snapshot_n01_group(PRIMARY_GROUP, 1, &[7, 8])
        .unwrap();
    let cancel = AtomicBool::new(false);
    sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &long_block(0, 0),
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    sender.port.send_fault = Some(PortFault::PathUnavailable);
    for i in 0..SEND_RETRY_ATTEMPTS {
        clocked_n01_pump(&mut sender, u64::from(i) + 1, u64::from(i) + 1);
    }
    sender.port.send_fault = None;
    let now = u64::from(SEND_RETRY_ATTEMPTS) + 1;
    assert!(
        sender.peers[sender.index_of(7).unwrap()]
            .send_hold_until_ns
            .is_some_and(|until| until > now)
    );
    let next = long_block(1, 0);
    let out = sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &next,
            N01AdmissionInputs {
                interface_now_ns: now,
                trusted_group_now_ns: now,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    assert!(out.peers.contains(&Some(N01PeerOutcome {
        peer: 7,
        disposition: N01PeerDisposition::Stalled
    })));
    assert!(out.peers.contains(&Some(N01PeerOutcome {
        peer: 8,
        disposition: N01PeerDisposition::Queued
    })));
    assert_eq!(
        clocked_n01_pump(&mut sender, now + 1, now + 1).media_sent,
        1
    );
    assert_eq!(
        sender.media_cursor, 0,
        "a real peer 8 send rotates the cursor to peer 7"
    );
    let later = long_block(2, 0);
    let out = sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &later,
            N01AdmissionInputs {
                interface_now_ns: now + 2,
                trusted_group_now_ns: now + 2,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    assert!(out.peers.contains(&Some(N01PeerOutcome {
        peer: 7,
        disposition: N01PeerDisposition::Stalled
    })));
    assert!(out.peers.contains(&Some(N01PeerOutcome {
        peer: 8,
        disposition: N01PeerDisposition::Queued
    })));
    assert_eq!(
        clocked_n01_pump(&mut sender, now + 3, now + 3).media_sent,
        1
    );
    let mut receiver = StreamReceiver::new(key(), stream(), 1);
    let packets: Vec<_> = sender
        .port
        .sent
        .iter()
        .map(|(_, wire, _)| receiver.accept(wire).unwrap())
        .collect();
    assert_eq!(
        packets.iter().map(|p| p.start_frame).collect::<Vec<_>>(),
        vec![next.start_frame, later.start_frame]
    );
    assert!(
        sender
            .port
            .sent
            .iter()
            .all(|(_, _, to)| *to == addr("127.0.0.1:42003"))
    );
    let next_time = now + 4;
    sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &long_block(3, 0),
            N01AdmissionInputs {
                interface_now_ns: next_time,
                trusted_group_now_ns: next_time,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    sender.port.send_fault = Some(PortFault::PathUnavailable);
    for i in 0..SEND_RETRY_ATTEMPTS - 1 {
        let time = next_time + u64::from(i) + 1;
        let report = clocked_n01_pump(&mut sender, time, time);
        assert!(!report.pace_limited);
    }
    let pace_time = next_time + u64::from(SEND_RETRY_ATTEMPTS);
    let report = clocked_n01_pump(&mut sender, pace_time, pace_time);
    assert!(report.pace_limited);
    let retry_time = report.next_send_ns.expect("pacer reports when to retry");
    assert!(retry_time > pace_time);
    let peer8 = sender.index_of(8).unwrap();
    assert_eq!(sender.peers[peer8].held.as_ref().unwrap().attempts, 2);
    assert_eq!(sender.aggregate_media().0, 1);
    // A held datagram consumes the only aggregate slot, even when peer 7 cools.
    let recovery = sender.peers[sender.index_of(7).unwrap()]
        .send_hold_until_ns
        .unwrap();
    assert!(retry_time < recovery);
    assert_eq!(
        sender.has_n01_eligible_peer(PRIMARY_GROUP, 1, &snapshot, &[7, 8], recovery),
        Ok(false)
    );
    let report = clocked_n01_pump(&mut sender, retry_time, retry_time);
    assert!(!report.pace_limited);
    assert_eq!(report.media_sent, 0);
    assert!(sender.peers[peer8].held.is_none());
    assert_eq!(sender.aggregate_media(), (0, 0));
    assert!(sender.peers[peer8].send_hold_until_ns.unwrap() > recovery);
    sender.port.send_fault = None;
    let held_time = retry_time + 1;
    assert!(held_time < recovery);
    assert_eq!(
        sender.has_n01_eligible_peer(PRIMARY_GROUP, 1, &snapshot, &[7, 8], held_time),
        Ok(false)
    );
    assert!(matches!(
        sender.try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &long_block(4, 0),
            N01AdmissionInputs {
                interface_now_ns: held_time,
                trusted_group_now_ns: held_time,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel
            }
        ),
        Err(AllPeerAdmissionError::Retry(AllPeerRetry::NoEligiblePeers))
    ));
    let recovery = sender.peers[sender.index_of(7).unwrap()]
        .send_hold_until_ns
        .unwrap();
    assert_eq!(
        sender.has_n01_eligible_peer(PRIMARY_GROUP, 1, &snapshot, &[7, 8], recovery),
        Ok(true)
    );
    let resumed = long_block(4, 0);
    let outcome = sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &resumed,
            N01AdmissionInputs {
                interface_now_ns: recovery,
                trusted_group_now_ns: recovery,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    assert!(outcome.peers.contains(&Some(N01PeerOutcome {
        peer: 7,
        disposition: N01PeerDisposition::Queued,
    })));
    assert!(outcome.peers.contains(&Some(N01PeerOutcome {
        peer: 8,
        disposition: N01PeerDisposition::Stalled,
    })));
    assert_eq!(
        clocked_n01_pump(&mut sender, recovery, recovery).media_sent,
        1
    );
    let (_, wire, to) = sender.port.sent.last().unwrap();
    assert_eq!(*to, addr("127.0.0.1:42001"));
    let mut recovered_receiver = StreamReceiver::new(key(), stream(), 1);
    assert_eq!(
        recovered_receiver.accept(wire).unwrap().start_frame,
        resumed.start_frame
    );
}

#[test]
fn n07_isolated_fanout_continues_healthy_peer_and_never_replays_skipped_pcm() {
    let mut sender = sender_over(ScriptPort::new());
    let m1 = addr("127.0.0.1:42001");
    let m2 = addr("127.0.0.1:42003");
    sender
        .add_peer(7, m1, addr("127.0.0.1:42002"), 1500)
        .unwrap();
    sender
        .add_peer(8, m2, addr("127.0.0.1:42004"), 1500)
        .unwrap();
    let snapshot = sender
        .snapshot_n01_group(PRIMARY_GROUP, 1, &[7, 8])
        .unwrap();
    let cancel = AtomicBool::new(false);
    sender.set_path_mtu(8, 1000).unwrap();
    let mut first = long_block(0, 0);
    first.payload.fill(0x31);
    let copy = first.clone();
    let result = sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &first,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    assert_eq!(result.status, N01IsolatedStatus::Published);
    assert_eq!(result.peer_count, 2);
    assert!(result.peers.contains(&Some(N01PeerOutcome {
        peer: 7,
        disposition: N01PeerDisposition::Queued
    })));
    assert!(result.peers.contains(&Some(N01PeerOutcome {
        peer: 8,
        disposition: N01PeerDisposition::Fenced
    })));
    assert_eq!(first, copy);
    assert_eq!(clocked_n01_pump(&mut sender, 1, 1).media_sent, 1);
    sender.set_path_mtu(8, 1500).unwrap();
    let mut next = long_block(1, 0);
    next.payload.fill(0x52);
    let result = sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &next,
            N01AdmissionInputs {
                interface_now_ns: 2,
                trusted_group_now_ns: 2,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    assert_eq!(result.status, N01IsolatedStatus::Published);
    assert!(result.peers.contains(&Some(N01PeerOutcome {
        peer: 7,
        disposition: N01PeerDisposition::Queued
    })));
    assert!(result.peers.contains(&Some(N01PeerOutcome {
        peer: 8,
        disposition: N01PeerDisposition::Queued
    })));
    assert_eq!(clocked_n01_pump(&mut sender, 3, 3).media_sent, 2);
    let mut first_receiver = StreamReceiver::new(key(), stream(), 1);
    let frames: Vec<_> = sender
        .port
        .sent
        .iter()
        .filter(|(_, _, to)| *to == m1)
        .map(|(_, wire, _)| first_receiver.accept(wire).unwrap())
        .collect();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].payload, first.payload);
    assert_eq!(frames[1].payload, next.payload);
    let mut second_receiver = StreamReceiver::new(key(), stream(), 1);
    let frames: Vec<_> = sender
        .port
        .sent
        .iter()
        .filter(|(_, _, to)| *to == m2)
        .map(|(_, wire, _)| second_receiver.accept(wire).unwrap())
        .collect();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].payload, next.payload);
    assert_eq!(frames[0].start_frame, next.start_frame);
}

#[test]
fn n07_isolated_fanout_all_unavailable_waits_then_expired_skips_once() {
    let mut sender = sender_over(ScriptPort::new());
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    sender
        .add_peer(8, addr("127.0.0.1:42003"), addr("127.0.0.1:42004"), 1500)
        .unwrap();
    let snapshot = sender
        .snapshot_n01_group(PRIMARY_GROUP, 1, &[7, 8])
        .unwrap();
    sender.set_path_mtu(7, 1000).unwrap();
    sender.set_path_mtu(8, 1000).unwrap();
    let frame = long_block(0, 0);
    let copy = frame.clone();
    let cancel = AtomicBool::new(false);
    let before = sender.group_view(PRIMARY_GROUP).unwrap();
    assert_eq!(
        sender.try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 1,
                trusted_group_now_ns: 1,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel
            }
        ),
        Err(AllPeerAdmissionError::Retry(AllPeerRetry::NoEligiblePeers))
    );
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before);
    assert_eq!(frame, copy);
    let expired = sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 2,
                trusted_group_now_ns: frame.consume_by_ns,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    assert_eq!(expired.status, N01IsolatedStatus::Expired);
    assert_eq!(expired.peer_count, 0);
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before);
    sender.set_path_mtu(7, 1500).unwrap();
    sender.set_path_mtu(8, 1500).unwrap();
    let fresh = long_block(1, 1_000_000_000);
    let next = sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &fresh,
            N01AdmissionInputs {
                interface_now_ns: 3,
                trusted_group_now_ns: frame.consume_by_ns + 1,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    assert_eq!(next.status, N01IsolatedStatus::Published);
    assert_eq!(
        clocked_n01_pump(&mut sender, 4, frame.consume_by_ns + 1).media_sent,
        2
    );
    for (_, wire, _) in &sender.port.sent {
        let packet = StreamReceiver::new(key(), stream(), 1)
            .accept(wire)
            .unwrap();
        assert_eq!(packet.start_frame, fresh.start_frame);
        assert_eq!(packet.payload, fresh.payload);
    }
}

#[test]
fn n07_isolated_fanout_partial_capacity_rotates_and_validates_every_profile() {
    let limits = CarrierLimits {
        aggregate_queue_packets: 1,
        pace_burst_bytes: 65_536,
        ..CarrierLimits::baseline()
    };
    let mut sender =
        CarrierSender::with_port(key(), stream(), 1, limits, ScriptPort::new()).unwrap();
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    sender
        .add_peer(8, addr("127.0.0.1:42003"), addr("127.0.0.1:42004"), 1500)
        .unwrap();
    let snapshot = sender
        .snapshot_n01_group(PRIMARY_GROUP, 1, &[7, 8])
        .unwrap();
    let cancel = AtomicBool::new(false);
    let mut partial = long_block(0, 0);
    partial.payload.truncate(512);
    let second = sender.index_of(8).unwrap();
    sender.peers[second].sender.profile = crate::StreamProfile {
        repair_allowed: true,
        partial_blocks_allowed: false,
    };
    assert!(matches!(
        sender.try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &partial,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel
            }
        ),
        Err(AllPeerAdmissionError::Invalid(CarrierError::Stream(
            StreamError::FeatureNotNegotiated { .. }
        )))
    ));
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 0);
    sender.peers[second].sender.profile = crate::StreamProfile::BASELINE;
    let first = sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &partial,
            N01AdmissionInputs {
                interface_now_ns: 1,
                trusted_group_now_ns: 1,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    assert!(first.peers.contains(&Some(N01PeerOutcome {
        peer: 7,
        disposition: N01PeerDisposition::Queued
    })));
    assert!(first.peers.contains(&Some(N01PeerOutcome {
        peer: 8,
        disposition: N01PeerDisposition::Capacity
    })));
    assert_eq!(clocked_n01_pump(&mut sender, 2, 2).media_sent, 1);
    let second_frame = long_block(1, 0);
    let second_out = sender
        .try_submit_group_media_isolated(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &second_frame,
            N01AdmissionInputs {
                interface_now_ns: 3,
                trusted_group_now_ns: 3,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    assert!(second_out.peers.contains(&Some(N01PeerOutcome {
        peer: 8,
        disposition: N01PeerDisposition::Queued
    })));
    assert!(second_out.peers.contains(&Some(N01PeerOutcome {
        peer: 7,
        disposition: N01PeerDisposition::Capacity
    })));
    assert_eq!(clocked_n01_pump(&mut sender, 4, 4).media_sent, 1);
    assert_eq!(sender.port.sent[0].2, addr("127.0.0.1:42001"));
    assert_eq!(sender.port.sent[1].2, addr("127.0.0.1:42003"));
}

#[test]
fn n07_clocked_n01_lifetime_bound_fence_blocks_queued_media_until_new_epoch() {
    let mut sender = sender_over(ScriptPort::new());
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    let snapshot = sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]).unwrap();
    let frame = long_block(0, 0);
    let cancel = AtomicBool::new(false);
    sender
        .try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    sender.fence_n01_group(PRIMARY_GROUP, 1, &snapshot).unwrap();
    assert_eq!(clocked_n01_pump(&mut sender, 1, 1).media_sent, 0);
    assert_eq!(sender.pump(2).media_sent, 0);
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 1);
    assert_eq!(
        sender.try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 2,
                trusted_group_now_ns: 2,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel
            }
        ),
        Err(AllPeerAdmissionError::MembershipChanged)
    );
    sender.advance_epoch(2).unwrap();
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 0);
    assert_eq!(
        sender.fence_n01_group(PRIMARY_GROUP, 1, &snapshot),
        Err(AllPeerAdmissionError::MembershipChanged)
    );
    let fresh = sender.snapshot_n01_group(PRIMARY_GROUP, 2, &[7]).unwrap();
    sender
        .try_submit_group_media_all(
            PRIMARY_GROUP,
            2,
            &fresh,
            &[7],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 3,
                trusted_group_now_ns: 3,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    let clock = N01GroupClock {
        group: PRIMARY_GROUP,
        epoch: 2,
        view: crate::playout::ClockView {
            group_ns: 4,
            uncertainty_ns: 0,
            usable: true,
        },
    };
    assert_eq!(sender.pump_n01_clocked(4, &[clock], &cancel).media_sent, 1);
    assert_eq!(
        StreamReceiver::new(key(), stream(), 2)
            .accept(&sender.port.sent[0].1)
            .unwrap()
            .payload,
        frame.payload
    );
}

#[test]
fn n07_all_peer_same_snapshot_recovers_link_fence_and_mtu_backpressure() {
    for mode in 0..3 {
        let limits = CarrierLimits {
            required_payload_bytes: if mode == 2 { 4 } else { MAX_PAYLOAD_BYTES },
            ..CarrierLimits::baseline()
        };
        let mut sender =
            CarrierSender::with_port(key(), stream(), 1, limits, ScriptPort::new()).unwrap();
        let m1 = addr("127.0.0.1:42001");
        let m2 = addr("127.0.0.1:42003");
        sender
            .add_peer(7, m1, addr("127.0.0.1:42002"), 1500)
            .unwrap();
        sender
            .add_peer(8, m2, addr("127.0.0.1:42004"), 1500)
            .unwrap();
        let snapshot = sender
            .snapshot_n01_group(PRIMARY_GROUP, 1, &[7, 8])
            .unwrap();
        let frame = long_block(0, 0);
        let copy = frame.clone();
        let cancel = AtomicBool::new(false);
        match mode {
            0 => sender.set_link_up(false),
            1 => {
                sender.set_path_mtu(8, 1000).unwrap();
            }
            _ => {
                sender.set_path_mtu(8, 900).unwrap();
            }
        }
        let before = sender.group_view(PRIMARY_GROUP).unwrap();
        let expected = match mode {
            0 => AllPeerRetry::LinkDown,
            1 => AllPeerRetry::PeerFenced(8),
            _ => AllPeerRetry::PathMtu(8),
        };
        assert_eq!(
            sender.try_submit_group_media_all(
                PRIMARY_GROUP,
                1,
                &snapshot,
                &[7, 8],
                &frame,
                N01AdmissionInputs {
                    interface_now_ns: 1,
                    trusted_group_now_ns: 1,
                    overlap_budget_bytes: usize::MAX,
                    cancelled: &cancel
                }
            ),
            Err(AllPeerAdmissionError::Retry(expected))
        );
        assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before);
        assert_eq!(frame, copy);
        if mode == 0 {
            sender.set_link_up(true);
        } else {
            sender.set_path_mtu(8, 1500).unwrap();
        }
        assert!(
            sender
                .try_submit_group_media_all(
                    PRIMARY_GROUP,
                    1,
                    &snapshot,
                    &[7, 8],
                    &frame,
                    N01AdmissionInputs {
                        interface_now_ns: 2,
                        trusted_group_now_ns: 2,
                        overlap_budget_bytes: usize::MAX,
                        cancelled: &cancel
                    }
                )
                .is_ok()
        );
        assert_eq!(clocked_n01_pump(&mut sender, 3, 3).media_sent, 2);
        for destination in [m1, m2] {
            let wire = &sender
                .port
                .sent
                .iter()
                .find(|(_, _, to)| *to == destination)
                .unwrap()
                .1;
            assert_eq!(
                StreamReceiver::new(key(), stream(), 1)
                    .accept(wire)
                    .unwrap()
                    .payload,
                frame.payload
            );
        }
    }
}

#[test]
fn n07_all_peer_audio_survives_legacy_and_fec_aggregate_pressure() {
    let limits = CarrierLimits {
        aggregate_queue_packets: 2,
        pace_burst_bytes: 65_536,
        ..CarrierLimits::baseline()
    };
    let mut sender =
        CarrierSender::with_port(key(), stream(), 1, limits, ScriptPort::new()).unwrap();
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    sender
        .add_peer(8, addr("127.0.0.1:42003"), addr("127.0.0.1:42004"), 1500)
        .unwrap();
    let legacy_group = sender
        .add_group(key(), StreamId::new(stream().get() + 1).unwrap(), 1)
        .unwrap();
    sender
        .add_peer_in_group(
            legacy_group,
            9,
            addr("127.0.0.1:42005"),
            addr("127.0.0.1:42006"),
            1500,
        )
        .unwrap();
    let fec_group = sender
        .add_group(key(), StreamId::new(stream().get() + 2).unwrap(), 1)
        .unwrap();
    sender
        .add_peer_in_group(
            fec_group,
            10,
            addr("127.0.0.1:42007"),
            addr("127.0.0.1:42008"),
            1500,
        )
        .unwrap();
    sender
        .select_group_fec(fec_group, 2, 500_000_000, &[10])
        .unwrap();
    let snapshot = sender
        .snapshot_n01_group(PRIMARY_GROUP, 1, &[7, 8])
        .unwrap();
    let cancel = AtomicBool::new(false);
    let frame = long_block(0, 0);
    sender
        .try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7, 8],
            &frame,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    let before = sender.group_view(PRIMARY_GROUP).unwrap();
    let peer7 = sender.peer_view(7).unwrap();
    let peer8 = sender.peer_view(8).unwrap();
    let old = sender
        .submit_group_media(legacy_group, 1, &frame, 0)
        .unwrap();
    assert_eq!((old.queued, old.evicted, old.rejected_aggregate), (0, 0, 1));
    let source = [[0x31_u8; crate::fec::BYTES]; crate::fec::K];
    let fec = sender
        .submit_group_fec_window(fec_group, 2, 0, source, 0)
        .unwrap();
    assert_eq!(
        (fec.queued, fec.evicted, fec.rejected_aggregate),
        (0, 0, crate::fec::N as u32)
    );
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap(), before);
    assert_eq!(sender.peer_view(7).unwrap(), peer7);
    assert_eq!(sender.peer_view(8).unwrap(), peer8);
    assert_eq!(clocked_n01_pump(&mut sender, 1, 1).media_sent, 2);
    for destination in [addr("127.0.0.1:42001"), addr("127.0.0.1:42003")] {
        let wire = &sender
            .port
            .sent
            .iter()
            .find(|(_, _, to)| *to == destination)
            .unwrap()
            .1;
        assert_eq!(
            StreamReceiver::new(key(), stream(), 1)
                .accept(wire)
                .unwrap()
                .payload,
            frame.payload
        );
    }
    assert_eq!(
        sender
            .submit_group_media(legacy_group, 1, &frame, 2)
            .unwrap()
            .queued,
        1
    );
    assert_eq!(sender.pump(3).media_sent, 1);
    let retried = sender
        .submit_group_fec_window(fec_group, 2, 1, source, 21_333_334)
        .unwrap();
    assert_eq!(retried.queued, crate::fec::N as u32);
    assert_eq!(retried.evicted, (crate::fec::N - 2) as u32);
}

#[test]
fn n07_clocked_n01_mixed_queues_preserve_each_deadline_domain() {
    for (interface_now, group_now, expected_payload) in [
        (3_000_000_000, 1_000_000_000, 0x55_u8),
        (1_000_000_000, 3_000_000_000, 0x33_u8),
        (2_000_000_000, 2_000_000_000, 0x33_u8),
    ] {
        let mut sender = sender_over(ScriptPort::new());
        sender
            .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
            .unwrap();
        let mut legacy = long_block(0, 0);
        legacy.payload.fill(0x33);
        let mut protected = long_block(1, 0);
        protected.payload.fill(0x55);
        assert_eq!(sender.submit_media(1, &legacy, 0).unwrap().queued, 1);
        let snapshot = sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]).unwrap();
        let cancel = AtomicBool::new(false);
        sender
            .try_submit_group_media_all(
                PRIMARY_GROUP,
                1,
                &snapshot,
                &[7],
                &protected,
                N01AdmissionInputs {
                    interface_now_ns: 0,
                    trusted_group_now_ns: 0,
                    overlap_budget_bytes: usize::MAX,
                    cancelled: &cancel,
                },
            )
            .unwrap();
        let report = clocked_n01_pump(&mut sender, interface_now, group_now);
        assert_eq!((report.media_sent, report.late_dropped), (1, 1));
        let packet = StreamReceiver::new(key(), stream(), 1)
            .accept(&sender.port.sent[0].1)
            .unwrap();
        assert!(packet.payload.iter().all(|byte| *byte == expected_payload));
    }
}

#[test]
fn n07_clocked_n01_missing_view_preserves_legacy_progress_and_blocks_protected() {
    let mut sender = sender_over(ScriptPort::new());
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    let mut legacy = long_block(0, 0);
    legacy.payload.fill(0x31);
    let mut protected = long_block(1, 0);
    protected.payload.fill(0x52);
    assert_eq!(sender.submit_media(1, &legacy, 0).unwrap().queued, 1);
    let snapshot = sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]).unwrap();
    let cancel = AtomicBool::new(false);
    sender
        .try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7],
            &protected,
            N01AdmissionInputs {
                interface_now_ns: 0,
                trusted_group_now_ns: 0,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    assert_eq!(sender.pump_n01_clocked(1, &[], &cancel).media_sent, 1);
    assert_eq!(sender.group_view(PRIMARY_GROUP).unwrap().queued_packets, 1);
    assert_eq!(clocked_n01_pump(&mut sender, 2, 2).media_sent, 1);
    let mut receiver = StreamReceiver::new(key(), stream(), 1);
    let first = receiver.accept(&sender.port.sent[0].1).unwrap();
    let second = receiver.accept(&sender.port.sent[1].1).unwrap();
    assert_eq!(first.payload, legacy.payload);
    assert_eq!(second.payload, protected.payload);
}

#[test]
fn n07_all_peer_accepted_queue_is_fenced_on_route_and_membership_change() {
    for remove in [false, true] {
        let mut sender = sender_over(ScriptPort::new());
        sender
            .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
            .unwrap();
        sender
            .add_peer(8, addr("127.0.0.1:42003"), addr("127.0.0.1:42004"), 1500)
            .unwrap();
        let snapshot = sender
            .snapshot_n01_group(PRIMARY_GROUP, 1, &[7, 8])
            .unwrap();
        let frame = long_block(0, 0);
        let cancel = AtomicBool::new(false);
        sender
            .try_submit_group_media_all(
                PRIMARY_GROUP,
                1,
                &snapshot,
                &[7, 8],
                &frame,
                N01AdmissionInputs {
                    interface_now_ns: 0,
                    trusted_group_now_ns: 0,
                    overlap_budget_bytes: usize::MAX,
                    cancelled: &cancel,
                },
            )
            .unwrap();
        if remove {
            sender.remove_peer(8).unwrap();
            sender
                .add_peer(8, addr("127.0.0.1:42003"), addr("127.0.0.1:42004"), 1500)
                .unwrap();
        } else {
            sender
                .peer_address_changed(8, addr("127.0.0.1:42103"), addr("127.0.0.1:42104"))
                .unwrap();
        }
        assert_eq!(clocked_n01_pump(&mut sender, 1, 1).media_sent, 0);
        assert_eq!(sender.pump(2).media_sent, 0);
        assert!(sender.port.sent.is_empty());
        sender.advance_epoch(2).unwrap();
        let fresh = sender
            .snapshot_n01_group(PRIMARY_GROUP, 2, &[7, 8])
            .unwrap();
        sender
            .try_submit_group_media_all(
                PRIMARY_GROUP,
                2,
                &fresh,
                &[7, 8],
                &frame,
                N01AdmissionInputs {
                    interface_now_ns: 2,
                    trusted_group_now_ns: 2,
                    overlap_budget_bytes: usize::MAX,
                    cancelled: &cancel,
                },
            )
            .unwrap();
        let clock = N01GroupClock {
            group: PRIMARY_GROUP,
            epoch: 2,
            view: crate::playout::ClockView {
                group_ns: 3,
                uncertainty_ns: 0,
                usable: true,
            },
        };
        assert_eq!(sender.pump_n01_clocked(3, &[clock], &cancel).media_sent, 2);
        for (_, wire, _) in &sender.port.sent {
            assert_eq!(
                StreamReceiver::new(key(), stream(), 2)
                    .accept(wire)
                    .unwrap()
                    .payload,
                frame.payload
            );
        }
    }
}

#[test]
fn n07_packed_queue_tag_preserves_lengths_flags_and_slot_bound() {
    let old_field_model = size_of::<OutboundFrame>() + 2 * size_of::<u64>();
    assert!(size_of::<QueuedFrame>() <= old_field_model);
    for length in [WIRE_OVERHEAD_BYTES + 1, MAX_DATAGRAM_BYTES] {
        for protected in [false, true] {
            let tagged = QueuedWireLen::new(length, protected).unwrap();
            assert_eq!(tagged.bytes(), length);
            assert_eq!(tagged.needs_group_clock(), protected);
        }
    }
    for invalid in [0, WIRE_OVERHEAD_BYTES, MAX_DATAGRAM_BYTES + 1, usize::MAX] {
        assert!(QueuedWireLen::new(invalid, false).is_none());
        assert!(QueuedWireLen::new(invalid, true).is_none());
    }
}

#[test]
fn n07_packed_queue_keeps_legacy_and_protected_clock_paths_distinct() {
    let limits = CarrierLimits {
        peer_queue_packets: 1,
        pace_burst_bytes: 65_536,
        ..CarrierLimits::baseline()
    };
    let mut sender =
        CarrierSender::with_port(key(), stream(), 1, limits, ScriptPort::new()).unwrap();
    sender
        .add_peer(7, addr("127.0.0.1:42001"), addr("127.0.0.1:42002"), 1500)
        .unwrap();
    let legacy = long_block(0, 0);
    let wire_len = WIRE_OVERHEAD_BYTES + legacy.payload.len();
    assert_eq!(sender.submit_media(1, &legacy, 0).unwrap().queued, 1);
    assert_eq!(sender.peers[0].media_q_bytes, wire_len);
    assert!(
        !sender.peers[0]
            .media_q
            .front()
            .unwrap()
            .group_clock_required()
    );
    assert_eq!(sender.pump(1).media_sent, 1);
    assert_eq!(sender.port.sent[0].1.len(), wire_len);

    let mut protected = long_block(1, 0);
    protected.payload.fill(0x62);
    let cancel = AtomicBool::new(false);
    attempt_n01(
        &mut sender,
        PRIMARY_GROUP,
        1,
        &[7],
        &protected,
        2,
        0,
        usize::MAX,
        &cancel,
    )
    .unwrap();
    assert_eq!(sender.peers[0].media_q_bytes, wire_len);
    let head = sender.peers[0].media_q.front().unwrap();
    assert!(head.group_clock_required());
    assert_eq!(head.wire_len(), wire_len);
    let report = sender.submit_media(1, &legacy, 3).unwrap();
    assert_eq!((report.queued, report.evicted), (0, 0));
    assert_eq!(sender.peers[0].media_q_bytes, wire_len);
    assert_eq!(sender.pump(4).media_sent, 0);
    assert_eq!(clocked_n01_pump(&mut sender, 5, 5).media_sent, 1);
    assert_eq!(sender.port.sent[1].1.len(), wire_len);
    assert_eq!(sender.peers[0].media_q_bytes, 0);
    let mut receiver = StreamReceiver::new(key(), stream(), 1);
    assert_eq!(
        receiver.accept(&sender.port.sent[0].1).unwrap().payload,
        legacy.payload
    );
    assert_eq!(
        receiver.accept(&sender.port.sent[1].1).unwrap().payload,
        protected.payload
    );

    let snapshot = sender.snapshot_n01_group(PRIMARY_GROUP, 1, &[7]).unwrap();
    let pending = long_block(2, 0);
    sender
        .try_submit_group_media_all(
            PRIMARY_GROUP,
            1,
            &snapshot,
            &[7],
            &pending,
            N01AdmissionInputs {
                interface_now_ns: 6,
                trusted_group_now_ns: 5,
                overlap_budget_bytes: usize::MAX,
                cancelled: &cancel,
            },
        )
        .unwrap();
    sender.fence_n01_group(PRIMARY_GROUP, 1, &snapshot).unwrap();
    assert_eq!(clocked_n01_pump(&mut sender, 7, 6).media_sent, 0);
    assert_eq!(sender.port.sent.len(), 2);
}
