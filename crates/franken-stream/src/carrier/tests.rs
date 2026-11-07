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
