//! Actual endpoint feedback bytes and real SenderWindow repair on the existing
//! scripted host clock/port. This is not a network, provider or board claim.
use super::*;

fn partial_window() -> Rig {
    let mut rig = Rig::new(true);
    rig.at(70 * MS);
    for esi in 2..fec::K {
        rig.push(rig.wire(0, esi));
    }
    assert_eq!(rig.poll().media_accepted, 2);
    rig.at(150 * MS);
    rig
}

fn step(rig: &mut Rig) -> Result<FecPollReport, MediaRefusal> {
    rig.endpoint
        .poll_fec_with_feedback(&mut rig.platform, &mut rig.clock, &AtomicBool::new(false))
}

fn feedback(rig: &mut Rig, cancelled: &AtomicBool) -> Result<FeedbackProgress, FeedbackError> {
    rig.endpoint
        .pump_fec_feedback(&mut rig.platform, &mut rig.clock, cancelled)
}

#[test]
fn n06_endpoint_feedback_reaches_real_tail_and_prepares_missing_pcm() {
    let mut rig = partial_window();
    let report = step(&mut rig).expect("bounded decoder and feedback step");
    assert_eq!(report.decode, DecodeState::Idle, "insufficient information");
    assert_eq!(report.feedback, Ok(FeedbackProgress::Sent { window: 0 }));
    let sent = rig.sent.borrow();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, Lane::Control);
    assert_eq!(sent[0].1.len(), fec::FEEDBACK_BYTES);
    assert_eq!(&sent[0].1[..4], b"FFWA");
    assert_eq!(
        sent[0].1[64], 3,
        "one aggregate requests missing sources 0/1"
    );
    let wire = sent[0].1.clone();
    drop(sent);

    let mut sender = fec::SenderWindow::new(rig.fec_config(), 0, source(0), 1).unwrap();
    let replies = sender
        .serve(
            franken_stream::playout::ClockView {
                group_ns: rig.group_at(rig.time.get()),
                uncertainty_ns: 500_000,
                usable: true,
            },
            &wire,
            &AtomicBool::new(false),
        )
        .expect("actual authenticated feedback admits real tail packets");
    assert_eq!(replies.admitted, 3);
    let tail_sources = replies.admitted.count_ones();
    for packet in replies.packets.into_iter().flatten() {
        rig.push(packet.to_vec());
    }
    rig.at(151 * MS);
    assert_eq!(rig.poll().media_accepted, 2);
    assert_eq!(rig.endpoint.verdicts().fec_retransmit, 2);
    assert_eq!(rig.endpoint.pending_feedback_bytes(), 0);
    assert_eq!(rig.endpoint.feedback_counters().sent, 1);

    rig.at(rig.local_at_cutoff(20_000));
    let mut out = [0; BLOCK_PAYLOAD_BYTES];
    let Preparation::Prepared(block) = rig
        .endpoint
        .prepare(&mut rig.platform, &mut rig.clock, &mut out)
        .expect("fresh admitted platform clock")
    else {
        panic!("tail-repaired block was not prepared");
    };
    assert_eq!(block.decision.outcome, Outcome::Real);
    assert_eq!(out, source(0)[0]);
    println!(
        "N06-ENDPOINT-FEEDBACK {}",
        serde_json::json!({"schema":"n06.endpoint-feedback.v1", "profile":fec::PROFILE,
            "feedback":rig.endpoint.feedback_counters(), "tail_sources":tail_sources,
            "prepared_real":block.decision.outcome == Outcome::Real,
            "proof":"scripted-host-port-real-wire"})
    );
}

#[test]
fn n06_endpoint_feedback_retries_same_bytes_without_regenerating_or_busy_spinning() {
    let mut rig = partial_window();
    rig.endpoint.carrier().port().fail_control_send.set(true);
    let report = step(&mut rig).unwrap();
    assert!(matches!(report.feedback, Err(FeedbackError::Transport(_))));
    assert_eq!(rig.endpoint.pending_feedback_bytes(), fec::FEEDBACK_BYTES);
    let original = rig.endpoint.pending_feedback.as_ref().unwrap().wire.0;
    assert_eq!(rig.endpoint.feedback_counters().generated, 1);
    assert_eq!(rig.endpoint.feedback_counters().send_errors, 1);
    for _ in 0..100 {
        assert_eq!(
            feedback(&mut rig, &AtomicBool::new(false)),
            Ok(FeedbackProgress::Deferred)
        );
    }
    assert_eq!(rig.endpoint.feedback_counters().send_errors, 1);
    assert_eq!(rig.endpoint.feedback_counters().retries, 0);
    assert!(rig.sent.borrow().is_empty());

    rig.at(151 * MS);
    rig.endpoint.carrier().port().fail_control_send.set(false);
    assert_eq!(
        feedback(&mut rig, &AtomicBool::new(false)),
        Ok(FeedbackProgress::Sent { window: 0 })
    );
    assert_eq!(rig.sent.borrow()[0].1, original);
    assert_eq!(rig.endpoint.pending_feedback_bytes(), 0);
    assert_eq!(rig.endpoint.feedback_counters().generated, 1);
    assert_eq!(rig.endpoint.feedback_counters().retries, 1);
    assert_eq!(rig.endpoint.feedback_counters().sent, 1);
}

#[test]
fn n06_endpoint_feedback_expires_before_a_tail_could_reach_its_cutoff() {
    let mut rig = partial_window();
    rig.endpoint.carrier().port().fail_control_send.set(true);
    assert!(matches!(
        step(&mut rig).unwrap().feedback,
        Err(FeedbackError::Transport(_))
    ));
    let deadline = feedback_send_deadline(
        &rig.endpoint.pending_feedback.as_ref().unwrap().wire,
        500_000,
    )
    .unwrap();
    let now = rig.time.get();
    rig.at(rig.local_of(deadline + MS, now));
    rig.endpoint.carrier().port().fail_control_send.set(false);
    assert_eq!(
        feedback(&mut rig, &AtomicBool::new(false)),
        Ok(FeedbackProgress::Expired { window: 0 })
    );
    assert!(
        rig.sent.borrow().is_empty(),
        "no useless late request goes on the wire"
    );
    assert_eq!(rig.endpoint.pending_feedback_bytes(), 0);
    assert_eq!(rig.endpoint.feedback_counters().expired, 1);
}

#[test]
fn n06_endpoint_feedback_cancel_and_new_stream_retire_pending_authority() {
    for restart in [false, true] {
        let mut rig = partial_window();
        rig.endpoint.carrier().port().fail_control_send.set(true);
        assert!(matches!(
            step(&mut rig).unwrap().feedback,
            Err(FeedbackError::Transport(_))
        ));
        assert_eq!(rig.endpoint.pending_feedback_bytes(), fec::FEEDBACK_BYTES);
        if restart {
            rig.endpoint.restart_stream(StreamId::new(99).unwrap(), 2);
            assert_eq!(
                feedback(&mut rig, &AtomicBool::new(false)),
                Ok(FeedbackProgress::Idle)
            );
        } else {
            assert_eq!(
                feedback(&mut rig, &AtomicBool::new(true)),
                Err(FeedbackError::Media(MediaRefusal::Fec(
                    fec::Refusal::Cancelled
                )))
            );
        }
        assert_eq!(rig.endpoint.pending_feedback_bytes(), 0);
        assert_eq!(rig.endpoint.feedback_counters().retired, 1);
        assert!(rig.sent.borrow().is_empty());
    }
    let mut baseline = Rig::new(false);
    let reads = baseline.reads.get();
    assert_eq!(
        feedback(&mut baseline, &AtomicBool::new(false)),
        Ok(FeedbackProgress::Idle)
    );
    assert_eq!(
        baseline.reads.get(),
        reads,
        "N01 idle path needs no extra clock IO"
    );
}

#[test]
fn n06_endpoint_feedback_clock_fault_cannot_release_a_retained_request() {
    let mut rig = partial_window();
    rig.endpoint.carrier().port().fail_control_send.set(true);
    assert!(matches!(
        step(&mut rig).unwrap().feedback,
        Err(FeedbackError::Transport(_))
    ));
    rig.clock.report_clock_fault();
    rig.endpoint.carrier().port().fail_control_send.set(false);
    assert_eq!(
        feedback(&mut rig, &AtomicBool::new(false)),
        Err(FeedbackError::Media(MediaRefusal::Fec(fec::Refusal::Clock)))
    );
    assert_eq!(rig.endpoint.pending_feedback_bytes(), 0);
    assert_eq!(rig.endpoint.feedback_counters().retired, 1);
    assert!(rig.sent.borrow().is_empty());
}

#[test]
fn n06_endpoint_feedback_origin_change_retires_old_bytes_and_can_send_new_window() {
    let mut rig = partial_window();
    rig.endpoint.carrier().port().fail_control_send.set(true);
    assert!(matches!(
        step(&mut rig).unwrap().feedback,
        Err(FeedbackError::Transport(_))
    ));
    let old = rig.endpoint.pending_feedback.as_ref().unwrap().wire.0;
    let moved = rig.start + 100 * MS;
    rig.admit(moved).expect("admitted new same-epoch timeline");
    rig.start = moved;
    assert_eq!(rig.endpoint.pending_feedback_bytes(), 0);
    assert_eq!(rig.endpoint.feedback_counters().retired, 1);
    rig.endpoint.carrier().port().fail_control_send.set(false);
    rig.at(230 * MS);
    for esi in 2..fec::K {
        rig.push(rig.wire(0, esi));
    }
    assert_eq!(rig.poll().media_accepted, 2);
    rig.at(250 * MS);
    assert_eq!(
        step(&mut rig).unwrap().feedback,
        Ok(FeedbackProgress::Sent { window: 0 })
    );
    assert_ne!(
        rig.sent.borrow()[0].1,
        old,
        "new origin is authenticated in different bytes"
    );
    assert_eq!(rig.endpoint.feedback_counters().generated, 2);
    assert_eq!(rig.endpoint.feedback_counters().sent, 1);
}

#[test]
fn n06_endpoint_feedback_combined_poll_cancel_retires_queued_transport() {
    let mut rig = partial_window();
    rig.endpoint.carrier().port().fail_control_send.set(true);
    assert!(matches!(
        step(&mut rig).unwrap().feedback,
        Err(FeedbackError::Transport(_))
    ));
    assert_eq!(rig.endpoint.pending_feedback_bytes(), fec::FEEDBACK_BYTES);
    let result = rig.endpoint.poll_fec_with_feedback(
        &mut rig.platform,
        &mut rig.clock,
        &AtomicBool::new(true),
    );
    assert!(matches!(
        result,
        Err(MediaRefusal::Fec(fec::Refusal::Cancelled))
    ));
    assert_eq!(rig.endpoint.pending_feedback_bytes(), 0);
    assert_eq!(rig.endpoint.feedback_counters().retired, 1);
    assert!(rig.sent.borrow().is_empty());
}

#[test]
fn n06_endpoint_feedback_retry_waits_out_the_protected_render_interval() {
    let mut rig = Rig::new(true);
    rig.at(450 * MS);
    for esi in 2..fec::K {
        rig.push(rig.wire(18, esi));
    }
    assert_eq!(rig.poll().media_accepted, 2);
    rig.at(530 * MS);
    rig.endpoint.carrier().port().fail_control_send.set(true);
    let report = step(&mut rig).unwrap();
    assert!(matches!(report.feedback, Err(FeedbackError::Transport(_))));
    let pending = rig.endpoint.pending_feedback.as_ref().unwrap();
    let window = feedback_u64(&pending.wire, 28);
    assert!(window >= 16, "real scheduled collection has caught up");

    rig.endpoint.carrier().port().fail_control_send.set(false);
    rig.at(rig.local_at_cutoff(-200_000));
    assert_eq!(
        feedback(&mut rig, &AtomicBool::new(false)),
        Ok(FeedbackProgress::Deferred)
    );
    assert!(rig.sent.borrow().is_empty());
    assert_eq!(rig.endpoint.feedback_counters().retries, 0);

    rig.at(rig.local_at_cutoff(20_000));
    let mut out = [0; BLOCK_PAYLOAD_BYTES];
    rig.endpoint
        .prepare(&mut rig.platform, &mut rig.clock, &mut out)
        .unwrap();
    rig.at(rig.local_at_cutoff(2 * MS as i64 + 20_000));
    assert_eq!(
        feedback(&mut rig, &AtomicBool::new(false)),
        Ok(FeedbackProgress::Sent { window })
    );
    assert_eq!(rig.sent.borrow().len(), 1);

    // The same protection must hold if time crosses the fence after the
    // readiness read but before the fresh clock reading authorizes the send.
    let mut rig = Rig::new(true);
    // Give the renderer an actual first block. Without one the correct
    // decision is muted-no-history, which cannot prove a healthy PCM render.
    rig.at(70 * MS);
    rig.push(rig.wire(0, 0));
    assert_eq!(rig.poll().media_accepted, 1);
    rig.at(450 * MS);
    for esi in 2..fec::K {
        rig.push(rig.wire(18, esi));
    }
    assert_eq!(rig.poll().media_accepted, 2);
    rig.at(530 * MS);
    rig.endpoint.carrier().port().fail_control_send.set(true);
    assert!(matches!(
        step(&mut rig).unwrap().feedback,
        Err(FeedbackError::Transport(_))
    ));
    let retained = rig.endpoint.pending_feedback.as_ref().unwrap().wire.0;
    let window = feedback_u64(&Feedback(retained), 28);
    rig.endpoint.carrier().port().fail_control_send.set(false);
    rig.at(rig.local_at_cutoff(-600_000));
    rig.clock_after_read
        .set(Some(rig.local_at_cutoff(-200_000)));
    let reads = rig.reads.get();
    assert_eq!(
        feedback(&mut rig, &AtomicBool::new(false)),
        Ok(FeedbackProgress::Deferred),
        "the fresh send reading entered render protection after readiness"
    );
    assert_eq!(rig.reads.get(), reads + 2);
    assert!(rig.sent.borrow().is_empty());
    assert_eq!(rig.endpoint.feedback_counters().retries, 0);
    assert_eq!(rig.endpoint.feedback_counters().generated, 1);
    assert_eq!(
        rig.endpoint.pending_feedback.as_ref().unwrap().wire.0,
        retained,
        "deferral must retain the exact authenticated request"
    );

    rig.at(rig.local_at_cutoff(20_000));
    let mut out = [0; BLOCK_PAYLOAD_BYTES];
    let prepared = rig
        .endpoint
        .prepare(&mut rig.platform, &mut rig.clock, &mut out)
        .unwrap();
    let Preparation::Prepared(block) = prepared else {
        panic!("authenticated first block must actually render: {prepared:?}");
    };
    assert_eq!(block.decision.outcome, Outcome::Real);
    assert_eq!(out, source(0)[0]);
    rig.at(rig.local_at_cutoff(2 * MS as i64 + 20_000));
    assert_eq!(
        feedback(&mut rig, &AtomicBool::new(false)),
        Ok(FeedbackProgress::Sent { window })
    );
    assert_eq!(rig.sent.borrow().len(), 1);
    assert_eq!(rig.sent.borrow()[0].1, retained);
    assert_eq!(rig.endpoint.feedback_counters().retries, 1);
    assert_eq!(rig.endpoint.feedback_counters().sent, 1);
}

#[test]
fn n06_endpoint_feedback_one_shot_readiness_clock_error_is_not_swallowed() {
    let mut rig = partial_window();
    rig.endpoint.carrier().port().fail_control_send.set(true);
    assert!(matches!(
        step(&mut rig).unwrap().feedback,
        Err(FeedbackError::Transport(_))
    ));
    rig.endpoint.carrier().port().fail_control_send.set(false);
    rig.at(151 * MS);
    let reads = rig.reads.get();
    rig.clock_fail_once.set(true);
    assert!(matches!(
        feedback(&mut rig, &AtomicBool::new(false)),
        Err(FeedbackError::Media(MediaRefusal::Clock(_)))
    ));
    assert_eq!(
        rig.reads.get(),
        reads + 1,
        "do not hide the failed first read with another read"
    );
    assert_eq!(rig.endpoint.pending_feedback_bytes(), 0);
    assert_eq!(rig.endpoint.feedback_counters().retired, 1);
    assert!(rig.sent.borrow().is_empty());
    assert!(matches!(
        rig.clock.output(rig.time.get()),
        franken_clock::group::Output::Muted(_)
    ));
    assert!(
        !rig.clock_fail_once.get(),
        "the one-shot failure was actually exercised"
    );
}

#[test]
fn n06_endpoint_ingress_readiness_clock_fault_keeps_wire_until_relock() {
    let mut rig = Rig::new(true);
    rig.at(70 * MS);
    rig.push(rig.wire(0, 0));
    rig.clock_fail_once.set(true);
    let reads = rig.reads.get();
    let report = rig.poll();
    assert_eq!(report.media_read, 0);
    assert_eq!(
        rig.queued(),
        1,
        "failed readiness cannot consume the datagram"
    );
    assert_eq!(rig.reads.get(), reads + 1);
    assert_eq!(rig.consumed(), 0);
    assert!(matches!(
        rig.clock.output(rig.time.get()),
        franken_clock::group::Output::Muted(_)
    ));
    rig.lock(80 * MS, OLD_TIMELINE_NS + 80 * MS);
    rig.at(130 * MS);
    rig.admit(rig.start)
        .expect("fresh lock and same admitted future timeline");
    let report = rig.poll();
    assert_eq!((report.media_read, report.media_accepted), (1, 1));
    assert_eq!(rig.consumed(), 1, "real recovery after fresh lock/start");
    assert_eq!(rig.queued(), 0);
}

/// A deterministic link around the actual carrier: successful initial sends
/// of source zero and every parity packet are erased, while retransmits arrive.
/// Both directions use the endpoint's actual encoded bytes, never test replies.
struct SenderLink {
    media: Queue,
    feedback: Sent,
    initial_drops: u64,
    sent: u64,
}

fn sender_address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 10)
}

impl DatagramPort for SenderLink {
    fn send_to(&mut self, lane: Lane, wire: &[u8], to: SocketAddr) -> Result<(), PortFault> {
        assert_eq!(lane, Lane::Media);
        assert_eq!(to, address());
        assert_eq!(wire.len(), fec::DATAGRAM);
        self.sent += 1;
        if wire[73] == 2 || (wire[73] == 0 && wire[72] == 0) {
            self.initial_drops += 1;
        } else {
            self.media.borrow_mut().push_back(wire.to_vec());
        }
        Ok(())
    }

    fn recv(&mut self, lane: Lane, out: &mut [u8]) -> Result<Received, PortFault> {
        if lane != Lane::Control || self.feedback.borrow().is_empty() {
            return Err(PortFault::WouldBlock);
        }
        let (lane, wire) = self.feedback.borrow_mut().remove(0);
        assert_eq!(lane, Lane::Control);
        assert_eq!(wire.len(), fec::FEEDBACK_BYTES);
        out[..wire.len()].copy_from_slice(&wire);
        Ok(Received {
            len: wire.len(),
            from: Some(address()),
        })
    }

    fn local_addr(&self, _lane: Lane) -> Result<SocketAddr, PortFault> {
        Ok(sender_address())
    }

    fn rebind(&mut self, _ip: IpAddr) -> Result<(), PortFault> {
        Ok(())
    }
}

#[test]
fn n06_endpoint_actual_paced_sender_feedback_roundtrip_recovers_missing_pcm() {
    use franken_stream::carrier::{CarrierLimits, PRIMARY_GROUP};
    let mut rig = Rig::new(true);
    rig.endpoint
        .carrier_mut()
        .set_sender_control(sender_address());
    let mut limits = CarrierLimits::baseline();
    limits.pace_bytes_per_sec = 2_000_000;
    limits.pace_burst_bytes = 32_000;
    let port = SenderLink {
        media: Rc::clone(&rig.queue),
        feedback: Rc::clone(&rig.sent),
        initial_drops: 0,
        sent: 0,
    };
    // Epoch zero is only the unused bootstrap state; selecting the host
    // profile makes the first actual stream epoch one on both ends.
    let mut sender = CarrierSender::with_port(key(), stream(), 0, limits, port).unwrap();
    sender.add_peer(7, address(), address(), 1500).unwrap();
    sender
        .select_group_fec(PRIMARY_GROUP, 1, rig.start, &[7])
        .unwrap();
    assert_eq!(
        sender
            .submit_group_fec_window(PRIMARY_GROUP, 1, 0, source(0), 70 * MS)
            .unwrap()
            .queued,
        8
    );
    let cancel = AtomicBool::new(false);
    for now in 70..90 {
        rig.at(now * MS);
        let view = franken_stream::playout::ClockView {
            group_ns: rig.group_at(rig.time.get()),
            uncertainty_ns: 500_000,
            usable: true,
        };
        sender.pump_fec(now * MS, &[(PRIMARY_GROUP, view)], &cancel);
    }
    assert_eq!(sender.port().sent, 8);
    let initial_sent = sender.port().sent;
    assert_eq!(sender.port().initial_drops, 5);
    assert_eq!(rig.poll().media_accepted, 3);
    assert_eq!(
        sender.peer_view(7).unwrap().in_flight,
        0,
        "FEC cannot spend N01 cumulative credit"
    );

    rig.at(150 * MS);
    assert_eq!(
        step(&mut rig).unwrap().feedback,
        Ok(FeedbackProgress::Sent { window: 0 })
    );
    assert_eq!(
        rig.endpoint.carrier().port().last_control_to.get(),
        Some(sender_address())
    );
    rig.at(151 * MS);
    let view = franken_stream::playout::ClockView {
        group_ns: rig.group_at(rig.time.get()),
        uncertainty_ns: 500_000,
        usable: true,
    };
    sender.pump_fec(151 * MS, &[(PRIMARY_GROUP, view)], &cancel);
    assert_eq!(
        sender.port().sent,
        9,
        "same paced sender emitted the real repair"
    );
    assert_eq!(rig.poll().media_accepted, 1);
    assert_eq!(rig.endpoint.verdicts().fec_retransmit, 1);
    rig.at(rig.local_at_cutoff(20_000));
    let mut out = [0; BLOCK_PAYLOAD_BYTES];
    let Preparation::Prepared(block) = rig
        .endpoint
        .prepare(&mut rig.platform, &mut rig.clock, &mut out)
        .unwrap()
    else {
        panic!("actual transport roundtrip did not reach prepared PCM");
    };
    assert_eq!(block.decision.outcome, Outcome::Real);
    assert_eq!(out, source(0)[0]);
    println!(
        "N06-PACED-ENDPOINT {}",
        serde_json::json!({
            "schema":"n06.paced-endpoint.v1", "profile":fec::PROFILE,
            "initial_sent":initial_sent, "injected_losses":sender.port().initial_drops,
            "tail_sent":sender.port().sent - initial_sent,
            "feedback":rig.endpoint.feedback_counters(),
            "prepared_real":block.decision.outcome == Outcome::Real,
            "proof":"scripted-host-link-real-carrier-endpoint-wire",
        })
    );
}
