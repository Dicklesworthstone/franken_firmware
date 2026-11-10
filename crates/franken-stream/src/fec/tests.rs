use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

// Test owner of the REAL existing N04 engine and real reusable FEC receiver.
// No fake decoder, wire authenticator or playout implementation.
struct Rig {
    fec: Receiver,
    engine: PlayoutEngine,
}
impl std::ops::Deref for Rig {
    type Target = Receiver;
    fn deref(&self) -> &Receiver {
        &self.fec
    }
}
impl std::ops::DerefMut for Rig {
    fn deref_mut(&mut self) -> &mut Receiver {
        &mut self.fec
    }
}
impl Rig {
    fn new(config: SessionConfig) -> Result<Self, Refusal> {
        let mut engine = PlayoutEngine::new(
            playout::PlayoutProfile::MUSIC,
            playout::PlayoutConfig {
                work_ns: WORK_NS,
                lead_ns: LEAD_NS,
                tolerance_ns: 0,
            },
        )
        .unwrap();
        engine
            .begin_stream(config.epoch, 0, config.presentation_origin_ns)
            .unwrap();
        Ok(Self {
            fec: Receiver::new(config)?,
            engine,
        })
    }
    fn ingest(&mut self, v: ClockView, w: &[u8]) -> Result<Option<Admission>, Refusal> {
        self.fec
            .ingest(&mut self.engine, v, w)
            .map(|event| event.admission)
    }
    fn poll(&mut self, v: ClockView, c: &AtomicBool) -> Result<DecodeState, Refusal> {
        let state = self.fec.poll(&mut self.engine, v, c)?;
        if state == DecodeState::Ready {
            self.fec.publish(&mut self.engine, v, c)
        } else {
            Ok(state)
        }
    }
    fn feedback(&mut self, v: ClockView) -> Result<Option<Feedback>, Refusal> {
        self.fec.feedback(&self.engine, v)
    }
    fn decide(&mut self, v: ClockView, out: &mut [u8; BYTES]) -> Poll {
        self.fec.decide(&mut self.engine, v, out)
    }
    fn snapshot(&self) -> playout::EngineSnapshot {
        self.engine.snapshot()
    }
    fn transition(&mut self, c: SessionConfig) -> Result<(), Refusal> {
        self.fec.transition(&mut self.engine, c)
    }
}

fn config() -> SessionConfig {
    SessionConfig {
        stream: StreamId::new(0x60601).unwrap(),
        epoch: 1,
        presentation_origin_ns: 500_000_000,
        key: StreamKey::from_bytes([0x66; 32]),
    }
}
fn source(window: u64) -> [[u8; BYTES]; K] {
    std::array::from_fn(|i| {
        std::array::from_fn(|b| ((0x60601 + window as usize * 29 + i * 37 + b * 11) % 251) as u8)
    })
}
fn view(group_ns: u64) -> ClockView {
    ClockView {
        group_ns,
        uncertainty_ns: GUARD_NS,
        usable: true,
    }
}
fn feed(receiver: &mut Rig, window: u64, mask: u8, now: u64) {
    let cfg = receiver.config.clone();
    let src = source(window);
    let digest = content_digest(&cfg.metadata(window).unwrap(), &src);
    for esi in 0..N {
        if mask & (1 << esi) != 0 {
            let wire = sign_symbol(
                &cfg,
                window,
                esi,
                if esi < K { 0 } else { 2 },
                digest,
                &encode_symbol(&src, esi).unwrap(),
            )
            .unwrap();
            let admitted = receiver.ingest(view(now), &wire).unwrap();
            assert_eq!(admitted.is_some(), esi < K);
        }
    }
}
fn finish(receiver: &mut Rig, now: u64) -> DecodeState {
    let cancel = AtomicBool::new(false);
    for step in 0..1000 {
        match receiver.poll(view(now + step * 30_000), &cancel) {
            Ok(DecodeState::Pending) => {}
            Ok(state) => return state,
            Err(Refusal::Deadline | Refusal::Protected { .. }) => {}
            Err(error) => panic!("poll refusal {error:?}"),
        }
    }
    panic!("bounded decoder did not complete")
}
fn decide(receiver: &mut Rig, block: u64) -> (playout::Outcome, [u8; BYTES]) {
    let mut bytes = [0; BYTES];
    let at = receiver
        .cutoff(block, GUARD_NS)
        .max(receiver.last_clock.unwrap_or(0));
    let Poll::Decision(result) = receiver.decide(view(at), &mut bytes) else {
        panic!("missing decision")
    };
    assert_eq!(result.block, block);
    (result.outcome, bytes)
}

fn symbol(cfg: &SessionConfig, window: u64, esi: usize, kind: u8) -> [u8; DATAGRAM] {
    let src = source(window);
    sign_symbol(
        cfg,
        window,
        esi,
        kind,
        content_digest(&cfg.metadata(window).unwrap(), &src),
        &encode_symbol(&src, esi).unwrap(),
    )
    .unwrap()
}

#[test]
fn n06_six_member_feedback_is_fair_at_the_fleet_cap_and_one_broadcast_is_final() {
    let cfg = config();
    let mut receivers: Vec<Rig> = (0..6).map(|_| Rig::new(cfg.clone()).unwrap()).collect();
    let mut requests = Vec::new();
    for (index, receiver) in receivers.iter_mut().enumerate() {
        feed(receiver, 0, if index < 4 { 14 } else { 7 }, 20_000_000);
        assert_eq!(
            receiver.poll(view(80_000_000), &AtomicBool::new(false)),
            Ok(DecodeState::Idle)
        );
        let request = receiver.feedback(view(80_000_000)).unwrap().unwrap();
        assert_eq!(request.0[64], if index < 4 { 1 } else { 8 });
        requests.push(request);
    }
    let mut sender = SenderWindow::new(cfg.clone(), 0, source(0), receivers.len()).unwrap();
    assert_eq!(sender.check_limit(), 7);
    let mut replies = Vec::new();
    for (index, request) in requests.iter().enumerate() {
        match sender.serve(view(100_000_000), &request.0, &AtomicBool::new(false)) {
            Ok(reply) => {
                assert!(index == 0 || index == 4);
                replies.extend(reply.packets.into_iter().flatten());
            }
            Err(Refusal::Duplicate) => assert!(matches!(index, 1..=3 | 5)),
            other => panic!(
                "member{index} not served by the bounded union: {}",
                other.is_ok()
            ),
        }
    }
    // Snapshot the six-member interval before the later rollover probe.
    let fleet_checks = sender.checks_used();
    let fleet_work = sender.charged_work();
    assert_eq!(fleet_checks, 6);
    assert_eq!(fleet_work, 6 * AUTH_WORK + 2 * (AUTH_WORK + 1024 + 1000));
    assert_eq!(replies.len(), 2);
    assert!(fleet_work * WORK_UNIT_NS <= WINDOW_ALLOWANCE_NS);
    for packet in &replies {
        for receiver in &mut receivers {
            assert!(matches!(
                receiver.ingest(view(105_000_000), packet),
                Ok(Some(Admission::Admitted)) | Err(Refusal::Duplicate)
            ));
        }
    }
    let mut observed = Vec::new();
    for (member, receiver) in receivers.iter_mut().enumerate() {
        for block in 0..4 {
            let (outcome, bytes) = decide(receiver, block);
            assert_eq!(
                (outcome, bytes),
                (playout::Outcome::Real, source(0)[block as usize])
            );
            let hash: String = Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            observed.push(serde_json::json!({"member":member,"block":block,"outcome":outcome.code(),"pcm_sha256":hash}));
        }
    }
    // Losing a single broadcast is a declared failure, not an infinite resend policy.
    assert!(matches!(
        sender.serve(view(130_000_000), &requests[0].0, &AtomicBool::new(false)),
        Err(Refusal::Duplicate)
    ));
    assert_eq!(sender.checks_used(), 1);
    assert_eq!(sender.charged_work(), AUTH_WORK);
    assert!(SenderWindow::new(cfg.clone(), 0, source(0), 0).is_err());
    assert!(SenderWindow::new(cfg.clone(), 0, source(0), 22).is_err());
    let mut fleet = SenderWindow::new(cfg, 0, source(0), MAX_GROUP_MEMBERS).unwrap();
    assert_eq!(fleet.check_limit(), 22);
    for _ in 0..MAX_GROUP_MEMBERS {
        let result = fleet.serve(view(100_000_000), &requests[0].0, &AtomicBool::new(false));
        assert!(result.is_ok() || matches!(result, Err(Refusal::Duplicate)));
    }
    assert_eq!(fleet.checks_used(), 21);
    assert!(fleet.charged_work() * WORK_UNIT_NS <= WINDOW_ALLOWANCE_NS);
    println!(
        "N06-FLEET {}",
        serde_json::json!({"schema":"n06.fleet.v1","profile":PROFILE,"group_members":receivers.len(),"fleet_cap":MAX_GROUP_MEMBERS,"checks":fleet_checks,"check_limit":sender.check_limit(),"charged_work":fleet_work,"request_masks":requests.iter().map(|request| request.0[64]).collect::<Vec<_>>(),"reply_esis":replies.iter().map(|packet| packet[72]).collect::<Vec<_>>(),"output":observed})
    );
}

#[test]
fn n06_pre_roll_rebind_retains_sources_and_complete_credit_identity_changes_with_origin() {
    let cfg = config();
    let mut receiver = Rig::new(cfg.clone()).unwrap();
    assert_eq!(
        receiver.ingest(view(20_000_000), &symbol(&cfg, 0, 0, 0)),
        Ok(Some(Admission::Admitted))
    );
    receiver
        .engine
        .begin_stream(cfg.epoch, 0, cfg.presentation_origin_ns)
        .unwrap();
    receiver
        .fec
        .rebind(&receiver.engine, cfg.presentation_origin_ns)
        .unwrap();
    assert_eq!(receiver.windows[0].mask, 1);
    assert_eq!(receiver.windows[0].published, 0);
    assert_eq!(
        receiver.poll(view(80_000_000), &AtomicBool::new(false)),
        Ok(DecodeState::Idle)
    );
    assert_eq!(receiver.counters.source_reoffers, 1);
    assert_eq!(receiver.windows[0].published, 1);
    assert_eq!(
        decide(&mut receiver, 0),
        (playout::Outcome::Real, source(0)[0])
    );

    let mut identity = Rig::new(cfg.clone()).unwrap();
    let before = identity
        .fec
        .ingest(
            &mut identity.engine,
            view(20_000_000),
            &symbol(&cfg, 0, 2, 0),
        )
        .unwrap();
    assert_eq!(
        before.credit_key(),
        (
            cfg.stream.get(),
            cfg.epoch,
            cfg.presentation_origin_ns,
            IngressKind::Source,
            2
        )
    );
    let mut changed = cfg.clone();
    changed.presentation_origin_ns += 100_000_000;
    identity
        .engine
        .begin_stream(changed.epoch, 0, changed.presentation_origin_ns)
        .unwrap();
    identity
        .fec
        .rebind(&identity.engine, changed.presentation_origin_ns)
        .unwrap();
    let after = identity
        .fec
        .ingest(
            &mut identity.engine,
            view(120_000_000),
            &symbol(&changed, 0, 2, 0),
        )
        .unwrap();
    assert_ne!(before.credit_key(), after.credit_key());
    assert_eq!(after.sequence, before.sequence);
    assert_eq!(after.epoch, before.epoch);
    assert_eq!(after.stream, before.stream);
    for block in 0..2 {
        decide(&mut identity, block);
    }
    assert_eq!(
        decide(&mut identity, 2),
        (playout::Outcome::Real, source(0)[2])
    );
}

#[test]
fn n06_distinct_forgery_work_exhaustion_and_targeted_pair_denial_have_live_recovery() {
    let cfg = config();
    let mut receiver = Rig::new(cfg.clone()).unwrap();
    let mut authenticated_failures = 0;
    let mut refused_work = 0;
    for window in 1..=8 {
        for esi in 0..N {
            let mut wire = symbol(&cfg, window, esi, if esi < K { 0 } else { 2 });
            wire[DATAGRAM - 1] ^= 1;
            match receiver.ingest(view(150_000_000), &wire) {
                Err(Refusal::Authentication) => authenticated_failures += 1,
                Err(Refusal::Work) => refused_work += 1,
                other => panic!("unexpected bounded forged-pair result {other:?}"),
            }
        }
    }
    assert_eq!(authenticated_failures, 48);
    assert_eq!(refused_work, 16);
    assert_eq!(receiver.counters.auth_work, 48 * AUTH_WORK);
    assert_eq!(
        receiver.ingest(view(150_000_000), &symbol(&cfg, 7, 2, 0)),
        Err(Refusal::Work)
    );
    assert!(receiver.windows.iter().all(|window| window.mask == 0));
    feed(&mut receiver, 7, 252, 172_000_000);
    assert_eq!(finish(&mut receiver, 230_000_000), DecodeState::Ready);
    for block in 0..28 {
        decide(&mut receiver, block);
    }
    assert_eq!(
        decide(&mut receiver, 28),
        (playout::Outcome::Real, source(7)[0])
    );

    let mut targeted = Rig::new(cfg.clone()).unwrap();
    let mut bad = symbol(&cfg, 0, 2, 0);
    bad[DATAGRAM - 1] ^= 1;
    for _ in 0..AUTH_PAIR_ATTEMPTS {
        assert_eq!(
            targeted.ingest(view(20_000_000), &bad),
            Err(Refusal::Authentication)
        );
    }
    assert_eq!(
        targeted.ingest(view(20_000_000), &symbol(&cfg, 0, 2, 0)),
        Err(Refusal::Storm)
    );
    feed(&mut targeted, 0, 248, 20_000_000);
    assert_eq!(finish(&mut targeted, 80_000_000), DecodeState::Ready);
    for block in 0..4 {
        assert_eq!(
            decide(&mut targeted, block),
            (playout::Outcome::Real, source(0)[block as usize])
        );
    }
}

#[test]
fn n06_rebind_preserves_pair_quota_until_next_interval() {
    let cfg = config();
    let mut receiver = Rig::new(cfg.clone()).unwrap();
    let mut bad = symbol(&cfg, 0, 2, 0);
    bad[DATAGRAM - 1] ^= 1;
    for _ in 0..AUTH_PAIR_ATTEMPTS {
        assert_eq!(
            receiver.ingest(view(20_000_000), &bad),
            Err(Refusal::Authentication)
        );
    }
    let charged = receiver.charged;
    receiver
        .engine
        .begin_stream(cfg.epoch, 0, cfg.presentation_origin_ns)
        .unwrap();
    receiver
        .fec
        .rebind(&receiver.engine, cfg.presentation_origin_ns)
        .unwrap();
    assert_eq!(receiver.charged, charged);
    // A backwards reading, even on malformed input, cannot anchor a fresh
    // interval or refund either work or the targeted pair's quota.
    assert_eq!(receiver.ingest(view(0), &[]), Err(Refusal::Clock));
    assert_eq!(receiver.last_clock, Some(20_000_000));
    assert_eq!(receiver.rebase_start, None);
    assert_eq!(receiver.charged, charged);
    assert_eq!(
        receiver.ingest(view(20_000_000), &symbol(&cfg, 0, 2, 0)),
        Err(Refusal::Storm)
    );
    assert_eq!(
        receiver.ingest(
            view(20_000_000 + WORK_INTERVAL_NS - 1),
            &symbol(&cfg, 0, 2, 0)
        ),
        Err(Refusal::Storm)
    );
    assert_eq!(receiver.charged, charged);
    // Expiry is still inside the aligned interval that saw the prior attempt.
    assert_eq!(
        receiver.ingest(view(20_000_000 + WORK_INTERVAL_NS), &symbol(&cfg, 0, 2, 0)),
        Err(Refusal::Storm)
    );
    assert_eq!(receiver.charged, charged);
    assert_eq!(
        receiver.ingest(view(42_666_667), &symbol(&cfg, 0, 2, 0)),
        Ok(Some(Admission::Admitted))
    );
    decide(&mut receiver, 0);
    decide(&mut receiver, 1);
    assert_eq!(decide(&mut receiver, 2).0, playout::Outcome::Real);
}

#[test]
fn n06_epoch_transition_preserves_work_cap_and_next_interval_recovers() {
    let cfg = config();
    let mut receiver = Rig::new(cfg.clone()).unwrap();
    let mut failures = 0;
    let mut refused = 0;
    for window in 1..=8 {
        for esi in 0..N {
            let mut wire = symbol(&cfg, window, esi, if esi < K { 0 } else { 2 });
            wire[DATAGRAM - 1] ^= 1;
            match receiver.ingest(view(150_000_000), &wire) {
                Err(Refusal::Authentication) => failures += 1,
                Err(Refusal::Work) => refused += 1,
                other => panic!("unexpected forged-pair result {other:?}"),
            }
        }
    }
    assert_eq!((failures, refused), (48, 16));
    assert_eq!(receiver.charged, 48 * AUTH_WORK);
    let mut next = cfg;
    next.epoch += 1;
    receiver.transition(next.clone()).unwrap();
    assert_eq!(receiver.charged, 48 * AUTH_WORK);
    assert_eq!(
        receiver.ingest(view(150_000_000), &symbol(&next, 7, 0, 0)),
        Err(Refusal::Work)
    );
    feed(&mut receiver, 7, 252, 172_000_000);
    assert_eq!(finish(&mut receiver, 230_000_000), DecodeState::Ready);
    for block in 0..28 {
        decide(&mut receiver, block);
    }
    assert_eq!(
        decide(&mut receiver, 28),
        (playout::Outcome::Real, source(7)[0])
    );
}

#[test]
fn n06_epoch_new_leader_clock_rebases_work_without_refund_or_stranding() {
    for (old_origin, new_origin) in [
        (100_500_000_000, 500_000_000),
        (500_000_000, 100_500_000_000),
    ] {
        let mut old = config();
        old.presentation_origin_ns = old_origin;
        let old_now = old_origin - 350_000_000;
        let mut receiver = Rig::new(old.clone()).unwrap();
        let mut failures = 0;
        let mut refused = 0;
        for window in 1..=8 {
            for esi in 0..N {
                let mut wire = symbol(&old, window, esi, if esi < K { 0 } else { 2 });
                wire[DATAGRAM - 1] ^= 1;
                match receiver.ingest(view(old_now), &wire) {
                    Err(Refusal::Authentication) => failures += 1,
                    Err(Refusal::Work) => refused += 1,
                    other => panic!("unexpected old-domain result {other:?}"),
                }
            }
        }
        assert_eq!((failures, refused), (48, 16));
        let mut next = old;
        next.epoch += 1;
        next.presentation_origin_ns = new_origin;
        receiver.transition(next.clone()).unwrap();
        let new_now = new_origin - 350_000_000;
        let packet = symbol(&next, 7, 0, 0);
        let mut unusable = view(new_now);
        unusable.usable = false;
        assert_eq!(receiver.ingest(unusable, &packet), Err(Refusal::Clock));
        assert_eq!(receiver.rebase_start, None);
        assert_eq!(receiver.charged, 48 * AUTH_WORK);
        assert_eq!(receiver.ingest(view(new_now), &packet), Err(Refusal::Work));
        assert_eq!(receiver.charged, 48 * AUTH_WORK);
        assert_eq!(
            receiver.ingest(view(new_now + WORK_INTERVAL_NS - 1), &packet),
            Err(Refusal::Work)
        );
        // Expiry follows an attempt in this same aligned interval, so the
        // ledger stays charged until the next aligned boundary.
        assert_eq!(
            receiver.ingest(view(new_now + WORK_INTERVAL_NS), &packet),
            Err(Refusal::Work)
        );
        let interval = work_interval(new_now + WORK_INTERVAL_NS);
        let next_boundary =
            (u128::from(interval + 1) * 1024 * 1_000_000_000).div_ceil(48_000) as u64;
        feed(&mut receiver, 7, 252, next_boundary);
        assert_eq!(
            finish(&mut receiver, new_now + 80_000_000),
            DecodeState::Ready
        );
        for block in 0..28 {
            decide(&mut receiver, block);
        }
        assert_eq!(
            decide(&mut receiver, 28),
            (playout::Outcome::Real, source(7)[0])
        );
    }
}

#[test]
fn n06_rebase_cannot_refund_work_spent_in_the_same_aligned_interval() {
    let cfg = config();
    let mut receiver = Rig::new(cfg.clone()).unwrap();
    // Establish the old timeline and rebind; neither malformed packet costs MAC work.
    assert_eq!(receiver.ingest(view(150_000_000), &[]), Err(Refusal::Shape));
    receiver
        .engine
        .begin_stream(cfg.epoch, 0, cfg.presentation_origin_ns)
        .unwrap();
    receiver
        .fec
        .rebind(&receiver.engine, cfg.presentation_origin_ns)
        .unwrap();
    assert_eq!(receiver.ingest(view(150_000_000), &[]), Err(Refusal::Shape));
    let before_expiry = 150_000_000 + WORK_INTERVAL_NS - 1;
    for window in 2..8 {
        for esi in 0..N {
            let mut forged = symbol(&cfg, window, esi, if esi < K { 0 } else { 2 });
            forged[DATAGRAM - 1] ^= 1;
            assert_eq!(
                receiver.ingest(view(before_expiry), &forged),
                Err(Refusal::Authentication)
            );
        }
    }
    assert_eq!(receiver.charged, 48 * AUTH_WORK);
    let genuine = symbol(&cfg, 8, 0, 0);
    assert_eq!(
        receiver.ingest(view(150_000_000 + WORK_INTERVAL_NS), &genuine),
        Err(Refusal::Work)
    );
    assert_eq!(receiver.charged, 48 * AUTH_WORK);
    assert_eq!(
        receiver.ingest(view(192_000_000), &genuine),
        Ok(Some(Admission::Admitted))
    );
    feed(&mut receiver, 8, 252, 192_000_000);
    assert_eq!(finish(&mut receiver, 270_000_000), DecodeState::Ready);
    for block in 0..32 {
        decide(&mut receiver, block);
    }
    assert_eq!(
        decide(&mut receiver, 32),
        (playout::Outcome::Real, source(8)[0])
    );
    assert_eq!(
        decide(&mut receiver, 33),
        (playout::Outcome::Real, source(8)[1])
    );
}

#[test]
fn n06_rebase_accounts_for_publication_in_the_fresh_clock_interval() {
    let cfg = config();
    let mut receiver = Rig::new(cfg.clone()).unwrap();
    feed(&mut receiver, 0, 252, 20_000_000);
    receiver
        .engine
        .begin_stream(cfg.epoch, 0, cfg.presentation_origin_ns)
        .unwrap();
    receiver
        .fec
        .rebind(&receiver.engine, cfg.presentation_origin_ns)
        .unwrap();
    assert_eq!(receiver.ingest(view(80_000_000), &[]), Err(Refusal::Shape));
    let cancelled = AtomicBool::new(false);
    let mut ready = false;
    for _ in 0..1000 {
        match receiver
            .fec
            .poll(&mut receiver.engine, view(84_000_000), &cancelled)
        {
            Ok(DecodeState::Pending) => {}
            Ok(DecodeState::Ready) => {
                ready = true;
                break;
            }
            other => panic!("unexpected decode state {other:?}"),
        }
    }
    assert!(ready, "bounded decode did not reach publication");
    let before = receiver.charged;
    assert_eq!(
        receiver
            .fec
            .publish(&mut receiver.engine, view(100_000_000), &cancelled),
        Ok(DecodeState::Ready)
    );
    let after = receiver.charged;
    assert!(after > before, "publication must charge real work");
    assert_eq!(
        receiver.ingest(view(80_000_000 + WORK_INTERVAL_NS), &[]),
        Err(Refusal::Shape)
    );
    assert_eq!(receiver.charged, after);
    assert_eq!(
        decide(&mut receiver, 0),
        (playout::Outcome::Real, source(0)[0])
    );
    assert_eq!(
        decide(&mut receiver, 1),
        (playout::Outcome::Real, source(0)[1])
    );
}

#[test]
fn n06_stored_source_retries_after_horizon_and_old_alias_cannot_evict_newer() {
    let cfg = config();
    let mut rig = Rig::new(cfg.clone()).unwrap();
    let wire = symbol(&cfg, 23, 3, 0); // block95 exceeds cursor0's94-block horizon.
    assert_eq!(
        rig.ingest(view(490_000_000), &wire),
        Ok(Some(Admission::TooFarAhead))
    );
    assert_eq!(rig.windows[7].mask, 8);
    assert_eq!(rig.windows[7].published, 0);
    decide(&mut rig, 0);
    decide(&mut rig, 1);
    let after_render = rig.last_clock.unwrap() + WORK_NS + LEAD_NS;
    assert_eq!(
        rig.poll(view(after_render), &AtomicBool::new(false)),
        Ok(DecodeState::Idle)
    );
    assert_eq!(rig.windows[7].published, 8);
    assert_eq!(rig.counters.source_reoffers, 1);
    for block in 2..95 {
        decide(&mut rig, block);
    }
    assert_eq!(
        decide(&mut rig, 95),
        (playout::Outcome::Real, source(23)[3])
    );

    let mut immediate = Rig::new(cfg.clone()).unwrap();
    let wire = symbol(&cfg, 0, 2, 0);
    assert_eq!(
        immediate.ingest(view(20_000_000), &wire),
        Ok(Some(Admission::Admitted))
    );
    immediate
        .poll(view(80_000_000), &AtomicBool::new(false))
        .unwrap();
    assert_eq!(
        immediate.ingest(view(80_000_000), &wire),
        Err(Refusal::Duplicate)
    );
    assert_eq!(immediate.counters.source_reoffers, 0);
    assert_eq!(immediate.counters.recovered, 0);
    for block in 0..2 {
        decide(&mut immediate, block);
    }
    assert_eq!(
        decide(&mut immediate, 2),
        (playout::Outcome::Real, source(0)[2])
    );

    let mut slots = Rig::new(cfg.clone()).unwrap();
    for window in 3..11 {
        assert_eq!(
            slots.ingest(view(205_000_000), &symbol(&cfg, window, 0, 0)),
            Ok(Some(Admission::Admitted))
        );
    }
    for window in 3..11 {
        assert_eq!(slots.windows[window as usize % WINDOWS].id, Some(window));
        assert_eq!(slots.windows[window as usize % WINDOWS].mask, 1);
    }
    assert_eq!(
        slots.ingest(view(220_000_000), &symbol(&cfg, 11, 0, 0)),
        Ok(Some(Admission::Admitted))
    );
    let digest = slots.windows[3].digest;
    assert_eq!(
        slots.ingest(view(220_000_000), &symbol(&cfg, 3, 1, 0)),
        Err(Refusal::Future)
    );
    assert_eq!(slots.windows[3].id, Some(11));
    assert_eq!(slots.windows[3].mask, 1);
    assert_eq!(slots.windows[3].digest, digest);
    for block in 0..44 {
        decide(&mut slots, block);
    }
    assert_eq!(
        decide(&mut slots, 44),
        (playout::Outcome::Real, source(11)[0])
    );
}

#[test]
fn n06_protected_retry_overdue_render_and_typed_credit_have_real_boundaries() {
    let cfg = config();
    let mut rig = Rig::new(cfg.clone()).unwrap();
    let wire = symbol(&cfg, 23, 0, 0);
    let cutoff = rig.cutoff(0, GUARD_NS);
    for now in [cutoff - AUTH_WORK * WORK_UNIT_NS, cutoff - 1] {
        assert_eq!(
            rig.ingest(view(now), &wire),
            Err(Refusal::Protected {
                until_ns: cutoff + WORK_NS + LEAD_NS
            })
        );
        assert_eq!(rig.counters.auth_work, 0);
        assert!(rig.windows.iter().all(|w| w.mask == 0));
    }
    decide(&mut rig, 0);
    assert!(matches!(
        rig.ingest(view(cutoff + 1), &wire),
        Err(Refusal::Protected { .. })
    ));
    assert_eq!(rig.counters.auth_work, 0);
    assert_eq!(
        rig.ingest(view(cutoff + WORK_NS + LEAD_NS), &wire),
        Ok(Some(Admission::Admitted))
    );
    let overdue = rig.cutoff(1, GUARD_NS) + 3_000_000;
    let used = rig.counters.decode_work;
    assert_eq!(
        rig.poll(view(overdue), &AtomicBool::new(false)),
        Err(Refusal::Protected { until_ns: overdue })
    );
    assert_eq!(rig.counters.decode_work, used);
    decide(&mut rig, 1);
    let after = overdue + WORK_NS + LEAD_NS;
    assert!(!matches!(
        rig.poll(view(after), &AtomicBool::new(false)),
        Err(Refusal::Protected { .. })
    ));
    for block in 2..92 {
        decide(&mut rig, block);
    }
    assert_eq!(
        decide(&mut rig, 92),
        (playout::Outcome::Real, source(23)[0])
    );

    let mut typed = Rig::new(cfg.clone()).unwrap();
    let mut keys = std::collections::HashSet::new();
    for window in 0..8 {
        for esi in 0..N {
            let wire = symbol(&cfg, window, esi, if esi < K { 0 } else { 2 });
            // This is exactly the wrong N01 offset; it is constant for N06.
            assert_eq!(read64(&wire, 24), cfg.epoch << 32);
            let repairs = typed.engine.stats().repairs_seen;
            let event = typed
                .fec
                .ingest(&mut typed.engine, view((window + 1) * 20_000_000), &wire)
                .unwrap();
            assert_eq!(event.sequence, window * 8 + esi as u64);
            assert!(keys.insert(event.credit_key()));
            if esi >= K {
                assert_eq!(event.admission, None);
                assert_eq!(typed.engine.stats().repairs_seen, repairs);
            }
        }
    }
    let mut retransmit = Rig::new(cfg.clone()).unwrap();
    let wire = symbol(&cfg, 0, 0, 1);
    let event = retransmit
        .fec
        .ingest(&mut retransmit.engine, view(20_000_000), &wire)
        .unwrap();
    assert_eq!(event.admission, Some(Admission::Admitted));
    assert!(
        keys.insert(event.credit_key()),
        "source and retransmit need distinct credit keys"
    );
    assert_eq!(
        decide(&mut retransmit, 0),
        (playout::Outcome::Real, source(0)[0])
    );
}

#[test]
fn n06_earliest_window_failed_transition_and_idle_cancel_preserve_recovery() {
    let mut ordered = Rig::new(config()).unwrap();
    feed(&mut ordered, 7, 252, 220_000_000);
    feed(&mut ordered, 8, 252, 220_000_000);
    assert_eq!(
        ordered.poll(view(260_000_000), &AtomicBool::new(false)),
        Ok(DecodeState::Pending)
    );
    assert_eq!(ordered.status().active_window, Some(7)); // index7 precedes index0 by deadline.
    assert_eq!(finish(&mut ordered, 260_030_000), DecodeState::Ready);
    assert_eq!(finish(&mut ordered, 270_000_000), DecodeState::Ready);
    for block in 0..28 {
        decide(&mut ordered, block);
    }
    assert_eq!(
        decide(&mut ordered, 28),
        (playout::Outcome::Real, source(7)[0])
    );
    for block in 29..32 {
        decide(&mut ordered, block);
    }
    assert_eq!(
        decide(&mut ordered, 32),
        (playout::Outcome::Real, source(8)[0])
    );

    let mut atomic = Rig::new(config()).unwrap();
    feed(&mut atomic, 0, 252, 20_000_000);
    assert_eq!(
        atomic.poll(view(80_000_000), &AtomicBool::new(false)),
        Ok(DecodeState::Pending)
    );
    let before = (
        atomic.active,
        atomic.reserved,
        atomic.solver.used(),
        atomic.engine.snapshot(),
    );
    assert_eq!(atomic.transition(config()), Err(Refusal::Epoch));
    let mut invalid = config();
    invalid.epoch += 1;
    invalid.presentation_origin_ns = super::super::MAX_TIMESTAMP_NS;
    assert_eq!(atomic.transition(invalid), Err(Refusal::Shape));
    assert_eq!(
        (
            atomic.active,
            atomic.reserved,
            atomic.solver.used(),
            atomic.engine.snapshot()
        ),
        before
    );
    assert_eq!(finish(&mut atomic, 80_030_000), DecodeState::Ready);
    assert_eq!(
        decide(&mut atomic, 0),
        (playout::Outcome::Real, source(0)[0])
    );

    let mut idle = Rig::new(config()).unwrap();
    feed(&mut idle, 0, 12, 20_000_000);
    idle.cancel();
    assert!(!idle.windows[0].cancelled);
    assert!(!idle.windows[0].attempted);
    feed(&mut idle, 0, 240, 30_000_000);
    assert_eq!(finish(&mut idle, 80_000_000), DecodeState::Ready);
    assert_eq!(decide(&mut idle, 0), (playout::Outcome::Real, source(0)[0]));
}

#[test]
fn n06_two_receivers_different_losses_share_bounded_broadcast_tail() {
    let cfg = config();
    let mut a = Rig::new(cfg.clone()).unwrap();
    let mut b = Rig::new(cfg.clone()).unwrap();
    feed(&mut a, 0, 12, 20_000_000);
    feed(&mut b, 0, 3, 20_000_000);
    for rig in [&mut a, &mut b] {
        assert_eq!(
            rig.poll(view(80_000_000), &AtomicBool::new(false)),
            Ok(DecodeState::Idle)
        );
    }
    let request_a = a.feedback(view(80_000_000)).unwrap().unwrap();
    let request_b = b.feedback(view(80_000_000)).unwrap().unwrap();
    assert_eq!(request_a.0[64], 3);
    assert_eq!(request_b.0[64], 12);
    let mut sender = SenderWindow::new(cfg, 0, source(0), 3).unwrap();
    let mut bad = request_a.0;
    bad[95] ^= 1;
    assert!(matches!(
        sender.serve(view(100_000_000), &bad, &AtomicBool::new(false)),
        Err(Refusal::Authentication)
    ));
    let replies_a = sender
        .serve(view(100_000_000), &request_a.0, &AtomicBool::new(false))
        .unwrap();
    let replies_b = sender
        .serve(view(100_000_000), &request_b.0, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(replies_a.admitted, 3);
    assert_eq!(replies_b.admitted, 12);
    assert_eq!(
        replies_a.packets.iter().flatten().count() + replies_b.packets.iter().flatten().count(),
        4
    );
    for reply in [replies_a, replies_b] {
        for packet in reply.packets.into_iter().flatten() {
            for receiver in [&mut a, &mut b] {
                assert!(matches!(
                    receiver.ingest(view(105_000_000), &packet),
                    Ok(Some(Admission::Admitted)) | Err(Refusal::Duplicate)
                ));
            }
        }
    }
    assert_eq!(sender.sent_mask, 15);
    assert!(matches!(
        sender.serve(view(130_000_000), &request_b.0, &AtomicBool::new(false)),
        Err(Refusal::Duplicate)
    ));
    for receiver in [&mut a, &mut b] {
        assert_eq!(
            receiver.counters.recovered, 0,
            "this positive is real retransmission, not FEC"
        );
        for block in 0..4 {
            assert_eq!(
                decide(receiver, block),
                (playout::Outcome::Real, source(0)[block as usize])
            );
        }
    }
}

#[test]
fn n06_authenticated_recovery_reaches_the_real_n04_consumer_once() {
    let mut receiver = Rig::new(config()).unwrap();
    feed(&mut receiver, 0, 252, 20_000_000);
    assert_eq!(finish(&mut receiver, 80_000_000), DecodeState::Ready);
    assert_eq!(receiver.counters.recovered, 2);
    let cfg = receiver.config.clone();
    let src = source(0);
    let tail = sign_symbol(
        &cfg,
        0,
        0,
        1,
        content_digest(&cfg.metadata(0).unwrap(), &src),
        &src[0],
    )
    .unwrap();
    assert_eq!(
        receiver.ingest(view(90_000_000), &tail),
        Ok(Some(Admission::Duplicate))
    );
    assert_eq!(receiver.counters.n04_duplicate, 1);
    for block in 0..4 {
        let (outcome, bytes) = decide(&mut receiver, block);
        assert_eq!(outcome, playout::Outcome::Real);
        assert_eq!(bytes, source(0)[block as usize]);
    }
    assert_eq!(receiver.snapshot().cursor, 4);
    let mut bytes = [0; BYTES];
    assert!(!matches!(
        receiver.decide(view(receiver.cutoff(3, GUARD_NS)), &mut bytes),
        Poll::Decision(_)
    ));
}

#[test]
fn n06_corrupt_authenticated_equations_and_source_digest_never_publish_recovery() {
    for contradictory in [true, false] {
        let mut receiver = Rig::new(config()).unwrap();
        let cfg = config();
        let src = source(0);
        let mut digest = content_digest(&cfg.metadata(0).unwrap(), &src);
        if !contradictory {
            digest[0] ^= 1;
        }
        for esi in 2..8 {
            let mut payload = encode_symbol(&src, esi).unwrap();
            if contradictory && esi == 7 {
                payload[7] ^= 1;
            }
            let wire =
                sign_symbol(&cfg, 0, esi, if esi < K { 0 } else { 2 }, digest, &payload).unwrap();
            let _ = receiver.ingest(view(20_000_000), &wire).unwrap();
        }
        assert_eq!(
            finish(&mut receiver, 80_000_000),
            if contradictory {
                DecodeState::Contradiction
            } else {
                DecodeState::Integrity
            }
        );
        assert_eq!(receiver.counters.recovered, 0);
        assert_eq!(receiver.counters.fallback, 1);
        assert_ne!(decide(&mut receiver, 0).0, playout::Outcome::Real);
        assert_eq!(decide(&mut receiver, 1).0, playout::Outcome::MutedNoHistory);
        assert_eq!(decide(&mut receiver, 2).0, playout::Outcome::Real);
    }
}

#[test]
fn n06_shape_identity_epoch_and_symbol_fuzz_are_bounded_before_state_commit() {
    let cfg = config();
    let src = source(0);
    let digest = content_digest(&cfg.metadata(0).unwrap(), &src);
    let honest = sign_symbol(&cfg, 0, 2, 0, digest, &src[2]).unwrap();
    for offset in [
        0,
        4,
        5,
        6,
        7,
        8,
        10,
        12,
        20,
        28,
        36,
        44,
        52,
        64,
        72,
        73,
        74,
        80,
        112,
        DATAGRAM - 1,
    ] {
        let mut receiver = Rig::new(cfg.clone()).unwrap();
        let mut wire = honest;
        wire[offset] ^= 0x80;
        assert!(receiver.ingest(view(20_000_000), &wire).is_err());
        assert!(receiver.windows.iter().all(|w| w.mask == 0));
        assert_eq!(
            receiver.ingest(view(20_000_000), &honest),
            Ok(Some(Admission::Admitted))
        );
    }
    for offset in [6, 7, 8, 20, 28, 36, 44, 52, 64, 72, 73, 74] {
        let mut receiver = Rig::new(cfg.clone()).unwrap();
        let mut wire = honest;
        wire[offset] ^= 0xff;
        let mac = tag(&cfg.key, &wire[..HEADER + BYTES]);
        wire[HEADER + BYTES..].copy_from_slice(&mac);
        assert!(receiver.ingest(view(20_000_000), &wire).is_err());
        assert!(receiver.windows.iter().all(|w| w.mask == 0));
    }
    let mut receiver = Rig::new(cfg).unwrap();
    for length in [0, 1, HEADER, DATAGRAM - 1] {
        assert_eq!(
            receiver.ingest(view(0), &honest[..length]),
            Err(Refusal::Shape)
        );
    }
    assert_eq!(receiver.counters.auth_work, 0);
}

#[test]
fn n06_duplicate_and_packet_storm_caps_leave_fixed_state_and_later_recovery() {
    let cfg = config();
    let src = source(0);
    let digest = content_digest(&cfg.metadata(0).unwrap(), &src);
    let wire = sign_symbol(&cfg, 0, 2, 0, digest, &src[2]).unwrap();
    let mut receiver = Rig::new(cfg.clone()).unwrap();
    assert_eq!(
        receiver.ingest(view(1_000_000), &wire),
        Ok(Some(Admission::Admitted))
    );
    let before = receiver.counters.auth_work;
    for _ in 0..100 {
        assert_eq!(
            receiver.ingest(view(1_000_000), &wire),
            Err(Refusal::Duplicate)
        );
    }
    assert_eq!(receiver.counters.auth_work, before);
    let genuine = sign_symbol(&cfg, 0, 3, 0, digest, &src[3]).unwrap();
    assert_eq!(
        receiver.ingest(view(1_000_000), &genuine),
        Ok(Some(Admission::Admitted))
    );
    let mut protected = Rig::new(cfg.clone()).unwrap();
    for window in [1, 2] {
        let src = source(window);
        let digest = content_digest(&cfg.metadata(window).unwrap(), &src);
        for esi in 0..N {
            let mut bad = sign_symbol(
                &cfg,
                window,
                esi,
                if esi < K { 0 } else { 2 },
                digest,
                &encode_symbol(&src, esi).unwrap(),
            )
            .unwrap();
            bad[DATAGRAM - 1] ^= 1;
            assert_eq!(
                protected.ingest(view(50_000_000), &bad),
                Err(Refusal::Authentication)
            );
        }
    }
    assert!(protected.windows.iter().all(|w| w.mask == 0));
    feed(&mut protected, 0, 252, 50_000_000);
    assert_eq!(protected.counters.authenticated, 6);
    assert_eq!(finish(&mut protected, 80_000_000), DecodeState::Ready);
    assert_eq!(protected.counters.recovered, 2);
    let mut bad = sign_symbol(
        &cfg,
        1,
        0,
        0,
        content_digest(&cfg.metadata(1).unwrap(), &source(1)),
        &source(1)[0],
    )
    .unwrap();
    bad[DATAGRAM - 1] ^= 1;
    let mut limited = Rig::new(cfg).unwrap();
    for _ in 0..AUTH_PAIR_ATTEMPTS {
        assert_eq!(
            limited.ingest(view(1_000_000), &bad),
            Err(Refusal::Authentication)
        );
    }
    let work = limited.counters.auth_work;
    for _ in 0..10_000 {
        assert_eq!(limited.ingest(view(1_000_000), &bad), Err(Refusal::Storm));
    }
    assert_eq!(limited.counters.auth_work, work);
    assert_eq!(limited.counters.storm, 10_000);
    feed(&mut limited, 0, 252, 2_000_000);
    assert_eq!(finish(&mut limited, 80_000_000), DecodeState::Ready);
}

#[test]
fn n06_cancel_releases_reservation_and_next_window_and_restart_really_recover() {
    let mut receiver = Rig::new(config()).unwrap();
    feed(&mut receiver, 0, 252, 20_000_000);
    let cancel = AtomicBool::new(false);
    assert_eq!(
        receiver.poll(view(80_000_000), &cancel),
        Ok(DecodeState::Pending)
    );
    let used = receiver.solver.used();
    cancel.store(true, Ordering::Release);
    assert_eq!(
        receiver.poll(view(80_030_000), &cancel),
        Err(Refusal::Cancelled)
    );
    assert_eq!(receiver.reserved, 0);
    assert!(receiver.active.is_none());
    assert_eq!(receiver.solver.used(), used);
    feed(&mut receiver, 1, 252, 85_000_000);
    assert_eq!(finish(&mut receiver, 115_000_000), DecodeState::Ready);
    for b in 0..4 {
        decide(&mut receiver, b);
    }
    assert_eq!(decide(&mut receiver, 4).0, playout::Outcome::Real);
    assert_eq!(decide(&mut receiver, 5).0, playout::Outcome::Real);
    let old = config();
    let mut fresh = old.clone();
    fresh.stream = StreamId::new(0x60602).unwrap();
    fresh.epoch += 1;
    let mut restarted = Rig::new(fresh).unwrap();
    let src = source(0);
    let wire = sign_symbol(
        &old,
        0,
        2,
        0,
        content_digest(&old.metadata(0).unwrap(), &src),
        &src[2],
    )
    .unwrap();
    assert_eq!(
        restarted.ingest(view(20_000_000), &wire),
        Err(Refusal::Identity)
    );
    feed(&mut restarted, 0, 252, 20_000_000);
    assert_eq!(finish(&mut restarted, 80_000_000), DecodeState::Ready);
    assert_eq!(decide(&mut restarted, 0).0, playout::Outcome::Real);
}

#[test]
fn n06_conservative_work_refusal_and_render_protection_keep_following_real() {
    let mut receiver = Rig::new(config()).unwrap();
    feed(&mut receiver, 0, 252, 20_000_000);
    feed(&mut receiver, 1, 15, 40_000_000);
    receiver.charged = WINDOW_ALLOWANCE_NS / WORK_UNIT_NS - MAX_WORK + 1;
    receiver.interval = receiver.source_window(80_000_000);
    assert_eq!(
        receiver.poll(view(80_000_000), &AtomicBool::new(false)),
        Ok(DecodeState::Idle)
    );
    assert_eq!(receiver.counters.work_refused, 1);
    assert_eq!(receiver.counters.recovered, 0);
    for b in 0..4 {
        decide(&mut receiver, b);
    }
    assert_eq!(decide(&mut receiver, 4).0, playout::Outcome::Real);
    let cutoff = receiver.cutoff(5, GUARD_NS);
    let used = receiver.counters.decode_work;
    assert!(matches!(
        receiver.poll(view(cutoff), &AtomicBool::new(false)),
        Err(Refusal::Protected { .. })
    ));
    assert_eq!(receiver.counters.decode_work, used);
    assert_eq!(decide(&mut receiver, 5).0, playout::Outcome::Real);
}

#[test]
fn n06_no_information_hybrid_tail_really_recovers_and_is_one_attempt() {
    let cfg = config();
    let mut receiver = Rig::new(cfg.clone()).unwrap();
    assert_eq!(
        receiver.poll(view(80_000_000), &AtomicBool::new(false)),
        Ok(DecodeState::Idle)
    );
    assert_eq!(receiver.counters.fallback, 1);
    let request = receiver.feedback(view(80_000_000)).unwrap().unwrap();
    assert!(receiver.feedback(view(80_000_000)).unwrap().is_none());
    assert_eq!(receiver.counters.feedback, 1);
    let mut sender = SenderWindow::new(cfg, 0, source(0), 3).unwrap();
    let reply = sender
        .serve(view(100_000_000), &request.0, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(reply.admitted, 15);
    for packet in reply.packets.into_iter().flatten() {
        assert_eq!(
            receiver.ingest(view(105_000_000), &packet),
            Ok(Some(Admission::Admitted))
        );
    }
    assert!(matches!(
        sender.serve(view(100_000_000), &request.0, &AtomicBool::new(false)),
        Err(Refusal::Duplicate)
    ));
    for block in 0..4 {
        let (outcome, bytes) = decide(&mut receiver, block);
        assert_eq!(outcome, playout::Outcome::Real);
        assert_eq!(bytes, source(0)[block as usize]);
    }
}

#[test]
fn n06_authenticated_feedback_corruption_deadline_and_storm_cannot_amplify() {
    let cfg = config();
    let mut receiver = Rig::new(cfg.clone()).unwrap();
    receiver
        .poll(view(80_000_000), &AtomicBool::new(false))
        .unwrap();
    let request = receiver.feedback(view(80_000_000)).unwrap().unwrap();
    let mut bad = request.0;
    bad[64] ^= 1;
    let mut sender = SenderWindow::new(cfg.clone(), 0, source(0), 3).unwrap();
    for _ in 0..4 {
        assert!(matches!(
            sender.serve(view(100_000_000), &bad, &AtomicBool::new(false)),
            Err(Refusal::Authentication)
        ));
    }
    assert!(matches!(
        sender.serve(view(100_000_000), &request.0, &AtomicBool::new(false)),
        Err(Refusal::Storm)
    ));
    assert!(!sender.served);
    assert_eq!(
        sender
            .serve(view(130_000_000), &request.0, &AtomicBool::new(false))
            .unwrap()
            .admitted,
        15
    );
    let mut expired = SenderWindow::new(cfg.clone(), 0, source(0), 3).unwrap();
    assert!(matches!(
        expired.serve(view(600_000_000), &request.0, &AtomicBool::new(false)),
        Err(Refusal::Deadline)
    ));
    assert!(!expired.served);
    let mut fresh = SenderWindow::new(cfg, 0, source(0), 3).unwrap();
    assert!(matches!(
        fresh.serve(view(100_000_000), &request.0, &AtomicBool::new(true)),
        Err(Refusal::Cancelled)
    ));
    assert_eq!(fresh.checks, 0);
    assert_eq!(
        fresh
            .serve(view(100_000_000), &request.0, &AtomicBool::new(false))
            .unwrap()
            .admitted,
        15
    );
}

#[test]
fn n06_inflight_expiry_cannot_publish_over_committed_concealment() {
    let mut receiver = Rig::new(config()).unwrap();
    feed(&mut receiver, 0, 252, 20_000_000);
    feed(&mut receiver, 1, 15, 40_000_000);
    assert_eq!(
        receiver.poll(view(80_000_000), &AtomicBool::new(false)),
        Ok(DecodeState::Pending)
    );
    let before = receiver.counters.decode_work;
    // Commit missing0 once, then let every remaining coding-window cutoff pass.
    let (outcome, committed) = decide(&mut receiver, 0);
    assert_ne!(outcome, playout::Outcome::Real);
    assert!(matches!(
        receiver.poll(view(520_000_000), &AtomicBool::new(false)),
        Err(Refusal::Protected { .. })
    ));
    for b in 1..5 {
        decide(&mut receiver, b);
    }
    assert_eq!(
        receiver.poll(view(522_000_000), &AtomicBool::new(false)),
        Err(Refusal::Deadline)
    );
    assert_eq!(receiver.counters.decode_work, before);
    assert_eq!(receiver.counters.recovered, 0);
    assert_eq!(receiver.reserved, 0);
    assert!(receiver.solver.output(0).is_none());
    assert_eq!(receiver.snapshot().cursor, 5);
    // The chosen bytes were returned by N04 and are not backed by solver memory.
    assert_eq!(committed, [0; BYTES]);
    assert_eq!(decide(&mut receiver, 5).0, playout::Outcome::Real);
}

#[test]
fn n06_stop_and_control_epoch_transition_release_and_rebind_real_recovery() {
    let mut receiver = Rig::new(config()).unwrap();
    feed(&mut receiver, 0, 252, 20_000_000);
    receiver
        .poll(view(80_000_000), &AtomicBool::new(false))
        .unwrap();
    receiver.stop();
    assert_eq!(receiver.reserved, 0);
    assert!(receiver.active.is_none());
    let work = receiver.counters.decode_work;
    assert_eq!(
        receiver.poll(view(90_000_000), &AtomicBool::new(false)),
        Err(Refusal::Cancelled)
    );
    assert_eq!(receiver.counters.decode_work, work);
    assert!(matches!(
        receiver.feedback(view(90_000_000)),
        Err(Refusal::Cancelled)
    ));
    let mut next = config();
    assert_eq!(receiver.transition(next.clone()), Err(Refusal::Epoch));
    next.epoch += 1;
    next.stream = StreamId::new(0x60603).unwrap();
    next.presentation_origin_ns = 700_000_000;
    receiver.transition(next).unwrap();
    feed(&mut receiver, 0, 252, 220_000_000);
    assert_eq!(finish(&mut receiver, 280_000_000), DecodeState::Ready);
    assert_eq!(decide(&mut receiver, 0).0, playout::Outcome::Real);
}

#[test]
fn n06_replay_baseline_hybrid_and_decode_overload_use_independent_pcm_observations() {
    enum Event {
        Packet(Box<[u8; DATAGRAM]>),
        Poll,
        OtherWork,
        Stop,
        Decide(u64),
    }
    for mode in ["baseline", "hybrid", "overload"] {
        let cfg = config();
        let mut rig = Rig::new(cfg.clone()).unwrap();
        let mut events = Vec::new();
        let mut trace = Sha256::new();
        for window in 0..8_u64 {
            let src = source(window);
            let metadata = cfg.metadata(window).unwrap();
            let digest = content_digest(&metadata, &src);
            for esi in 0..N {
                let missing = window % 2 == 1 && window < 4 && esi < 2;
                let sent = if esi < K {
                    playout::frames_to_ns((window * 4 + esi as u64) * 256)
                } else {
                    playout::frames_to_ns((window + 1) * 1024)
                        + 1_000_000
                        + (esi - K) as u64 * 100_000
                };
                trace.update(window.to_be_bytes());
                trace.update((esi as u64).to_be_bytes());
                trace.update(sent.to_be_bytes());
                trace.update([u8::from(missing)]);
                if !missing && (esi < K || mode != "baseline") {
                    let wire = sign_symbol(
                        &cfg,
                        window,
                        esi,
                        if esi < K { 0 } else { 2 },
                        digest,
                        &encode_symbol(&src, esi).unwrap(),
                    )
                    .unwrap();
                    events.push((sent + 2_000_000, 1, Event::Packet(Box::new(wire))));
                }
            }
        }
        if mode != "baseline" {
            for tick in 0..4800 {
                events.push((tick * 50_000, 2, Event::Poll));
            }
        }
        if mode == "overload" {
            events.push((95_900_000, 0, Event::OtherWork));
        }
        events.push((240_000_000, 0, Event::Stop));
        for block in 0..32 {
            events.push((rig.cutoff(block, GUARD_NS), 0, Event::Decide(block)));
        }
        events.sort_by_key(|(at, order, _)| (*at, *order));
        let cancel = AtomicBool::new(false);
        let mut output = Vec::new();
        let mut injected = 0;
        let mut lost_feedback = 0;
        for (at, _, event) in events {
            match event {
                Event::Packet(wire) => {
                    let _ = rig.ingest(view(at), wire.as_slice()).unwrap();
                }
                Event::Poll => {
                    match rig.poll(view(at), &cancel) {
                        Ok(_) => {}
                        Err(Refusal::Deadline | Refusal::Protected { .. }) => {}
                        Err(error) => panic!("replay mode={mode} at={at} error={error:?}"),
                    }
                    if let Some(request) = rig.feedback(view(at)).unwrap() {
                        // One fixed, strategy-independent recorded fault: aggregate
                        // feedback for window1 is lost. No hypothetical success.
                        assert_eq!(read64(&request.0, 28), 1);
                        lost_feedback += 1;
                    }
                }
                Event::OtherWork => {
                    rig.update_interval(at);
                    let target = WINDOW_ALLOWANCE_NS / WORK_UNIT_NS - MAX_WORK + 1;
                    injected = target - rig.charged;
                    rig.charge(injected).unwrap();
                }
                Event::Stop => rig.stop(),
                Event::Decide(block) => {
                    let (outcome, bytes) = decide(&mut rig, block);
                    let sum = Sha256::digest(bytes);
                    let hash: String = sum.iter().map(|byte| format!("{byte:02x}")).collect();
                    output.push(serde_json::json!({"block":block,"outcome":outcome.code(),"pcm_sha256":hash,"cursor":rig.snapshot().cursor}));
                }
            }
        }
        assert_eq!(rig.snapshot().cursor, 32);
        assert!(rig.counters.decode_work > 0 || mode == "baseline");
        if mode == "overload" {
            assert!(rig.counters.work_refused > 0);
            assert!(rig.counters.recovered > 0);
            assert_eq!(lost_feedback, 1);
        }
        let trace: String = trace
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        println!(
            "N06-REPLAY {}",
            serde_json::json!({"schema":"n06.replay.v1","profile":PROFILE,"mode":mode,"source_epoch":1,"frames":256,"blocks":32,"seed":0x60601,"channel_trace_sha256":trace,"output":output,"status":rig.status(),"injected_other_work_units":injected,"lost_feedback":lost_feedback,"evidence_class":"offline-host-synthetic","production_fec_profile_admitted":false})
        );
    }
}

#[test]
fn n06_render_end_preserves_late_before_dac_and_still_live_positive_recovery() {
    let mut rig = Rig::new(config()).unwrap();
    feed(&mut rig, 0, 252, 20_000_000);
    let cancel = AtomicBool::new(false);
    let mut checkpoint = false;
    for i in 0..1000 {
        assert_eq!(
            rig.poll(view(80_000_000 + i * 30_000), &cancel),
            Ok(DecodeState::Pending)
        );
        if rig.solver.next_step_work() == 512 {
            checkpoint = true;
            break;
        }
    }
    assert!(
        checkpoint,
        "must park at the actual final digest checkpoint"
    );
    assert_eq!(rig.counters.recovered, 0);
    let cutoff = rig.cutoff(0, GUARD_NS);
    assert_eq!(
        rig.fec
            .poll(&mut rig.engine, view(cutoff - 1_000_000), &cancel),
        Ok(DecodeState::Ready)
    );
    assert_eq!(
        rig.counters.recovered, 0,
        "Ready is not permission to publish with a stale timestamp"
    );
    let (_, committed) = decide(&mut rig, 0);
    assert_eq!(committed, [0; BYTES]);
    let used = rig.solver.used();
    assert!(matches!(
        rig.poll(view(cutoff + 1), &cancel),
        Err(Refusal::Protected { .. })
    ));
    assert_eq!(rig.solver.used(), used);
    let after_render = cutoff + WORK_NS + LEAD_NS;
    assert!(after_render < rig.config.presentation_origin_ns);
    assert_eq!(
        rig.poll(view(after_render), &cancel),
        Ok(DecodeState::Ready)
    );
    assert_eq!(rig.counters.late, 1);
    assert_eq!(rig.counters.recovered, 1);
    assert_eq!(rig.snapshot().cursor, 1);
    assert_eq!(decide(&mut rig, 1).0, playout::Outcome::Real);
    assert_eq!(decide(&mut rig, 2).0, playout::Outcome::Real);
    println!(
        "N06-LATE {}",
        serde_json::json!({"schema":"n06.late.v1","profile":PROFILE,"completed_ns":after_render,"consume_by_ns":cutoff,"presentation_ns":rig.config.presentation_origin_ns,"late":rig.counters.late,"recovered":rig.counters.recovered,"cursor":rig.snapshot().cursor})
    );
}

#[test]
fn n06_authenticated_future_bounds_and_zero_budget_cancel_are_paired_with_positive_paths() {
    let cfg = config();
    let src = source(2);
    let digest = content_digest(&cfg.metadata(2).unwrap(), &src);
    let mut rig = Rig::new(cfg.clone()).unwrap();
    let future = sign_symbol(&cfg, 2, 2, 0, digest, &src[2]).unwrap();
    assert_eq!(rig.ingest(view(0), &future), Err(Refusal::Future));
    assert!(rig.windows.iter().all(|w| w.id.is_none()));
    let src = source(1);
    let next = sign_symbol(
        &cfg,
        1,
        2,
        0,
        content_digest(&cfg.metadata(1).unwrap(), &src),
        &src[2],
    )
    .unwrap();
    assert_eq!(rig.ingest(view(0), &next), Ok(Some(Admission::Admitted)));
    let mut decoder = IncrementalDecode::new();
    decoder.begin(252, [0; 32], &cfg.metadata(0).unwrap());
    let used = decoder.used();
    assert_eq!(
        decoder.poll(&[[0; BYTES]; N], 0, &AtomicBool::new(true)),
        DecodeState::Cancelled
    );
    assert_eq!(decoder.used(), used);
    assert!(decoder.output(0).is_none());
    let mut healthy = Rig::new(cfg).unwrap();
    feed(&mut healthy, 0, 252, 20_000_000);
    assert_eq!(finish(&mut healthy, 80_000_000), DecodeState::Ready);
}
