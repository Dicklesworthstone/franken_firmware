//! Unit and seeded property tests of the link manager, the ownership matrix and the peer directory. Every event is
//! synthetic: no interface, lease server or resolver is touched, and a pass here says nothing about a radio.

use super::*;

const SEC: u64 = 1_000_000_000;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("ip address")
}

fn sa(text: &str) -> SocketAddr {
    text.parse().expect("socket address")
}

fn manager() -> LinkManager {
    LinkManager::new(LinkConfig::baseline(PROFILES[0], 1)).expect("a valid configuration")
}

/// A manager brought to `Up` on `addr` at time 0: interface up, address bound, rebind succeeded.
fn up_on(addr: IpAddr, lease_ns: Option<u64>) -> LinkManager {
    let mut mgr = manager();
    mgr.on_event(0, LinkEvent::InterfaceUp);
    mgr.on_event(0, LinkEvent::AddressBound { ip: addr, lease_ns });
    mgr.on_event(0, LinkEvent::RebindResult { ip: addr, ok: true });
    assert_eq!(mgr.status().state, LinkState::Up);
    mgr
}

#[test]
fn n07_the_ownership_matrix_is_consistent_and_claims_nothing_e04_does_not_know() {
    assert_eq!(matrix_problems(), Vec::<String>::new());
    let all = ownership_matrix();
    let radio: Vec<_> = all.iter().filter(|d| d.e04_record.is_some()).collect();
    assert_eq!(radio.len(), 7, "the seven E04 radio duties");
    for duty in &radio {
        assert_eq!(duty.owner, Owner::Unestablished, "{}", duty.id);
        assert_eq!(
            duty.implementation,
            Implementation::NotStarted,
            "{}",
            duty.id
        );
        assert!(duty.wireless_only, "{}", duty.id);
        assert_eq!(duty.blockers, [E04_OWNERSHIP_BLOCKER, E04_QUAL_BLOCKER]);
    }
    // the duties the bead names are all present, none silently dropped
    for id in [
        "link.state_events",
        "link.association",
        "addr.acquisition",
        "addr.lease_renewal",
        "route.maintenance",
        "resolver.maintenance",
        "socket.rebind",
        "path.stale_cleanup",
        "identity.stable_across_ip_change",
        "reconnect.backoff",
    ] {
        assert!(all.iter().any(|d| d.id == id), "{id} must be in the matrix");
    }
    // the check is not blind: a table that claims more than E04 knows, or drops a blocker, is reported
    let mut claimed = all.to_vec();
    let roam = claimed
        .iter()
        .position(|d| d.id == "radio.roam")
        .expect("roam");
    claimed[roam].owner = Owner::Rust;
    claimed[roam].implementation = Implementation::Implemented;
    let problems = matrix_problems_of(&claimed);
    assert!(
        problems
            .iter()
            .any(|p| p.starts_with("radio.roam: claims more than E04 knows")),
        "{problems:?}"
    );
    let mut bare = all.to_vec();
    let assoc = bare
        .iter()
        .position(|d| d.id == "link.association")
        .expect("association");
    bare[assoc].blockers = &[];
    assert!(
        matrix_problems_of(&bare)
            .iter()
            .any(|p| p.starts_with("link.association: unestablished without a blocker"))
    );
    let mut loose = all.to_vec();
    let multicast = loose
        .iter()
        .position(|d| d.id == "radio.multicast_delivery")
        .expect("multicast");
    loose[multicast].blockers = &[E04_OWNERSHIP_BLOCKER];
    assert!(
        matrix_problems_of(&loose)
            .iter()
            .any(|p| p.starts_with("radio.multicast_delivery: E04 blockers not carried verbatim"))
    );
}

#[test]
fn n07_every_profile_stays_unqualified_and_wireless_is_tracked_as_required() {
    assert_eq!(PROFILES.len(), 3);
    for profile in PROFILES {
        assert!(profile.required, "{}", profile.id);
        assert!(profile.pending_receipt.starts_with('Q'), "{}", profile.id);
        assert!(profile.ipv4 && !profile.ipv6, "{}", profile.id);
        assert!(profile.default_path_mtu >= 1132, "{}", profile.id);
    }
    assert!(PROFILES.iter().any(|p| p.kind == LinkKind::WifiStation));
    assert!(PROFILES.iter().any(|p| p.kind == LinkKind::SonosNetMesh));
    assert!(PROFILES.iter().any(|p| p.kind == LinkKind::Wired));
}

#[test]
fn n07_an_interface_cycle_on_the_same_address_resumes_without_a_rebind() {
    let a = ip("10.0.0.5");
    let mut mgr = manager();
    assert_eq!(mgr.status().state, LinkState::Down);
    assert!(mgr.on_event(0, LinkEvent::InterfaceUp).is_empty());
    assert_eq!(mgr.status().state, LinkState::WaitingForAddress);
    assert_eq!(
        mgr.on_event(
            1,
            LinkEvent::AddressBound {
                ip: a,
                lease_ns: Some(3600 * SEC)
            }
        ),
        vec![LinkAction::Rebind { ip: a, attempt: 1 }]
    );
    assert_eq!(mgr.status().state, LinkState::Binding);
    assert_eq!(
        mgr.on_event(2, LinkEvent::RebindResult { ip: a, ok: true }),
        vec![LinkAction::Resume {
            ip: a,
            generation: 1
        }]
    );
    assert_eq!(
        mgr.on_event(3, LinkEvent::InterfaceDown),
        vec![LinkAction::Quiesce {
            reason: TransportReason::InterfaceDown
        }]
    );
    assert_eq!(mgr.status().state, LinkState::Down);
    // the same address is still bound: the interface returning resumes at once
    assert_eq!(
        mgr.on_event(4, LinkEvent::InterfaceUp),
        vec![LinkAction::Resume {
            ip: a,
            generation: 1
        }]
    );
    assert_eq!(mgr.counters().rebinds_requested, 1);
    assert_eq!(mgr.counters().resumes, 2);
}

#[test]
fn n07_an_address_change_rebinds_releases_the_stale_path_and_a_lost_address_forces_a_rebind() {
    let (a, b) = (ip("10.0.0.5"), ip("10.0.0.6"));
    let mut mgr = up_on(a, None);
    assert_eq!(
        mgr.on_event(
            10,
            LinkEvent::AddressBound {
                ip: b,
                lease_ns: None
            }
        ),
        vec![
            LinkAction::Quiesce {
                reason: TransportReason::AddressChanged
            },
            LinkAction::Rebind { ip: b, attempt: 1 },
        ]
    );
    assert_eq!(
        mgr.on_event(11, LinkEvent::RebindResult { ip: b, ok: true }),
        vec![
            LinkAction::ReleaseStale { old_ip: a },
            LinkAction::Resume {
                ip: b,
                generation: 2
            },
        ]
    );
    assert_eq!(mgr.counters().stale_releases, 1);

    // an address that disappears and comes back is not trusted to have kept its sockets: it rebinds
    assert_eq!(
        mgr.on_event(20, LinkEvent::AddressLost),
        vec![LinkAction::Quiesce {
            reason: TransportReason::AddressMissing
        }]
    );
    assert_eq!(mgr.status().state, LinkState::WaitingForAddress);
    assert_eq!(mgr.status().bound, None);
    assert_eq!(
        mgr.on_event(
            21,
            LinkEvent::AddressBound {
                ip: b,
                lease_ns: None
            }
        ),
        vec![LinkAction::Rebind { ip: b, attempt: 1 }]
    );
    // the same address again: nothing stale to release
    assert_eq!(
        mgr.on_event(22, LinkEvent::RebindResult { ip: b, ok: true }),
        vec![LinkAction::Resume {
            ip: b,
            generation: 4
        }]
    );
}

#[test]
fn n07_a_failed_rebind_backs_off_by_the_schedule_and_spends_a_bounded_budget() {
    let a = ip("10.0.0.5");
    let mut cfg = LinkConfig::baseline(PROFILES[0], 42);
    cfg.max_rebind_attempts = 3;
    let mut mgr = LinkManager::new(cfg).expect("valid");
    mgr.on_event(0, LinkEvent::InterfaceUp);
    assert_eq!(
        mgr.on_event(
            0,
            LinkEvent::AddressBound {
                ip: a,
                lease_ns: None
            }
        ),
        vec![LinkAction::Rebind { ip: a, attempt: 1 }]
    );

    assert!(
        mgr.on_event(100, LinkEvent::RebindResult { ip: a, ok: false })
            .is_empty()
    );
    let due1 = 100 + mgr.backoff_ns(1);
    assert_eq!(mgr.status().state, LinkState::Backoff);
    assert_eq!(mgr.status().next_attempt_ns, Some(due1));
    assert!(mgr.on_tick(due1 - 1).is_empty(), "one tick early is early");
    assert_eq!(
        mgr.on_tick(due1),
        vec![LinkAction::Rebind { ip: a, attempt: 2 }]
    );

    let failed2 = due1 + 10;
    assert!(
        mgr.on_event(failed2, LinkEvent::RebindResult { ip: a, ok: false })
            .is_empty()
    );
    let due2 = failed2 + mgr.backoff_ns(2);
    assert!(mgr.backoff_ns(2) >= mgr.backoff_ns(1));
    assert_eq!(mgr.status().next_attempt_ns, Some(due2));
    assert_eq!(
        mgr.on_tick(due2),
        vec![LinkAction::Rebind { ip: a, attempt: 3 }]
    );

    // the third failure spends the budget: reported once, then silence
    assert_eq!(
        mgr.on_event(due2 + 10, LinkEvent::RebindResult { ip: a, ok: false }),
        vec![LinkAction::GiveUp {
            reason: TransportReason::ReconnectBudgetSpent
        }]
    );
    assert_eq!(mgr.status().state, LinkState::Failed);
    assert_eq!(
        mgr.status().reason,
        Some(TransportReason::ReconnectBudgetSpent)
    );
    assert_eq!(mgr.counters().rebinds_failed, 3);
    assert_eq!(mgr.counters().give_ups, 1);
    assert!(mgr.on_tick(due2 + 1000 * SEC).is_empty());
    // the WAN coming back does not revive a failed local link
    assert!(
        mgr.on_event(
            due2 + 1001 * SEC,
            LinkEvent::WanReachability { reachable: true }
        )
        .is_empty()
    );
    assert_eq!(mgr.status().state, LinkState::Failed);

    // a new outage (the interface cycles) starts a fresh budget, and success resumes
    let later = due2 + 2000 * SEC;
    assert_eq!(
        mgr.on_event(later, LinkEvent::InterfaceDown),
        vec![LinkAction::Quiesce {
            reason: TransportReason::InterfaceDown
        }]
    );
    assert_eq!(
        mgr.on_event(later + 1, LinkEvent::InterfaceUp),
        vec![LinkAction::Rebind { ip: a, attempt: 1 }]
    );
    assert_eq!(
        mgr.on_event(later + 2, LinkEvent::RebindResult { ip: a, ok: true }),
        vec![LinkAction::Resume {
            ip: a,
            generation: 1
        }]
    );
}

#[test]
fn n07_the_backoff_never_decreases_never_exceeds_the_cap_and_replays_from_its_seed() {
    for seed in [0_u64, 1, 7, 0xDEAD_BEEF] {
        let mgr = LinkManager::new(LinkConfig::baseline(PROFILES[0], seed)).expect("valid");
        let again = LinkManager::new(LinkConfig::baseline(PROFILES[0], seed)).expect("valid");
        let cfg = mgr.config().clone();
        let mut previous = 0;
        for attempt in 1..=40_u32 {
            let wait = mgr.backoff_ns(attempt);
            assert!(wait >= previous, "seed {seed} attempt {attempt}");
            assert!(wait <= cfg.backoff_max_ns, "seed {seed} attempt {attempt}");
            assert_eq!(wait, again.backoff_ns(attempt), "replay from the seed");
            previous = wait;
        }
        assert!(mgr.backoff_ns(1) >= cfg.backoff_initial_ns);
        assert_eq!(mgr.backoff_ns(40), cfg.backoff_max_ns, "the cap is reached");
    }
}

#[test]
fn n07_an_address_of_an_undeclared_family_is_refused_and_never_disturbs_the_path_in_use() {
    let (a, v6) = (ip("10.0.0.5"), ip("fd00::5"));
    let mut mgr = up_on(a, None);
    let before = mgr.status();
    assert!(
        mgr.on_event(
            5,
            LinkEvent::AddressBound {
                ip: v6,
                lease_ns: None
            }
        )
        .is_empty()
    );
    assert_eq!(mgr.status(), before, "the working path is untouched");
    assert_eq!(mgr.counters().refused_addresses, 1);

    // with no address at all and only IPv6 on offer: a bounded wait, then the reason is named
    let mut only = manager();
    only.on_event(0, LinkEvent::InterfaceUp);
    assert!(
        only.on_event(
            1,
            LinkEvent::AddressBound {
                ip: v6,
                lease_ns: None
            }
        )
        .is_empty()
    );
    assert_eq!(
        only.status().reason,
        Some(TransportReason::UnsupportedAddressFamily)
    );
    let wait = only.config().address_wait_ns;
    assert!(only.on_tick(wait - 1).is_empty());
    assert_eq!(
        only.on_tick(wait),
        vec![LinkAction::GiveUp {
            reason: TransportReason::UnsupportedAddressFamily
        }]
    );

    // the permitted positive: a profile that declares IPv6 takes the same address
    let dual = LinkProfile {
        ipv6: true,
        ..PROFILES[0]
    };
    let mut mgr6 = LinkManager::new(LinkConfig::baseline(dual, 1)).expect("valid");
    mgr6.on_event(0, LinkEvent::InterfaceUp);
    assert_eq!(
        mgr6.on_event(
            1,
            LinkEvent::AddressBound {
                ip: v6,
                lease_ns: None
            }
        ),
        vec![LinkAction::Rebind { ip: v6, attempt: 1 }]
    );
}

#[test]
fn n07_wan_and_resolver_events_change_nothing_and_a_lapsed_lease_stops_sending() {
    let a = ip("10.0.0.5");
    let mut mgr = up_on(a, Some(10 * SEC));
    let mut down = manager();
    for target in [&mut mgr, &mut down] {
        for event in [
            LinkEvent::WanReachability { reachable: false },
            LinkEvent::WanReachability { reachable: true },
            LinkEvent::ResolverChanged {
                servers: 0,
                usable: false,
            },
        ] {
            let before = target.status();
            assert!(target.on_event(SEC, event).is_empty());
            assert_eq!(target.status(), before);
        }
        assert_eq!(target.counters().wan_events, 2);
        assert_eq!(target.counters().resolver_events, 1);
    }

    // the lease ends at 10 s and sending stops one guard (1 s) earlier, unless it was renewed
    assert!(mgr.on_tick(9 * SEC - 1).is_empty());
    mgr.on_event(5 * SEC, LinkEvent::LeaseRenewed { lease_ns: 10 * SEC });
    assert!(
        mgr.on_tick(9 * SEC).is_empty(),
        "the renewal moved the lapse to 14 s"
    );
    assert_eq!(
        mgr.on_tick(14 * SEC),
        vec![LinkAction::Quiesce {
            reason: TransportReason::LeaseLapsed
        }]
    );
    assert_eq!(mgr.status().state, LinkState::WaitingForAddress);
    assert_eq!(mgr.status().addr, None);
    assert_eq!(mgr.counters().lease_lapses, 1);
    // a fresh lease on the same address rebinds and resumes
    assert_eq!(
        mgr.on_event(
            15 * SEC,
            LinkEvent::AddressBound {
                ip: a,
                lease_ns: Some(60 * SEC)
            }
        ),
        vec![LinkAction::Rebind { ip: a, attempt: 1 }]
    );
    assert!(matches!(
        mgr.on_event(15 * SEC, LinkEvent::RebindResult { ip: a, ok: true })
            .as_slice(),
        [LinkAction::Resume { .. }]
    ));
}

#[test]
fn n07_the_wait_for_an_address_is_bounded_and_a_late_address_starts_over() {
    let a = ip("10.0.0.5");
    let mut mgr = manager();
    mgr.on_event(0, LinkEvent::InterfaceUp);
    let wait = mgr.config().address_wait_ns;
    assert!(mgr.on_tick(wait - 1).is_empty());
    assert_eq!(
        mgr.on_tick(wait),
        vec![LinkAction::GiveUp {
            reason: TransportReason::AddressMissing
        }]
    );
    assert_eq!(mgr.status().state, LinkState::Failed);
    assert!(mgr.on_tick(wait + 1).is_empty(), "reported once");
    assert_eq!(
        mgr.on_event(
            wait + 2,
            LinkEvent::AddressBound {
                ip: a,
                lease_ns: None
            }
        ),
        vec![LinkAction::Rebind { ip: a, attempt: 1 }]
    );
}

#[test]
fn n07_a_stale_rebind_result_is_ignored_and_the_current_one_applies() {
    let (a, b) = (ip("10.0.0.5"), ip("10.0.0.6"));
    let mut mgr = manager();
    mgr.on_event(0, LinkEvent::InterfaceUp);
    assert_eq!(
        mgr.on_event(
            1,
            LinkEvent::AddressBound {
                ip: a,
                lease_ns: None
            }
        ),
        vec![LinkAction::Rebind { ip: a, attempt: 1 }]
    );
    assert_eq!(
        mgr.on_event(
            2,
            LinkEvent::AddressBound {
                ip: b,
                lease_ns: None
            }
        ),
        vec![LinkAction::Rebind { ip: b, attempt: 1 }]
    );
    assert!(
        mgr.on_event(3, LinkEvent::RebindResult { ip: a, ok: true })
            .is_empty(),
        "the result for the address that moved on is stale"
    );
    assert_eq!(mgr.counters().ignored_events, 1);
    assert_eq!(mgr.status().state, LinkState::Binding);
    assert_eq!(
        mgr.on_event(4, LinkEvent::RebindResult { ip: b, ok: true }),
        vec![LinkAction::Resume {
            ip: b,
            generation: 2
        }]
    );
    // a result nobody awaits is ignored too
    assert!(
        mgr.on_event(5, LinkEvent::RebindResult { ip: b, ok: true })
            .is_empty()
    );
    assert_eq!(mgr.counters().ignored_events, 2);
}

/// A seeded generator for the invariant sweep: `SplitMix64`, so every sequence replays from its seed.
struct Draw(u64);

impl Draw {
    fn word(&mut self) -> u64 {
        self.0 = splitmix64(self.0);
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.word() % bound
    }
}

fn check(
    mgr: &LinkManager,
    actions: &[LinkAction],
    before: &LinkStatus,
    event: Option<&LinkEvent>,
    seed: u64,
    step: usize,
    now_ns: u64,
) {
    let now = mgr.status();
    let cfg = mgr.config();
    let at = format!("seed {seed} step {step}");
    if now.state == LinkState::Up {
        assert!(now.iface_up, "{at}: up needs the interface");
        assert!(
            now.addr.is_some() && now.bound == now.addr,
            "{at}: up needs sockets on the current address"
        );
    }
    if now.state == LinkState::Binding {
        assert!(now.iface_up && now.addr.is_some(), "{at}");
    }
    assert_eq!(now.state == LinkState::Down, !now.iface_up, "{at}");
    assert!(now.attempt <= cfg.max_rebind_attempts, "{at}");
    let lease_open =
        |end: Option<u64>| end.is_none_or(|end| now_ns < end.saturating_sub(cfg.lease_guard_ns));
    if now.state == LinkState::Up {
        assert!(
            lease_open(now.lease_end_ns),
            "{at}: up on an address whose lease has ended"
        );
    }
    for action in actions {
        match action {
            LinkAction::Rebind { ip, attempt } => {
                assert_eq!(Some(*ip), now.addr, "{at}");
                assert!(cfg.profile.declares(*ip), "{at}: undeclared family");
                assert!(*attempt >= 1 && *attempt <= cfg.max_rebind_attempts, "{at}");
            }
            LinkAction::Resume { ip, generation } => {
                assert!(
                    lease_open(now.lease_end_ns),
                    "{at}: resumed onto an ended lease"
                );
                assert_eq!(now.state, LinkState::Up, "{at}");
                assert_eq!(Some(*ip), now.addr, "{at}");
                assert_eq!(*generation, now.generation, "{at}");
            }
            LinkAction::GiveUp { .. } => assert_eq!(now.state, LinkState::Failed, "{at}"),
            LinkAction::Quiesce { .. } => assert_ne!(now.state, LinkState::Up, "{at}"),
            LinkAction::ReleaseStale { old_ip } => {
                assert_ne!(Some(*old_ip), now.addr, "{at}");
            }
        }
    }
    if matches!(
        event,
        Some(LinkEvent::WanReachability { .. } | LinkEvent::ResolverChanged { .. })
    ) {
        assert!(
            actions.is_empty(),
            "{at}: WAN and resolver events act on nothing"
        );
        assert_eq!(&now, before, "{at}: and change nothing");
    }
}

#[test]
fn n07_seeded_random_event_sequences_keep_every_invariant() {
    let pool = [
        ip("10.0.0.5"),
        ip("10.0.0.6"),
        ip("fd00::5"),
        ip("192.0.2.9"),
    ];
    let mut applied = 0_u64;
    for seed in 0..100_u64 {
        let mut draw = Draw(seed);
        let profile = PROFILES[(seed % 3) as usize];
        let mut mgr = LinkManager::new(LinkConfig::baseline(profile, seed)).expect("valid");
        let mut now = 0_u64;
        // rebind outcomes the "caller" has not delivered yet, some of them failures, some arriving late or stale
        let mut awaiting: Vec<LinkEvent> = Vec::new();
        for step in 0..400_usize {
            let before = mgr.status();
            let mut event: Option<LinkEvent> = None;
            if !awaiting.is_empty() && draw.below(2) == 0 {
                event = Some(awaiting.remove(0));
            } else {
                match draw.below(10) {
                    0 => event = Some(LinkEvent::InterfaceUp),
                    1 => event = Some(LinkEvent::InterfaceDown),
                    2 => {
                        let ip = pool[draw.below(pool.len() as u64) as usize];
                        let lease_ns = (draw.below(2) == 0).then(|| (2 + draw.below(29)) * SEC);
                        event = Some(LinkEvent::AddressBound { ip, lease_ns });
                    }
                    3 => event = Some(LinkEvent::AddressLost),
                    4 => {
                        event = Some(LinkEvent::LeaseRenewed {
                            lease_ns: (2 + draw.below(29)) * SEC,
                        });
                    }
                    5 => {
                        event = Some(LinkEvent::WanReachability {
                            reachable: draw.below(2) == 0,
                        });
                    }
                    6 => {
                        event = Some(LinkEvent::ResolverChanged {
                            servers: draw.below(4) as u8,
                            usable: draw.below(2) == 0,
                        });
                    }
                    _ => {}
                }
            }
            let actions = match event {
                Some(event) => mgr.on_event(now, event),
                None => {
                    now += draw.below(3 * SEC);
                    mgr.on_tick(now)
                }
            };
            for action in &actions {
                if let LinkAction::Rebind { ip, .. } = action {
                    awaiting.push(LinkEvent::RebindResult {
                        ip: *ip,
                        ok: draw.below(3) != 0,
                    });
                }
            }
            check(&mgr, &actions, &before, event.as_ref(), seed, step, now);
            applied += 1;
        }
    }
    assert_eq!(applied, 40_000);
}

#[test]
fn n07_a_speaker_keeps_its_identity_and_handle_when_its_address_moves() {
    let mut dir = PeerDirectory::new(2);
    assert!(dir.is_empty());
    let (m1, c1) = (sa("10.0.0.5:5000"), sa("10.0.0.5:5001"));
    let (m2, c2) = (sa("10.0.0.9:5000"), sa("10.0.0.9:5001"));
    assert_eq!(dir.announce(0xA1, 7, m1, c1, 1), Ok(Announced::New));
    assert_eq!(dir.announce(0xA1, 7, m1, c1, 2), Ok(Announced::Unchanged));
    assert_eq!(
        dir.lookup(0xA1).map(|(peer, path)| (peer, path.generation)),
        Some((7, 2))
    );
    // it moves: same identity, same handle, a new path, and the old one is handed back for cleanup
    match dir.announce(0xA1, 7, m2, c2, 3) {
        Ok(Announced::Moved { old }) => assert_eq!((old.media, old.control), (m1, c1)),
        other => panic!("expected a move, got {other:?}"),
    }
    // an older generation never overwrites a newer one
    assert_eq!(
        dir.announce(0xA1, 7, m1, c1, 2),
        Err(DirectoryError::Stale { got: 2, current: 3 })
    );
    assert_eq!(dir.lookup(0xA1).map(|(_, path)| path.media), Some(m2));
    // the handle is the speaker's for good
    assert_eq!(
        dir.announce(0xA1, 8, m2, c2, 4),
        Err(DirectoryError::PeerHandleChanged {
            speaker: 0xA1,
            held: 7,
            asked: 8
        })
    );
    // another speaker cannot take its address or its handle, and a refusal changes nothing
    let (m3, c3) = (sa("10.0.0.7:5000"), sa("10.0.0.7:5001"));
    assert_eq!(
        dir.announce(0xB2, 9, m2, c3, 1),
        Err(DirectoryError::AddressInUse { with: 0xA1 })
    );
    assert_eq!(
        dir.announce(0xB2, 7, m3, c3, 1),
        Err(DirectoryError::PeerHandleInUse {
            peer: 7,
            with: 0xA1
        })
    );
    assert_eq!(dir.len(), 1);
    // the permitted positive: its own address and handle
    assert_eq!(dir.announce(0xB2, 9, m3, c3, 1), Ok(Announced::New));
    // bounded, and leaving frees the room
    let (m4, c4) = (sa("10.0.0.8:5000"), sa("10.0.0.8:5001"));
    assert_eq!(
        dir.announce(0xC3, 10, m4, c4, 1),
        Err(DirectoryError::Full { max: 2 })
    );
    assert!(dir.remove(0xB2));
    assert!(!dir.remove(0xB2));
    assert_eq!(dir.announce(0xC3, 10, m4, c4, 1), Ok(Announced::New));
}

#[test]
fn n07_every_transport_reason_has_a_stable_code_and_never_names_the_wan() {
    let mut codes: Vec<&str> = TransportReason::ALL.iter().map(|r| r.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), TransportReason::ALL.len(), "codes are unique");
    for reason in TransportReason::ALL {
        assert!(reason.code().starts_with("N07_"));
        let text = reason.ux_text().to_ascii_lowercase();
        for word in ["wan", "internet", "cloud", "online", "dns"] {
            assert!(!text.contains(word), "{} mentions {word}", reason.code());
        }
    }
}

#[test]
fn n07_a_lease_that_ended_during_an_outage_is_never_resumed_and_a_short_outage_is() {
    let a = ip("10.0.0.5");
    // across the lease: up on a 10 s lease, the interface down at 5 s and back at 20 s
    let mut mgr = up_on(a, Some(10 * SEC));
    assert_eq!(
        mgr.on_event(5 * SEC, LinkEvent::InterfaceDown),
        vec![LinkAction::Quiesce {
            reason: TransportReason::InterfaceDown
        }]
    );
    assert!(
        mgr.on_event(20 * SEC, LinkEvent::InterfaceUp).is_empty(),
        "no resume onto an address whose lease ended while the interface was down"
    );
    let status = mgr.status();
    assert_eq!(
        (status.state, status.addr, status.bound, status.reason),
        (
            LinkState::WaitingForAddress,
            None,
            None,
            Some(TransportReason::LeaseLapsed)
        )
    );
    assert_eq!(
        (mgr.counters().lease_lapses, mgr.counters().resumes),
        (1, 1)
    );
    // the address returns with a fresh lease: it is rebound and then resumed
    assert_eq!(
        mgr.on_event(
            21 * SEC,
            LinkEvent::AddressBound {
                ip: a,
                lease_ns: Some(60 * SEC)
            }
        ),
        vec![LinkAction::Rebind { ip: a, attempt: 1 }]
    );
    assert!(matches!(
        mgr.on_event(21 * SEC, LinkEvent::RebindResult { ip: a, ok: true })
            .as_slice(),
        [LinkAction::Resume { .. }]
    ));

    // the permitted positive: a short outage on the same address, well inside its lease, resumes
    let mut short = up_on(a, Some(100 * SEC));
    short.on_event(5 * SEC, LinkEvent::InterfaceDown);
    assert_eq!(
        short.on_event(8 * SEC, LinkEvent::InterfaceUp),
        vec![LinkAction::Resume {
            ip: a,
            generation: 1
        }]
    );

    // a tick while down notices an ended lease too, without a quiesce (nothing was sending)
    let mut down = up_on(a, Some(10 * SEC));
    down.on_event(5 * SEC, LinkEvent::InterfaceDown);
    assert!(down.on_tick(20 * SEC).is_empty());
    assert_eq!(down.status().addr, None);
    assert_eq!(down.counters().lease_lapses, 1);
    assert!(down.on_event(21 * SEC, LinkEvent::InterfaceUp).is_empty());
    assert_eq!(down.status().state, LinkState::WaitingForAddress);
}

#[test]
fn n07_a_rebind_that_finishes_after_the_lease_ended_does_not_resume() {
    let a = ip("10.0.0.5");
    let mut mgr = manager();
    mgr.on_event(0, LinkEvent::InterfaceUp);
    assert_eq!(
        mgr.on_event(
            0,
            LinkEvent::AddressBound {
                ip: a,
                lease_ns: Some(10 * SEC)
            }
        ),
        vec![LinkAction::Rebind { ip: a, attempt: 1 }]
    );
    // the result arrives after the lease ended: the manager lapses it first, and the result is stale
    assert_eq!(
        mgr.on_event(20 * SEC, LinkEvent::RebindResult { ip: a, ok: true }),
        vec![LinkAction::Quiesce {
            reason: TransportReason::LeaseLapsed
        }]
    );
    assert_eq!(mgr.status().state, LinkState::WaitingForAddress);

    // a backoff that was running when the lease ended is cancelled, not retried onto the dead address
    let mut backing = manager();
    backing.on_event(0, LinkEvent::InterfaceUp);
    backing.on_event(
        0,
        LinkEvent::AddressBound {
            ip: a,
            lease_ns: Some(10 * SEC),
        },
    );
    backing.on_event(SEC, LinkEvent::RebindResult { ip: a, ok: false });
    assert_eq!(backing.status().state, LinkState::Backoff);
    assert_eq!(
        backing.on_tick(20 * SEC),
        vec![LinkAction::Quiesce {
            reason: TransportReason::LeaseLapsed
        }]
    );
    assert_eq!(backing.status().state, LinkState::WaitingForAddress);
}
