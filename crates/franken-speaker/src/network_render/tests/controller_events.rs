//! Private WIP: co-owner control/clock-failure cleanup integration.
#![cfg(unix)]
use crate::file_medium::{FailAt, FaultingMedium};
use franken_control::channel::owner::{FleetControlOwner, FreshFleetGroup, FreshGroupError};
use franken_control::channel::peer::{PeerId, PeerRole, compute_proof};
use franken_control::channel::pipeline::{ChannelConfig, Limits, RamMedium};
use franken_control::channel::request::{ControlCommand, ControlRequest, RequestBody};
use franken_control::channel::wire::encode_request;
use franken_control::contracts::secret_store::{
    Generation, SecretError, SecretHandle, SecretMeta, SecretStore, SecretValue,
};
use franken_control::fsonos::{Endpoint, EndpointConfig, LegacyBridge};
use franken_session::{AuthorityToken, UnifiedGroupSession};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::rc::Rc;

struct KeyEntry {
    generation: Generation,
    value: SecretValue,
}

/// A volatile secret store for the harness. `franken-control`'s own in-memory store is `cfg(test)` and cannot be reached from
/// another crate. Nothing is written anywhere; a value is wiped when it is dropped (`SecretValue`).
struct HarnessKeys {
    entries: BTreeMap<SecretHandle, KeyEntry>,
    capacity: usize,
}

impl HarnessKeys {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity: 8,
        }
    }
}

/// Shows how many entries exist and nothing about them.
impl fmt::Debug for HarnessKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HarnessKeys")
            .field("entries", &self.entries.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl SecretStore for HarnessKeys {
    fn insert(
        &mut self,
        handle: &SecretHandle,
        value: SecretValue,
    ) -> Result<Generation, SecretError> {
        if self.entries.contains_key(handle) {
            return Err(SecretError::AlreadyExists {
                handle: handle.clone(),
            });
        }
        if self.entries.len() >= self.capacity {
            return Err(SecretError::StoreFull { max: self.capacity });
        }
        self.entries.insert(
            handle.clone(),
            KeyEntry {
                generation: Generation::FIRST,
                value,
            },
        );
        Ok(Generation::FIRST)
    }

    fn replace(
        &mut self,
        handle: &SecretHandle,
        value: SecretValue,
        expected: Generation,
    ) -> Result<Generation, SecretError> {
        let entry = self
            .entries
            .get_mut(handle)
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })?;
        if entry.generation != expected {
            return Err(SecretError::StaleGeneration {
                handle: handle.clone(),
                expected: expected.get(),
                actual: entry.generation.get(),
            });
        }
        let next =
            entry
                .generation
                .successor()
                .ok_or_else(|| SecretError::GenerationExhausted {
                    handle: handle.clone(),
                })?;
        // The old value is dropped here, which wipes it.
        entry.value = value;
        entry.generation = next;
        Ok(next)
    }

    fn remove(&mut self, handle: &SecretHandle) -> Result<(), SecretError> {
        self.entries
            .remove(handle)
            .map(|_| ())
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })
    }

    fn generation(&self, handle: &SecretHandle) -> Result<Generation, SecretError> {
        self.entries
            .get(handle)
            .map(|entry| entry.generation)
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })
    }

    fn with_secret<R>(
        &self,
        handle: &SecretHandle,
        f: impl FnOnce(Generation, &[u8]) -> R,
    ) -> Result<R, SecretError> {
        let entry = self
            .entries
            .get(handle)
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })?;
        Ok(f(entry.generation, entry.value.expose()))
    }

    fn list(&self) -> Vec<SecretMeta> {
        self.entries
            .iter()
            .map(|(handle, entry)| SecretMeta {
                handle: handle.clone(),
                generation: entry.generation,
                byte_len: entry.value.byte_len(),
            })
            .collect()
    }
}

const TEST_EPOCH: u64 = 1;
const TEST_MEMBER: &str = "speaker";
const TEST_NOW_NS: u64 = 1_000_000_000;
const TEST_CONTROLLER: &str = "controller";
const TEST_PANEL: &str = "panel";
const TEST_BRIDGE: &str = "legacy-bridge";
type TestFleet = FleetControlOwner<HarnessKeys, FaultingMedium<RamMedium>>;
fn test_key(peer: &str) -> Vec<u8> {
    format!("fixture-key-{peer}-0123456789abcdef").into_bytes()
}
fn test_peer(peer: &str) -> PeerId {
    PeerId::parse(peer).unwrap()
}

/// All credentials are public test keys; storage is synthetic, but uses the real
/// durable FleetControlOwner and may fail the first post-arming program call.
fn test_fleet_unleased() -> (TestFleet, Endpoint, Rc<Cell<bool>>) {
    let armed = Rc::new(Cell::new(false));
    let medium = FaultingMedium::new(
        RamMedium::new(Limits::fleet_control_development().segment_bytes),
        Some(FailAt::Program(1)),
        Rc::clone(&armed),
    );
    let (mut fleet, _) =
        TestFleet::boot(HarnessKeys::new(), medium, ChannelConfig::provisional()).unwrap();
    for (name, role, epoch) in [
        (TEST_CONTROLLER, PeerRole::Controller, Some(TEST_EPOCH)),
        (TEST_BRIDGE, PeerRole::Controller, Some(TEST_EPOCH)),
        (TEST_PANEL, PeerRole::LocalUser, None),
    ] {
        fleet
            .admit(&test_peer(name), role, &test_key(name), epoch, 1)
            .unwrap();
    }
    fleet.reserve_legacy_peer(&test_peer(TEST_BRIDGE)).unwrap();
    let endpoint = Endpoint::new(
        EndpointConfig::provisional(TEST_MEMBER),
        LegacyBridge::new(test_peer(TEST_BRIDGE), test_key(TEST_BRIDGE)),
        1,
        1,
    )
    .unwrap();
    (fleet, endpoint, armed)
}
fn test_fleet(session: &UnifiedGroupSession) -> (TestFleet, Endpoint, Rc<Cell<bool>>) {
    let (mut fleet, endpoint, armed) = test_fleet_unleased();
    fleet
        .install_lease(
            session,
            AuthorityToken::issue(session, u64::MAX),
            TEST_NOW_NS,
        )
        .unwrap();
    (fleet, endpoint, armed)
}

/// Signed real N02 ingress, not a fabricated settlement.
fn test_wire(peer: &str, seq: u64, revision: Option<u64>, command: ControlCommand) -> Vec<u8> {
    let body = RequestBody::new(test_peer(peer), seq, TEST_EPOCH, revision, command).unwrap();
    let proof = compute_proof(&test_key(peer), &body.signing_bytes());
    encode_request(&ControlRequest::new(body, proof)).unwrap()
}

// Underlying fake accepts only retained buffers here; its reset ACK settles its
// actual retained views. The copying method is intentionally unavailable.
use super::*;
use crate::render::RenderState;
use crate::settled_render::{
    DrainProgress, IngressError, OwnerError, PendingMember, PlaybackStep, RenderApplication,
    SettledRender,
};
use franken_control::channel::endpoint::{FecHandled, Handled};
use franken_control::channel::pipeline::{Outcome, SubmitResult};
use franken_hal::abi::EVENT_LEN;
use franken_hal::backend::{
    AbiKind, DeviceBackend, DriverError, FakeCall, Provenance as HalProvenance, RawCapabilities,
};
use franken_hal::slots::KernelView;
use franken_session::{ChannelRole, MembershipConfig};

struct RetainedPurge {
    inner: FakeBackend,
    capable: bool,
    suppress_next_flush: Rc<Cell<bool>>,
    flush_requests: Rc<Cell<u32>>,
}
impl DeviceBackend for RetainedPurge {
    fn provenance(&self) -> HalProvenance {
        self.inner.provenance()
    }
    fn abi(&self) -> AbiKind {
        self.inner.abi()
    }
    fn capabilities(&mut self) -> Result<RawCapabilities, DriverError> {
        self.inner.capabilities()
    }
    fn set_mute(&mut self, muted: bool) -> Result<bool, DriverError> {
        self.inner.set_mute(muted)
    }
    fn start(&mut self) -> Result<(), DriverError> {
        self.inner.start()
    }
    fn write(&mut self, _: &[u8]) -> Result<usize, DriverError> {
        Err(DriverError::Errno(38))
    }
    fn submit_retained(
        &mut self,
        slot: u16,
        generation: u32,
        view: KernelView,
        len: usize,
    ) -> Result<usize, DriverError> {
        self.inner.submit_retained(slot, generation, view, len)
    }
    fn poll_event(&mut self, record: &mut [u8; EVENT_LEN]) -> Result<Option<usize>, DriverError> {
        self.inner.poll_event(record)
    }
    fn request_flush(&mut self) -> Result<(), DriverError> {
        self.flush_requests.set(self.flush_requests.get() + 1);
        if self.suppress_next_flush.replace(false) {
            // Script a later driver failure: request accepted, no ACK issued.
            Ok(())
        } else {
            self.inner.request_flush()
        }
    }
    fn stop_flush_supported(&self) -> bool {
        self.capable
    }
    fn reset(&mut self) -> Result<bool, DriverError> {
        self.inner.reset()
    }
    fn reset_ack_discards_playback(&self) -> bool {
        true
    }
    fn wait_tick(&mut self) {
        self.inner.wait_tick();
    }
}

/// A real NetworkRender with local UDP, admitted synthetic clock and retained
/// silence in the model HAL; its clock can be failed after a committed control.
type TestSettled =
    SettledRender<HarnessKeys, FaultingMedium<RamMedium>, HostUdp, TestKernel, RetainedPurge>;
struct ControllerRig {
    owner: TestSettled,
    clock_fail: Rc<Cell<bool>>,
    local_now: Rc<Cell<u64>>,
    suppress_flush: Rc<Cell<bool>>,
    flush_requests: Rc<Cell<u32>>,
    storage_fail: Rc<Cell<bool>>,
    token: AuthorityToken,
    probe: FakeProbe,
    socket: UdpSocket,
    address: SocketAddr,
    sender: StreamSender,
    start_group_ns: u64,
    start_local_ns: u64,
}
fn prepared_owner(capable: bool) -> ControllerRig {
    prepared_owner_with_completion(capable, 100)
}
type TestFresh = FreshFleetGroup<HarnessKeys, FaultingMedium<RamMedium>>;
type TestNetwork = NetworkRender<HostUdp, TestKernel, RetainedPurge>;
struct PreparedParts {
    network: TestNetwork,
    clock_fail: Rc<Cell<bool>>,
    local_now: Rc<Cell<u64>>,
    suppress_flush: Rc<Cell<bool>>,
    flush_requests: Rc<Cell<u32>>,
    probe: FakeProbe,
    socket: UdpSocket,
    address: SocketAddr,
    sender: StreamSender,
    start_group_ns: u64,
    start_local_ns: u64,
}
fn prepared_parts(capable: bool, completion_ticks: u64) -> PreparedParts {
    prepared_parts_for_feedback(capable, completion_ticks, 512, None)
}

// Alternate trusted fixture provisioning for real source/feedback integration.
// Existing controller cases retain their original 512-frame/localhost:9 setup.
fn prepared_parts_for_feedback(
    capable: bool,
    completion_ticks: u64,
    final_frame: u64,
    sender_control: Option<SocketAddr>,
) -> PreparedParts {
    let mut net = network();
    if let Some(address) = sender_control {
        net.endpoint.carrier_mut().set_sender_control(address);
    }
    let address = net.endpoint.carrier().media_addr().unwrap();
    let start_local_ns = net
        .clock
        .local_for_group(net.start_group_ns, net.now.get())
        .unwrap();
    let mut cfg = FakeConfig::retained();
    cfg.geometry = RawGeometry {
        ring_depth: 4,
        frames_per_block: 64,
        channels: 2,
        bytes_per_sample: 2,
    };
    cfg.completion_delay_ticks = completion_ticks;
    cfg.min_submission_lead_ticks = Some(6);
    cfg.flush_ack_delay_ticks = Some(3);
    let (backend, probe) = FakeBackend::new(cfg);
    probe.capture_submissions(8);
    let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2);
    let suppress_flush = Rc::new(Cell::new(false));
    let flush_requests = Rc::new(Cell::new(0));
    let backend = RetainedPurge {
        inner: backend,
        capable,
        suppress_next_flush: Rc::clone(&suppress_flush),
        flush_requests: Rc::clone(&flush_requests),
    };
    let mut hal = HalSession::open(profile(), backend, config).unwrap();
    hal.prepare().unwrap();
    assert!(hal.abort_mute().unwrap().mute_acknowledged);
    hal.reset_device().unwrap();
    assert!(hal.silent_prepared_after_reset());
    assert_eq!(
        hal.prime_silence().unwrap().accepted_bytes,
        RENDER_FRAMES * 4
    );
    assert_eq!(probe.kernel_touch_pending(), (1, 0));
    let mut config = RenderConfig::standard(RENDER_FRAMES);
    config.window_ticks = 8;
    let render = RenderLoop::new(
        hal,
        dsp(),
        DriftResampler::new(ResamplerConfig::default()).unwrap(),
        config,
    )
    .unwrap();
    let first = render.next_slot().unwrap();
    let mapping = TickMapping {
        anchor_tick: first.presentation_tick,
        anchor_group_ns: net.start_group_ns,
        ns_numerator: 1_000_000,
        tick_denominator: 3,
        uncertainty_ns: 0,
        presentation_tolerance_ns: 1,
    };
    let schedule = StartSchedule {
        epoch: 1,
        start_group_ns: net.start_group_ns,
    };
    let network_owner = NetworkRender::admit(
        net.endpoint,
        net.platform,
        net.clock,
        render,
        NetworkRenderAdmission {
            schedule,
            anchor_frame: 0,
            final_frame,
            mapping,
            capacity_frames: 1024,
            start: StartPreconditions {
                presentation_mapping_installed: true,
                safe_gain_installed: true,
            },
        },
    )
    .unwrap();
    PreparedParts {
        network: network_owner,
        clock_fail: net.fail,
        local_now: net.now,
        suppress_flush,
        flush_requests,
        probe,
        socket: net.socket,
        address,
        sender: net.sender,
        start_group_ns: net.start_group_ns,
        start_local_ns,
    }
}
fn pending_member() -> PendingMember {
    PendingMember {
        member_id: TEST_MEMBER.into(),
        profile_id: profile().profile_id,
        role: ChannelRole::Stereo,
        ceiling: 1.0,
    }
}
fn provision_bundle(
    control: TestFleet,
    token: AuthorityToken,
) -> Result<TestFresh, FreshGroupError> {
    control.provision_fresh_group(
        "grp",
        "coord",
        TEST_EPOCH,
        MembershipConfig::default(),
        token,
        CLOCK_ORIGIN + 50_000_000,
    )
}
fn prepared_owner_with_completion(capable: bool, completion_ticks: u64) -> ControllerRig {
    let parts = prepared_parts(capable, completion_ticks);
    let session = UnifiedGroupSession::new("grp", "coord", TEST_EPOCH);
    let token = AuthorityToken::issue(&session, u64::MAX);
    let (control, soap, storage_fail) = test_fleet_unleased();
    let bundle = provision_bundle(control, token.clone()).unwrap();
    let owner =
        SettledRender::admit_fresh_group(bundle, soap, parts.network, pending_member(), 7).unwrap();
    ControllerRig {
        owner,
        clock_fail: parts.clock_fail,
        local_now: parts.local_now,
        suppress_flush: parts.suppress_flush,
        flush_requests: parts.flush_requests,
        storage_fail,
        token,
        probe: parts.probe,
        socket: parts.socket,
        address: parts.address,
        sender: parts.sender,
        start_group_ns: parts.start_group_ns,
        start_local_ns: parts.start_local_ns,
    }
}

#[test]
fn committed_control_then_prestart_clock_fault_drains_without_clock_or_source() {
    for ack in [true, false] {
        let ControllerRig {
            mut owner,
            clock_fail,
            suppress_flush,
            probe,
            ..
        } = prepared_owner(true);
        suppress_flush.set(!ack);
        let result = owner
            .receive(&test_wire(
                TEST_CONTROLLER,
                1,
                Some(0),
                ControlCommand::SetGroupVolume { volume: 70 },
            ))
            .unwrap();
        assert!(matches!(
            result,
            FecHandled::Control(Handled::Request {
                result: SubmitResult::Queued { .. },
                ..
            })
        ));
        let applied = owner.step_control().unwrap();
        let settlements = applied.control.unwrap();
        assert_eq!(settlements.len(), 1);
        assert!(matches!(
            settlements[0].outcome,
            Outcome::Committed { revision: 1 }
        ));
        assert!(matches!(applied.render, Ok(RenderApplication::WaitingJoin)));
        let prime = probe.captured_submissions();
        assert_eq!(prime, vec![vec![0; RENDER_FRAMES * 4]]);
        let held = probe.pending_slots();
        assert_eq!(held.len(), 1);
        clock_fail.set(true);
        assert!(matches!(
            owner.poll_media(),
            Err(OwnerError::Render(NetworkRenderError::Clock))
        ));
        assert_eq!(owner.render_state(), RenderState::Draining);
        assert_eq!(probe.pending_slots(), held);
        let mut timing = ScriptedTiming::default();
        let mut report = None;
        for _ in 0..20 {
            match owner.drain_tick(&mut timing).unwrap() {
                DrainProgress::Tick { report, .. } => assert_eq!(report.started, None),
                DrainProgress::Finished(done) => {
                    report = Some(done);
                    break;
                }
                DrainProgress::NotStartedUnacknowledged => {
                    panic!("clock failure must expose drain")
                }
            }
        }
        let stop = report.expect("bounded drain completes even with clock still failed");
        assert_eq!(stop.acknowledged, ack);
        assert_eq!(
            owner.render_state(),
            if ack {
                RenderState::Stopped
            } else {
                RenderState::Faulted
            }
        );
        if ack {
            assert_eq!(probe.pending(), 0);
        } else {
            assert_eq!(probe.pending_slots(), held);
            assert_eq!(probe.kernel_touch_pending(), (1, 0));
        }
        assert_eq!(probe.captured_submissions(), prime);
        assert!(!probe.calls().contains(&FakeCall::Start));
        assert!(!probe.calls().contains(&FakeCall::SetMute(false)));
        assert_eq!(probe.use_after_free(), 0);
        assert_eq!(probe.modified_while_owned(), 0);
        assert!(matches!(
            owner.render_step(&mut timing),
            Ok(PlaybackStep::Stopping)
        ));
    }
    // A separately admitted owner with a healthy clock can receive again. Its
    // join is still pending, so this is not a claim of audible recovery.
    let mut fresh = prepared_owner(true);
    assert!(fresh.owner.poll_media().is_ok());
    let mut timing = ScriptedTiming::default();
    assert!(matches!(
        fresh.owner.render_step(&mut timing),
        Ok(PlaybackStep::WaitingJoin)
    ));
    assert!(fresh.owner.request_stop().is_ok());
    assert!(finish_drain(&mut fresh.owner).acknowledged);
}

fn begin_local_join(rig: &mut ControllerRig) -> u64 {
    let cutover = ((CLOCK_ORIGIN + 2_000_000_000) * 48_000) / 1_000_000_000;
    rig.owner
        .propose_join(
            rig.token.clone(),
            profile(),
            cutover,
            CLOCK_ORIGIN + 1_000_000_000,
        )
        .unwrap()
}

fn stop_wire(peer: &str, seq: u64) -> Vec<u8> {
    test_wire(
        peer,
        seq,
        None,
        ControlCommand::StopGroupPlayback {
            now_ns: TEST_NOW_NS,
            irrevocable_dma_tail_ns: 0,
        },
    )
}

fn finish_drain(owner: &mut TestSettled) -> crate::render::StopReport {
    let mut timing = ScriptedTiming::default();
    for _ in 0..20 {
        match owner.drain_tick(&mut timing).unwrap() {
            DrainProgress::Tick { report, .. } => assert_eq!(report.started, None),
            DrainProgress::Finished(report) => return report,
            DrainProgress::NotStartedUnacknowledged => panic!("missing started drain"),
        }
    }
    panic!("bounded drain never finished");
}

#[test]
fn committed_empty_group_stop_cancels_pending_join_and_duplicate_does_not_repeat() {
    use franken_session::ProposalStatus;
    let mut rig = prepared_owner(true);
    let join = begin_local_join(&mut rig);
    rig.owner.ack_local(join).unwrap();
    assert!(matches!(
        rig.owner.commit_join(join),
        Ok(ProposalStatus::Committed { .. })
    ));
    let stop = stop_wire(TEST_CONTROLLER, 1);
    assert!(matches!(
        rig.owner.receive(&stop).unwrap(),
        FecHandled::Control(Handled::Request {
            result: SubmitResult::Queued { .. },
            ..
        })
    ));
    let result = rig.owner.step_control().unwrap();
    let settled = result.control.unwrap();
    assert_eq!(settled.len(), 1);
    assert!(matches!(
        settled[0].outcome,
        Outcome::Committed { revision: 1 }
    ));
    assert!(matches!(result.render, Ok(RenderApplication::Stopping)));
    assert_eq!(rig.owner.render_state(), RenderState::Draining);
    let calls = rig.probe.calls();
    let held = rig.probe.pending_slots();
    assert_eq!(held.len(), 1);
    assert!(matches!(
        rig.owner.receive(&stop).unwrap(),
        FecHandled::Control(Handled::Request {
            result: SubmitResult::Settled(Outcome::Committed { revision: 1 }),
            ..
        })
    ));
    assert!(matches!(
        rig.owner.step_control().unwrap().render,
        Ok(RenderApplication::Stopping)
    ));
    assert_eq!(
        rig.probe.calls(),
        calls,
        "duplicate stop must not repeat HAL effects"
    );
    assert_eq!(rig.probe.pending_slots(), held);
    let fresh = test_wire(
        TEST_CONTROLLER,
        2,
        Some(1),
        ControlCommand::SetGroupVolume { volume: 80 },
    );
    assert!(matches!(
        rig.owner.receive(&fresh).unwrap(),
        FecHandled::Control(Handled::Request {
            result: SubmitResult::Queued { .. },
            ..
        })
    ));
    let result = rig.owner.step_control().unwrap();
    let settled = result.control.unwrap();
    assert_eq!(settled.len(), 1);
    assert!(matches!(
        settled[0].outcome,
        Outcome::Committed { revision: 2 }
    ));
    assert!(matches!(result.render, Ok(RenderApplication::Stopping)));
    assert_eq!(
        rig.probe.calls(),
        calls,
        "post-stop control cannot reopen PCM"
    );
    assert_eq!(rig.probe.pending_slots(), held);
    assert!(matches!(
        rig.owner.tick_membership(join),
        Err(OwnerError::JoinState)
    ));
    assert!(matches!(
        rig.owner.propose_join(
            rig.token.clone(),
            profile(),
            5_000_000,
            CLOCK_ORIGIN + 1_000_000_000
        ),
        Err(OwnerError::JoinState)
    ));
    rig.clock_fail.set(true);
    assert!(matches!(
        rig.owner.receive(&stop),
        Err(IngressError::Owner(OwnerError::Render(
            NetworkRenderError::Clock
        )))
    ));
    assert_eq!(
        rig.probe.calls(),
        calls,
        "failed clock cannot fabricate a duplicate result or render effect"
    );
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert!(!rig.probe.calls().contains(&FakeCall::Start));
    assert!(!rig.probe.calls().contains(&FakeCall::SetMute(false)));
    assert_eq!(
        rig.probe.captured_submissions(),
        vec![vec![0; RENDER_FRAMES * 4]]
    );
}

#[test]
fn failed_store_withholds_remote_stop_but_reapplies_local_stop() {
    use franken_control::fsonos::Service;
    // Root 30961 corrects the former WaitingJoin/Ready expectation: a failed
    // durable write revokes fresh-owner health and requires actual cancellation.
    for local in [false, true] {
        for ack in [true, false] {
            let mut rig = prepared_owner(true);
            let sid = subscribe_events(&mut rig, Service::AvTransport);
            let wire = packet(
                &mut rig.sender,
                0,
                rig.start_group_ns,
                BLOCK_FRAMES as usize,
            );
            rig.socket.send_to(&wire, rig.address).unwrap();
            let poll = rig.owner.poll_media().unwrap();
            assert_eq!((poll.media_read, poll.media_accepted), (1, 1));
            let pulled_before = rig.owner.received_frames_pulled();
            assert_eq!(pulled_before, 0, "accepted media is not yet consumed");
            let held = rig.probe.pending_slots();
            assert_eq!(held.len(), 1);
            let prime = rig.probe.captured_submissions();
            assert_eq!(prime, vec![vec![0; RENDER_FRAMES * 4]]);
            rig.storage_fail.set(true);
            rig.suppress_flush.set(!ack);
            let peer = if local { TEST_PANEL } else { TEST_CONTROLLER };
            let stop = stop_wire(peer, 1);
            assert!(matches!(
                rig.owner.receive(&stop).unwrap(),
                FecHandled::Control(Handled::Request {
                    result: SubmitResult::Queued { .. },
                    ..
                })
            ));
            let calls_before = rig.probe.calls().len();
            let flushes_before = rig.flush_requests.get();
            let result = rig.owner.step_control().unwrap();
            let failed = result
                .control
                .expect_err("armed program failure must be reported");
            if local {
                assert!(failed.withheld.is_empty());
                assert_eq!(failed.applied.len(), 1);
                assert!(matches!(
                    failed.applied[0].outcome,
                    Outcome::Committed { .. }
                ));
            } else {
                assert!(failed.applied.is_empty());
                assert_eq!(failed.withheld.len(), 1);
                assert!(matches!(
                    failed.withheld[0].outcome,
                    Outcome::Committed { .. }
                ));
            }
            assert!(matches!(result.render, Ok(RenderApplication::Stopping)));
            assert_eq!(rig.owner.render_state(), RenderState::Draining);
            assert_eq!(rig.owner.received_frames_pulled(), pulled_before);
            assert!(
                result.notifications.is_empty(),
                "initial transport is already TRANSITIONING"
            );
            assert!(rig.probe.calls()[calls_before..].contains(&FakeCall::SetMute(true)));
            assert_eq!(rig.flush_requests.get(), flushes_before + 1);
            assert_eq!(rig.probe.pending_slots(), held);
            assert_eq!(rig.probe.kernel_touch_pending(), (1, 0));
            assert_eq!(rig.probe.captured_submissions(), prime);
            let mut timing = ScriptedTiming::default();
            assert!(matches!(
                rig.owner.render_step(&mut timing),
                Ok(PlaybackStep::Stopping)
            ));
            let mut waiting = false;
            let mut terminal = None;
            for _ in 0..20 {
                match rig.owner.drain_tick(&mut timing).unwrap() {
                    DrainProgress::Tick { report, state } => {
                        assert_eq!(report.started, None);
                        if state == RenderState::Draining {
                            waiting = true;
                            assert_eq!(rig.probe.pending_slots(), held);
                            assert_eq!(rig.probe.kernel_touch_pending(), (1, 0));
                            assert!(rig.owner.publish_transport().unwrap().is_empty());
                        }
                    }
                    DrainProgress::Finished(report) => {
                        terminal = Some(report);
                        break;
                    }
                    DrainProgress::NotStartedUnacknowledged => panic!("missing drain"),
                }
            }
            assert!(
                waiting,
                "a delayed or missing ACK must expose retained custody"
            );
            let report = terminal.expect("bounded drain terminal report");
            assert_eq!(report.acknowledged, ack);
            if ack {
                assert_eq!(rig.owner.render_state(), RenderState::Stopped);
                assert_eq!(rig.probe.pending(), 0);
                let events = rig.owner.publish_transport().unwrap();
                assert_eq!(events.len(), 1);
                event_is(&events[0], &sid, 1, "STOPPED");
            } else {
                assert_eq!(rig.owner.render_state(), RenderState::Faulted);
                assert_eq!(rig.probe.pending_slots(), held);
                assert_eq!(rig.probe.kernel_touch_pending(), (1, 0));
                assert!(rig.owner.publish_transport().unwrap().is_empty());
            }
            assert_eq!(rig.probe.captured_submissions(), prime);
            assert_eq!(
                rig.owner.received_frames_pulled(),
                pulled_before,
                "fail-stop and its ACK/no-ACK drain must not pull accepted media"
            );
            assert!(!rig.probe.calls().contains(&FakeCall::Start));
            assert!(!rig.probe.calls().contains(&FakeCall::SetMute(false)));
            assert_eq!(rig.probe.use_after_free(), 0);
            assert_eq!(rig.probe.modified_while_owned(), 0);
        }
    }
}

#[test]
fn readiness_requires_declared_stop_capability_and_later_noack_retains_custody() {
    let mut unknown = prepared_owner(false);
    let pending = begin_local_join(&mut unknown);
    assert!(matches!(
        unknown.owner.ack_local(pending),
        Err(OwnerError::LocalReadinessUnproven)
    ));
    assert_eq!(unknown.owner.render_state(), RenderState::Ready);
    assert_eq!(unknown.probe.kernel_touch_pending(), (1, 0));
    unknown.owner.request_stop().unwrap();
    assert!(
        finish_drain(&mut unknown.owner).acknowledged,
        "normal model supports flush even when capability not declared"
    );

    let mut capable = prepared_owner(true);
    let pending = begin_local_join(&mut capable);
    capable.owner.ack_local(pending).unwrap();
    let held = capable.probe.pending_slots();
    assert_eq!(held.len(), 1);
    capable.suppress_flush.set(true);
    capable.owner.request_stop().unwrap();
    let stop = finish_drain(&mut capable.owner);
    assert!(!stop.acknowledged, "declaration is not an ACK");
    assert_eq!(capable.owner.render_state(), RenderState::Faulted);
    assert_eq!(capable.probe.pending_slots(), held);
    assert_eq!(capable.probe.kernel_touch_pending(), (1, 0));
    assert_eq!(capable.probe.use_after_free(), 0);
    assert_eq!(capable.probe.modified_while_owned(), 0);
    assert!(!capable.probe.calls().contains(&FakeCall::Start));
    assert!(!capable.probe.calls().contains(&FakeCall::SetMute(false)));
}

#[test]
fn signed_local_stop_still_silences_after_session_sequence_is_exhausted() {
    use franken_session::{FencedControlCommand, GroupCommandPayload};
    let mut session = UnifiedGroupSession::new("grp", "coord", TEST_EPOCH);
    session.state_revision = u64::MAX;
    // A prior real reducer effect consumed the terminal session sequence, but
    // it was not a stop. The next signed local Stop must still actually apply.
    session
        .apply_command(FencedControlCommand {
            epoch: TEST_EPOCH,
            command_seq: u64::MAX,
            payload: GroupCommandPayload::SetGroupVolume {
                volume_0_to_100: 70,
            },
        })
        .unwrap();
    assert!(session.last_group_stop().is_none());
    let (mut control, _soap, _armed) = test_fleet(&session);
    let wire = stop_wire(TEST_PANEL, 1);
    assert!(matches!(
        control.receive(TEST_NOW_NS, &session, &wire).unwrap(),
        FecHandled::Control(Handled::Request {
            result: SubmitResult::Queued { .. },
            ..
        })
    ));
    let settled = control.step(TEST_NOW_NS, &mut session).unwrap();
    assert_eq!(settled.len(), 1);
    assert!(
        matches!(
            settled[0].outcome,
            Outcome::Committed { revision: u64::MAX }
        ),
        "a fresh local stop must actually silence after the session sequence is exhausted"
    );
    assert!(session.last_group_stop().is_some());
    let marker = session.last_group_stop();
    assert!(matches!(
        control.receive(TEST_NOW_NS, &session, &wire).unwrap(),
        FecHandled::Control(Handled::Request {
            result: SubmitResult::Settled(Outcome::Committed { revision: u64::MAX }),
            ..
        })
    ));
    assert_eq!(session.last_group_stop(), marker);
}

/// Subscribe through the real owned G03 endpoint; these are produced events,
/// not notification delivery or a physical speaker observation.
fn subscribe_events(rig: &mut ControllerRig, service: franken_control::fsonos::Service) -> String {
    subscribe_events_at_revision(rig, service, 0)
}
fn subscribe_events_at_revision(
    rig: &mut ControllerRig,
    service: franken_control::fsonos::Service,
    revision: u64,
) -> String {
    use franken_control::fsonos::{HttpRequest, Ingress};
    let headers = [
        ("CALLBACK", "<http://127.0.0.1:3400/notify>"),
        ("NT", "upnp:event"),
        ("TIMEOUT", "Second-300"),
    ];
    let request = HttpRequest {
        method: "SUBSCRIBE",
        path: service.event_path(),
        peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        ingress: Ingress::LocalLegacy,
        headers: &headers,
        body: b"",
    };
    let result = rig.owner.handle_soap(&request).unwrap();
    assert_eq!(result.control.response.status, 200);
    assert!(
        result.notifications.is_empty(),
        "SOAP initial event remains on Handled"
    );
    assert_eq!(result.control.notifications.len(), 1);
    let first = &result.control.notifications[0];
    assert_eq!(first.service, service);
    assert_eq!(first.seq, 0);
    assert_eq!(first.callback, "http://127.0.0.1:3400/notify");
    assert!(first.body.contains(&format!(
        "<FrankenStateRevision>{revision}</FrankenStateRevision>"
    )));
    if service == franken_control::fsonos::Service::AvTransport {
        assert!(first.body.contains("TRANSITIONING"));
    }
    first.sid.clone()
}

fn wrong_key_wire(seq: u64, revision: u64, volume: u8) -> Vec<u8> {
    let body = RequestBody::new(
        test_peer(TEST_CONTROLLER),
        seq,
        TEST_EPOCH,
        Some(revision),
        ControlCommand::SetGroupVolume { volume },
    )
    .unwrap();
    let proof = compute_proof(&test_key("wrong-controller"), &body.signing_bytes());
    encode_request(&ControlRequest::new(body, proof)).unwrap()
}

#[test]
fn gena_signed_group_updates_only_actual_committed_state() {
    use franken_control::channel::pipeline::Rejection;
    use franken_control::fsonos::Service;
    let mut rig = prepared_owner(true);
    let sid = subscribe_events(&mut rig, Service::GroupRenderingControl);
    let first = test_wire(
        TEST_CONTROLLER,
        1,
        Some(0),
        ControlCommand::SetGroupVolume { volume: 70 },
    );
    assert!(matches!(
        rig.owner.receive(&first).unwrap(),
        FecHandled::Control(Handled::Request {
            result: SubmitResult::Queued { .. },
            ..
        })
    ));
    let applied = rig.owner.step_control().unwrap();
    assert!(matches!(
        applied.control.unwrap()[0].outcome,
        Outcome::Committed { revision: 1 }
    ));
    assert!(matches!(applied.render, Ok(RenderApplication::WaitingJoin)));
    assert_eq!(applied.notifications.len(), 1);
    let event = &applied.notifications[0];
    assert_eq!(
        (&event.sid, event.service, event.seq),
        (&sid, Service::GroupRenderingControl, 1)
    );
    assert!(event.body.contains("<GroupVolume>70</GroupVolume>"));
    assert!(
        event
            .body
            .contains("<FrankenStateRevision>1</FrankenStateRevision>")
    );
    assert!(event.body.contains("<FrankenEpoch>1</FrankenEpoch>"));

    assert!(matches!(
        rig.owner.receive(&first).unwrap(),
        FecHandled::Control(Handled::Request {
            result: SubmitResult::Settled(Outcome::Committed { revision: 1 }),
            ..
        })
    ));
    assert!(rig.owner.step_control().unwrap().notifications.is_empty());
    assert!(matches!(
        rig.owner.receive(&wrong_key_wire(2, 1, 80)).unwrap(),
        FecHandled::Control(Handled::Request {
            result: SubmitResult::Rejected(Rejection::Unauthenticated(_)),
            ..
        })
    ));
    assert!(rig.owner.step_control().unwrap().notifications.is_empty());
    let second = test_wire(
        TEST_CONTROLLER,
        2,
        Some(1),
        ControlCommand::SetGroupVolume { volume: 80 },
    );
    assert!(matches!(
        rig.owner.receive(&second).unwrap(),
        FecHandled::Control(Handled::Request {
            result: SubmitResult::Queued { .. },
            ..
        })
    ));
    let applied = rig.owner.step_control().unwrap();
    assert!(matches!(
        applied.control.unwrap()[0].outcome,
        Outcome::Committed { revision: 2 }
    ));
    assert_eq!(applied.notifications.len(), 1);
    let event = &applied.notifications[0];
    assert_eq!(
        (&event.sid, event.service, event.seq),
        (&sid, Service::GroupRenderingControl, 2)
    );
    assert!(event.body.contains("<GroupVolume>80</GroupVolume>"));
    assert!(
        event
            .body
            .contains("<FrankenStateRevision>2</FrankenStateRevision>")
    );

    rig.storage_fail.set(true);
    let withheld = test_wire(
        TEST_CONTROLLER,
        3,
        Some(2),
        ControlCommand::SetGroupVolume { volume: 90 },
    );
    assert!(matches!(
        rig.owner.receive(&withheld).unwrap(),
        FecHandled::Control(Handled::Request {
            result: SubmitResult::Queued { .. },
            ..
        })
    ));
    let failed = rig.owner.step_control().unwrap();
    let store = failed.control.expect_err("armed write must fail");
    assert!(store.applied.is_empty());
    assert_eq!(store.withheld.len(), 1);
    assert!(matches!(
        store.withheld[0].outcome,
        Outcome::Committed { revision: 3 }
    ));
    assert!(
        failed.notifications.is_empty(),
        "withheld state must not produce an event"
    );
    assert!(!rig.probe.calls().contains(&FakeCall::Start));
    assert!(!rig.probe.calls().contains(&FakeCall::SetMute(false)));
}

#[test]
fn gena_membership_activation_and_failed_store_local_silence_are_truthful() {
    use franken_control::fsonos::Service;
    use franken_session::ProposalStatus;
    let mut rig = prepared_owner(true);
    let topology_sid = subscribe_events(&mut rig, Service::ZoneGroupTopology);
    let rendering_sid = subscribe_events(&mut rig, Service::RenderingControl);
    let cutover = ((CLOCK_ORIGIN + 500_000_000) * 48_000) / 1_000_000_000;
    let join = rig
        .owner
        .propose_join(
            rig.token.clone(),
            profile(),
            cutover,
            CLOCK_ORIGIN + 300_000_000,
        )
        .unwrap();
    rig.owner.ack_local(join).unwrap();
    assert!(matches!(
        rig.owner.commit_join(join),
        Ok(ProposalStatus::Committed { .. })
    ));
    let before_cutover = rig.owner.tick_membership(join).unwrap();
    assert!(before_cutover.settled.is_empty());
    assert!(before_cutover.notifications.is_empty());
    rig.local_now.set(600_000_000);
    let result = rig.owner.tick_membership(join).unwrap();
    assert!(result.settled.iter().any(|(id, status)| *id == join
        && matches!(status, ProposalStatus::Activated { revision: 1, .. })));
    assert_eq!(result.notifications.len(), 2);
    let topology = result
        .notifications
        .iter()
        .find(|n| n.sid == topology_sid)
        .expect("topology notification");
    assert_eq!(
        (topology.service, topology.seq),
        (Service::ZoneGroupTopology, 1)
    );
    assert!(topology.body.contains(TEST_MEMBER));
    assert!(
        topology
            .body
            .contains("<FrankenStateRevision>1</FrankenStateRevision>")
    );
    let rendering = result
        .notifications
        .iter()
        .find(|n| n.sid == rendering_sid)
        .expect("member state notification");
    assert_eq!(
        (rendering.service, rendering.seq),
        (Service::RenderingControl, 1)
    );
    assert!(
        rendering
            .body
            .contains("<FrankenStateRevision>1</FrankenStateRevision>")
    );

    rig.storage_fail.set(true);
    let mute = test_wire(
        TEST_PANEL,
        1,
        None,
        ControlCommand::SetMemberMute {
            member_id: TEST_MEMBER.into(),
            muted: true,
        },
    );
    assert!(matches!(
        rig.owner.receive(&mute).unwrap(),
        FecHandled::Control(Handled::Request {
            result: SubmitResult::Queued { .. },
            ..
        })
    ));
    let result = rig.owner.step_control().unwrap();
    let failed = result.control.expect_err("armed write must fail");
    assert!(failed.withheld.is_empty());
    assert_eq!(failed.applied.len(), 1);
    assert!(matches!(
        failed.applied[0].outcome,
        Outcome::Committed { revision: 2 }
    ));
    assert_eq!(result.notifications.len(), 1);
    let event = &result.notifications[0];
    assert_eq!(
        (&event.sid, event.service, event.seq),
        (&rendering_sid, Service::RenderingControl, 2)
    );
    assert!(event.body.contains("Mute channel=\"Master\" val=\"1\""));
    assert!(
        event
            .body
            .contains("<FrankenStateRevision>2</FrankenStateRevision>")
    );
    assert!(!result.notifications.iter().any(|n| n.sid == topology_sid));
}

#[test]
fn gena_soap_notifications_stay_on_handled_without_double_publish() {
    use franken_control::fsonos::{HttpRequest, Ingress, Service};
    let mut rig = prepared_owner(true);
    let service = Service::GroupRenderingControl;
    let sid = subscribe_events(&mut rig, service);
    let action = format!("\"{}#SetGroupVolume\"", service.urn());
    let body = crate::control_adapter::envelope(
        service,
        "SetGroupVolume",
        &[("InstanceID", "0"), ("DesiredVolume", "75")],
    );
    let headers = [("SOAPACTION", action.as_str())];
    let req = HttpRequest {
        method: "POST",
        path: service.control_path(),
        peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        ingress: Ingress::LocalLegacy,
        headers: &headers,
        body: body.as_bytes(),
    };
    let answer = rig.owner.handle_soap(&req).unwrap();
    assert_eq!(answer.control.response.status, 200);
    assert!(
        answer.notifications.is_empty(),
        "SOAP events must not also be returned as non-SOAP events"
    );
    assert_eq!(answer.control.notifications.len(), 1);
    let event = &answer.control.notifications[0];
    assert_eq!((&event.sid, event.service, event.seq), (&sid, service, 1));
    assert!(event.body.contains("<GroupVolume>75</GroupVolume>"));
    assert!(
        event
            .body
            .contains("<FrankenStateRevision>1</FrankenStateRevision>")
    );
    assert!(
        rig.owner.step_control().unwrap().notifications.is_empty(),
        "same committed state cannot be republished"
    );
}

// These controls exercise the private co-owner with synthetic localhost media
// and a model HAL. Produced GENA events are not delivered notifications.
fn activate_for_media(rig: &mut ControllerRig) {
    use franken_session::ProposalStatus;
    let cutover = ((CLOCK_ORIGIN + 500_000_000) * 48_000) / 1_000_000_000;
    let join = rig
        .owner
        .propose_join(
            rig.token.clone(),
            profile(),
            cutover,
            CLOCK_ORIGIN + 300_000_000,
        )
        .unwrap();
    rig.owner.ack_local(join).unwrap();
    assert!(matches!(
        rig.owner.commit_join(join),
        Ok(ProposalStatus::Committed { .. })
    ));
    rig.local_now.set(600_000_000);
    let result = rig.owner.tick_membership(join).unwrap();
    assert!(result.settled.iter().any(|(id, status)| *id == join
        && matches!(status, ProposalStatus::Activated { revision: 1, .. })));
    for block in 0..2 {
        let wire = packet(
            &mut rig.sender,
            block,
            rig.start_group_ns,
            BLOCK_FRAMES as usize,
        );
        rig.socket.send_to(&wire, rig.address).unwrap();
        let report = rig.owner.poll_media().unwrap();
        assert_eq!((report.media_read, report.media_accepted), (1, 1));
    }
}

fn event_is(event: &franken_control::fsonos::Notification, sid: &str, seq: u32, state: &str) {
    assert_eq!(event.sid, sid);
    assert_eq!(event.service, franken_control::fsonos::Service::AvTransport);
    assert_eq!(event.seq, seq);
    assert!(
        event.body.contains(state),
        "missing {state}: {}",
        event.body
    );
}

fn drive_to_playing(rig: &mut ControllerRig, sid: &str) -> (ScriptedTiming, u64) {
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    for step in 0..5000_u64 {
        rig.local_now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        assert!(matches!(
            rig.owner.render_step(&mut timing).unwrap(),
            PlaybackStep::Render(_)
        ));
        let events = rig.owner.publish_transport().unwrap();
        if !events.is_empty() {
            assert_eq!(events.len(), 1);
            event_is(&events[0], sid, 1, "PLAYING");
            let captured = rig.probe.captured_submissions();
            assert!(
                captured.len() > 1,
                "PLAYING requires a new submission after silent priming"
            );
            assert!(captured.iter().skip(1).flatten().any(|b| *b != 0));
            assert!(
                rig.owner.received_frames_pulled() > 0,
                "positive playback must consume actual accepted source frames"
            );
            return (timing, step + 1);
        }
    }
    panic!("no protected playback submission within bounded schedule");
}

#[test]
fn natural_eof_publishes_transition_then_stopped_only_after_delayed_ack() {
    use franken_control::fsonos::Service;
    let mut rig = prepared_owner_with_completion(true, 2);
    rig.probe.capture_submissions(128);
    activate_for_media(&mut rig);
    let sid = subscribe_events_at_revision(&mut rig, Service::AvTransport, 1);
    assert!(rig.owner.publish_transport().unwrap().is_empty());
    let (mut timing, first_step) = drive_to_playing(&mut rig, &sid);
    let mut saw_drain = false;
    for step in first_step..5000_u64 {
        rig.local_now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        rig.owner.render_step(&mut timing).unwrap();
        if rig.owner.render_state() == RenderState::Draining {
            saw_drain = true;
            break;
        }
        assert!(rig.owner.publish_transport().unwrap().is_empty());
    }
    assert!(
        saw_drain,
        "finite 512-frame input must enter its natural drain"
    );
    let events = rig.owner.publish_transport().unwrap();
    assert_eq!(events.len(), 1);
    event_is(&events[0], &sid, 2, "TRANSITIONING");
    assert!(matches!(
        rig.owner.render_step(&mut timing).unwrap(),
        PlaybackStep::Stopping
    ));
    let mut saw_wait = false;
    let mut acknowledged = false;
    for _ in 0..20 {
        let progress = rig.owner.drain_tick(&mut timing).unwrap();
        if rig.owner.render_state() == RenderState::Draining {
            saw_wait = true;
            assert!(rig.owner.publish_transport().unwrap().is_empty());
        }
        if let DrainProgress::Finished(report) = progress {
            acknowledged = report.acknowledged;
            break;
        }
    }
    assert!(
        saw_wait,
        "delayed flush must leave a visible unacknowledged interval"
    );
    assert!(acknowledged);
    assert_eq!(rig.owner.render_state(), RenderState::Stopped);
    let events = rig.owner.publish_transport().unwrap();
    assert_eq!(events.len(), 1);
    event_is(&events[0], &sid, 3, "STOPPED");
    assert!(rig.owner.publish_transport().unwrap().is_empty());
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}

#[test]
fn missing_ack_never_reports_stopped_and_subscriber_removal_is_respected() {
    use franken_control::fsonos::{HttpRequest, Ingress, Service};
    let mut rig = prepared_owner_with_completion(true, 2);
    rig.probe.capture_submissions(128);
    activate_for_media(&mut rig);
    let old_sid = subscribe_events_at_revision(&mut rig, Service::AvTransport, 1);
    let (mut timing, _) = drive_to_playing(&mut rig, &old_sid);
    // A new subscriber receives the current state, then the old one departs.
    let headers = [
        ("CALLBACK", "<http://127.0.0.1:3401/notify>"),
        ("NT", "upnp:event"),
        ("TIMEOUT", "Second-300"),
    ];
    let req = HttpRequest {
        method: "SUBSCRIBE",
        path: Service::AvTransport.event_path(),
        peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        ingress: Ingress::LocalLegacy,
        headers: &headers,
        body: b"",
    };
    let joined = rig.owner.handle_soap(&req).unwrap();
    assert_eq!(joined.control.response.status, 200);
    assert_eq!(joined.control.notifications.len(), 1);
    let new = &joined.control.notifications[0];
    let new_sid = new.sid.clone();
    assert_ne!(old_sid, new_sid);
    event_is(new, &new_sid, 0, "PLAYING");
    let headers = [("SID", old_sid.as_str())];
    let req = HttpRequest {
        method: "UNSUBSCRIBE",
        path: Service::AvTransport.event_path(),
        peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        ingress: Ingress::LocalLegacy,
        headers: &headers,
        body: b"",
    };
    assert_eq!(
        rig.owner.handle_soap(&req).unwrap().control.response.status,
        200
    );
    rig.suppress_flush.set(true);
    rig.owner.request_stop().unwrap();
    let events = rig.owner.publish_transport().unwrap();
    assert_eq!(events.len(), 1);
    event_is(&events[0], &new_sid, 1, "TRANSITIONING");
    let mut terminal = None;
    for _ in 0..20 {
        match rig.owner.drain_tick(&mut timing).unwrap() {
            DrainProgress::Finished(report) => {
                terminal = Some(report);
                break;
            }
            DrainProgress::Tick { .. } => {
                assert!(rig.owner.publish_transport().unwrap().is_empty())
            }
            DrainProgress::NotStartedUnacknowledged => panic!("missing stop drain"),
        }
    }
    assert!(
        !terminal
            .expect("bounded no-ACK terminal report")
            .acknowledged
    );
    assert_eq!(rig.owner.render_state(), RenderState::Faulted);
    assert!(rig.owner.publish_transport().unwrap().is_empty());
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}

#[test]
fn failed_group_volume_store_never_publishes_the_rolled_back_value() {
    use franken_control::fsonos::Service;
    for ack in [true, false] {
        let mut rig = prepared_owner_with_completion(true, 2);
        rig.probe.capture_submissions(128);
        activate_for_media(&mut rig);
        let transport_sid = subscribe_events_at_revision(&mut rig, Service::AvTransport, 1);
        let group_sid = subscribe_events_at_revision(&mut rig, Service::GroupRenderingControl, 1);
        let (mut timing, _) = drive_to_playing(&mut rig, &transport_sid);
        // Hold actual submitted slots so the observation covers the interval
        // before the delayed flush ACK rather than ordinary completion.
        rig.probe.set_lose_completions(true);
        let held = rig.probe.pending_slots();
        assert!(
            !held.is_empty(),
            "real protected submission must still be in model custody"
        );
        let captured = rig.probe.captured_submissions();
        rig.storage_fail.set(true);
        rig.suppress_flush.set(!ack);
        let cmd = test_wire(
            TEST_CONTROLLER,
            1,
            Some(1),
            ControlCommand::SetGroupVolume { volume: 90 },
        );
        assert!(matches!(
            rig.owner.receive(&cmd).unwrap(),
            FecHandled::Control(Handled::Request {
                result: SubmitResult::Queued { .. },
                ..
            })
        ));
        let calls_before = rig.probe.calls().len();
        let flushes_before = rig.flush_requests.get();
        let result = rig.owner.step_control().unwrap();
        let failed = result
            .control
            .expect_err("injected durable program failure");
        assert!(failed.applied.is_empty());
        assert_eq!(failed.withheld.len(), 1);
        assert!(matches!(
            failed.withheld[0].outcome,
            Outcome::Committed { revision: 2 }
        ));
        assert!(
            !result.notifications.iter().any(|n| n.sid == group_sid),
            "rolled-back volume must not produce a group event"
        );
        assert_eq!(
            result.notifications.len(),
            1,
            "durability failure during playback must publish the actual stop transition"
        );
        let event = &result.notifications[0];
        event_is(event, &transport_sid, 2, "TRANSITIONING");
        assert!(!event.body.contains("<GroupVolume>90</GroupVolume>"));
        assert!(
            !event.body.contains("STOPPED"),
            "failure is not a flush acknowledgement"
        );
        assert!(matches!(result.render, Ok(RenderApplication::Stopping)));
        assert_eq!(rig.owner.render_state(), RenderState::Draining);
        assert!(rig.probe.calls()[calls_before..].contains(&FakeCall::SetMute(true)));
        assert_eq!(rig.flush_requests.get(), flushes_before + 1);
        assert_eq!(rig.probe.pending_slots(), held);
        assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
        assert!(matches!(
            rig.owner.render_step(&mut timing),
            Ok(PlaybackStep::Stopping)
        ));
        let mut waiting = false;
        let mut terminal = None;
        for _ in 0..20 {
            match rig.owner.drain_tick(&mut timing).unwrap() {
                DrainProgress::Tick { report, state } => {
                    assert_eq!(report.started, None);
                    if state == RenderState::Draining {
                        waiting = true;
                        assert_eq!(rig.probe.pending_slots(), held);
                        assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
                        assert!(rig.owner.publish_transport().unwrap().is_empty());
                    }
                }
                DrainProgress::Finished(report) => {
                    terminal = Some(report);
                    break;
                }
                DrainProgress::NotStartedUnacknowledged => panic!("missing active drain"),
            }
        }
        assert!(
            waiting,
            "delayed or absent ACK must not report stopped early"
        );
        assert_eq!(terminal.expect("bounded active drain").acknowledged, ack);
        if ack {
            assert_eq!(rig.owner.render_state(), RenderState::Stopped);
            assert_eq!(rig.probe.pending(), 0);
            let events = rig.owner.publish_transport().unwrap();
            assert_eq!(events.len(), 1);
            event_is(&events[0], &transport_sid, 3, "STOPPED");
        } else {
            assert_eq!(rig.owner.render_state(), RenderState::Faulted);
            assert_eq!(rig.probe.pending_slots(), held);
            assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
            assert!(rig.owner.publish_transport().unwrap().is_empty());
        }
        assert_eq!(rig.probe.captured_submissions(), captured);
        assert_eq!(rig.probe.use_after_free(), 0);
        assert_eq!(rig.probe.modified_while_owned(), 0);
    }
}

#[test]
fn failed_clock_defers_transport_notification_without_fabricating_timestamp() {
    use franken_control::fsonos::Service;
    let mut rig = prepared_owner_with_completion(true, 2);
    rig.probe.capture_submissions(128);
    activate_for_media(&mut rig);
    let sid = subscribe_events_at_revision(&mut rig, Service::AvTransport, 1);
    let (_timing, _) = drive_to_playing(&mut rig, &sid);
    rig.clock_fail.set(true);
    assert!(
        rig.owner.publish_transport().unwrap().is_empty(),
        "no dirty event requires no clock"
    );
    rig.owner.request_stop().unwrap();
    assert!(
        rig.owner.publish_transport().is_err(),
        "dirty update requires actual owner clock"
    );
    rig.clock_fail.set(false);
    assert!(
        rig.owner.publish_transport().is_err(),
        "restoring the local clock does not reconstruct the cleared group-clock fit"
    );
}

fn bare_fleet() -> TestFleet {
    let armed = Rc::new(Cell::new(false));
    let medium = FaultingMedium::new(
        RamMedium::new(Limits::fleet_control_development().segment_bytes),
        None,
        armed,
    );
    TestFleet::boot(HarnessKeys::new(), medium, ChannelConfig::provisional())
        .unwrap()
        .0
}
fn group_token(group: &str, issuer: &str, epoch: u64, expires_at_ns: u64) -> AuthorityToken {
    AuthorityToken {
        group_id: group.into(),
        issuer_id: issuer.into(),
        epoch,
        expires_at_ns,
    }
}

#[test]
fn fresh_bundle_rejects_existing_media_used_owner_and_mismatched_authority() {
    use franken_session::MembershipError;
    let token = group_token("grp", "coord", TEST_EPOCH, u64::MAX);
    let original = bare_fleet();
    let medium = original.into_storage();
    let (existing, _) =
        TestFleet::boot(HarnessKeys::new(), medium, ChannelConfig::provisional()).unwrap();
    assert!(matches!(
        provision_bundle(existing, token.clone()),
        Err(FreshGroupError::NotFresh)
    ));
    let mut used = bare_fleet();
    let mut earlier = UnifiedGroupSession::new("grp", "coord", TEST_EPOCH);
    used.step(CLOCK_ORIGIN, &mut earlier).unwrap();
    assert!(matches!(
        provision_bundle(used, token),
        Err(FreshGroupError::NotFresh)
    ));
    for (bad, expected) in [
        (group_token("wrong", "coord", TEST_EPOCH, u64::MAX), 0),
        (group_token("grp", "wrong", TEST_EPOCH, u64::MAX), 1),
        (group_token("grp", "coord", TEST_EPOCH + 1, u64::MAX), 2),
        (group_token("grp", "coord", TEST_EPOCH, CLOCK_ORIGIN), 3),
    ] {
        let result = provision_bundle(bare_fleet(), bad);
        assert!(matches!(
            (expected, result),
            (
                0,
                Err(FreshGroupError::Authority(MembershipError::WrongGroup))
            ) | (
                1,
                Err(FreshGroupError::Authority(
                    MembershipError::NotConfiguredIssuer
                ))
            ) | (
                2,
                Err(FreshGroupError::Authority(
                    MembershipError::FutureAuthority { .. }
                ))
            ) | (
                3,
                Err(FreshGroupError::Authority(
                    MembershipError::AuthorityExpired { .. }
                ))
            )
        ));
    }
}

#[test]
fn fresh_coowner_rechecks_network_epoch_leader_clock_and_admission_time() {
    use crate::settled_render::AdmissionError;
    // Wrong network epoch: the fresh bundle itself is valid for epoch two.
    let parts = prepared_parts(true, 2);
    let (control, soap, _) = test_fleet_unleased();
    let bundle = control
        .provision_fresh_group(
            "grp",
            "coord",
            TEST_EPOCH + 1,
            MembershipConfig::default(),
            group_token("grp", "coord", TEST_EPOCH + 1, u64::MAX),
            CLOCK_ORIGIN + 50_000_000,
        )
        .unwrap();
    assert!(matches!(
        SettledRender::admit_fresh_group(bundle, soap, parts.network, pending_member(), 7),
        Err(AdmissionError::Binding)
    ));

    let parts = prepared_parts(true, 2);
    let (control, soap, _) = test_fleet_unleased();
    let bundle =
        provision_bundle(control, group_token("grp", "coord", TEST_EPOCH, u64::MAX)).unwrap();
    assert!(matches!(
        SettledRender::admit_fresh_group(bundle, soap, parts.network, pending_member(), 8),
        Err(AdmissionError::Binding)
    ));

    let parts = prepared_parts(true, 2);
    let (control, soap, _) = test_fleet_unleased();
    let token = group_token("grp", "coord", TEST_EPOCH, 50_000_000_000);
    // Valid when Yellow's bundle forms at zero; expired on this owner's real group clock.
    let bundle = control
        .provision_fresh_group(
            "grp",
            "coord",
            TEST_EPOCH,
            MembershipConfig::default(),
            token,
            0,
        )
        .unwrap();
    assert!(matches!(
        SettledRender::admit_fresh_group(bundle, soap, parts.network, pending_member(), 7),
        Err(AdmissionError::Binding)
    ));

    let parts = prepared_parts(true, 2);
    let (control, soap, _) = test_fleet_unleased();
    let bundle =
        provision_bundle(control, group_token("grp", "coord", TEST_EPOCH, u64::MAX)).unwrap();
    parts.clock_fail.set(true);
    assert!(matches!(
        SettledRender::admit_fresh_group(bundle, soap, parts.network, pending_member(), 7),
        Err(AdmissionError::Render(NetworkRenderError::Clock))
    ));
}

#[test]
fn fresh_owner_does_not_mint_ready_member_or_start_before_protocol_activation() {
    let mut rig = prepared_owner_with_completion(true, 2);
    let mut timing = ScriptedTiming::default();
    assert!(matches!(rig.owner.ack_local(1), Err(OwnerError::JoinState)));
    assert!(matches!(
        rig.owner.render_step(&mut timing),
        Ok(PlaybackStep::WaitingJoin)
    ));
    assert!(!rig.probe.calls().contains(&FakeCall::Start));
    assert_eq!(
        rig.probe.captured_submissions(),
        vec![vec![0; RENDER_FRAMES * 4]]
    );
}

#[test]
fn fresh_join_rejects_substitute_token_but_accepts_the_provisioned_token() {
    let mut rig = prepared_owner(true);
    let cutover = ((CLOCK_ORIGIN + 2_000_000_000) * 48_000) / 1_000_000_000;
    let mut replacement = rig.token.clone();
    replacement.expires_at_ns -= 1;
    assert!(matches!(
        rig.owner.propose_join(
            replacement,
            profile(),
            cutover,
            CLOCK_ORIGIN + 1_000_000_000
        ),
        Err(OwnerError::JoinState)
    ));
    assert!(
        rig.owner
            .propose_join(
                rig.token.clone(),
                profile(),
                cutover,
                CLOCK_ORIGIN + 1_000_000_000
            )
            .is_ok()
    );
}

#[test]
fn provisioned_lease_expires_while_waiting_and_causes_actual_drain() {
    let parts = prepared_parts(true, 2);
    let (control, soap, _) = test_fleet_unleased();
    let token = group_token("grp", "coord", TEST_EPOCH, CLOCK_ORIGIN + 700_000_000);
    let bundle = provision_bundle(control, token).unwrap();
    let mut owner =
        SettledRender::admit_fresh_group(bundle, soap, parts.network, pending_member(), 7).unwrap();
    let mut timing = ScriptedTiming::default();
    parts.local_now.set(200_000_000);
    assert!(matches!(
        owner.render_step(&mut timing),
        Ok(PlaybackStep::WaitingJoin)
    ));
    parts.local_now.set(800_000_000);
    assert!(matches!(
        owner.render_step(&mut timing),
        Err(OwnerError::LeaseExpired)
    ));
    assert_eq!(owner.render_state(), RenderState::Draining);
    assert!(!parts.probe.calls().contains(&FakeCall::Start));
    assert!(finish_drain(&mut owner).acknowledged);
}

#[test]
fn fresh_bundle_cannot_be_reprovisioned_after_parts_are_consumed() {
    let token = group_token("grp", "coord", TEST_EPOCH, u64::MAX);
    let fresh = provision_bundle(bare_fleet(), token.clone()).unwrap();
    let (owner, membership, session, authority) = fresh.into_parts();
    assert!(owner.fresh_group_is_healthy());
    assert!(session.members.is_empty());
    assert!(membership.lease_is_live(&session, &authority, CLOCK_ORIGIN + 50_000_000));
    assert!(
        matches!(
            provision_bundle(owner, token),
            Err(FreshGroupError::NotFresh)
        ),
        "one owner must not form another fresh session after its bundle is unpacked"
    );
}

#[test]
fn failed_flush_on_prepared_or_active_owner_still_exposes_terminal_drain() {
    use franken_control::fsonos::Service;
    use franken_hal::backend::Op;
    for active in [false, true] {
        let mut rig = prepared_owner_with_completion(true, if active { 2 } else { 100 });
        rig.probe.capture_submissions(128);
        let mut timing = if active {
            activate_for_media(&mut rig);
            let sid = subscribe_events_at_revision(&mut rig, Service::AvTransport, 1);
            drive_to_playing(&mut rig, &sid).0
        } else {
            ScriptedTiming::default()
        };
        rig.probe.set_lose_completions(true);
        let held = rig.probe.pending_slots();
        assert!(!held.is_empty());
        let captured = rig.probe.captured_submissions();
        let before = rig.probe.calls().len();
        let flushes_before = rig.flush_requests.get();
        rig.probe.fail_next(Op::RequestFlush, DriverError::Errno(5));
        // RenderLoop records the HAL abort error and proceeds into drain;
        // no caller-visible error or flush ACK is invented by the fixture.
        assert!(matches!(
            rig.owner.request_stop(),
            Ok(RenderApplication::Stopping)
        ));
        assert_eq!(rig.flush_requests.get(), flushes_before + 1);
        let calls = rig.probe.calls();
        assert!(calls[before..].contains(&FakeCall::SetMute(true)));
        assert!(calls[before..].contains(&FakeCall::RequestFlush));
        assert!(matches!(
            rig.owner.render_step(&mut timing),
            Ok(PlaybackStep::Stopping)
        ));
        assert_eq!(rig.probe.pending_slots(), held);
        assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
        let mut report = None;
        for _ in 0..20 {
            match rig.owner.drain_tick(&mut timing).unwrap() {
                DrainProgress::Tick { report, .. } => assert_eq!(report.started, None),
                DrainProgress::Finished(done) => {
                    report = Some(done);
                    break;
                }
                DrainProgress::NotStartedUnacknowledged => {
                    panic!("failed flush must not hide drain")
                }
            }
        }
        assert!(!report.expect("fault report must be reachable").acknowledged);
        assert_eq!(rig.owner.render_state(), RenderState::Faulted);
        assert_eq!(rig.probe.pending_slots(), held);
        assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
        assert_eq!(rig.probe.captured_submissions(), captured);
        if !active {
            assert!(!rig.probe.calls().contains(&FakeCall::Start));
        }
        assert_eq!(rig.probe.use_after_free(), 0);
        assert_eq!(rig.probe.modified_while_owned(), 0);
    }
}

#[test]
fn coowner_start_failure_stays_faulted_without_submission_or_fabricated_ack() {
    use franken_control::fsonos::Service;
    use franken_hal::backend::Op;
    let mut rig = prepared_owner_with_completion(true, 2);
    rig.probe.capture_submissions(128);
    activate_for_media(&mut rig);
    let pulled_before = rig.owner.received_frames_pulled();
    assert_eq!(
        pulled_before, 0,
        "accepted media has not yet reached the source"
    );
    let sid = subscribe_events_at_revision(&mut rig, Service::AvTransport, 1);
    let held = rig.probe.pending_slots();
    assert_eq!(held.len(), 1);
    let prime = rig.probe.captured_submissions();
    assert_eq!(prime, vec![vec![0; RENDER_FRAMES * 4]]);
    rig.probe.fail_next(Op::Start, DriverError::Errno(5));
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    let mut failed = false;
    for step in 0..5000_u64 {
        rig.local_now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        match rig.owner.render_step(&mut timing) {
            Ok(PlaybackStep::Render(_)) => {
                assert!(rig.owner.publish_transport().unwrap().is_empty());
            }
            Err(OwnerError::Render(NetworkRenderError::Render(_))) => {
                failed = true;
                break;
            }
            other => panic!("unexpected start-failure result: {other:?}"),
        }
    }
    assert!(
        failed,
        "the admitted media must actually reach the injected START error"
    );
    assert_eq!(
        rig.probe
            .calls()
            .iter()
            .filter(|call| **call == FakeCall::Start)
            .count(),
        1
    );
    assert_eq!(rig.owner.render_state(), RenderState::Faulted);
    assert_eq!(
        rig.owner.received_frames_pulled(),
        pulled_before,
        "failed backend start must precede pulling the source"
    );
    assert_eq!(rig.probe.captured_submissions(), prime);
    assert_eq!(rig.probe.pending_slots(), held);
    assert_eq!(rig.probe.kernel_touch_pending(), (1, 0));
    assert!(matches!(
        rig.owner.render_step(&mut timing),
        Ok(PlaybackStep::Stopping)
    ));
    match rig.owner.drain_tick(&mut timing).unwrap() {
        DrainProgress::Finished(report) => assert!(!report.acknowledged),
        other => panic!("faulted owner must expose its unacknowledged report: {other:?}"),
    }
    assert!(
        rig.owner.publish_transport().unwrap().is_empty(),
        "initial TRANSITIONING cannot become PLAYING or STOPPED on failed start"
    );
    assert_eq!(rig.probe.captured_submissions(), prime);
    assert_eq!(
        rig.owner.received_frames_pulled(),
        pulled_before,
        "fault handling must not subsequently pull the source"
    );
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    let _ = sid;
}

/// Reach the real finite-source boundary while preserving the original clock
/// schedule. A zero trim step observes the co-owner's reconciliation result;
/// it does not change the intended gain or advance the render clock.
fn finite_tail_fixture(hold_tail: bool) -> (ControllerRig, ScriptedTiming, u64, String, String) {
    use franken_control::fsonos::Service;
    let mut rig = prepared_owner_with_completion(true, 2);
    rig.probe.capture_submissions(128);
    activate_for_media(&mut rig);
    let transport_sid = subscribe_events_at_revision(&mut rig, Service::AvTransport, 1);
    let group_sid = subscribe_events_at_revision(&mut rig, Service::GroupRenderingControl, 1);
    let (mut timing, first_step) = drive_to_playing(&mut rig, &transport_sid);
    let flushes_before = rig.flush_requests.get();
    let mut holding = false;
    for step in first_step..5000_u64 {
        rig.local_now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        match rig.owner.local_trim_step(0).unwrap().unwrap() {
            RenderApplication::Finishing => {
                assert!(matches!(
                    rig.owner.render_state(),
                    RenderState::Running | RenderState::Muted
                ));
                assert!(rig.owner.received_frames_pulled() > 0);
                if hold_tail {
                    assert!(
                        holding,
                        "the final model custody window must have been armed"
                    );
                    assert!(
                        !rig.probe.pending_slots().is_empty(),
                        "the finishing control must observe a real retained model slot"
                    );
                }
                assert_eq!(
                    rig.flush_requests.get(),
                    flushes_before,
                    "finite tail must be observed before any stop request"
                );
                return (rig, timing, step, transport_sid, group_sid);
            }
            RenderApplication::PolicyAccepted => {}
            other => panic!("unexpected result before finite finishing: {other:?}"),
        }
        assert!(matches!(
            rig.owner.render_step(&mut timing).unwrap(),
            PlaybackStep::Render(_)
        ));
        // After seven actual protected submissions (plus the silent prime),
        // withhold later completions so the final retained custody is visible.
        // The four-slot ring still has room for the eighth 64-frame block.
        if hold_tail && !holding && rig.probe.captured_submissions().len() >= 8 {
            rig.probe.set_lose_completions(true);
            holding = true;
        }
        assert!(rig.owner.publish_transport().unwrap().is_empty());
        assert_eq!(rig.flush_requests.get(), flushes_before);
    }
    panic!("never observed the finite finishing interval");
}

fn scheduled_tail_with_volume_change(change: bool) -> Vec<Vec<u8>> {
    use franken_control::fsonos::Service;
    let (mut rig, mut timing, first_step, transport_sid, group_sid) = finite_tail_fixture(false);
    // Independent clock instance with the same four synthetic probes; this is
    // an independent observation, not access to the owner's private clock.
    let oracle_clock = network().clock;
    let end_group_ns = rig.start_group_ns.checked_add(frames_to_ns(512)).unwrap();
    let anchor = oracle_clock.reading(rig.local_now.get()).unwrap();
    let earliest = franken_clock::group::group_at(&anchor, rig.local_now.get())
        .saturating_sub(anchor.uncertainty_ns);
    assert!(
        earliest < end_group_ns,
        "must observe finishing before scheduled source end"
    );
    let pulled = rig.owner.received_frames_pulled();
    let flushes = rig.flush_requests.get();
    if change {
        let wire = test_wire(
            TEST_CONTROLLER,
            1,
            Some(1),
            ControlCommand::SetGroupVolume { volume: 75 },
        );
        assert!(matches!(
            rig.owner.receive(&wire).unwrap(),
            FecHandled::Control(Handled::Request {
                result: SubmitResult::Queued { .. },
                ..
            })
        ));
    }
    let result = rig.owner.step_control().unwrap();
    let settled = result.control.unwrap();
    if change {
        assert_eq!(settled.len(), 1);
        assert!(matches!(
            settled[0].outcome,
            Outcome::Committed { revision: 2 }
        ));
        assert_eq!(result.notifications.len(), 1);
        let event = &result.notifications[0];
        assert_eq!(
            (&event.sid, event.service, event.seq),
            (&group_sid, Service::GroupRenderingControl, 1)
        );
        assert!(event.body.contains("<GroupVolume>75</GroupVolume>"));
    } else {
        assert!(settled.is_empty());
        assert!(result.notifications.is_empty());
    }
    assert!(
        matches!(result.render, Ok(RenderApplication::Finishing)),
        "a committed future gain intent must not be reported as applied to exhausted PCM"
    );
    assert_eq!(rig.owner.received_frames_pulled(), pulled);
    assert_eq!(
        rig.flush_requests.get(),
        flushes,
        "intent must not flush the scheduled tail"
    );
    let mut draining = false;
    for step in first_step..5000_u64 {
        rig.local_now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        assert!(matches!(
            rig.owner.render_step(&mut timing).unwrap(),
            PlaybackStep::Render(_)
        ));
        assert_eq!(
            rig.owner.received_frames_pulled(),
            pulled,
            "no new real source PCM after finishing"
        );
        if rig.owner.render_state() == RenderState::Draining {
            let now = rig.local_now.get();
            let anchor = oracle_clock.reading(now).unwrap();
            let earliest =
                franken_clock::group::group_at(&anchor, now).saturating_sub(anchor.uncertainty_ns);
            assert!(
                earliest >= end_group_ns,
                "flush at earliest group time {earliest} precedes scheduled end {end_group_ns}"
            );
            draining = true;
            break;
        }
        assert_eq!(
            rig.flush_requests.get(),
            flushes,
            "no flush before scheduled end"
        );
        assert!(rig.owner.publish_transport().unwrap().is_empty());
    }
    assert!(draining, "scheduled tail must reach its natural drain");
    assert_eq!(rig.flush_requests.get(), flushes + 1);
    let events = rig.owner.publish_transport().unwrap();
    assert_eq!(events.len(), 1);
    event_is(&events[0], &transport_sid, 2, "TRANSITIONING");
    let report = finish_drain(&mut rig.owner);
    assert!(report.acknowledged);
    assert_eq!(rig.owner.render_state(), RenderState::Stopped);
    let events = rig.owner.publish_transport().unwrap();
    assert_eq!(events.len(), 1);
    event_is(&events[0], &transport_sid, 3, "STOPPED");
    assert_eq!(rig.owner.received_frames_pulled(), pulled);
    assert_eq!(
        pulled, 512,
        "all accepted source frames must actually be consumed"
    );
    let (reference_blocks, reference_frames) = expected_protected(&signal(0, 512), 0);
    assert!(
        reference_frames >= 512,
        "independent D03 reference must cover the complete source"
    );
    let captured = rig.probe.captured_submissions();
    assert_eq!(
        captured.len(),
        reference_blocks.len() + 1,
        "capture must contain the silent prime and every independently expected protected block"
    );
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    captured
}

#[test]
fn finite_tail_volume_intent_is_deferred_without_early_flush_or_new_source_pcm() {
    let baseline = scheduled_tail_with_volume_change(false);
    let changed = scheduled_tail_with_volume_change(true);
    assert!(baseline.iter().skip(1).flatten().any(|byte| *byte != 0));
    assert_eq!(
        changed, baseline,
        "post-EOF control may not alter the already prepared or scheduled protected output"
    );
}

#[test]
fn local_mute_and_stop_cancel_finishing_tail_and_require_actual_ack() {
    // Direct stop/mute, authenticated local stop/mute, failed-store local
    // mute, and failed-store remote mute which must be rolled back.
    for mode in 0..6 {
        for ack in [true, false] {
            let (mut rig, mut timing, _, transport_sid, _) = finite_tail_fixture(true);
            let pulled = rig.owner.received_frames_pulled();
            let flushes = rig.flush_requests.get();
            let calls_before = rig.probe.calls().len();
            let captured = rig.probe.captured_submissions();
            rig.probe.set_lose_completions(true);
            let held = rig.probe.pending_slots();
            rig.suppress_flush.set(!ack);
            let mut control_events = None;
            let mut rendering_sid = None;
            let stop = match mode {
                0 => rig.owner.request_stop(),
                1 => rig.owner.local_mute(true),
                2..=5 => {
                    if mode == 4 || mode == 5 {
                        rendering_sid = Some(subscribe_events_at_revision(
                            &mut rig,
                            franken_control::fsonos::Service::RenderingControl,
                            1,
                        ));
                        rig.storage_fail.set(true);
                    }
                    let wire = if mode == 2 {
                        stop_wire(TEST_PANEL, 1)
                    } else {
                        test_wire(
                            if mode == 5 {
                                TEST_CONTROLLER
                            } else {
                                TEST_PANEL
                            },
                            1,
                            if mode == 5 { Some(1) } else { None },
                            ControlCommand::SetMemberMute {
                                member_id: TEST_MEMBER.into(),
                                muted: true,
                            },
                        )
                    };
                    assert!(matches!(
                        rig.owner.receive(&wire).unwrap(),
                        FecHandled::Control(Handled::Request {
                            result: SubmitResult::Queued { .. },
                            ..
                        })
                    ));
                    let result = rig.owner.step_control().unwrap();
                    if mode == 4 || mode == 5 {
                        let failed = result.control.expect_err("injected mute store failure");
                        if mode == 4 {
                            assert!(failed.withheld.is_empty());
                            assert_eq!(failed.applied.len(), 1);
                            assert!(matches!(
                                failed.applied[0].outcome,
                                Outcome::Committed { revision: 2 }
                            ));
                        } else {
                            assert!(failed.applied.is_empty());
                            assert_eq!(failed.withheld.len(), 1);
                            assert!(matches!(
                                failed.withheld[0].outcome,
                                Outcome::Committed { revision: 2 }
                            ));
                        }
                    } else {
                        let outcomes = result.control.unwrap();
                        assert_eq!(outcomes.len(), 1);
                        assert!(matches!(
                            outcomes[0].outcome,
                            Outcome::Committed { revision: 2 }
                        ));
                    }
                    control_events = Some(result.notifications);
                    result.render
                }
                _ => unreachable!(),
            };
            assert!(matches!(stop, Ok(RenderApplication::Stopping)));
            if mode == 3 || mode == 4 {
                assert_eq!(
                    rig.owner.effective_mute(),
                    Some(franken_dsp::volume::MuteReason::Group)
                );
            }
            if let Some(sid) = rendering_sid.as_ref() {
                let events = control_events.as_ref().expect("mute step notifications");
                if mode == 4 {
                    let event = events
                        .iter()
                        .find(|event| &event.sid == sid)
                        .expect("reapplied local mute must publish actual live member state");
                    assert_eq!(event.seq, 1);
                    assert!(event.body.contains("Mute channel=\"Master\" val=\"1\""));
                    assert!(
                        event
                            .body
                            .contains("<FrankenStateRevision>2</FrankenStateRevision>")
                    );
                } else {
                    assert_eq!(
                        rig.owner.effective_mute(),
                        None,
                        "withheld remote mute must not change live desired intent"
                    );
                    assert!(
                        !events.iter().any(|event| &event.sid == sid),
                        "withheld remote mute must not publish a member mute event"
                    );
                }
            }
            assert_eq!(rig.owner.render_state(), RenderState::Draining);
            assert_eq!(rig.flush_requests.get(), flushes + 1);
            assert!(rig.probe.calls()[calls_before..].contains(&FakeCall::SetMute(true)));
            assert_eq!(rig.owner.received_frames_pulled(), pulled);
            assert_eq!(rig.probe.pending_slots(), held);
            assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
            assert!(matches!(
                rig.owner.render_step(&mut timing),
                Ok(PlaybackStep::Stopping)
            ));
            let events = match control_events {
                Some(events) => events,
                None => rig.owner.publish_transport().unwrap(),
            };
            let transitions: Vec<_> = events
                .iter()
                .filter(|event| event.sid == transport_sid)
                .collect();
            assert_eq!(transitions.len(), 1);
            event_is(transitions[0], &transport_sid, 2, "TRANSITIONING");
            assert!(rig.owner.publish_transport().unwrap().is_empty());
            let report = finish_drain(&mut rig.owner);
            assert_eq!(report.acknowledged, ack);
            assert_eq!(rig.owner.received_frames_pulled(), pulled);
            assert_eq!(rig.probe.captured_submissions(), captured);
            if ack {
                assert_eq!(rig.owner.render_state(), RenderState::Stopped);
                assert_eq!(rig.probe.pending(), 0);
                let events = rig.owner.publish_transport().unwrap();
                assert_eq!(events.len(), 1);
                event_is(&events[0], &transport_sid, 3, "STOPPED");
            } else {
                assert_eq!(rig.owner.render_state(), RenderState::Faulted);
                assert_eq!(rig.probe.pending_slots(), held);
                assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
                assert!(rig.owner.publish_transport().unwrap().is_empty());
            }
            assert_eq!(rig.probe.use_after_free(), 0);
            assert_eq!(rig.probe.modified_while_owned(), 0);
        }
    }
}

#[test]
fn finite_tail_clock_failure_is_not_misreported_as_normal_finishing() {
    let (mut rig, _, _, _, _) = finite_tail_fixture(false);
    let pulled = rig.owner.received_frames_pulled();
    let flushes = rig.flush_requests.get();
    rig.clock_fail.set(true);
    assert!(matches!(
        rig.owner.local_trim_step(0).unwrap(),
        Err(OwnerError::Render(NetworkRenderError::Clock))
    ));
    assert_eq!(rig.owner.render_state(), RenderState::Draining);
    assert_eq!(rig.flush_requests.get(), flushes + 1);
    assert_eq!(rig.owner.received_frames_pulled(), pulled);
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert_eq!(rig.owner.received_frames_pulled(), pulled);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}

#[cfg(unix)]
mod role_integration;

#[cfg(unix)]
mod binding_integration;

#[cfg(unix)]
mod button_integration;

#[cfg(unix)]
mod http_integration;

#[cfg(unix)]
mod http_eventing;

#[cfg(unix)]
mod final_feedback;
