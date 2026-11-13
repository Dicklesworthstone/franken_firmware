//! Actual fsonos-proto client through one mailbox to one protected owner.
//! Loopback and scripted host fixtures only; not device or provider evidence.
#![cfg(unix)]
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::rc::Rc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use franken_board_profile::BoardProfile;
use franken_clock::group::{GroupClock, GroupClockConfig, ProbeResponse, StartSchedule};
use franken_control::channel::owner::FleetControlOwner;
use franken_control::channel::peer::{PeerId, PeerRole};
use franken_control::channel::pipeline::{ChannelConfig, Limits, RamMedium};
use franken_control::contracts::secret_store::{
    Generation, SecretError, SecretHandle, SecretMeta, SecretStore, SecretValue,
};
use franken_control::fsonos::{Endpoint, EndpointConfig, LegacyBridge};
use franken_dsp::protection::{
    Admission as ProtectionAdmission, ProtectedBoardDsp, synthetic_calibration_for,
};
use franken_dsp::resample::{DriftResampler, ResamplerConfig};
use franken_hal::abi::{EVENT_LEN, RawGeometry};
use franken_hal::backend::{
    AbiKind, DeviceBackend, DriverError, FakeBackend, FakeConfig, FakeProbe,
    Provenance as HalProvenance, RawCapabilities,
};
use franken_hal::session::{HalSession, SessionConfig, StartPreconditions};
use franken_hal::slots::{KernelView, LeakLedger};
use franken_platform::MemoryBudgetLedger;
use franken_platform::abi::Abi;
use franken_platform::layer::PlatformLayer;
use franken_platform::ops::{KernelOps, Provenance, Timespec};
use franken_session::{
    AuthorityToken, ChannelRole, MembershipConfig, ProposalStatus, UnifiedGroupSession,
};
use franken_speaker::fsonos_loopback::{
    self as shim, CallbackLimits, CallbackTarget, FsonosLoopback, LoopbackLimits, Policy,
    mailbox_eventing_control,
};
use franken_speaker::media_playout::MediaPlayout;
use franken_speaker::net_carrier::MediaEndpoint;
use franken_speaker::network_render::{NetworkRender, NetworkRenderAdmission, TickMapping};
use franken_speaker::render::{RenderConfig, RenderLoop, ScriptedTiming};
use franken_speaker::settled_http::{
    HttpMailboxConfig, HttpMailboxOwner, HttpService, http_mailbox,
};
use franken_speaker::settled_render::{DrainProgress, PendingMember, PlaybackStep, SettledRender};
use franken_stream::carrier::{CarrierReceiver, HostUdp, ReceiverLimits};
use franken_stream::playout::{BLOCK_FRAMES, PlayoutConfig, PlayoutProfile, frames_to_ns};
use franken_stream::{OutboundFrame, StreamId, StreamKey, StreamReceiver, StreamSender};
use fsonos_proto::control::set_volume;
use fsonos_proto::gena::{Notify, Subscription};
use fsonos_proto::net::{EventSink, Lan};
use fsonos_proto::soap::RENDERING_CONTROL;
use fsonos_proto::{ProtoError, Transport};

const MEMBER: &str = "speaker";
const PLAYER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const CLOCK_ORIGIN: u64 = 100_000_000_000;
const RENDER_FRAMES: usize = 64;
const TAG: &str = "RenderingControl";

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

struct TestKernel {
    now: Rc<Cell<u64>>,
    fail: Rc<Cell<bool>>,
}

impl KernelOps for TestKernel {
    fn provenance(&self) -> Provenance {
        Provenance::Simulated
    }
    fn backend_abi(&self) -> Option<Abi> {
        None
    }
    fn clock_gettime_monotonic(&mut self, out: &mut Timespec) -> isize {
        if self.fail.get() {
            return -38;
        }
        let now = self.now.get();
        out.secs = i64::try_from(now / 1_000_000_000).unwrap();
        out.nanos = i64::try_from(now % 1_000_000_000).unwrap();
        0
    }
    fn getrandom(&mut self, _buf: &mut [u8], _flags: u32) -> isize {
        -38
    }
    fn open_dev_random(&mut self, _flags: u32) -> isize {
        -38
    }
    fn eventfd2(&mut self, _initval: u32, _flags: u32) -> isize {
        7
    }
    fn pipe2(&mut self, _fds: &mut [i32; 2], _flags: u32) -> isize {
        -38
    }
    fn write(&mut self, _fd: i32, _buf: &[u8]) -> isize {
        -38
    }
    fn read(&mut self, _fd: i32, _buf: &mut [u8]) -> isize {
        -38
    }
    fn close(&mut self, _fd: i32) -> isize {
        0
    }
}

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

type Owner = SettledRender<HarnessKeys, RamMedium, HostUdp, TestKernel, RetainedPurge>;

fn profile() -> BoardProfile {
    franken_board_profile::synthetic_test_fixture_catalog()
        .into_iter()
        .find(|p| p.model_number == "S1")
        .unwrap()
}
fn key_for(name: &str) -> Vec<u8> {
    format!("fixture-key-{name}-0123456789abcdef").into_bytes()
}
fn peer(name: &str) -> PeerId {
    PeerId::parse(name).unwrap()
}

struct Rig {
    owner: Owner,
    now: Rc<Cell<u64>>,
    probe: FakeProbe,
    socket: UdpSocket,
    address: SocketAddr,
    sender: StreamSender,
    start_group_ns: u64,
    start_local_ns: u64,
}

fn rig() -> Rig {
    rig_with_identity(None)
}

fn rig_with_identity(identity: Option<&shim::DiscoveryIdentity>) -> Rig {
    rig_with_identity_at(identity, Ipv4Addr::LOCALHOST)
}

fn rig_with_identity_at(identity: Option<&shim::DiscoveryIdentity>, logical: Ipv4Addr) -> Rig {
    let member = identity.map_or(MEMBER, |identity| identity.uuid.as_str());
    // Each standalone fixture is coordinated by its actual member.
    let coordinator = member;
    // Synthetic distinct standalone groups and endpoint boot namespaces for the two-owner fixture.
    let (group_id, subscription_nonce) = match logical.octets() {
        [127, 0, 0, 2] => ("owner-a", 1),
        [127, 0, 0, 3] => ("owner-b", 2),
        _ => ("grp", 1),
    };
    let now = Rc::new(Cell::new(50_000_000));
    let kernel = TestKernel {
        now: Rc::clone(&now),
        fail: Rc::new(Cell::new(false)),
    };
    let matrix = shim_guest_matrix();
    let platform = PlatformLayer::admit(&matrix, kernel).unwrap();
    let mut clock = GroupClock::new(GroupClockConfig::standard().unwrap(), 1, 7, 100).unwrap();
    for k in 1..=4_u64 {
        let t1 = k * 10_000_000;
        let req = clock.next_probe(t1);
        clock
            .on_response(
                ProbeResponse {
                    epoch: clock.epoch(),
                    leader: clock.leader(),
                    seq: req.seq,
                    t1_echo_ns: req.t1_local_ns,
                    t2_group_ns: CLOCK_ORIGIN + t1 + 400_000,
                    t3_group_ns: CLOCK_ORIGIN + t1 + 450_000,
                },
                t1 + 850_000,
            )
            .unwrap();
    }
    let start_group_ns = clock.group_ns(now.get()).unwrap() + 1_000_000_000;
    let start_local_ns = clock.local_for_group(start_group_ns, now.get()).unwrap();
    clock
        .set_authority(1, start_local_ns + 2_000_000_000, now.get())
        .unwrap();
    let key = StreamKey::from_bytes([0x42; 32]);
    let stream = StreamId::new(0x5EED_5EED_0000_0001).unwrap();
    let receiver = CarrierReceiver::bind(
        key.clone(),
        stream,
        1,
        ReceiverLimits::baseline(),
        PLAYER,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
    )
    .unwrap();
    let ledger = MemoryBudgetLedger {
        nominal_ram_bytes: 32 * 1024 * 1024,
        kernel_and_driver_reserved_bytes: 14 * 1024 * 1024,
        dma_ring_reserved_bytes: 512 * 1024,
        core_runtime_peak_bytes: 3 * 1024 * 1024,
        stream_and_jitter_bytes: 2 * 1024 * 1024,
        native_integrations_bytes: 4 * 1024 * 1024,
        required_safety_floor_bytes: MemoryBudgetLedger::MIN_SAFETY_FLOOR_BYTES,
    };
    let media = MediaPlayout::new(
        StreamReceiver::new(key.clone(), stream, 1),
        PlayoutProfile::MUSIC,
        PlayoutConfig {
            work_ns: 10_000_000,
            lead_ns: 1_000_000,
            tolerance_ns: 1_000_000,
        },
        &ledger,
        0,
    )
    .unwrap();
    let endpoint = MediaEndpoint::new(receiver, media);
    let address = endpoint.carrier().media_addr().unwrap();
    let mut cfg = FakeConfig::retained();
    cfg.geometry = RawGeometry {
        ring_depth: 4,
        frames_per_block: 64,
        channels: 2,
        bytes_per_sample: 2,
    };
    cfg.completion_delay_ticks = 2;
    cfg.min_submission_lead_ticks = Some(6);
    cfg.flush_ack_delay_ticks = Some(3);
    let (backend, probe) = FakeBackend::new(cfg);
    probe.capture_submissions(128);
    let backend = RetainedPurge {
        inner: backend,
        capable: true,
        suppress_next_flush: Rc::new(Cell::new(false)),
        flush_requests: Rc::new(Cell::new(0)),
    };
    let mut hal = HalSession::open(
        profile(),
        backend,
        SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2),
    )
    .unwrap();
    hal.prepare().unwrap();
    assert!(hal.abort_mute().unwrap().mute_acknowledged);
    hal.reset_device().unwrap();
    assert!(hal.silent_prepared_after_reset());
    assert_eq!(
        hal.prime_silence().unwrap().accepted_bytes,
        RENDER_FRAMES * 4
    );
    let board = profile();
    let calibration = synthetic_calibration_for(&board);
    let dsp = ProtectedBoardDsp::admit(
        &board,
        Some(&calibration),
        ProtectionAdmission::HostSimulation,
    );
    let mut config = RenderConfig::standard(RENDER_FRAMES);
    config.window_ticks = 8;
    let render = RenderLoop::new(
        hal,
        dsp,
        DriftResampler::new(ResamplerConfig::default()).unwrap(),
        config,
    )
    .unwrap();
    let first = render.next_slot().unwrap();
    let mapping = TickMapping {
        anchor_tick: first.presentation_tick,
        anchor_group_ns: start_group_ns,
        ns_numerator: 1_000_000,
        tick_denominator: 3,
        uncertainty_ns: 0,
        presentation_tolerance_ns: 1,
    };
    let network = NetworkRender::admit(
        endpoint,
        platform,
        clock,
        render,
        NetworkRenderAdmission {
            schedule: StartSchedule {
                epoch: 1,
                start_group_ns,
            },
            anchor_frame: 0,
            final_frame: 512,
            mapping,
            capacity_frames: 1024,
            start: StartPreconditions {
                presentation_mapping_installed: true,
                safe_gain_installed: true,
            },
        },
    )
    .unwrap();
    let (mut fleet, _) = FleetControlOwner::boot(
        HarnessKeys::new(),
        RamMedium::new(Limits::fleet_control_development().segment_bytes),
        ChannelConfig::provisional(),
    )
    .unwrap();
    let bridge = peer("legacy-bridge");
    fleet
        .admit(
            &bridge,
            PeerRole::Controller,
            &key_for("legacy-bridge"),
            Some(1),
            1,
        )
        .unwrap();
    fleet.reserve_legacy_peer(&bridge).unwrap();
    let mut soap = Endpoint::new(
        EndpointConfig::provisional(member),
        LegacyBridge::new(bridge, key_for("legacy-bridge")),
        subscription_nonce,
        1,
    )
    .unwrap();
    if let Some(identity) = identity {
        let device = identity.device_at_loopback(logical).unwrap();
        soap.configure_discovery(device).unwrap();
    }
    let initial_session = UnifiedGroupSession::new(group_id, coordinator, 1);
    let authority = AuthorityToken::issue(&initial_session, u64::MAX);
    let fresh = fleet
        .provision_fresh_group(
            group_id,
            coordinator,
            1,
            MembershipConfig::default(),
            authority.clone(),
            CLOCK_ORIGIN + 50_000_000,
        )
        .unwrap();
    let mut owner = SettledRender::admit_fresh_group(
        fresh,
        soap,
        network,
        PendingMember {
            member_id: member.into(),
            profile_id: board.profile_id.clone(),
            role: ChannelRole::Stereo,
            ceiling: 1.0,
        },
        7,
    )
    .unwrap();
    let cutover = ((CLOCK_ORIGIN + 500_000_000) * 48_000) / 1_000_000_000;
    let join = owner
        .propose_join(authority, board, cutover, CLOCK_ORIGIN + 300_000_000)
        .unwrap();
    owner.ack_local(join).unwrap();
    assert!(matches!(
        owner.commit_join(join),
        Ok(ProposalStatus::Committed { .. })
    ));
    now.set(600_000_000);
    let activated = owner.tick_membership(join).unwrap();
    assert!(activated.settled.iter().any(|(id, status)| *id == join
        && matches!(status, ProposalStatus::Activated { revision: 1, .. })));
    let mut rig = Rig {
        owner,
        now,
        probe,
        socket: UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
        address,
        sender: StreamSender::new(key, stream, 1),
        start_group_ns,
        start_local_ns,
    };
    for block in 0..2_u64 {
        let start = block * BLOCK_FRAMES;
        let pts = rig.start_group_ns + frames_to_ns(start);
        let mut payload = Vec::with_capacity(BLOCK_FRAMES as usize * 4);
        for n in 0..BLOCK_FRAMES {
            let left = (((start + n) % 101) as i16 - 50) * 220;
            payload.extend_from_slice(&left.to_be_bytes());
            payload.extend_from_slice(&(left / 2).to_be_bytes());
        }
        let wire = rig
            .sender
            .send(OutboundFrame::media(start, pts, pts - 5_333_333, payload))
            .unwrap();
        rig.socket.send_to(&wire, rig.address).unwrap();
        let report = rig.owner.poll_media().unwrap();
        assert_eq!((report.media_read, report.media_accepted), (1, 1));
    }
    rig
}

fn shim_guest_matrix() -> franken_platform::KernelCapabilityMatrix {
    franken_speaker::guest_evidence::for_abi(Abi::PowerPc32).matrix()
}

struct Evented {
    lan: Lan,
}
impl Evented {
    fn to(addr: SocketAddr) -> Self {
        assert!(addr.ip().is_loopback());
        Self {
            lan: Lan::with_timeout(Duration::from_secs(3))
                .unwrap()
                .with_routes(vec![(PLAYER, addr)]),
        }
    }
    fn subscribe(&self, callback: &str) -> Result<Subscription, ProtoError> {
        self.lan
            .subscribe(PLAYER, RENDERING_CONTROL.event_path, callback, 300)
    }
    fn renew(&self, sid: &str) -> Result<Subscription, ProtoError> {
        self.lan
            .renew(PLAYER, RENDERING_CONTROL.event_path, sid, 600)
    }
    fn unsubscribe(&self, sid: &str) -> Result<(), ProtoError> {
        self.lan
            .unsubscribe(PLAYER, RENDERING_CONTROL.event_path, sid)
    }
}
impl Transport for Evented {
    fn soap_post(
        &self,
        host: IpAddr,
        path: &str,
        action: &str,
        body: &str,
    ) -> Result<String, ProtoError> {
        if host != PLAYER {
            return Err(ProtoError::Network {
                target: host.to_string(),
                detail: "not the loopback fixture".into(),
            });
        }
        self.lan.soap_post(host, path, action, body)
    }
}

fn call_owner<R: Send + 'static>(
    rig: &mut Rig,
    mailbox: &mut HttpMailboxOwner,
    addr: SocketAddr,
    f: impl FnOnce(&Evented) -> R + Send + 'static,
) -> R {
    let client = thread::spawn(move || {
        let c = Evented::to(addr);
        f(&c)
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut served = false;
    while Instant::now() < deadline {
        match rig.owner.service_http(mailbox).unwrap() {
            HttpService::Idle => {
                if client.is_finished() {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
            HttpService::Replied => {
                served = true;
                break;
            }
            other => panic!("owner did not serve client request: {other:?}"),
        }
    }
    assert!(
        served,
        "the actual protected owner must service the request"
    );
    client.join().expect("actual client worker")
}
fn next(sink: &EventSink) -> Notify {
    sink.recv_timeout(Duration::from_secs(5))
        .expect("actual client received NOTIFY")
}

/// Render three protected blocks, retain the last actual program token, then
/// request stop and wait for the fake backend's own flush ACK.
fn three_blocks_and_stop(mut rig: Rig) -> Vec<Vec<u8>> {
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    for step in 0..5000_u64 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        assert!(matches!(
            rig.owner.render_step(&mut timing).unwrap(),
            PlaybackStep::Render(_)
        ));
        if rig.probe.captured_submissions().len() >= 4 {
            break;
        }
    }
    let captures = rig.probe.captured_submissions();
    assert!(
        captures.len() >= 4,
        "three actual program submissions after silent prime"
    );
    let pcm = captures[1..4].to_vec();
    assert!(pcm.iter().flatten().any(|b| *b != 0));
    let token = rig
        .probe
        .calls()
        .iter()
        .rev()
        .find_map(|call| match call {
            franken_hal::backend::FakeCall::SubmitRetained {
                slot, generation, ..
            } => Some((*slot, *generation)),
            _ => None,
        })
        .expect("actual submitted program token");
    assert!(rig.probe.pending_slots().contains(&token));
    rig.probe.set_lose_completions(true);
    let pulled = rig.owner.received_frames_pulled();
    let captures_before_stop = rig.probe.captured_submissions();
    let flushes_before = rig
        .probe
        .calls()
        .iter()
        .filter(|call| matches!(call, franken_hal::backend::FakeCall::RequestFlush))
        .count();
    assert!(matches!(
        rig.owner.request_stop(),
        Ok(franken_speaker::settled_render::RenderApplication::Stopping)
    ));
    assert!(rig.probe.pending_slots().contains(&token));
    assert_eq!(rig.probe.kernel_touch_pending().1, 0);
    assert_eq!(
        rig.probe
            .calls()
            .iter()
            .filter(|call| matches!(call, franken_hal::backend::FakeCall::RequestFlush))
            .count(),
        flushes_before + 1
    );
    let mut ack = false;
    for _ in 0..20 {
        match rig.owner.drain_tick(&mut timing).unwrap() {
            DrainProgress::Tick { report, .. } => assert!(report.started.is_none()),
            DrainProgress::Finished(report) => {
                ack = report.acknowledged;
                break;
            }
            DrainProgress::NotStartedUnacknowledged => panic!("missing actual drain"),
        }
    }
    assert!(ack, "model HAL must actually acknowledge its flush");
    assert!(!rig.probe.pending_slots().contains(&token));
    assert_eq!(rig.probe.pending(), 0);
    assert_eq!(rig.owner.received_frames_pulled(), pulled);
    assert_eq!(rig.probe.captured_submissions(), captures_before_stop);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    pcm
}

#[test]
fn real_fsonos_eventing_changes_same_owner_protected_pcm_and_stops_with_ack() {
    let baseline = three_blocks_and_stop(rig());
    let mut rig = rig();
    let sink = EventSink::start(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let callback = sink.callback_url(TAG);
    let target = CallbackTarget::new(sink.local_addr(), &format!("/{TAG}")).unwrap();
    let (client, mut mailbox) =
        http_mailbox(HttpMailboxConfig::new(16 * 1024, 32, Duration::from_millis(800)).unwrap())
            .unwrap();
    let raw = client.clone();
    let server = FsonosLoopback::start_eventing_with_control(
        shim::fixture_session_for(MEMBER, "neighbor").unwrap(),
        MEMBER,
        Policy::LocalLink,
        LoopbackLimits::standard(),
        target,
        CallbackLimits::standard(),
        move |_, _, _| Ok(mailbox_eventing_control(client)),
    )
    .unwrap();
    let addr = server.addr();
    assert!(addr.ip().is_loopback());

    // An opted-in owner event worker admits exactly one transport: a cloned
    // raw mailbox client must not bypass the event ordering/delivery path.
    let bypass = franken_control::fsonos::HttpRequest {
        method: "SUBSCRIBE",
        path: RENDERING_CONTROL.event_path,
        peer_ip: PLAYER,
        ingress: franken_control::fsonos::Ingress::LocalLegacy,
        headers: &[],
        body: &[],
    };
    assert!(matches!(
        raw.submit(&bypass),
        Err(franken_speaker::settled_http::HttpMailboxError::Busy)
    ));
    assert_eq!(rig.owner.received_frames_pulled(), 0);

    // The core/shim's allowed callback is paired with a refused different path.
    let wrong_callback = format!("http://{}/wrong", sink.local_addr());
    let wrong = Evented::to(addr)
        .subscribe(&wrong_callback)
        .expect_err("wrong callback rejected");
    assert!(
        matches!(wrong, ProtoError::Network { ref detail, .. } if detail == "SUBSCRIBE: HTTP 412")
    );
    let callback_for_request = callback.clone();
    let sub = call_owner(&mut rig, &mut mailbox, addr, move |c| {
        c.subscribe(&callback_for_request)
    })
    .unwrap();
    assert!(sub.sid.starts_with("uuid:"));
    let initial = next(&sink);
    assert_eq!(initial.sid, sub.sid);
    assert_eq!(initial.seq, 0);
    assert_eq!(initial.path, format!("/{TAG}"));
    let initial_change = initial.last_change().unwrap().unwrap();
    assert_eq!(initial_change.volume(), Some(50));
    let before_revision = server.with_session(|s| s.state_revision);
    assert_eq!(before_revision, 1);

    call_owner(&mut rig, &mut mailbox, addr, |c| set_volume(c, PLAYER, 90)).unwrap();
    let changed = next(&sink);
    assert_eq!(changed.sid, sub.sid);
    assert_eq!(changed.seq, 1);
    assert_eq!(changed.last_change().unwrap().unwrap().volume(), Some(90));
    assert_eq!(
        server.with_session(|s| (s.state_revision, s.members[MEMBER].volume_0_to_100)),
        (2, 90)
    );
    let sid = sub.sid.clone();
    let renewed = call_owner(&mut rig, &mut mailbox, addr, move |c| c.renew(&sid)).unwrap();
    assert_eq!(renewed.sid, sub.sid);
    assert_eq!(renewed.timeout_secs, 600);
    assert!(sink.recv_timeout(Duration::from_millis(300)).is_none());
    let sid = sub.sid.clone();
    call_owner(&mut rig, &mut mailbox, addr, move |c| c.unsubscribe(&sid)).unwrap();
    call_owner(&mut rig, &mut mailbox, addr, |c| set_volume(c, PLAYER, 80)).unwrap();
    assert!(sink.recv_timeout(Duration::from_millis(300)).is_none());
    assert_eq!(
        server.with_session(|s| (s.state_revision, s.members[MEMBER].volume_0_to_100)),
        (3, 80)
    );
    let deadline = Instant::now() + Duration::from_secs(8);
    let report = loop {
        let report = server.callback_report().unwrap();
        if report.offered >= 2 && report.reconciled() {
            break report;
        }
        assert!(
            Instant::now() < deadline,
            "callback delivery never settled: {report:?}"
        );
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(report.subscribes_refused, 1);
    assert_eq!((report.offered, report.delivered), (2, 2));
    assert_eq!(
        report.refused + report.dropped + report.failed + report.unframed,
        0
    );
    assert!(server.stop().reconciled());

    // Dropping the event worker must keep all raw senders fenced until the
    // real owner has cleared its subscriptions. This test unsubscribed above,
    // so the actual owner's cleanup count is zero, not a synthetic clear.
    assert!(matches!(
        raw.submit(&bypass),
        Err(franken_speaker::settled_http::HttpMailboxError::Busy)
    ));
    assert_eq!(rig.owner.release_http_eventing(&mut mailbox).unwrap(), 0);
    let pending = raw
        .submit(&bypass)
        .expect("raw mailbox reopens after owner cleanup");
    assert!(matches!(
        rig.owner.service_http(&mut mailbox),
        Ok(HttpService::Replied)
    ));
    let reply = pending.wait().unwrap();
    let handled = reply.result.unwrap();
    assert_eq!(handled.control.response.status, 412);
    assert!(handled.control.notifications.is_empty());
    assert!(handled.notifications.is_empty());
    assert_eq!(reply.session.state_revision, 3);

    let controlled = three_blocks_and_stop(rig);
    assert_ne!(
        controlled, baseline,
        "same owner's committed control must change protected PCM"
    );
}

/// A real client confined to the responder and HTTP listener of this owner.
/// It cannot multicast or issue HTTP to a different host.
struct OwnedDiscoveryClient {
    lan: Lan,
    allowed: Vec<IpAddr>,
}

impl OwnedDiscoveryClient {
    fn at(http: SocketAddr, search: SocketAddr) -> Self {
        assert!(http.ip() == PLAYER && http.port() != 0);
        assert!(search.ip() == PLAYER && search.port() != 0);
        let lan = Lan::with_timeout(Duration::from_secs(3))
            .unwrap()
            .with_routes(vec![(PLAYER, http)])
            .with_ssdp_target(search);
        Self {
            lan,
            allowed: vec![PLAYER],
        }
    }

    fn two(
        logical: [IpAddr; 2],
        http: [SocketAddr; 2],
        search: SocketAddr,
    ) -> Result<Self, ProtoError> {
        let a = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let b = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3));
        let local = |addr: SocketAddr| addr.ip() == PLAYER && addr.port() != 0;
        if logical != [a, b]
            || !local(http[0])
            || !local(http[1])
            || http[0] == http[1]
            || !local(search)
        {
            return Err(Self::refused("invalid confined routes"));
        }
        let lan = Lan::with_timeout(Duration::from_secs(3))?
            .with_routes(vec![(a, http[0]), (b, http[1])])
            .with_ssdp_target(search);
        Ok(Self {
            lan,
            allowed: vec![a, b],
        })
    }

    fn refused(target: &str) -> ProtoError {
        ProtoError::Network {
            target: target.into(),
            detail: "not the loopback fixture".into(),
        }
    }

    fn subscribe_for(&self, host: IpAddr, callback: &str) -> Result<Subscription, ProtoError> {
        if !self.allowed.contains(&host) {
            return Err(Self::refused(&host.to_string()));
        }
        self.lan
            .subscribe(host, RENDERING_CONTROL.event_path, callback, 300)
    }

    fn renew_for(&self, host: IpAddr, sid: &str) -> Result<Subscription, ProtoError> {
        if !self.allowed.contains(&host) {
            return Err(Self::refused(&host.to_string()));
        }
        self.lan.renew(host, RENDERING_CONTROL.event_path, sid, 600)
    }

    fn subscribe(&self, callback: &str) -> Result<Subscription, ProtoError> {
        self.subscribe_for(PLAYER, callback)
    }

    fn renew(&self, sid: &str) -> Result<Subscription, ProtoError> {
        self.renew_for(PLAYER, sid)
    }
}

impl Transport for OwnedDiscoveryClient {
    fn soap_post(
        &self,
        host: IpAddr,
        path: &str,
        action: &str,
        body: &str,
    ) -> Result<String, ProtoError> {
        if !self.allowed.contains(&host)
            || (path != RENDERING_CONTROL.control_path
                && path != fsonos_proto::soap::ZONE_GROUP_TOPOLOGY.control_path)
        {
            return Err(Self::refused(&host.to_string()));
        }
        self.lan.soap_post(host, path, action, body)
    }

    fn http_get(&self, url: &str) -> Result<String, ProtoError> {
        if !self
            .allowed
            .iter()
            .any(|host| url == fsonos_proto::ssdp::description_url(*host))
        {
            return Err(Self::refused(url));
        }
        self.lan.http_get(url)
    }

    fn ssdp_search(
        &self,
        mx_secs: u8,
        wait: Duration,
    ) -> Result<Vec<fsonos_proto::ssdp::Advert>, ProtoError> {
        self.lan.ssdp_search(mx_secs, wait)
    }
}

/// Run a single actual-client HTTP request while the protected owner services its mailbox.
fn call_discovered<R: Send + 'static>(
    rig: &mut Rig,
    mailbox: &mut HttpMailboxOwner,
    server: &FsonosLoopback,
    f: impl FnOnce(&OwnedDiscoveryClient) -> R + Send + 'static,
) -> R {
    let http = server.addr();
    let search = server.discovery_addr().unwrap();
    let worker = thread::spawn(move || f(&OwnedDiscoveryClient::at(http, search)));
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut served = false;
    while Instant::now() < deadline {
        match rig.owner.service_http(mailbox).unwrap() {
            HttpService::Idle if worker.is_finished() => break,
            HttpService::Idle => thread::sleep(Duration::from_millis(1)),
            HttpService::Replied => {
                served = true;
                break;
            }
            other => panic!("owner did not serve discovered client: {other:?}"),
        }
    }
    assert!(
        served,
        "the actual owner must service the discovered client"
    );
    worker.join().expect("actual client worker")
}

/// Startup performs owner preflight over this mailbox; starting on the owner
/// thread would deadlock the very service needed to establish readiness.
fn try_start_owned_discovery(
    rig: &mut Rig,
    mailbox: &mut HttpMailboxOwner,
    client: franken_speaker::settled_http::HttpMailboxClient,
    session: UnifiedGroupSession,
    identity: shim::DiscoveryIdentity,
    target: CallbackTarget,
) -> Result<FsonosLoopback, String> {
    let worker = thread::spawn(move || {
        FsonosLoopback::start_discoverable_eventing_with_mailbox(
            session,
            &identity,
            Policy::LocalLink,
            LoopbackLimits::standard(),
            shim::DiscoveryLimits::standard(),
            (target, CallbackLimits::standard()),
            client,
        )
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut served = 0;
    while !worker.is_finished() && Instant::now() < deadline {
        match rig.owner.service_http(mailbox).unwrap() {
            HttpService::Idle => thread::sleep(Duration::from_millis(1)),
            HttpService::Replied => served += 1,
            other => panic!("owner startup preflight failed: {other:?}"),
        }
    }
    assert!(worker.is_finished(), "owner-backed startup did not finish");
    assert!(served > 0, "startup must preflight the actual owner");
    worker.join().unwrap()
}

fn start_owned_discovery(
    rig: &mut Rig,
    mailbox: &mut HttpMailboxOwner,
    client: franken_speaker::settled_http::HttpMailboxClient,
    session: UnifiedGroupSession,
    identity: shim::DiscoveryIdentity,
    target: CallbackTarget,
) -> FsonosLoopback {
    try_start_owned_discovery(rig, mailbox, client, session, identity, target)
        .expect("owner-backed discovery starts")
}

fn discover_owner(
    rig: &mut Rig,
    mailbox: &mut HttpMailboxOwner,
    server: &FsonosLoopback,
    identity: &shim::DiscoveryIdentity,
) {
    let client = OwnedDiscoveryClient::at(server.addr(), server.discovery_addr().unwrap());
    let adverts = client.ssdp_search(1, Duration::from_millis(700)).unwrap();
    assert_eq!(adverts.len(), 1);
    let advert = &adverts[0];
    assert_eq!(advert.st, fsonos_proto::ssdp::SONOS_ST);
    assert_eq!(advert.location, fsonos_proto::ssdp::description_url(PLAYER));
    assert_eq!(
        advert.usn.as_deref(),
        Some(format!("uuid:{}::{}", identity.uuid, fsonos_proto::ssdp::SONOS_ST).as_str())
    );
    let location = advert.location.clone();
    let document = call_discovered(rig, mailbox, server, move |client| {
        client.http_get(&location)
    })
    .unwrap();
    let described = fsonos_proto::description::parse_device_description(&document).unwrap();
    assert_eq!(described.udn.0, identity.uuid);
    assert_eq!(described.room_name, identity.room);
    assert!(described.has_service(RENDERING_CONTROL.service_type));
    let zones = call_discovered(rig, mailbox, server, |client| {
        fsonos_proto::topology::get_zone_group_state(client, PLAYER)
    })
    .unwrap();
    assert_eq!(zones.groups.len(), 1);
    let group = &zones.groups[0];
    assert_eq!(group.id, "grp:1");
    assert_eq!(group.coordinator.0, identity.uuid);
    assert_eq!(group.members.len(), 1);
    assert_eq!(
        group
            .members
            .iter()
            .filter(|member| member.uuid == group.coordinator)
            .count(),
        1,
        "the parsed group's coordinator must occur exactly once among its members"
    );
    let member = &group.members[0];
    assert_eq!(member.uuid.0, identity.uuid);
    assert_eq!(member.location, advert.location);
    assert_eq!(member.zone_name, identity.room);
    assert_eq!(member.ip(), Some(PLAYER));
}

#[test]
fn actual_client_discovers_same_protected_owner_across_restart_and_new_subscription() {
    let identity = shim::DiscoveryIdentity::fixture();
    let baseline = three_blocks_and_stop(rig_with_identity(Some(&identity)));
    let mut rig = rig_with_identity(Some(&identity));
    let sink = EventSink::start(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let target = || CallbackTarget::new(sink.local_addr(), &format!("/{TAG}")).unwrap();
    let (client, mut mailbox) =
        http_mailbox(HttpMailboxConfig::new(16 * 1024, 32, Duration::from_millis(800)).unwrap())
            .unwrap();

    // Seed the transport with a snapshot returned by this exact owner, not a
    // second fixture session. The actual description is read on this owner.
    let get = franken_control::fsonos::HttpRequest {
        method: "GET",
        path: franken_control::fsonos::ssdp::DESCRIPTION_PATH,
        peer_ip: PLAYER,
        ingress: franken_control::fsonos::Ingress::LocalLegacy,
        headers: &[],
        body: &[],
    };
    let pending = client.submit(&get).unwrap();
    assert!(matches!(
        rig.owner.service_http(&mut mailbox),
        Ok(HttpService::Replied)
    ));
    let actual = pending.wait().unwrap();
    assert_eq!(actual.result.unwrap().control.response.status, 200);
    let server = start_owned_discovery(
        &mut rig,
        &mut mailbox,
        client.clone(),
        actual.session,
        identity.clone(),
        target(),
    );
    discover_owner(&mut rig, &mut mailbox, &server, &identity);
    let callback = sink.callback_url(TAG);
    let callback_first = callback.clone();
    let first = call_discovered(&mut rig, &mut mailbox, &server, move |c| {
        c.subscribe(&callback_first)
    })
    .unwrap();
    let initial = next(&sink);
    assert_eq!((initial.sid.as_str(), initial.seq), (first.sid.as_str(), 0));
    assert_eq!(initial.last_change().unwrap().unwrap().volume(), Some(50));
    assert_eq!(server.with_session(|s| s.state_revision), 1);
    call_discovered(&mut rig, &mut mailbox, &server, |c| {
        set_volume(c, PLAYER, 90)
    })
    .unwrap();
    let changed = next(&sink);
    assert_eq!((changed.sid.as_str(), changed.seq), (first.sid.as_str(), 1));
    assert_eq!(changed.last_change().unwrap().unwrap().volume(), Some(90));
    assert_eq!(
        server.with_session(|s| (s.state_revision, s.members[&identity.uuid].volume_0_to_100)),
        (2, 90)
    );
    let session = server.with_session(Clone::clone);
    assert!(server.stop().reconciled());
    assert_eq!(rig.owner.release_http_eventing(&mut mailbox).unwrap(), 1);
    assert!(sink.recv_timeout(Duration::from_millis(300)).is_none());

    let server = start_owned_discovery(
        &mut rig,
        &mut mailbox,
        client,
        session,
        identity.clone(),
        target(),
    );
    discover_owner(&mut rig, &mut mailbox, &server, &identity);
    let old_sid = first.sid.clone();
    let old =
        call_discovered(&mut rig, &mut mailbox, &server, move |c| c.renew(&old_sid)).unwrap_err();
    assert!(
        matches!(old, ProtoError::Network { ref detail, .. } if detail == "SUBSCRIBE: HTTP 412")
    );
    assert!(sink.recv_timeout(Duration::from_millis(300)).is_none());
    let second = call_discovered(&mut rig, &mut mailbox, &server, move |c| {
        c.subscribe(&callback)
    })
    .unwrap();
    assert_ne!(first.sid, second.sid);
    let initial = next(&sink);
    assert_eq!(
        (initial.sid.as_str(), initial.seq),
        (second.sid.as_str(), 0)
    );
    assert_eq!(initial.last_change().unwrap().unwrap().volume(), Some(90));
    call_discovered(&mut rig, &mut mailbox, &server, |c| {
        set_volume(c, PLAYER, 80)
    })
    .unwrap();
    let changed = next(&sink);
    assert_eq!(
        (changed.sid.as_str(), changed.seq),
        (second.sid.as_str(), 1)
    );
    assert_eq!(changed.last_change().unwrap().unwrap().volume(), Some(80));
    assert_eq!(
        server.with_session(|s| (s.state_revision, s.members[&identity.uuid].volume_0_to_100)),
        (3, 80)
    );
    assert!(server.stop().reconciled());
    assert_eq!(rig.owner.release_http_eventing(&mut mailbox).unwrap(), 1);
    assert!(sink.recv_timeout(Duration::from_millis(300)).is_none());
    let controlled = three_blocks_and_stop(rig);
    assert_ne!(
        controlled, baseline,
        "same discovered owner's control changes nonzero protected PCM"
    );
}

#[test]
fn failed_owner_discovery_preflight_fences_until_real_owner_cleanup_then_succeeds() {
    let identity = shim::DiscoveryIdentity::fixture();
    let mut rig = rig_with_identity(Some(&identity));
    let sink = EventSink::start(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let callback = sink.callback_url(TAG);
    let target = || CallbackTarget::new(sink.local_addr(), &format!("/{TAG}")).unwrap();
    let (client, mut mailbox) =
        http_mailbox(HttpMailboxConfig::new(16 * 1024, 32, Duration::from_millis(800)).unwrap())
            .unwrap();

    // The actual endpoint has one live SID before the new worker attaches.
    // This raw path returns the initial notification to this caller; it has no
    // callback outbox, so do not present that vector as delivered.
    let callback_header = format!("<{callback}>");
    let headers = [
        ("CALLBACK", callback_header.as_str()),
        ("NT", "upnp:event"),
        ("TIMEOUT", "Second-300"),
    ];
    let subscribe = franken_control::fsonos::HttpRequest {
        method: "SUBSCRIBE",
        path: RENDERING_CONTROL.event_path,
        peer_ip: PLAYER,
        ingress: franken_control::fsonos::Ingress::LocalLegacy,
        headers: &headers,
        body: &[],
    };
    let pending = client.submit(&subscribe).unwrap();
    assert!(matches!(
        rig.owner.service_http(&mut mailbox),
        Ok(HttpService::Replied)
    ));
    let reply = pending.wait().unwrap();
    let handled = reply.result.unwrap().control;
    assert_eq!(handled.response.status, 200);
    let old_sid = handled
        .response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("SID"))
        .map(|(_, value)| value.clone())
        .expect("actual owner-issued SID");
    assert_eq!(handled.notifications.len(), 1);
    assert_eq!(handled.notifications[0].sid, old_sid);
    assert_eq!(handled.notifications[0].seq, 0);
    assert!(sink.recv_timeout(Duration::from_millis(300)).is_none());
    let owner_session = reply.session;

    // Same actual member, but transport room differs from the owner's real
    // configured device. The attached worker must fail its real GET preflight.
    let mut mismatch = identity.clone();
    mismatch.room = "Other room".into();
    let failure = match try_start_owned_discovery(
        &mut rig,
        &mut mailbox,
        client.clone(),
        owner_session,
        mismatch,
        target(),
    ) {
        Ok(_) => panic!("mismatched actual owner must not advertise"),
        Err(reason) => reason,
    };
    assert_eq!(failure, "owner discovery identity mismatch");
    let get = franken_control::fsonos::HttpRequest {
        method: "GET",
        path: franken_control::fsonos::ssdp::DESCRIPTION_PATH,
        peer_ip: PLAYER,
        ingress: franken_control::fsonos::Ingress::LocalLegacy,
        headers: &[],
        body: &[],
    };
    assert!(matches!(
        client.submit(&get),
        Err(franken_speaker::settled_http::HttpMailboxError::Busy)
    ));
    assert!(sink.recv_timeout(Duration::from_millis(300)).is_none());

    // The actual owner performs invalidation only after the delivery terminal
    // fence has settled; this does not assume the fence was still pending at
    // the instant startup returned an error.
    let deadline = Instant::now() + Duration::from_secs(3);
    let invalidated = loop {
        match rig.owner.release_http_eventing(&mut mailbox) {
            Ok(count) => break count,
            Err(franken_speaker::settled_http::HttpMailboxError::Busy) => {
                assert!(
                    Instant::now() < deadline,
                    "actual callback terminal did not settle"
                );
                thread::sleep(Duration::from_millis(1));
            }
            other => panic!("actual owner cleanup failed: {other:?}"),
        }
    };
    assert_eq!(invalidated, 1, "the actual owner's live SID is invalidated");
    let pending = client
        .submit(&get)
        .expect("owner cleanup reopens the mailbox");
    assert!(matches!(
        rig.owner.service_http(&mut mailbox),
        Ok(HttpService::Replied)
    ));
    let reply = pending.wait().unwrap();
    assert_eq!(reply.result.unwrap().control.response.status, 200);
    let server = start_owned_discovery(
        &mut rig,
        &mut mailbox,
        client,
        reply.session,
        identity.clone(),
        target(),
    );
    discover_owner(&mut rig, &mut mailbox, &server, &identity);
    let refused_sid = old_sid.clone();
    let refused = call_discovered(&mut rig, &mut mailbox, &server, move |c| {
        c.renew(&refused_sid)
    })
    .unwrap_err();
    assert!(
        matches!(refused, ProtoError::Network { ref detail, .. } if detail == "SUBSCRIBE: HTTP 412")
    );
    let sub = call_discovered(&mut rig, &mut mailbox, &server, move |c| {
        c.subscribe(&callback)
    })
    .unwrap();
    assert_ne!(sub.sid, old_sid);
    let delivered = next(&sink);
    assert_eq!(
        (delivered.sid.as_str(), delivered.seq),
        (sub.sid.as_str(), 0)
    );
    assert_eq!(delivered.last_change().unwrap().unwrap().volume(), Some(50));
    assert!(server.stop().reconciled());
    assert_eq!(rig.owner.release_http_eventing(&mut mailbox).unwrap(), 1);
    assert!(sink.recv_timeout(Duration::from_millis(300)).is_none());
    let pcm = three_blocks_and_stop(rig);
    assert!(pcm.iter().flatten().any(|byte| *byte != 0));
}

fn owner_snapshot(
    rig: &mut Rig,
    mailbox: &mut HttpMailboxOwner,
    client: &franken_speaker::settled_http::HttpMailboxClient,
) -> UnifiedGroupSession {
    let get = franken_control::fsonos::HttpRequest {
        method: "GET",
        path: franken_control::fsonos::ssdp::DESCRIPTION_PATH,
        peer_ip: PLAYER,
        ingress: franken_control::fsonos::Ingress::LocalLegacy,
        headers: &[],
        body: &[],
    };
    let pending = client.submit(&get).unwrap();
    assert!(matches!(
        rig.owner.service_http(mailbox),
        Ok(HttpService::Replied)
    ));
    let reply = pending.wait().unwrap();
    assert_eq!(reply.result.unwrap().control.response.status, 200);
    reply.session
}

fn start_owner_at(
    rig: &mut Rig,
    mailbox: &mut HttpMailboxOwner,
    client: franken_speaker::settled_http::HttpMailboxClient,
    session: UnifiedGroupSession,
    identity: shim::DiscoveryIdentity,
    logical: Ipv4Addr,
    target: CallbackTarget,
) -> Result<FsonosLoopback, String> {
    let worker = thread::spawn(move || {
        FsonosLoopback::start_discoverable_eventing_at_mailbox(
            session,
            (&identity, logical),
            Policy::LocalLink,
            LoopbackLimits::standard(),
            shim::DiscoveryLimits::standard(),
            (target, CallbackLimits::standard()),
            client,
        )
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut served = 0;
    while !worker.is_finished() && Instant::now() < deadline {
        match rig.owner.service_http(mailbox).unwrap() {
            HttpService::Idle => thread::sleep(Duration::from_millis(1)),
            HttpService::Replied => served += 1,
            other => panic!("actual owner preflight failed: {other:?}"),
        }
    }
    assert!(worker.is_finished(), "owner startup did not finish");
    assert!(served > 0, "preflight must reach the actual owner");
    worker.join().unwrap()
}

fn two_owner_call<R: Send + 'static>(
    rigs: (&mut Rig, &mut Rig),
    mailboxes: (&mut HttpMailboxOwner, &mut HttpMailboxOwner),
    http: [SocketAddr; 2],
    search: SocketAddr,
    expect_service: [bool; 2],
    f: impl FnOnce(&OwnedDiscoveryClient) -> R + Send + 'static,
) -> R {
    let logical = [
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
    ];
    let worker = thread::spawn(move || {
        let client = OwnedDiscoveryClient::two(logical, http, search).unwrap();
        f(&client)
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut seen = [false; 2];
    while !worker.is_finished() && Instant::now() < deadline {
        for (index, result) in [
            rigs.0.owner.service_http(mailboxes.0),
            rigs.1.owner.service_http(mailboxes.1),
        ]
        .into_iter()
        .enumerate()
        {
            match result.unwrap() {
                HttpService::Idle => {}
                HttpService::Replied => seen[index] = true,
                other => panic!("owner {index} could not serve client: {other:?}"),
            }
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert!(worker.is_finished(), "actual client did not finish");
    let result = worker.join().expect("actual client worker");
    assert_eq!(seen, expect_service, "owner service mask mismatch");
    result
}

#[test]
fn two_owner_client_rejects_unconfined_routes_and_requests_before_delegation() {
    let a = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    let b = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3));
    let first = SocketAddr::from((Ipv4Addr::LOCALHOST, 9101));
    let second = SocketAddr::from((Ipv4Addr::LOCALHOST, 9102));
    let search = SocketAddr::from((Ipv4Addr::LOCALHOST, 9103));
    assert!(OwnedDiscoveryClient::two([a, a], [first, second], search).is_err());
    assert!(OwnedDiscoveryClient::two([a, b], [first, first], search).is_err());
    assert!(
        OwnedDiscoveryClient::two(
            [a, b],
            [first, SocketAddr::from(([192, 0, 2, 1], 9102))],
            search
        )
        .is_err()
    );
    assert!(
        OwnedDiscoveryClient::two(
            [a, b],
            [first, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))],
            search
        )
        .is_err()
    );
    assert!(
        OwnedDiscoveryClient::two(
            [a, b],
            [first, second],
            SocketAddr::from(([192, 0, 2, 1], 9103))
        )
        .is_err()
    );
    let client = OwnedDiscoveryClient::two([a, b], [first, second], search).unwrap();
    let blocked = |error| matches!(error, ProtoError::Network { ref detail, .. } if detail == "not the loopback fixture");
    assert!(blocked(
        client
            .soap_post(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)), "/", "x", "")
            .unwrap_err()
    ));
    assert!(blocked(
        client
            .subscribe_for(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), "http://127.0.0.1/")
            .unwrap_err()
    ));
    assert!(blocked(
        client.soap_post(a, "@192.0.2.1/", "x", "").unwrap_err()
    ));
    assert!(blocked(client.subscribe("http://127.0.0.1/").unwrap_err()));
    for url in [
        "http://127.0.0.2:1401/xml/device_description.xml",
        "http://127.0.0.4:1400/xml/device_description.xml",
        "http://192.0.2.1:1400/xml/device_description.xml",
        "http://127.0.0.2:1400/other",
    ] {
        assert!(blocked(client.http_get(url).unwrap_err()));
    }
}

#[test]
fn two_real_standalone_owners_are_discovered_controlled_and_rendered_independently() {
    let ip_a = Ipv4Addr::new(127, 0, 0, 2);
    let ip_b = Ipv4Addr::new(127, 0, 0, 3);
    let hosts = [IpAddr::V4(ip_a), IpAddr::V4(ip_b)];
    let identity_a = shim::DiscoveryIdentity::fixture();
    let identity_b = shim::DiscoveryIdentity {
        uuid: shim::FIXTURE_OTHER_UUID.into(),
        room: "Office".into(),
    };
    assert_ne!(identity_a.uuid, identity_b.uuid);
    let baseline_a = three_blocks_and_stop(rig_with_identity_at(Some(&identity_a), ip_a));
    let baseline_b = three_blocks_and_stop(rig_with_identity_at(Some(&identity_b), ip_b));
    let mut a = rig_with_identity_at(Some(&identity_a), ip_a);
    let mut b = rig_with_identity_at(Some(&identity_b), ip_b);
    let sink_a = EventSink::start(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let sink_b = EventSink::start(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let make_target_a = || CallbackTarget::new(sink_a.local_addr(), &format!("/{TAG}")).unwrap();
    let make_target_b = || CallbackTarget::new(sink_b.local_addr(), &format!("/{TAG}")).unwrap();
    let config = HttpMailboxConfig::new(16 * 1024, 32, Duration::from_millis(800)).unwrap();
    let (client_a, mut mailbox_a) = http_mailbox(config).unwrap();
    let (client_b, mut mailbox_b) = http_mailbox(config).unwrap();
    let session_a = owner_snapshot(&mut a, &mut mailbox_a, &client_a);
    let session_b = owner_snapshot(&mut b, &mut mailbox_b, &client_b);
    assert!(matches!(
        a.owner.service_http(&mut mailbox_b),
        Err(franken_speaker::settled_http::HttpMailboxError::Unavailable)
    ));
    assert!(matches!(
        b.owner.service_http(&mut mailbox_a),
        Err(franken_speaker::settled_http::HttpMailboxError::Unavailable)
    ));

    // Same UUID/name but wrong advertised location must fail the owner's real
    // preflight, leave the attachment fenced, then clean up only owner A.
    let failure = match start_owner_at(
        &mut a,
        &mut mailbox_a,
        client_a.clone(),
        session_a.clone(),
        identity_a.clone(),
        ip_b,
        make_target_a(),
    ) {
        Ok(_) => panic!("wrong logical location was advertised"),
        Err(reason) => reason,
    };
    assert_eq!(failure, "owner discovery identity mismatch");
    let get = franken_control::fsonos::HttpRequest {
        method: "GET",
        path: franken_control::fsonos::ssdp::DESCRIPTION_PATH,
        peer_ip: PLAYER,
        ingress: franken_control::fsonos::Ingress::LocalLegacy,
        headers: &[],
        body: &[],
    };
    assert!(matches!(
        client_a.submit(&get),
        Err(franken_speaker::settled_http::HttpMailboxError::Busy)
    ));
    assert_eq!(a.owner.release_http_eventing(&mut mailbox_a).unwrap(), 0);
    let server_a = start_owner_at(
        &mut a,
        &mut mailbox_a,
        client_a.clone(),
        session_a,
        identity_a.clone(),
        ip_a,
        make_target_a(),
    )
    .unwrap();
    let server_b = start_owner_at(
        &mut b,
        &mut mailbox_b,
        client_b.clone(),
        session_b,
        identity_b.clone(),
        ip_b,
        make_target_b(),
    )
    .unwrap();
    // A second adapter cannot reuse the already attached owner-A client.
    // It must fail without asking either owner to service a new request.
    let duplicate_session = server_a.with_session(Clone::clone);
    let duplicate_identity = identity_a.clone();
    let duplicate_client = client_a.clone();
    let duplicate_target = make_target_a();
    let duplicate = thread::spawn(move || {
        FsonosLoopback::start_discoverable_eventing_at_mailbox(
            duplicate_session,
            (&duplicate_identity, ip_a),
            Policy::LocalLink,
            LoopbackLimits::standard(),
            shim::DiscoveryLimits::standard(),
            (duplicate_target, CallbackLimits::standard()),
            duplicate_client,
        )
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    while !duplicate.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(1));
    }
    assert!(duplicate.is_finished(), "second attachment did not settle");
    match duplicate.join().unwrap() {
        Ok(_) => panic!("second adapter reused an attached owner mailbox"),
        Err(reason) => assert_eq!(reason, "owner eventing attachment is unavailable"),
    }
    let http = [server_a.addr(), server_b.addr()];
    let search_a = server_a.discovery_addr().unwrap();
    let search_b = server_b.discovery_addr().unwrap();
    assert_ne!(http[0], http[1]);
    assert_ne!(search_a, search_b);
    for (search, id, host) in [
        (search_a, &identity_a, hosts[0]),
        (search_b, &identity_b, hosts[1]),
    ] {
        let client = OwnedDiscoveryClient::two(hosts, http, search).unwrap();
        let found = client.ssdp_search(1, Duration::from_millis(700)).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].location, fsonos_proto::ssdp::description_url(host));
        assert_eq!(
            found[0].usn.as_deref(),
            Some(format!("uuid:{}::{}", id.uuid, fsonos_proto::ssdp::SONOS_ST).as_str())
        );
    }
    let (doc_a, doc_b, zones_a, zones_b) = two_owner_call(
        (&mut a, &mut b),
        (&mut mailbox_a, &mut mailbox_b),
        http,
        search_a,
        [true, true],
        move |client| {
            Ok::<_, ProtoError>((
                client.http_get(&fsonos_proto::ssdp::description_url(hosts[0]))?,
                client.http_get(&fsonos_proto::ssdp::description_url(hosts[1]))?,
                fsonos_proto::topology::get_zone_group_state(client, hosts[0])?,
                fsonos_proto::topology::get_zone_group_state(client, hosts[1])?,
            ))
        },
    )
    .unwrap();
    for (doc, zones, identity, host, group) in [
        (&doc_a, &zones_a, &identity_a, hosts[0], "owner-a:1"),
        (&doc_b, &zones_b, &identity_b, hosts[1], "owner-b:1"),
    ] {
        let parsed = fsonos_proto::description::parse_device_description(doc).unwrap();
        assert_eq!(parsed.udn.0, identity.uuid);
        assert_eq!(parsed.room_name, identity.room);
        assert!(parsed.has_service(RENDERING_CONTROL.service_type));
        assert_eq!(zones.groups.len(), 1);
        let actual = &zones.groups[0];
        assert_eq!(actual.id, group);
        assert_eq!(actual.coordinator.0, identity.uuid);
        assert_eq!(actual.members.len(), 1);
        assert_eq!(
            actual
                .members
                .iter()
                .filter(|member| member.uuid == actual.coordinator)
                .count(),
            1
        );
        assert_eq!(actual.members[0].uuid.0, identity.uuid);
        assert_eq!(
            actual.members[0].location,
            fsonos_proto::ssdp::description_url(host)
        );
        assert_eq!(actual.members[0].zone_name, identity.room);
        assert_eq!(actual.members[0].ip(), Some(host));
    }
    // Plant an extra *real* owner-B read before the expected owner-A read.
    // Both SDK calls must succeed; only the exact service-mask oracle rejects it.
    let planted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        two_owner_call(
            (&mut a, &mut b),
            (&mut mailbox_a, &mut mailbox_b),
            http,
            search_a,
            [true, false],
            move |client| {
                let b = fsonos_proto::control::get_volume(client, hosts[1]).expect("real B read");
                let a = fsonos_proto::control::get_volume(client, hosts[0]).expect("real A read");
                (a, b)
            },
        )
    }));
    let error = planted.expect_err("an extra owner service must fail the mask oracle");
    let message = error
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| error.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(message.contains("owner service mask mismatch"));
    assert!(message.contains("left: [true, true]"));
    assert!(message.contains("right: [true, false]"));
    let bounded_message: String = message.chars().take(256).collect();
    println!(
        "FFW_TWO_OWNER_ISOLATION_CANARY observed=[true,true] expected=[true,false] message={bounded_message:?}"
    );
    let paired = two_owner_call(
        (&mut a, &mut b),
        (&mut mailbox_a, &mut mailbox_b),
        http,
        search_a,
        [true, true],
        move |client| {
            Ok::<_, ProtoError>((
                fsonos_proto::control::get_volume(client, hosts[1])?,
                fsonos_proto::control::get_volume(client, hosts[0])?,
            ))
        },
    )
    .unwrap();
    assert_eq!(paired, (50, 50));
    let callbacks = [sink_a.callback_url(TAG), sink_b.callback_url(TAG)];
    let (sub_a, sub_b) = two_owner_call(
        (&mut a, &mut b),
        (&mut mailbox_a, &mut mailbox_b),
        http,
        search_a,
        [true, true],
        move |client| {
            Ok::<_, ProtoError>((
                client.subscribe_for(hosts[0], &callbacks[0])?,
                client.subscribe_for(hosts[1], &callbacks[1])?,
            ))
        },
    )
    .unwrap();
    assert_ne!(sub_a.sid, sub_b.sid);
    let first_a = next(&sink_a);
    let first_b = next(&sink_b);
    assert_eq!((first_a.sid.as_str(), first_a.seq), (sub_a.sid.as_str(), 0));
    assert_eq!((first_b.sid.as_str(), first_b.seq), (sub_b.sid.as_str(), 0));
    assert_eq!(first_a.last_change().unwrap().unwrap().volume(), Some(50));
    assert_eq!(first_b.last_change().unwrap().unwrap().volume(), Some(50));
    let wrong_sid = sub_a.sid.clone();
    let wrong = two_owner_call(
        (&mut a, &mut b),
        (&mut mailbox_a, &mut mailbox_b),
        http,
        search_a,
        [false, true],
        move |c| c.renew_for(hosts[1], &wrong_sid),
    )
    .unwrap_err();
    assert!(
        matches!(wrong, ProtoError::Network { ref detail, .. } if detail == "SUBSCRIBE: HTTP 412")
    );
    assert!(sink_a.recv_timeout(Duration::from_millis(300)).is_none());
    assert!(sink_b.recv_timeout(Duration::from_millis(300)).is_none());
    let fresh_a = two_owner_call(
        (&mut a, &mut b),
        (&mut mailbox_a, &mut mailbox_b),
        http,
        search_a,
        [true, false],
        move |c| fsonos_proto::control::get_volume(c, hosts[0]),
    )
    .unwrap();
    assert_eq!(fresh_a, 50);

    two_owner_call(
        (&mut a, &mut b),
        (&mut mailbox_a, &mut mailbox_b),
        http,
        search_a,
        [true, false],
        move |c| set_volume(c, hosts[0], 90),
    )
    .unwrap();
    let changed_a = next(&sink_a);
    assert_eq!(
        (changed_a.sid.as_str(), changed_a.seq),
        (sub_a.sid.as_str(), 1)
    );
    assert_eq!(changed_a.last_change().unwrap().unwrap().volume(), Some(90));
    assert!(sink_b.recv_timeout(Duration::from_millis(300)).is_none());
    let fresh_b = two_owner_call(
        (&mut a, &mut b),
        (&mut mailbox_a, &mut mailbox_b),
        http,
        search_b,
        [false, true],
        move |c| fsonos_proto::control::get_volume(c, hosts[1]),
    )
    .unwrap();
    assert_eq!(fresh_b, 50);
    assert_eq!(
        server_b.with_session(|s| (
            s.state_revision,
            s.members[&identity_b.uuid].volume_0_to_100
        )),
        (1, 50)
    );
    two_owner_call(
        (&mut a, &mut b),
        (&mut mailbox_a, &mut mailbox_b),
        http,
        search_b,
        [false, true],
        move |c| set_volume(c, hosts[1], 70),
    )
    .unwrap();
    let changed_b = next(&sink_b);
    assert_eq!(
        (changed_b.sid.as_str(), changed_b.seq),
        (sub_b.sid.as_str(), 1)
    );
    assert_eq!(changed_b.last_change().unwrap().unwrap().volume(), Some(70));
    assert!(sink_a.recv_timeout(Duration::from_millis(300)).is_none());
    let fresh_a = two_owner_call(
        (&mut a, &mut b),
        (&mut mailbox_a, &mut mailbox_b),
        http,
        search_a,
        [true, false],
        move |c| fsonos_proto::control::get_volume(c, hosts[0]),
    )
    .unwrap();
    assert_eq!(fresh_a, 90);
    assert_eq!(
        server_a.with_session(|s| (
            s.state_revision,
            s.members[&identity_a.uuid].volume_0_to_100
        )),
        (2, 90)
    );
    assert_eq!(
        server_b.with_session(|s| (
            s.state_revision,
            s.members[&identity_b.uuid].volume_0_to_100
        )),
        (2, 70)
    );

    assert!(server_a.stop().reconciled());
    assert_eq!(a.owner.release_http_eventing(&mut mailbox_a).unwrap(), 1);
    assert!(matches!(
        client_b.submit(&get),
        Err(franken_speaker::settled_http::HttpMailboxError::Busy)
    ));
    two_owner_call(
        (&mut a, &mut b),
        (&mut mailbox_a, &mut mailbox_b),
        http,
        search_b,
        [false, true],
        move |c| set_volume(c, hosts[1], 60),
    )
    .unwrap();
    let still_b = next(&sink_b);
    assert_eq!((still_b.sid.as_str(), still_b.seq), (sub_b.sid.as_str(), 2));
    assert_eq!(still_b.last_change().unwrap().unwrap().volume(), Some(60));
    assert!(sink_a.recv_timeout(Duration::from_millis(300)).is_none());
    // A's adapter is stopped, so read through its reopened associated mailbox.
    // The real endpoint response and owner snapshot both prove A stayed at 90.
    let action = fsonos_proto::soap::soap_action_header(&RENDERING_CONTROL, "GetVolume");
    let body = fsonos_proto::soap::envelope(
        &RENDERING_CONTROL,
        "GetVolume",
        "<InstanceID>0</InstanceID><Channel>Master</Channel>",
    );
    let headers = [("SOAPACTION", action.as_str())];
    let read_a = franken_control::fsonos::HttpRequest {
        method: "POST",
        path: RENDERING_CONTROL.control_path,
        peer_ip: PLAYER,
        ingress: franken_control::fsonos::Ingress::LocalLegacy,
        headers: &headers,
        body: body.as_bytes(),
    };
    let pending = client_a
        .submit(&read_a)
        .expect("cleaned-up A mailbox accepts read");
    assert!(matches!(
        a.owner.service_http(&mut mailbox_a),
        Ok(HttpService::Replied)
    ));
    let actual = pending.wait().unwrap();
    assert_eq!(
        (
            actual.session.state_revision,
            actual.session.members[&identity_a.uuid].volume_0_to_100
        ),
        (2, 90)
    );
    let response = actual.result.unwrap().control.response;
    assert_eq!(response.status, 200);
    assert_eq!(
        fsonos_proto::soap::parse_response(&response.body, "GetVolume")
            .unwrap()
            .require_u32("CurrentVolume")
            .unwrap(),
        90
    );
    assert!(server_b.stop().reconciled());
    assert_eq!(b.owner.release_http_eventing(&mut mailbox_b).unwrap(), 1);
    assert!(sink_b.recv_timeout(Duration::from_millis(300)).is_none());
    let pcm_a = three_blocks_and_stop(a);
    let pcm_b = three_blocks_and_stop(b);
    assert_ne!(pcm_a, baseline_a);
    assert_ne!(pcm_b, baseline_b);
    assert_ne!(pcm_a, pcm_b);
}
