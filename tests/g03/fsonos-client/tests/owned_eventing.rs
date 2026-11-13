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
    let soap = Endpoint::new(
        EndpointConfig::provisional(MEMBER),
        LegacyBridge::new(bridge, key_for("legacy-bridge")),
        1,
        1,
    )
    .unwrap();
    let initial_session = UnifiedGroupSession::new("grp", "coord", 1);
    let authority = AuthorityToken::issue(&initial_session, u64::MAX);
    let fresh = fleet
        .provision_fresh_group(
            "grp",
            "coord",
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
            member_id: MEMBER.into(),
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
