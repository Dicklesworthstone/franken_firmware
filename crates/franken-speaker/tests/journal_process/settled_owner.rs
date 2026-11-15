//! Actual process/file journal through SettledRender. Only HAL and clock are
//! scripted; this is not a device, acoustic timing, or old-kernel qualification.
//! S1 matches the established two-channel NetworkRender synthetic fixture.
use super::TestSecrets;
use franken_board_profile::synthetic_test_fixture_catalog;
use franken_clock::group::{GroupClock, GroupClockConfig, ProbeResponse, StartSchedule};
use franken_control::channel::owner::FleetControlOwner;
use franken_control::channel::peer::{PeerId, PeerRole, compute_proof};
use franken_control::channel::pipeline::{ChannelConfig, Outcome};
use franken_control::channel::request::{ControlCommand, ControlRequest, RequestBody};
use franken_control::channel::wire::encode_request;
use franken_control::fsonos::{Endpoint, EndpointConfig, LegacyBridge};
use franken_dsp::protection::{Admission, ProtectedBoardDsp, synthetic_calibration_for};
use franken_dsp::resample::{DriftResampler, ResamplerConfig};
use franken_hal::abi::{EVENT_LEN, RawGeometry};
use franken_hal::backend::{
    AbiKind, DeviceBackend, DriverError, FakeBackend, FakeConfig, Provenance as HalProvenance,
    RawCapabilities,
};
use franken_hal::session::{HalSession, SessionConfig, StartPreconditions};
use franken_hal::slots::{KernelView, LeakLedger};
use franken_journal::Limits;
use franken_platform::abi::Abi;
use franken_platform::ops::{KernelOps, Provenance, Timespec};
use franken_platform::sim::admit_simulated_layer;
use franken_session::{AuthorityToken, ChannelRole, MembershipConfig, UnifiedGroupSession};
use franken_speaker::media_playout::MediaPlayout;
use franken_speaker::net_carrier::MediaEndpoint;
use franken_speaker::network_render::{NetworkRender, NetworkRenderAdmission, TickMapping};
use franken_speaker::render::{RenderConfig, RenderLoop, RenderState, ScriptedTiming};
use franken_speaker::settled_render::{DrainProgress, PendingMember, SettledRender};
use franken_stream::carrier::{CarrierReceiver, HostUdp, ReceiverLimits};
use franken_stream::playout::{PlayoutConfig, PlayoutProfile};
use franken_stream::{StreamId, StreamKey, StreamReceiver};
use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;

const TEST_EPOCH: u64 = 1;
const TEST_MEMBER: &str = "speaker";
const TEST_CONTROLLER: &str = "controller";
const TEST_BRIDGE: &str = "legacy-bridge";
const CLOCK_ORIGIN: u64 = 100_000_000_000;
fn synthetic_ledger(stream_and_jitter_bytes: u64) -> franken_platform::MemoryBudgetLedger {
    use franken_platform::MemoryBudgetLedger;
    MemoryBudgetLedger {
        nominal_ram_bytes: 32 * 1024 * 1024,
        kernel_and_driver_reserved_bytes: 14 * 1024 * 1024,
        dma_ring_reserved_bytes: 512 * 1024,
        core_runtime_peak_bytes: 3 * 1024 * 1024,
        stream_and_jitter_bytes,
        native_integrations_bytes: 4 * 1024 * 1024,
        required_safety_floor_bytes: MemoryBudgetLedger::MIN_SAFETY_FLOOR_BYTES,
    }
}
fn test_peer(name: &str) -> PeerId {
    PeerId::parse(name).unwrap()
}
fn test_key(name: &str) -> Vec<u8> {
    format!("fixture-key-{name}-0123456789abcdef").into_bytes()
}
fn test_wire(peer: &str, seq: u64, revision: Option<u64>, command: ControlCommand) -> Vec<u8> {
    let body = RequestBody::new(test_peer(peer), seq, TEST_EPOCH, revision, command).unwrap();
    let proof = compute_proof(&test_key(peer), &body.signing_bytes());
    encode_request(&ControlRequest::new(body, proof)).unwrap()
}

struct TestKernel {
    now: Rc<Cell<u64>>,
}
impl KernelOps for TestKernel {
    fn provenance(&self) -> Provenance {
        Provenance::Simulated
    }
    fn backend_abi(&self) -> Option<Abi> {
        None
    }
    fn clock_gettime_monotonic(&mut self, out: &mut Timespec) -> isize {
        out.secs = i64::try_from(self.now.get() / 1_000_000_000).unwrap();
        out.nanos = i64::try_from(self.now.get() % 1_000_000_000).unwrap();
        0
    }
    fn getrandom(&mut self, _: &mut [u8], _: u32) -> isize {
        -38
    }
    fn open_dev_random(&mut self, _: u32) -> isize {
        -38
    }
    fn eventfd2(&mut self, _: u32, _: u32) -> isize {
        7
    }
    fn pipe2(&mut self, _: &mut [i32; 2], _: u32) -> isize {
        -38
    }
    fn write(&mut self, _: i32, _: &[u8]) -> isize {
        -38
    }
    fn read(&mut self, _: i32, _: &mut [u8]) -> isize {
        -38
    }
    fn close(&mut self, _: i32) -> isize {
        0
    }
}

struct StopBackend(FakeBackend, Option<Rc<Cell<bool>>>);
impl DeviceBackend for StopBackend {
    fn provenance(&self) -> HalProvenance {
        self.0.provenance()
    }
    fn abi(&self) -> AbiKind {
        self.0.abi()
    }
    fn capabilities(&mut self) -> Result<RawCapabilities, DriverError> {
        self.0.capabilities()
    }
    fn set_mute(&mut self, v: bool) -> Result<bool, DriverError> {
        if v && self.1.as_ref().is_some_and(|fail| fail.get()) {
            return Err(DriverError::Errno(5));
        }
        self.0.set_mute(v)
    }
    fn start(&mut self) -> Result<(), DriverError> {
        self.0.start()
    }
    fn write(&mut self, _: &[u8]) -> Result<usize, DriverError> {
        Err(DriverError::Errno(38))
    }
    fn submit_retained(
        &mut self,
        s: u16,
        g: u32,
        v: KernelView,
        n: usize,
    ) -> Result<usize, DriverError> {
        self.0.submit_retained(s, g, v, n)
    }
    fn poll_event(&mut self, r: &mut [u8; EVENT_LEN]) -> Result<Option<usize>, DriverError> {
        self.0.poll_event(r)
    }
    fn request_flush(&mut self) -> Result<(), DriverError> {
        self.0.request_flush()
    }
    fn stop_flush_supported(&self) -> bool {
        true
    }
    fn reset(&mut self) -> Result<bool, DriverError> {
        self.0.reset()
    }
    fn reset_ack_discards_playback(&self) -> bool {
        true
    }
    fn wait_tick(&mut self) {
        self.0.wait_tick();
    }
}

fn prepared_network_with_failure(
    failure: Option<Rc<Cell<bool>>>,
) -> NetworkRender<HostUdp, TestKernel, StopBackend> {
    let now = Rc::new(Cell::new(50_000_000));
    let matrix = franken_speaker::guest_evidence::for_abi(Abi::PowerPc32).matrix();
    let platform = admit_simulated_layer(
        &matrix,
        TestKernel {
            now: Rc::clone(&now),
        },
    )
    .unwrap();
    let mut clock = GroupClock::new(GroupClockConfig::standard().unwrap(), 1, 7, 100).unwrap();
    for k in 1..=4u64 {
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
    let start_local = clock.local_for_group(start_group_ns, now.get()).unwrap();
    clock
        .set_authority(1, start_local + 2_000_000_000, now.get())
        .unwrap();
    let key = StreamKey::from_bytes([0x42; 32]);
    let stream = StreamId::new(0x5eed000000000001).unwrap();
    let receiver = CarrierReceiver::bind(
        key.clone(),
        stream,
        1,
        ReceiverLimits::baseline(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
    )
    .unwrap();
    let media = MediaPlayout::new(
        StreamReceiver::new(key, stream, 1),
        PlayoutProfile::MUSIC,
        PlayoutConfig {
            work_ns: 10_000_000,
            lead_ns: 1_000_000,
            tolerance_ns: 1_000_000,
        },
        &synthetic_ledger(2 * 1024 * 1024),
        0,
    )
    .unwrap();
    let board = synthetic_test_fixture_catalog()
        .into_iter()
        .find(|b| b.model_number == "S1")
        .unwrap();
    let calibration = synthetic_calibration_for(&board);
    let dsp = ProtectedBoardDsp::admit(&board, Some(&calibration), Admission::HostSimulation);
    let mut config = FakeConfig::retained();
    config.geometry = RawGeometry {
        ring_depth: 4,
        frames_per_block: 64,
        channels: 2,
        bytes_per_sample: 2,
    };
    config.completion_delay_ticks = 100;
    config.min_submission_lead_ticks = Some(6);
    config.flush_ack_delay_ticks = Some(3);
    let (backend, _probe) = FakeBackend::new(config);
    let mut hal = HalSession::open(
        board,
        StopBackend(backend, failure),
        SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2),
    )
    .unwrap();
    hal.prepare().unwrap();
    assert!(hal.abort_mute().unwrap().mute_acknowledged);
    hal.reset_device().unwrap();
    assert!(hal.silent_prepared_after_reset());
    assert_eq!(hal.prime_silence().unwrap().accepted_bytes, 64 * 4);
    let mut config = RenderConfig::standard(64);
    config.window_ticks = 8;
    let render = RenderLoop::new(
        hal,
        dsp,
        DriftResampler::new(ResamplerConfig::default()).unwrap(),
        config,
    )
    .unwrap();
    let mapping = TickMapping {
        anchor_tick: render.next_slot().unwrap().presentation_tick,
        anchor_group_ns: start_group_ns,
        ns_numerator: 1_000_000,
        tick_denominator: 3,
        uncertainty_ns: 0,
        presentation_tolerance_ns: 1,
    };
    NetworkRender::admit(
        MediaEndpoint::new(receiver, media),
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
    .unwrap()
}
fn pending_member() -> PendingMember {
    let board = synthetic_test_fixture_catalog()
        .into_iter()
        .find(|b| b.model_number == "S1")
        .unwrap();
    PendingMember {
        member_id: TEST_MEMBER.into(),
        profile_id: board.profile_id,
        role: ChannelRole::Stereo,
        ceiling: 1.0,
    }
}

pub(super) fn run(executable: &std::path::Path, cancel: bool) {
    run_mode(
        executable,
        cancel,
        false,
        false,
        false,
        false,
        ContinuationMode::Original,
    );
}
pub(super) fn run_http(executable: &std::path::Path, cancel: bool) {
    run_mode(
        executable,
        cancel,
        true,
        false,
        false,
        false,
        ContinuationMode::Original,
    );
}
pub(super) fn run_lost_http(executable: &std::path::Path) {
    run_mode(
        executable,
        false,
        true,
        true,
        false,
        false,
        ContinuationMode::Original,
    );
}
pub(super) fn run_expired_http(executable: &std::path::Path) {
    run_mode(
        executable,
        false,
        true,
        true,
        true,
        false,
        ContinuationMode::Original,
    );
}
pub(super) fn run_stop_failure(executable: &std::path::Path) {
    run_mode(
        executable,
        true,
        true,
        false,
        false,
        true,
        ContinuationMode::Original,
    );
}
pub(super) fn run_replaced_mailbox(executable: &std::path::Path, cancel: bool) {
    run_mode(
        executable,
        cancel,
        true,
        false,
        false,
        false,
        ContinuationMode::ReplacedMailbox,
    );
}
pub(super) fn run_datagram_turn(executable: &std::path::Path, cancel: bool) {
    run_mode(
        executable,
        cancel,
        false,
        false,
        false,
        false,
        ContinuationMode::DatagramTurn,
    );
}
#[derive(Clone, Copy)]
enum ContinuationMode {
    Original,
    ReplacedMailbox,
    DatagramTurn,
}
fn run_mode(
    executable: &std::path::Path,
    cancel: bool,
    http: bool,
    lost: bool,
    expired: bool,
    fail_stop: bool,
    mode: ContinuationMode,
) {
    let replaced_mailbox = matches!(mode, ContinuationMode::ReplacedMailbox);
    let automatic_datagram = matches!(mode, ContinuationMode::DatagramTurn);
    use asupersync::runtime::legacy_profile::{LegacyCaps, LegacyProfile};
    use franken_speaker::file_medium::FileMedium;
    use franken_speaker::journal_process::{ProcessStorage, WorkerCustody};
    use std::future::poll_fn;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::task::{Context as TaskContext, Wake, Waker};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    struct ChildOwner(WorkerCustody);
    impl Drop for ChildOwner {
        fn drop(&mut self) {
            let _ = self.0.shutdown_off_loop(Duration::from_secs(2));
        }
    }
    struct Watch {
        count: Arc<AtomicUsize>,
        forward: Waker,
    }
    impl Wake for Watch {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.forward.wake_by_ref();
        }
    }
    let signal = |pid: u32, name: &str| {
        assert!(
            std::process::Command::new("kill")
                .args([name, &pid.to_string()])
                .status()
                .unwrap()
                .success()
        );
    };
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "ffw-settled-process-{}-{nonce}.img",
        std::process::id()
    ));
    let limits = Limits::fleet_control_development();
    let (mut control, _) = FleetControlOwner::boot(
        TestSecrets::fleet_control_development(),
        FileMedium::create_new(&path, &limits).unwrap(),
        ChannelConfig::provisional(),
    )
    .unwrap();
    for name in [TEST_CONTROLLER, TEST_BRIDGE] {
        control
            .admit(
                &test_peer(name),
                PeerRole::Controller,
                &test_key(name),
                Some(TEST_EPOCH),
                1,
            )
            .unwrap();
    }
    control
        .reserve_legacy_peer(&test_peer(TEST_BRIDGE))
        .unwrap();
    let session = UnifiedGroupSession::new("grp", "coord", TEST_EPOCH);
    let token = AuthorityToken::issue(&session, u64::MAX);
    let fresh = control
        .provision_fresh_group(
            "grp",
            "coord",
            TEST_EPOCH,
            MembershipConfig::default(),
            token,
            CLOCK_ORIGIN + 50_000_000,
        )
        .unwrap();
    let Ok((handoff, file)) = fresh.into_storage_handoff() else {
        panic!("fresh owner transfer");
    };
    drop(file);
    let (storage, custody) = ProcessStorage::spawn_off_loop(executable, &path, &limits).unwrap();
    let mut child = ChildOwner(custody);
    let (journal, recovery) = franken_journal::Journal::open(storage, limits.clone()).unwrap();
    assert_eq!(recovery.source, franken_journal::Source::Segment);
    let Ok(fresh) = handoff.attach(journal) else {
        panic!("actual provisioned fresh bundle");
    };
    let soap = Endpoint::new(
        EndpointConfig::provisional(TEST_MEMBER),
        LegacyBridge::new(test_peer(TEST_BRIDGE), test_key(TEST_BRIDGE)),
        1,
        1,
    )
    .unwrap();
    let stop_failure = Rc::new(Cell::new(false));
    let mut owner = SettledRender::admit_fresh_group(
        fresh,
        soap,
        prepared_network_with_failure(Some(Rc::clone(&stop_failure))),
        pending_member(),
        7,
    )
    .unwrap();
    owner = match owner.into_stopped_parts() {
        Err(owner) => owner,
        Ok(_) => panic!("unacknowledged output custody must remain owned"),
    };
    let runtime = LegacyProfile::new(
        LegacyCaps {
            worker_threads: 1,
            thread_stack_bytes: 256 * 1024,
            blocking_max_threads: 0,
            blocking_thread_stack_bytes: 0,
            global_queue_limit: 8,
            blocking_max_queued: 0,
        },
        256 * 1024,
    )
    .caller_driven()
    .build()
    .unwrap();
    owner = if http {
        use franken_control::fsonos::{HttpRequest, Ingress, Service};
        use franken_speaker::settled_http::{
            HttpMailboxConfig, HttpMailboxError, HttpService, http_mailbox,
        };
        use std::sync::atomic::AtomicBool;
        let (client, mut mailbox) =
            http_mailbox(HttpMailboxConfig::new(4096, 8, Duration::from_secs(1)).unwrap()).unwrap();
        let body = br#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:SetRelativeGroupVolume xmlns:u="urn:schemas-upnp-org:service:GroupRenderingControl:1"><InstanceID>0</InstanceID><Adjustment>10</Adjustment></u:SetRelativeGroupVolume></s:Body></s:Envelope>"#;
        let headers = [(
            "SOAPAction",
            "\"urn:schemas-upnp-org:service:GroupRenderingControl:1#SetRelativeGroupVolume\"",
        )];
        let request = HttpRequest {
            method: "POST",
            path: Service::GroupRenderingControl.control_path(),
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ingress: Ingress::LocalLegacy,
            headers: &headers,
            body,
        };
        if lost {
            // Production event generation; no callback HTTP is sent by this fixture.
            let subscription = HttpRequest {
                method: "SUBSCRIBE",
                path: Service::GroupRenderingControl.event_path(),
                peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                ingress: Ingress::LocalLegacy,
                headers: &[
                    ("CALLBACK", "<http://127.0.0.1:3400/events>"),
                    ("NT", "upnp:event"),
                    ("TIMEOUT", "Second-300"),
                ],
                body: &[],
            };
            let initial = owner.handle_soap(&subscription).unwrap();
            assert_eq!(initial.control.response.status, 200);
            assert_eq!(initial.control.notifications.len(), 1);
        }
        assert_eq!(client.diagnostics().lost_replies, 0);
        assert_eq!(client.diagnostics().lost_notifications, 0);
        let mut response = Some(client.submit(&request).unwrap());
        owner.use_pollable_control();
        assert!(matches!(
            owner.handle_soap(&request),
            Err(franken_speaker::settled_render::OwnerError::ControlPending)
        ));
        assert!(matches!(
            owner.step_control(),
            Err(franken_speaker::settled_render::OwnerError::ControlPending)
        ));
        signal(child.0.id(), "-STOP");
        assert_eq!(
            owner.service_http(&mut mailbox).unwrap(),
            HttpService::Pending
        );
        assert!(
            matches!(client.submit(&request), Err(HttpMailboxError::Busy)),
            "in-flight HTTP retains the single admission slot"
        );
        let mut replacement_pending = None;
        let mut replacement_client = None;
        if replaced_mailbox {
            let (new_client, mut new_mailbox) =
                http_mailbox(HttpMailboxConfig::new(4096, 8, Duration::from_secs(1)).unwrap())
                    .unwrap();
            assert_eq!(
                new_mailbox.service_one(|_| panic!("empty generic mailbox")),
                Ok(HttpService::Idle)
            );
            replacement_pending = Some(new_client.submit(&request).unwrap());
            replacement_client = Some(new_client);
            // Drops the original mailbox while its accepted envelope remains
            // owned by SettledRender and its original receiver remains live.
            mailbox = new_mailbox;
        }
        stop_failure.set(fail_stop);
        let stop = AtomicBool::new(cancel);
        let mut timing = ScriptedTiming::default();
        let turn = owner
            .service_turn(&mut mailbox, &mut timing, &stop, Duration::from_millis(3))
            .unwrap();
        let runtime_stats = owner.control_runtime_stats();
        assert!(runtime_stats.peak_future_state_bytes > std::mem::size_of::<usize>());
        assert!(runtime_stats.peak_future_state_bytes <= runtime_stats.future_state_limit_bytes);
        assert!(
            turn.http.is_none(),
            "stopped real worker cannot acknowledge journal commit"
        );
        if fail_stop {
            assert!(
                matches!(turn.stop, Some(Ok(_))),
                "cancel acceptance is not mute ACK"
            );
            assert_eq!(
                turn.stop_mute_acknowledged,
                Some(false),
                "failed HAL mute is visible"
            );
            // Keep the mute failure enabled. This faults the HAL; it cannot
            // produce a flush ACK or surrender renderer custody below.
        } else if cancel {
            assert!(matches!(turn.stop, Some(Ok(_))));
            assert_eq!(turn.stop_mute_acknowledged, Some(true));
        }
        if cancel {
            assert!(
                turn.drain.is_some(),
                "local Stop drains HAL while journal remains pending"
            );
        }
        if expired {
            assert!(matches!(
                response.take().unwrap().wait(),
                Err(HttpMailboxError::TimeoutOutcomeUnknown)
            ));
        } else if lost {
            drop(response.take());
        }
        signal(child.0.id(), "-CONT");
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        loop {
            match owner.service_http(&mut mailbox).unwrap() {
                HttpService::Replied if !lost => break,
                HttpService::ReplyLost if lost => break,
                HttpService::Pending => assert!(std::time::Instant::now() < deadline),
                other => panic!("unexpected service outcome: {other:?}"),
            }
        }
        if lost {
            assert_eq!(client.diagnostics().lost_replies, 1);
            assert_eq!(
                client.diagnostics().lost_notifications,
                1,
                "produced GENA event is accounted as lost"
            );
        } else {
            assert_eq!(client.diagnostics().lost_replies, 0);
            assert_eq!(client.diagnostics().lost_notifications, 0);
        }
        if !lost {
            let reply = response.unwrap().wait().unwrap();
            let handled = reply.result.unwrap().control;
            assert_eq!(
                handled.response.status,
                if cancel { 500 } else { 200 },
                "{}",
                handled.response.body
            );
            assert_eq!(
                reply.session.group_master_volume,
                if cancel { 50 } else { 60 }
            );
        }
        if replaced_mailbox {
            assert_eq!(
                owner.service_http(&mut mailbox),
                Err(HttpMailboxError::Unavailable)
            );
            assert!(
                matches!(
                    replacement_client.as_ref().unwrap().submit(&request),
                    Err(HttpMailboxError::Busy)
                ),
                "replacement envelope was never taken"
            );
            assert_eq!(
                replacement_client
                    .as_ref()
                    .unwrap()
                    .diagnostics()
                    .lost_replies,
                0
            );
            assert_eq!(
                client.diagnostics().lost_replies,
                0,
                "original authorized response reached its original receiver"
            );
            drop(replacement_pending);
        }
        if !cancel && !replaced_mailbox {
            // Positive successor through the SAME normal HTTP entry point.
            let next = client.submit(&request).unwrap();
            loop {
                match owner.service_http(&mut mailbox).unwrap() {
                    HttpService::Replied => break,
                    HttpService::Pending => assert!(std::time::Instant::now() < deadline),
                    other => panic!("unexpected successor outcome: {other:?}"),
                }
            }
            let reply = next.wait().unwrap();
            assert_eq!(reply.result.unwrap().control.response.status, 200);
            assert_eq!(reply.session.group_master_volume, 70);
            assert_eq!(client.diagnostics().lost_replies, usize::from(lost));
            assert_eq!(
                client.diagnostics().lost_notifications,
                usize::from(lost),
                "consumed successor adds no lost event"
            );
        }
        owner.request_stop().unwrap();
        owner
    } else if automatic_datagram {
        use franken_control::channel::owner::DeferredIngressError;
        use franken_speaker::settled_http::{HttpMailboxConfig, http_mailbox};
        use std::sync::atomic::AtomicBool;
        let (client, mut mailbox) =
            http_mailbox(HttpMailboxConfig::new(4096, 8, Duration::from_secs(1)).unwrap()).unwrap();
        assert_eq!(
            owner.service_http(&mut mailbox).unwrap(),
            franken_speaker::settled_http::HttpService::Idle
        );
        let (_wrong_client, mut wrong_mailbox) =
            http_mailbox(HttpMailboxConfig::new(4096, 8, Duration::from_secs(1)).unwrap()).unwrap();
        assert_eq!(
            wrong_mailbox.service_one(|_| panic!("empty generic mailbox")),
            Ok(franken_speaker::settled_http::HttpService::Idle)
        );
        let request = test_wire(
            TEST_CONTROLLER,
            1,
            Some(0),
            ControlCommand::AdjustGroupVolume { delta: 10 },
        );
        owner.receive(&request).unwrap();
        signal(child.0.id(), "-STOP");
        let stop = AtomicBool::new(false);
        let mut timing = ScriptedTiming::default();
        let first = owner
            .service_turn(
                &mut wrong_mailbox,
                &mut timing,
                &stop,
                Duration::from_millis(3),
            )
            .unwrap();
        assert!(matches!(
            first.http,
            Some(Err(
                franken_speaker::settled_http::HttpMailboxError::Unavailable
            ))
        ));
        assert!(
            first.control.is_none(),
            "real stopped child cannot acknowledge durable datagram"
        );
        // Association errors are returned promptly. Repeated normal turns
        // still advance bounded cursor bookkeeping to the stopped worker's I/O.
        for _ in 0..32 {
            let turn = owner
                .service_turn(
                    &mut wrong_mailbox,
                    &mut timing,
                    &stop,
                    Duration::from_millis(3),
                )
                .unwrap();
            assert!(turn.control.is_none());
            assert!(matches!(
                turn.http,
                Some(Err(
                    franken_speaker::settled_http::HttpMailboxError::Unavailable
                ))
            ));
        }
        let successor = test_wire(
            TEST_CONTROLLER,
            2,
            Some(1),
            ControlCommand::AdjustGroupVolume { delta: 10 },
        );
        assert_eq!(
            owner.defer_control_datagram(&vec![0; 4097]),
            Err(DeferredIngressError::TooLarge)
        );
        for _ in 0..8 {
            owner.defer_control_datagram(&successor).unwrap();
        }
        assert_eq!(
            owner.defer_control_datagram(&successor),
            Err(DeferredIngressError::Full)
        );

        // The normal HTTP envelope waits intact behind the one journal owner.
        let read = franken_control::fsonos::HttpRequest {
            method: "GET",
            path: "/",
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ingress: franken_control::fsonos::Ingress::LocalLegacy,
            headers: &[],
            body: &[],
        };
        let queued_http = client.submit(&read).unwrap();
        stop.store(cancel, Ordering::Release);
        let stalled = owner
            .service_turn(
                &mut wrong_mailbox,
                &mut timing,
                &stop,
                Duration::from_millis(3),
            )
            .unwrap();
        assert!(stalled.control.is_none());
        assert!(matches!(
            stalled.http,
            Some(Err(
                franken_speaker::settled_http::HttpMailboxError::Unavailable
            ))
        ));
        if cancel {
            assert!(stalled.stop.is_some());
            assert!(stalled.drain.is_some());
        }
        signal(child.0.id(), "-CONT");
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let complete = loop {
            let turn = owner
                .service_turn(
                    &mut wrong_mailbox,
                    &mut timing,
                    &stop,
                    Duration::from_millis(3),
                )
                .unwrap();
            assert!(matches!(
                turn.http,
                Some(Err(
                    franken_speaker::settled_http::HttpMailboxError::Unavailable
                ))
            ));
            if let Some(result) = turn.control {
                break result.unwrap();
            }
            assert!(std::time::Instant::now() < deadline);
        };
        assert_eq!(
            owner.service_http(&mut mailbox).unwrap(),
            franken_speaker::settled_http::HttpService::Replied
        );
        assert_eq!(
            queued_http
                .wait()
                .unwrap()
                .result
                .unwrap()
                .control
                .response
                .status,
            405
        );
        assert_eq!(complete.deferred_datagrams.len(), 8);
        let debug = format!("{complete:?}");
        assert!(debug.contains("deferred_datagram_count: 8"));
        assert!(
            !debug.contains(TEST_CONTROLLER),
            "Debug must not expose authenticated raw ingress"
        );
        assert!(
            complete
                .deferred_datagrams
                .iter()
                .all(|bytes| *bytes == successor)
        );
        if cancel {
            assert!(matches!(
                complete.step.control,
                Err(franken_control::channel::pipeline::PendingStepFailure::FenceChanged { .. })
            ));
        } else {
            assert!(matches!(
                complete.step.control.unwrap()[0].outcome,
                Outcome::Committed { revision: 1 }
            ));
            // Reauthenticate explicitly returned raw ingress at current time;
            // duplicate sequence numbers must not multiply its relative effect.
            for bytes in complete.deferred_datagrams {
                owner.receive(&bytes).unwrap();
            }
            let next = loop {
                let turn = owner
                    .service_turn(
                        &mut wrong_mailbox,
                        &mut timing,
                        &stop,
                        Duration::from_millis(3),
                    )
                    .unwrap();
                assert!(matches!(
                    turn.http,
                    Some(Err(
                        franken_speaker::settled_http::HttpMailboxError::Unavailable
                    ))
                ));
                if let Some(result) = turn.control {
                    break result.unwrap();
                }
                assert!(std::time::Instant::now() < deadline);
            };
            assert!(matches!(
                next.step.control.unwrap()[0].outcome,
                Outcome::Committed { revision: 2 }
            ));
            assert!(next.deferred_datagrams.is_empty());
        }
        owner.request_stop().unwrap();
        owner
    } else {
        let bytes = test_wire(
            TEST_CONTROLLER,
            1,
            Some(0),
            ControlCommand::AdjustGroupVolume { delta: 10 },
        );
        owner.receive(&bytes).unwrap();
        owner.begin_pending_control().unwrap();
        let mut owner = Some(owner);
        signal(child.0.id(), "-STOP");
        let wakes = Arc::new(AtomicUsize::new(0));
        let mut observed_stall = false;
        let result = runtime.block_on(async {
            let context = asupersync::cx::Cx::current().unwrap();
            assert!(context.timer_driver().is_some());
            asupersync::time::timeout(
                context.now(),
                Duration::from_secs(3),
                poll_fn(|cx| {
                    let waker = Waker::from(Arc::new(Watch {
                        count: Arc::clone(&wakes),
                        forward: cx.waker().clone(),
                    }));
                    let before = wakes.load(Ordering::SeqCst);
                    let result = owner
                        .as_mut()
                        .unwrap()
                        .poll_pending_control(&mut TaskContext::from_waker(&waker));
                    if result.is_pending()
                        && !observed_stall
                        && wakes.load(Ordering::SeqCst) == before
                    {
                        observed_stall = true;
                        if cancel {
                            let current = owner.as_mut().unwrap();
                            current.request_stop().unwrap();
                            let mut timing = ScriptedTiming::default();
                            let mut ack = false;
                            for _ in 0..20 {
                                if let DrainProgress::Finished(report) =
                                    current.drain_tick(&mut timing).unwrap()
                                {
                                    assert!(report.acknowledged);
                                    ack = true;
                                    break;
                                }
                            }
                            assert!(ack, "HAL drain must complete while child remains stopped");
                            assert!(child.0.try_reap().unwrap().is_none());
                            owner = Some(match owner.take().unwrap().into_stopped_parts() {
                                Err(retained) => retained,
                                Ok(_) => panic!("HAL ACK cannot surrender pending journal custody"),
                            });
                        }
                        signal(child.0.id(), "-CONT");
                        cx.waker().wake_by_ref();
                    }
                    result
                }),
            )
            .await
            .expect("bounded child completion")
            .unwrap()
        });
        let mut owner = owner.expect("pending owner recovered after every refused handoff");
        assert!(observed_stall);
        if cancel {
            assert!(matches!(
                result.step.control,
                Err(franken_control::channel::pipeline::PendingStepFailure::FenceChanged { .. })
            ));
        } else {
            assert!(matches!(
                result.step.control.unwrap()[0].outcome,
                Outcome::Committed { revision: 1 }
            ));
            owner.request_stop().unwrap();
        }
        owner
    };
    if fail_stop {
        let mut timing = ScriptedTiming::default();
        let mut terminal = false;
        for _ in 0..20 {
            if let DrainProgress::Finished(report) = owner.drain_tick(&mut timing).unwrap() {
                assert!(
                    !report.acknowledged,
                    "HAL mute failure must not become a flush ACK"
                );
                terminal = true;
                break;
            }
        }
        assert!(terminal);
        let owner = match owner.into_stopped_parts() {
            Err(owner) => owner,
            Ok(_) => panic!("faulted, unacknowledged HAL must retain complete owner"),
        };
        // The HTTP result already proves the journal transaction finished.
        // Explicitly reap this fixture's child while preserving the faulted
        // owner; production cannot extract/reopen or claim hardware recovery.
        child.0.shutdown_off_loop(Duration::from_secs(2)).unwrap();
        drop(owner);
        return;
    }
    let mut timing = ScriptedTiming::default();
    let mut acknowledged = false;
    for _ in 0..20 {
        if let DrainProgress::Finished(report) = owner.drain_tick(&mut timing).unwrap() {
            assert!(report.acknowledged);
            acknowledged = true;
            break;
        }
    }
    assert!(acknowledged);
    assert!(
        !stop_failure.get(),
        "only successful mute cases reach acknowledged handoff"
    );
    let Ok(parts) = owner.into_stopped_parts() else {
        panic!("settled HAL and journal custody can transfer");
    };
    assert_eq!(
        parts.session.group_master_volume,
        if cancel {
            50
        } else if (http && !replaced_mailbox) || automatic_datagram {
            70
        } else {
            60
        }
    );
    assert_eq!(parts.render.render_state(), RenderState::Stopped);
    let committed_revision = parts.session.state_revision;
    let mut storage = parts.control.into_storage();
    runtime.block_on(async {
        let context = asupersync::cx::Cx::current().unwrap();
        assert!(context.timer_driver().is_some());
        asupersync::time::timeout(
            context.now(),
            Duration::from_secs(3),
            poll_fn(|cx| storage.poll_quiesce(cx)),
        )
        .await
        .expect("bounded worker quiescence")
        .unwrap();
    });
    child.0.shutdown_off_loop(Duration::from_secs(2)).unwrap();
    drop(storage);
    let (journal, _) =
        franken_journal::Journal::open(FileMedium::open_existing(&path, &limits).unwrap(), limits)
            .unwrap();
    if http {
        // Legacy SOAP explicitly uses unstable retry IDs. It persists revision
        // highwater, not an authenticated per-peer sequence floor.
        assert!(!journal.state().records.contains_key(b"n02.seq".as_slice()));
        if !cancel {
            assert_eq!(
                journal
                    .state()
                    .marks
                    .get(franken_control::channel::pipeline::HIGH_WATER_KEY),
                Some(&committed_revision)
            );
            assert!(committed_revision > 0);
        }
    } else {
        assert!(journal.state().records.contains_key(b"n02.seq".as_slice()));
    }
}
