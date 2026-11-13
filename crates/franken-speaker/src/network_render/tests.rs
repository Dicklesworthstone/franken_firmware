//! Offline network-to-protected-render tests. The socket is localhost and the
//! clock and retained HAL are scripted; none of these fixtures is a device.

use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::rc::Rc;
use std::sync::Arc;

use super::{
    FinalFeedbackConfig, FinalFeedbackOutcome, NetworkRender, NetworkRenderAdmission,
    NetworkRenderError, OwnerStep, PreparedPcm, TickMapping,
};
use franken_clock::group::{GroupClock, GroupClockConfig, ProbeResponse, StartSchedule};
use franken_dsp::StereoAudioBlock;
use franken_dsp::protection::{
    Admission as ProtectionAdmission, ProtectedBoardDsp, ProtectedOutput, synthetic_calibration_for,
};
use franken_dsp::resample::{DriftResampler, FrameSource, ResamplerConfig, SliceSource};
use franken_hal::abi::RawGeometry;
use franken_hal::backend::{FakeBackend, FakeConfig, FakeProbe};
use franken_hal::session::{HalSession, SessionConfig, StartPreconditions};
use franken_hal::slots::LeakLedger;
use franken_platform::abi::Abi;
use franken_platform::layer::PlatformLayer;
use franken_platform::ops::{KernelOps, Provenance, Timespec};
use franken_stream::carrier::{
    CarrierLimits, CarrierReceiver, CarrierSender, HostUdp, ReceiverLimits,
};
use franken_stream::playout::{
    BLOCK_FRAMES, BLOCK_PAYLOAD_BYTES, Decision, Outcome, PlayoutConfig, PlayoutProfile,
    frames_to_ns,
};
use franken_stream::{OutboundFrame, StreamId, StreamKey, StreamReceiver, StreamSender};

use crate::media_playout::{MediaPlayout, PreparedBlock, Release, synthetic_ledger};
use crate::net_carrier::MediaEndpoint;
use crate::render::{RenderConfig, RenderLoop, RenderState, ScriptedTiming};

const RENDER_FRAMES: usize = 64;
const CLOCK_ORIGIN: u64 = 100_000_000_000;

struct TestKernel {
    now: Rc<Cell<u64>>,
    fail: Rc<Cell<bool>>,
    advance_after_read_ns: Rc<Cell<u64>>,
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
        self.now.set(
            now.checked_add(self.advance_after_read_ns.get())
                .expect("test clock advance overflow"),
        );
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

fn profile() -> franken_board_profile::BoardProfile {
    franken_board_profile::synthetic_test_fixture_catalog()
        .into_iter()
        .find(|p| p.model_number == "S1")
        .unwrap()
}

fn dsp() -> ProtectedBoardDsp {
    let board = profile();
    let calibration = synthetic_calibration_for(&board);
    ProtectedBoardDsp::admit(
        &board,
        Some(&calibration),
        ProtectionAdmission::HostSimulation,
    )
}

fn renderer_with_phase(ratio_ppb: i32, advance: bool) -> (RenderLoop<FakeBackend>, FakeProbe) {
    renderer_with_policy(ratio_ppb, advance, false)
}

fn renderer_with_policy(
    ratio_ppb: i32,
    advance: bool,
    withhold_flush_ack: bool,
) -> (RenderLoop<FakeBackend>, FakeProbe) {
    let mut cfg = FakeConfig::retained();
    cfg.geometry = RawGeometry {
        ring_depth: 4,
        frames_per_block: 64,
        channels: 2,
        bytes_per_sample: 2,
    };
    cfg.completion_delay_ticks = 2;
    cfg.min_submission_lead_ticks = Some(6);
    cfg.flush_ack_delay_ticks = if withhold_flush_ack { None } else { Some(4) };
    let (backend, probe) = FakeBackend::new(cfg);
    probe.capture_submissions(512);
    let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2);
    let mut session = HalSession::open(profile(), backend, config).unwrap();
    session.prepare().unwrap();
    let mut resampler =
        DriftResampler::with_initial_ppb(ResamplerConfig::default(), ratio_ppb).unwrap();
    if advance {
        let samples = [0.25_f32; 4];
        let mut source = SliceSource::new(&samples, &samples).unwrap();
        let mut left = [0.0];
        let mut right = [0.0];
        assert_eq!(
            resampler
                .render(&mut source, &mut left, &mut right)
                .unwrap()
                .produced,
            1
        );
    }
    let mut render_config = RenderConfig::standard(RENDER_FRAMES);
    // Scripted scheduling window admits both sides of the group-clock
    // uncertainty; it is a test model, not a measured device deadline.
    render_config.window_ticks = 8;
    (
        RenderLoop::new(session, dsp(), resampler, render_config).unwrap(),
        probe,
    )
}

struct NetworkFixture {
    now: Rc<Cell<u64>>,
    fail: Rc<Cell<bool>>,
    platform: PlatformLayer<TestKernel>,
    clock: GroupClock,
    endpoint: MediaEndpoint<HostUdp>,
    socket: UdpSocket,
    sender: StreamSender,
    start_group_ns: u64,
}

fn network() -> NetworkFixture {
    network_with_authority(2_000_000_000)
}

fn network_with_authority(authority_after_start_ns: u64) -> NetworkFixture {
    let now = Rc::new(Cell::new(50_000_000));
    let fail = Rc::new(Cell::new(false));
    let kernel = TestKernel {
        now: Rc::clone(&now),
        fail: Rc::clone(&fail),
        advance_after_read_ns: Rc::new(Cell::new(0)),
    };
    let matrix = crate::guest_evidence::for_abi(Abi::PowerPc32).matrix();
    let platform = crate::platform_start::admit_test_layer(&matrix, kernel).unwrap();
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
        .set_authority(1, start_local_ns + authority_after_start_ns, now.get())
        .unwrap();
    let key = StreamKey::from_bytes([0x42; 32]);
    let stream = StreamId::new(0x5EED_5EED_0000_0001).unwrap();
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
        StreamReceiver::new(key.clone(), stream, 1),
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
    let endpoint = MediaEndpoint::new(receiver, media);
    NetworkFixture {
        now,
        fail,
        platform,
        clock,
        endpoint,
        socket: UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
        sender: StreamSender::new(key, stream, 1),
        start_group_ns,
    }
}

/// Known in-phase stereo values: the S1 fixture routes mid, so anti-phase
/// samples would incorrectly make a positive integration test silent.
fn signal(start: u64, frames: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(frames * 4);
    for i in 0..frames {
        let phase = (start + i as u64) % 101;
        let left = (phase as i16 - 50) * 220;
        let right = left / 2;
        bytes.extend_from_slice(&left.to_be_bytes());
        bytes.extend_from_slice(&right.to_be_bytes());
    }
    bytes
}

fn packet(sender: &mut StreamSender, block: u64, start: u64, frames: usize) -> Vec<u8> {
    let frame = block * BLOCK_FRAMES;
    let pts = start + frames_to_ns(frame);
    sender
        .send(OutboundFrame::media(
            frame,
            pts,
            pts - 5_333_333,
            signal(frame, frames),
        ))
        .unwrap()
}

type TestOwner = NetworkRender<HostUdp, TestKernel, FakeBackend>;

struct RunningFixture {
    owner: TestOwner,
    now: Rc<Cell<u64>>,
    fail: Rc<Cell<bool>>,
    socket: UdpSocket,
    address: SocketAddr,
    sender: StreamSender,
    start_group_ns: u64,
    start_local_ns: u64,
    probe: FakeProbe,
}

fn earliest_group_time(rig: &RunningFixture) -> u64 {
    let local = rig.now.get();
    let uncertainty = rig.owner.clock.report(local).uncertainty_ns.unwrap();
    rig.owner
        .clock
        .group_ns(local)
        .unwrap()
        .saturating_sub(uncertainty)
}

fn running(final_frame: u64) -> RunningFixture {
    running_with_ratio(final_frame, 0)
}

fn running_with_ratio(final_frame: u64, ratio_ppb: i32) -> RunningFixture {
    running_with_authority(final_frame, ratio_ppb, 2_000_000_000)
}

fn running_with_authority(
    final_frame: u64,
    ratio_ppb: i32,
    authority_after_start_ns: u64,
) -> RunningFixture {
    running_with_policy(final_frame, ratio_ppb, authority_after_start_ns, false)
}

fn running_with_policy(
    final_frame: u64,
    ratio_ppb: i32,
    authority_after_start_ns: u64,
    withhold_flush_ack: bool,
) -> RunningFixture {
    let net = network_with_authority(authority_after_start_ns);
    let (render, probe) = renderer_with_policy(ratio_ppb, false, withhold_flush_ack);
    let first = render.next_slot().expect("ready render slot");
    let q32_one = 1_i64 << 32;
    let step = u64::try_from(q32_one + i64::from(ratio_ppb) * q32_one / 1_000_000_000).unwrap();
    let mapping = TickMapping {
        anchor_tick: first.presentation_tick,
        anchor_group_ns: net.start_group_ns,
        ns_numerator: 1_000_000 * step,
        tick_denominator: 3 * (1_u64 << 32),
        uncertainty_ns: 0,
        presentation_tolerance_ns: 1,
    };
    let start_local_ns = net
        .clock
        .local_for_group(net.start_group_ns, net.now.get())
        .unwrap();
    let address = net.endpoint.carrier().media_addr().unwrap();
    let schedule = StartSchedule {
        epoch: 1,
        start_group_ns: net.start_group_ns,
    };
    let owner = NetworkRender::admit(
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
    .expect("admit valid local fixture");
    RunningFixture {
        owner,
        now: net.now,
        fail: net.fail,
        socket: net.socket,
        address,
        sender: net.sender,
        start_group_ns: net.start_group_ns,
        start_local_ns,
        probe,
    }
}

fn try_admission(
    capacity: usize,
    numerator: u64,
    keep_control: bool,
    anchor_offset_ns: u64,
) -> Result<TestOwner, NetworkRenderError> {
    try_admission_with_phase(capacity, numerator, keep_control, anchor_offset_ns, false)
}

fn try_admission_with_phase(
    capacity: usize,
    numerator: u64,
    keep_control: bool,
    anchor_offset_ns: u64,
    advanced: bool,
) -> Result<TestOwner, NetworkRenderError> {
    let net = network();
    let (render, _) = renderer_with_phase(0, advanced);
    let mapping = TickMapping {
        anchor_tick: render.next_slot().unwrap().presentation_tick,
        anchor_group_ns: net.start_group_ns + anchor_offset_ns,
        ns_numerator: numerator,
        tick_denominator: 3,
        uncertainty_ns: 0,
        presentation_tolerance_ns: 1,
    };
    let held = keep_control.then(|| render.control_port());
    let result = NetworkRender::admit(
        net.endpoint,
        net.platform,
        net.clock,
        render,
        NetworkRenderAdmission {
            schedule: StartSchedule {
                epoch: 1,
                start_group_ns: net.start_group_ns,
            },
            anchor_frame: 0,
            final_frame: 2 * BLOCK_FRAMES,
            mapping,
            capacity_frames: capacity,
            start: StartPreconditions {
                presentation_mapping_installed: true,
                safe_gain_installed: true,
            },
        },
    );
    drop(held);
    result
}

#[test]
fn admission_refuses_capacity_bad_mapping_and_shared_control() {
    assert!(matches!(
        try_admission(513, 1_000_000, false, 0),
        Err(NetworkRenderError::Configuration)
    ));
    assert!(matches!(
        try_admission(1025, 1_000_000, false, 0),
        Err(NetworkRenderError::Configuration)
    ));
    assert!(matches!(
        try_admission(514, 1_020_000, false, 0),
        Err(NetworkRenderError::Mapping)
    ));
    assert!(matches!(
        try_admission(514, 1_000_000, true, 0),
        Err(NetworkRenderError::Configuration)
    ));
    assert!(matches!(
        try_admission(514, 1_000_000, false, 2),
        Err(NetworkRenderError::Mapping)
    ));
    assert!(matches!(
        try_admission_with_phase(514, 1_000_000, false, 0, true),
        Err(NetworkRenderError::Configuration)
    ));
    assert!(try_admission(514, 1_000_000, false, 0).is_ok());
    assert!(try_admission(514, 1_000_001, false, 0).is_ok());
    println!("FFW_NETWORK_RENDER_ADMISSION: {{\"refused\":6,\"valid_admitted\":true}}");
}

#[test]
fn localhost_bad_mac_does_not_revoke_prepared_pcm() {
    let mut rig = running(2 * BLOCK_FRAMES);
    let first = packet(&mut rig.sender, 0, rig.start_group_ns, 256);
    rig.socket.send_to(&first, rig.address).unwrap();
    let report = rig.owner.poll().unwrap();
    assert_eq!((report.media_read, report.media_accepted), (1, 1));

    // Reach the first N04 cutoff, but stay before the synthetic device's first
    // release. No second PCM block is available yet, so no render is needed.
    rig.now.set(rig.start_local_ns - 10_500_000);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    rig.owner.step(&mut timing).unwrap();
    let queued = rig.owner.queued_frames();
    assert_eq!(queued, 256, "the admitted first block must be retained");

    let second = packet(&mut rig.sender, 1, rig.start_group_ns, 256);
    let mut damaged = second.clone();
    damaged[47] ^= 1; // N01 authenticated presentation timestamp.
    let body_start = franken_stream::HEADER_LEN_BYTES;
    let body_end = damaged.len() - franken_stream::AUTH_TAG_LEN_BYTES;
    damaged[body_start..body_end].fill(0x7f); // audibly distinct forged PCM, without a new tag.
    rig.socket.send_to(&damaged, rig.address).unwrap();
    let rejected = rig.owner.poll().unwrap();
    assert_eq!((rejected.media_read, rejected.media_accepted), (1, 0));
    assert_eq!(rig.owner.queued_frames(), queued);
    assert_eq!(rig.owner.verdicts().refused, 1);
    rig.socket.send_to(&second, rig.address).unwrap();
    let accepted = rig.owner.poll().unwrap();
    assert_eq!((accepted.media_read, accepted.media_accepted), (1, 1));
    assert_eq!(rig.owner.queued_frames(), queued);
    let mut complete = false;
    for step in 0..5000_u64 {
        rig.now
            .set(rig.start_local_ns - 10_500_000 + step * 100_000);
        match rig
            .owner
            .step(&mut timing)
            .expect("bad MAC must not revoke valid audio")
        {
            OwnerStep::Complete => {
                complete = true;
                break;
            }
            OwnerStep::Waiting | OwnerStep::Tick(_) => {}
        }
    }
    assert!(
        complete,
        "the same owner must finish after the rejected packet"
    );
    let (expected, expected_frames) = expected_protected(&signal(0, 512), 0);
    assert_eq!(expected_frames, 512);
    let actual = rig.probe.captured_submissions();
    assert_eq!(
        actual, expected,
        "valid PCM after bad MAC must reach the protected HAL in order"
    );
    assert!(actual.iter().flatten().any(|byte| *byte != 0));
    assert_eq!(rig.owner.received_frames_pulled(), 512);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    println!(
        "FFW_NETWORK_RENDER_AUTH: {{\"bad_mac\":1,\"queued_preserved\":{queued},\"valid_successor\":1,\"protected_frames\":{expected_frames}}}"
    );
}

#[test]
fn clock_fault_clears_queued_pcm_and_requires_a_fresh_owner() {
    let mut rig = running(2 * BLOCK_FRAMES);
    let wire = packet(&mut rig.sender, 0, rig.start_group_ns, 256);
    rig.socket.send_to(&wire, rig.address).unwrap();
    assert_eq!(rig.owner.poll().unwrap().media_accepted, 1);
    rig.now.set(rig.start_local_ns - 10_500_000);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    rig.owner.step(&mut timing).unwrap();
    assert_eq!(rig.owner.queued_frames(), 256);
    assert_eq!(rig.probe.pending(), 0);
    rig.fail.set(true);
    assert!(matches!(
        rig.owner.step(&mut timing),
        Err(NetworkRenderError::Clock)
    ));
    assert_eq!(rig.owner.queued_frames(), 0);
    assert_eq!(rig.probe.pending(), 0);
    rig.fail.set(false);
    assert!(matches!(
        rig.owner.step(&mut timing),
        Err(NetworkRenderError::Ended)
    ));

    let mut fresh = running(2 * BLOCK_FRAMES);
    let recovered = packet(&mut fresh.sender, 0, fresh.start_group_ns, 256);
    fresh.socket.send_to(&recovered, fresh.address).unwrap();
    assert_eq!(fresh.owner.poll().unwrap().media_accepted, 1);
    fresh.now.set(fresh.start_local_ns - 10_500_000);
    fresh.owner.step(&mut timing).unwrap();
    assert_eq!(fresh.owner.queued_frames(), 256);
    let (recovered_frames, _) = exercise_finite_stream(512, 0);
    assert_eq!(recovered_frames, 512);
    println!(
        "FFW_NETWORK_RENDER_CLOCK: {{\"cleared\":256,\"fresh_accepted\":1,\"fresh_frames\":{recovered_frames}}}"
    );
}

#[test]
fn authority_expiry_invalidates_queued_audio() {
    let mut rig = running_with_authority(2 * BLOCK_FRAMES, 0, 10_000_000);
    let wire = packet(&mut rig.sender, 0, rig.start_group_ns, 256);
    rig.socket.send_to(&wire, rig.address).unwrap();
    assert_eq!(rig.owner.poll().unwrap().media_accepted, 1);
    rig.now.set(rig.start_local_ns - 10_500_000);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    rig.owner.step(&mut timing).unwrap();
    assert_eq!(rig.owner.queued_frames(), 256);
    rig.now.set(rig.start_local_ns + 10_000_000);
    assert!(matches!(
        rig.owner.step(&mut timing),
        Err(NetworkRenderError::Clock)
    ));
    assert_eq!(rig.owner.queued_frames(), 0);
    assert!(rig.probe.captured_submissions().is_empty());
    println!("FFW_NETWORK_RENDER_AUTHORITY: {{\"expired\":true,\"submitted\":0}}");
}

#[test]
fn a_missed_preparation_deadline_never_submits_late_pcm() {
    let mut rig = running(2 * BLOCK_FRAMES);
    let wire = packet(&mut rig.sender, 0, rig.start_group_ns, 256);
    rig.socket.send_to(&wire, rig.address).unwrap();
    assert_eq!(rig.owner.poll().unwrap().media_accepted, 1);
    rig.now.set(rig.start_local_ns + 50_000_000);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    assert!(matches!(
        rig.owner.step(&mut timing),
        Err(NetworkRenderError::Timeline)
    ));
    assert!(rig.probe.captured_submissions().is_empty());
    assert_eq!(rig.probe.pending(), 0);
    println!("FFW_NETWORK_RENDER_LATE: {{\"refused\":true,\"submitted\":0}}");
}

#[test]
fn a_missed_mapped_render_deadline_cancels_prepared_pcm() {
    let mut rig = running(2 * BLOCK_FRAMES);
    let wire = packet(&mut rig.sender, 0, rig.start_group_ns, 256);
    rig.socket.send_to(&wire, rig.address).unwrap();
    assert_eq!(rig.owner.poll().unwrap().media_accepted, 1);
    rig.now.set(rig.start_local_ns - 10_500_000);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    rig.owner.step(&mut timing).unwrap();
    assert_eq!(
        rig.owner.queued_frames(),
        256,
        "whole-block handoff was timely"
    );
    // The admitted fake HAL requires 2 ms of lead. This is after its mapped
    // deadline even though the N01 presentation itself is still ahead.
    rig.now.set(rig.start_local_ns - 1_000_000);
    assert!(matches!(
        rig.owner.step(&mut timing),
        Err(NetworkRenderError::Timeline)
    ));
    assert_eq!(rig.owner.queued_frames(), 0);
    assert!(rig.probe.captured_submissions().is_empty());
    println!("FFW_NETWORK_RENDER_PIECE_LATE: {{\"timely_handoff\":true,\"submitted\":0}}");
}

#[test]
fn clock_fault_during_busy_block_keeps_submitted_dma_until_flush_ack() {
    use crate::render::RenderState;
    use franken_hal::backend::FakeCall;

    let mut rig = running(3 * BLOCK_FRAMES);
    // The backend still owns submitted blocks; normal completion is withheld.
    rig.probe.set_lose_completions(true);
    for block in 0..3 {
        let wire = packet(&mut rig.sender, block, rig.start_group_ns, 256);
        rig.socket.send_to(&wire, rig.address).unwrap();
        assert_eq!(rig.owner.poll().unwrap().media_accepted, 1);
    }
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    let mut reached = false;
    for step in 0..1000_u64 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        rig.owner
            .step(&mut timing)
            .expect("live source must remain admitted");
        if rig.probe.pending() > 0 && rig.owner.block_in_progress() {
            reached = true;
            break;
        }
    }
    assert!(
        reached,
        "must observe actual submitted custody and a later busy block"
    );
    let held = rig.probe.pending();
    let submitted = rig.probe.captured_submissions().len();
    assert!(held > 0 && submitted > 0);
    rig.fail.set(true);
    assert!(matches!(
        rig.owner.step(&mut timing),
        Err(NetworkRenderError::Clock)
    ));
    assert_eq!(rig.owner.queued_frames(), 0);
    assert_eq!(rig.owner.render_state(), RenderState::Draining);
    assert_eq!(
        rig.probe.pending(),
        held,
        "software cancellation is not DMA completion"
    );
    assert_eq!(
        rig.probe.captured_submissions().len(),
        submitted,
        "busy block must not be submitted after fault"
    );
    assert!(
        rig.probe
            .calls()
            .iter()
            .any(|call| matches!(call, FakeCall::RequestFlush))
    );
    for _ in 0..2 {
        rig.owner.drain_tick(&mut timing).unwrap();
        assert_eq!(
            rig.probe.pending(),
            held,
            "unacknowledged DMA must remain held"
        );
    }
    for _ in 0..8 {
        if rig.owner.render_state() != RenderState::Draining {
            break;
        }
        rig.owner.drain_tick(&mut timing).unwrap();
    }
    assert_eq!(rig.owner.render_state(), RenderState::Stopped);
    assert_eq!(
        rig.probe.pending(),
        0,
        "fake flush acknowledgment retires its own buffers"
    );
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    assert_eq!(rig.probe.captured_submissions().len(), submitted);
    println!(
        "FFW_NETWORK_RENDER_CUSTODY: {{\"held_before_ack\":{held},\"after_ack\":0,\"busy_resubmitted\":false}}"
    );
}

#[test]
fn finite_eof_waits_for_scheduled_end_after_early_dma_completion() {
    use crate::render::RenderState;
    use franken_hal::backend::FakeCall;

    let mut rig = running(64);
    let wire = packet(&mut rig.sender, 0, rig.start_group_ns, 64);
    rig.socket.send_to(&wire, rig.address).unwrap();
    assert_eq!(rig.owner.poll().unwrap().media_accepted, 1);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    let mut completion_step = None;
    for step in 0..1000_u64 {
        let now = rig.start_local_ns - 15_000_000 + step * 100_000;
        rig.now.set(now);
        match rig.owner.step(&mut timing).expect("valid finite source") {
            OwnerStep::Complete => {
                panic!("DMA completion cannot end the source before presentation")
            }
            OwnerStep::Waiting | OwnerStep::Tick(_) => {}
        }
        if rig.probe.captured_submissions().len() == 1 && rig.probe.pending() == 0 {
            assert!(
                now < rig.start_local_ns,
                "the fake completion must precede scheduled presentation"
            );
            assert_eq!(rig.owner.render_state(), RenderState::Running);
            assert_eq!(rig.owner.in_flight(), 0, "the HAL completion was handled");
            assert!(earliest_group_time(&rig) < rig.start_group_ns + frames_to_ns(64));
            assert!(
                !rig.probe
                    .calls()
                    .iter()
                    .any(|call| matches!(call, FakeCall::RequestFlush)),
                "DMA completion alone must not mute the still-scheduled block"
            );
            completion_step = Some(step);
            break;
        }
    }
    let first = completion_step.expect("must observe early completion before presentation");
    let mut complete = false;
    let mut first_flush_earliest = None;
    for step in first + 1..5000_u64 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        let outcome = rig
            .owner
            .step(&mut timing)
            .expect("finite EOF must complete after scheduled end");
        if first_flush_earliest.is_none()
            && rig
                .probe
                .calls()
                .iter()
                .any(|call| matches!(call, FakeCall::RequestFlush))
        {
            first_flush_earliest = Some(earliest_group_time(&rig));
        }
        match outcome {
            OwnerStep::Complete => {
                complete = true;
                break;
            }
            OwnerStep::Waiting | OwnerStep::Tick(_) => {}
        }
    }
    assert!(complete);
    assert!(
        first_flush_earliest.expect("finite EOF must request a flush")
            >= rig.start_group_ns + frames_to_ns(64),
        "the first flush must not precede the admitted presentation end"
    );
    assert!(earliest_group_time(&rig) >= rig.start_group_ns + frames_to_ns(64));
    assert!(
        rig.probe
            .calls()
            .iter()
            .any(|call| matches!(call, FakeCall::RequestFlush))
    );
    let (expected, count) = expected_protected(&signal(0, 64), 0);
    assert_eq!(count, 64);
    assert_eq!(rig.probe.captured_submissions(), expected);
    assert_eq!(rig.probe.use_after_free(), 0);
    println!(
        "FFW_NETWORK_RENDER_EOF_EARLY_DMA: {{\"early_completion\":true,\"scheduled_end_observed\":true,\"frames\":{count}}}"
    );
}

#[test]
fn finite_eof_lost_completion_and_flush_ack_faults_without_freeing_dma() {
    use crate::render::{FaultReason, RenderState};
    use franken_hal::backend::FakeCall;
    use franken_hal::slots::SlotState;

    let mut rig = running_with_policy(64, 0, 2_000_000_000, true);
    rig.probe.set_lose_completions(true);
    let wire = packet(&mut rig.sender, 0, rig.start_group_ns, 64);
    rig.socket.send_to(&wire, rig.address).unwrap();
    assert_eq!(rig.owner.poll().unwrap().media_accepted, 1);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    let mut observed_fault = false;
    let mut flush_earliest = None;
    let mut flush_tick = None;
    let stop_deadline_ticks = rig.owner.render.session().stop_deadline_ticks().unwrap();
    assert_eq!(
        stop_deadline_ticks, 8,
        "the fixture admits an eight-tick stop deadline"
    );
    for step in 0..5000_u64 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        let result = rig.owner.step(&mut timing);
        if flush_earliest.is_none()
            && rig
                .probe
                .calls()
                .iter()
                .any(|call| matches!(call, FakeCall::RequestFlush))
        {
            flush_earliest = Some(earliest_group_time(&rig));
            flush_tick = Some(rig.probe.tick());
        }
        match result {
            Err(NetworkRenderError::Preparation) => {
                observed_fault = true;
                break;
            }
            Err(other) => panic!("unexpected EOF failure: {other:?}"),
            Ok(OwnerStep::Complete) => {
                panic!("lost completion and missing flush ACK cannot complete")
            }
            Ok(OwnerStep::Waiting | OwnerStep::Tick(_)) => {}
        }
    }
    assert!(observed_fault, "EOF must reach a bounded drain fault");
    assert!(
        flush_earliest.expect("EOF must request a flush") >= rig.start_group_ns + frames_to_ns(64),
        "EOF must not mute before the admitted presentation end"
    );
    assert!(
        rig.probe
            .calls()
            .iter()
            .any(|call| matches!(call, FakeCall::RequestFlush))
    );
    assert_eq!(rig.owner.render_state(), RenderState::Faulted);
    assert_eq!(rig.owner.render.fault(), Some(FaultReason::DrainTimedOut));
    let elapsed_ticks = rig
        .probe
        .tick()
        .checked_sub(flush_tick.expect("flush tick"))
        .expect("fake device clock must remain monotone");
    assert!(
        elapsed_ticks > 0 && elapsed_ticks <= stop_deadline_ticks + 1,
        "flush-to-fault took {elapsed_ticks} ticks; bound is {}",
        stop_deadline_ticks + 1
    );
    assert_eq!(
        rig.probe.pending(),
        1,
        "the fake device still holds its DMA view"
    );
    assert!(
        rig.owner
            .render
            .session()
            .slot_states()
            .contains(&SlotState::Quarantined),
        "the unacknowledged slot must be quarantined, not freed"
    );
    assert_eq!(
        rig.probe.kernel_touch_pending(),
        (1, 0),
        "fake kernel must still read the owned storage"
    );
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    let (expected, count) = expected_protected(&signal(0, 64), 0);
    assert_eq!(count, 64);
    assert_eq!(rig.probe.captured_submissions(), expected);
    println!(
        "FFW_NETWORK_RENDER_EOF_LOST_ACK: {{\"bounded_fault\":true,\"flush_to_fault_ticks\":{elapsed_ticks},\"stop_deadline_ticks\":{stop_deadline_ticks},\"dma_pending\":1,\"quarantined\":true}}"
    );
}

fn exercise_finite_stream(frames: usize, ratio_ppb: i32) -> (usize, usize) {
    let mut rig = running_with_ratio(frames as u64, ratio_ppb);
    let mut block = 0_u64;
    let mut remaining = frames;
    while remaining > 0 {
        let this = remaining.min(BLOCK_FRAMES as usize);
        let wire = packet(&mut rig.sender, block, rig.start_group_ns, this);
        rig.socket.send_to(&wire, rig.address).unwrap();
        let polled = rig.owner.poll().unwrap();
        assert_eq!((polled.media_read, polled.media_accepted), (1, 1));
        remaining -= this;
        block += 1;
    }
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    let mut finished = false;
    for step in 0..5000_u64 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        match rig
            .owner
            .step(&mut timing)
            .expect("finite stream must stay admitted")
        {
            OwnerStep::Complete => {
                finished = true;
                break;
            }
            OwnerStep::Waiting | OwnerStep::Tick(_) => {}
        }
    }
    assert!(
        finished,
        "finite source must terminate within the bounded clock schedule"
    );
    let (expected, expected_frames) = expected_protected(&signal(0, frames), ratio_ppb);
    let actual = rig.probe.captured_submissions();
    assert_eq!(rig.owner.received_frames_pulled(), frames as u64);
    assert_eq!(rig.owner.timeline_silence_pulled(), 0);
    assert!(
        rig.owner.final_padding_pulled() <= 2,
        "source lookahead exceeded explicit finite bound"
    );
    assert_eq!(
        actual, expected,
        "protected PCM differs or tail has wrong duration"
    );
    assert!(
        actual.iter().flatten().any(|byte| *byte != 0),
        "protected signal is silent"
    );
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    (expected_frames, actual.len())
}

#[test]
fn localhost_full_and_partial_tail_match_independent_protected_output() {
    let full = exercise_finite_stream(512, 0);
    let partial = exercise_finite_stream(2 * 256 + 37, 0);
    println!(
        "FFW_NETWORK_RENDER_PCM: {{\"full_frames\":{},\"full_blocks\":{},\"partial_frames\":{},\"partial_blocks\":{}}}",
        full.0, full.1, partial.0, partial.1
    );
}

#[test]
fn localhost_finite_tail_keeps_both_drift_signs() {
    // Long enough to force different output lengths at +/-500 ppm, with no
    // assumed rounded count; a separate D03 instance computes the reference.
    let negative = exercise_finite_stream(8192, -500_000);
    let zero = exercise_finite_stream(8192, 0);
    let positive = exercise_finite_stream(8192, 500_000);
    assert!(
        negative.0 > zero.0 && zero.0 > positive.0,
        "both drift signs must affect the finite real stream: {negative:?} {zero:?} {positive:?}"
    );
    println!(
        "FFW_NETWORK_RENDER_DRIFT: {{\"negative_frames\":{},\"zero_frames\":{},\"positive_frames\":{}}}",
        negative.0, zero.0, positive.0
    );
}

/// Independent run of the same admitted D03 and D02 stages; compares actual
/// retained-HAL submissions to protected output, not to unprocessed N01 PCM.
fn expected_protected(pcm: &[u8], ratio_ppb: i32) -> (Vec<Vec<u8>>, usize) {
    let mut left = Vec::new();
    let mut right = Vec::new();
    for frame in pcm.as_chunks::<4>().0 {
        left.push(f32::from(i16::from_be_bytes([frame[0], frame[1]])) / 32768.0);
        right.push(f32::from(i16::from_be_bytes([frame[2], frame[3]])) / 32768.0);
    }
    // Explicit end-of-stream adds exactly D03's two lookahead frames. The
    // independent renderer zero-pads only the final device block after D03
    // stops; it does not add more source samples.
    left.extend([0.0; 2]);
    right.extend([0.0; 2]);
    let mut source = SliceSource::new(&left, &right).unwrap();
    let mut resampler =
        DriftResampler::with_initial_ppb(ResamplerConfig::default(), ratio_ppb).unwrap();
    let mut dsp = dsp();
    dsp.set_muted(false).unwrap();
    let mut block = StereoAudioBlock::silence(0);
    let mut output = ProtectedOutput::new();
    let mut all = Vec::new();
    let mut emitted_frames = 0;
    for index in 0..(pcm.len() / 4 + 1) {
        let result = resampler
            .render(
                &mut source,
                &mut block.left[..RENDER_FRAMES],
                &mut block.right[..RENDER_FRAMES],
            )
            .unwrap();
        if result.produced == 0 {
            return (all, emitted_frames);
        }
        emitted_frames += result.produced;
        block.left[result.produced..RENDER_FRAMES].fill(0.0);
        block.right[result.produced..RENDER_FRAMES].fill(0.0);
        block.frames = RENDER_FRAMES;
        block.start_frame = (index * RENDER_FRAMES) as u64;
        dsp.render_into(&block, &mut output);
        let mut bytes = Vec::new();
        for frame in 0..RENDER_FRAMES {
            for lane in output.samples.iter().take(2) {
                bytes.extend_from_slice(&lane[frame].to_be_bytes());
            }
        }
        all.push(bytes);
        if result.underrun {
            return (all, emitted_frames);
        }
    }
    panic!("reference resampler failed to reach the finite source boundary");
}

fn prepared(block: u64, frames: u16, start_ns: u64) -> PreparedBlock {
    let presentation_ns = start_ns + frames_to_ns(block * BLOCK_FRAMES);
    PreparedBlock {
        decision: Decision {
            block,
            outcome: Outcome::Real,
            presentation_ns,
            frames,
            gap_before_ns: 0,
            submit_deadline_ns: presentation_ns - 1_000_000,
            late_by_ns: 0,
        },
        release: Release::Armed { starts_in_ns: 1 },
    }
}

fn pcm_block(block: u64, frames: usize) -> [u8; BLOCK_PAYLOAD_BYTES] {
    let mut out = [0; BLOCK_PAYLOAD_BYTES];
    let bytes = signal(block * BLOCK_FRAMES, frames);
    out[..bytes.len()].copy_from_slice(&bytes);
    out
}

#[test]
fn queue_refusals_preserve_valid_pcm_and_allow_the_valid_successor() {
    let start = CLOCK_ORIGIN + 1_000_000_000;
    let mut q = PreparedPcm::new(514, 0, 3 * BLOCK_FRAMES, start);
    q.offer(prepared(0, 256, start), &pcm_block(0, 256))
        .unwrap();
    let mut wrong = prepared(1, 256, start);
    wrong.decision.presentation_ns += 1;
    assert!(matches!(
        q.offer(wrong, &pcm_block(1, 256)),
        Err(NetworkRenderError::Timeline)
    ));
    wrong = prepared(1, 256, start);
    wrong.decision.gap_before_ns = 1;
    assert!(matches!(
        q.offer(wrong, &pcm_block(1, 256)),
        Err(NetworkRenderError::Timeline)
    ));
    assert!(matches!(
        q.offer(prepared(2, 64, start), &pcm_block(2, 64)),
        Err(NetworkRenderError::Timeline)
    ));
    assert_eq!(q.len, 256);
    q.offer(prepared(1, 256, start), &pcm_block(1, 256))
        .unwrap();
    assert!(matches!(
        q.offer(prepared(2, 256, start), &pcm_block(2, 256)),
        Err(NetworkRenderError::Capacity)
    ));
    assert_eq!(q.len, 512);
    for raw in signal(0, 256).as_chunks::<4>().0 {
        let frame = q.pull().unwrap();
        assert_eq!(
            frame[0],
            f32::from(i16::from_be_bytes([raw[0], raw[1]])) / 32768.0
        );
        assert_eq!(
            frame[1],
            f32::from(i16::from_be_bytes([raw[2], raw[3]])) / 32768.0
        );
    }
    q.offer(prepared(2, 256, start), &pcm_block(2, 256))
        .unwrap();
    assert_eq!(q.len, 512);
    println!("FFW_NETWORK_RENDER_QUEUE: {{\"rejected\":4,\"recovered\":true}}");
}

#[test]
fn queue_partial_payload_is_not_implicit_end_of_stream() {
    let start = CLOCK_ORIGIN + 1_000_000_000;
    let mut q = PreparedPcm::new(514, 0, 3 * BLOCK_FRAMES, start);
    q.offer(prepared(0, 64, start), &pcm_block(0, 64)).unwrap();
    assert_eq!(q.len, 256);
    for _ in 0..64 {
        assert!(q.pull().is_some());
    }
    for _ in 64..256 {
        assert_eq!(q.pull(), Some([0.0, 0.0]));
    }
    q.offer(prepared(1, 256, start), &pcm_block(1, 256))
        .unwrap();
    assert_eq!(q.len, 256);
    println!(
        "FFW_NETWORK_RENDER_PARTIAL: {{\"pcm_frames\":64,\"gap_frames\":192,\"next_block_accepted\":true}}"
    );
}

#[test]
fn queue_accepts_explicit_partial_final_frame() {
    let start = CLOCK_ORIGIN + 1_000_000_000;
    let mut q = PreparedPcm::new(514, 0, BLOCK_FRAMES + 37, start);
    q.offer(prepared(0, 256, start), &pcm_block(0, 256))
        .unwrap();
    q.offer(prepared(1, 37, start), &pcm_block(1, 37)).unwrap();
    assert_eq!(q.len, 293);
    assert!(matches!(
        q.offer(prepared(2, 1, start), &pcm_block(2, 1)),
        Err(NetworkRenderError::Timeline)
    ));
    println!("FFW_NETWORK_RENDER_FINAL: {{\"frames\":293,\"tail\":37}}");
}

/// A control may change the DSP target/state but not the stream, its next
/// deadline, resampler phase, owned DMA, or the device's accepted bytes.
#[derive(Debug, PartialEq)]
struct ControlContinuity {
    next: Option<crate::render::RenderSlot>,
    counters: crate::render::RenderCounters,
    queued: usize,
    next_source_frame: u64,
    real_pulled: u64,
    concealed_pulled: u64,
    silence_pulled: u64,
    padding_pulled: u64,
    in_flight: usize,
    pending: Vec<(u16, u32)>,
    accepted: Vec<Vec<u8>>,
    calls: Vec<franken_hal::backend::FakeCall>,
}

fn control_continuity(rig: &RunningFixture) -> ControlContinuity {
    ControlContinuity {
        next: rig.owner.render.next_slot(),
        counters: rig.owner.render_counters(),
        queued: rig.owner.queued_frames(),
        next_source_frame: rig.owner.pcm.next_frame,
        real_pulled: rig.owner.received_frames_pulled(),
        concealed_pulled: rig.owner.concealed_frames_pulled(),
        silence_pulled: rig.owner.timeline_silence_pulled(),
        padding_pulled: rig.owner.final_padding_pulled(),
        in_flight: rig.owner.in_flight(),
        pending: rig.probe.pending_slots(),
        accepted: rig.probe.captured_submissions(),
        calls: rig.probe.calls(),
    }
}

/// Empty the bounded render-event queue before the one synchronous control
/// call under test. A successful RenderLoop::unmute sets the D02 mute bit and
/// records Muted -> Running; a subsequent cancel cannot erase that transition.
fn begin_muted_observation(rig: &mut RunningFixture) -> (u64, u64, u64) {
    assert_eq!(rig.owner.render_state(), crate::render::RenderState::Muted);
    assert!(rig.owner.render.dsp().is_muted());
    while rig.owner.render.take_event().is_some() {}
    let c = rig.owner.render_counters();
    (c.events_dropped, c.events_evicted, c.events_lost_critical)
}

fn finish_muted_observation(
    rig: &mut RunningFixture,
    before: (u64, u64, u64),
    expected: crate::render::RenderEventKind,
    muted: bool,
) {
    let mut events = Vec::new();
    while let Some(event) = rig.owner.render.take_event() {
        events.push(event.kind);
    }
    let c = rig.owner.render_counters();
    assert_eq!(
        (c.events_dropped, c.events_evicted, c.events_lost_critical),
        before,
        "the bounded event queue must not hide a control transition"
    );
    assert_eq!(
        events,
        vec![expected],
        "unexpected ordered render control transitions"
    );
    assert_eq!(rig.owner.render.dsp().is_muted(), muted);
}

/// A separate D03/D02 chain from the same signed source, changing only the
/// intended DSP controls at block boundaries. No renderer or adapter state is
/// copied into the reference.
fn expected_volume_mute(pcm: &[u8]) -> (Vec<Vec<u8>>, usize) {
    let mut left = Vec::new();
    let mut right = Vec::new();
    for frame in pcm.as_chunks::<4>().0 {
        left.push(f32::from(i16::from_be_bytes([frame[0], frame[1]])) / 32768.0);
        right.push(f32::from(i16::from_be_bytes([frame[2], frame[3]])) / 32768.0);
    }
    left.extend([0.0; 2]);
    right.extend([0.0; 2]);
    let mut source = SliceSource::new(&left, &right).unwrap();
    let mut resampler = DriftResampler::new(ResamplerConfig::default()).unwrap();
    let mut dsp = dsp();
    dsp.set_muted(false).unwrap();
    let mut input = StereoAudioBlock::silence(0);
    let mut output = ProtectedOutput::new();
    let mut blocks = Vec::new();
    let mut frames = 0;
    for index in 0..(pcm.len() / 4 + 1) {
        let report = resampler
            .render(
                &mut source,
                &mut input.left[..RENDER_FRAMES],
                &mut input.right[..RENDER_FRAMES],
            )
            .unwrap();
        if report.produced == 0 {
            return (blocks, frames);
        }
        frames += report.produced;
        input.left[report.produced..RENDER_FRAMES].fill(0.0);
        input.right[report.produced..RENDER_FRAMES].fill(0.0);
        input.frames = RENDER_FRAMES;
        input.start_frame = (index * RENDER_FRAMES) as u64;
        match index {
            4 => {
                assert_eq!(dsp.set_user_gain(0.25), 0.25);
            }
            11 => dsp.set_muted(true).unwrap(),
            31 => dsp.set_muted(false).unwrap(),
            _ => {}
        }
        dsp.render_into(&input, &mut output);
        let mut bytes = Vec::with_capacity(RENDER_FRAMES * 4);
        for frame in 0..RENDER_FRAMES {
            for lane in output.samples.iter().take(2) {
                bytes.extend_from_slice(&lane[frame].to_be_bytes());
            }
        }
        blocks.push(bytes);
        if report.underrun {
            return (blocks, frames);
        }
    }
    panic!("reference did not reach finite source end");
}

#[test]
fn localhost_serialized_volume_and_mute_resume_match_independent_protected_pcm() {
    use crate::render::RenderState;

    let mut rig = running(4096);
    for block in 0..16_u64 {
        let wire = packet(&mut rig.sender, block, rig.start_group_ns, 256);
        rig.socket.send_to(&wire, rig.address).unwrap();
        assert_eq!(rig.owner.poll().unwrap().media_accepted, 1);
    }
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    let (mut gain_set, mut muted, mut resumed, mut complete) = (false, false, false, false);
    for step in 0..5000_u64 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        match rig
            .owner
            .step(&mut timing)
            .expect("live audio and controls stay admitted")
        {
            OwnerStep::Tick(report) => {
                if let Some(index) = report.started {
                    // Hold the previous block's actual retained DMA across each
                    // control, then restore normal completion immediately.
                    if matches!(index, 2 | 9 | 29) {
                        rig.probe.set_lose_completions(true);
                    }
                    if matches!(index, 3 | 10 | 30) {
                        assert!(
                            rig.owner.block_in_progress(),
                            "the current PCM block is already rendered"
                        );
                        assert!(
                            rig.probe.pending() > 0,
                            "a previous DMA block must still be held"
                        );
                        let before = control_continuity(&rig);
                        match index {
                            3 => {
                                assert_eq!(rig.owner.set_gain(0.25).unwrap(), 0.25);
                                gain_set = true;
                            }
                            10 => {
                                rig.owner.mute().unwrap();
                                assert_eq!(rig.owner.render_state(), RenderState::Muted);
                                assert!(rig.owner.render.dsp().is_muted());
                                muted = true;
                            }
                            30 => {
                                let events_before = begin_muted_observation(&mut rig);
                                rig.owner.unmute().unwrap();
                                assert_eq!(rig.owner.render_state(), RenderState::Running);
                                finish_muted_observation(
                                    &mut rig,
                                    events_before,
                                    crate::render::RenderEventKind::State {
                                        from: RenderState::Muted,
                                        to: RenderState::Running,
                                    },
                                    false,
                                );
                                resumed = true;
                            }
                            _ => unreachable!(),
                        }
                        assert_eq!(
                            control_continuity(&rig),
                            before,
                            "control changed busy PCM, source/phase or held DMA"
                        );
                        rig.probe.set_lose_completions(false);
                    }
                }
            }
            OwnerStep::Waiting => {}
            OwnerStep::Complete => {
                complete = true;
                break;
            }
        }
    }
    assert!(complete && gain_set && muted && resumed);
    let (expected, frames) = expected_volume_mute(&signal(0, 4096));
    let (untouched, _) = expected_protected(&signal(0, 4096), 0);
    let actual = rig.probe.captured_submissions();
    assert_eq!(frames, 4096);
    assert_eq!(
        actual, expected,
        "every post-DSP block must match the independent controlled stages"
    );
    assert_ne!(actual[10], untouched[10], "volume must affect real PCM");
    assert!(
        actual[25].iter().all(|byte| *byte == 0),
        "mute ramp must reach silence"
    );
    assert!(
        actual[55].iter().any(|byte| *byte != 0),
        "unmute must recover real PCM"
    );
    assert_eq!(rig.owner.received_frames_pulled(), 4096);
    assert_eq!(rig.owner.timeline_silence_pulled(), 0);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    let before = control_continuity(&rig);
    assert!(matches!(
        rig.owner.set_gain(1.0),
        Err(NetworkRenderError::Ended)
    ));
    assert!(matches!(rig.owner.mute(), Err(NetworkRenderError::Ended)));
    assert!(matches!(rig.owner.unmute(), Err(NetworkRenderError::Ended)));
    assert_eq!(control_continuity(&rig), before);
    println!(
        "FFW_NETWORK_RENDER_VOLUME: {{\"frames\":{frames},\"gain\":0.25,\"muted\":true,\"recovered\":true,\"busy_and_dma_preserved\":true}}"
    );
}

/// Reach a real, completed protected block and mute in the idle gap. The
/// caller may then invalidate authority or clock before attempting to unmute.
fn start_and_mute(rig: &mut RunningFixture, timing: &mut ScriptedTiming) {
    use crate::render::RenderState;

    for block in 0..2_u64 {
        let wire = packet(&mut rig.sender, block, rig.start_group_ns, 256);
        rig.socket.send_to(&wire, rig.address).unwrap();
        assert_eq!(rig.owner.poll().unwrap().media_accepted, 1);
    }
    for step in 0..1000_u64 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        if let OwnerStep::Tick(report) = rig.owner.step(timing).expect("reach first PCM block")
            && report.finished.is_some_and(|(index, _)| index == 0)
        {
            assert!(!rig.owner.block_in_progress());
            assert_eq!(rig.probe.captured_submissions().len(), 1);
            let before = control_continuity(rig);
            rig.owner.mute().unwrap();
            assert_eq!(rig.owner.render_state(), RenderState::Muted);
            assert_eq!(control_continuity(rig), before);
            return;
        }
    }
    panic!("did not reach a live completed block");
}

fn fake_unmutes(rig: &RunningFixture) -> usize {
    use franken_hal::backend::FakeCall;
    rig.probe
        .calls()
        .iter()
        .filter(|call| matches!(call, FakeCall::SetMute(false)))
        .count()
}

#[test]
fn mute_cannot_be_undone_after_a_clock_fault_and_fresh_owner_recovers() {
    use crate::render::RenderState;

    let mut rig = running(4096);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    start_and_mute(&mut rig, &mut timing);
    let accepted = rig.probe.captured_submissions();
    let held = rig.probe.pending_slots();
    assert!(!held.is_empty(), "the fake must still hold submitted DMA");
    let unmutes = fake_unmutes(&rig);
    let events_before = begin_muted_observation(&mut rig);
    rig.fail.set(true);
    assert!(matches!(rig.owner.unmute(), Err(NetworkRenderError::Clock)));
    finish_muted_observation(
        &mut rig,
        events_before,
        crate::render::RenderEventKind::State {
            from: RenderState::Muted,
            to: RenderState::Draining,
        },
        true,
    );
    assert!(matches!(
        rig.owner.clock.output(rig.now.get()),
        franken_clock::group::Output::Muted(franken_clock::group::MuteReason::ClockFault)
    ));
    assert_eq!(rig.owner.render_state(), RenderState::Draining);
    assert_eq!(rig.owner.queued_frames(), 0);
    assert_eq!(
        rig.probe.captured_submissions(),
        accepted,
        "fault must not submit stale audio"
    );
    assert_eq!(
        rig.probe.pending_slots(),
        held,
        "unacknowledged DMA remains held"
    );
    assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
    assert_eq!(
        fake_unmutes(&rig),
        unmutes,
        "fault must not unmute the fake HAL"
    );
    rig.fail.set(false);
    assert!(matches!(rig.owner.unmute(), Err(NetworkRenderError::Ended)));
    assert!(matches!(
        rig.owner.set_gain(0.5),
        Err(NetworkRenderError::Ended)
    ));
    assert!(matches!(rig.owner.mute(), Err(NetworkRenderError::Ended)));
    assert_eq!(rig.probe.captured_submissions(), accepted);
    assert_eq!(fake_unmutes(&rig), unmutes);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    let (fresh_frames, _) = exercise_finite_stream(512, 0);
    assert_eq!(
        fresh_frames, 512,
        "a newly admitted owner must render valid PCM"
    );
    println!(
        "FFW_NETWORK_RENDER_CONTROL_CLOCK: {{\"unmute_refused\":true,\"stale_submissions\":0,\"fresh_frames\":{fresh_frames}}}"
    );
}

fn start_busy_and_mute(rig: &mut RunningFixture, timing: &mut ScriptedTiming) {
    use crate::render::RenderState;

    for block in 0..2_u64 {
        let wire = packet(&mut rig.sender, block, rig.start_group_ns, 256);
        rig.socket.send_to(&wire, rig.address).unwrap();
        assert_eq!(rig.owner.poll().unwrap().media_accepted, 1);
    }
    for step in 0..1000_u64 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        if let OwnerStep::Tick(report) = rig.owner.step(timing).expect("live source") {
            if report.started == Some(0) {
                rig.probe.set_lose_completions(true);
            }
            if report.started == Some(1) {
                assert!(rig.owner.block_in_progress());
                assert!(
                    rig.probe.pending() > 0,
                    "earlier PCM must still be owned by the fake device"
                );
                let before = control_continuity(rig);
                rig.owner.mute().unwrap();
                assert_eq!(rig.owner.render_state(), RenderState::Muted);
                assert_eq!(control_continuity(rig), before);
                return;
            }
        }
    }
    panic!("must exercise the busy control with real held PCM");
}

#[test]
fn clock_fault_during_busy_control_discards_busy_pcm_but_keeps_held_dma() {
    use crate::render::RenderState;

    let mut rig = running(4096);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    start_busy_and_mute(&mut rig, &mut timing);
    let accepted = rig.probe.captured_submissions();
    let held = rig.probe.pending_slots();
    let unmutes = fake_unmutes(&rig);
    let events_before = begin_muted_observation(&mut rig);
    rig.fail.set(true);
    assert!(matches!(rig.owner.unmute(), Err(NetworkRenderError::Clock)));
    finish_muted_observation(
        &mut rig,
        events_before,
        crate::render::RenderEventKind::State {
            from: RenderState::Muted,
            to: RenderState::Draining,
        },
        true,
    );
    assert_eq!(rig.owner.render_state(), RenderState::Draining);
    assert!(
        !rig.owner.block_in_progress(),
        "invalidation must discard the rendered busy block"
    );
    assert_eq!(rig.owner.queued_frames(), 0);
    assert_eq!(
        rig.probe.captured_submissions(),
        accepted,
        "busy PCM must not be submitted after fault"
    );
    assert_eq!(
        rig.probe.pending_slots(),
        held,
        "already submitted DMA remains owned until acknowledgment"
    );
    assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
    assert_eq!(fake_unmutes(&rig), unmutes);
    for _ in 0..2 {
        rig.owner.drain_tick(&mut timing).unwrap();
        assert_eq!(rig.probe.pending_slots(), held);
    }
    for _ in 0..8 {
        if rig.owner.render_state() != RenderState::Draining {
            break;
        }
        rig.owner.drain_tick(&mut timing).unwrap();
    }
    assert_eq!(rig.owner.render_state(), RenderState::Stopped);
    assert_eq!(rig.probe.pending(), 0);
    assert_eq!(rig.probe.captured_submissions(), accepted);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    println!(
        "FFW_NETWORK_RENDER_CONTROL_BUSY_FAULT: {{\"held_before_ack\":{},\"stale_submissions\":0}}",
        held.len()
    );
}

#[test]
fn expired_busy_deadline_refuses_unmute_and_cancels_without_losing_dma() {
    use crate::render::RenderState;

    let mut rig = running(4096);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    start_busy_and_mute(&mut rig, &mut timing);
    let accepted = rig.probe.captured_submissions();
    let held = rig.probe.pending_slots();
    let unmutes = fake_unmutes(&rig);
    let events_before = begin_muted_observation(&mut rig);
    let deadline = rig.owner.busy_deadline_ns.expect("active busy deadline");
    let late_group = deadline.checked_add(2_000_000).unwrap();
    let late_local = rig
        .owner
        .clock
        .local_for_group(late_group, rig.now.get())
        .unwrap();
    assert!(late_local > rig.now.get());
    rig.now.set(late_local);
    assert!(
        matches!(
            rig.owner.clock.output(rig.now.get()),
            franken_clock::group::Output::Armed { .. } | franken_clock::group::Output::Audible
        ),
        "the clock must remain usable; this is a deadline refusal"
    );
    assert!(matches!(
        rig.owner.unmute(),
        Err(NetworkRenderError::Timeline)
    ));
    finish_muted_observation(
        &mut rig,
        events_before,
        crate::render::RenderEventKind::State {
            from: RenderState::Muted,
            to: RenderState::Draining,
        },
        true,
    );
    assert_eq!(rig.owner.render_state(), RenderState::Draining);
    assert!(!rig.owner.block_in_progress());
    assert_eq!(rig.owner.queued_frames(), 0);
    assert_eq!(rig.probe.captured_submissions(), accepted);
    assert_eq!(rig.probe.pending_slots(), held);
    assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
    assert_eq!(fake_unmutes(&rig), unmutes);
    assert!(matches!(rig.owner.unmute(), Err(NetworkRenderError::Ended)));
    assert_eq!(fake_unmutes(&rig), unmutes);
    for _ in 0..2 {
        rig.owner.drain_tick(&mut timing).unwrap();
        assert_eq!(
            rig.probe.pending_slots(),
            held,
            "DMA must remain held before flush ACK"
        );
    }
    for _ in 0..8 {
        if rig.owner.render_state() != RenderState::Draining {
            break;
        }
        rig.owner.drain_tick(&mut timing).unwrap();
    }
    assert_eq!(rig.owner.render_state(), RenderState::Stopped);
    assert_eq!(
        rig.probe.pending(),
        0,
        "only the actual flush ACK retires the held DMA"
    );
    assert_eq!(rig.probe.captured_submissions(), accepted);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    println!(
        "FFW_NETWORK_RENDER_CONTROL_DEADLINE: {{\"refused\":true,\"held_dma\":{},\"stale_submissions\":0}}",
        held.len()
    );
}

#[test]
fn mute_cannot_be_undone_after_authority_expiry() {
    use crate::render::RenderState;

    let mut rig = running_with_authority(4096, 0, 10_000_000);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    start_and_mute(&mut rig, &mut timing);
    let accepted = rig.probe.captured_submissions();
    let held = rig.probe.pending_slots();
    assert!(!held.is_empty(), "the fake must still hold submitted DMA");
    let unmutes = fake_unmutes(&rig);
    let events_before = begin_muted_observation(&mut rig);
    rig.now.set(rig.start_local_ns + 10_000_000);
    assert!(matches!(
        rig.owner.clock.output(rig.now.get()),
        franken_clock::group::Output::Muted(franken_clock::group::MuteReason::AuthorityExpired)
    ));
    assert!(matches!(rig.owner.unmute(), Err(NetworkRenderError::Clock)));
    finish_muted_observation(
        &mut rig,
        events_before,
        crate::render::RenderEventKind::State {
            from: RenderState::Muted,
            to: RenderState::Draining,
        },
        true,
    );
    assert_eq!(rig.owner.render_state(), RenderState::Draining);
    assert_eq!(rig.owner.queued_frames(), 0);
    assert_eq!(rig.probe.captured_submissions(), accepted);
    assert_eq!(rig.probe.pending_slots(), held);
    assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
    assert_eq!(fake_unmutes(&rig), unmutes);
    assert!(matches!(rig.owner.unmute(), Err(NetworkRenderError::Ended)));
    assert_eq!(fake_unmutes(&rig), unmutes);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    println!(
        "FFW_NETWORK_RENDER_CONTROL_AUTHORITY: {{\"unmute_refused\":true,\"stale_submissions\":0}}"
    );
}

#[test]
fn exhausted_source_rejects_controls_without_interrupting_scheduled_eof() {
    use crate::render::RenderState;
    use franken_hal::backend::FakeCall;

    let mut rig = running(64);
    let wire = packet(&mut rig.sender, 0, rig.start_group_ns, 64);
    rig.socket.send_to(&wire, rig.address).unwrap();
    assert_eq!(rig.owner.poll().unwrap().media_accepted, 1);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    let mut boundary = None;
    for step in 0..1000_u64 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        let outcome = rig.owner.step(&mut timing).expect("live finite source");
        assert!(!matches!(outcome, OwnerStep::Complete));
        if rig.probe.captured_submissions().len() == 1
            && rig.owner.in_flight() == 0
            && !rig.owner.block_in_progress()
        {
            assert!(earliest_group_time(&rig) < rig.start_group_ns + frames_to_ns(64));
            let before = control_continuity(&rig);
            assert!(matches!(
                rig.owner.set_gain(0.5),
                Err(NetworkRenderError::Ended)
            ));
            assert!(matches!(rig.owner.mute(), Err(NetworkRenderError::Ended)));
            assert!(matches!(rig.owner.unmute(), Err(NetworkRenderError::Ended)));
            assert_eq!(control_continuity(&rig), before);
            assert_eq!(rig.owner.render_state(), RenderState::Running);
            assert!(
                !rig.probe
                    .calls()
                    .iter()
                    .any(|call| matches!(call, FakeCall::RequestFlush))
            );
            boundary = Some(step);
            break;
        }
    }
    let start = boundary.expect("observe completed DMA before scheduled EOF");
    let mut complete = false;
    for step in start + 1..5000_u64 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        if matches!(rig.owner.step(&mut timing).unwrap(), OwnerStep::Complete) {
            complete = true;
            break;
        }
    }
    assert!(complete);
    let (expected, frames) = expected_protected(&signal(0, 64), 0);
    assert_eq!(frames, 64);
    assert_eq!(rig.probe.captured_submissions(), expected);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    println!(
        "FFW_NETWORK_RENDER_CONTROL_EOF: {{\"refused\":3,\"eof_completed\":true,\"frames\":{frames}}}"
    );
}

#[cfg(unix)]
mod controller_events;

fn feedback_config() -> FinalFeedbackConfig {
    FinalFeedbackConfig {
        interval_ns: 10_000_000,
        grace_ns: 500_000_000,
        max_reports: 2,
    }
}

fn complete_finite_feedback_owner(rig: &mut RunningFixture) {
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    for step in 0..5000_u64 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        if matches!(rig.owner.step(&mut timing).unwrap(), OwnerStep::Complete) {
            assert_eq!(rig.owner.render_state(), RenderState::Stopped);
            assert!(rig.owner.render.stop_report().acknowledged);
            return;
        }
    }
    panic!("finite owner did not complete its actual drain");
}

fn feed_one_finite_block(rig: &mut RunningFixture) {
    let wire = packet(&mut rig.sender, 0, rig.start_group_ns, 64);
    rig.socket.send_to(&wire, rig.address).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let report = rig.owner.poll().unwrap();
        if report.media_accepted == 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "receiver did not consume media"
        );
        std::thread::yield_now();
    }
}

#[test]
fn final_feedback_recovers_real_lost_credit_after_natural_drain() {
    let mut rig = running(64);
    rig.probe.set_lose_completions(true);
    rig.owner.enable_final_feedback(feedback_config()).unwrap();
    assert_eq!(
        rig.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::NotDue
    );
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    relay
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    let mut sender = CarrierSender::bind(
        StreamKey::from_bytes([0x42; 32]),
        StreamId::new(0x5EED_5EED_0000_0001).unwrap(),
        1,
        CarrierLimits::baseline(),
        ip,
    )
    .unwrap();
    let receiver_control = relay.local_addr().unwrap();
    rig.owner
        .endpoint
        .carrier_mut()
        .set_sender_control(receiver_control);
    sender
        .add_peer(7, rig.address, receiver_control, 1500)
        .unwrap();
    let pts = rig.start_group_ns;
    let frame = OutboundFrame::media(0, pts, pts - 5_333_333, signal(0, 64));
    assert_eq!(sender.submit_media(1, &frame, 0).unwrap().queued, 1);
    assert_eq!(sender.pump(0).media_sent, 1);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if rig.owner.poll().unwrap().media_accepted == 1 {
            break;
        }
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert_eq!(rig.owner.endpoint.carrier().consumed_next(), 1);
    rig.owner.report().unwrap();
    let mut first = [0_u8; 128];
    let (first_len, _) = relay.recv_from(&mut first).unwrap(); // drop genuine final report
    assert_eq!(sender.peer_view(7).unwrap().in_flight, 1);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    let mut natural_drain = false;
    for step in 0..5000_u64 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        rig.owner.step(&mut timing).unwrap();
        if rig.owner.complete && rig.owner.render_state() == RenderState::Draining {
            natural_drain = true;
            break;
        }
    }
    assert!(natural_drain);
    let retained = rig.probe.pending();
    assert!(
        retained > 0,
        "actual backend buffers await the flush acknowledgment"
    );
    assert!(!rig.owner.render.stop_report().acknowledged);
    let captures = rig.probe.captured_submissions();
    assert!(!captures.is_empty());
    assert!(matches!(rig.owner.report(), Err(NetworkRenderError::Ended)));
    let media_read = rig.owner.endpoint.carrier().stats().media_read;
    assert_eq!(
        rig.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Sent
    );
    let mut retry = [0_u8; 128];
    let (retry_len, _) = relay.recv_from(&mut retry).unwrap();
    assert_eq!(&retry[..retry_len], &first[..first_len]);
    relay
        .send_to(&retry[..retry_len], sender.control_addr().unwrap())
        .unwrap();
    let until = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        sender.poll_reports();
        if sender.peer_view(7).unwrap().reported_next == 1 {
            break;
        }
        assert!(std::time::Instant::now() < until);
        std::thread::yield_now();
    }
    assert_eq!(sender.peer_view(7).unwrap().in_flight, 0);
    assert_eq!(
        rig.probe.pending(),
        retained,
        "credit does not acknowledge HAL stop"
    );
    assert_eq!(
        rig.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::NotDue
    );
    let late = packet(&mut rig.sender, 0, rig.start_group_ns, 64);
    rig.socket.send_to(&late, rig.address).unwrap();
    assert!(matches!(rig.owner.poll(), Err(NetworkRenderError::Ended)));
    assert_eq!(rig.owner.endpoint.carrier().stats().media_read, media_read);
    assert_eq!(rig.probe.captured_submissions(), captures);
    let mut stopped = false;
    for _ in 0..20 {
        rig.now.set(rig.now.get() + 100_000);
        if matches!(rig.owner.step(&mut timing).unwrap(), OwnerStep::Complete) {
            stopped = true;
            break;
        }
    }
    assert!(stopped);
    assert!(rig.owner.render.stop_report().acknowledged);
    assert_eq!(rig.probe.pending(), 0);
    rig.now.set(rig.now.get() + 12_000_000);
    assert_eq!(
        rig.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Sent
    );
    assert_eq!(
        rig.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Expired
    );
    assert_eq!(
        rig.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Expired
    );
}

#[test]
fn final_feedback_is_bounded_and_explicit_stop_is_irrevocable() {
    let mut disabled = running(64);
    assert_eq!(
        disabled.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Disabled
    );
    for config in [
        FinalFeedbackConfig {
            interval_ns: 0,
            ..feedback_config()
        },
        FinalFeedbackConfig {
            interval_ns: 1_000_000_001,
            ..feedback_config()
        },
        FinalFeedbackConfig {
            grace_ns: 9_999_999,
            ..feedback_config()
        },
        FinalFeedbackConfig {
            grace_ns: 5_000_000_001,
            ..feedback_config()
        },
        FinalFeedbackConfig {
            max_reports: 0,
            ..feedback_config()
        },
        FinalFeedbackConfig {
            max_reports: 17,
            ..feedback_config()
        },
    ] {
        assert!(matches!(
            disabled.owner.enable_final_feedback(config),
            Err(NetworkRenderError::Configuration)
        ));
    }
    disabled
        .owner
        .enable_final_feedback(feedback_config())
        .unwrap();
    assert!(matches!(
        disabled.owner.enable_final_feedback(feedback_config()),
        Err(NetworkRenderError::Configuration)
    ));
    disabled.owner.cancel().unwrap();
    assert_eq!(
        disabled.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Disabled
    );
    assert!(matches!(
        disabled.owner.enable_final_feedback(feedback_config()),
        Err(NetworkRenderError::Configuration)
    ));

    let mut revoked = running(64);
    revoked
        .owner
        .enable_final_feedback(feedback_config())
        .unwrap();
    revoked.owner.revoke_final_feedback();
    revoked.owner.revoke_final_feedback();
    assert_eq!(
        revoked.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Disabled
    );
    assert!(matches!(
        revoked.owner.enable_final_feedback(feedback_config()),
        Err(NetworkRenderError::Configuration)
    ));

    let mut complete = running(64);
    complete
        .owner
        .enable_final_feedback(feedback_config())
        .unwrap();
    feed_one_finite_block(&mut complete);
    complete_finite_feedback_owner(&mut complete);
    assert!(complete.owner.complete);
    complete.owner.cancel().unwrap(); // Explicit cancel after natural completion also revokes.
    assert!(complete.owner.complete);
    assert_eq!(
        complete.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Disabled
    );
    assert!(matches!(
        complete.owner.enable_final_feedback(feedback_config()),
        Err(NetworkRenderError::Configuration)
    ));
}

#[test]
fn final_feedback_expiry_epoch_and_clock_fault_fail_closed() {
    let mut expired = running(64);
    expired
        .owner
        .enable_final_feedback(FinalFeedbackConfig {
            interval_ns: 10_000_000,
            grace_ns: 30_000_000,
            max_reports: 2,
        })
        .unwrap();
    feed_one_finite_block(&mut expired);
    complete_finite_feedback_owner(&mut expired);
    expired.now.set(expired.now.get() + 40_000_000);
    assert_eq!(
        expired.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Expired
    );
    assert_eq!(
        expired.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Expired
    );

    let mut stale = running(64);
    stale
        .owner
        .enable_final_feedback(feedback_config())
        .unwrap();
    feed_one_finite_block(&mut stale);
    complete_finite_feedback_owner(&mut stale);
    stale.owner.clock.begin_epoch(2, 8).unwrap();
    assert!(matches!(
        stale.owner.final_feedback(),
        Err(NetworkRenderError::Clock)
    ));
    assert_eq!(
        stale.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Disabled
    );

    let mut authority = running_with_authority(64, 0, 10_000_000);
    authority
        .owner
        .enable_final_feedback(feedback_config())
        .unwrap();
    feed_one_finite_block(&mut authority);
    complete_finite_feedback_owner(&mut authority);
    authority.now.set(authority.start_local_ns + 10_000_000);
    assert!(matches!(
        authority.owner.final_feedback(),
        Err(NetworkRenderError::Clock)
    ));
    assert_eq!(
        authority.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Disabled
    );

    let mut faulty = running(64);
    faulty
        .owner
        .enable_final_feedback(feedback_config())
        .unwrap();
    feed_one_finite_block(&mut faulty);
    complete_finite_feedback_owner(&mut faulty);
    faulty.fail.set(true);
    assert!(matches!(
        faulty.owner.final_feedback(),
        Err(NetworkRenderError::Clock)
    ));
    assert_eq!(
        faulty.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Disabled
    );
}

#[test]
fn final_feedback_is_revoked_on_natural_drain_fault() {
    let mut rig = running_with_policy(64, 0, 2_000_000_000, true);
    rig.owner.enable_final_feedback(feedback_config()).unwrap();
    rig.probe.set_lose_completions(true);
    feed_one_finite_block(&mut rig);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    let mut failed = false;
    for step in 0..5000_u64 {
        rig.now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        match rig.owner.step(&mut timing) {
            Err(NetworkRenderError::Preparation) => {
                failed = true;
                break;
            }
            Err(other) => panic!("unexpected drain error: {other:?}"),
            Ok(OwnerStep::Complete) => panic!("unacknowledged flush cannot complete"),
            Ok(OwnerStep::Waiting | OwnerStep::Tick(_)) => {}
        }
    }
    assert!(failed);
    assert_eq!(rig.owner.render_state(), RenderState::Faulted);
    assert!(
        rig.owner.complete,
        "fault followed the natural EOF transition"
    );
    assert_eq!(
        rig.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Disabled
    );
    assert!(matches!(
        rig.owner.enable_final_feedback(feedback_config()),
        Err(NetworkRenderError::Configuration)
    ));
}

#[test]
fn final_feedback_revokes_real_early_render_fault_before_completion() {
    use franken_hal::backend::{DriverError, Op};

    let mut faulted = running(64);
    faulted
        .owner
        .enable_final_feedback(feedback_config())
        .unwrap();
    assert_eq!(
        faulted.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::NotDue
    );
    // Exercise the actual backend failure before NetworkRender's normal error
    // handler, so the final-feedback guard itself sees a live faulted renderer.
    faulted.probe.fail_next(Op::Start, DriverError::Errno(5));
    assert!(
        faulted
            .owner
            .render
            .start(StartPreconditions {
                presentation_mapping_installed: true,
                safe_gain_installed: true,
            })
            .is_err()
    );
    assert_eq!(faulted.owner.render_state(), RenderState::Faulted);
    assert!(!faulted.owner.complete);
    assert!(faulted.owner.final_feedback.is_some());
    let before = faulted.owner.endpoint.carrier().stats().reports_sent;
    assert_eq!(
        faulted.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Disabled
    );
    assert!(faulted.owner.final_feedback.is_none());
    assert_eq!(
        faulted.owner.endpoint.carrier().stats().reports_sent,
        before
    );
    assert!(matches!(
        faulted.owner.enable_final_feedback(feedback_config()),
        Err(NetworkRenderError::Configuration)
    ));

    // The ordinary owner path independently revokes on a pre-completion clock fault.
    let mut clock_fault = running(64);
    clock_fault
        .owner
        .enable_final_feedback(feedback_config())
        .unwrap();
    clock_fault.fail.set(true);
    assert!(matches!(
        clock_fault.owner.poll(),
        Err(NetworkRenderError::Clock)
    ));
    assert!(!clock_fault.owner.complete);
    assert_eq!(
        clock_fault.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Disabled
    );

    let mut healthy = running(64);
    healthy
        .owner
        .enable_final_feedback(feedback_config())
        .unwrap();
    assert_eq!(
        healthy.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::NotDue
    );
}

#[test]
fn final_feedback_grace_uses_actual_n03_lower_bound_and_excludes_boundary() {
    let mut rig = running(64);
    let config = FinalFeedbackConfig {
        interval_ns: 10_000_000,
        grace_ns: 30_000_000,
        max_reports: 2,
    };
    rig.owner.enable_final_feedback(config).unwrap();
    let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    relay
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    rig.owner
        .endpoint
        .carrier_mut()
        .set_sender_control(relay.local_addr().unwrap());
    feed_one_finite_block(&mut rig);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    let mut transition = None;
    let mut stopped = false;
    for step in 0..5000_u64 {
        let local = rig.start_local_ns - 15_000_000 + step * 100_000;
        rig.now.set(local);
        let outcome = rig.owner.step(&mut timing).unwrap();
        if rig.owner.complete && transition.is_none() {
            let center = rig.owner.clock.group_ns(local).unwrap();
            let uncertainty = rig.owner.clock.report(local).uncertainty_ns.unwrap();
            assert!(uncertainty > 0, "the actual N03 bound must be nonzero");
            transition = Some((center, uncertainty));
        }
        if matches!(outcome, OwnerStep::Complete) {
            stopped = true;
            break;
        }
    }
    assert!(stopped);
    let (initial_center, initial_uncertainty) = transition.unwrap();
    let deadline = rig
        .owner
        .final_feedback
        .as_ref()
        .unwrap()
        .deadline_ns
        .unwrap();
    assert_eq!(
        deadline,
        initial_center.checked_sub(initial_uncertainty).unwrap() + config.grace_ns
    );
    let old_midpoint_deadline = initial_center + config.grace_ns;
    let latest_at = |local: u64| {
        rig.owner.clock.group_ns(local).unwrap()
            + rig.owner.clock.report(local).uncertainty_ns.unwrap()
    };
    let mut inside = rig.now.get();
    let mut outside = inside + 40_000_000;
    assert!(latest_at(inside) < deadline);
    assert!(latest_at(outside) >= deadline);
    // Find adjacent actual local instants straddling the conservative bound.
    while inside + 1 < outside {
        let mid = inside + (outside - inside) / 2;
        if latest_at(mid) < deadline {
            inside = mid;
        } else {
            outside = mid;
        }
    }
    assert!(latest_at(inside) < deadline);
    assert!(latest_at(outside) >= deadline);
    assert!(
        latest_at(outside) < old_midpoint_deadline,
        "the rejected midpoint anchor would have allowed the outside report"
    );
    rig.now.set(inside);
    assert_eq!(
        rig.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Sent
    );
    let mut wire = [0_u8; 128];
    let (len, _) = relay.recv_from(&mut wire).unwrap();
    assert!(len > 0);
    let sent = rig.owner.endpoint.carrier().stats().reports_sent;
    rig.now.set(outside);
    assert_eq!(
        rig.owner.final_feedback().unwrap(),
        FinalFeedbackOutcome::Expired
    );
    assert_eq!(rig.owner.endpoint.carrier().stats().reports_sent, sent);
    relay.set_nonblocking(true).unwrap();
    assert_eq!(
        relay.recv_from(&mut wire).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(matches!(
        rig.owner.enable_final_feedback(config),
        Err(NetworkRenderError::Configuration)
    ));
}

#[test]
fn final_feedback_grace_arithmetic_extremes_permanently_revoke() {
    for view in [
        franken_stream::playout::ClockView {
            group_ns: 1,
            uncertainty_ns: 2,
            usable: true,
        },
        franken_stream::playout::ClockView {
            group_ns: u64::MAX - 1,
            uncertainty_ns: 0,
            usable: true,
        },
    ] {
        let mut rig = running(64);
        rig.owner.enable_final_feedback(feedback_config()).unwrap();
        // An explicit extreme-view probe covers arithmetic impossible in this
        // fixture's ordinary N03 timeline; it is not a clock measurement.
        rig.owner.arm_final_feedback(view);
        assert_eq!(
            rig.owner.final_feedback().unwrap(),
            FinalFeedbackOutcome::Disabled
        );
        assert!(matches!(
            rig.owner.enable_final_feedback(feedback_config()),
            Err(NetworkRenderError::Configuration)
        ));
        assert_eq!(rig.owner.endpoint.carrier().stats().reports_sent, 0);
    }
}

#[test]
fn final_feedback_permit_receives_send_bound_and_denial_revokes() {
    for permitted in [false, true] {
        let mut rig = running(64);
        rig.owner.enable_final_feedback(feedback_config()).unwrap();
        let calls = Cell::new(0_u32);
        assert_eq!(
            rig.owner
                .final_feedback_if(|_| {
                    calls.set(calls.get() + 1);
                    true
                })
                .unwrap(),
            FinalFeedbackOutcome::NotDue
        );
        assert_eq!(calls.get(), 0, "a non-due retry never invokes authority");
        let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        relay
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        rig.owner
            .endpoint
            .carrier_mut()
            .set_sender_control(relay.local_addr().unwrap());
        feed_one_finite_block(&mut rig);
        complete_finite_feedback_owner(&mut rig);
        let local = rig.now.get();
        let expected = rig.owner.clock.group_ns(local).unwrap()
            + rig.owner.clock.report(local).uncertainty_ns.unwrap();
        let seen = Cell::new(None);
        let before = rig.owner.endpoint.carrier().stats().reports_sent;
        let outcome = rig
            .owner
            .final_feedback_if(|latest| {
                calls.set(calls.get() + 1);
                seen.set(Some(latest));
                permitted
            })
            .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(seen.get(), Some(expected));
        let mut wire = [0_u8; 128];
        if permitted {
            assert_eq!(outcome, FinalFeedbackOutcome::Sent);
            assert_eq!(
                rig.owner.endpoint.carrier().stats().reports_sent,
                before + 1
            );
            assert!(relay.recv_from(&mut wire).unwrap().0 > 0);
        } else {
            assert_eq!(outcome, FinalFeedbackOutcome::Disabled);
            assert_eq!(rig.owner.endpoint.carrier().stats().reports_sent, before);
            relay.set_nonblocking(true).unwrap();
            assert_eq!(
                relay.recv_from(&mut wire).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert_eq!(
                rig.owner
                    .final_feedback_if(|_| panic!("revoked permit invoked"))
                    .unwrap(),
                FinalFeedbackOutcome::Disabled
            );
            assert!(matches!(
                rig.owner.enable_final_feedback(feedback_config()),
                Err(NetworkRenderError::Configuration)
            ));
        }
    }
}
