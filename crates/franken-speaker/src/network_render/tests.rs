//! Offline network-to-protected-render tests. The socket is localhost and the
//! clock and retained HAL are scripted; none of these fixtures is a device.

use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::rc::Rc;
use std::sync::Arc;

use super::{
    NetworkRender, NetworkRenderAdmission, NetworkRenderError, OwnerStep, PreparedPcm, TickMapping,
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
use franken_stream::carrier::{CarrierReceiver, HostUdp, ReceiverLimits};
use franken_stream::playout::{
    BLOCK_FRAMES, BLOCK_PAYLOAD_BYTES, Decision, Outcome, PlayoutConfig, PlayoutProfile,
    frames_to_ns,
};
use franken_stream::{OutboundFrame, StreamId, StreamKey, StreamReceiver, StreamSender};

use crate::media_playout::{MediaPlayout, PreparedBlock, Release, synthetic_ledger};
use crate::net_carrier::MediaEndpoint;
use crate::render::{RenderConfig, RenderLoop, ScriptedTiming};

const RENDER_FRAMES: usize = 64;
const CLOCK_ORIGIN: u64 = 100_000_000_000;

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
