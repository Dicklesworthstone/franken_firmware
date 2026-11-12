//! Private causal controls for reset-proven software-silent startup.
//! Synthetic profile, scripted timing and FakeBackend: not hardware proof.
use franken_board_profile::{BoardProfile, synthetic_test_fixture_catalog};
use franken_dsp::{
    StereoAudioBlock,
    protection::{Admission, ProtectedBoardDsp, ProtectedOutput, synthetic_calibration_for},
    resample::{DriftResampler, FrameSource, ResamplerConfig},
};
use franken_hal::{
    abi::{EVENT_LEN, RawGeometry},
    backend::{
        AbiKind, DeviceBackend, DriverError, FakeBackend, FakeCall, FakeConfig, FakeProbe, Op,
        Provenance, RawCapabilities,
    },
    session::{HalSession, SessionConfig, SessionError, StartPreconditions},
    slots::{KernelView, LeakLedger},
};
use franken_speaker::render::{
    RenderConfig, RenderError, RenderEventKind, RenderLoop, RenderSource, RenderState,
    ScriptedTiming, Starvation,
};
use std::ops::Deref;
use std::sync::{Arc, Mutex};

const FRAMES: usize = 64;
const BYTES: usize = FRAMES * 4;
const READY: StartPreconditions = StartPreconditions {
    presentation_mapping_installed: true,
    safe_gain_installed: true,
};

fn board() -> BoardProfile {
    synthetic_test_fixture_catalog()
        .into_iter()
        .find(|p| p.model_number == "S1")
        .unwrap()
}
fn dsp() -> ProtectedBoardDsp {
    let board = board();
    ProtectedBoardDsp::admit(
        &board,
        Some(&synthetic_calibration_for(&board)),
        Admission::HostSimulation,
    )
}
// This bounded, opt-in model stores every accepted copied byte itself. Its
// reset delegates to the real fake and purges the copied queue only on ACK.
// The fake independently checks retained views and custody.
const FIFO_CAP: usize = 65_536;
struct CopyFifo {
    bytes: Box<[u8; FIFO_CAP]>,
    len: usize,
    fail_after_copy: bool,
    deny_next_reset: bool,
}
struct PurgeBackend {
    inner: FakeBackend,
    fifo: Arc<Mutex<CopyFifo>>,
}
struct ModelProbe {
    inner: FakeProbe,
    fifo: Arc<Mutex<CopyFifo>>,
}
impl Deref for ModelProbe {
    type Target = FakeProbe;
    fn deref(&self) -> &FakeProbe {
        &self.inner
    }
}
impl ModelProbe {
    fn copied(&self) -> Vec<u8> {
        let q = self.fifo.lock().unwrap();
        q.bytes[..q.len].to_vec()
    }
    fn fail_after_copy(&self) {
        self.fifo.lock().unwrap().fail_after_copy = true;
    }
    fn deny_next_reset(&self) {
        self.fifo.lock().unwrap().deny_next_reset = true;
    }
}
impl DeviceBackend for PurgeBackend {
    fn provenance(&self) -> Provenance {
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
    fn write(&mut self, bytes: &[u8]) -> Result<usize, DriverError> {
        let mut q = self.fifo.lock().unwrap();
        if bytes.len() > FIFO_CAP - q.len {
            return Err(DriverError::Errno(28));
        }
        let accepted = self.inner.write(bytes)?;
        if accepted > bytes.len() {
            return Ok(accepted);
        }
        let begin = q.len;
        q.bytes[begin..begin + accepted].copy_from_slice(&bytes[..accepted]);
        q.len += accepted;
        if std::mem::take(&mut q.fail_after_copy) {
            return Err(DriverError::Errno(5));
        }
        Ok(accepted)
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
        self.inner.request_flush()
    }
    fn reset(&mut self) -> Result<bool, DriverError> {
        if std::mem::take(&mut self.fifo.lock().unwrap().deny_next_reset) {
            return Ok(false);
        }
        let ack = self.inner.reset()?;
        if ack {
            let mut q = self.fifo.lock().unwrap();
            q.bytes.fill(0);
            q.len = 0;
        }
        Ok(ack)
    }
    fn reset_ack_discards_playback(&self) -> bool {
        true
    }
    fn wait_tick(&mut self) {
        self.inner.wait_tick();
    }
}

fn session(copying: bool, reset_ack: bool, prime: u32) -> (HalSession<PurgeBackend>, ModelProbe) {
    let mut cfg = if copying {
        FakeConfig::copying()
    } else {
        FakeConfig::retained()
    };
    cfg.geometry = RawGeometry {
        ring_depth: 4,
        frames_per_block: 64,
        channels: 2,
        bytes_per_sample: 2,
    };
    cfg.completion_delay_ticks = 2;
    cfg.flush_ack_delay_ticks = None;
    cfg.reset_ack = reset_ack;
    let (inner, fake_probe) = FakeBackend::new(cfg);
    fake_probe.capture_submissions(256);
    let fifo = Arc::new(Mutex::new(CopyFifo {
        bytes: Box::new([0; FIFO_CAP]),
        len: 0,
        fail_after_copy: false,
        deny_next_reset: false,
    }));
    let backend = PurgeBackend {
        inner,
        fifo: Arc::clone(&fifo),
    };
    let probe = ModelProbe {
        inner: fake_probe,
        fifo,
    };
    let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2)
        .with_required_silence_blocks(prime);
    let mut s = HalSession::open(board(), backend, config).unwrap();
    s.prepare().unwrap();
    (s, probe)
}
fn acknowledged_reset(s: &mut HalSession<PurgeBackend>) {
    assert!(s.abort_mute().unwrap().mute_acknowledged);
    s.reset_device().unwrap();
    assert!(s.silent_prepared_after_reset());
}
fn renderer(s: HalSession<PurgeBackend>, dsp: ProtectedBoardDsp) -> RenderLoop<PurgeBackend> {
    RenderLoop::new(
        s,
        dsp,
        DriftResampler::new(ResamplerConfig::default()).unwrap(),
        RenderConfig::standard(FRAMES),
    )
    .unwrap()
}

#[test]
fn retained_no_ack_preserves_readable_nonzero_storage_then_ack_retires_it() {
    let (mut s, probe) = session(false, false, 0);
    let block = [0x12; BYTES];
    assert!(!s.silent_prepared_after_reset());
    assert_eq!(s.submit(&block).unwrap().accepted_bytes, BYTES);
    let held = probe.pending_slots();
    assert_eq!(held.len(), 1);
    assert_eq!(probe.captured_submissions(), vec![block.to_vec()]);
    assert!(s.abort_mute().unwrap().mute_acknowledged);
    assert!(matches!(
        s.reset_device(),
        Err(SessionError::ResetNotAcknowledged)
    ));
    assert!(!s.silent_prepared_after_reset());
    assert_eq!(probe.pending_slots(), held);
    assert_eq!(probe.kernel_touch_pending(), (1, 0));
    assert_eq!(probe.modified_while_owned(), 0);
    assert_eq!(probe.use_after_free(), 0);
    let (mut good, good_probe) = session(false, true, 0);
    assert_eq!(good.submit(&block).unwrap().accepted_bytes, BYTES);
    assert_eq!(good_probe.kernel_touch_pending(), (1, 0));
    acknowledged_reset(&mut good);
    assert_eq!(good_probe.pending(), 0);
    assert_eq!(good_probe.kernel_touch_pending(), (0, 0));
    assert_eq!(good_probe.use_after_free(), 0);
    assert_eq!(good_probe.modified_while_owned(), 0);
}

#[test]
fn nonzero_prequeue_refusal_keeps_backend_and_retained_custody_untouched() {
    for copying in [false, true] {
        let (mut s, probe) = session(copying, true, 0);
        acknowledged_reset(&mut s);
        let bytes = [0x24; BYTES];
        assert_eq!(s.submit(&bytes).unwrap().accepted_bytes, BYTES);
        assert!(!s.silent_prepared_after_reset());
        let held = probe.pending_slots();
        if !copying {
            assert_eq!(held.len(), 1);
            assert_eq!(probe.captured_submissions(), vec![bytes.to_vec()]);
        }
        let mut l = renderer(s, dsp());
        assert_eq!(l.in_flight(), 0, "render count does not prove HAL custody");
        let calls = probe.calls();
        assert!(matches!(
            l.start_silent(READY),
            Err(RenderError::SilentStartUnproven)
        ));
        assert_eq!(l.state(), RenderState::Ready);
        assert_eq!(probe.calls(), calls);
        assert_eq!(probe.pending_slots(), held);
        if !copying {
            assert_eq!(probe.kernel_touch_pending(), (1, 0));
            assert_eq!(probe.captured_submissions(), vec![bytes.to_vec()]);
        } else {
            assert_eq!(
                probe.copied(),
                bytes,
                "copied nonzero remains queued across refusal"
            );
        }
    }
}

#[test]
fn copied_fifo_survives_no_ack_and_ack_purges_before_silent_admission() {
    let block = [0x53; BYTES];
    let (mut denied, no_ack_probe) = session(true, false, 0);
    assert_eq!(denied.submit(&block).unwrap().accepted_bytes, BYTES);
    assert_eq!(no_ack_probe.copied(), block);
    assert!(denied.abort_mute().unwrap().mute_acknowledged);
    assert!(matches!(
        denied.reset_device(),
        Err(SessionError::ResetNotAcknowledged)
    ));
    assert_eq!(
        no_ack_probe.copied(),
        block,
        "failed reset must retain actual queued copied bytes"
    );
    assert!(!denied.silent_prepared_after_reset());
    let (mut admitted, ack_probe) = session(true, true, 0);
    assert_eq!(admitted.submit(&block).unwrap().accepted_bytes, BYTES);
    assert_eq!(ack_probe.copied(), block);
    assert!(admitted.abort_mute().unwrap().mute_acknowledged);
    ack_probe.fail_next(Op::Reset, DriverError::Errno(5));
    assert!(admitted.reset_device().is_err());
    assert_eq!(
        ack_probe.copied(),
        block,
        "reset error cannot purge or prove silence"
    );
    assert!(!admitted.silent_prepared_after_reset());
    admitted.reset_device().unwrap();
    assert!(admitted.silent_prepared_after_reset());
    assert!(
        ack_probe.copied().is_empty(),
        "acknowledged purge removes queued copied bytes"
    );
    let mut render = renderer(admitted, dsp());
    render.start_silent(READY).unwrap();
    assert_eq!(render.state(), RenderState::Muted);
    assert!(ack_probe.copied().is_empty());
}

#[test]
fn unqualified_fake_reset_ack_never_establishes_silent_proof() {
    for copying in [false, true] {
        let mut cfg = if copying {
            FakeConfig::copying()
        } else {
            FakeConfig::retained()
        };
        cfg.geometry = RawGeometry {
            ring_depth: 4,
            frames_per_block: 64,
            channels: 2,
            bytes_per_sample: 2,
        };
        let (backend, probe) = FakeBackend::new(cfg);
        let mut s = HalSession::open(
            board(),
            backend,
            SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2),
        )
        .unwrap();
        s.prepare().unwrap();
        assert!(s.abort_mute().unwrap().mute_acknowledged);
        s.reset_device().unwrap();
        assert!(!s.silent_prepared_after_reset());
        let mut render = RenderLoop::new(
            s,
            dsp(),
            DriftResampler::new(ResamplerConfig::default()).unwrap(),
            RenderConfig::standard(FRAMES),
        )
        .unwrap();
        let before = probe.calls();
        assert!(matches!(
            render.start_silent(READY),
            Err(RenderError::SilentStartUnproven)
        ));
        assert_eq!(probe.calls(), before);
    }
}

#[test]
fn copying_short_and_failed_nonzero_attempts_invalidate_until_reset_ack() {
    let (mut s, probe) = session(true, true, 0);
    acknowledged_reset(&mut s);
    probe.set_accept_limit(Some(4));
    assert_eq!(s.submit(&[0x31; BYTES]).unwrap().accepted_bytes, 4);
    assert_eq!(probe.copied(), vec![0x31; 4]);
    assert!(!s.silent_prepared_after_reset());
    assert!(
        probe
            .calls()
            .iter()
            .any(|c| matches!(c, FakeCall::Write(_)))
    );
    acknowledged_reset(&mut s);
    probe.set_accept_limit(Some(0));
    assert_eq!(s.submit(&[0x32; BYTES]).unwrap().accepted_bytes, 0);
    assert!(
        !s.silent_prepared_after_reset(),
        "zero-length acceptance still followed a nonzero attempt"
    );
    acknowledged_reset(&mut s);
    probe.set_accept_limit(None);
    probe.fail_after_copy();
    assert!(s.submit(&[0x33; BYTES]).is_err());
    assert_eq!(
        probe.copied(),
        vec![0x33; BYTES],
        "ambiguous failure happened after the model retained bytes"
    );
    assert!(!s.silent_prepared_after_reset());
    probe.fail_next(Op::Reset, DriverError::Errno(5));
    assert!(s.reset_device().is_err());
    assert_eq!(
        probe.copied(),
        vec![0x33; BYTES],
        "failed reset cannot erase ambiguously copied bytes"
    );
    assert!(!s.silent_prepared_after_reset());
    probe.deny_next_reset();
    assert!(matches!(
        s.reset_device(),
        Err(SessionError::ResetNotAcknowledged)
    ));
    assert_eq!(
        probe.copied(),
        vec![0x33; BYTES],
        "reset without ACK must retain ambiguously copied bytes"
    );
    assert!(!s.silent_prepared_after_reset());
    s.reset_device().unwrap();
    assert!(probe.copied().is_empty());
    assert!(s.silent_prepared_after_reset());
    let mut l = renderer(s, dsp());
    l.start_silent(READY).unwrap();
    assert_eq!(l.state(), RenderState::Muted);
}

struct CountSource {
    pulls: usize,
}
impl FrameSource for CountSource {
    fn pull(&mut self) -> Option<[f32; 2]> {
        self.pulls += 1;
        Some([0.25, 0.125])
    }
}
impl RenderSource for CountSource {
    fn starvation(&self) -> Option<Starvation> {
        None
    }
}

#[test]
fn primed_silent_start_pulls_real_source_and_silences_then_recovers() {
    let (mut s, probe) = session(false, true, 1);
    acknowledged_reset(&mut s);
    let before = probe.calls();
    assert!(matches!(
        s.start(READY),
        Err(SessionError::UnmuteBeforeSilencePrime {
            primed: 0,
            required: 1
        })
    ));
    assert_eq!(
        probe.calls(),
        before,
        "failed priming gate must precede backend start"
    );
    assert_eq!(s.prime_silence().unwrap().accepted_bytes, BYTES);
    assert!(s.silent_prepared_after_reset());
    assert_eq!(probe.captured_submissions(), vec![vec![0; BYTES]]);
    let mut l = renderer(s, dsp());
    let mut source = CountSource { pulls: 0 };
    let before = probe.calls().len();
    l.start_silent(READY).unwrap();
    assert_eq!(source.pulls, 0);
    assert_eq!(l.state(), RenderState::Muted);
    assert!(l.dsp().is_muted());
    assert_eq!(
        &probe.calls()[before..],
        &[FakeCall::Start, FakeCall::SetMute(false)]
    );
    assert_eq!(
        l.take_event().unwrap().kind,
        RenderEventKind::State {
            from: RenderState::Ready,
            to: RenderState::Muted
        }
    );
    assert!(l.take_event().is_none());
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..Default::default()
    };
    for _ in 0..20 {
        l.tick(&mut source, &mut timing);
    }
    let after_silent = probe.captured_submissions();
    assert!(
        source.pulls > 0,
        "silent output must follow an actual source pull"
    );
    assert!(
        after_silent.len() > 1,
        "a real rendered block must reach FakeHAL"
    );
    assert!(after_silent.iter().flatten().all(|&b| b == 0));
    l.unmute().unwrap();
    for _ in 0..100 {
        l.tick(&mut source, &mut timing);
    }
    let recovered = probe.captured_submissions();
    assert!(
        recovered[after_silent.len()..]
            .iter()
            .flatten()
            .any(|&b| b != 0),
        "permitted unmute must recover actual protected output"
    );
    assert_eq!(probe.use_after_free(), 0);
    assert_eq!(probe.modified_while_owned(), 0);
}

#[test]
fn nonzero_applied_gain_refuses_silent_start_but_normal_start_remains_available() {
    let (mut s, probe) = session(true, true, 0);
    acknowledged_reset(&mut s);
    let mut active = dsp();
    active.set_muted(false).unwrap();
    let mut block = StereoAudioBlock::silence(0);
    block.frames = FRAMES;
    block.left[..FRAMES].fill(0.25);
    block.right[..FRAMES].fill(0.125);
    let mut out = ProtectedOutput::new();
    for _ in 0..20 {
        active.render_into(&block, &mut out);
    }
    assert!(active.applied_gain() > 0.0);
    let mut l = renderer(s, active);
    let before = probe.calls();
    assert!(matches!(
        l.start_silent(READY),
        Err(RenderError::SilentStartUnproven)
    ));
    assert_eq!(l.state(), RenderState::Ready);
    assert_eq!(probe.calls(), before);
    l.start(READY).unwrap();
    assert_eq!(l.state(), RenderState::Running);
    assert!(
        probe.calls()[before.len()..]
            .iter()
            .any(|c| matches!(c, FakeCall::SetMute(false)))
    );
    let mut source = CountSource { pulls: 0 };
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..Default::default()
    };
    for _ in 0..20 {
        l.tick(&mut source, &mut timing);
    }
    assert!(source.pulls > 0);
    assert!(
        probe.copied().iter().any(|&byte| byte != 0),
        "ordinary start must produce audible-path PCM in the model"
    );
}

#[test]
fn silent_start_wrapper_refuses_missing_required_silence_prime() {
    let (mut session, probe) = session(false, true, 1);
    acknowledged_reset(&mut session);
    assert!(session.silent_prepared_after_reset());
    assert_eq!(session.required_silence_blocks(), 1);
    assert_eq!(session.primed_silence_blocks(), 0);
    let dsp = dsp();
    assert_eq!(dsp.applied_gain(), 0.0);
    let mut renderer = renderer(session, dsp);
    assert_eq!(renderer.state(), RenderState::Ready);
    let calls_before = probe.calls();
    assert!(
        !calls_before
            .iter()
            .any(|call| matches!(call, FakeCall::Start | FakeCall::SetMute(false)))
    );
    assert!(probe.captured_submissions().is_empty());
    assert!(matches!(
        renderer.start_silent(READY),
        Err(RenderError::Session(
            SessionError::UnmuteBeforeSilencePrime {
                primed: 0,
                required: 1
            }
        ))
    ));
    assert_eq!(renderer.state(), RenderState::Ready);
    assert_eq!(
        probe.calls(),
        calls_before,
        "refused start cannot call backend start or unmute"
    );
    assert!(
        probe.captured_submissions().is_empty(),
        "refused start cannot submit output"
    );
    assert_eq!(probe.pending(), 0);
    assert!(renderer.take_event().is_none());
}
