//! The selected N06 hybrid through the real N07 receiving endpoint: the real `CarrierReceiver` over a scripted in-memory port, the
//! real `MediaPlayout` with the host-development FEC selected, the real N04 engine, a real `GroupClock` and an admitted platform
//! layer over a scripted kernel clock. Every datagram is a real authenticated N06 wire from `fec::sign_symbol`. Nothing here is a
//! paced FEC sender, a peer negotiation or a production admission, and no test here has been compiled or run when it is written.

use super::*;
use crate::guest_evidence;
use crate::media_playout::synthetic_ledger;
use franken_clock::group::{GroupClockConfig, ProbeResponse, StartSchedule};
use franken_platform::ops::{Provenance, Timespec};
use franken_stream::carrier::{ReceiverLimits, SinkCounters};
use franken_stream::playout::{Outcome, PlayoutConfig, PlayoutProfile, consume_by};
use franken_stream::{OutboundFrame, StreamId, StreamKey, StreamReceiver, StreamSender};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

const ABI: Abi = Abi::PowerPc32;
const OLD_TIMELINE_NS: u64 = 100_000_000_000;
const ENOSYS_PPC: isize = 38;
const MS: u64 = 1_000_000;
const WORK_NS: u64 = MS;
const LEAD_NS: u64 = MS;

fn key() -> StreamKey {
    StreamKey::from_bytes([0x5A; 32])
}

fn stream() -> StreamId {
    StreamId::new(0x5EED_5EED_0000_0006).expect("stream id")
}

/// A kernel that only keeps time, and counts how often it was asked for it.
struct ClockKernel {
    time: Rc<Cell<u64>>,
    reads: Rc<Cell<u64>>,
}

impl KernelOps for ClockKernel {
    fn provenance(&self) -> Provenance {
        Provenance::Simulated
    }
    fn backend_abi(&self) -> Option<Abi> {
        None
    }
    fn clock_gettime_monotonic(&mut self, out: &mut Timespec) -> isize {
        self.reads.set(self.reads.get() + 1);
        let now = self.time.get();
        out.secs = i64::try_from(now / 1_000_000_000).unwrap_or(i64::MAX);
        out.nanos = i64::try_from(now % 1_000_000_000).unwrap_or(0);
        0
    }
    fn getrandom(&mut self, _buf: &mut [u8], _flags: u32) -> isize {
        -ENOSYS_PPC
    }
    fn open_dev_random(&mut self, _flags: u32) -> isize {
        -ENOSYS_PPC
    }
    fn eventfd2(&mut self, _initval: u32, _flags: u32) -> isize {
        7
    }
    fn pipe2(&mut self, _fds: &mut [i32; 2], _flags: u32) -> isize {
        -ENOSYS_PPC
    }
    fn write(&mut self, _fd: i32, _buf: &[u8]) -> isize {
        -ENOSYS_PPC
    }
    fn read(&mut self, _fd: i32, _buf: &mut [u8]) -> isize {
        -ENOSYS_PPC
    }
    fn close(&mut self, _fd: i32) -> isize {
        0
    }
}

/// An in-memory port: the media lane reads from a queue the test fills (a datagram longer than the caller's buffer is cut to it,
/// as the P02 port reports it), the control lane is always empty and sends are accepted and recorded in `sent`, in order, with the
/// lane they went out on. `after_read` moves the scripted platform
/// clock right after the next media read, which is how a test makes render protection begin between a readiness check and the
/// offer that follows it.
struct ScriptPort {
    queue: Rc<RefCell<VecDeque<Vec<u8>>>>,
    time: Rc<Cell<u64>>,
    after_read: Rc<Cell<Option<u64>>>,
    sent: Sent,
    address: SocketAddr,
}

impl DatagramPort for ScriptPort {
    fn send_to(&mut self, lane: Lane, bytes: &[u8], _to: SocketAddr) -> Result<(), PortFault> {
        self.sent.borrow_mut().push((lane, bytes.to_vec()));
        Ok(())
    }
    fn recv(&mut self, lane: Lane, buf: &mut [u8]) -> Result<Received, PortFault> {
        if lane != Lane::Media {
            return Err(PortFault::WouldBlock);
        }
        let next = self.queue.borrow_mut().pop_front();
        let Some(datagram) = next else {
            return Err(PortFault::WouldBlock);
        };
        let len = datagram.len().min(buf.len());
        buf[..len].copy_from_slice(&datagram[..len]);
        if let Some(local) = self.after_read.take() {
            self.time.set(local);
        }
        Ok(Received { len, from: None })
    }
    fn local_addr(&self, _lane: Lane) -> Result<SocketAddr, PortFault> {
        Ok(self.address)
    }
    fn rebind(&mut self, _ip: IpAddr) -> Result<(), PortFault> {
        Ok(())
    }
}

fn address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9)
}

/// The media lane's queue the test fills, the clock hook the port moves after its next read, and what the port was asked to send
/// (lane and bytes, in order): all three shared with the port.
type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;
type Hook = Rc<Cell<Option<u64>>>;
type Sent = Rc<RefCell<Vec<(Lane, Vec<u8>)>>>;

fn script_port(time: &Rc<Cell<u64>>) -> (ScriptPort, Queue, Hook, Sent) {
    let queue = Rc::new(RefCell::new(VecDeque::new()));
    let after_read = Rc::new(Cell::new(None));
    let sent = Rc::new(RefCell::new(Vec::new()));
    let port = ScriptPort {
        queue: Rc::clone(&queue),
        time: Rc::clone(time),
        after_read: Rc::clone(&after_read),
        sent: Rc::clone(&sent),
        address: address(),
    };
    (port, queue, after_read, sent)
}

/// The four source blocks of coding window `window`: never silent, different per window and per block.
fn source(window: u64) -> [[u8; fec::BYTES]; fec::K] {
    std::array::from_fn(|block| {
        std::array::from_fn(|byte| {
            ((window as usize * 29 + block * 37 + byte * 11 + 5) % 251) as u8 + 1
        })
    })
}

struct Rig {
    time: Rc<Cell<u64>>,
    reads: Rc<Cell<u64>>,
    queue: Rc<RefCell<VecDeque<Vec<u8>>>>,
    after_read: Rc<Cell<Option<u64>>>,
    sent: Sent,
    endpoint: MediaEndpoint<ScriptPort>,
    platform: PlatformLayer<ClockKernel>,
    clock: GroupClock,
    /// The presentation origin the stream is signed under (block 0's presentation time).
    start: u64,
}

impl Rig {
    /// A locked clock and an admitted start 500 ms after local 50 ms, the stream's first block at that start. With
    /// `select_fec` the host-development N06 hybrid is selected on the media path, as the trusted control call does it.
    fn new(select_fec: bool) -> Self {
        let time = Rc::new(Cell::new(0));
        let reads = Rc::new(Cell::new(0));
        let (port, queue, after_read, sent) = script_port(&time);
        let carrier = CarrierReceiver::with_port(
            key(),
            stream(),
            1,
            ReceiverLimits::baseline(),
            port,
            address(),
        )
        .expect("receiver over the scripted port");
        // The N06 selection requires the standard music shape: 1 ms downstream work, 1 ms lead, no tolerance.
        let media = MediaPlayout::new(
            StreamReceiver::new(key(), stream(), 1),
            PlayoutProfile::MUSIC,
            PlayoutConfig {
                work_ns: WORK_NS,
                lead_ns: LEAD_NS,
                tolerance_ns: 0,
            },
            &synthetic_ledger(2 * 1024 * 1024),
            0,
        )
        .expect("media path");
        let platform = crate::platform_start::admit_test_layer(
            &guest_evidence::for_abi(ABI).matrix(),
            ClockKernel {
                time: Rc::clone(&time),
                reads: Rc::clone(&reads),
            },
        )
        .expect("admitted platform layer");
        let clock = GroupClock::new(GroupClockConfig::standard().expect("config"), 1, 7, 100)
            .expect("group clock");
        let mut rig = Self {
            time,
            reads,
            queue,
            after_read,
            sent,
            endpoint: MediaEndpoint::new(carrier, media),
            platform,
            clock,
            start: 0,
        };
        rig.lock(0, OLD_TIMELINE_NS);
        rig.at(50 * MS);
        rig.start = rig.group_at(50 * MS) + 500 * MS;
        rig.admit(rig.start).expect("admitted start");
        if select_fec {
            rig.select_fec();
        }
        rig
    }

    /// Four accepted exchanges 10 ms apart; the group clock then reads `group_origin_ns` at `local_origin_ns`.
    fn lock(&mut self, local_origin_ns: u64, group_origin_ns: u64) {
        for k in 1..=4_u64 {
            let offset = k * 10 * MS;
            let t1 = local_origin_ns + offset;
            let req = self.clock.next_probe(t1);
            let (epoch, leader) = (self.clock.epoch(), self.clock.leader());
            self.clock
                .on_response(
                    ProbeResponse {
                        epoch,
                        leader,
                        seq: req.seq,
                        t1_echo_ns: req.t1_local_ns,
                        t2_group_ns: group_origin_ns + offset + 400_000,
                        t3_group_ns: group_origin_ns + offset + 450_000,
                    },
                    t1 + 850_000,
                )
                .expect("accepted exchange");
        }
    }

    fn at(&self, local_ns: u64) {
        self.time.set(local_ns);
    }

    fn group_at(&self, local_ns: u64) -> u64 {
        self.clock.group_ns(local_ns).expect("a fitted clock")
    }

    /// The local instant at which the group clock reads `group_ns`, judged at `now_local_ns`.
    fn local_of(&self, group_ns: u64, now_local_ns: u64) -> u64 {
        self.clock
            .local_for_group(group_ns, now_local_ns)
            .expect("a fitted clock")
    }

    fn admit(
        &mut self,
        start_group_ns: u64,
    ) -> Result<franken_clock::group::StartPlan, StartRefusal> {
        let sched = StartSchedule {
            epoch: self.clock.epoch(),
            start_group_ns,
        };
        self.endpoint
            .admit_start(&mut self.platform, &mut self.clock, sched, 0)
    }

    fn fec_config(&self) -> fec::SessionConfig {
        fec::SessionConfig {
            stream: stream(),
            epoch: 1,
            presentation_origin_ns: self.start,
            key: key(),
        }
    }

    fn select_fec(&mut self) {
        let capacity =
            self.endpoint.media().resident_bytes() + fec::Receiver::resident_bytes() as u64;
        let config = self.fec_config();
        self.endpoint
            .media_mut()
            .enable_host_fec(config, &synthetic_ledger(capacity), 0)
            .expect("host-development FEC");
    }

    /// The authenticated N06 wire for symbol `esi` of coding window `window`: a source symbol for `esi < 4`, else a repair symbol.
    fn wire(&self, window: u64, esi: usize) -> Vec<u8> {
        let config = self.fec_config();
        let source = source(window);
        let digest = fec::content_digest(&config.metadata(window).expect("metadata"), &source);
        fec::sign_symbol(
            &config,
            window,
            esi,
            if esi < fec::K { 0 } else { 2 },
            digest,
            &fec::encode_symbol(&source, esi).expect("symbol"),
        )
        .expect("signed symbol")
        .to_vec()
    }

    fn push(&self, wire: Vec<u8>) {
        self.queue.borrow_mut().push_back(wire);
    }

    fn queued(&self) -> usize {
        self.queue.borrow().len()
    }

    fn poll(&mut self) -> PollReport {
        self.endpoint.poll(&mut self.platform, &mut self.clock)
    }

    fn consumed(&self) -> u64 {
        self.endpoint.carrier().consumed_next()
    }

    /// Block 0's engine cutoff in group time as the receiver sees it at `local_ns` (the uncertainty is the clock's at that instant).
    fn cutoff_group(&self, local_ns: u64) -> u64 {
        let uncertainty = self
            .clock
            .report(local_ns)
            .uncertainty_ns
            .expect("a fit")
            .max(500_000);
        consume_by(self.start, WORK_NS, LEAD_NS, uncertainty)
    }

    /// The local instant at which the group clock reads block 0's cutoff plus `offset_ns`. Found by iteration because the cutoff
    /// moves with the clock's uncertainty at that instant.
    fn local_at_cutoff(&self, offset_ns: i64) -> u64 {
        let mut local = self.local_of(self.start, 100 * MS);
        for _ in 0..8 {
            let target = self
                .cutoff_group(local)
                .checked_add_signed(offset_ns)
                .expect("in range");
            let next = self.local_of(target, local);
            if next == local {
                break;
            }
            local = next;
        }
        local
    }
}

/// Window 23's first source symbol is block 92, ahead of block 0's cutoff and inside the engine's horizon once the cursor has
/// moved, and window 23 is the current coding window around block 0's cutoff.
const WINDOW_AT_CUTOFF: u64 = 23;

#[test]
fn n06_carrier_credits_selected_n06_at_authenticated_sequences_and_decodes_to_exact_pcm() {
    let mut rig = Rig::new(true);
    rig.at(70 * MS);
    for esi in 2..fec::N {
        let wire = rig.wire(0, esi);
        assert_eq!(wire.len(), fec::DATAGRAM, "the whole N06 wire is offered");
        rig.push(wire);
    }
    let report = rig.poll();
    assert_eq!((report.media_read, report.media_accepted), (6, 6));
    // Sources 2 and 3 and repairs 4..7 of window 0: the highest authenticated sequence is 0 * 8 + 7.
    assert_eq!(rig.consumed(), 8);
    let endpoint = &rig.endpoint;
    assert_eq!(
        endpoint.carrier().sink_counters(),
        &SinkCounters {
            admitted: 6,
            refused: 0,
            backpressure: 0
        }
    );
    let verdicts = endpoint.verdicts();
    assert_eq!(
        (
            verdicts.fec_source,
            verdicts.fec_retransmit,
            verdicts.fec_repair_buffered
        ),
        (2, 0, 4)
    );
    assert_eq!(
        verdicts.count("admitted"),
        2,
        "only the two source symbols have an engine verdict; repair symbols have none"
    );
    assert_eq!(
        (
            verdicts.refused,
            verdicts.backpressure,
            verdicts.credit_refused
        ),
        (0, 0, 0)
    );
    assert_eq!(
        endpoint.media().receiver_counters().datagrams_seen,
        0,
        "a selected N06 datagram is not admitted a second time as N01"
    );

    // Decode on the endpoint's own schedule: bounded steps, then the recovered blocks reach the N04 engine.
    let cancel = AtomicBool::new(false);
    let mut ready = false;
    for step in 0..1000 {
        rig.at(130 * MS + step * 30_000);
        let state = rig
            .endpoint
            .poll_fec(&mut rig.platform, &mut rig.clock, &cancel)
            .expect("a decode step");
        if state == DecodeState::Ready {
            ready = true;
            break;
        }
        assert_eq!(state, DecodeState::Pending);
    }
    assert!(ready, "the bounded decoder completed");
    let status = rig.endpoint.media().host_fec_status().expect("selected");
    assert_eq!(status.counters.recovered, 2);

    // The existing consumer prepares the recovered block 0 for the downstream sink: real PCM, byte for byte.
    rig.at(rig.local_at_cutoff(20_000));
    let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
    let Preparation::Prepared(block) = rig
        .endpoint
        .prepare(&mut rig.platform, &mut rig.clock, &mut out)
        .expect("the clock is readable")
    else {
        panic!("the recovered block was not prepared");
    };
    assert_eq!(block.decision.outcome, Outcome::Real);
    assert_eq!(out, source(0)[0]);
}

#[test]
fn n06_carrier_credit_is_bounded_by_the_fec_receivers_authenticated_window_range() {
    let mut rig = Rig::new(true);
    rig.at(70 * MS);
    // Around local 70 ms the current coding window is 0, so window 1 is the newest the receiver takes and window 2 is not.
    rig.push(rig.wire(1, 5));
    rig.push(rig.wire(2, 5));
    let report = rig.poll();
    assert_eq!((report.media_read, report.media_accepted), (2, 1));
    assert_eq!(
        rig.consumed(),
        8 + 5 + 1,
        "the newest window's repair symbol is credited at its sequence 13"
    );
    assert_eq!(rig.endpoint.verdicts().fec_repair_buffered, 1);
    assert_eq!(
        (
            rig.endpoint.carrier().sink_counters().admitted,
            rig.endpoint.carrier().sink_counters().refused
        ),
        (1, 1),
        "the window beyond the range was refused before any state changed and earned nothing"
    );

    // Around local 280 ms the current window is 10: windows 4..=11 are in range, window 3 is not (the retained range is
    // exactly eight windows, [current - 6, current + 1]).
    rig.at(280 * MS);
    rig.push(rig.wire(3, 5));
    rig.push(rig.wire(4, 5));
    let report = rig.poll();
    assert_eq!((report.media_read, report.media_accepted), (2, 1));
    assert_eq!(rig.consumed(), 4 * 8 + 5 + 1);
    assert_eq!(
        (
            rig.endpoint.carrier().sink_counters().admitted,
            rig.endpoint.carrier().sink_counters().refused
        ),
        (2, 2)
    );
    assert_eq!(rig.endpoint.verdicts().fec_repair_buffered, 2);
}

#[test]
fn n06_carrier_render_protection_leaves_datagrams_in_the_port_and_credits_them_next_poll() {
    let mut rig = Rig::new(true);
    rig.push(rig.wire(WINDOW_AT_CUTOFF, 0));

    // Just before block 0's cutoff the receiver defers: nothing is read, counted or lost.
    rig.at(rig.local_at_cutoff(-200_000));
    let report = rig.poll();
    assert_eq!((report.media_read, report.media_accepted), (0, 0));
    assert_eq!(rig.queued(), 1, "the datagram waits in the port");
    assert_eq!(rig.endpoint.verdicts().fec_deferred_polls, 1);
    assert_eq!(
        rig.endpoint.carrier().sink_counters(),
        &SinkCounters::default()
    );
    assert_eq!(rig.consumed(), 0);

    // The renderer takes block 0's decision; its complete render interval is protected as well.
    rig.at(rig.local_at_cutoff(20_000));
    let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
    let prepared = rig
        .endpoint
        .prepare(&mut rig.platform, &mut rig.clock, &mut out)
        .expect("the clock is readable");
    assert!(
        matches!(prepared, Preparation::Quiet { .. }),
        "{prepared:?}"
    );
    rig.at(rig.time.get() + MS);
    let report = rig.poll();
    assert_eq!(report.media_read, 0);
    assert_eq!(rig.queued(), 1);
    assert_eq!(rig.endpoint.verdicts().fec_deferred_polls, 2);

    // After the render interval the same datagram is read, admitted by the engine and credited at its own sequence.
    rig.at(rig.time.get() + 2 * MS + 10_000);
    let report = rig.poll();
    assert_eq!((report.media_read, report.media_accepted), (1, 1));
    assert_eq!(rig.queued(), 0);
    assert_eq!(rig.consumed(), WINDOW_AT_CUTOFF * 8 + 1);
    assert_eq!(rig.endpoint.verdicts().count("admitted"), 1);
    assert_eq!(rig.endpoint.verdicts().fec_source, 1);
    assert_eq!(rig.endpoint.verdicts().fec_deferred_polls, 2);
}

#[test]
fn n06_carrier_protection_that_begins_between_the_check_and_the_offer_drops_one_as_backpressure() {
    let mut rig = Rig::new(true);
    rig.push(rig.wire(WINDOW_AT_CUTOFF, 0));
    rig.push(rig.wire(WINDOW_AT_CUTOFF, 1));
    // The readiness check passes a millisecond before the cutoff; the first read then moves the clock into the protected
    // interval, so the offer that follows it is deferred by the receiver itself.
    rig.at(rig.local_at_cutoff(-(MS as i64)));
    rig.after_read.set(Some(rig.local_at_cutoff(-200_000)));
    let report = rig.poll();
    assert_eq!(report.media_read, 1, "the loop stops after the deferral");
    assert_eq!(rig.queued(), 1, "the second datagram is not read");
    assert_eq!(
        rig.endpoint.carrier().sink_counters(),
        &SinkCounters {
            admitted: 0,
            refused: 0,
            backpressure: 1
        }
    );
    let verdicts = rig.endpoint.verdicts();
    assert_eq!(verdicts.fec_deferred_dropped, 1);
    assert_eq!(verdicts.fec_deferred_polls, 1);
    assert_eq!(verdicts.backpressure, 1);
    assert_eq!(verdicts.refused, 0);
    assert_eq!(
        rig.consumed(),
        0,
        "a datagram that was not stored earns no credit"
    );
}

#[test]
fn n06_carrier_a_media_epoch_the_carrier_does_not_report_earns_no_credit() {
    let mut rig = Rig::new(true);
    rig.at(70 * MS);
    // The control path moved the carrier to epoch 2 and has not yet moved the media path: the media path still authenticates
    // epoch 1, and a report naming epoch 2 must not carry epoch 1's numbers.
    rig.endpoint.carrier_mut().advance_epoch(2);
    assert_eq!(rig.endpoint.carrier().epoch(), 2);
    rig.push(rig.wire(0, 2));
    let report = rig.poll();
    assert_eq!(report.media_read, 1);
    assert_eq!(rig.consumed(), 0);
    assert_eq!(rig.endpoint.verdicts().credit_refused, 1);
    assert_eq!(rig.endpoint.verdicts().fec_source, 0);
    assert_eq!(
        rig.endpoint.carrier().sink_counters(),
        &SinkCounters {
            admitted: 0,
            refused: 1,
            backpressure: 0
        }
    );
}

#[test]
fn n06_carrier_a_moved_fec_origin_restarts_credit_and_a_refused_start_changes_nothing() {
    let mut rig = Rig::new(true);
    rig.at(70 * MS);
    rig.push(rig.wire(0, 2));
    rig.push(rig.wire(0, 3));
    rig.poll();
    assert_eq!(rig.consumed(), 4);

    // The same origin again (a relock before the stream began): the numbering is the same, so the credit stays.
    rig.at(100 * MS);
    let same = rig.start;
    rig.admit(same).expect("the same start is re-admitted");
    assert_eq!(rig.endpoint.media().host_fec_origin(), Some(same));
    assert_eq!(rig.consumed(), 4);

    // A new origin inside the same epoch begins a new numbering from window 0: credit begins again with it.
    let moved = rig.group_at(100 * MS) + 500 * MS;
    rig.admit(moved).expect("the moved start is admitted");
    rig.start = moved;
    assert_eq!(rig.endpoint.media().host_fec_origin(), Some(moved));
    assert_eq!(rig.consumed(), 0);
    rig.at(120 * MS);
    rig.push(rig.wire(0, 2));
    rig.poll();
    assert_eq!(rig.consumed(), 3);

    // A start the FEC receiver refuses (another epoch) changes neither the origin nor the credit.
    let refused = rig.endpoint.admit_start(
        &mut rig.platform,
        &mut rig.clock,
        StartSchedule {
            epoch: 99,
            start_group_ns: moved + 100 * MS,
        },
        0,
    );
    assert!(
        matches!(refused, Err(StartRefusal::Fec(fec::Refusal::Epoch))),
        "{refused:?}"
    );
    assert_eq!(rig.endpoint.media().host_fec_origin(), Some(moved));
    assert_eq!(rig.consumed(), 3);
}

#[test]
fn n06_carrier_baseline_asks_no_clock_for_readiness_and_credits_the_authenticated_n01_sequence() {
    let mut rig = Rig::new(false);
    rig.at(60 * MS);
    let before = rig.reads.get();
    let report = rig.poll();
    assert_eq!(report.media_read, 0);
    assert_eq!(
        rig.reads.get(),
        before,
        "without the N06 selection the readiness check reads no clock"
    );

    let pcm: Vec<u8> = (0..BLOCK_PAYLOAD_BYTES)
        .map(|i| 0x11 + (i % 200) as u8)
        .collect();
    let mut sender = StreamSender::new(key(), stream(), 1);
    let wire = sender
        .send(OutboundFrame::media(
            0,
            rig.start,
            rig.start - 5_333_333,
            pcm,
        ))
        .expect("signed N01 frame");
    assert!(wire.len() <= franken_stream::MAX_DATAGRAM_BYTES);
    rig.push(wire);
    let report = rig.poll();
    assert_eq!((report.media_read, report.media_accepted), (1, 1));
    assert_eq!(
        rig.consumed(),
        1,
        "the first N01 sequence is 0, so the credit is 1"
    );
    let endpoint = &rig.endpoint;
    assert_eq!(endpoint.verdicts().count("admitted"), 1);
    assert_eq!(endpoint.media().receiver_counters().datagrams_seen, 1);
    let verdicts = endpoint.verdicts();
    assert_eq!(
        (
            verdicts.credit_refused,
            verdicts.fec_source,
            verdicts.fec_retransmit,
            verdicts.fec_repair_buffered,
            verdicts.fec_deferred_polls,
            verdicts.fec_deferred_dropped
        ),
        (0, 0, 0, 0, 0, 0)
    );
    assert_eq!(
        endpoint.carrier().sink_counters(),
        &SinkCounters {
            admitted: 1,
            refused: 0,
            backpressure: 0
        }
    );
}

/// Records the length of every datagram it is offered and refuses it.
struct LengthSink {
    declared: usize,
    seen: Vec<usize>,
}

impl MediaSink for LengthSink {
    fn offer(&mut self, datagram: &[u8]) -> SinkVerdict {
        self.seen.push(datagram.len());
        SinkVerdict::Refused
    }
    fn max_datagram_bytes(&self) -> usize {
        self.declared
    }
}

#[test]
fn n06_carrier_reads_the_datagram_length_the_sink_declares_and_no_more() {
    let n01_largest = franken_stream::MAX_DATAGRAM_BYTES;
    let cases = [
        // (declared, datagram offered, length the sink sees)
        (n01_largest, fec::DATAGRAM, n01_largest + 1),
        (fec::DATAGRAM, fec::DATAGRAM, fec::DATAGRAM),
        (fec::DATAGRAM, fec::DATAGRAM + 1, fec::DATAGRAM + 1),
        (usize::MAX, fec::DATAGRAM + 5, fec::DATAGRAM + 1),
        (0, fec::DATAGRAM, n01_largest + 1),
    ];
    for (declared, offered, expected) in cases {
        let time = Rc::new(Cell::new(0));
        let (port, queue, _, _) = script_port(&time);
        let mut carrier = CarrierReceiver::with_port(
            key(),
            stream(),
            1,
            ReceiverLimits::baseline(),
            port,
            address(),
        )
        .expect("receiver over the scripted port");
        queue.borrow_mut().push_back(vec![0xAB; offered]);
        let mut sink = LengthSink {
            declared,
            seen: Vec::new(),
        };
        let report = carrier.poll_into(&mut sink);
        assert_eq!(report.media_read, 1);
        assert_eq!(
            sink.seen,
            [expected],
            "declared {declared}, offered {offered}"
        );
    }
}

#[test]
fn n06_carrier_a_start_admitted_behind_the_endpoint_restarts_credit_at_the_next_poll() {
    let mut rig = Rig::new(true);
    rig.at(70 * MS);
    rig.push(rig.wire(0, 2));
    rig.poll();
    assert_eq!(rig.consumed(), 3);

    // The control path reaches the media path directly, not through the endpoint's own `admit_start`.
    rig.at(100 * MS);
    let moved = rig.group_at(100 * MS) + 500 * MS;
    let sched = StartSchedule {
        epoch: rig.clock.epoch(),
        start_group_ns: moved,
    };
    rig.endpoint
        .media_mut()
        .admit_start(&mut rig.platform, &mut rig.clock, sched, 0)
        .expect("the moved start is admitted");
    assert_eq!(rig.consumed(), 3, "nothing has told the carrier yet");
    // An empty poll is enough: the generation is read from the media path before anything is offered.
    rig.poll();
    assert_eq!(rig.consumed(), 0);
    assert_eq!(rig.endpoint.media().host_fec_origin(), Some(moved));

    // The new numbering is credited from its own sequences.
    rig.start = moved;
    rig.at(120 * MS);
    rig.push(rig.wire(0, 3));
    rig.poll();
    assert_eq!(rig.consumed(), 4);
}

#[test]
fn n06_carrier_credit_is_refused_unless_stream_epoch_origin_and_format_all_match() {
    let mut rig = Rig::new(true);
    let origin = rig.start;
    let good = AuthenticatedIngress {
        admission: None,
        sequence: 13,
        source_epoch: 1,
        wire_bytes: fec::DATAGRAM,
        format: AuthenticatedFormat::N06RepairSymbol,
        stream: stream().get(),
        origin_ns: origin,
    };
    let mut verdicts = EngineVerdicts::default();
    let mut sink = PlayoutSink {
        media: rig.endpoint.media_mut(),
        platform: &mut rig.platform,
        clock: &mut rig.clock,
        verdicts: &mut verdicts,
        epoch: 1,
        stream: stream().get(),
        origin,
        fec_selected: true,
    };
    assert_eq!(sink.credit(&good), SinkVerdict::Admitted { seq: 13 });
    // Each of the four parts of the identity, changed alone, earns nothing.
    let others = [
        AuthenticatedIngress {
            stream: good.stream + 1,
            ..good
        },
        AuthenticatedIngress {
            source_epoch: 2,
            ..good
        },
        AuthenticatedIngress {
            origin_ns: origin + 1,
            ..good
        },
        AuthenticatedIngress {
            format: AuthenticatedFormat::N01Media,
            ..good
        },
    ];
    for (done, event) in others.iter().enumerate() {
        assert_eq!(sink.credit(event), SinkVerdict::Refused);
        assert_eq!(sink.verdicts.credit_refused, done as u64 + 1);
    }
    // The identity that matches is still credited afterwards, and only it was counted by format.
    assert_eq!(sink.credit(&good), SinkVerdict::Admitted { seq: 13 });
    assert_eq!(sink.verdicts.fec_repair_buffered, 2);
}

#[test]
fn n06_carrier_bind_stream_swaps_streams_and_ends_a_selected_fec_session() {
    let mut rig = Rig::new(true);
    rig.at(70 * MS);
    assert!(rig.endpoint.media().host_fec_selected());
    let old_wire = StreamSender::new(key(), stream(), 1)
        .send(OutboundFrame::media(
            0,
            rig.start,
            rig.start - 5_333_333,
            vec![9u8; BLOCK_PAYLOAD_BYTES],
        ))
        .expect("signed N01 frame of the old stream");

    // A source restart under a fresh stream id, same key, strictly newer epoch.
    let fresh = StreamId::new(0x5EED_5EED_0000_0007).expect("stream id");
    rig.endpoint.media_mut().bind_stream(fresh, 2);
    assert!(
        !rig.endpoint.media().host_fec_selected(),
        "the N06 session names the old stream, so it ends with the bind"
    );

    // The old stream's datagram is refused as a stream the receiver is no longer bound to.
    let refused =
        rig.endpoint
            .media_mut()
            .ingest_authenticated(&mut rig.platform, &mut rig.clock, &old_wire);
    assert!(
        matches!(refused, Err(MediaRefusal::Stream(_))),
        "{refused:?}"
    );

    // The new stream's datagram, signed under the new id and epoch, is authenticated and carries the new identity.
    let new_wire = StreamSender::new(key(), fresh, 2)
        .send(OutboundFrame::media(
            0,
            rig.start,
            rig.start - 5_333_333,
            vec![7u8; BLOCK_PAYLOAD_BYTES],
        ))
        .expect("signed N01 frame of the new stream");
    let event = rig
        .endpoint
        .media_mut()
        .ingest_authenticated(&mut rig.platform, &mut rig.clock, &new_wire)
        .expect("the new stream is bound");
    assert_eq!(
        (event.stream, event.source_epoch, event.format),
        (fresh.get(), 2, AuthenticatedFormat::N01Media)
    );
}

/// A signed N01 media frame of block `block` (256 frames each) from `sender`, in the shape the other tests here use.
fn signed(sender: &mut StreamSender, rig: &Rig, block: u64, tag: u8) -> Vec<u8> {
    let presentation = rig.start + block * 5_333_333;
    sender
        .send(OutboundFrame::media(
            block * 256,
            presentation,
            presentation - 5_333_333,
            vec![tag; BLOCK_PAYLOAD_BYTES],
        ))
        .expect("signed N01 frame")
}

#[test]
fn n06_carrier_restart_stream_swaps_media_and_carrier_together_and_credit_restarts_from_zero() {
    let mut rig = Rig::new(false); // the N01 baseline: a stream restart is not an N06 matter
    rig.at(60 * MS);
    let mut old = StreamSender::new(key(), stream(), 1);
    rig.push(signed(&mut old, &rig, 0, 1));
    let report = rig.poll();
    assert_eq!((report.media_read, report.media_accepted), (1, 1));
    assert_eq!(rig.consumed(), 1);

    // The control path announces a source restart: a fresh stream id and a strictly newer epoch.
    let fresh = StreamId::new(0x5EED_5EED_0000_0007).expect("stream id");
    rig.endpoint.restart_stream(fresh, 2);
    assert_eq!(rig.endpoint.carrier().stream_id(), fresh);
    assert_eq!(rig.endpoint.carrier().epoch(), 2);
    assert_eq!(rig.consumed(), 0, "credit begins again with the new stream");

    // The old stream's next datagram is authentic under the key but names a stream the endpoint is no longer bound to: it is
    // read from the port and refused, and credit stays where it is.
    rig.push(signed(&mut old, &rig, 1, 2));
    let report = rig.poll();
    assert_eq!((report.media_read, report.media_accepted), (1, 0));
    assert_eq!(rig.consumed(), 0);
    assert_eq!(rig.endpoint.verdicts().refused, 1);
    assert_eq!(rig.endpoint.verdicts().credit_refused, 0);

    // The new stream's first datagram, signed under the new id and epoch, is authenticated and credited from sequence 0.
    let mut next = StreamSender::new(key(), fresh, 2);
    rig.push(signed(&mut next, &rig, 0, 3));
    let report = rig.poll();
    assert_eq!((report.media_read, report.media_accepted), (1, 1));
    assert_eq!(rig.consumed(), 1);
    // The engine is still on the old timeline: the clock and the engine are the control path's calls (`begin_epoch`,
    // `admit_start`), not the endpoint's, so it says the new epoch is ahead of its own.
    assert_eq!(rig.endpoint.verdicts().count("future_epoch"), 1);
    assert_eq!(rig.endpoint.verdicts().credit_refused, 0);

    // The report names the new stream, the new epoch and the new position.
    rig.endpoint.report().expect("report sent");
    let sent = rig.sent.borrow();
    let (lane, wire) = sent.last().expect("a report was sent");
    assert_eq!(*lane, Lane::Control);
    assert_eq!(&wire[8..16], &fresh.get().to_be_bytes());
    assert_eq!(&wire[16..24], &2u64.to_be_bytes());
    assert_eq!(&wire[24..32], &1u64.to_be_bytes());
}
