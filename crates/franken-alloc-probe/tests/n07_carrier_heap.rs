//! The N07 carrier's heap, measured on the host (`N07` / `ffw-ybr`): the real `CarrierSender` and one real `CarrierReceiver` per
//! peer, over in-memory rings, through fill, cache and probe, credit clear, rebind and move, and epoch restart, three times
//! round, under the counting allocator.
//!
//! **What is measured.** Every call into the sender (`add_peer`, `submit_media`, `pump`, `poll_reports`, `rebind`,
//! `peer_address_changed`, `advance_epoch`) and into a receiver (`poll`, `take_media`, `send_report`, `advance_epoch`) runs in
//! its own `measure_heap` window, and a `Meter` adds the windows up: the **level** is the heap the sender (or the receivers)
//! hold between calls, the **high-water** is the level plus the window peak at its highest, and the **call peak** is the most one
//! call held above where it started, which is where the temporary encode buffers and the clone a submit makes show up. The rings
//! that stand in for the network are filled before any window opens and never allocate afterwards, and the frames the harness
//! builds are dropped outside the windows, so nothing here is charged to the carrier that is not the carrier's.
//!
//! **The bounds are written from the caps, not read off the run.** `bounds` computes them from the limits: the closed form
//! `CarrierLimits::max_retained_bytes()` (queued wire bytes under the peer and aggregate caps, one cached datagram per peer, the
//! unreported list at its allocated bound, full control queues) for the payload and sequence allocations; the queue slot arrays,
//! which that figure leaves out because they are struct-sized, as slots times the size of a slot, with the slot count bounded by
//! twice the queue caps (a growing queue may reserve up to twice its length); and the two tables, which are struct state and not
//! payload: the sender allocates the peer table and the group table once each, at `max_peers` slots, when it is built, so their
//! bound is `CarrierLimits::max_peer_table_bytes()` plus `CarrierLimits::max_group_table_bytes()` and the sender's own
//! `peer_table_bytes()` plus `group_table_bytes()` must equal it from construction on, with one peer admitted or eight (the
//! slots no peer or group fills are allocated and are counted; the equality assumes the toolchain's `Vec::with_capacity`
//! allocates exactly the request, and if it ever allocated more the check fails and prints both figures rather than widening the
//! bound). Admission is held to allocate exactly the two tables and the peer's unreported list and nothing else; the first
//! native run of this test found 56 bytes more, the primary group's one-slot allocation, which the report did not name, and the
//! group table (preallocated and reported, with this check unchanged) is the fix, not a wider tolerance. The measured figures
//! only have to fit. The report is held to the
//! heap too: it may only name bytes that are live, and the heap may not exceed what it names plus the slots and the table.
//!
//! **Slacks, stated and not hidden.** A rebind and a move there and back may leave the level up to one datagram (1104 B) away
//! from where it started, and between the last two rounds the level may rise by up to two datagrams for each peer. Both are
//! checked as those bounded differences; neither is a claim that a round retains nothing or that the carrier cannot leak.
//!
//! **Pairs.** An ordinary run (one peer, a window of 16, the queue at the per-peer cap) and a boundary run (the peer cap of
//! eight, the largest window of 4096, which the 1000-number sequence budget bounds, the queue at the aggregate cap, one
//! receiver held until its inbound queue is full) both pass their own bounds, and each reaches its caps exactly, so neither is
//! vacuous. A port that keeps every datagram it is handed (a real retained-growth plant, through the real carrier) is caught
//! by the growth check; every other check is shown to fail on a synthetic edit of a passing run, one at a time, so none is
//! carried by another.
//!
//! **Groups.** A second kind of run builds a sender at a peer cap that is not a power of two (3 and 5, where a registry grown by
//! pushing would hold more slots than the cap), adds groups up to the cap, is refused the one past it, loses one and takes
//! another back, each call in its own window. Building holds exactly the two tables, the group table is its bound at the start
//! and at the end, and no group call allocates, not even for an instant. Each of those checks fails on a synthetic edit of the
//! passing run, one at a time.
//!
//! **What this is not.** Host heap only, in the bytes the program asked for (not what the system allocator reserved, and not
//! fragmentation); inline sizes are those of the platform the test runs on. Nothing here ran on a board or a guest; it is not a
//! resident-set, stack, kernel-buffer or CPU figure and admits no profile. It covers the media and report phases it drives, not
//! every heap path of N07: the sender's control queue is never filled here (the rig routes only receiver reports on the control
//! lane), so its allowance in the closed form is bound but not exercised. The size of the private per-peer state is not read by
//! the test: the table is taken in bytes from the crate's own report and bound, and the queue slot size is that of the public
//! `OutboundFrame` plus two words.
use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;

use franken_alloc_probe::{CountingAllocator, heap_is_tracked, measure_heap};
use franken_stream::carrier::{
    CarrierError, CarrierLimits, CarrierReceiver, CarrierSender, DatagramPort, Lane,
    MAX_CONTROL_BYTES, MAX_WINDOW_PACKETS, PortFault, Received, ReceiverLimits, RetainedBytes,
    SEQ_AHEAD_LIMIT,
};
use franken_stream::{
    AuthenticatedStreamPacket, MAX_DATAGRAM_BYTES, MAX_PAYLOAD_BYTES, OutboundFrame, StreamId,
    StreamKey,
};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator::new();

const MS: u64 = 1_000_000;
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// Slots in each in-memory ring, every one allocated before a window opens.
const RING_SLOTS: usize = 64;
/// Fill-and-clear rounds, and iterations (one millisecond each) of a fill: enough for a window of 16 to stall and be probed, and
/// for the largest window to spend the whole sequence budget and be probed too.
const ROUNDS: usize = 3;
const FILL: u64 = 1_300;
/// Iterations at the start of the first round in which receiver 1 reads but does not take what it read.
const HOLD: u64 = 100;
/// Bytes of fixed state per receiver beyond its queues.
const RX_FIXED: usize = 1_024;
/// How many datagram-sized units one call may hold at its peak: the clone a submit makes, the encoded wire, the signing scratch,
/// the old and the new block of a queue that is growing.
const CALL_UNITS: usize = 6;
/// What one queue slot of the sender can hold: the public frame it queues, the byte count and the arrival time.
const MEDIA_SLOT: usize = size_of::<OutboundFrame>() + 2 * size_of::<u64>();
const CONTROL_SLOT: usize = size_of::<Vec<u8>>();

fn key() -> StreamKey {
    StreamKey::from_bytes([0x71; 32])
}

fn stream() -> StreamId {
    StreamId::new(0x0700_0000_0000_0071).expect("a nonzero stream id")
}

fn peer_port(id: u32) -> u16 {
    43_000 + 2 * u16::try_from(id).expect("a small peer id")
}

fn peer_media(id: u32) -> SocketAddr {
    SocketAddr::new(LOOPBACK, peer_port(id))
}

fn peer_control(id: u32) -> SocketAddr {
    SocketAddr::new(LOOPBACK, peer_port(id) + 1)
}

fn receiver_local(id: u32) -> SocketAddr {
    SocketAddr::new(
        LOOPBACK,
        41_100 + 2 * u16::try_from(id).expect("a small peer id"),
    )
}

fn moved_media(id: u32) -> SocketAddr {
    SocketAddr::new(LOOPBACK, peer_port(id) + 100)
}

fn moved_control(id: u32) -> SocketAddr {
    SocketAddr::new(LOOPBACK, peer_port(id) + 101)
}

fn block_frame(index: u64, now_ns: u64) -> OutboundFrame {
    OutboundFrame::media(
        index * 256,
        now_ns + 4_000_000_000,
        now_ns + 2_000_000_000,
        vec![0x11; MAX_PAYLOAD_BYTES],
    )
}

// ------------------------------------------------------------------------------------------------- the network, in memory

/// A fixed ring of datagram slots, each allocated at its full size before any window opens. A push copies into a slot and a pop
/// copies out: neither allocates. A push into a full ring is a harness fault and panics, so no datagram is lost unseen.
struct Ring {
    slots: Vec<Vec<u8>>,
    head: usize,
    len: usize,
}

type Shared = Rc<RefCell<Ring>>;

impl Ring {
    fn new(slots: usize) -> Shared {
        Rc::new(RefCell::new(Self {
            slots: (0..slots)
                .map(|_| Vec::with_capacity(MAX_DATAGRAM_BYTES + 1))
                .collect(),
            head: 0,
            len: 0,
        }))
    }

    fn push(&mut self, bytes: &[u8]) {
        assert!(self.len < self.slots.len(), "a ring of the rig is full");
        let at = (self.head + self.len) % self.slots.len();
        let slot = &mut self.slots[at];
        slot.clear();
        slot.extend_from_slice(bytes);
        self.len += 1;
    }

    fn pop_into(&mut self, buf: &mut [u8]) -> Option<usize> {
        if self.len == 0 {
            return None;
        }
        let slot = &self.slots[self.head];
        let n = slot.len().min(buf.len());
        buf[..n].copy_from_slice(&slot[..n]);
        self.head = (self.head + 1) % self.slots.len();
        self.len -= 1;
        Some(n)
    }
}

/// One end's port. The sender's routes a media datagram to the ring of the receiver whose address it names; a receiver's reports
/// go to the one control ring the sender reads. `hoard` is the plant: when set, the port keeps a copy of every media datagram it
/// is handed and never lets go of it.
struct Wire {
    routes: Vec<(SocketAddr, Shared)>,
    send_control: Shared,
    recv_media: Shared,
    recv_control: Shared,
    hoard: Option<Vec<Vec<u8>>>,
    local: SocketAddr,
}

impl DatagramPort for Wire {
    fn send_to(&mut self, lane: Lane, bytes: &[u8], to: SocketAddr) -> Result<(), PortFault> {
        match lane {
            Lane::Media => {
                if let Some(hoard) = self.hoard.as_mut() {
                    hoard.push(bytes.to_vec());
                }
                if let Some((_, ring)) = self.routes.iter().find(|(addr, _)| *addr == to) {
                    ring.borrow_mut().push(bytes);
                }
            }
            Lane::Control => self.send_control.borrow_mut().push(bytes),
        }
        Ok(())
    }

    fn recv(&mut self, lane: Lane, buf: &mut [u8]) -> Result<Received, PortFault> {
        let ring = match lane {
            Lane::Media => &self.recv_media,
            Lane::Control => &self.recv_control,
        };
        let got = ring.borrow_mut().pop_into(buf);
        match got {
            Some(len) => Ok(Received { len, from: None }),
            None => Err(PortFault::WouldBlock),
        }
    }

    fn local_addr(&self, lane: Lane) -> Result<SocketAddr, PortFault> {
        Ok(match lane {
            Lane::Media => self.local,
            Lane::Control => SocketAddr::new(self.local.ip(), self.local.port() + 1),
        })
    }

    fn rebind(&mut self, ip: IpAddr) -> Result<(), PortFault> {
        self.local = SocketAddr::new(ip, self.local.port());
        Ok(())
    }
}

// ------------------------------------------------------------------------------------------------------------- the meter

/// Adds up the `measure_heap` windows of one party's calls.
#[derive(Default)]
struct Meter {
    /// The heap held between calls, relative to before the first.
    level: isize,
    /// The most that heap held at any instant, inside a call or between two.
    high: isize,
    /// The most any one call held above where it started.
    call_peak: usize,
    /// The peak of the call made last.
    last_peak: usize,
}

impl Meter {
    fn call<R>(&mut self, f: impl FnOnce() -> R) -> R {
        let (result, window) = measure_heap(f);
        let peak = isize::try_from(window.peak_above_start).unwrap_or(isize::MAX);
        self.high = self.high.max(self.level.saturating_add(peak));
        self.call_peak = self.call_peak.max(window.peak_above_start);
        self.last_peak = window.peak_above_start;
        self.level = self.level.saturating_add(window.net_bytes);
        result
    }
}

// ----------------------------------------------------------------------------------------------------------------- the rig

#[derive(Debug, Clone)]
struct Checkpoint {
    level: isize,
    report: RetainedBytes,
    /// The peer table and the group table in bytes, by the sender's own reports (see `CarrierSender::peer_table_bytes` and
    /// `CarrierSender::group_table_bytes`).
    table: usize,
}

struct Rig {
    sender: CarrierSender<Wire>,
    receivers: Vec<CarrierReceiver<Wire>>,
    meter: Meter,
    rx: Meter,
    now: u64,
    index: u64,
    epoch: u64,
}

impl Rig {
    fn new(limits: &CarrierLimits, peers: u32, hoard: bool) -> Self {
        let reports = Ring::new(RING_SLOTS);
        let mut routes = Vec::new();
        let mut receivers = Vec::new();
        let mut rx = Meter::default();
        for id in 1..=peers {
            let media_ring = Ring::new(RING_SLOTS);
            routes.push((peer_media(id), Rc::clone(&media_ring)));
            let wire = Wire {
                routes: Vec::new(),
                send_control: Rc::clone(&reports),
                recv_media: media_ring,
                recv_control: Ring::new(1),
                hoard: None,
                local: receiver_local(id),
            };
            let receiver = rx.call(|| {
                CarrierReceiver::with_port(
                    key(),
                    stream(),
                    1,
                    ReceiverLimits::baseline(),
                    wire,
                    SocketAddr::new(LOOPBACK, 41_001),
                )
                .expect("a receiver")
                .with_peer_id(id)
                .expect("a peer id that fits")
            });
            receivers.push(receiver);
        }
        let wire = Wire {
            routes,
            send_control: Ring::new(1),
            recv_media: Ring::new(1),
            recv_control: reports,
            hoard: hoard.then(Vec::new),
            local: SocketAddr::new(LOOPBACK, 41_000),
        };
        let mut meter = Meter::default();
        let mut sender = meter.call(|| {
            CarrierSender::with_port(key(), stream(), 1, limits.clone(), wire).expect("a sender")
        });
        for id in 1..=peers {
            meter
                .call(|| sender.add_peer(id, peer_media(id), peer_control(id), 1500))
                .expect("a peer within the limits");
        }
        Self {
            sender,
            receivers,
            meter,
            rx,
            now: 0,
            index: 0,
            epoch: 1,
        }
    }

    /// One millisecond: a block is submitted to every peer, the sender pumps, and every receiver reads. A receiver that is `held`
    /// reads into its inbound queue but does not take what it read.
    fn step(&mut self, held: bool) {
        self.now += MS;
        let block = block_frame(self.index, self.now);
        self.index += 1;
        let (now, epoch) = (self.now, self.epoch);
        let sender = &mut self.sender;
        self.meter
            .call(|| sender.submit_media(epoch, &block, now))
            .expect("the epoch is current");
        self.meter.call(|| sender.pump(now));
        drop(block);
        for (position, receiver) in self.receivers.iter_mut().enumerate() {
            let hold = held && position == 0;
            self.rx.call(|| {
                receiver.poll();
                if !hold {
                    drop(receiver.take_media(usize::MAX));
                }
            });
        }
    }

    /// Every receiver reports what it consumed, and the sender reads the reports. Returns the unreported numbers the sender still
    /// counts, by length, afterwards.
    fn clear(&mut self) -> u64 {
        for receiver in &mut self.receivers {
            self.rx
                .call(|| receiver.send_report().expect("the receiver reports"));
        }
        let sender = &mut self.sender;
        let applied = self.meter.call(|| sender.poll_reports());
        assert_eq!(
            usize::try_from(applied).expect("a count"),
            self.receivers.len(),
            "every report moved its peer"
        );
        (1..=u32::try_from(self.receivers.len()).expect("a small count"))
            .map(|id| self.sender.peer_view(id).expect("a peer").in_flight)
            .sum()
    }

    fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            level: self.meter.level,
            report: self.sender.retained_bytes(),
            table: self
                .sender
                .peer_table_bytes()
                .saturating_add(self.sender.group_table_bytes()),
        }
    }
}

// --------------------------------------------------------------------------------------------------------------- the plans

struct Plan {
    limits: CarrierLimits,
    peers: usize,
}

/// One peer, a window of 16, the queue at the per-peer cap.
fn ordinary() -> Plan {
    Plan {
        limits: CarrierLimits {
            pace_bytes_per_sec: 1_000_000_000,
            pace_burst_bytes: 1_000_000,
            ..CarrierLimits::baseline()
        },
        peers: 1,
    }
}

/// The peer cap, the largest window (bounded in effect by the sequence budget), the queue at the aggregate cap.
fn boundary() -> Plan {
    let limits = CarrierLimits {
        window_packets: MAX_WINDOW_PACKETS,
        pace_bytes_per_sec: 1_000_000_000,
        pace_burst_bytes: 1_000_000,
        ..CarrierLimits::baseline()
    };
    let peers = limits.max_peers;
    Plan { limits, peers }
}

impl Plan {
    /// Numbers the unreported list can hold: the smaller of the window and the sequence budget.
    fn window_effective(&self) -> usize {
        let budget = usize::try_from(SEQ_AHEAD_LIMIT).expect("fits");
        usize::try_from(self.limits.window_packets)
            .expect("fits")
            .min(budget)
    }

    /// Frames the queues hold when full: the aggregate cap binds before the per-peer caps added up.
    fn queued_frames(&self) -> usize {
        self.limits
            .aggregate_queue_packets
            .min(self.peers * self.limits.peer_queue_packets)
    }
}

// ----------------------------------------------------------------------------------------------------------------- the run

#[derive(Debug, Clone)]
struct Run {
    admitted: Checkpoint,
    filled: Checkpoint,
    cleared: Checkpoint,
    moved: Checkpoint,
    restarted: Checkpoint,
    reused: Checkpoint,
    sender_high: isize,
    call_peak: usize,
    first_pump_peak: usize,
    /// What the heap held after construction and admission beyond the two tables and the unreported lists: nothing, since those
    /// are all the two allocate.
    admission_extra: isize,
    /// The sender's level after each round's credit clear.
    cycle_levels: Vec<isize>,
    /// Unreported numbers the sender still counted right after a clear (by length): zero, while the allocation stays.
    logical_after_clear: u64,
    probes_sent: u64,
    rx_high: isize,
    rx_call_peak: usize,
    /// Receiver 1 at the end of its hold: what its inbound queue held and how many datagrams it refused for want of room.
    rx_inbound: usize,
    rx_overflow: u64,
}

fn drive(plan: &Plan, hoard: bool) -> Run {
    let peers = u32::try_from(plan.peers).expect("a small count");
    let mut rig = Rig::new(&plan.limits, peers, hoard);
    let admitted = rig.checkpoint();
    let allocated = isize::try_from(admitted.report.unreported).expect("fits");
    let table = isize::try_from(admitted.table).expect("fits");
    let admission_extra = admitted.level - allocated - table;

    // the first millisecond, which signs and caches the first datagram of every peer, is also the first of receiver 1's hold
    rig.step(true);
    let first_pump_peak = rig.meter.last_peak;

    let (mut filled, mut logical_after_clear) = (admitted.clone(), 0);
    let (mut rx_inbound, mut rx_overflow) = (0, 0);
    let mut cycle_levels = Vec::new();
    for round in 0..ROUNDS {
        for i in 0..FILL {
            // the hold is `HOLD` milliseconds in all, counting the first one above
            let held = round == 0 && i + 1 < HOLD;
            rig.step(held);
            if round == 0 && i + 2 == HOLD {
                rx_inbound = rig.receivers[0].inbound_len();
                rx_overflow = rig.receivers[0].stats().inbound_overflow;
            }
        }
        if round == 0 {
            filled = rig.checkpoint();
        }
        logical_after_clear += rig.clear();
        cycle_levels.push(rig.meter.level);
    }
    let cleared = rig.checkpoint();
    let probes_sent = rig.sender.control_stats().probes_sent;

    // a rebind of the local sockets, and every peer moved to another address and back
    let sender = &mut rig.sender;
    rig.meter
        .call(|| sender.rebind(LOOPBACK))
        .expect("the sockets rebind");
    for id in 1..=peers {
        rig.meter
            .call(|| sender.peer_address_changed(id, moved_media(id), moved_control(id)))
            .expect("the peer moves");
        rig.meter
            .call(|| sender.peer_address_changed(id, peer_media(id), peer_control(id)))
            .expect("the peer moves back");
    }
    let moved = rig.checkpoint();

    // an epoch restart: every count starts again, and the receivers adopt it
    let sender = &mut rig.sender;
    rig.meter
        .call(|| sender.advance_epoch(2))
        .expect("a newer epoch");
    for receiver in &mut rig.receivers {
        rig.rx.call(|| receiver.advance_epoch(2));
    }
    rig.epoch = 2;
    let restarted = rig.checkpoint();
    for _ in 0..30 {
        rig.step(false);
    }
    let reused = rig.checkpoint();

    Run {
        admitted,
        filled,
        cleared,
        moved,
        restarted,
        reused,
        sender_high: rig.meter.high,
        call_peak: rig.meter.call_peak,
        first_pump_peak,
        admission_extra,
        cycle_levels,
        logical_after_clear,
        probes_sent,
        rx_high: rig.rx.high,
        rx_call_peak: rig.rx.call_peak,
        rx_inbound,
        rx_overflow,
    }
}

// ------------------------------------------------------------------------------------------------ the bounds, from the caps

struct Bounds {
    /// The most heap the sender may hold at any instant.
    retained: isize,
    /// The most one sender call may hold above where it started.
    call: usize,
    /// The most the first pump may hold: it signs and caches one datagram for every peer.
    first_pump: usize,
    /// The most slots the two queues of all peers may have allocated.
    queue_slots: usize,
    /// The peer table and the group table at their bounds, from the limits alone: the sender allocates all of both when it is built.
    table: usize,
    /// The largest the report's total may be.
    total: usize,
    /// How far one round's level may sit above the last.
    growth: usize,
    rx_retained: isize,
    rx_call: usize,
}

/// The two tables at their bounds, from the limits alone: the peer table and the group table, each `max_peers` slots.
fn tables(limits: &CarrierLimits) -> usize {
    limits
        .max_peer_table_bytes()
        .saturating_add(limits.max_group_table_bytes())
}

fn bounds(plan: &Plan) -> Bounds {
    let limits = &plan.limits;
    let mut admitted = limits.clone();
    admitted.max_peers = plan.peers;
    let accounted = admitted.max_retained_bytes();
    let queue_slots = plan.peers * 2 * (limits.peer_queue_packets + limits.control_queue_packets);
    let slots = queue_slots * MEDIA_SLOT.max(CONTROL_SLOT);
    // the configured peer cap, not the admitted count: the tables are allocated at the cap whatever is admitted
    let table = tables(limits);
    let unreported_each = plan.window_effective() * size_of::<u64>();
    let rl = ReceiverLimits::baseline();
    let rx_each =
        2 * rl.inbound_packets * (MAX_PAYLOAD_BYTES + size_of::<AuthenticatedStreamPacket>())
            + 2 * rl.control_inbox_packets * (MAX_CONTROL_BYTES + size_of::<Vec<u8>>())
            + RX_FIXED;
    Bounds {
        retained: isize::try_from(
            accounted
                .total()
                .saturating_add(slots)
                .saturating_add(table),
        )
        .unwrap_or(isize::MAX),
        // the call that builds the sender allocates both tables at once
        call: (CALL_UNITS + plan.peers) * MAX_DATAGRAM_BYTES + 2 * slots + unreported_each + table,
        first_pump: (CALL_UNITS + plan.peers) * MAX_DATAGRAM_BYTES,
        queue_slots,
        table,
        total: accounted.total(),
        growth: plan.peers * 2 * MAX_DATAGRAM_BYTES,
        rx_retained: isize::try_from(plan.peers * rx_each).unwrap_or(isize::MAX),
        rx_call: rx_each + CALL_UNITS * MAX_DATAGRAM_BYTES,
    }
}

/// The names of the checks the run breaks; empty if it breaks none.
fn failures(run: &Run, plan: &Plan, b: &Bounds) -> Vec<&'static str> {
    let mut bad = Vec::new();
    let signed = |bytes: usize| isize::try_from(bytes).unwrap_or(isize::MAX);
    if run.sender_high > b.retained {
        bad.push("HIGH");
    }
    if run.call_peak > b.call {
        bad.push("CALL");
    }
    // the temporary encode peak is observed (a datagram really was live) and is a few datagrams, not hidden and not unbounded
    if run.first_pump_peak < MAX_DATAGRAM_BYTES || run.first_pump_peak > b.first_pump {
        bad.push("ENCODE");
    }
    // admission allocates the two tables and the unreported lists and nothing else (the slots no peer or group fills are still in
    // the level)
    if run.admission_extra != 0 {
        bad.push("ADMIT");
    }
    for point in [
        &run.admitted,
        &run.filled,
        &run.cleared,
        &run.moved,
        &run.restarted,
        &run.reused,
    ] {
        let report = &point.report;
        // the peer table is its bound from construction on, with every slot counted whether or not a peer fills it
        if point.table != b.table {
            bad.push("TABLE");
        }
        // the report names only bytes that are live (the table included) ...
        if point.level
            < signed(
                report
                    .unreported
                    .saturating_add(report.cached)
                    .saturating_add(point.table),
            )
        {
            bad.push("REPORT-LIVE");
        }
        // ... and the heap holds nothing beyond it but the slot arrays and the table
        let beyond = report
            .total()
            .saturating_add(
                report
                    .queue_slots
                    .saturating_mul(MEDIA_SLOT.max(CONTROL_SLOT)),
            )
            .saturating_add(b.table);
        if point.level > signed(beyond) {
            bad.push("REPORT-COVERS");
        }
        if report.queue_slots > b.queue_slots {
            bad.push("SLOTS");
        }
        if report.total() > b.total {
            bad.push("TOTAL");
        }
    }
    // the level between the last two rounds rises by no more than two datagrams for each peer: a bounded slack, not zero growth
    if let [.., before, last] = run.cycle_levels.as_slice() {
        if last.saturating_sub(*before) > signed(b.growth) {
            bad.push("GROWTH");
        }
    } else {
        bad.push("GROWTH");
    }
    // the caps are reached exactly: a datagram cached per peer, the queues full, the list allocated at its bound
    let unreported = plan.peers * plan.window_effective() * size_of::<u64>();
    if run.filled.report.cached != plan.peers * MAX_DATAGRAM_BYTES
        || run.filled.report.queued != plan.queued_frames() * MAX_DATAGRAM_BYTES
        || run.filled.report.unreported != unreported
        || run.probes_sent == 0
    {
        bad.push("CAPS");
    }
    // a credit clear empties the list by length and leaves the allocation, and the report still shows it
    if run.logical_after_clear != 0 || run.cleared.report.unreported != run.filled.report.unreported
    {
        bad.push("CLEAR");
    }
    // a rebind and a move there and back leave the level within one datagram of where it was: a bounded slack, not equality
    if run.moved.level.abs_diff(run.cleared.level) > MAX_DATAGRAM_BYTES {
        bad.push("MOVE");
    }
    // an epoch restart drops the cached datagram and the queues, and keeps the allocation
    if run.restarted.report.cached != 0
        || run.restarted.report.unreported != run.filled.report.unreported
        || run.restarted.level >= run.moved.level
    {
        bad.push("EPOCH");
    }
    // the receivers: under their caps, and receiver 1 held exactly to its inbound cap or to what was sent
    let rl = ReceiverLimits::baseline();
    let sent_in_hold = plan
        .window_effective()
        .min(usize::try_from(HOLD).expect("fits"));
    let held = sent_in_hold.min(rl.inbound_packets);
    if run.rx_high > b.rx_retained
        || run.rx_call_peak > b.rx_call
        || run.rx_inbound != held
        || run.rx_overflow != u64::try_from(sent_in_hold - held).expect("fits")
    {
        bad.push("RX");
    }
    bad.sort_unstable();
    bad.dedup();
    bad
}

// ---------------------------------------------------------------------------------------------------------------- the groups

/// A sender that carries as many groups as its cap allows, is refused the one past it, loses one and takes another: the heap each
/// call held, and the group table the sender reported right after it was built and at the end.
#[derive(Debug, Clone)]
struct GroupRun {
    max_peers: usize,
    /// The heap the call that built the sender left behind.
    built_level: isize,
    /// Both tables at their bounds, and the group table alone, from the limits.
    tables: usize,
    bound: usize,
    table_built: usize,
    table_end: usize,
    /// The net heap and the peak above the start of each group call, in order: the groups added up to the cap, the one past it,
    /// a removal, and the add-back.
    calls: Vec<(isize, usize)>,
    /// Whether the call past the cap was refused as past the cap, and how many groups the sender carried at the end.
    refused: bool,
    groups_end: usize,
}

fn measured<R>(calls: &mut Vec<(isize, usize)>, f: impl FnOnce() -> R) -> R {
    let (result, window) = measure_heap(f);
    calls.push((window.net_bytes, window.peak_above_start));
    result
}

fn group_stream(n: usize) -> StreamId {
    StreamId::new(0x0700_0000_0000_2000 + u64::try_from(n).expect("a small count"))
        .expect("a nonzero stream id")
}

fn group_run(max_peers: usize) -> GroupRun {
    let limits = CarrierLimits {
        max_peers,
        ..CarrierLimits::baseline()
    };
    let wire = Wire {
        routes: Vec::new(),
        send_control: Ring::new(1),
        recv_media: Ring::new(1),
        recv_control: Ring::new(1),
        hoard: None,
        local: SocketAddr::new(LOOPBACK, 41_000),
    };
    let (built, window) =
        measure_heap(|| CarrierSender::with_port(key(), stream(), 1, limits.clone(), wire));
    let mut sender = built.expect("a sender");
    let table_built = sender.group_table_bytes();
    let mut calls = Vec::new();
    let mut added = Vec::new();
    // the primary group holds one slot, so the cap allows `max_peers - 1` more
    for n in 1..max_peers {
        let (group_key, id) = (key(), group_stream(n));
        let group = measured(&mut calls, || sender.add_group(group_key, id, 3));
        added.push(group.expect("a group within the cap"));
    }
    let (group_key, id) = (key(), group_stream(max_peers));
    let refused = matches!(
        measured(&mut calls, || sender.add_group(group_key, id, 3)),
        Err(CarrierError::TooManyGroups { max }) if max == max_peers
    );
    let gone = *added.first().expect("a cap with room for a second group");
    measured(&mut calls, || sender.remove_group(gone)).expect("a group leaves");
    let (group_key, id) = (key(), group_stream(0));
    measured(&mut calls, || sender.add_group(group_key, id, 3)).expect("room again");
    GroupRun {
        max_peers,
        built_level: window.net_bytes,
        tables: tables(&limits),
        bound: limits.max_group_table_bytes(),
        table_built,
        table_end: sender.group_table_bytes(),
        calls,
        refused,
        groups_end: sender.group_ids().len(),
    }
}

/// The names of the checks a group run breaks; empty if it breaks none.
fn group_failures(run: &GroupRun) -> Vec<&'static str> {
    let mut bad = Vec::new();
    // building the sender allocates the two tables and nothing else: no peer is admitted, so no list exists yet
    if run.built_level != isize::try_from(run.tables).unwrap_or(isize::MAX) {
        bad.push("G-BUILD");
    }
    // the group table is its bound from construction on and at the end, whether one slot is filled or all of them
    if run.table_built != run.bound || run.table_end != run.bound {
        bad.push("G-TABLE");
    }
    // adding a group, a refusal past the cap, a removal and an add-back allocate nothing, not even for an instant
    if run.calls.iter().any(|&(net, peak)| net != 0 || peak != 0) {
        bad.push("G-ALLOC");
    }
    // every call was made and measured, the cap was reached, and the one past it was refused as such
    if run.calls.len() != run.max_peers + 2 || !run.refused || run.groups_end != run.max_peers {
        bad.push("G-CAP");
    }
    bad
}

// ----------------------------------------------------------------------------------------------------------------- the tests

#[test]
fn the_heap_figure_is_live_in_this_binary() {
    assert!(
        heap_is_tracked(),
        "the counting allocator is not this binary's global allocator, or its live figure did not move"
    );
}

#[test]
fn n07_the_carrier_heap_at_ordinary_caps_fits_the_bound_written_from_them() {
    assert!(heap_is_tracked());
    let plan = ordinary();
    let run = drive(&plan, false);
    assert_eq!(
        failures(&run, &plan, &bounds(&plan)),
        Vec::<&str>::new(),
        "{run:#?}"
    );
    // the ordinary case: the per-peer cap binds, and the list is the window of 16
    assert_eq!(plan.queued_frames(), plan.limits.peer_queue_packets);
    assert_eq!(run.filled.report.unreported, 16 * size_of::<u64>());
    // one peer of eight: the tables are allocated at the configured cap whatever is admitted, so the spare slots exist, are
    // reported, and are in the level (the level holds at least the tables before a single list or datagram is counted)
    assert!(plan.peers < plan.limits.max_peers);
    assert_eq!(run.admitted.table, tables(&plan.limits));
    assert!(run.admitted.level >= isize::try_from(run.admitted.table).expect("fits"));
}

#[test]
fn n07_the_carrier_heap_at_the_peer_aggregate_and_window_caps_fits_the_bound_written_from_them() {
    assert!(heap_is_tracked());
    let plan = boundary();
    let run = drive(&plan, false);
    assert_eq!(
        failures(&run, &plan, &bounds(&plan)),
        Vec::<&str>::new(),
        "{run:#?}"
    );
    // the boundary: eight peers, the aggregate packet cap binding before the per-peer caps added up, the list at the
    // sequence budget under a window of 4096, and a receiver held until its inbound queue was full and refusing
    assert_eq!(plan.peers, plan.limits.max_peers);
    assert_eq!(run.admitted.table, tables(&plan.limits));
    assert!(plan.queued_frames() < plan.peers * plan.limits.peer_queue_packets);
    assert_eq!(
        run.filled.report.unreported,
        plan.peers * usize::try_from(SEQ_AHEAD_LIMIT).expect("fits") * size_of::<u64>()
    );
    assert_eq!(run.rx_inbound, ReceiverLimits::baseline().inbound_packets);
    assert!(run.rx_overflow > 0);
    // and the boundary holds more than the ordinary case, so neither pass is vacuous
    let small = drive(&ordinary(), false);
    assert!(run.sender_high > small.sender_high);
}

#[test]
fn n07_a_port_that_keeps_every_datagram_is_caught_as_growth() {
    assert!(heap_is_tracked());
    let plan = ordinary();
    let b = bounds(&plan);
    // the control: the same run without the plant passes
    assert_eq!(
        failures(&drive(&plan, false), &plan, &b),
        Vec::<&str>::new()
    );
    // the plant: the port the real carrier sends through keeps a copy of everything it is handed, so each round leaves more heap
    let leaking = drive(&plan, true);
    let bad = failures(&leaking, &plan, &b);
    assert!(bad.contains(&"GROWTH"), "{bad:?}");
    let [.., before, last] = leaking.cycle_levels.as_slice() else {
        panic!("rounds were run");
    };
    assert!(
        last - before > isize::try_from(b.growth).expect("fits"),
        "{:?}",
        leaking.cycle_levels
    );
}

#[test]
fn n07_each_heap_check_fails_on_its_own_synthetic_edit_of_a_passing_run() {
    assert!(heap_is_tracked());
    let plan = ordinary();
    let b = bounds(&plan);
    let base = drive(&plan, false);
    assert_eq!(failures(&base, &plan, &b), Vec::<&str>::new());
    let check = |name: &'static str, plant: &dyn Fn(&mut Run)| {
        let mut run = base.clone();
        plant(&mut run);
        let bad = failures(&run, &plan, &b);
        assert!(bad.contains(&name), "{name} was not caught: {bad:?}");
    };
    // large enough to beat any difference between two rounds of the unedited run
    let beyond_growth = isize::try_from(2 * b.growth + 1).expect("fits");
    let beyond_total = isize::try_from(b.total + 1).expect("fits");
    let one_more = isize::try_from(MAX_DATAGRAM_BYTES + 1).expect("fits");
    check("HIGH", &|r: &mut Run| r.sender_high = b.retained + 1);
    check("CALL", &|r: &mut Run| r.call_peak = b.call + 1);
    check("ENCODE", &|r: &mut Run| r.first_pump_peak = 0);
    check("ADMIT", &|r: &mut Run| r.admission_extra = 1);
    check("TABLE", &|r: &mut Run| r.admitted.table = b.table + 1);
    check("TABLE", &|r: &mut Run| r.filled.table = b.table - 1);
    check("REPORT-LIVE", &|r: &mut Run| r.filled.level = 0);
    // the control for the spare table slots (one peer and the one group fill a slot of each table): a measurement that did not
    // see them (the level without the slots no peer or group fills) cannot hold the tables the sender reports, and is caught; so
    // the spare allocation stays charged
    let spare =
        isize::try_from(b.table / plan.limits.max_peers * (plan.limits.max_peers - plan.peers))
            .expect("fits");
    assert!(spare > 0, "the ordinary plan leaves table slots unfilled");
    check("REPORT-LIVE", &|r: &mut Run| r.admitted.level -= spare);
    check("REPORT-COVERS", &|r: &mut Run| {
        r.filled.level += beyond_total
    });
    // and at the one checkpoint where no queued frame's over-count can hide a byte: admission, where the level is exactly the
    // tables and the lists, so a single byte more than the report names is caught (the 56 the first native run found was
    // hidden everywhere else)
    check("REPORT-COVERS", &|r: &mut Run| r.admitted.level += 1);
    check("SLOTS", &|r: &mut Run| {
        r.filled.report.queue_slots = b.queue_slots + 1;
    });
    check("TOTAL", &|r: &mut Run| r.filled.report.queued = b.total + 1);
    check("GROWTH", &|r: &mut Run| {
        let n = r.cycle_levels.len();
        r.cycle_levels[n - 1] += beyond_growth;
    });
    check("CAPS", &|r: &mut Run| r.filled.report.queued += 1);
    check("CLEAR", &|r: &mut Run| r.cleared.report.unreported = 0);
    check("MOVE", &|r: &mut Run| r.moved.level += one_more);
    check("EPOCH", &|r: &mut Run| r.restarted.report.cached = 1);
    check("RX", &|r: &mut Run| r.rx_inbound += 1);
}

#[test]
fn n07_groups_come_and_go_without_moving_the_heap_at_peer_caps_that_are_not_powers_of_two() {
    assert!(heap_is_tracked());
    for max_peers in [3, 5] {
        let run = group_run(max_peers);
        assert_eq!(group_failures(&run), Vec::<&str>::new(), "{run:#?}");
        // the group table is a real allocation of its own, and the cap is reached and passed
        assert!(run.bound > 0);
        assert_eq!(run.groups_end, max_peers);
    }
}

#[test]
fn n07_each_group_heap_check_fails_on_its_own_synthetic_edit_of_a_passing_run() {
    assert!(heap_is_tracked());
    let base = group_run(5);
    assert_eq!(group_failures(&base), Vec::<&str>::new());
    let check = |name: &'static str, plant: &dyn Fn(&mut GroupRun)| {
        let mut run = base.clone();
        plant(&mut run);
        let bad = group_failures(&run);
        assert!(bad.contains(&name), "{name} was not caught: {bad:?}");
    };
    // a build that holds one byte more or less than the two tables (the first native run's was a registry of one slot, built
    // beside a table that did not count it)
    check("G-BUILD", &|r: &mut GroupRun| r.built_level += 1);
    check("G-BUILD", &|r: &mut GroupRun| r.built_level -= 1);
    // a group table that is not its bound at the start, or that moved by the end
    check("G-TABLE", &|r: &mut GroupRun| r.table_built = r.bound + 1);
    check("G-TABLE", &|r: &mut GroupRun| r.table_built = r.bound - 1);
    check("G-TABLE", &|r: &mut GroupRun| r.table_end = r.bound + 1);
    // a group call that kept a byte, or that held one for an instant: an add, the refusal, the removal, the add-back
    check("G-ALLOC", &|r: &mut GroupRun| r.calls[0].0 = 1);
    check("G-ALLOC", &|r: &mut GroupRun| r.calls[0].1 = 1);
    check("G-ALLOC", &|r: &mut GroupRun| r.calls[4].0 = 1);
    check("G-ALLOC", &|r: &mut GroupRun| r.calls[5].0 = -1);
    check("G-ALLOC", &|r: &mut GroupRun| r.calls[6].1 = 1);
    // a call that was never measured, a past-the-cap call that was not refused as such, a cap that was not reached
    check("G-CAP", &|r: &mut GroupRun| {
        r.calls.pop();
    });
    check("G-CAP", &|r: &mut GroupRun| r.refused = false);
    check("G-CAP", &|r: &mut GroupRun| r.groups_end -= 1);
}
