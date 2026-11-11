//! N07 actual-carrier end to end (bead `ffw-ybr`, `docs/contracts/n07.md`): the paced UDP carrier over real sockets bound to
//! 127.0.0.1 only. Nothing leaves the host: no LAN, no discovery, no device, no provider.
//!
//! Each scripted world in `vectors/n07_scenarios.json` is played by a small interpreter over a real `CarrierSender`, one real
//! `CarrierReceiver` per peer and, where a script asks for it, a seeded relay that drops and reorders datagrams on the way. The
//! clock is the script's, not the machine's, and every step waits for exactly the datagrams it caused, so the run is lock-step
//! and its numbers do not depend on scheduling. The record it observes is compared, key for key, with the record
//! `tests/n07/model.py` predicts for the same script from the contract alone (the model never sees this code), and each received
//! block is also compared with an independently written sample formula. The observed record is printed as `N07-OBSERVED` for
//! `tests/n07/run_cases.py`.

use franken_stream::carrier::{
    CarrierError, CarrierLimits, CarrierReceiver, CarrierSender, PumpReport, ReceiverLimits,
    SubmitReport,
};
use franken_stream::{OutboundFrame, StreamId, StreamKey, StreamSender};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

const SCENARIOS: &str = include_str!("vectors/n07_scenarios.json");
const WAIT: Duration = Duration::from_secs(5);
const BLOCK_FRAMES: u64 = 256;
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn key() -> StreamKey {
    StreamKey::from_bytes([0x07; 32])
}

fn stream() -> StreamId {
    StreamId::new(0x0700_0000_0000_0001).expect("nonzero stream id")
}

/// The sample oracle: what block `block` carries, written down here and in the model, never taken from the carrier.
fn payload_for_block(block: u64) -> Vec<u8> {
    (0..1024u64)
        .map(|i| ((block * 131 + i * 7 + 3) & 0xFF) as u8)
        .collect()
}

fn frame_for_block(block: u64, now: u64, deadline: u64) -> OutboundFrame {
    OutboundFrame::media(
        block * BLOCK_FRAMES,
        now + deadline + 2_000_000,
        now + deadline,
        payload_for_block(block),
    )
}

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// A seeded lossy hop between the carrier and one receiver, over two real sockets.
struct Relay {
    socket: UdpSocket,
    target: SocketAddr,
    rng: SplitMix64,
    loss_permille: u64,
    reorder_permille: u64,
    lost: u64,
    reordered: u64,
    forwarded: u64,
}

impl Relay {
    fn new(config: &Value, target: SocketAddr) -> Self {
        let socket = UdpSocket::bind((LOOPBACK, 0)).expect("bind relay");
        socket
            .set_read_timeout(Some(WAIT))
            .expect("relay read timeout");
        Self {
            socket,
            target,
            rng: SplitMix64(config["seed"].as_u64().expect("relay seed")),
            loss_permille: config["loss_permille"].as_u64().expect("relay loss"),
            reorder_permille: config["reorder_permille"].as_u64().expect("relay reorder"),
            lost: 0,
            reordered: 0,
            forwarded: 0,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.socket.local_addr().expect("relay address")
    }

    /// Read exactly the `expected` datagrams the carrier sent, drop and swap some of them by the seeded schedule, forward the
    /// rest, and return how many were forwarded.
    fn forward(&mut self, expected: u64) -> u64 {
        let mut buf = [0u8; 2048];
        let mut held: Option<Vec<u8>> = None;
        let mut out: Vec<Vec<u8>> = Vec::new();
        for _ in 0..expected {
            let (len, _) = self
                .socket
                .recv_from(&mut buf)
                .expect("the relay received a datagram the carrier sent");
            let datagram = buf[..len].to_vec();
            if self.rng.next() % 1000 < self.loss_permille {
                self.lost += 1;
                continue;
            }
            let roll = self.rng.next() % 1000;
            if let Some(older) = held.take() {
                out.push(datagram);
                out.push(older);
                self.reordered += 1;
            } else if roll < self.reorder_permille {
                held = Some(datagram);
            } else {
                out.push(datagram);
            }
        }
        if let Some(older) = held.take() {
            out.push(older);
        }
        for datagram in &out {
            self.socket
                .send_to(datagram, self.target)
                .expect("relay forwards");
        }
        self.forwarded += out.len() as u64;
        out.len() as u64
    }
}

struct Rig {
    receiver: CarrierReceiver,
    retired: Vec<CarrierReceiver>,
    relay: Option<Relay>,
    consumer: bool,
    delivered: Vec<Value>,
    control_received: Vec<u64>,
    samples_checked: u64,
    sample_mismatches: u64,
    seen_media: u64,
    seen_control: u64,
}

fn to_json<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("serializes")
}

fn merged<T: Serialize + DeserializeOwned>(base: &T, overrides: Option<&Value>) -> T {
    let mut value = to_json(base);
    if let Some(Value::Object(extra)) = overrides {
        let map = value.as_object_mut().expect("limits are an object");
        for (name, entry) in extra {
            map.insert(name.clone(), entry.clone());
        }
    }
    serde_json::from_value(value).expect("limits deserialize: an unknown field is an error")
}

fn num(op: &Value, name: &str) -> u64 {
    op[name]
        .as_u64()
        .unwrap_or_else(|| panic!("op {op} needs a number {name}"))
}

struct World {
    epoch: u64,
    now: u64,
    link_up: bool,
    sender: CarrierSender,
    receiver_limits: ReceiverLimits,
    rigs: BTreeMap<u32, Rig>,
    trace: Vec<Value>,
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < WAIT, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

impl World {
    fn new(scenario: &Value) -> Self {
        let limits: CarrierLimits = merged(&CarrierLimits::baseline(), scenario.get("limits"));
        let receiver_limits: ReceiverLimits =
            merged(&ReceiverLimits::baseline(), scenario.get("receiver_limits"));
        let epoch = scenario.get("epoch").and_then(Value::as_u64).unwrap_or(1);
        let sender = CarrierSender::bind(key(), stream(), epoch, limits, LOOPBACK)
            .expect("bind the carrier on loopback");
        let mut world = Self {
            epoch,
            now: 0,
            link_up: true,
            sender,
            receiver_limits,
            rigs: BTreeMap::new(),
            trace: Vec::new(),
        };
        for spec in scenario["peers"].as_array().expect("peers") {
            let code = world.add_peer(
                num(spec, "peer") as u32,
                num(spec, "mtu") as usize,
                "ok",
                spec.get("relay"),
            );
            assert_eq!(code, "ok", "the scenario's own peers are admitted");
        }
        world
    }

    fn add_peer(&mut self, peer: u32, mtu: usize, kind: &str, relay: Option<&Value>) -> String {
        let outcome = match kind {
            "lan" => {
                let media: SocketAddr = "192.0.2.7:9".parse().expect("address");
                let control: SocketAddr = "192.0.2.7:10".parse().expect("address");
                self.sender.add_peer(peer, media, control, mtu)
            }
            "v6" => {
                let media: SocketAddr = "[::1]:9".parse().expect("address");
                let control: SocketAddr = "[::1]:10".parse().expect("address");
                self.sender.add_peer(peer, media, control, mtu)
            }
            _ => {
                let sender_control = self.sender.control_addr().expect("sender control address");
                let receiver = CarrierReceiver::bind(
                    key(),
                    stream(),
                    self.epoch,
                    self.receiver_limits.clone(),
                    LOOPBACK,
                    sender_control,
                )
                .expect("bind a receiver on loopback");
                let receiver_media = receiver.media_addr().expect("receiver media address");
                let relay = relay.map(|config| Relay::new(config, receiver_media));
                let media_target = relay.as_ref().map_or(receiver_media, Relay::addr);
                let control = receiver.control_addr().expect("receiver control address");
                let result = self.sender.add_peer(peer, media_target, control, mtu);
                if result.is_ok() {
                    self.rigs.insert(
                        peer,
                        Rig {
                            receiver,
                            retired: Vec::new(),
                            relay,
                            consumer: true,
                            delivered: Vec::new(),
                            control_received: Vec::new(),
                            samples_checked: 0,
                            sample_mismatches: 0,
                            seen_media: 0,
                            seen_control: 0,
                        },
                    );
                }
                result
            }
        };
        match outcome {
            Ok(()) => "ok".to_string(),
            Err(err) => err.code().to_string(),
        }
    }

    fn submit_block(
        &mut self,
        epoch: u64,
        block: u64,
        deadline: u64,
    ) -> Result<SubmitReport, CarrierError> {
        let frame = frame_for_block(block, self.now, deadline);
        self.sender.submit_media(epoch, &frame, self.now)
    }

    /// Wait until the sender has read `count` more control datagrams (reports) than it had.
    fn wait_for_reports(&mut self, count: u64) {
        if count == 0 {
            return;
        }
        let target = self.sender.stats().control_datagrams_in + count;
        let sender = &mut self.sender;
        wait_for("the sender to read the receivers' reports", || {
            sender.poll_reports();
            sender.stats().control_datagrams_in >= target
        });
    }

    /// One pump, then everything it caused: the relays forward, the receivers read, control is drained, the consumers take what
    /// arrived and report how far they got.
    fn pump_and_deliver(&mut self) -> PumpReport {
        let report = self.sender.pump(self.now);
        // A scripted world keeps every peer's window open inside a probe interval (the model asserts the same), so no peer is
        // probed here: a probe is a datagram that no per-pump media count accounts for. Probes are proven by the unit tests over a
        // genuine N01 receiver; a script that probes must first teach this interpreter and the model to deliver the copy.
        assert_eq!(
            self.sender.control_stats().probes_sent,
            0,
            "a scripted world probed a peer"
        );
        let ids: Vec<u32> = self.rigs.keys().copied().collect();
        for id in &ids {
            let view = self.sender.peer_view(*id).expect("peer in the carrier");
            let Some(rig) = self.rigs.get_mut(id) else {
                continue;
            };
            let sent = view.counters.media_sent_packets - rig.seen_media;
            let control_sent = view.counters.control_sent - rig.seen_control;
            rig.seen_media = view.counters.media_sent_packets;
            rig.seen_control = view.counters.control_sent;
            let forwarded = match rig.relay.as_mut() {
                Some(relay) => relay.forward(sent),
                None => sent,
            };
            let media_target = rig.receiver.stats().media_read + forwarded;
            let control_target = rig.receiver.stats().control_read + control_sent;
            let receiver = &mut rig.receiver;
            wait_for("a receiver to read the datagrams sent to it", || {
                receiver.poll();
                receiver.stats().media_read >= media_target
                    && receiver.stats().control_read >= control_target
            });
            for message in rig.receiver.take_control(64) {
                rig.control_received.push(u64::from(message[1]));
            }
        }
        let mut reports = 0u64;
        for id in &ids {
            let Some(rig) = self.rigs.get_mut(id) else {
                continue;
            };
            if !rig.consumer {
                continue;
            }
            for packet in rig.receiver.take_media(4096) {
                let block = packet.start_frame / BLOCK_FRAMES;
                rig.samples_checked += 1;
                if packet.payload != payload_for_block(block) {
                    rig.sample_mismatches += 1;
                }
                rig.delivered
                    .push(json!([packet.session_epoch, packet.seq, block]));
            }
            if self.link_up {
                rig.receiver.send_report().expect("send a report");
                reports += 1;
            }
        }
        self.wait_for_reports(reports);
        report
    }

    fn run(&mut self, scenario: &Value) {
        for (index, op) in scenario["ops"].as_array().expect("ops").iter().enumerate() {
            let name = op["op"].as_str().expect("op name");
            if let Some(mut result) = self.apply(name, op) {
                let entry = result.as_object_mut().expect("a result is an object");
                entry.insert("op".to_string(), json!(index));
                entry.insert("name".to_string(), json!(name));
                self.trace.push(result);
            }
        }
    }

    fn apply(&mut self, name: &str, op: &Value) -> Option<Value> {
        match name {
            "submit" => {
                let mut total = Totals::default();
                for block in num(op, "first_block")..num(op, "first_block") + num(op, "blocks") {
                    let report = self
                        .submit_block(self.epoch, block, num(op, "deadline_ns"))
                        .expect("a submit under the active epoch");
                    total.add_submit(&report);
                }
                Some(total.json(num(op, "blocks"), false))
            }
            "stream" => {
                let mut total = Totals::default();
                for block in num(op, "first_block")..num(op, "first_block") + num(op, "blocks") {
                    let report = self
                        .submit_block(self.epoch, block, num(op, "deadline_ns"))
                        .expect("a submit under the active epoch");
                    total.add_submit(&report);
                    let pump = self.pump_and_deliver();
                    total.add_pump(&pump);
                    self.now += num(op, "period_ns");
                }
                Some(total.json(num(op, "blocks"), true))
            }
            "pump" => Some(json!({"pump": to_json(&self.pump_and_deliver())})),
            "settle" => {
                let mut pumps = 0u64;
                let mut last = PumpReport::default();
                for _ in 0..64 {
                    last = self.pump_and_deliver();
                    pumps += 1;
                    if last.pace_limited {
                        self.now = last
                            .next_send_ns
                            .expect("a pace-limited pump names its deadline");
                    } else {
                        break;
                    }
                }
                Some(
                    json!({"settle_pumps": pumps, "final_pump": to_json(&last), "now_ns": self.now}),
                )
            }
            "advance" => {
                self.now += num(op, "ns");
                None
            }
            "consumer" => {
                let active = op["active"].as_bool().expect("active");
                self.rigs
                    .get_mut(&(num(op, "peer") as u32))
                    .expect("peer")
                    .consumer = active;
                None
            }
            "control" => {
                let mut bytes = vec![0u8; 16];
                bytes[0] = 0xC0;
                bytes[1] = num(op, "tag") as u8;
                let code = match self.sender.submit_control(num(op, "peer") as u32, &bytes) {
                    Ok(()) => "ok",
                    Err(err) => err.code(),
                };
                Some(json!({ "code": code }))
            }
            "add_peer" => {
                let code = self.add_peer(
                    num(op, "peer") as u32,
                    num(op, "mtu") as usize,
                    op.get("kind").and_then(Value::as_str).unwrap_or("ok"),
                    op.get("relay"),
                );
                Some(json!({ "code": code }))
            }
            "remove_peer" => {
                let peer = num(op, "peer") as u32;
                self.sender.remove_peer(peer).expect("remove the peer");
                self.rigs.remove(&peer);
                None
            }
            "set_mtu" => {
                let outcome = self
                    .sender
                    .set_path_mtu(num(op, "peer") as u32, num(op, "mtu") as usize)
                    .expect("known peer");
                Some(json!({ "outcome": to_json(&outcome) }))
            }
            "link" => {
                let up = op["up"].as_bool().expect("up");
                self.sender.set_link_up(up);
                self.link_up = up;
                None
            }
            "epoch" => {
                let to = num(op, "to");
                self.sender.advance_epoch(to).expect("a newer epoch");
                self.epoch = to;
                let skipped: Vec<u64> = op
                    .get("skip_receivers")
                    .and_then(Value::as_array)
                    .map(|list| list.iter().filter_map(Value::as_u64).collect())
                    .unwrap_or_default();
                for (peer, rig) in &mut self.rigs {
                    if !skipped.contains(&u64::from(*peer)) {
                        rig.receiver.advance_epoch(to);
                    }
                }
                None
            }
            "receiver_epoch" => {
                self.rigs
                    .get_mut(&(num(op, "peer") as u32))
                    .expect("peer")
                    .receiver
                    .advance_epoch(num(op, "to"));
                None
            }
            "stale_submit" => {
                let code = match self.submit_block(num(op, "epoch"), 0, 1_000_000) {
                    Ok(_) => "ok",
                    Err(err) => err.code(),
                };
                Some(json!({ "code": code }))
            }
            "inject_old" => {
                // a captured datagram from an earlier epoch, validly signed, replayed straight at a receiver
                let mut old = StreamSender::new(key(), stream(), num(op, "epoch"));
                let wire = old
                    .send(frame_for_block(0, self.now, 1_000_000))
                    .expect("the old sender encodes");
                let rig = self.rigs.get_mut(&(num(op, "peer") as u32)).expect("peer");
                let thief = UdpSocket::bind((LOOPBACK, 0)).expect("bind");
                thief
                    .send_to(&wire, rig.receiver.media_addr().expect("address"))
                    .expect("inject");
                let target = rig.receiver.stats().media_read + 1;
                let receiver = &mut rig.receiver;
                wait_for("the injected datagram", || {
                    receiver.poll();
                    receiver.stats().media_read >= target
                });
                None
            }
            "addr_change" => {
                let peer = num(op, "peer") as u32;
                let sender_control = self.sender.control_addr().expect("sender control address");
                let fresh = CarrierReceiver::bind(
                    key(),
                    stream(),
                    self.sender.epoch(),
                    self.receiver_limits.clone(),
                    LOOPBACK,
                    sender_control,
                )
                .expect("bind the receiver's new endpoint");
                let media = fresh.media_addr().expect("address");
                let control = fresh.control_addr().expect("address");
                let rig = self.rigs.get_mut(&peer).expect("peer");
                let old = std::mem::replace(&mut rig.receiver, fresh);
                rig.retired.push(old);
                self.sender
                    .peer_address_changed(peer, media, control)
                    .expect("the peer keeps its identity");
                None
            }
            "old_report" => {
                let rig = self.rigs.get_mut(&(num(op, "peer") as u32)).expect("peer");
                rig.retired
                    .last_mut()
                    .expect("a retired endpoint")
                    .send_report()
                    .expect("the old endpoint reports");
                self.wait_for_reports(1);
                None
            }
            other => panic!("unknown op {other}"),
        }
    }

    fn record(&self, id: &str) -> Value {
        let mut peers = serde_json::Map::new();
        for (peer, rig) in &self.rigs {
            let view = self.sender.peer_view(*peer).expect("peer view");
            peers.insert(
                peer.to_string(),
                json!({
                    "view": to_json(&view),
                    "delivered": rig.delivered,
                    "control_received": rig.control_received,
                    "samples_checked": rig.samples_checked,
                    "sample_mismatches": rig.sample_mismatches,
                    "receiver": {
                        "stats": to_json(rig.receiver.stats()),
                        "stream": to_json(rig.receiver.stream_counters()),
                        "consumed_next": rig.receiver.consumed_next(),
                        "inbound_len": rig.receiver.inbound_len(),
                    },
                    "relay": rig.relay.as_ref().map(|relay| json!({
                        "lost": relay.lost,
                        "reordered": relay.reordered,
                        "forwarded": relay.forwarded,
                    })),
                }),
            );
        }
        json!({
            "id": id,
            "final_now_ns": self.now,
            "trace": self.trace,
            "peers": peers,
            "stats": to_json(self.sender.stats()),
        })
    }
}

/// Sums of what the reports of a `submit` or `stream` op said.
#[derive(Default)]
struct Totals {
    queued: u64,
    evicted: u64,
    rejected_aggregate: u64,
    skipped_fenced: u64,
    media_sent: u64,
    control_sent: u64,
    late_dropped: u64,
}

impl Totals {
    fn add_submit(&mut self, report: &SubmitReport) {
        self.queued += u64::from(report.queued);
        self.evicted += u64::from(report.evicted);
        self.rejected_aggregate += u64::from(report.rejected_aggregate);
        self.skipped_fenced += u64::from(report.skipped_fenced);
    }

    fn add_pump(&mut self, report: &PumpReport) {
        self.media_sent += u64::from(report.media_sent);
        self.control_sent += u64::from(report.control_sent);
        self.late_dropped += u64::from(report.late_dropped);
    }

    fn json(&self, submitted: u64, with_pumps: bool) -> Value {
        let mut value = json!({
            "submitted": submitted,
            "queued": self.queued,
            "evicted": self.evicted,
            "rejected_aggregate": self.rejected_aggregate,
            "skipped_fenced": self.skipped_fenced,
        });
        if with_pumps {
            let map = value.as_object_mut().expect("object");
            map.insert("media_sent".to_string(), json!(self.media_sent));
            map.insert("control_sent".to_string(), json!(self.control_sent));
            map.insert("late_dropped".to_string(), json!(self.late_dropped));
        }
        value
    }
}

/// The first place two records differ, as a path, for a failure message.
fn first_difference(path: &str, observed: &Value, expected: &Value) -> Option<String> {
    match (observed, expected) {
        (Value::Object(a), Value::Object(b)) => {
            for (name, entry) in b {
                match a.get(name) {
                    None => {
                        return Some(format!("{path}/{name}: missing from the observed record"));
                    }
                    Some(seen) => {
                        if let Some(found) =
                            first_difference(&format!("{path}/{name}"), seen, entry)
                        {
                            return Some(found);
                        }
                    }
                }
            }
            a.keys()
                .find(|name| !b.contains_key(*name))
                .map(|name| format!("{path}/{name}: not in the expected record"))
        }
        (Value::Array(a), Value::Array(b)) => {
            if a.len() != b.len() {
                return Some(format!(
                    "{path}: {} entries observed, {} expected",
                    a.len(),
                    b.len()
                ));
            }
            a.iter()
                .zip(b)
                .enumerate()
                .find_map(|(index, (seen, want))| {
                    first_difference(&format!("{path}[{index}]"), seen, want)
                })
        }
        _ if observed == expected => None,
        _ => Some(format!("{path}: observed {observed}, expected {expected}")),
    }
}

/// The original scenario vectors describe N01 worlds and remain unchanged. A world
/// never selects FEC or emits FEC feedback, so its added telemetry is explicitly
/// zero/false. Extend only the independent expectation; never drop actual fields.
fn expected_with_idle_fec(legacy: &Value) -> Value {
    let mut expected = legacy.clone();
    let stats = expected["stats"]
        .as_object_mut()
        .expect("legacy interface stats");
    for field in [
        "fec_feedback_accepted",
        "fec_feedback_refused",
        "fec_work_refused",
        "fec_feedback_deferred",
        "fec_feedback_overflow",
    ] {
        assert!(stats.insert(field.to_string(), json!(0)).is_none());
    }
    for peer in expected["peers"]
        .as_object_mut()
        .expect("legacy peers")
        .values_mut()
    {
        if peer["view"].is_null() {
            continue;
        }
        let view = peer["view"].as_object_mut().expect("legacy peer view");
        assert!(
            view.insert("fec_feedback_pending".into(), json!(false))
                .is_none()
        );
        let counters = view["counters"]
            .as_object_mut()
            .expect("legacy peer counters");
        for field in [
            "fec_sent_packets",
            "fec_feedback_accepted",
            "fec_feedback_refused",
            "fec_feedback_deferred",
            "fec_feedback_overflow",
        ] {
            assert!(counters.insert(field.to_string(), json!(0)).is_none());
        }
    }
    expected
}

#[test]
fn n07_idle_fec_expectations_reject_nonzero_missing_mistyped_and_unknown_fields() {
    let doc: Value = serde_json::from_str(SCENARIOS).expect("scenario vectors");
    for scenario in doc["scenarios"].as_array().expect("scenarios") {
        let expected = expected_with_idle_fec(&scenario["expect"]);
        assert_eq!(first_difference("", &expected, &expected), None);
        let mut paths = Vec::new();
        for field in [
            "fec_feedback_accepted",
            "fec_feedback_refused",
            "fec_work_refused",
            "fec_feedback_deferred",
            "fec_feedback_overflow",
        ] {
            paths.push(format!("/stats/{field}"));
        }
        for (peer, entry) in expected["peers"].as_object().unwrap() {
            if entry["view"].is_null() {
                continue;
            }
            paths.push(format!("/peers/{peer}/view/fec_feedback_pending"));
            for field in [
                "fec_sent_packets",
                "fec_feedback_accepted",
                "fec_feedback_refused",
                "fec_feedback_deferred",
                "fec_feedback_overflow",
            ] {
                paths.push(format!("/peers/{peer}/view/counters/{field}"));
            }
        }
        for path in paths {
            let original = expected.pointer(&path).unwrap();
            let mut altered = expected.clone();
            *altered.pointer_mut(&path).unwrap() = if original.is_boolean() {
                json!(true)
            } else {
                json!(1)
            };
            assert!(
                first_difference("", &altered, &expected).is_some(),
                "nonzero {path}"
            );
            *altered.pointer_mut(&path).unwrap() = if original.is_boolean() {
                json!(0)
            } else {
                json!(false)
            };
            assert!(
                first_difference("", &altered, &expected).is_some(),
                "wrong type {path}"
            );
        }
        let mut missing = expected.clone();
        missing["stats"]
            .as_object_mut()
            .unwrap()
            .remove("fec_work_refused");
        assert!(first_difference("", &missing, &expected).is_some());
        let mut unknown = expected.clone();
        unknown["stats"]["undeclared_counter"] = json!(0);
        assert!(first_difference("", &unknown, &expected).is_some());
    }
}

fn run_scenario(id: &str) {
    let doc: Value = serde_json::from_str(SCENARIOS).expect("the scenario file parses");
    let scenario = doc["scenarios"]
        .as_array()
        .expect("scenarios")
        .iter()
        .find(|s| s["id"] == id)
        .unwrap_or_else(|| panic!("scenario {id} is not in the scenario file"));
    let mut world = World::new(scenario);
    world.run(scenario);
    let observed = world.record(id);
    println!(
        "N07-OBSERVED {}",
        serde_json::to_string(&observed).expect("serializes")
    );
    for (peer, entry) in observed["peers"].as_object().expect("peers") {
        assert_eq!(
            entry["sample_mismatches"], 0,
            "{id}: peer {peer} received a block whose samples are not the independent oracle's"
        );
        assert!(
            entry["samples_checked"].as_u64().unwrap_or(0) > 0,
            "{id}: peer {peer} received nothing, so no sample was compared"
        );
    }
    let expected = expected_with_idle_fec(&scenario["expect"]);
    if let Some(found) = first_difference("", &observed, &expected) {
        panic!("{id}: the carrier disagrees with the model: {found}");
    }
}

#[test]
fn n07_s1_zero_loss_paced() {
    run_scenario("N07-S1-zero-loss-paced");
}

#[test]
fn n07_s2_slow_peer_isolated() {
    run_scenario("N07-S2-slow-peer-isolated");
}

#[test]
fn n07_s3_saturation_control_priority() {
    run_scenario("N07-S3-saturation-control-priority");
}

#[test]
fn n07_s4_epoch_fence() {
    run_scenario("N07-S4-epoch-fence");
}

#[test]
fn n07_s5_mtu_admission_address_family() {
    run_scenario("N07-S5-mtu-admission-address-family");
}

#[test]
fn n07_s6_link_and_address_change() {
    run_scenario("N07-S6-link-and-address-change");
}

#[test]
fn n07_s7_loss_and_reorder() {
    run_scenario("N07-S7-loss-and-reorder");
}

#[test]
fn n07_the_carrier_binds_loopback_only_and_refuses_anything_else_before_a_socket_is_used() {
    let lan: IpAddr = "192.0.2.1".parse().expect("address");
    let refused = CarrierSender::bind(key(), stream(), 1, CarrierLimits::baseline(), lan);
    assert!(
        matches!(refused, Err(CarrierError::NotLoopback(_))),
        "a non-loopback bind must be refused, not attempted"
    );
    // the permitted positive: the same limits bind on loopback
    let sender = CarrierSender::bind(key(), stream(), 1, CarrierLimits::baseline(), LOOPBACK)
        .expect("loopback binds");
    assert!(sender.media_addr().expect("address").ip().is_loopback());
    assert!(sender.control_addr().expect("address").ip().is_loopback());
}

#[test]
fn n07_a_report_that_is_not_authentic_or_not_from_the_peer_moves_nothing() {
    let mut sender =
        CarrierSender::bind(key(), stream(), 1, CarrierLimits::baseline(), LOOPBACK).expect("bind");
    let sender_control = sender.control_addr().expect("address");
    let mut receiver = CarrierReceiver::bind(
        key(),
        stream(),
        1,
        ReceiverLimits::baseline(),
        LOOPBACK,
        sender_control,
    )
    .expect("bind");
    sender
        .add_peer(
            1,
            receiver.media_addr().expect("address"),
            receiver.control_addr().expect("address"),
            1500,
        )
        .expect("admitted");
    sender
        .submit_media(1, &frame_for_block(0, 0, 1_000_000_000), 0)
        .expect("queued");
    assert_eq!(sender.pump(0).media_sent, 1);

    let attacker = UdpSocket::bind((LOOPBACK, 0)).expect("bind");
    let mut forged = [0u8; 48];
    forged[0..4].copy_from_slice(b"FFWR");
    forged[4] = 1;
    // (a) too short, (b) the right shape with a tag nobody computed, (c) a genuine report made with another key
    attacker.send_to(&[1, 2, 3], sender_control).expect("send");
    attacker.send_to(&forged, sender_control).expect("send");
    let mut other = CarrierReceiver::bind(
        StreamKey::from_bytes([0x08; 32]),
        stream(),
        1,
        ReceiverLimits::baseline(),
        LOOPBACK,
        sender_control,
    )
    .expect("bind");
    other.send_report().expect("send");
    wait_for("the three unauthentic datagrams", || {
        sender.poll_reports();
        sender.stats().control_datagrams_in >= 3
    });
    let stats = sender.stats();
    assert_eq!(stats.reports_malformed, 1);
    assert_eq!(stats.reports_bad_tag, 2);
    let view = sender.peer_view(1).expect("peer");
    assert_eq!((view.reported_next, view.counters.reports_accepted), (0, 0));

    // the permitted positive: the peer's own report, after it consumed the block, moves its position
    wait_for("the block", || {
        receiver.poll();
        receiver.stats().media_read >= 1
    });
    assert_eq!(receiver.take_media(8).len(), 1);
    receiver.send_report().expect("send");
    wait_for("the genuine report", || {
        sender.poll_reports();
        sender.stats().control_datagrams_in >= 4
    });
    let view = sender.peer_view(1).expect("peer");
    assert_eq!((view.reported_next, view.counters.reports_accepted), (1, 1));
}
