//! The two datagram targets: the stateless decoder and the stateful receiver (`docs/contracts/n01.md` section 11).
//!
//! `check_*` return `Err(why)` when an oracle is violated and are what the tests call; `run_*` panic on `Err`, which is
//! what libFuzzer reports as a crash. Every verdict the real code gives is compared with the one the contract predicts
//! from the bytes alone (`wire::expected_decode`, `model::Window`), so a wrong ACCEPT, a wrong rejection code and a
//! wrong order of checks are all findings, not just a panic.

use crate::fixture::fixture;
use crate::model::Window;
use crate::{plant, wire};
use franken_stream::{AuthenticatedStreamPacket, PacketKind, StreamId, StreamKey, StreamReceiver};
use std::collections::BTreeSet;

/// Operations per stateful run; more bytes of input than this many operations describe are ignored.
pub const MAX_OPS: usize = 64;

pub const OP_RAW: u8 = 0;
pub const OP_RESIGNED: u8 = 1;
pub const OP_ADVANCE_EPOCH: u8 = 2;
pub const OP_BIND: u8 = 3;

/// What every ACCEPTED packet must satisfy, whatever the datagram looked like: the declared bounds.
pub fn bounds(packet: &AuthenticatedStreamPacket) -> Result<(), String> {
    let len = packet.payload.len();
    if !(4..=wire::MAX_PAYLOAD).contains(&len) || !len.is_multiple_of(4) {
        return Err(format!("accepted a payload of {len} bytes"));
    }
    if packet.flags & 0xF0 != 0 {
        return Err(format!("accepted critical flag bits {:#04x}", packet.flags));
    }
    if !packet.start_frame.is_multiple_of(wire::FRAMES_PER_BLOCK) {
        return Err(format!("accepted start frame {}", packet.start_frame));
    }
    if packet.presentation_time_ns > wire::MAX_TIMESTAMP_NS
        || packet.consume_by_ns > packet.presentation_time_ns
    {
        return Err("accepted timestamps outside the contract".to_string());
    }
    if packet.stream_id.get() == 0 {
        return Err("accepted stream id 0".to_string());
    }
    let size = packet.fec_group_size;
    let index = packet.fec_index;
    let fec_ok = match packet.kind {
        PacketKind::Media => {
            if size == 0 {
                index == 0
            } else {
                size <= wire::MAX_FEC_GROUP && index < size
            }
        }
        PacketKind::Repair => {
            (1..=wire::MAX_FEC_GROUP).contains(&size) && index < wire::MAX_FEC_GROUP
        }
    };
    if !fec_ok {
        return Err(format!(
            "accepted FEC fields group size {size}, index {index}"
        ));
    }
    Ok(())
}

/// The stateless decoder against the contract: the verdict, the re-encode and the bounds.
pub fn check_decode(datagram: &[u8]) -> Result<(), String> {
    let raw_key = &fixture().wire_key;
    let key = StreamKey::from_bytes(*raw_key);
    let expected = wire::expected_decode(raw_key, datagram);
    match AuthenticatedStreamPacket::decode_and_verify(datagram, &key) {
        Ok(packet) => {
            plant::after_accept(packet.payload.len());
            if expected != "OK" {
                return Err(format!(
                    "accepted a {}-byte datagram the contract refuses as {expected}",
                    datagram.len()
                ));
            }
            let again = packet
                .encode_signed(&key)
                .map_err(|err| format!("an accepted packet does not re-encode: {}", err.code()))?;
            if again != datagram {
                return Err("an accepted datagram does not re-encode byte for byte".to_string());
            }
            bounds(&packet)
        }
        Err(err) => {
            if err.code() == expected {
                Ok(())
            } else {
                Err(format!(
                    "refused as {} where the contract says {expected}",
                    err.code()
                ))
            }
        }
    }
}

pub fn run_decode(input: &[u8]) {
    let datagram = wire::datagram_for(&fixture().wire_key, input);
    if let Err(why) = check_decode(&datagram) {
        panic!("stream_decode: {why}");
    }
}

/// One step of a stateful run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Datagram(Vec<u8>),
    AdvanceEpoch(u64),
    Bind { stream_id: u64, epoch: u64 },
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn left(&self) -> usize {
        self.data.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.left() < n {
            return None;
        }
        let data: &'a [u8] = self.data;
        let bytes = &data[self.pos..self.pos + n];
        self.pos += n;
        Some(bytes)
    }

    fn byte(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|b| wire::be64(b, 0))
    }
}

/// Decode an operation stream: `OP_RAW len16 bytes`, `OP_RESIGNED len16 header||payload`, `OP_ADVANCE_EPOCH u64`,
/// `OP_BIND u64 u64`; anything else, or a cut-off operation, ends the stream.
pub fn parse_ops(key: &[u8; 32], input: &[u8]) -> Vec<Op> {
    let mut cursor = Cursor {
        data: input,
        pos: 0,
    };
    let mut ops = Vec::new();
    while ops.len() < MAX_OPS {
        let Some(tag) = cursor.byte() else { break };
        match tag {
            OP_RAW | OP_RESIGNED => {
                let Some(declared) = cursor.u16() else { break };
                let n = usize::from(declared).min(cursor.left());
                let Some(bytes) = cursor.take(n) else { break };
                if tag == OP_RESIGNED {
                    ops.push(Op::Datagram(wire::resign(key, bytes)));
                } else {
                    ops.push(Op::Datagram(bytes.to_vec()));
                }
            }
            OP_ADVANCE_EPOCH => {
                let Some(epoch) = cursor.u64() else { break };
                ops.push(Op::AdvanceEpoch(epoch));
            }
            OP_BIND => {
                let (Some(stream_id), Some(epoch)) = (cursor.u64(), cursor.u64()) else {
                    break;
                };
                ops.push(Op::Bind { stream_id, epoch });
            }
            _ => break,
        }
    }
    ops
}

fn put_len_and_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&bytes[..usize::from(len)]);
}

/// The encoders the seed corpus uses; `parse_ops` is their inverse.
pub fn encode_raw(out: &mut Vec<u8>, datagram: &[u8]) {
    out.push(OP_RAW);
    put_len_and_bytes(out, datagram);
}

pub fn encode_advance_epoch(out: &mut Vec<u8>, epoch: u64) {
    out.push(OP_ADVANCE_EPOCH);
    out.extend_from_slice(&epoch.to_be_bytes());
}

pub fn encode_bind(out: &mut Vec<u8>, stream_id: u64, epoch: u64) {
    out.push(OP_BIND);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(&epoch.to_be_bytes());
}

/// What the receiver must answer for a datagram the contract accepts statelessly, given the bound stream, the active
/// epoch and the window: the stateful half of the receive order.
fn stateful_verdict(datagram: &[u8], stream: u64, epoch: u64, window: &Window) -> &'static str {
    if wire::be64(datagram, 8) != stream {
        return "WRONG_STREAM";
    }
    let packet_epoch = wire::be64(datagram, 16);
    if packet_epoch < epoch {
        return "STALE_EPOCH";
    }
    if packet_epoch > epoch {
        return "FUTURE_EPOCH";
    }
    window.judge(wire::be64(datagram, 24))
}

/// Run an operation stream against a real `StreamReceiver` and the independent model together. Returns how many
/// datagrams were accepted. Checked at every datagram: the verdict and rejection code; on every accept: the bounds,
/// that the packet is for the bound stream and the active epoch, and that no `(window generation, sequence)` is accepted
/// twice; after every epoch or stream operation: the active epoch; at the end: the counters (every datagram lands in
/// exactly one bucket, and none that failed a structural check cost a MAC).
pub fn check_receiver(input: &[u8]) -> Result<u64, String> {
    let f = fixture();
    let key = StreamKey::from_bytes(f.wire_key);
    let initial = StreamId::new(f.receiver_stream)
        .map_err(|err| format!("the fixture stream id is refused: {}", err.code()))?;
    let mut rx = StreamReceiver::new(key, initial, f.receiver_epoch);
    let mut stream = f.receiver_stream;
    let mut epoch = f.receiver_epoch;
    let mut window = Window::default();
    let mut generation = 0u32;
    let mut ever_accepted: BTreeSet<(u32, u64)> = BTreeSet::new();
    let mut seen = 0u64;
    let mut accepted = 0u64;

    for op in parse_ops(&f.wire_key, input) {
        match op {
            Op::AdvanceEpoch(new) => {
                rx.advance_epoch(new);
                if new > epoch {
                    epoch = new;
                    window = Window::default();
                    generation += 1;
                }
                if rx.active_epoch() != epoch {
                    return Err(format!(
                        "active epoch is {} after advance_epoch({new}); the model says {epoch}",
                        rx.active_epoch()
                    ));
                }
            }
            Op::Bind {
                stream_id,
                epoch: new,
            } => {
                let Ok(id) = StreamId::new(stream_id) else {
                    continue;
                };
                rx.bind_stream(id, new);
                stream = stream_id;
                epoch = new;
                window = Window::default();
                generation += 1;
                if rx.active_epoch() != epoch {
                    return Err(format!(
                        "active epoch is {} after bind_stream(_, {new}); the model says {epoch}",
                        rx.active_epoch()
                    ));
                }
            }
            Op::Datagram(datagram) => {
                seen += 1;
                let stateless = wire::expected_decode(&f.wire_key, &datagram);
                let verdict = if stateless == "OK" {
                    stateful_verdict(&datagram, stream, epoch, &window)
                } else {
                    stateless
                };
                match rx.accept(&datagram) {
                    Ok(packet) => {
                        plant::after_accept(packet.payload.len());
                        if verdict != "OK" {
                            return Err(format!(
                                "accepted a datagram the contract refuses as {verdict}"
                            ));
                        }
                        bounds(&packet)?;
                        if packet.stream_id.get() != stream {
                            return Err("accepted a packet of another stream".to_string());
                        }
                        if packet.session_epoch != epoch
                            || packet.session_epoch != rx.active_epoch()
                        {
                            return Err(format!(
                                "accepted epoch {} while epoch {epoch} is active",
                                packet.session_epoch
                            ));
                        }
                        if !ever_accepted.insert((generation, packet.seq)) {
                            return Err(format!("accepted sequence {} twice", packet.seq));
                        }
                        let before = window.high();
                        window.record(packet.seq);
                        if window.high() < before {
                            return Err(
                                "the accepted sequence high-water mark moved backwards".to_string()
                            );
                        }
                        accepted += 1;
                    }
                    Err(err) => {
                        if err.code() != verdict {
                            return Err(format!(
                                "refused as {} where the contract says {verdict}",
                                err.code()
                            ));
                        }
                    }
                }
            }
        }
    }

    let c = rx.counters();
    let rejected = c.rejected_structure
        + c.rejected_unsupported_version
        + c.rejected_authentication
        + c.rejected_malformed_fields
        + c.rejected_wrong_stream
        + c.rejected_stale_epoch
        + c.rejected_future_epoch
        + c.rejected_replay
        + c.rejected_future_sequence
        + c.rejected_not_negotiated;
    if c.datagrams_seen != seen
        || c.accepted != accepted
        || c.datagrams_seen != c.accepted + rejected
    {
        return Err(format!(
            "counters do not add up: seen {} accepted {} rejected {rejected}, expected seen {seen} accepted {accepted}",
            c.datagrams_seen, c.accepted
        ));
    }
    if c.mac_verifications + c.rejected_structure + c.rejected_unsupported_version
        != c.datagrams_seen
    {
        return Err(format!(
            "unauthenticated work is not capped: {} MACs for {} datagrams, {} refused before the MAC",
            c.mac_verifications,
            c.datagrams_seen,
            c.rejected_structure + c.rejected_unsupported_version
        ));
    }
    Ok(accepted)
}

pub fn run_receiver(input: &[u8]) {
    if let Err(why) = check_receiver(input) {
        panic!("stream_receiver: {why}");
    }
}
