//! Wire codecs at the HAL adapter boundary (`P04` / `ffw-0bh`).
//!
//! Every multi-byte field is **big-endian regardless of the host CPU**, and every decoder treats its
//! input as untrusted: a record of the wrong length, an unknown kind, a slot number that does not
//! fit, or a reserved field that is not zero is rejected, never repaired. A rejected record is a
//! malformed device response, and the session answers it by failing muted.
//!
//! Two layouts live here, with different evidence:
//!
//! * [`RawGeometry`] is the 16-byte answer to the geometry query. Its four-word layout (offsets 0,
//!   4, 8, 12) and the values it holds were decoded from the retained model-16 driver's ioctl
//!   handler (see `tests/e04/anchors/audiodev_m16.json` and `docs/contracts/e04.md`). The field
//!   *names* are inferred from cross-checks inside that driver, not from a header.
//! * [`DeviceEvent`] is a 12-byte event record defined by this harness for the fake device. It is a
//!   MODEL of an event channel. No retained driver is known to emit it, so a pass against it is not
//!   driver evidence.
//!
//! Golden byte vectors for both are in `tests/p04/abi_vectors.json`.

use serde::{Deserialize, Serialize};

/// Length of a geometry record.
pub const GEOMETRY_LEN: usize = 16;
/// Length of an event record.
pub const EVENT_LEN: usize = 12;

const KIND_COMPLETED: u32 = 1;
const KIND_POSITION: u32 = 2;
const KIND_FLUSH_ACK: u32 = 3;
const KIND_DEVICE_LOST: u32 = 4;

/// Why a record was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum AbiError {
    #[error("record is {actual} byte(s), expected {expected}")]
    Length { expected: usize, actual: usize },
    #[error("unknown record kind {0}")]
    UnknownKind(u32),
    #[error("slot number {0} does not fit in 16 bits")]
    SlotRange(u32),
    #[error("record kind {0} has a nonzero reserved field")]
    ReservedNonZero(u32),
}

/// The answer to the geometry query, exactly as the device sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawGeometry {
    pub ring_depth: u32,
    pub frames_per_block: u32,
    pub channels: u32,
    pub bytes_per_sample: u32,
}

/// What the device reports. Every field is untrusted until the session has checked it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceEvent {
    /// The device finished with a slot. `generation` names which use of the slot.
    Completed { slot: u16, generation: u32 },
    /// A wrapping 32-bit count of frames the device has consumed.
    Position { counter: u32 },
    /// The device acknowledges that it stopped and flushed.
    FlushAck,
    /// The device is gone. Whatever it was reading may still be in flight.
    DeviceLost,
}

fn be32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Decode a geometry record.
pub fn decode_geometry(bytes: &[u8]) -> Result<RawGeometry, AbiError> {
    if bytes.len() != GEOMETRY_LEN {
        return Err(AbiError::Length {
            expected: GEOMETRY_LEN,
            actual: bytes.len(),
        });
    }
    Ok(RawGeometry {
        ring_depth: be32(bytes, 0),
        frames_per_block: be32(bytes, 4),
        channels: be32(bytes, 8),
        bytes_per_sample: be32(bytes, 12),
    })
}

/// Encode a geometry record.
#[must_use]
pub fn encode_geometry(g: &RawGeometry) -> [u8; GEOMETRY_LEN] {
    let mut out = [0u8; GEOMETRY_LEN];
    out[0..4].copy_from_slice(&g.ring_depth.to_be_bytes());
    out[4..8].copy_from_slice(&g.frames_per_block.to_be_bytes());
    out[8..12].copy_from_slice(&g.channels.to_be_bytes());
    out[12..16].copy_from_slice(&g.bytes_per_sample.to_be_bytes());
    out
}

/// Decode an event record. Unused fields must be zero.
pub fn decode_event(bytes: &[u8]) -> Result<DeviceEvent, AbiError> {
    if bytes.len() != EVENT_LEN {
        return Err(AbiError::Length {
            expected: EVENT_LEN,
            actual: bytes.len(),
        });
    }
    let kind = be32(bytes, 0);
    let a = be32(bytes, 4);
    let b = be32(bytes, 8);
    match kind {
        KIND_COMPLETED => {
            let slot = u16::try_from(a).map_err(|_| AbiError::SlotRange(a))?;
            Ok(DeviceEvent::Completed {
                slot,
                generation: b,
            })
        }
        KIND_POSITION => {
            if b != 0 {
                return Err(AbiError::ReservedNonZero(kind));
            }
            Ok(DeviceEvent::Position { counter: a })
        }
        KIND_FLUSH_ACK | KIND_DEVICE_LOST => {
            if a != 0 || b != 0 {
                return Err(AbiError::ReservedNonZero(kind));
            }
            if kind == KIND_FLUSH_ACK {
                Ok(DeviceEvent::FlushAck)
            } else {
                Ok(DeviceEvent::DeviceLost)
            }
        }
        other => Err(AbiError::UnknownKind(other)),
    }
}

/// Encode an event record.
#[must_use]
pub fn encode_event(event: &DeviceEvent) -> [u8; EVENT_LEN] {
    let (kind, a, b) = match *event {
        DeviceEvent::Completed { slot, generation } => {
            (KIND_COMPLETED, u32::from(slot), generation)
        }
        DeviceEvent::Position { counter } => (KIND_POSITION, counter, 0),
        DeviceEvent::FlushAck => (KIND_FLUSH_ACK, 0, 0),
        DeviceEvent::DeviceLost => (KIND_DEVICE_LOST, 0, 0),
    };
    let mut out = [0u8; EVENT_LEN];
    out[0..4].copy_from_slice(&kind.to_be_bytes());
    out[4..8].copy_from_slice(&a.to_be_bytes());
    out[8..12].copy_from_slice(&b.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS_JSON: &str = include_str!("../../../tests/p04/abi_vectors.json");

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len() & 1 == 0, "odd hex length in {s:?}");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn hand_computed_event_vectors() {
        // kind 1, slot 3, generation 7: every word big-endian.
        let e = DeviceEvent::Completed {
            slot: 3,
            generation: 7,
        };
        assert_eq!(
            encode_event(&e),
            [0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 7],
            "completed slot 3 generation 7"
        );
        // A value whose bytes are all different shows the order of the bytes, not just the length.
        let e = DeviceEvent::Completed {
            slot: 0xABCD,
            generation: 0x0102_0304,
        };
        assert_eq!(encode_event(&e), [0, 0, 0, 1, 0, 0, 0xAB, 0xCD, 1, 2, 3, 4]);
        assert_eq!(
            encode_event(&DeviceEvent::Position {
                counter: 0xFFFF_FFF0
            }),
            [0, 0, 0, 2, 0xFF, 0xFF, 0xFF, 0xF0, 0, 0, 0, 0]
        );
        assert_eq!(
            encode_event(&DeviceEvent::FlushAck),
            [0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            encode_event(&DeviceEvent::DeviceLost),
            [0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn hand_computed_geometry_vectors() {
        let g = RawGeometry {
            ring_depth: 10,
            frames_per_block: 512,
            channels: 2,
            bytes_per_sample: 4,
        };
        assert_eq!(
            encode_geometry(&g),
            [0, 0, 0, 10, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 4]
        );
        let five = RawGeometry { channels: 5, ..g };
        assert_eq!(encode_geometry(&five)[8..12], [0, 0, 0, 5]);
        assert_eq!(decode_geometry(&encode_geometry(&g)), Ok(g));
    }

    #[test]
    fn every_valid_event_round_trips_and_every_defect_is_rejected() {
        for event in [
            DeviceEvent::Completed {
                slot: 0,
                generation: 0,
            },
            DeviceEvent::Completed {
                slot: u16::MAX,
                generation: u32::MAX,
            },
            DeviceEvent::Position { counter: 0 },
            DeviceEvent::Position { counter: u32::MAX },
            DeviceEvent::FlushAck,
            DeviceEvent::DeviceLost,
        ] {
            assert_eq!(decode_event(&encode_event(&event)), Ok(event));
        }
        assert_eq!(
            decode_event(&[0; 11]),
            Err(AbiError::Length {
                expected: 12,
                actual: 11
            })
        );
        assert_eq!(
            decode_event(&[0; 13]),
            Err(AbiError::Length {
                expected: 12,
                actual: 13
            })
        );
        assert_eq!(decode_event(&[0; 12]), Err(AbiError::UnknownKind(0)));
        assert_eq!(
            decode_event(&[0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(AbiError::UnknownKind(9))
        );
        // Slot 0x10000 does not fit in 16 bits.
        assert_eq!(
            decode_event(&[0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0]),
            Err(AbiError::SlotRange(0x1_0000))
        );
        // Reserved words must be zero for every kind that does not use them.
        assert_eq!(
            decode_event(&[0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0]),
            Err(AbiError::ReservedNonZero(3))
        );
        assert_eq!(
            decode_event(&[0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1]),
            Err(AbiError::ReservedNonZero(4))
        );
        assert_eq!(
            decode_event(&[0, 0, 0, 2, 0, 0, 0, 5, 0, 0, 0, 1]),
            Err(AbiError::ReservedNonZero(2))
        );
        assert_eq!(
            decode_geometry(&[0; 15]),
            Err(AbiError::Length {
                expected: 16,
                actual: 15
            })
        );
    }

    #[test]
    fn the_committed_vectors_decode_and_encode_as_written() {
        let doc: serde_json::Value = serde_json::from_str(VECTORS_JSON).unwrap();
        assert_eq!(doc["schema"], "ffw.p04.abi_vectors.v1");
        let vectors = doc["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 14, "a vector was added or dropped");
        for v in vectors {
            let id = v["id"].as_str().unwrap();
            let bytes = unhex(v["hex"].as_str().unwrap());
            let codec = v["codec"].as_str().unwrap();
            let expect = &v["expect"];
            match (codec, expect.get("error")) {
                ("event", None) => {
                    let ev = decode_event(&bytes).unwrap_or_else(|e| panic!("{id}: {e}"));
                    let want = match expect["kind"].as_str().unwrap() {
                        "completed" => DeviceEvent::Completed {
                            slot: u16::try_from(expect["slot"].as_u64().unwrap()).unwrap(),
                            generation: u32::try_from(expect["generation"].as_u64().unwrap())
                                .unwrap(),
                        },
                        "position" => DeviceEvent::Position {
                            counter: u32::try_from(expect["counter"].as_u64().unwrap()).unwrap(),
                        },
                        "flush_ack" => DeviceEvent::FlushAck,
                        "device_lost" => DeviceEvent::DeviceLost,
                        other => panic!("{id}: unknown kind {other}"),
                    };
                    assert_eq!(ev, want, "{id}");
                    assert_eq!(encode_event(&ev).to_vec(), bytes, "{id}: re-encode");
                }
                ("geometry", None) => {
                    let g = decode_geometry(&bytes).unwrap_or_else(|e| panic!("{id}: {e}"));
                    let field = |name: &str| u32::try_from(expect[name].as_u64().unwrap()).unwrap();
                    assert_eq!(g.ring_depth, field("ring_depth"), "{id}");
                    assert_eq!(g.frames_per_block, field("frames_per_block"), "{id}");
                    assert_eq!(g.channels, field("channels"), "{id}");
                    assert_eq!(g.bytes_per_sample, field("bytes_per_sample"), "{id}");
                    assert_eq!(encode_geometry(&g).to_vec(), bytes, "{id}: re-encode");
                }
                (_, Some(error)) => {
                    let got = match codec {
                        "event" => decode_event(&bytes).unwrap_err(),
                        _ => decode_geometry(&bytes).unwrap_err(),
                    };
                    let name = match got {
                        AbiError::Length { .. } => "length",
                        AbiError::UnknownKind(_) => "unknown_kind",
                        AbiError::SlotRange(_) => "slot_range",
                        AbiError::ReservedNonZero(_) => "reserved_non_zero",
                    };
                    assert_eq!(error.as_str().unwrap(), name, "{id}");
                }
                (other, _) => panic!("{id}: unknown codec {other}"),
            }
        }
    }
}
