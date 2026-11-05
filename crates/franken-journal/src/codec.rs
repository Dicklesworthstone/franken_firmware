//! Byte-level encoding: CRC-32, segment headers, frames and operation lists. Big-endian everywhere. Every length is
//! checked against its bound before the bytes it announces are taken, so a hostile length cannot cause an allocation or a
//! read past the payload.

use crate::state::{Namespace, Op};
use crate::{JournalError, Limits};

pub const ERASED: u8 = 0xFF;
pub const FRAME_MAGIC: u8 = 0xA5;
pub const KIND_TXN: u8 = 1;
pub const KIND_SNAPSHOT: u8 = 2;
pub const SEG_HEADER: usize = 16;
pub const FRAME_HEADER: usize = 12;
pub const FORMAT_VERSION: u8 = 1;
pub const LEGACY_VERSION: u8 = 0;
pub const MAX_SEQ: u32 = u32::MAX;

const T_PUT: u8 = 1;
const T_DELETE: u8 = 2;
const T_RESET: u8 = 3;
const T_INSTALL: u8 = 4;
const T_REVOKE: u8 = 5;
const T_RESET_PAIRING: u8 = 6;
const T_RAISE: u8 = 7;
const T_TOMB: u8 = 8;

/// CRC-32/IEEE (reflected, polynomial 0xEDB88320, init and final xor all ones): `zlib.crc32` over the concatenation.
#[must_use]
pub fn crc32(parts: &[&[u8]]) -> u32 {
    let mut crc = u32::MAX;
    for part in parts {
        for &byte in *part {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
    }
    !crc
}

#[must_use]
pub fn encode_segment_header(version: u8, generation: u32, first_seq: u32) -> [u8; SEG_HEADER] {
    let mut out = [0u8; SEG_HEADER];
    out[0] = b'F';
    out[1] = b'J';
    out[2] = version;
    out[4..8].copy_from_slice(&generation.to_be_bytes());
    out[8..12].copy_from_slice(&first_seq.to_be_bytes());
    let crc = crc32(&[&out[..12]]);
    out[12..16].copy_from_slice(&crc.to_be_bytes());
    out
}

/// A parsed segment header whose checksum held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentHeader {
    pub version: u8,
    pub generation: u32,
    pub first_seq: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderParse {
    /// All sixteen bytes erased.
    Blank,
    /// Wrong magic or a failed checksum (a retired segment has its magic cleared).
    Invalid,
    Ok(SegmentHeader),
}

#[must_use]
pub fn parse_segment_header(head: &[u8; SEG_HEADER]) -> HeaderParse {
    if head.iter().all(|&b| b == ERASED) {
        return HeaderParse::Blank;
    }
    let stored = u32::from_be_bytes([head[12], head[13], head[14], head[15]]);
    if head[0] != b'F' || head[1] != b'J' || stored != crc32(&[&head[..12]]) {
        return HeaderParse::Invalid;
    }
    HeaderParse::Ok(SegmentHeader {
        version: head[2],
        generation: u32::from_be_bytes([head[4], head[5], head[6], head[7]]),
        first_seq: u32::from_be_bytes([head[8], head[9], head[10], head[11]]),
    })
}

/// # Errors
/// [`JournalError::TxnTooLarge`] if the payload length does not fit the frame's 16-bit field.
pub fn encode_frame(kind: u8, seq: u32, payload: &[u8]) -> Result<Vec<u8>, JournalError> {
    let len = u16::try_from(payload.len()).map_err(|_| JournalError::TxnTooLarge)?;
    let mut head = [0u8; 8];
    head[0] = FRAME_MAGIC;
    head[1] = kind;
    head[2..4].copy_from_slice(&len.to_be_bytes());
    head[4..8].copy_from_slice(&seq.to_be_bytes());
    let crc = crc32(&[&head[..], payload]);
    let mut out = Vec::with_capacity(FRAME_HEADER + payload.len());
    out.extend_from_slice(&head);
    out.extend_from_slice(&crc.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// The twelve bytes in front of a payload, split into fields. The checksum is NOT verified here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub magic: u8,
    pub kind: u8,
    pub length: usize,
    pub seq: u32,
    pub crc: u32,
}

#[must_use]
pub fn parse_frame_header(head: &[u8; FRAME_HEADER]) -> FrameHeader {
    FrameHeader {
        magic: head[0],
        kind: head[1],
        length: usize::from(u16::from_be_bytes([head[2], head[3]])),
        seq: u32::from_be_bytes([head[4], head[5], head[6], head[7]]),
        crc: u32::from_be_bytes([head[8], head[9], head[10], head[11]]),
    }
}

fn push_key(out: &mut Vec<u8>, key: &[u8]) -> Result<(), JournalError> {
    out.push(u8::try_from(key.len()).map_err(|_| JournalError::InvalidKey)?);
    out.extend_from_slice(key);
    Ok(())
}

fn push_value(out: &mut Vec<u8>, value: &[u8]) -> Result<(), JournalError> {
    let len = u16::try_from(value.len()).map_err(|_| JournalError::ValueTooLong)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn encode_op(out: &mut Vec<u8>, op: &Op) -> Result<(), JournalError> {
    match op {
        Op::Put { ns, key, value } => {
            out.push(T_PUT);
            out.push(ns.as_u8());
            push_key(out, key)?;
            push_value(out, value)?;
        }
        Op::Delete { ns, key } => {
            out.push(T_DELETE);
            out.push(ns.as_u8());
            push_key(out, key)?;
        }
        Op::Reset { ns } => {
            out.push(T_RESET);
            out.push(ns.as_u8());
        }
        Op::Install {
            id,
            version,
            secret,
        } => {
            out.push(T_INSTALL);
            push_key(out, id)?;
            out.extend_from_slice(&version.to_be_bytes());
            push_value(out, secret)?;
        }
        Op::Revoke { id } => {
            out.push(T_REVOKE);
            push_key(out, id)?;
        }
        Op::ResetPairing => out.push(T_RESET_PAIRING),
        Op::Raise { key, value } => {
            out.push(T_RAISE);
            push_key(out, key)?;
            out.extend_from_slice(&value.to_be_bytes());
        }
        Op::Tomb { id, version } => {
            out.push(T_TOMB);
            push_key(out, id)?;
            out.extend_from_slice(&version.to_be_bytes());
        }
    }
    Ok(())
}

/// An operation list: a 16-bit count, then each operation.
///
/// # Errors
/// A key, value or count that does not fit its length field.
pub fn encode_ops(ops: &[Op]) -> Result<Vec<u8>, JournalError> {
    let count = u16::try_from(ops.len()).map_err(|_| JournalError::TxnTooLarge)?;
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_be_bytes());
    for op in ops {
        encode_op(&mut out, op)?;
    }
    Ok(out)
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], JournalError> {
        let end = self.pos.checked_add(n).ok_or(JournalError::Malformed)?;
        if end > self.data.len() {
            return Err(JournalError::Malformed);
        }
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, JournalError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, JournalError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u64(&mut self) -> Result<u64, JournalError> {
        let b = self.take(8)?;
        let mut raw = [0u8; 8];
        raw.copy_from_slice(b);
        Ok(u64::from_be_bytes(raw))
    }

    /// A key: its length is bounded BEFORE the bytes are taken.
    fn key(&mut self, max: usize) -> Result<Vec<u8>, JournalError> {
        let len = usize::from(self.u8()?);
        if len > max {
            return Err(JournalError::Malformed);
        }
        Ok(self.take(len)?.to_vec())
    }

    fn value(&mut self, max: usize) -> Result<Vec<u8>, JournalError> {
        let len = usize::from(self.u16()?);
        if len > max {
            return Err(JournalError::Malformed);
        }
        Ok(self.take(len)?.to_vec())
    }
}

fn blob_namespace(raw: u8) -> Result<Namespace, JournalError> {
    match Namespace::from_u8(raw) {
        Some(ns) if ns.is_blob() => Ok(ns),
        _ => Err(JournalError::Malformed),
    }
}

/// Decode a payload written under `schema` (0 = legacy, 1 = current). `snapshot` is true for a snapshot frame, the only
/// place a tombstone operation may appear.
///
/// # Errors
/// [`JournalError::Malformed`] for anything that does not parse exactly: a length above its bound, a truncated field,
/// an unknown tag, trailing bytes.
pub fn decode_ops(
    lim: &Limits,
    payload: &[u8],
    schema: u8,
    snapshot: bool,
) -> Result<Vec<Op>, JournalError> {
    let mut r = Reader {
        data: payload,
        pos: 0,
    };
    let count = r.u16()?;
    let mut ops = Vec::new();
    for _ in 0..count {
        let tag = r.u8()?;
        let op = match tag {
            T_PUT => {
                let ns = blob_namespace(r.u8()?)?;
                let l = lim.ns(ns);
                let key = r.key(l.key_max)?;
                let value = r.value(l.value_max)?;
                Op::Put { ns, key, value }
            }
            T_DELETE => {
                let ns = blob_namespace(r.u8()?)?;
                let key = r.key(lim.ns(ns).key_max)?;
                Op::Delete { ns, key }
            }
            T_RESET => {
                let ns = Namespace::from_u8(r.u8()?).ok_or(JournalError::Malformed)?;
                Op::Reset { ns }
            }
            T_INSTALL => {
                let l = lim.ns(Namespace::Credentials);
                let id = r.key(l.key_max)?;
                let version = if schema >= FORMAT_VERSION {
                    r.u64()?
                } else {
                    1
                };
                let secret = r.value(l.value_max)?;
                Op::Install {
                    id,
                    version,
                    secret,
                }
            }
            T_REVOKE if schema >= FORMAT_VERSION => Op::Revoke {
                id: r.key(lim.ns(Namespace::Credentials).key_max)?,
            },
            T_TOMB if schema >= FORMAT_VERSION => {
                let id = r.key(lim.ns(Namespace::Credentials).key_max)?;
                Op::Tomb {
                    id,
                    version: r.u64()?,
                }
            }
            T_RAISE if schema >= FORMAT_VERSION => {
                let key = r.key(lim.ns(Namespace::Marks).key_max)?;
                Op::Raise {
                    key,
                    value: r.u64()?,
                }
            }
            T_RESET_PAIRING if schema >= FORMAT_VERSION => Op::ResetPairing,
            _ => return Err(JournalError::Malformed),
        };
        ops.push(op);
    }
    if r.pos != payload.len() {
        return Err(JournalError::Malformed);
    }
    if !snapshot && ops.iter().any(|op| matches!(op, Op::Tomb { .. })) {
        return Err(JournalError::Malformed);
    }
    Ok(ops)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_the_published_check_value() {
        // CRC-32/IEEE of "123456789" is 0xCBF43926 (the standard check value); splitting the input changes nothing.
        assert_eq!(crc32(&[b"123456789"]), 0xCBF4_3926);
        assert_eq!(crc32(&[b"1234", b"56789"]), 0xCBF4_3926);
        assert_eq!(crc32(&[]), 0);
    }

    #[test]
    fn a_segment_header_round_trips_and_a_flipped_bit_is_not_a_header() {
        let head = encode_segment_header(FORMAT_VERSION, 7, 42);
        assert_eq!(
            parse_segment_header(&head),
            HeaderParse::Ok(SegmentHeader {
                version: FORMAT_VERSION,
                generation: 7,
                first_seq: 42
            })
        );
        let mut bad = head;
        bad[5] ^= 1;
        assert_eq!(parse_segment_header(&bad), HeaderParse::Invalid);
        assert_eq!(
            parse_segment_header(&[ERASED; SEG_HEADER]),
            HeaderParse::Blank
        );
        let mut retired = head;
        retired[0] = 0;
        retired[1] = 0;
        assert_eq!(parse_segment_header(&retired), HeaderParse::Invalid);
    }

    #[test]
    fn a_hostile_length_is_refused_before_any_bytes_are_taken() {
        let lim = Limits::tiny();
        // one Put into settings with a value length of 0xFFFF and no value bytes behind it
        let payload = [0, 1, T_PUT, 1, 1, b'k', 0xFF, 0xFF];
        assert_eq!(
            decode_ops(&lim, &payload, FORMAT_VERSION, false),
            Err(JournalError::Malformed)
        );
        // a key length above the namespace bound
        let payload = [0, 1, T_PUT, 1, 200, b'k'];
        assert_eq!(
            decode_ops(&lim, &payload, FORMAT_VERSION, false),
            Err(JournalError::Malformed)
        );
        // a count that promises more operations than there are bytes
        assert_eq!(
            decode_ops(&lim, &[0xFF, 0xFF], FORMAT_VERSION, false),
            Err(JournalError::Malformed)
        );
    }
}
