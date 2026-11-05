//! An independent statement of the N01 datagram contract (`docs/contracts/n01.md` sections 1-3), used as the oracle.
//!
//! Nothing here calls the decoder under test. `expected_decode` says, from the bytes alone, what the contract requires
//! of a datagram: the first rejection in receive order (structure, MAC, fields), or `"OK"`. The constants are this
//! file's own copy, so a drift in franken-stream is a disagreement the tests report, not something shared.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

pub const HEADER: usize = 64;
pub const TAG: usize = 16;
pub const MAX_PAYLOAD: usize = 1024;
pub const MIN_DATAGRAM: usize = HEADER + TAG;
pub const MAX_DATAGRAM: usize = HEADER + MAX_PAYLOAD + TAG;
pub const FRAMES_PER_BLOCK: u64 = 256;
pub const MAX_TIMESTAMP_NS: u64 = 1 << 62;
pub const MAX_FEC_GROUP: u8 = 16;
pub const CONTEXT: &[u8] = b"FFWS-v1-auth";

const OFF_VERSION: usize = 4;
const OFF_KIND: usize = 5;
const OFF_FLAGS: usize = 6;
const OFF_FORMAT: usize = 7;
const OFF_STREAM: usize = 8;
const OFF_START_FRAME: usize = 32;
const OFF_PRESENTATION: usize = 40;
const OFF_CONSUME_BY: usize = 48;
const OFF_FEC_INDEX: usize = 58;
const OFF_FEC_SIZE: usize = 59;
const OFF_FRAME_COUNT: usize = 60;
const OFF_PAYLOAD_LEN: usize = 62;

type HmacSha256 = Hmac<Sha256>;

pub fn be16(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

pub fn be32(buf: &[u8], off: usize) -> u32 {
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&buf[off..off + 4]);
    u32::from_be_bytes(raw)
}

pub fn be64(buf: &[u8], off: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&buf[off..off + 8]);
    u64::from_be_bytes(raw)
}

/// `HMAC-SHA256(key, context || header || payload)[..16]`, from the contract.
pub fn tag(key: &[u8; 32], header: &[u8], payload: &[u8]) -> [u8; TAG] {
    let mut mac = HmacSha256::new_from_slice(key).expect("any key length is a valid HMAC key");
    mac.update(CONTEXT);
    mac.update(header);
    mac.update(payload);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; TAG];
    out.copy_from_slice(&full[..TAG]);
    out
}

const NOTHING: &[u8] = &[];

/// The first byte picks how the rest is used: 1 means "re-sign it", 2 means "re-sign it and make the declared payload
/// length follow the declared frame count", any other value means "as is".
pub fn split_mode(input: &[u8]) -> (u8, &[u8]) {
    match input.split_first() {
        Some((mode, rest)) => (*mode, rest),
        None => (0, NOTHING),
    }
}

pub const MODE_RESIGN: u8 = 1;
pub const MODE_RESIGN_FIT: u8 = 2;

/// Turn `header || payload` bytes into a datagram that carries a valid tag, whatever the header says. The header is
/// the first 64 bytes (zero-padded when short); the payload is the rest, cut or zero-padded to the length the header
/// declares (capped at twice the maximum, so one run does bounded work). This is how a mutator reaches the
/// field-validation code behind the MAC: it edits fields, and the tag follows.
pub fn resign(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    sign(key, data, false)
}

/// `resign`, except that a header whose frame count is in range (1 to `FRAMES_PER_BLOCK`) has its payload length set to
/// four bytes per frame, whatever the input said. The contract couples the two fields (`FRAME_COUNT_MISMATCH`), so a
/// mutator that edits one of them is refused on the other and never reaches an accepted packet of a new size; here
/// the length follows, and the frame count is the one free choice. A frame count outside the range is left alone, with
/// the payload length as given, so the range check and everything behind it stay reachable. Mode 1 keeps the fields
/// independent, which is the only way to reach `FRAME_COUNT_MISMATCH` behind a valid tag.
pub fn resign_fitted(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    sign(key, data, true)
}

fn sign(key: &[u8; 32], data: &[u8], fit: bool) -> Vec<u8> {
    let mut header = [0u8; HEADER];
    let n = data.len().min(HEADER);
    header[..n].copy_from_slice(&data[..n]);
    let frames = be16(&header, OFF_FRAME_COUNT);
    if fit && frames != 0 && u64::from(frames) <= FRAMES_PER_BLOCK {
        // At most FRAMES_PER_BLOCK * 4 = MAX_PAYLOAD, so this cannot overflow a u16.
        let fitted = frames * 4;
        header[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 2].copy_from_slice(&fitted.to_be_bytes());
    }
    let rest: &[u8] = if data.len() > HEADER {
        &data[HEADER..]
    } else {
        &[]
    };
    let declared = usize::from(be16(&header, OFF_PAYLOAD_LEN)).min(2 * MAX_PAYLOAD);
    let mut payload = rest.to_vec();
    payload.resize(declared, 0);
    let mut out = Vec::with_capacity(HEADER + declared + TAG);
    out.extend_from_slice(&header);
    out.extend_from_slice(&payload);
    out.extend_from_slice(&tag(key, &header, &payload));
    out
}

/// The datagram a target is really handed for `input`.
pub fn datagram_for(key: &[u8; 32], input: &[u8]) -> Vec<u8> {
    let (mode, rest) = split_mode(input);
    match mode {
        MODE_RESIGN => resign(key, rest),
        MODE_RESIGN_FIT => resign_fitted(key, rest),
        _ => rest.to_vec(),
    }
}

/// The cheap pre-MAC checks, in the contract's order. `Some(code)` if the datagram must be refused before any MAC work.
pub fn structure(wire: &[u8]) -> Option<&'static str> {
    if wire.len() < MIN_DATAGRAM {
        return Some("PACKET_TOO_SHORT");
    }
    if wire.len() > MAX_DATAGRAM {
        return Some("DATAGRAM_TOO_LONG");
    }
    if wire[0..4] != *b"FFWS" {
        return Some("BAD_MAGIC");
    }
    if wire[OFF_VERSION] != 1 {
        return Some("UNSUPPORTED_VERSION");
    }
    let payload = usize::from(be16(wire, OFF_PAYLOAD_LEN));
    if payload > MAX_PAYLOAD {
        return Some("PAYLOAD_TOO_LARGE");
    }
    let expected = HEADER + payload + TAG;
    if wire.len() < expected {
        return Some("TRUNCATED");
    }
    if wire.len() > expected {
        return Some("TRAILING_BYTES");
    }
    None
}

/// Whether the tag is right. Only meaningful when `structure` passed.
pub fn tag_valid(key: &[u8; 32], wire: &[u8]) -> bool {
    let body_end = wire.len() - TAG;
    tag(key, &wire[..HEADER], &wire[HEADER..body_end])[..] == wire[body_end..]
}

/// The field rules, first failure in the contract's order. Only meaningful when `structure` passed.
pub fn fields(wire: &[u8]) -> Option<&'static str> {
    let kind = wire[OFF_KIND];
    if kind != 1 && kind != 2 {
        return Some("UNKNOWN_PACKET_KIND");
    }
    if wire[OFF_FLAGS] & 0xF0 != 0 {
        return Some("UNKNOWN_CRITICAL_FLAGS");
    }
    if wire[OFF_FORMAT] != 1 {
        return Some("UNKNOWN_FORMAT");
    }
    let frames = u64::from(be16(wire, OFF_FRAME_COUNT));
    let payload = u64::from(be16(wire, OFF_PAYLOAD_LEN));
    if frames == 0 || frames > FRAMES_PER_BLOCK {
        return Some("FRAME_COUNT_OUT_OF_RANGE");
    }
    if payload != frames * 4 {
        return Some("FRAME_COUNT_MISMATCH");
    }
    if !be64(wire, OFF_START_FRAME).is_multiple_of(FRAMES_PER_BLOCK) {
        return Some("MISALIGNED_START_FRAME");
    }
    let presentation = be64(wire, OFF_PRESENTATION);
    let consume_by = be64(wire, OFF_CONSUME_BY);
    if presentation > MAX_TIMESTAMP_NS || consume_by > presentation {
        return Some("INVALID_TIMESTAMPS");
    }
    let index = wire[OFF_FEC_INDEX];
    let size = wire[OFF_FEC_SIZE];
    let fec_ok = if kind == 1 {
        if size == 0 {
            index == 0
        } else {
            size <= MAX_FEC_GROUP && index < size
        }
    } else {
        (1..=MAX_FEC_GROUP).contains(&size) && index < MAX_FEC_GROUP
    };
    if !fec_ok {
        return Some("INVALID_FEC_FIELDS");
    }
    if be64(wire, OFF_STREAM) == 0 {
        return Some("INVALID_STREAM_ID");
    }
    None
}

/// What the contract requires of `decode_and_verify(wire)`: the first rejection in receive order, or `"OK"`.
pub fn expected_decode(key: &[u8; 32], wire: &[u8]) -> &'static str {
    if let Some(code) = structure(wire) {
        return code;
    }
    if !tag_valid(key, wire) {
        return "AUTH_FAILED";
    }
    fields(wire).unwrap_or("OK")
}
