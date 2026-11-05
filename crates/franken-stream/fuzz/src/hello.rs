//! The two negotiation targets: the receiver's `respond` (which parses an Offer) and the initiator's `finish` (which
//! parses an Answer) (`docs/contracts/n01.md` sections 9 and 11).
//!
//! As in `wire`, the verdict each call must give is predicted from the bytes alone by an independent parse of the
//! 116-byte message layout in section 9 (this file's own offsets and constants), and an accepted exchange must be
//! consistent with that parse: the session carries the offer's identities and epoch, the selection is what `select`
//! gives for the two capability sets, and the Answer verifies, names the offer's SHA-256 and repeats the selection.

use crate::fixture::fixture;
use crate::wire;
use franken_stream::{
    respond, select, Capabilities, Initiator, Selection, StreamId, StreamKey, HELLO_DATAGRAM_BYTES,
};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

pub const BODY: usize = 100;
pub const TAG: usize = 16;
pub const LEN: usize = BODY + TAG;
pub const CONTEXT: &[u8] = b"FFWS-v1-hello";

const OFF_KIND: usize = 5;
const OFF_FLAGS: usize = 6;
const OFF_WIRE_MIN: usize = 7;
const OFF_WIRE_MAX: usize = 8;
const OFF_FORMATS: usize = 9;
const OFF_MAX_PAYLOAD: usize = 10;
const OFF_MANDATORY: usize = 12;
const OFF_OPTIONAL: usize = 16;
const OFF_PEER: usize = 20;
const OFF_STREAM: usize = 28;
const OFF_EPOCH: usize = 36;
const OFF_NONCE: usize = 44;
const OFF_SEL_VERSION: usize = 60;
const OFF_SEL_FORMAT: usize = 61;
const OFF_SEL_MAX_PAYLOAD: usize = 62;
const OFF_SEL_FEATURES: usize = 64;
const OFF_DIGEST: usize = 68;

type HmacSha256 = Hmac<Sha256>;

pub fn tag(psk: &[u8; 32], body: &[u8]) -> [u8; TAG] {
    let mut mac = HmacSha256::new_from_slice(psk).expect("any key length is a valid HMAC key");
    mac.update(CONTEXT);
    mac.update(body);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; TAG];
    out.copy_from_slice(&full[..TAG]);
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// A 100-byte body (the data cut or zero-padded to it) with a valid tag, whatever the body says.
pub fn resign(psk: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut body = data.to_vec();
    body.resize(BODY, 0);
    let mut out = body.clone();
    out.extend_from_slice(&tag(psk, &body));
    out
}

pub fn datagram_for(psk: &[u8; 32], input: &[u8]) -> Vec<u8> {
    let (mode, rest) = wire::split_mode(input);
    if mode == wire::MODE_RESIGN {
        resign(psk, rest)
    } else {
        rest.to_vec()
    }
}

/// Everything in a message, read straight from the bytes. Only call it on a datagram of `LEN` bytes.
#[derive(Debug, Clone)]
pub struct Parsed {
    pub kind: u8,
    pub flags: u8,
    pub caps: Capabilities,
    pub peer: u64,
    pub stream: u64,
    pub epoch: u64,
    pub nonce: [u8; 16],
    pub selection: Selection,
    pub digest: [u8; 32],
}

pub fn parse(msg: &[u8]) -> Parsed {
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&msg[OFF_NONCE..OFF_NONCE + 16]);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&msg[OFF_DIGEST..OFF_DIGEST + 32]);
    Parsed {
        kind: msg[OFF_KIND],
        flags: msg[OFF_FLAGS],
        caps: Capabilities {
            wire_min: msg[OFF_WIRE_MIN],
            wire_max: msg[OFF_WIRE_MAX],
            formats: msg[OFF_FORMATS],
            max_payload_bytes: wire::be16(msg, OFF_MAX_PAYLOAD),
            mandatory_features: wire::be32(msg, OFF_MANDATORY),
            optional_features: wire::be32(msg, OFF_OPTIONAL),
        },
        peer: wire::be64(msg, OFF_PEER),
        stream: wire::be64(msg, OFF_STREAM),
        epoch: wire::be64(msg, OFF_EPOCH),
        nonce,
        selection: Selection {
            wire_version: msg[OFF_SEL_VERSION],
            format: msg[OFF_SEL_FORMAT],
            max_payload_bytes: wire::be16(msg, OFF_SEL_MAX_PAYLOAD),
            features: wire::be32(msg, OFF_SEL_FEATURES),
        },
        digest,
    }
}

fn caps_valid(c: &Capabilities) -> bool {
    c.wire_min >= 1
        && c.wire_min <= c.wire_max
        && c.formats != 0
        && c.max_payload_bytes >= 4
        && c.max_payload_bytes.is_multiple_of(4)
        && c.mandatory_features & c.optional_features == 0
}

fn selection_well_formed(s: &Selection) -> bool {
    s.wire_version >= 1
        && s.format.count_ones() == 1
        && s.max_payload_bytes >= 4
        && s.max_payload_bytes.is_multiple_of(4)
}

fn selection_is_zero(s: &Selection) -> bool {
    s.wire_version == 0 && s.format == 0 && s.max_payload_bytes == 0 && s.features == 0
}

/// What the contract requires of decoding a message: the first rejection in order, or `"OK"`.
pub fn expected_decode(psk: &[u8; 32], msg: &[u8]) -> &'static str {
    if msg.len() != LEN {
        return "HELLO_LENGTH";
    }
    if msg[0..4] != *b"FFWN" {
        return "HELLO_BAD_MAGIC";
    }
    if msg[4] != 1 {
        return "HELLO_UNSUPPORTED_VERSION";
    }
    if tag(psk, &msg[..BODY])[..] != msg[BODY..] {
        return "HELLO_AUTH_FAILED";
    }
    let p = parse(msg);
    if p.kind != 1 && p.kind != 2 {
        return "UNKNOWN_HELLO_KIND";
    }
    if p.flags & 0xF0 != 0 {
        return "UNKNOWN_CRITICAL_HELLO_FLAGS";
    }
    if !caps_valid(&p.caps) {
        return "INVALID_CAPABILITIES";
    }
    if p.stream == 0 || p.peer == 0 {
        return "INVALID_PEER_IDENTITY";
    }
    if p.nonce == [0u8; 16] {
        return "INVALID_NONCE";
    }
    if p.kind == 1 {
        if !selection_is_zero(&p.selection) || p.digest != [0u8; 32] {
            return "MALFORMED_HELLO";
        }
    } else if !selection_well_formed(&p.selection) {
        return "MALFORMED_HELLO";
    }
    "OK"
}

/// `respond` against the contract. The receiver is the fixture's: its capabilities, identity and nonce, with the
/// current epoch equal to the fixture's offer epoch (so older offers are stale and the golden one is not).
pub fn check_respond(input: &[u8]) -> Result<(), String> {
    let f = fixture();
    let n = &f.negotiation;
    let psk = StreamKey::from_bytes(f.hello_key);
    let offer = datagram_for(&f.hello_key, input);
    let min_epoch = n.epoch;

    let mut expected = expected_decode(&f.hello_key, &offer);
    let mut chosen = None;
    if expected == "OK" {
        let p = parse(&offer);
        expected = if p.kind != 1 {
            "WRONG_HELLO_KIND"
        } else if p.epoch < min_epoch {
            "STALE_OFFER_EPOCH"
        } else if p.peer == n.receiver_peer || p.nonce == n.answer_nonce {
            "REFLECTED_HELLO"
        } else {
            match select(&p.caps, &n.receiver_caps) {
                Ok(selection) => {
                    chosen = Some(selection);
                    "OK"
                }
                Err(err) => err.code(),
            }
        };
    }

    match respond(
        &psk,
        n.receiver_caps,
        n.receiver_peer,
        min_epoch,
        n.answer_nonce,
        &offer,
    ) {
        Ok((session, answer)) => {
            let (true, Some(selection)) = (expected == "OK", chosen) else {
                return Err(format!(
                    "accepted an offer the contract refuses as {expected}"
                ));
            };
            let p = parse(&offer);
            if answer.len() != HELLO_DATAGRAM_BYTES || answer.len() != LEN {
                return Err(format!("the answer is {} bytes", answer.len()));
            }
            let verdict = expected_decode(&f.hello_key, &answer);
            if verdict != "OK" {
                return Err(format!("the answer does not verify: {verdict}"));
            }
            let a = parse(&answer);
            if a.kind != 2
                || a.peer != n.receiver_peer
                || a.stream != p.stream
                || a.epoch != p.epoch
                || a.nonce != n.answer_nonce
                || a.caps != n.receiver_caps
                || a.selection != selection
                || a.digest != sha256(&offer)
            {
                return Err("the answer does not repeat the exchange it answers".to_string());
            }
            if *session.selection() != selection
                || session.stream_id().get() != p.stream
                || session.epoch() != p.epoch
                || session.local_peer_id() != n.receiver_peer
                || session.remote_peer_id() != p.peer
            {
                return Err(
                    "the session does not carry the offer's identities and selection".to_string(),
                );
            }
            Ok(())
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

pub fn run_respond(input: &[u8]) {
    if let Err(why) = check_respond(input) {
        panic!("negotiation_respond: {why}");
    }
}

/// `finish` against the contract, for the fixture's own offer and an arbitrary Answer.
pub fn check_finish(input: &[u8]) -> Result<(), String> {
    let f = fixture();
    let n = &f.negotiation;
    let psk = StreamKey::from_bytes(f.hello_key);
    let stream = StreamId::new(n.stream_id)
        .map_err(|err| format!("the fixture stream id: {}", err.code()))?;
    let (initiator, offer) = Initiator::offer(
        &psk,
        n.sender_caps,
        n.sender_peer,
        stream,
        n.epoch,
        n.offer_nonce,
    )
    .map_err(|err| format!("the fixture offer is refused: {}", err.code()))?;
    if offer != n.offer_wire {
        return Err(
            "the offer the crate builds is not the committed vector (fixture drift)".to_string(),
        );
    }
    let answer = datagram_for(&f.hello_key, input);

    let mut expected = expected_decode(&f.hello_key, &answer);
    let mut chosen = None;
    if expected == "OK" {
        let p = parse(&answer);
        expected = if p.kind != 2 {
            "WRONG_HELLO_KIND"
        } else if p.stream != n.stream_id {
            "STREAM_MISMATCH"
        } else if p.epoch != n.epoch {
            "EPOCH_MISMATCH"
        } else if p.peer == n.sender_peer || p.nonce == n.offer_nonce {
            "REFLECTED_HELLO"
        } else if p.digest != sha256(&offer) {
            "OFFER_DIGEST_MISMATCH"
        } else {
            match select(&n.sender_caps, &p.caps) {
                Err(err) => err.code(),
                Ok(wanted) => {
                    chosen = Some(wanted);
                    if p.selection == wanted {
                        "OK"
                    } else if p.selection.wire_version < wanted.wire_version {
                        "DOWNGRADE_DETECTED"
                    } else {
                        "SELECTION_MISMATCH"
                    }
                }
            }
        };
    }

    match initiator.finish(&answer) {
        Ok(session) => {
            let (true, Some(selection)) = (expected == "OK", chosen) else {
                return Err(format!(
                    "accepted an answer the contract refuses as {expected}"
                ));
            };
            let p = parse(&answer);
            if *session.selection() != selection
                || session.stream_id().get() != n.stream_id
                || session.epoch() != n.epoch
                || session.local_peer_id() != n.sender_peer
                || session.remote_peer_id() != p.peer
            {
                return Err(
                    "the session does not carry the exchange's identities and selection"
                        .to_string(),
                );
            }
            Ok(())
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

pub fn run_finish(input: &[u8]) {
    if let Err(why) = check_finish(input) {
        panic!("negotiation_finish: {why}");
    }
}
