//! The committed golden vectors, read once, as the fixed context every target fuzzes inside.
//!
//! Nothing here is invented: the key, the capabilities, the identities, the nonces and both Hello datagrams come from
//! the two vector files `tests/n01/` generates, so the seed corpus (made from the same files) is valid input.

use franken_stream::Capabilities;
use serde_json::Value;
use std::sync::OnceLock;

pub const WIRE_VECTORS: &str = include_str!("../../tests/vectors/n01_wire_vectors.json");
pub const NEGOTIATION_VECTORS: &str =
    include_str!("../../tests/vectors/n01_negotiation_vectors.json");

/// Negotiation 0 of the vector file: the offer a sender made and the answer a receiver gave.
pub struct Negotiation {
    pub sender_caps: Capabilities,
    pub receiver_caps: Capabilities,
    pub sender_peer: u64,
    pub receiver_peer: u64,
    pub stream_id: u64,
    pub epoch: u64,
    pub offer_nonce: [u8; 16],
    pub answer_nonce: [u8; 16],
    pub offer_wire: Vec<u8>,
    pub answer_wire: Vec<u8>,
}

pub struct Fixture {
    pub wire_key: [u8; 32],
    pub hello_key: [u8; 32],
    /// The stream and epoch scenario 0 starts on: the receiver every stateful run begins with.
    pub receiver_stream: u64,
    pub receiver_epoch: u64,
    pub negotiation: Negotiation,
}

pub fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(load)
}

pub fn parse_wire_vectors() -> Value {
    serde_json::from_str(WIRE_VECTORS).expect("the wire vector file parses")
}

pub fn parse_negotiation_vectors() -> Value {
    serde_json::from_str(NEGOTIATION_VECTORS).expect("the negotiation vector file parses")
}

pub fn unhex(text: &str) -> Vec<u8> {
    assert!(
        text.len().is_multiple_of(2),
        "odd-length hex in a vector file"
    );
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digit = |c: u8| match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => panic!("not lowercase hex in a vector file"),
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

fn array<const N: usize>(bytes: Vec<u8>, what: &str) -> [u8; N] {
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("{what} is not {N} bytes in the vector file"))
}

pub fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("vector field {key} is missing or not a string"))
}

pub fn number(value: &Value, key: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("vector field {key} is missing or not a u64"))
}

fn caps(value: &Value, key: &str) -> Capabilities {
    serde_json::from_value(value[key].clone())
        .unwrap_or_else(|_| panic!("vector field {key} is not a Capabilities object"))
}

fn load() -> Fixture {
    let wire = parse_wire_vectors();
    let negotiation = parse_negotiation_vectors();
    let first = &negotiation["negotiations"][0];
    let scenario = &wire["scenarios"][0];
    Fixture {
        wire_key: array(unhex(text(&wire, "key_hex")), "wire key"),
        hello_key: array(unhex(text(&negotiation, "key_hex")), "negotiation key"),
        receiver_stream: number(scenario, "stream_id"),
        receiver_epoch: number(scenario, "epoch"),
        negotiation: Negotiation {
            sender_caps: caps(first, "sender_caps"),
            receiver_caps: caps(first, "receiver_caps"),
            sender_peer: number(first, "sender_peer"),
            receiver_peer: number(first, "receiver_peer"),
            stream_id: number(first, "stream_id"),
            epoch: number(first, "epoch"),
            offer_nonce: array(unhex(text(first, "offer_nonce_hex")), "offer nonce"),
            answer_nonce: array(unhex(text(first, "answer_nonce_hex")), "answer nonce"),
            offer_wire: unhex(text(first, "offer_hex")),
            answer_wire: unhex(text(first, "answer_hex")),
        },
    }
}
