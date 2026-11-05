//! The seed corpus: the committed golden vectors, in the input format each target reads.
//!
//! Rust writes the corpus (`seed_corpus` binary) and the host tests replay the very same list in process, so the
//! on-disk format has one source. Every seed is valid or one mutation from valid input, which is what lets a
//! coverage-guided run start inside the contract instead of searching for the 4-byte magic.

use crate::fixture::{number, parse_negotiation_vectors, parse_wire_vectors, text, unhex};
use crate::stream::{encode_advance_epoch, encode_bind, encode_raw};
use crate::wire;
use serde_json::Value;
use std::collections::BTreeSet;

pub const STREAM_DECODE: &str = "stream_decode";
pub const STREAM_RECEIVER: &str = "stream_receiver";
pub const NEGOTIATION_RESPOND: &str = "negotiation_respond";
pub const NEGOTIATION_FINISH: &str = "negotiation_finish";
pub const TARGETS: [&str; 4] = [
    STREAM_DECODE,
    STREAM_RECEIVER,
    NEGOTIATION_RESPOND,
    NEGOTIATION_FINISH,
];

/// A scenario seed carries at most this many steps, so one input stays far below `-max_len`.
pub const SCENARIO_SEED_STEPS: usize = 40;

#[derive(Debug, Clone)]
pub struct Seed {
    pub target: &'static str,
    pub name: String,
    pub bytes: Vec<u8>,
}

fn raw(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8];
    out.extend_from_slice(bytes);
    out
}

fn resigned(body: &[u8]) -> Vec<u8> {
    let mut out = vec![wire::MODE_RESIGN];
    out.extend_from_slice(body);
    out
}

fn fitted(body: &[u8]) -> Vec<u8> {
    let mut out = vec![wire::MODE_RESIGN_FIT];
    out.extend_from_slice(body);
    out
}

fn array<'a>(doc: &'a Value, key: &str) -> &'a [Value] {
    doc[key]
        .as_array()
        .unwrap_or_else(|| panic!("vector document has no array {key}"))
}

/// The receiver operations of the first `SCENARIO_SEED_STEPS` steps of a scenario, starting from its own binding.
pub fn scenario_ops(scenario: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_bind(
        &mut out,
        number(scenario, "stream_id"),
        number(scenario, "epoch"),
    );
    for step in array(scenario, "steps").iter().take(SCENARIO_SEED_STEPS) {
        match text(step, "op") {
            "datagram" => encode_raw(&mut out, &unhex(text(step, "wire_hex"))),
            "advance_epoch" => encode_advance_epoch(&mut out, number(step, "epoch")),
            "bind" => encode_bind(&mut out, number(step, "stream_id"), number(step, "epoch")),
            other => panic!("unknown scenario op {other}"),
        }
    }
    out
}

/// How many of a scenario seed's datagrams the vector file says are accepted.
pub fn scenario_expected_accepted(scenario: &Value) -> u64 {
    array(scenario, "steps")
        .iter()
        .take(SCENARIO_SEED_STEPS)
        .filter(|step| text(step, "op") == "datagram" && text(step, "expect") == "OK")
        .count() as u64
}

pub fn all() -> Vec<Seed> {
    let wire_doc = parse_wire_vectors();
    let negotiation_doc = parse_negotiation_vectors();
    let mut seeds = Vec::new();

    // stream_decode: every vector as is, every accepted vector also as "re-sign this header and payload" and as "re-sign
    // it with the payload length fitted to the frame count", and every distinct datagram the scenarios feed a receiver.
    let mut known: BTreeSet<Vec<u8>> = BTreeSet::new();
    for vector in array(&wire_doc, "vectors") {
        let id = text(vector, "id");
        let datagram = unhex(text(vector, "wire_hex"));
        seeds.push(Seed {
            target: STREAM_DECODE,
            name: format!("{id}-raw"),
            bytes: raw(&datagram),
        });
        if text(vector, "expect") == "ACCEPT" {
            let cut = datagram.len() - wire::TAG;
            seeds.push(Seed {
                target: STREAM_DECODE,
                name: format!("{id}-resign"),
                bytes: resigned(&datagram[..cut]),
            });
            seeds.push(Seed {
                target: STREAM_DECODE,
                name: format!("{id}-fit"),
                bytes: fitted(&datagram[..cut]),
            });
        }
        known.insert(datagram);
    }
    let scenarios = array(&wire_doc, "scenarios");
    for scenario in scenarios {
        let id = text(scenario, "id");
        for (index, step) in array(scenario, "steps").iter().enumerate() {
            if text(step, "op") != "datagram" {
                continue;
            }
            let datagram = unhex(text(step, "wire_hex"));
            if known.insert(datagram.clone()) {
                seeds.push(Seed {
                    target: STREAM_DECODE,
                    name: format!("{id}-step-{index:03}"),
                    bytes: raw(&datagram),
                });
            }
        }
    }

    // stream_receiver: the opening steps of each scenario.
    for scenario in scenarios {
        seeds.push(Seed {
            target: STREAM_RECEIVER,
            name: text(scenario, "id").to_string(),
            bytes: scenario_ops(scenario),
        });
    }

    // negotiation_respond parses Offers; negotiation_finish parses Answers.
    for negotiation in array(&negotiation_doc, "negotiations") {
        let id = text(negotiation, "id");
        let offer = unhex(text(negotiation, "offer_hex"));
        let answer = unhex(text(negotiation, "answer_hex"));
        seeds.push(Seed {
            target: NEGOTIATION_RESPOND,
            name: format!("{id}-offer-raw"),
            bytes: raw(&offer),
        });
        seeds.push(Seed {
            target: NEGOTIATION_RESPOND,
            name: format!("{id}-offer-resign"),
            bytes: resigned(&offer[..crate::hello::BODY]),
        });
        seeds.push(Seed {
            target: NEGOTIATION_FINISH,
            name: format!("{id}-answer-raw"),
            bytes: raw(&answer),
        });
        seeds.push(Seed {
            target: NEGOTIATION_FINISH,
            name: format!("{id}-answer-resign"),
            bytes: resigned(&answer[..crate::hello::BODY]),
        });
    }
    for rejection in array(&negotiation_doc, "rejections") {
        let id = text(rejection, "id");
        match text(rejection, "op") {
            "respond" => seeds.push(Seed {
                target: NEGOTIATION_RESPOND,
                name: format!("{id}-offer"),
                bytes: raw(&unhex(text(rejection, "offer_hex"))),
            }),
            "finish" => seeds.push(Seed {
                target: NEGOTIATION_FINISH,
                name: format!("{id}-answer"),
                bytes: raw(&unhex(text(rejection, "answer_hex"))),
            }),
            other => panic!("unknown rejection op {other}"),
        }
    }
    seeds
}
