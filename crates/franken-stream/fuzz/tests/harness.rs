//! Host tests of the fuzz harness itself (`docs/contracts/n01.md` section 11): they run under plain `cargo test` with no
//! fuzzer, so the oracles, the seed corpus and the planted bug are checked even where libFuzzer is not available.
//!
//! Every expected verdict below is written by hand from the contract; the code under test is only ever asked whether
//! it agrees. Each rejection is paired with the untouched input, accepted.

use franken_stream::{
    respond, AuthenticatedStreamPacket, Initiator, ReplayWindow, StreamId, StreamKey,
    StreamReceiver,
};
use franken_stream_fuzz::fixture::{
    fixture, number, parse_negotiation_vectors, parse_wire_vectors, text, unhex,
};
use franken_stream_fuzz::model::Window;
use franken_stream_fuzz::seed::{
    all, scenario_expected_accepted, scenario_ops, NEGOTIATION_FINISH, NEGOTIATION_RESPOND,
    STREAM_DECODE, STREAM_RECEIVER, TARGETS,
};
use franken_stream_fuzz::stream::{
    bounds, check_decode, check_receiver, encode_advance_epoch, encode_bind, encode_raw, parse_ops,
    Op, MAX_OPS,
};
use franken_stream_fuzz::{hello, plant, wire};
use serde_json::Value;
use std::collections::BTreeSet;

/// The largest input any run is given (`-max_len` in the central lines).
const MAX_LEN: usize = 32768;

fn vector_wire(id: &str) -> Vec<u8> {
    let doc = parse_wire_vectors();
    let vectors = doc["vectors"].as_array().expect("vectors");
    let vector = vectors
        .iter()
        .find(|v| v["id"] == id)
        .expect("the vector exists");
    unhex(text(vector, "wire_hex"))
}

fn key() -> StreamKey {
    StreamKey::from_bytes(fixture().wire_key)
}

/// A negotiation target's input for a message used as is (mode 0).
fn raw_input(message: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8];
    out.extend_from_slice(message);
    out
}

fn edit(base: &[u8], offset: usize, bytes: &[u8]) -> Vec<u8> {
    let mut out = base.to_vec();
    out[offset..offset + bytes.len()].copy_from_slice(bytes);
    out
}

fn run(target: &str, input: &[u8]) -> Result<(), String> {
    match target {
        STREAM_DECODE => check_decode(&wire::datagram_for(&fixture().wire_key, input)),
        STREAM_RECEIVER => check_receiver(input).map(|_| ()),
        NEGOTIATION_RESPOND => hello::check_respond(input),
        NEGOTIATION_FINISH => hello::check_finish(input),
        other => Err(format!("unknown target {other}")),
    }
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

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

// Only the clean build's smoke run mutates; the control build would otherwise warn about dead code.
#[cfg_attr(feature = "control", allow(dead_code))]
fn mutate(rng: &mut SplitMix64, base: &[u8]) -> Vec<u8> {
    let mut data = base.to_vec();
    for _ in 0..=rng.below(4) {
        let len = data.len() as u64;
        match rng.below(6) {
            0 if len > 0 => {
                let i = rng.below(len) as usize;
                data[i] ^= 1 << rng.below(8);
            }
            1 if len > 0 => {
                let i = rng.below(len) as usize;
                data[i] = rng.next() as u8;
            }
            2 => {
                let i = rng.below(len + 1) as usize;
                data.insert(i, rng.next() as u8);
            }
            3 if len > 0 => {
                let i = rng.below(len) as usize;
                data.remove(i);
            }
            4 => {
                let keep = rng.below(len + 1) as usize;
                data.truncate(keep);
            }
            _ => data.push(rng.next() as u8),
        }
    }
    data
}

// ---- the contract's own numbers -------------------------------------------------------------------------------

#[test]
fn this_crates_copy_of_the_contract_numbers_is_franken_streams() {
    assert_eq!(wire::HEADER, franken_stream::HEADER_LEN_BYTES);
    assert_eq!(wire::TAG, franken_stream::AUTH_TAG_LEN_BYTES);
    assert_eq!(wire::MAX_PAYLOAD, franken_stream::MAX_PAYLOAD_BYTES);
    assert_eq!(wire::MIN_DATAGRAM, franken_stream::MIN_DATAGRAM_BYTES);
    assert_eq!(wire::MAX_DATAGRAM, franken_stream::MAX_DATAGRAM_BYTES);
    assert_eq!(wire::MAX_PAYLOAD / 4, wire::FRAMES_PER_BLOCK as usize);
    assert_eq!(wire::CONTEXT, franken_stream::AUTH_CONTEXT);
    assert_eq!(wire::MAX_TIMESTAMP_NS, franken_stream::MAX_TIMESTAMP_NS);
    assert_eq!(wire::MAX_FEC_GROUP, franken_stream::MAX_FEC_GROUP_SIZE);
    assert_eq!(franken_stream::WIRE_MAGIC, *b"FFWS");
    assert_eq!(franken_stream::WIRE_VERSION, 1);
    assert_eq!(
        franken_stream_fuzz::model::WINDOW,
        franken_stream::REPLAY_WINDOW_PACKETS
    );
    assert_eq!(
        franken_stream_fuzz::model::MAX_GAP,
        franken_stream::MAX_FORWARD_SEQ_GAP
    );
    assert_eq!(hello::LEN, franken_stream::HELLO_DATAGRAM_BYTES);
}

// ---- the seed corpus -------------------------------------------------------------------------------------------

#[test]
fn the_seed_corpus_has_every_vector_in_the_format_each_target_reads() {
    let wire_doc = parse_wire_vectors();
    let neg_doc = parse_negotiation_vectors();
    let vectors = wire_doc["vectors"].as_array().expect("vectors");
    let accepted = vectors.iter().filter(|v| v["expect"] == "ACCEPT").count();
    let negotiations = neg_doc["negotiations"]
        .as_array()
        .expect("negotiations")
        .len();
    let rejections = neg_doc["rejections"].as_array().expect("rejections");
    let respond_rejections = rejections.iter().filter(|r| r["op"] == "respond").count();
    let finish_rejections = rejections.iter().filter(|r| r["op"] == "finish").count();
    assert!(accepted >= 7 && negotiations >= 4 && respond_rejections > 0 && finish_rejections > 0);

    let seeds = all();
    let count = |target: &str| seeds.iter().filter(|s| s.target == target).count();
    assert!(
        count(STREAM_DECODE) >= vectors.len() + 2 * accepted,
        "{}",
        count(STREAM_DECODE)
    );
    assert_eq!(
        count(STREAM_RECEIVER),
        wire_doc["scenarios"].as_array().expect("scenarios").len()
    );
    assert_eq!(
        count(NEGOTIATION_RESPOND),
        2 * negotiations + respond_rejections
    );
    assert_eq!(
        count(NEGOTIATION_FINISH),
        2 * negotiations + finish_rejections
    );
    for target in TARGETS {
        let mut names: Vec<&str> = seeds
            .iter()
            .filter(|s| s.target == target)
            .map(|s| s.name.as_str())
            .collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "duplicate seed names for {target}");
    }
    assert!(seeds
        .iter()
        .all(|s| s.bytes.len() <= MAX_LEN && !s.bytes.is_empty()));

    // Every accepted vector is a seed three ways: as is (mode 0), re-signed (mode 1) and fitted (mode 2), and each of
    // the three gives the vector's datagram back.
    for vector in vectors.iter().filter(|v| v["expect"] == "ACCEPT") {
        let id = text(vector, "id");
        let datagram = unhex(text(vector, "wire_hex"));
        for (suffix, mode) in [
            ("raw", 0u8),
            ("resign", wire::MODE_RESIGN),
            ("fit", wire::MODE_RESIGN_FIT),
        ] {
            let name = format!("{id}-{suffix}");
            let seed = seeds
                .iter()
                .find(|s| s.target == STREAM_DECODE && s.name == name)
                .unwrap_or_else(|| panic!("no seed {name}"));
            assert_eq!(seed.bytes[0], mode, "{name}");
            assert_eq!(
                wire::datagram_for(&fixture().wire_key, &seed.bytes),
                datagram,
                "{name}"
            );
        }
    }
}

#[test]
fn every_seed_passes_its_oracle_in_this_build() {
    for seed in all() {
        if let Err(why) = run(seed.target, &seed.bytes) {
            panic!(
                "seed {}/{} violates an oracle: {why}",
                seed.target, seed.name
            );
        }
    }
}

#[test]
fn scenario_seeds_are_accepted_exactly_as_often_as_the_vector_file_says() {
    let doc = parse_wire_vectors();
    for scenario in doc["scenarios"].as_array().expect("scenarios") {
        let want = scenario_expected_accepted(scenario);
        assert!(
            want >= 5,
            "{} accepts only {want} in its seed prefix",
            text(scenario, "id")
        );
        assert_eq!(
            check_receiver(&scenario_ops(scenario)),
            Ok(want),
            "{}",
            text(scenario, "id")
        );
    }
}

#[test]
fn re_signing_an_accepted_vectors_header_and_payload_gives_back_the_vector() {
    let doc = parse_wire_vectors();
    let mut checked = 0;
    for vector in doc["vectors"].as_array().expect("vectors") {
        if vector["expect"] != "ACCEPT" {
            continue;
        }
        let datagram = unhex(text(vector, "wire_hex"));
        let body = &datagram[..datagram.len() - wire::TAG];
        assert_eq!(
            wire::resign(&fixture().wire_key, body),
            datagram,
            "{}",
            text(vector, "id")
        );
        assert_eq!(
            wire::resign_fitted(&fixture().wire_key, body),
            datagram,
            "{}",
            text(vector, "id")
        );
        checked += 1;
    }
    assert!(checked >= 7);
}

#[test]
fn re_signing_follows_the_declared_payload_length_and_stays_bounded() {
    let golden = vector_wire("N01-GV-002");
    let body = &golden[..golden.len() - wire::TAG];
    let declared = usize::from(wire::be16(body, 62));
    assert!(declared >= 8);

    // More bytes than declared are cut, fewer are zero-padded: the datagram is exactly header + declared + tag.
    let longer = [body, &[7u8; 40][..]].concat();
    assert_eq!(
        wire::resign(&fixture().wire_key, &longer).len(),
        wire::HEADER + declared + wire::TAG
    );
    let shorter = &body[..wire::HEADER + 2];
    assert_eq!(
        wire::resign(&fixture().wire_key, shorter).len(),
        wire::HEADER + declared + wire::TAG
    );
    // A header shorter than 64 bytes is zero-padded; zero declares an empty payload.
    assert_eq!(
        wire::resign(&fixture().wire_key, &[]).len(),
        wire::HEADER + wire::TAG
    );
    // A declared length is capped at twice the maximum: one run does bounded work.
    let huge = edit(body, 62, &[0xFF, 0xFF]);
    assert_eq!(
        wire::resign(&fixture().wire_key, &huge).len(),
        wire::HEADER + 2 * wire::MAX_PAYLOAD + wire::TAG
    );
}

#[test]
fn fitting_makes_the_payload_length_follow_the_frame_count_and_changes_nothing_else() {
    let golden = vector_wire("N01-GV-002");
    let header = &golden[..wire::HEADER];
    let wire_key = fixture().wire_key;
    let last_frame_count = u16::try_from(wire::FRAMES_PER_BLOCK).expect("256 fits in 16 bits");

    // Every frame count in range, with a payload length that is wrong on purpose (7 is no multiple of 4): re-signing it
    // as it stands (mode 1) is refused as a mismatch, and fitting (mode 2) gives an accepted packet of four bytes per frame.
    for frames in 1..=last_frame_count {
        let body = edit(
            &edit(header, 60, &frames.to_be_bytes()),
            62,
            &7u16.to_be_bytes(),
        );
        assert_real_code(&wire::resign(&wire_key, &body), "FRAME_COUNT_MISMATCH");
        let fitted = wire::resign_fitted(&wire_key, &body);
        assert_eq!(wire::expected_decode(&wire_key, &fitted), "OK", "{frames}");
        let packet =
            AuthenticatedStreamPacket::decode_and_verify(&fitted, &key()).expect("accepted");
        assert_eq!(packet.payload.len(), 4 * usize::from(frames), "{frames}");
        // nothing but the payload length field was touched
        assert_eq!(fitted[..62], body[..62], "{frames}");
        assert_eq!(fitted[62..64], (4 * frames).to_be_bytes(), "{frames}");
    }

    // A frame count outside the range is left alone, with the payload length as given (the golden's 12): the range check
    // and everything behind it stay reachable in mode 2, and the datagram is the mode 1 one.
    for frames in [0u16, 257, 1000, 0xFFFF] {
        let body = edit(header, 60, &frames.to_be_bytes());
        let fitted = wire::resign_fitted(&wire_key, &body);
        assert_eq!(fitted, wire::resign(&wire_key, &body), "{frames}");
        assert_real_code(&fitted, "FRAME_COUNT_OUT_OF_RANGE");
    }

    // The mode byte picks the rule, and any other value is "as is".
    let mismatched = edit(header, 62, &7u16.to_be_bytes());
    let with_mode = |mode: u8| [&[mode][..], &mismatched[..]].concat();
    let resigned = wire::resign(&wire_key, &mismatched);
    let fitted = wire::resign_fitted(&wire_key, &mismatched);
    assert_ne!(resigned, fitted);
    assert_eq!(
        wire::datagram_for(&wire_key, &with_mode(wire::MODE_RESIGN)),
        resigned
    );
    assert_eq!(
        wire::datagram_for(&wire_key, &with_mode(wire::MODE_RESIGN_FIT)),
        fitted
    );
    for mode in [0u8, 3, 255] {
        assert_eq!(wire::datagram_for(&wire_key, &with_mode(mode)), mismatched);
    }
}

// ---- the stateless oracle, pinned by hand -------------------------------------------------------------------

fn assert_real_code(datagram: &[u8], code: &str) {
    assert_eq!(
        wire::expected_decode(&fixture().wire_key, datagram),
        code,
        "the oracle"
    );
    let real = AuthenticatedStreamPacket::decode_and_verify(datagram, &key());
    match (code, real) {
        ("OK", Ok(_)) => {}
        (_, Err(err)) => assert_eq!(err.code(), code, "the decoder"),
        (_, Ok(_)) => panic!("the decoder accepted a datagram the contract refuses as {code}"),
    }
    assert_eq!(
        check_decode(datagram),
        Ok(()),
        "oracle and decoder disagree"
    );
}

#[test]
fn structural_rejections_are_the_contracts_and_the_untouched_datagram_is_accepted() {
    let golden = vector_wire("N01-GV-002");
    assert_real_code(&golden, "OK");
    assert_real_code(&golden[..wire::MIN_DATAGRAM - 1], "PACKET_TOO_SHORT");
    assert_real_code(
        &[golden.clone(), vec![0u8; 2000]].concat(),
        "DATAGRAM_TOO_LONG",
    );
    assert_real_code(&edit(&golden, 0, b"FFWX"), "BAD_MAGIC");
    assert_real_code(&edit(&golden, 4, &[2]), "UNSUPPORTED_VERSION");
    assert_real_code(&edit(&golden, 62, &[0x04, 0x01]), "PAYLOAD_TOO_LARGE");
    assert_real_code(&golden[..golden.len() - 1], "TRUNCATED");
    assert_real_code(&[golden.clone(), vec![0u8]].concat(), "TRAILING_BYTES");
    let mut forged = golden.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    assert_real_code(&forged, "AUTH_FAILED");
}

#[test]
fn every_field_rule_is_the_contracts_when_the_tag_is_valid_and_the_untouched_header_is_accepted() {
    let golden = vector_wire("N01-GV-002");
    let body = golden[..golden.len() - wire::TAG].to_vec();
    let resigned = |b: &[u8]| wire::resign(&fixture().wire_key, b);
    assert_real_code(&resigned(&body), "OK");

    assert_real_code(&resigned(&edit(&body, 5, &[3])), "UNKNOWN_PACKET_KIND");
    assert_real_code(
        &resigned(&edit(&body, 6, &[0x10])),
        "UNKNOWN_CRITICAL_FLAGS",
    );
    assert_real_code(&resigned(&edit(&body, 7, &[2])), "UNKNOWN_FORMAT");
    assert_real_code(
        &resigned(&edit(&body, 60, &[0, 0])),
        "FRAME_COUNT_OUT_OF_RANGE",
    );
    assert_real_code(
        &resigned(&edit(&body, 60, &[1, 44])),
        "FRAME_COUNT_OUT_OF_RANGE",
    );
    assert_real_code(&resigned(&edit(&body, 60, &[0, 2])), "FRAME_COUNT_MISMATCH");
    assert_real_code(
        &resigned(&edit(&body, 32, &1u64.to_be_bytes())),
        "MISALIGNED_START_FRAME",
    );
    let presentation = wire::be64(&body, 40);
    assert_real_code(
        &resigned(&edit(&body, 48, &(presentation + 1).to_be_bytes())),
        "INVALID_TIMESTAMPS",
    );
    assert_real_code(
        &resigned(&edit(
            &body,
            40,
            &(wire::MAX_TIMESTAMP_NS + 1).to_be_bytes(),
        )),
        "INVALID_TIMESTAMPS",
    );
    assert_real_code(&resigned(&edit(&body, 59, &[17])), "INVALID_FEC_FIELDS");
    assert_real_code(&resigned(&edit(&body, 8, &[0u8; 8])), "INVALID_STREAM_ID");
    // The first failing rule in receive order wins: kind before flags.
    assert_real_code(
        &resigned(&edit(&edit(&body, 5, &[3]), 6, &[0x10])),
        "UNKNOWN_PACKET_KIND",
    );
}

#[test]
fn the_bounds_oracle_flags_each_violation_and_passes_the_golden_packets() {
    for id in ["N01-GV-001", "N01-GV-002", "N01-GV-004", "N01-GV-005"] {
        let packet = AuthenticatedStreamPacket::decode_and_verify(&vector_wire(id), &key())
            .expect("accepted");
        assert_eq!(bounds(&packet), Ok(()), "{id}");
    }
    let good = AuthenticatedStreamPacket::decode_and_verify(&vector_wire("N01-GV-002"), &key())
        .expect("accepted");
    let violations: Vec<(&str, AuthenticatedStreamPacket)> = vec![
        (
            "payload too short",
            AuthenticatedStreamPacket {
                payload: vec![0u8; 3],
                ..good.clone()
            },
        ),
        (
            "payload not a multiple of 4",
            AuthenticatedStreamPacket {
                payload: vec![0u8; 10],
                ..good.clone()
            },
        ),
        (
            "payload too long",
            AuthenticatedStreamPacket {
                payload: vec![0u8; 1028],
                ..good.clone()
            },
        ),
        (
            "critical flags",
            AuthenticatedStreamPacket {
                flags: 0x10,
                ..good.clone()
            },
        ),
        (
            "misaligned start frame",
            AuthenticatedStreamPacket {
                start_frame: 1,
                ..good.clone()
            },
        ),
        (
            "consume-by after presentation",
            AuthenticatedStreamPacket {
                consume_by_ns: good.presentation_time_ns + 1,
                ..good.clone()
            },
        ),
        (
            "presentation past the maximum",
            AuthenticatedStreamPacket {
                presentation_time_ns: wire::MAX_TIMESTAMP_NS + 1,
                consume_by_ns: 0,
                ..good.clone()
            },
        ),
        (
            "oversize FEC group",
            AuthenticatedStreamPacket {
                fec_group_size: 17,
                fec_index: 0,
                ..good.clone()
            },
        ),
        (
            "FEC index outside its group",
            AuthenticatedStreamPacket {
                fec_group_size: 2,
                fec_index: 2,
                ..good.clone()
            },
        ),
    ];
    for (what, packet) in violations {
        assert!(bounds(&packet).is_err(), "{what} was not flagged");
    }
}

// ---- the stateful oracle ---------------------------------------------------------------------------------------

fn first_scenario_datagram() -> Vec<u8> {
    let doc = parse_wire_vectors();
    let step = &doc["scenarios"][0]["steps"][0];
    assert_eq!(step["op"], "datagram");
    assert_eq!(step["expect"], "OK");
    unhex(text(step, "wire_hex"))
}

#[test]
fn a_replay_is_refused_and_a_stale_epoch_is_refused_and_the_first_delivery_is_accepted() {
    let d = first_scenario_datagram();
    let key = fixture().wire_key;
    let epoch = fixture().receiver_epoch;
    let mut once = Vec::new();
    encode_raw(&mut once, &d);
    assert_eq!(check_receiver(&once), Ok(1));

    let mut twice = once.clone();
    encode_raw(&mut twice, &d);
    assert_eq!(
        check_receiver(&twice),
        Ok(1),
        "the duplicate must be refused"
    );

    let mut stale = once.clone();
    encode_advance_epoch(&mut stale, epoch + 1);
    encode_raw(&mut stale, &d);
    assert_eq!(
        check_receiver(&stale),
        Ok(1),
        "an older epoch must be refused once the epoch advanced"
    );

    // The same datagram after a bind to a restarted stream is a packet of the wrong stream.
    let mut rebound = Vec::new();
    encode_bind(&mut rebound, fixture().receiver_stream ^ 1, epoch);
    encode_raw(&mut rebound, &d);
    assert_eq!(check_receiver(&rebound), Ok(0));

    // ...and a re-signed copy of it is accepted exactly like the original (the paired positive).
    let body = &d[..d.len() - wire::TAG];
    let mut resigned = vec![wire::MODE_RESIGN];
    resigned.extend_from_slice(body);
    assert_eq!(wire::datagram_for(&key, &resigned), d);
}

#[test]
fn a_repeated_bind_of_the_bound_stream_does_not_reopen_its_sequence_space() {
    let d = first_scenario_datagram();
    let stream = fixture().receiver_stream;
    let epoch = fixture().receiver_epoch;
    // The datagram, a bind that names the stream it already is bound to, the datagram again: the second delivery is
    // a replay, whether the bind repeats the epoch or names an older one.
    for (what, bind_epoch) in [
        ("the same epoch", epoch),
        ("an older epoch", epoch.saturating_sub(1)),
    ] {
        let mut ops = Vec::new();
        encode_raw(&mut ops, &d);
        encode_bind(&mut ops, stream, bind_epoch);
        encode_raw(&mut ops, &d);
        assert_eq!(
            check_receiver(&ops),
            Ok(1),
            "a bind of the bound stream with {what} made a replay acceptable"
        );
    }
    // Paired positives: the first delivery is accepted, and a bind to a different identity does start a new sequence
    // space (the datagram is then of the wrong stream, as in the test above, and nothing is accepted).
    let mut once = Vec::new();
    encode_raw(&mut once, &d);
    assert_eq!(check_receiver(&once), Ok(1));
    let mut other = Vec::new();
    encode_bind(&mut other, stream ^ 1, epoch);
    encode_raw(&mut other, &d);
    assert_eq!(check_receiver(&other), Ok(0));
}

/// The first datagram of a scenario that the vector file says is answered `expect`.
fn first_datagram_expecting(scenario: &Value, expect: &str) -> Vec<u8> {
    let step = scenario["steps"]
        .as_array()
        .expect("steps")
        .iter()
        .find(|s| text(s, "op") == "datagram" && text(s, "expect") == expect)
        .unwrap_or_else(|| panic!("the scenario has no datagram expecting {expect}"));
    unhex(text(step, "wire_hex"))
}

#[test]
fn a_scenario_starts_from_a_fresh_receiver_and_a_lower_epoch_rebind_of_the_bound_stream_is_no_way_there(
) {
    // N01-SC-002 names the fixture's own stream at epoch 3, and every run begins with that stream at epoch 7. A bind of the
    // stream a receiver already holds is not a restart: it must never rewind the epoch, or a captured epoch-3 datagram
    // would be accepted again. So a scenario cannot be initialized by one bind; its seed restarts through another identity.
    let doc = parse_wire_vectors();
    let low = doc["scenarios"]
        .as_array()
        .expect("scenarios")
        .iter()
        .find(|s| {
            number(s, "stream_id") == fixture().receiver_stream
                && number(s, "epoch") < fixture().receiver_epoch
        })
        .expect("a scenario on the fixture's stream at an older epoch");
    let raw_stream = number(low, "stream_id");
    let low_epoch = number(low, "epoch");
    let stream = StreamId::new(raw_stream).expect("the scenario's stream id");
    // Hand-derived from the contract (section 3): a packet of an older epoch than the active one is STALE_EPOCH, one of a
    // newer epoch is FUTURE_EPOCH, and the same epoch is judged by the window. The vector file says the scenario's first
    // datagram is from epoch 4 (FUTURE_EPOCH) and its next from epoch 3 (OK), on a receiver at epoch 3.
    let newer = first_datagram_expecting(low, "FUTURE_EPOCH");
    let current = first_datagram_expecting(low, "OK");

    // The permitted case: a receiver created for the scenario's own state, as the wire replay and the Python reference do.
    let mut fresh = StreamReceiver::new(key(), stream, low_epoch);
    assert_eq!(
        fresh.accept(&newer).map_err(|e| e.code()),
        Err("FUTURE_EPOCH")
    );
    assert!(fresh.accept(&current).is_ok());

    // The attack: the receiver every run begins with, then a lower-epoch bind of the stream it holds. The bind changes
    // nothing, so the same traffic is stale; it is not accepted again, and the epoch is not rewound.
    let mut attacked = StreamReceiver::new(key(), stream, fixture().receiver_epoch);
    attacked.bind_stream(stream, low_epoch);
    assert_eq!(
        attacked.active_epoch(),
        fixture().receiver_epoch,
        "a lower-epoch bind of the bound stream rewound the epoch"
    );
    assert_eq!(
        attacked.accept(&current).map_err(|e| e.code()),
        Err("STALE_EPOCH")
    );
    assert_eq!(
        attacked.accept(&newer).map_err(|e| e.code()),
        Err("STALE_EPOCH")
    );

    // The same pair through the oracle that runs every seed. The corpus's seed reaches the scenario's state by two binds
    // (another identity, then its own) and is accepted as often as the vector file says; the old initializer, one bind
    // of the bound stream, gets nothing.
    let seed = scenario_ops(low);
    let mut one = Vec::new();
    encode_bind(&mut one, raw_stream, low_epoch);
    let bind_len = one.len();
    assert_eq!(
        parse_ops(&fixture().wire_key, &seed[..2 * bind_len]),
        vec![
            Op::Bind {
                stream_id: raw_stream ^ 1,
                epoch: low_epoch
            },
            Op::Bind {
                stream_id: raw_stream,
                epoch: low_epoch
            }
        ]
    );
    let want = scenario_expected_accepted(low);
    assert!(
        want >= 5,
        "the scenario accepts only {want} in its seed prefix"
    );
    assert_eq!(check_receiver(&seed), Ok(want));
    let mut old_style = one;
    old_style.extend_from_slice(&seed[2 * bind_len..]);
    assert_eq!(
        check_receiver(&old_style),
        Ok(0),
        "the old initializer must get nothing: its datagrams are of an older epoch than the receiver holds"
    );
}

#[test]
fn operation_streams_round_trip_and_stop_at_the_first_unreadable_operation() {
    let key = fixture().wire_key;
    let d = first_scenario_datagram();
    let mut bytes = Vec::new();
    encode_bind(&mut bytes, 5, 9);
    encode_raw(&mut bytes, &d);
    encode_advance_epoch(&mut bytes, 12);
    assert_eq!(
        parse_ops(&key, &bytes),
        vec![
            Op::Bind {
                stream_id: 5,
                epoch: 9
            },
            Op::Datagram(d.clone()),
            Op::AdvanceEpoch(12)
        ]
    );
    // A cut-off operation, and an unknown tag, end the stream; what came before stays.
    assert_eq!(parse_ops(&key, &bytes[..bytes.len() - 3]).len(), 2);
    let mut unknown = bytes.clone();
    unknown.push(0xEE);
    encode_advance_epoch(&mut unknown, 99);
    assert_eq!(parse_ops(&key, &unknown).len(), 3);
    // More operations than a run takes are ignored.
    let mut many = Vec::new();
    for _ in 0..(MAX_OPS + 10) {
        encode_advance_epoch(&mut many, 1);
    }
    assert_eq!(parse_ops(&key, &many).len(), MAX_OPS);
    assert!(parse_ops(&key, &[]).is_empty());
}

#[test]
fn the_window_model_agrees_with_the_real_window_on_a_long_seeded_walk() {
    let mut rng = SplitMix64(0x4E30_3146);
    let mut real = ReplayWindow::new(0);
    let mut model = Window::default();
    let mut high = 0u64;
    let mut accepted = 0u64;
    let mut refused = 0u64;
    for step in 0..60_000u64 {
        let seq = match rng.below(10) {
            0 => rng.next() >> rng.below(64),
            1 => high.saturating_sub(rng.below(100)),
            2 => high.saturating_add(1020 + rng.below(10)),
            _ => high
                .saturating_add(rng.below(3))
                .saturating_sub(rng.below(70) * u64::from(rng.below(3) == 0)),
        };
        let verdict = model.judge(seq);
        match real.check_and_record(0, seq) {
            Ok(()) => {
                assert_eq!(verdict, "OK", "step {step}: the real window accepted {seq}");
                model.record(seq);
                high = high.max(seq);
                accepted += 1;
            }
            Err(err) => {
                assert_eq!(err.code(), verdict, "step {step}: sequence {seq}");
                refused += 1;
            }
        }
    }
    assert!(
        accepted > 10_000 && refused > 5_000,
        "accepted {accepted}, refused {refused}"
    );
}

#[test]
fn the_window_model_hand_cases() {
    let mut w = Window::default();
    assert_eq!(w.judge(0), "OK");
    assert_eq!(w.judge(1024), "OK");
    assert_eq!(w.judge(1025), "FUTURE_SEQUENCE");
    w.record(100);
    assert_eq!(w.judge(100), "REPLAY_OR_DUPLICATE");
    assert_eq!(w.judge(37), "OK");
    assert_eq!(w.judge(36), "REPLAY_OR_DUPLICATE");
    assert_eq!(w.judge(1124), "OK");
    assert_eq!(w.judge(1125), "FUTURE_SEQUENCE");
    w.record(37);
    assert_eq!(w.judge(37), "REPLAY_OR_DUPLICATE");
    assert_eq!(w.high(), Some(100));
}

// ---- the negotiation oracle, pinned by hand ----------------------------------------------------------------------

fn real_respond_code(offer: &[u8]) -> &'static str {
    let f = fixture();
    let n = &f.negotiation;
    match respond(
        &StreamKey::from_bytes(f.hello_key),
        n.receiver_caps,
        n.receiver_peer,
        n.epoch,
        n.answer_nonce,
        offer,
    ) {
        Ok(_) => "OK",
        Err(err) => err.code(),
    }
}

fn real_finish_code(answer: &[u8]) -> &'static str {
    let f = fixture();
    let n = &f.negotiation;
    let psk = StreamKey::from_bytes(f.hello_key);
    let stream = StreamId::new(n.stream_id).expect("nonzero");
    let (initiator, _) = Initiator::offer(
        &psk,
        n.sender_caps,
        n.sender_peer,
        stream,
        n.epoch,
        n.offer_nonce,
    )
    .expect("offer");
    match initiator.finish(answer) {
        Ok(_) => "OK",
        Err(err) => err.code(),
    }
}

#[test]
fn offers_are_refused_for_the_contracts_reason_and_the_golden_offer_is_accepted() {
    let n = &fixture().negotiation;
    let psk = fixture().hello_key;
    let body = n.offer_wire[..hello::BODY].to_vec();
    let resigned = |b: &[u8]| hello::resign(&psk, b);

    // decode-level rejections, by hand
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("golden", n.offer_wire.clone(), "OK"),
        ("golden, re-signed", resigned(&body), "OK"),
        (
            "short",
            n.offer_wire[..hello::LEN - 1].to_vec(),
            "HELLO_LENGTH",
        ),
        ("magic", edit(&n.offer_wire, 0, b"FFWX"), "HELLO_BAD_MAGIC"),
        (
            "version",
            edit(&n.offer_wire, 4, &[2]),
            "HELLO_UNSUPPORTED_VERSION",
        ),
        (
            "tag",
            edit(
                &n.offer_wire,
                hello::LEN - 1,
                &[n.offer_wire[hello::LEN - 1] ^ 1],
            ),
            "HELLO_AUTH_FAILED",
        ),
        (
            "kind",
            resigned(&edit(&body, 5, &[3])),
            "UNKNOWN_HELLO_KIND",
        ),
        (
            "critical flags",
            resigned(&edit(&body, 6, &[0x10])),
            "UNKNOWN_CRITICAL_HELLO_FLAGS",
        ),
        (
            "wire_min 0",
            resigned(&edit(&body, 7, &[0])),
            "INVALID_CAPABILITIES",
        ),
        (
            "peer 0",
            resigned(&edit(&body, 20, &[0u8; 8])),
            "INVALID_PEER_IDENTITY",
        ),
        (
            "stream 0",
            resigned(&edit(&body, 28, &[0u8; 8])),
            "INVALID_PEER_IDENTITY",
        ),
        (
            "nonce 0",
            resigned(&edit(&body, 44, &[0u8; 16])),
            "INVALID_NONCE",
        ),
        (
            "offer with a selection",
            resigned(&edit(&body, 60, &[1])),
            "MALFORMED_HELLO",
        ),
    ];
    for (what, offer, code) in &cases {
        assert_eq!(
            hello::expected_decode(&psk, offer),
            *code,
            "{what}: the oracle"
        );
        assert_eq!(
            hello::check_respond(&raw_input(offer)),
            Ok(()),
            "{what}: oracle and respond disagree"
        );
        // `respond` is the decoder's only caller here, and in the decode-level cases its verdict is the decoder's.
        assert_eq!(real_respond_code(offer), *code, "{what}: respond");
    }

    // respond-level rejections: valid messages the receiver still refuses
    let epoch_back = resigned(&edit(&body, 36, &(n.epoch - 1).to_be_bytes()));
    let reflected = resigned(&edit(&body, 20, &n.receiver_peer.to_be_bytes()));
    let no_version = resigned(&edit(&edit(&body, 7, &[2]), 8, &[2]));
    for (what, offer, code) in [
        ("an older epoch", &epoch_back, "STALE_OFFER_EPOCH"),
        ("the receiver's own identity", &reflected, "REFLECTED_HELLO"),
        (
            "a version range of only 2",
            &no_version,
            "NO_COMMON_VERSION",
        ),
        (
            "an Answer where an Offer belongs",
            &n.answer_wire,
            "WRONG_HELLO_KIND",
        ),
    ] {
        assert_eq!(
            hello::expected_decode(&psk, offer),
            "OK",
            "{what}: it is a well-formed message"
        );
        assert_eq!(hello::check_respond(&raw_input(offer)), Ok(()), "{what}");
        assert_eq!(real_respond_code(offer), code, "{what}: respond");
    }
}

#[test]
fn answers_are_refused_for_the_contracts_reason_and_the_golden_answer_is_accepted() {
    let n = &fixture().negotiation;
    let psk = fixture().hello_key;
    let body = n.answer_wire[..hello::BODY].to_vec();
    let resigned = |b: &[u8]| hello::resign(&psk, b);
    let other_stream = resigned(&edit(&body, 28, &(n.stream_id ^ 1).to_be_bytes()));
    let other_epoch = resigned(&edit(&body, 36, &(n.epoch + 1).to_be_bytes()));
    let reflected = resigned(&edit(&body, 20, &n.sender_peer.to_be_bytes()));
    let mut flipped = body.clone();
    flipped[68] ^= 1;
    let wrong_digest = resigned(&flipped);
    let wrong_selection = resigned(&edit(&body, 64, &[0, 0, 0, 1]));

    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("golden", n.answer_wire.clone(), "OK"),
        ("golden, re-signed", resigned(&body), "OK"),
        (
            "an Offer where an Answer belongs",
            n.offer_wire.clone(),
            "WRONG_HELLO_KIND",
        ),
        ("another stream", other_stream, "STREAM_MISMATCH"),
        ("another epoch", other_epoch, "EPOCH_MISMATCH"),
        ("the sender's own identity", reflected, "REFLECTED_HELLO"),
        (
            "another offer's digest",
            wrong_digest,
            "OFFER_DIGEST_MISMATCH",
        ),
        (
            "a selection the capabilities do not give",
            wrong_selection,
            "SELECTION_MISMATCH",
        ),
    ];
    for (what, answer, code) in &cases {
        assert_eq!(
            hello::check_finish(&raw_input(answer)),
            Ok(()),
            "{what}: oracle and finish disagree"
        );
        assert_eq!(real_finish_code(answer), *code, "{what}: finish");
    }
}

// ---- seeded smoke fuzz and the planted bug ------------------------------------------------------------------------

#[cfg(not(feature = "control"))]
#[test]
fn a_seeded_mutation_run_over_every_seed_violates_no_oracle() {
    let seeds = all();
    let mut rng = SplitMix64(0x4E30_3166);
    let mut failures = Vec::new();
    for round in 0..24_000u64 {
        let seed = &seeds[rng.below(seeds.len() as u64) as usize];
        let input = mutate(&mut rng, &seed.bytes);
        if let Err(why) = run(seed.target, &input) {
            failures.push(format!(
                "round {round}, seed {}/{}: {why}",
                seed.target, seed.name
            ));
            if failures.len() >= 5 {
                break;
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[cfg(not(feature = "control"))]
#[test]
fn arbitrary_bytes_violate_no_oracle_in_any_target() {
    let mut rng = SplitMix64(0x4E30_3167);
    for round in 0..8_000u64 {
        let len = rng.below(400) as usize;
        let input: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        for target in TARGETS {
            if let Err(why) = run(target, &input) {
                panic!("round {round}, target {target}, {len} bytes: {why}");
            }
        }
    }
}

/// A valid datagram for every payload length a packet can have, signed with the fixture key.
fn datagram_with_payload_len(len: usize) -> Vec<u8> {
    let golden = vector_wire("N01-GV-002");
    let mut body = golden[..wire::HEADER].to_vec();
    body = edit(&body, 60, &((len / 4) as u16).to_be_bytes());
    body = edit(&body, 62, &(len as u16).to_be_bytes());
    wire::resign(&fixture().wire_key, &body)
}

#[test]
fn a_datagram_of_every_valid_payload_length_is_accepted_by_the_decoder() {
    let mut accepted = 0;
    for len in (4..=wire::MAX_PAYLOAD).step_by(4) {
        let datagram = datagram_with_payload_len(len);
        assert_eq!(
            wire::expected_decode(&fixture().wire_key, &datagram),
            "OK",
            "{len}"
        );
        let decoded =
            AuthenticatedStreamPacket::decode_and_verify(&datagram, &key()).expect("accepted");
        assert_eq!(decoded.payload.len(), len);
        accepted += 1;
    }
    assert_eq!(accepted, 256);
}

#[cfg(not(feature = "control"))]
#[test]
fn the_clean_build_carries_no_plant_and_every_length_passes_every_oracle() {
    assert!(!plant::control_enabled());
    for len in (4..=wire::MAX_PAYLOAD).step_by(4) {
        let datagram = datagram_with_payload_len(len);
        assert_eq!(check_decode(&datagram), Ok(()), "{len}");
        plant::after_accept(len);
    }
}

#[cfg(feature = "control")]
#[test]
fn the_control_build_panics_for_exactly_the_planted_band_of_payload_lengths_and_no_other() {
    assert!(plant::control_enabled());
    let band: Vec<usize> = (plant::CONTROL_PAYLOAD_MIN..=plant::CONTROL_PAYLOAD_MAX)
        .step_by(4)
        .collect();
    assert_eq!(band.len(), 50);
    let mut fired = Vec::new();
    for len in (4..=wire::MAX_PAYLOAD).step_by(4) {
        let datagram = datagram_with_payload_len(len);
        let result = std::panic::catch_unwind(|| check_decode(&datagram));
        match result {
            Err(_) => fired.push(len),
            Ok(verdict) => assert_eq!(verdict, Ok(()), "{len}"),
        }
    }
    assert_eq!(fired, band);
}

#[test]
fn the_planted_band_is_no_seeds_and_no_bit_flip_or_small_step_from_one() {
    for edge in [plant::CONTROL_PAYLOAD_MIN, plant::CONTROL_PAYLOAD_MAX] {
        assert!(
            edge.is_multiple_of(4) && edge <= wire::MAX_PAYLOAD,
            "{edge}"
        );
        assert!(plant::in_band(edge), "{edge}");
    }
    assert!(!plant::in_band(plant::CONTROL_PAYLOAD_MIN - 4));
    assert!(!plant::in_band(plant::CONTROL_PAYLOAD_MAX + 4));

    // The frame counts the seeds accept: none is in the band.
    let mut frame_counts = BTreeSet::new();
    for seed in all().iter().filter(|s| s.target == STREAM_DECODE) {
        let datagram = wire::datagram_for(&fixture().wire_key, &seed.bytes);
        if let Ok(packet) = AuthenticatedStreamPacket::decode_and_verify(&datagram, &key()) {
            let len = packet.payload.len();
            assert!(!plant::in_band(len), "seed {} is in the band", seed.name);
            frame_counts.insert(len / 4);
        }
    }
    assert!(frame_counts.len() >= 4, "{frame_counts:?}");

    // One edit of a frame count (a flipped bit, a step of up to ten, a byte swap) from any of them stays out of it, so
    // the control is not found by the cheapest mutation a run makes.
    for &frames in &frame_counts {
        for bit in 0..16 {
            let flipped = frames ^ (1usize << bit);
            assert!(
                !plant::in_band(4 * flipped),
                "{frames} with bit {bit} flipped"
            );
        }
        for near in frames.saturating_sub(10)..=frames + 10 {
            assert!(!plant::in_band(4 * near), "{frames} stepped to {near}");
        }
        let swapped = u16::try_from(frames)
            .expect("a frame count fits in 16 bits")
            .swap_bytes();
        assert!(
            !plant::in_band(4 * usize::from(swapped)),
            "{frames} byte-swapped"
        );
    }
}

#[test]
fn the_json_helpers_read_what_the_vector_files_hold() {
    let doc: Value = parse_wire_vectors();
    assert_eq!(
        number(&doc["scenarios"][0], "stream_id"),
        fixture().receiver_stream
    );
    assert_eq!(
        number(&doc["scenarios"][0], "epoch"),
        fixture().receiver_epoch
    );
}
