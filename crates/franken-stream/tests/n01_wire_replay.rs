//! The N01 golden-vector replay, run by the central host (`ffw-ey5`, contract section 7).
//!
//! The replay itself is `src/bin/n01_wire_guest/replay.rs`, the same file the guest binary compiles, so what a
//! big-endian guest will run is exactly what runs here. On this host it can only show the replay agrees with the
//! vectors on THIS machine's byte order; `tests/n01/guest_transcript.py` judges a log from a big-endian guest.
//! Every expectation below is written by hand or comes from the vector files, not from the code under test.

#[path = "../src/bin/n01_wire_guest/replay.rs"]
mod replay;

use replay::{NEGOTIATION_JSON, Transcript, WIRE_JSON, fnv1a64, transcript, transcript_of};
use serde_json::{Value, json};

fn committed() -> Transcript {
    transcript().expect("the committed vectors parse")
}

fn lines_of<'a>(t: &'a Transcript, tag: &str) -> Vec<&'a str> {
    let prefix = format!("{tag} ");
    t.lines
        .iter()
        .filter(|line| line.starts_with(&prefix))
        .map(String::as_str)
        .collect()
}

fn pair<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    line.split_whitespace()
        .find_map(|token| token.strip_prefix(prefix.as_str()))
}

/// The verdict printed for the planted datagram called `name`.
fn plant_verdict<'a>(plants: &[&'a str], name: &str) -> Option<&'a str> {
    let line = plants
        .iter()
        .find(|line| line.split_whitespace().nth(1) == Some(name))?;
    pair(line, "verdict")
}

#[test]
fn the_fingerprint_function_matches_the_published_fnv_1a_test_vectors() {
    assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
    assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
    assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
}

#[test]
fn the_committed_vectors_replay_with_no_mismatch_and_the_shape_the_judge_requires() {
    let t = committed();
    assert_eq!(t.mismatches, 0, "{:#?}", lines_of(&t, "N01-MISMATCH"));
    // Floors, so the replay cannot quietly shrink with the vector file.
    assert!(lines_of(&t, "N01-WIRE").len() >= 37);
    assert!(lines_of(&t, "N01-SCEN").len() >= 2);
    assert!(lines_of(&t, "N01-NEG").len() >= 4);
    assert!(lines_of(&t, "N01-NEGREJ").len() >= 31);
    assert_eq!(lines_of(&t, "N01-PLANT").len(), 5);
    let done = lines_of(&t, "N01-DONE");
    assert_eq!(done.len(), 1);
    assert_eq!(t.lines.last().map(String::as_str), Some(done[0]));
    assert_eq!(pair(done[0], "mismatches"), Some("0"));
    assert_eq!(
        pair(done[0], "wire").map(str::to_string),
        Some(lines_of(&t, "N01-WIRE").len().to_string())
    );
}

#[test]
fn every_accepted_vector_decodes_to_the_references_fields_and_re_encodes_to_the_same_bytes() {
    let t = committed();
    let accepted: Vec<&str> = lines_of(&t, "N01-WIRE")
        .into_iter()
        .filter(|line| pair(line, "verdict") == Some("ACCEPT"))
        .collect();
    assert!(accepted.len() >= 7, "{} accepted vectors", accepted.len());
    for line in accepted {
        assert_eq!(pair(line, "fields"), Some("ok"), "{line}");
        assert_eq!(pair(line, "reencode"), Some("ok"), "{line}");
    }
    // The rejected ones carry no decoded fields to compare.
    for line in lines_of(&t, "N01-WIRE") {
        if pair(line, "verdict") != Some("ACCEPT") {
            assert_eq!(pair(line, "fields"), Some("na"), "{line}");
            assert_eq!(pair(line, "reencode"), Some("na"), "{line}");
        }
    }
}

#[test]
fn the_planted_rejections_are_refused_and_the_permitted_positives_are_accepted() {
    let t = committed();
    let plants = lines_of(&t, "N01-PLANT");
    // Hand-written from the contract, not read back from the code.
    assert_eq!(plant_verdict(&plants, "untouched"), Some("ACCEPT"));
    assert_eq!(plant_verdict(&plants, "resigned_untouched"), Some("ACCEPT"));
    assert_eq!(
        plant_verdict(&plants, "payload_bit_flipped"),
        Some("AUTH_FAILED")
    );
    assert_eq!(
        plant_verdict(&plants, "tag_bit_flipped"),
        Some("AUTH_FAILED")
    );
    // Authentic, with its frame count written little-endian (01 00 became 00 01): only the structure can refuse it.
    assert_eq!(
        plant_verdict(&plants, "frame_count_little_endian_resigned"),
        Some("FRAME_COUNT_MISMATCH")
    );
}

#[test]
fn the_byte_order_probe_describes_the_machine_that_ran_it() {
    let t = committed();
    let guest = lines_of(&t, "N01-GUEST");
    assert_eq!(guest.len(), 1);
    let line = guest[0];
    // The two renderings are fixed by the value 0x0102030405060708 and say nothing about this machine.
    assert_eq!(pair(line, "probe_be"), Some("0102030405060708"));
    assert_eq!(pair(line, "probe_le"), Some("0807060504030201"));
    let (endian, native) = if cfg!(target_endian = "big") {
        ("big", "0102030405060708")
    } else {
        ("little", "0807060504030201")
    };
    assert_eq!(pair(line, "endian"), Some(endian));
    assert_eq!(pair(line, "probe_native"), Some(native));
    assert_eq!(
        pair(line, "pointer_bits").map(str::to_string),
        Some(usize::BITS.to_string())
    );
}

#[test]
fn a_replay_handed_a_corrupted_expectation_reports_a_mismatch_and_would_exit_non_zero() {
    // A rejected vector claimed to be accepted.
    let mut wire: Value = serde_json::from_str(WIRE_JSON).expect("parses");
    let index = wire["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .position(|v| v["expect"] != "ACCEPT")
        .expect("a rejected vector");
    let id = wire["vectors"][index]["id"]
        .as_str()
        .expect("id")
        .to_string();
    wire["vectors"][index]["expect"] = json!("ACCEPT");
    let t = transcript_of(&wire.to_string(), NEGOTIATION_JSON).expect("still parses");
    assert!(t.mismatches >= 1);
    assert!(
        lines_of(&t, "N01-MISMATCH")
            .iter()
            .any(|line| line.contains(&id)),
        "{:?}",
        lines_of(&t, "N01-MISMATCH")
    );
    assert_eq!(
        pair(lines_of(&t, "N01-DONE")[0], "mismatches").map(str::to_string),
        Some(t.mismatches.to_string())
    );

    // An accepted vector whose recorded fields are wrong.
    let mut wire: Value = serde_json::from_str(WIRE_JSON).expect("parses");
    let accepted = wire["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .position(|v| v["expect"] == "ACCEPT")
        .expect("an accepted vector");
    let seq = wire["vectors"][accepted]["fields"]["seq"]
        .as_u64()
        .expect("seq");
    wire["vectors"][accepted]["fields"]["seq"] = json!(seq + 1);
    let t = transcript_of(&wire.to_string(), NEGOTIATION_JSON).expect("still parses");
    assert!(
        lines_of(&t, "N01-WIRE")
            .iter()
            .any(|line| pair(line, "fields") == Some("differ")),
        "a wrong field was not seen"
    );
    assert!(t.mismatches >= 1);

    // A negotiation whose recorded transcript digest is wrong.
    let mut negotiation: Value = serde_json::from_str(NEGOTIATION_JSON).expect("parses");
    negotiation["negotiations"][0]["transcript_hex"] = json!("00".repeat(32));
    let t = transcript_of(WIRE_JSON, &negotiation.to_string()).expect("still parses");
    assert!(
        lines_of(&t, "N01-NEG")
            .iter()
            .any(|line| pair(line, "transcript") == Some("differ")),
        "a wrong digest was not seen"
    );
    assert!(t.mismatches >= 1);

    // Paired positive: the untouched documents are clean.
    assert_eq!(committed().mismatches, 0);
}

#[test]
fn a_document_that_cannot_be_read_produces_no_done_line() {
    assert!(transcript_of("{", NEGOTIATION_JSON).is_err());
    assert!(transcript_of(WIRE_JSON, "[]").is_err());
}
