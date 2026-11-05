//! Replays the shared vectors written by `tests/u01/make_vectors.py`. The Python reference and this crate are two
//! implementations of `docs/contracts/u01.md`: they must produce the same media bytes after each scenario, the same media
//! after every power cut, and the same result for every hostile image.

mod common;

use common::{enumerate_cuts, hex, parse_steps, run_script, sha256_hex, unhex};
use franken_journal::{Journal, Limits, MemStorage, Source};
use serde_json::Value;

const VECTORS: &str = include_str!("vectors/u01_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors parse")
}

fn tiny_json_matches(lim: &Limits, doc: &Value) {
    assert_eq!(
        doc["segment_bytes"].as_u64(),
        Some(lim.segment_bytes as u64)
    );
    assert_eq!(
        doc["max_txn_payload"].as_u64(),
        Some(lim.max_txn_payload as u64)
    );
    assert_eq!(
        doc["min_flush_interval_ticks"].as_u64(),
        Some(lim.min_flush_interval_ticks)
    );
    assert_eq!(
        doc["max_segment_gen"].as_u64(),
        Some(u64::from(lim.max_segment_gen))
    );
    assert_eq!(
        doc["worst_snapshot_payload"].as_u64(),
        Some(lim.worst_snapshot_payload() as u64)
    );
    for (id, l) in [
        ("1", &lim.settings),
        ("2", &lim.credentials),
        ("3", &lim.calibration),
        ("4", &lim.records),
        ("5", &lim.marks),
    ] {
        let want = [l.key_max as u64, l.value_max as u64, l.entries as u64];
        let got: Vec<u64> = doc["namespaces"][id]
            .as_array()
            .expect("namespace limits")
            .iter()
            .map(|v| v.as_u64().expect("limit"))
            .collect();
        assert_eq!(got, want, "namespace {id}");
    }
}

#[test]
fn the_limits_and_the_format_constants_are_the_ones_the_reference_used() {
    let doc = vectors();
    tiny_json_matches(&Limits::tiny(), &doc["limits"]["tiny"]);
    tiny_json_matches(&Limits::standard(), &doc["limits"]["standard"]);
    Limits::tiny()
        .validate()
        .expect("tiny limits fit their segment");
    Limits::standard()
        .validate()
        .expect("standard limits fit their segment");
    let f = &doc["format"];
    assert_eq!(
        f["frame_magic"].as_u64(),
        Some(u64::from(franken_journal::codec::FRAME_MAGIC))
    );
    assert_eq!(
        f["segment_header"].as_u64(),
        Some(franken_journal::codec::SEG_HEADER as u64)
    );
    assert_eq!(
        f["frame_header"].as_u64(),
        Some(franken_journal::codec::FRAME_HEADER as u64)
    );
    assert_eq!(
        f["version"].as_u64(),
        Some(u64::from(franken_journal::codec::FORMAT_VERSION))
    );
    assert_eq!(
        f["legacy_version"].as_u64(),
        Some(u64::from(franken_journal::codec::LEGACY_VERSION))
    );
}

#[test]
fn every_scripted_scenario_produces_the_references_states_outcomes_and_media_bytes() {
    let doc = vectors();
    let lim = Limits::tiny();
    for script in doc["scripts"].as_array().expect("scripts") {
        let id = script["id"].as_str().expect("id");
        let steps = parse_steps(&script["steps"]);
        let mut media = MemStorage::new(lim.segment_bytes);
        let run = run_script(&lim, &steps, &mut media).expect("the script runs");
        let want_outcomes: Vec<&str> = script["outcomes"]
            .as_array()
            .expect("outcomes")
            .iter()
            .map(|v| v.as_str().expect("outcome"))
            .collect();
        assert_eq!(run.outcomes, want_outcomes, "{id}: outcomes");
        let want_states: Vec<&str> = script["states_hex"]
            .as_array()
            .expect("states")
            .iter()
            .map(|v| v.as_str().expect("state"))
            .collect();
        assert_eq!(run.states, want_states, "{id}: states after every step");
        assert_eq!(
            sha256_hex(media.durable()),
            script["final_media_sha256"].as_str().expect("digest"),
            "{id}: final media bytes"
        );
        assert_eq!(
            run.frames_written,
            script["frames_written"].as_u64().expect("frames"),
            "{id}: frames"
        );
        assert_eq!(
            run.compactions,
            script["compactions"].as_u64().expect("compactions"),
            "{id}: compactions"
        );
        assert_eq!(
            run.bytes_programmed,
            script["bytes_programmed"].as_u64().expect("bytes"),
            "{id}: bytes programmed"
        );
        assert_eq!(
            media.ops_done() as u64,
            script["storage_ops"].as_u64().expect("ops"),
            "{id}: storage operations"
        );
    }
}

#[test]
fn power_cut_at_every_point_gives_the_same_media_as_the_reference_and_recovers_old_or_new() {
    let doc = vectors();
    let lim = Limits::tiny();
    for script in doc["scripts"].as_array().expect("scripts") {
        let id = script["id"].as_str().expect("id");
        let steps = parse_steps(&script["steps"]);
        for (key, reverse) in [("cuts_forward", false), ("cuts_reverse", true)] {
            let got = enumerate_cuts(&lim, &steps, reverse);
            let want = &script[key];
            assert_eq!(
                got.cuts as u64,
                want["cuts"].as_u64().expect("cuts"),
                "{id} {key}: number of cuts"
            );
            assert_eq!(
                got.old as u64,
                want["old"].as_u64().expect("old"),
                "{id} {key}: cuts recovering the old state"
            );
            assert_eq!(
                got.new as u64,
                want["new"].as_u64().expect("new"),
                "{id} {key}: cuts recovering the new state"
            );
            assert_eq!(
                got.total_ops as u64,
                want["total_ops"].as_u64().expect("ops"),
                "{id} {key}: storage operations"
            );
            assert_eq!(
                got.digest,
                want["digest"].as_str().expect("digest"),
                "{id} {key}: digest of the media after every cut"
            );
        }
    }
}

#[test]
fn every_hostile_image_opens_as_the_reference_says_and_leaves_the_same_bytes_behind() {
    let doc = vectors();
    let lim = Limits::tiny();
    for case in doc["images"].as_array().expect("images") {
        let id = case["id"].as_str().expect("id");
        let image = unhex(case["image_hex"].as_str().expect("image"));
        let mut media = MemStorage::from_image(lim.segment_bytes, &image);
        let expect = &case["expect"];
        {
            let opened = Journal::open(&mut media, lim.clone());
            if let Some(code) = expect.get("error").and_then(Value::as_str) {
                assert_eq!(
                    opened.err().map(|e| e.code()),
                    Some(code_static(code)),
                    "{id}: error"
                );
            } else {
                let (journal, rec) =
                    opened.unwrap_or_else(|e| panic!("{id}: open failed with {}", e.code()));
                assert_eq!(
                    hex(journal.state().canonical_bytes().expect("canonical state")),
                    expect["state_hex"].as_str().expect("state"),
                    "{id}: recovered state"
                );
                if let Some(source) = expect.get("source").and_then(Value::as_str) {
                    let got = match rec.source {
                        Source::Blank => "blank",
                        Source::Unrecoverable => "unrecoverable",
                        Source::Segment => "segment",
                    };
                    assert_eq!(got, source, "{id}: source");
                }
                if let Some(want) = expect.get("tail_dirty").and_then(Value::as_bool) {
                    assert_eq!(rec.tail_dirty, want, "{id}: tail_dirty");
                }
                if let Some(want) = expect.get("compacted").and_then(Value::as_bool) {
                    assert_eq!(rec.compacted, want, "{id}: compacted");
                }
                if let Some(want) = expect.get("retired_stale").and_then(Value::as_bool) {
                    assert_eq!(rec.retired_stale, want, "{id}: retired_stale");
                }
                if let Some(want) = expect.get("migrated_from").and_then(Value::as_u64) {
                    assert_eq!(
                        rec.migrated_from,
                        Some(u8::try_from(want).expect("version")),
                        "{id}: migrated_from"
                    );
                }
                if let Some(want) = expect.get("gen").and_then(Value::as_u64) {
                    assert_eq!(u64::from(rec.generation), want, "{id}: generation");
                }
            }
        }
        assert_eq!(
            sha256_hex(media.durable()),
            case["media_after_sha256"].as_str().expect("digest"),
            "{id}: the medium after open (repair writes included)"
        );
    }
}

/// The error codes the vectors use, as `'static` names to compare with `JournalError::code`.
fn code_static(code: &str) -> &'static str {
    match code {
        "unsupported_version" => "unsupported_version",
        "malformed" => "malformed",
        other => panic!("unexpected error code in the vectors: {other}"),
    }
}
