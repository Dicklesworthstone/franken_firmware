//! The properties of `docs/contracts/u01.md` that do not need the shared vectors: failed and unknown-outcome storage
//! operations, namespace separation, versioned credentials and tombstones across restart and compaction, high-water
//! marks, bounds, write and wear limits, redaction, and that nothing revoked comes back.

mod common;

use common::{Step, enumerate_cuts, hex, state_hex, unhex};
use franken_journal::{
    Commit, Credential, Journal, JournalError, Limits, MemStorage, Namespace, Phase, Recovery,
    Source,
};

fn tiny() -> Limits {
    Limits::tiny()
}

fn fresh() -> MemStorage {
    MemStorage::new(tiny().segment_bytes)
}

fn reopen(media: &mut MemStorage) -> (Journal<&mut MemStorage>, Recovery) {
    media.restart();
    Journal::open(media, tiny()).expect("reopen")
}

/// Small distinct settings changes, one flush each, until the journal has compacted once more.
fn churn_until_compaction(j: &mut Journal<&mut MemStorage>, from_tick: u64) {
    let target = j.compactions() + 1;
    let mut n: u64 = 0;
    while j.compactions() < target {
        n += 1;
        j.stage_setting(b"vol", format!("{:02}", n % 100).as_bytes())
            .expect("stage");
        j.flush_settings(from_tick + 100 * n).expect("flush");
        assert!(n < 1000, "the journal never compacted");
    }
}

#[test]
fn a_failed_or_unknown_commit_poisons_the_journal_and_reopening_yields_exactly_old_or_new() {
    // baseline: the states before and after "revoke a", and the storage operations that step uses
    let prefix = [
        Step::Install(b"a".to_vec(), 1, b"s1".to_vec()),
        Step::Install(b"b".to_vec(), 1, b"sb".to_vec()),
    ];
    let revoke = Step::Revoke(b"a".to_vec());
    let mut base = fresh();
    let (before, after, start, end) = {
        let (mut j, _) = Journal::open(&mut base, tiny()).unwrap();
        for step in &prefix {
            common::apply(&mut j, step).unwrap();
        }
        let before = state_hex(&j);
        let start = j.storage().ops_done();
        common::apply(&mut j, &revoke).unwrap();
        (before, state_hex(&j), start, j.storage().ops_done())
    };
    assert!(end > start);
    for index in start..end {
        for mode in ["io", "sync_lost", "sync_kept"] {
            let mut media = fresh();
            // Assigned exactly once below; every other path out of the block continues or panics.
            let failed_phase;
            {
                let (mut j, _) = Journal::open(&mut media, tiny()).unwrap();
                for step in &prefix {
                    common::apply(&mut j, step).unwrap();
                }
                match mode {
                    "io" => j.storage_mut().fail_op_at = Some(index),
                    other => {
                        j.storage_mut().sync_fail_at = Some(index);
                        j.storage_mut().sync_fail_persists = other == "sync_kept";
                    }
                }
                match common::apply(&mut j, &revoke) {
                    Ok(_) => continue, // this index is not of the kind the mode injects
                    Err(JournalError::Storage(_)) => {}
                    Err(other) => panic!("unexpected error {}", other.code()),
                }
                assert!(
                    j.is_poisoned(),
                    "a failed storage operation must poison the journal"
                );
                assert_eq!(
                    state_hex(&j),
                    before,
                    "the published state changed although the commit failed"
                );
                assert_eq!(
                    j.install(b"c", 1, b"x").unwrap_err(),
                    JournalError::Poisoned
                );
                failed_phase = j.phase();
            }
            assert!(
                matches!(failed_phase, Phase::Staged | Phase::Written),
                "a failed commit reports the last step that completed, never Synced or Published"
            );
            let (j, _) = reopen(&mut media);
            let got = state_hex(&j);
            assert!(
                got == before || got == after,
                "{mode} at {index}: recovered neither old nor new"
            );
        }
    }
}

#[test]
fn a_revoked_identity_never_comes_back_across_cuts_inside_compactions() {
    let mut steps = vec![
        Step::Install(b"a".to_vec(), 1, b"s".to_vec()),
        Step::Revoke(b"a".to_vec()),
    ];
    for i in 0..40u64 {
        steps.push(Step::Stage(
            b"vol".to_vec(),
            format!("{:02}", i % 100).into_bytes(),
        ));
        steps.push(Step::Flush(100 * (i + 1)));
    }
    // once "revoke a" has returned, every state the oracle accepts has `a` revoked: it asserts old-or-new at each cut
    // (exactly "new" after a step finished), and the compactions in the churn must carry the tombstone forward
    let cuts = enumerate_cuts(&tiny(), &steps, false);
    assert!(cuts.cuts > 500);
    let cuts = enumerate_cuts(&tiny(), &steps, true);
    assert!(cuts.cuts > 500);
}

#[test]
fn the_three_resets_are_separate_operations() {
    let mut media = fresh();
    let (mut j, _) = Journal::open(&mut media, tiny()).unwrap();
    j.put(Namespace::Settings, b"vol", b"40").unwrap();
    j.put(Namespace::Calibration, b"board-a", b"cal").unwrap();
    j.put(Namespace::Records, b"voter", b"rec").unwrap();
    j.install(b"peer", 1, b"secret").unwrap();
    j.raise_mark(b"epoch", 9).unwrap();
    let snap = j.state().clone();

    j.reset_settings().unwrap();
    assert!(j.state().settings.is_empty());
    assert_eq!(j.state().calibration, snap.calibration);
    assert_eq!(j.state().credentials, snap.credentials);
    assert_eq!(j.state().records, snap.records);
    assert_eq!(j.state().marks, snap.marks);

    j.clear_calibration().unwrap();
    assert!(j.state().calibration.is_empty());
    assert_eq!(j.state().credentials, snap.credentials);
    assert_eq!(j.state().records, snap.records);

    j.put(Namespace::Settings, b"vol", b"41").unwrap();
    j.put(Namespace::Calibration, b"board-a", b"cal").unwrap();
    j.reset_pairing().unwrap();
    assert!(
        matches!(
            j.credential(b"peer"),
            Some(Credential::Revoked { version: 1 })
        ),
        "a pairing reset leaves a tombstone"
    );
    assert_eq!(
        j.state().settings.len(),
        1,
        "a pairing reset must not touch settings"
    );
    assert_eq!(
        j.state().calibration.len(),
        1,
        "a pairing reset must not touch calibration"
    );
    assert_eq!(j.state().records, snap.records);
    assert_eq!(j.state().marks, snap.marks);
}

#[test]
fn credentials_are_versioned_and_a_tombstone_survives_restart_and_compaction() {
    let mut media = fresh();
    {
        let (mut j, _) = Journal::open(&mut media, tiny()).unwrap();
        j.install(b"a", 1, b"s1").unwrap();
        assert_eq!(
            j.install(b"a", 1, b"other").unwrap_err(),
            JournalError::NotNewer { current: 1 }
        );
        j.install(b"a", 2, b"s2").unwrap();
        j.revoke(b"a").unwrap();
        assert_eq!(
            j.install(b"a", 2, b"s2").unwrap_err(),
            JournalError::Revoked { tombstone: 2 }
        );
        assert_eq!(j.revoke(b"a").unwrap_err(), JournalError::AlreadyRevoked);
        assert_eq!(j.revoke(b"zz").unwrap_err(), JournalError::NotFound);
    }
    for round in 0..2u64 {
        let (mut j, rec) = reopen(&mut media);
        assert_eq!(rec.source, Source::Segment);
        assert_eq!(
            j.install(b"a", 2, b"s2").unwrap_err(),
            JournalError::Revoked { tombstone: 2 }
        );
        churn_until_compaction(&mut j, 1_000_000 * (round + 1));
        assert_eq!(
            j.install(b"a", 1, b"s1").unwrap_err(),
            JournalError::Revoked { tombstone: 2 }
        );
    }
    let (mut j, _) = reopen(&mut media);
    j.install(b"a", 3, b"s3").unwrap(); // a strictly higher version re-admits it
    assert!(matches!(
        j.credential(b"a"),
        Some(Credential::Live { version: 3, .. })
    ));
    // a tombstone still occupies its identity slot: three slots, none can be recycled
    j.install(b"b", 1, b"sb").unwrap();
    j.install(b"c", 1, b"sc").unwrap();
    j.revoke(b"c").unwrap();
    assert_eq!(
        j.install(b"d", 1, b"sd").unwrap_err(),
        JournalError::NamespaceFull
    );
}

#[test]
fn a_mark_never_goes_down_and_an_unchanged_mark_writes_nothing() {
    let mut media = fresh();
    {
        let (mut j, _) = Journal::open(&mut media, tiny()).unwrap();
        j.raise_mark(b"epoch", 5).unwrap();
        assert_eq!(
            j.raise_mark(b"epoch", 4).unwrap_err(),
            JournalError::MarkRegressed { current: 5 }
        );
        let ops = j.storage().ops_done();
        assert_eq!(j.raise_mark(b"epoch", 5).unwrap(), Commit::Noop);
        assert_eq!(
            j.storage().ops_done(),
            ops,
            "an unchanged mark must write nothing"
        );
        j.raise_mark(b"epoch", 6).unwrap();
    }
    let (mut j, _) = reopen(&mut media);
    assert_eq!(j.state().marks[b"epoch".as_slice()], 6);
    assert_eq!(
        j.raise_mark(b"other", 1).unwrap_err(),
        JournalError::NamespaceFull
    );
}

#[test]
fn bounds_are_enforced_and_a_refused_operation_writes_nothing() {
    let mut media = fresh();
    let (mut j, _) = Journal::open(&mut media, tiny()).unwrap();
    assert_eq!(
        j.put(Namespace::Settings, b"", b"v").unwrap_err(),
        JournalError::InvalidKey
    );
    assert_eq!(
        j.put(Namespace::Settings, &[b'k'; 9], b"v").unwrap_err(),
        JournalError::InvalidKey
    );
    assert_eq!(
        j.put(Namespace::Settings, b"k", &[b'v'; 17]).unwrap_err(),
        JournalError::ValueTooLong
    );
    assert_eq!(
        j.put(Namespace::Credentials, b"k", b"v").unwrap_err(),
        JournalError::BadOp
    );
    assert_eq!(
        j.install(b"p", 0, b"s").unwrap_err(),
        JournalError::BadVersion
    );
    j.put(Namespace::Settings, b"a", b"1").unwrap();
    j.put(Namespace::Settings, b"b", b"2").unwrap();
    assert_eq!(
        j.put(Namespace::Settings, b"c", b"3").unwrap_err(),
        JournalError::NamespaceFull
    );
    assert_eq!(
        j.delete(Namespace::Settings, b"zz").unwrap_err(),
        JournalError::NotFound
    );
    let ops = j.storage().ops_done();
    let big: Vec<franken_journal::Op> = (0..6)
        .map(|_| franken_journal::Op::Put {
            ns: Namespace::Settings,
            key: b"a".to_vec(),
            value: vec![b'x'; 16],
        })
        .collect();
    assert_eq!(j.commit(&big).unwrap_err(), JournalError::TxnTooLarge);
    assert_eq!(
        j.storage().ops_done(),
        ops,
        "a refused operation must not touch the medium"
    );
    assert!(!j.is_poisoned());
    assert_eq!(
        j.put(Namespace::Settings, b"a", b"1").unwrap(),
        Commit::Noop,
        "an unchanged put writes nothing"
    );
    assert_eq!(j.storage().ops_done(), ops);
    // a configuration that cannot hold its own worst case is refused before any medium is touched
    let mut bad = tiny();
    bad.segment_bytes = 256;
    assert_eq!(bad.validate().unwrap_err(), JournalError::BadConfig);
    let mut other = MemStorage::new(256);
    assert_eq!(
        Journal::open(&mut other, bad).err(),
        Some(JournalError::BadConfig)
    );
    assert_eq!(other.ops_done(), 0);
}

#[test]
fn a_volume_storm_is_one_frame_and_the_wear_budget_is_a_hard_limit() {
    let mut media = fresh();
    {
        let (mut j, _) = Journal::open(&mut media, tiny()).unwrap();
        let base = j.storage().ops_done();
        for i in 0..500u32 {
            j.stage_setting(b"vol", format!("{:02}", i % 100).as_bytes())
                .unwrap();
        }
        assert_eq!(
            j.storage().ops_done(),
            base,
            "staging must not touch the medium"
        );
        assert_eq!(j.flush_settings(1000).unwrap(), Commit::Appended);
        let one_flush = j.storage().ops_done() - base;
        for tick in [1001u64, 1005, 1009] {
            j.stage_setting(b"vol", b"77").unwrap();
            assert_eq!(
                j.flush_settings(tick).unwrap_err(),
                JournalError::RateLimited {
                    retry_after: 1010 - tick
                }
            );
        }
        assert_eq!(
            j.storage().ops_done() - base,
            one_flush,
            "a rate-limited flush must write nothing"
        );
        assert_eq!(j.flush_settings(1010).unwrap(), Commit::Appended);
        assert_eq!(j.frames_written(), 2);
    }
    // wear: a budget of two generations allows exactly one compaction after the format
    let mut tight = tiny();
    tight.max_segment_gen = 2;
    let mut media = MemStorage::new(tight.segment_bytes);
    let (mut j, _) = Journal::open(&mut media, tight).unwrap();
    let mut refused = None;
    for i in 0..80u32 {
        let ops = j.storage().ops_done();
        match j.put(
            Namespace::Settings,
            b"a",
            format!("{:02}", i % 100).as_bytes(),
        ) {
            Ok(_) => {}
            Err(err) => {
                assert_eq!(err, JournalError::WearExhausted);
                assert_eq!(
                    j.storage().ops_done(),
                    ops,
                    "a refused compaction must not touch the medium"
                );
                assert!(!j.is_poisoned());
                refused = Some(i);
                break;
            }
        }
    }
    assert!(refused.is_some(), "the wear budget was never enforced");
    assert!(
        j.state().settings.contains_key(b"a".as_slice()),
        "reads still work"
    );
}

#[test]
fn errors_never_carry_a_key_or_a_value() {
    let mut media = fresh();
    let (mut j, _) = Journal::open(&mut media, tiny()).unwrap();
    j.install(b"peer", 1, b"TOPSECRETVAL").unwrap();
    let failures = [
        j.install(b"PEERSECRET", 1, b"s").unwrap_err(),
        j.install(b"p", 1, b"TOPSECRETVALUE_TOO_LONG").unwrap_err(),
        j.install(b"peer", 1, b"xxxxx").unwrap_err(),
        j.revoke(b"nobody").unwrap_err(),
        j.put(Namespace::Credentials, b"peer", b"zzzz").unwrap_err(),
        j.put(Namespace::Settings, b"PEERSECRET", b"v").unwrap_err(),
    ];
    for err in failures {
        let text = format!("{err} {err:?}");
        for needle in ["PEERSECRET", "TOPSECRET", "peer", "nobody", "xxxxx"] {
            assert!(
                !text.contains(needle),
                "an error carried a key or a value: {text}"
            );
        }
    }
}

#[test]
fn the_medium_is_never_programmed_over_a_dirty_byte() {
    // Rust-only property: whatever the scenario, no program ever needed to set a bit (the fake would have refused)
    let mut media = fresh();
    let (mut j, _) = Journal::open(&mut media, tiny()).unwrap();
    j.install(b"a", 1, b"s").unwrap();
    j.revoke(b"a").unwrap();
    churn_until_compaction(&mut j, 0);
    churn_until_compaction(&mut j, 5_000_000);
    assert!(!j.is_poisoned());
    assert!(j.compactions() >= 2);
}

#[test]
fn a_recovered_journal_is_immediately_usable_for_every_hostile_image() {
    let doc: serde_json::Value =
        serde_json::from_str(include_str!("vectors/u01_vectors.json")).unwrap();
    for case in doc["images"].as_array().unwrap() {
        if case["expect"].get("error").is_some() {
            continue;
        }
        let id = case["id"].as_str().unwrap();
        let mut media = MemStorage::from_image(
            tiny().segment_bytes,
            &unhex(case["image_hex"].as_str().unwrap()),
        );
        {
            let (mut j, _) = Journal::open(&mut media, tiny()).unwrap();
            j.put(Namespace::Settings, b"after", b"ok")
                .unwrap_or_else(|e| panic!("{id}: write after recovery: {}", e.code()));
        }
        let (j, rec) = reopen(&mut media);
        assert_eq!(
            j.state().settings[b"after".as_slice()],
            b"ok".to_vec(),
            "{id}: the write after recovery was lost"
        );
        if case["expect"].get("migrated_from").is_some() {
            assert_eq!(
                rec.migrated_from, None,
                "{id}: the medium is still in the old schema after migration"
            );
        }
    }
}

#[test]
fn a_failed_open_leaves_the_medium_for_the_next_attempt() {
    // power fails while formatting a blank medium at every operation: the next open still gets an empty, working journal
    for n in 0..8usize {
        let mut media = fresh();
        media.cut_after_ops = Some(n);
        let first = Journal::open(&mut media, tiny());
        if first.is_ok() {
            continue; // the cut was beyond the format
        }
        drop(first);
        media.restart();
        let (j, rec) = Journal::open(&mut media, tiny()).expect("formats again");
        assert!(matches!(rec.source, Source::Blank | Source::Unrecoverable));
        assert_eq!(
            hex(j.state().canonical_bytes().unwrap()),
            "0000",
            "an empty journal"
        );
    }
}
