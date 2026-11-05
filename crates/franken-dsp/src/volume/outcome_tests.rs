//! Tests for results by command id (`G02` / `ffw-ld0`, section 12: "Report terminal results by command ID so
//! clients can reconcile timeouts").
//!
//! What they show: a member reports the result a command produced when it was applied (not the state a replay
//! later finds), says honestly which revisions were never applied and which it can no longer tell, answers
//! consistently with what `apply` does for the same id, and changes nothing by being asked. The model test
//! recomputes every expected answer from the FULL applied log, a different formulation from the ring buffer and
//! floor the implementation keeps incrementally.
//!
//! What they do not show: any retry scheduler, timeout or acknowledgement (there is none), or that a UI uses the
//! answer sensibly. Existing pinned behaviour (an older replay is `stale_revision`) is asserted unchanged.

use super::*;

const EPOCH: u64 = 7;

fn stamp(epoch: u64, revision: u64) -> Stamp {
    Stamp { epoch, revision }
}

fn member() -> MemberVolume {
    let mut m = MemberVolume::new(1.0);
    m.declare_epoch(EPOCH).expect("declare");
    m.complete_join();
    m
}

fn apply(m: &mut MemberVolume, revision: u64, command: VolumeCommand) -> CommandReceipt {
    m.apply(stamp(EPOCH, revision), command).expect("accepted")
}

fn outcome(m: &MemberVolume, revision: u64) -> CommandOutcome {
    m.command_outcome(stamp(EPOCH, revision))
        .expect("same epoch")
}

/// Seeded and fixed, so a failure replays: SplitMix64.
struct SplitMix(u64);

impl SplitMix {
    fn draw(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

// ---- what a result is ---------------------------------------------------------------------------------------

#[test]
fn a_command_reports_the_receipt_it_produced_when_applied_not_the_state_a_replay_finds_later() {
    let mut m = member();
    let first = apply(&mut m, 1, VolumeCommand::SetVolume(50));
    assert!(!first.duplicate);
    assert_eq!(first.effective_mute, None);
    assert!((first.target_gain - 0.5).abs() < 1e-6, "{first:?}");

    // The room's own button mutes it afterwards. A replay of revision 1 is the pinned duplicate, and it
    // describes the state NOW (silent), exactly as before this feature.
    m.local_mute(true);
    let replay = m
        .apply(stamp(EPOCH, 1), VolumeCommand::SetVolume(50))
        .expect("duplicate");
    assert!(replay.duplicate);
    assert_eq!(replay.effective_mute, Some(MuteReason::Local));
    assert!(replay.target_gain.abs() < 1e-6);

    // The outcome of the command itself is what it produced when applied: audible at 0.5, not a duplicate.
    assert_eq!(
        outcome(&m, 1),
        CommandOutcome::Applied {
            command: VolumeCommand::SetVolume(50),
            receipt: first
        }
    );
}

#[test]
fn an_older_applied_command_keeps_its_result_while_apply_still_refuses_its_replay_as_stale() {
    let mut m = member();
    let r1 = apply(&mut m, 1, VolumeCommand::SetVolume(20));
    let r2 = apply(&mut m, 2, VolumeCommand::AdjustVolume(30));
    let r3 = apply(&mut m, 3, VolumeCommand::SetGroupMute(true));
    assert_eq!(r3.effective_mute, Some(MuteReason::Group));

    // Pinned, unchanged: an older replay is stale_revision.
    assert_eq!(
        m.apply(stamp(EPOCH, 1), VolumeCommand::SetVolume(20)),
        Err(VolumeError::StaleRevision {
            revision: 1,
            last: 3
        })
    );
    // New: the same id still reports what it did.
    for (revision, command, receipt) in [
        (1, VolumeCommand::SetVolume(20), r1),
        (2, VolumeCommand::AdjustVolume(30), r2),
        (3, VolumeCommand::SetGroupMute(true), r3),
    ] {
        assert_eq!(
            outcome(&m, revision),
            CommandOutcome::Applied { command, receipt },
            "revision {revision}"
        );
    }
    assert!((r1.target_gain - 0.2).abs() < 1e-6 && (r2.target_gain - 0.5).abs() < 1e-6);
    assert!(
        r3.target_gain.abs() < 1e-6,
        "group mute silences the target"
    );
}

#[test]
fn a_revision_nothing_carries_is_not_applied_if_newer_than_everything_and_skipped_if_a_newer_one_was_applied()
 {
    let mut m = member();
    apply(&mut m, 1, VolumeCommand::SetVolume(10));
    apply(&mut m, 4, VolumeCommand::SetVolume(40)); // 2 and 3 were lost or refused on the way

    assert!(matches!(outcome(&m, 1), CommandOutcome::Applied { .. }));
    assert_eq!(outcome(&m, 2), CommandOutcome::Skipped);
    assert_eq!(outcome(&m, 3), CommandOutcome::Skipped);
    assert!(matches!(outcome(&m, 4), CommandOutcome::Applied { .. }));
    assert_eq!(outcome(&m, 5), CommandOutcome::NotApplied);
    assert_eq!(outcome(&m, u64::MAX), CommandOutcome::NotApplied);
    assert_eq!(
        outcome(&m, 0),
        CommandOutcome::Skipped,
        "revisions start at 1: 0 can never be applied"
    );

    // The words mean what they say about apply:
    // Skipped -> a resend is refused as stale, NotApplied -> a valid resend is accepted.
    assert_eq!(
        m.apply(stamp(EPOCH, 2), VolumeCommand::SetVolume(1)),
        Err(VolumeError::StaleRevision {
            revision: 2,
            last: 4
        })
    );
    assert!(
        m.apply(stamp(EPOCH, 5), VolumeCommand::SetVolume(1))
            .is_ok()
    );
    assert!(matches!(
        outcome(&m, 5),
        CommandOutcome::Applied {
            command: VolumeCommand::SetVolume(1),
            ..
        }
    ));
}

#[test]
fn a_refused_command_is_not_recorded_and_consumes_no_revision() {
    let mut m = member();
    assert_eq!(
        m.apply(stamp(EPOCH, 1), VolumeCommand::SetVolume(101)),
        Err(VolumeError::VolumeOutOfRange { value: 101 })
    );
    assert_eq!(
        outcome(&m, 1),
        CommandOutcome::NotApplied,
        "the refusal left no trace"
    );
    assert_eq!(m.last_revision(), 0);

    // What a caller sees for a refused id AFTER THE FACT, case 1: nothing newer has been applied. The id reads
    // `NotApplied`, and resending the same command repeats the refusal, so the reason is recoverable by resending.
    assert_eq!(
        m.apply(stamp(EPOCH, 1), VolumeCommand::SetVolume(101)),
        Err(VolumeError::VolumeOutOfRange { value: 101 })
    );
    assert_eq!(outcome(&m, 1), CommandOutcome::NotApplied);

    // The same revision, corrected, is accepted and is then what the id reports.
    let ok = apply(&mut m, 1, VolumeCommand::SetVolume(10));
    assert_eq!(
        outcome(&m, 1),
        CommandOutcome::Applied {
            command: VolumeCommand::SetVolume(10),
            receipt: ok
        }
    );

    // Case 2: a NEWER command was applied after the refusal. The refused id now reads `Skipped`, exactly like a
    // lost one, and resending it is refused as stale, so the refusal REASON is no longer recoverable. This is the
    // limit of not retaining refusals; the caller still learns the fact that matters, that it took no effect.
    let mut later = member();
    assert_eq!(
        later.apply(stamp(EPOCH, 1), VolumeCommand::SetVolume(101)),
        Err(VolumeError::VolumeOutOfRange { value: 101 })
    );
    apply(&mut later, 2, VolumeCommand::SetVolume(10));
    assert_eq!(outcome(&later, 1), CommandOutcome::Skipped);
    assert_eq!(
        later.apply(stamp(EPOCH, 1), VolumeCommand::SetVolume(101)),
        Err(VolumeError::StaleRevision {
            revision: 1,
            last: 2
        })
    );
}

// ---- how far back ---------------------------------------------------------------------------------------------

#[test]
fn results_beyond_the_retention_window_are_forgotten_with_the_oldest_remembered_revision_stated() {
    let mut m = member();
    let last = RESULT_RETENTION as u64 + 8;
    for revision in 1..=last {
        apply(
            &mut m,
            revision,
            VolumeCommand::SetVolume((revision % 100) as u8),
        );
    }
    // The first 8 were overwritten; revisions 9 ..= 40 are remembered.
    let remembered_from = last - RESULT_RETENTION as u64 + 1;
    assert_eq!(remembered_from, 9);
    for revision in [1, 2, 8] {
        assert_eq!(
            outcome(&m, revision),
            CommandOutcome::Forgotten { remembered_from },
            "revision {revision}"
        );
    }
    for revision in [9, 10, 24, last] {
        assert!(
            matches!(outcome(&m, revision), CommandOutcome::Applied { .. }),
            "revision {revision}"
        );
    }
    assert_eq!(outcome(&m, last + 1), CommandOutcome::NotApplied);
}

#[test]
fn inside_the_window_a_gap_is_skipped_and_below_it_everything_is_forgotten() {
    let mut m = member();
    // Even revisions only: 2, 4, ..., 80. Forty commands; the oldest eight (2 ..= 16) are overwritten.
    for revision in (2..=80).step_by(2) {
        apply(
            &mut m,
            revision,
            VolumeCommand::SetVolume((revision % 100) as u8),
        );
    }
    assert_eq!(
        outcome(&m, 16),
        CommandOutcome::Forgotten {
            remembered_from: 17
        }
    );
    assert_eq!(
        outcome(&m, 15),
        CommandOutcome::Forgotten {
            remembered_from: 17
        }
    );
    assert_eq!(
        outcome(&m, 17),
        CommandOutcome::Skipped,
        "17 is in the window and was never applied"
    );
    assert!(matches!(outcome(&m, 18), CommandOutcome::Applied { .. }));
    assert_eq!(outcome(&m, 79), CommandOutcome::Skipped);
    assert!(matches!(outcome(&m, 80), CommandOutcome::Applied { .. }));
    assert_eq!(outcome(&m, 81), CommandOutcome::NotApplied);
}

// ---- authority --------------------------------------------------------------------------------------------------

#[test]
fn the_epoch_rules_are_those_of_apply_and_a_new_epoch_forgets_the_old_results() {
    let fresh = MemberVolume::new(1.0);
    assert_eq!(
        fresh.command_outcome(stamp(EPOCH, 1)),
        Err(VolumeError::NoAuthority)
    );

    let mut m = member();
    apply(&mut m, 1, VolumeCommand::SetVolume(30));
    assert!(m.command_outcome(stamp(EPOCH, 1)).is_ok());
    assert_eq!(
        m.command_outcome(stamp(EPOCH - 1, 1)),
        Err(VolumeError::StaleEpoch {
            command: EPOCH - 1,
            current: EPOCH
        })
    );
    assert_eq!(
        m.command_outcome(stamp(EPOCH + 1, 1)),
        Err(VolumeError::UndeclaredEpoch {
            command: EPOCH + 1,
            current: EPOCH
        })
    );

    // Declaring the same epoch again keeps the results; a newer epoch starts a new numbering.
    m.declare_epoch(EPOCH).expect("same epoch");
    assert!(matches!(outcome(&m, 1), CommandOutcome::Applied { .. }));
    m.declare_epoch(EPOCH + 1).expect("newer epoch");
    assert_eq!(
        m.command_outcome(stamp(EPOCH + 1, 1)),
        Ok(CommandOutcome::NotApplied)
    );
    assert_eq!(
        m.command_outcome(stamp(EPOCH, 1)),
        Err(VolumeError::StaleEpoch {
            command: EPOCH,
            current: EPOCH + 1
        })
    );
}

#[test]
fn a_member_that_joined_from_a_snapshot_cannot_report_the_revisions_the_snapshot_covers() {
    let mut m = member();
    apply(&mut m, 1, VolumeCommand::SetVolume(10));
    apply(&mut m, 2, VolumeCommand::SetVolume(20));
    m.reconnect(GroupSnapshot {
        epoch: EPOCH,
        revision: 10,
        master_volume: 40,
        group_mute: false,
    })
    .expect("reconnect");

    // Revisions 1 ..= 10 are inside the snapshot: it may have applied them, and this member cannot say.
    for revision in [1, 2, 3, 10] {
        assert_eq!(
            outcome(&m, revision),
            CommandOutcome::Forgotten {
                remembered_from: 11
            },
            "revision {revision}"
        );
    }
    assert_eq!(outcome(&m, 11), CommandOutcome::NotApplied);
    let after = apply(&mut m, 11, VolumeCommand::SetVolume(55));
    assert_eq!(
        outcome(&m, 11),
        CommandOutcome::Applied {
            command: VolumeCommand::SetVolume(55),
            receipt: after
        }
    );
    assert_eq!(
        outcome(&m, 10),
        CommandOutcome::Forgotten {
            remembered_from: 11
        }
    );
}

#[test]
fn asking_changes_nothing() {
    let mut m = member();
    for revision in 1..=40 {
        apply(&mut m, revision, VolumeCommand::AdjustVolume(1));
    }
    m.local_mute(true);
    let before = format!("{m:?}");
    for revision in [0, 1, 8, 9, 40, 41, u64::MAX] {
        let _ = m.command_outcome(stamp(EPOCH, revision));
    }
    let _ = m.command_outcome(stamp(EPOCH + 1, 1));
    let _ = m.command_outcome(stamp(EPOCH - 1, 1));
    assert_eq!(
        format!("{m:?}"),
        before,
        "a query must not change any state, including the retained results"
    );
}

// ---- the group -----------------------------------------------------------------------------------------------------

#[test]
fn a_group_reports_the_authority_and_each_member_and_an_absent_member_never_applied_it() {
    let mut group = GroupVolume::new(3);
    group.add_member(1, 1.0).expect("add 1");
    group.add_member(2, 1.0).expect("add 2");
    for id in [1, 2] {
        group.member_mut(id).expect("member").complete_join();
    }
    group
        .apply(stamp(3, 1), VolumeCommand::SetVolume(40))
        .expect("first");
    group.set_present(2, false).expect("member 2 leaves");
    group
        .apply(stamp(3, 2), VolumeCommand::SetVolume(60))
        .expect("second");

    let report = group.command_outcome(stamp(3, 2)).expect("same epoch");
    match report.authority {
        CommandOutcome::Applied { command, receipt } => {
            assert_eq!(command, VolumeCommand::SetVolume(60));
            assert!((receipt.target_gain - 0.6).abs() < 1e-6, "{receipt:?}");
        }
        other => panic!("the authority applied it, it reported {other:?}"),
    }
    let by_id = |report: &GroupOutcome, id: u32| {
        report
            .members
            .iter()
            .find(|m| m.id == id)
            .copied()
            .expect("member")
    };
    assert!(matches!(
        by_id(&report, 1).outcome,
        Ok(CommandOutcome::Applied {
            command: VolumeCommand::SetVolume(60),
            ..
        })
    ));
    assert!(by_id(&report, 1).present);
    // Member 2 was absent: it was sent nothing, and it has applied only revision 1.
    assert_eq!(by_id(&report, 2).outcome, Ok(CommandOutcome::NotApplied));
    assert!(!by_id(&report, 2).present);
    assert_eq!(
        report.members.iter().map(|m| m.id).collect::<Vec<_>>(),
        vec![1, 2],
        "in the order added"
    );

    // It comes back from a snapshot at revision 2: the snapshot covers revisions 1 and 2, so it can no longer say.
    group.rejoin(2).expect("rejoin");
    let after = group.command_outcome(stamp(3, 2)).expect("same epoch");
    assert_eq!(
        by_id(&after, 2).outcome,
        Ok(CommandOutcome::Forgotten { remembered_from: 3 })
    );
    assert!(by_id(&after, 2).present);
    assert!(
        matches!(by_id(&after, 1).outcome, Ok(CommandOutcome::Applied { .. })),
        "the others are unaffected"
    );
    assert!(matches!(after.authority, CommandOutcome::Applied { .. }));

    assert_eq!(
        group.command_outcome(stamp(2, 1)).err(),
        Some(VolumeError::StaleEpoch {
            command: 2,
            current: 3
        })
    );
}

#[test]
fn a_member_added_late_cannot_report_what_happened_before_it_joined() {
    let mut group = GroupVolume::new(1);
    group.add_member(1, 1.0).expect("add");
    group
        .apply(stamp(1, 1), VolumeCommand::SetVolume(30))
        .expect("applied");
    group
        .apply(stamp(1, 2), VolumeCommand::SetVolume(35))
        .expect("applied");
    group.add_member(2, 1.0).expect("late member");

    let report = group.command_outcome(stamp(1, 2)).expect("same epoch");
    let late = report
        .members
        .iter()
        .find(|m| m.id == 2)
        .copied()
        .expect("member 2");
    assert_eq!(
        late.outcome,
        Ok(CommandOutcome::Forgotten { remembered_from: 3 })
    );
    assert!(matches!(report.authority, CommandOutcome::Applied { .. }));
}

// ---- against a model ---------------------------------------------------------------------------------------------

/// The expected answer computed from the FULL applied log, not from a ring: the retained results are the last
/// `RESULT_RETENTION` entries, the floor is the larger of the reset floor and one above the newest evicted entry.
struct Model {
    log: Vec<(u64, VolumeCommand, CommandReceipt)>,
    base_floor: u64,
    last_revision: u64,
}

impl Model {
    fn new() -> Self {
        Self {
            log: Vec::new(),
            base_floor: 1,
            last_revision: 0,
        }
    }

    fn reset(&mut self, floor: u64, last_revision: u64) {
        self.log.clear();
        self.base_floor = floor;
        self.last_revision = last_revision;
    }

    /// True when the oldest results were overwritten, so the floor sits above where the last reset put it.
    fn eviction_raised_floor(&self) -> bool {
        self.log.len() > RESULT_RETENTION
            && self.log[self.log.len() - RESULT_RETENTION - 1].0 + 1 > self.base_floor
    }

    fn expected(&self, revision: u64) -> CommandOutcome {
        let kept = self.log.len().min(RESULT_RETENTION);
        let retained = &self.log[self.log.len() - kept..];
        if let Some((_, command, receipt)) = retained.iter().find(|(r, _, _)| *r == revision) {
            return CommandOutcome::Applied {
                command: *command,
                receipt: *receipt,
            };
        }
        let floor = if self.log.len() > RESULT_RETENTION {
            self.base_floor
                .max(self.log[self.log.len() - RESULT_RETENTION - 1].0 + 1)
        } else {
            self.base_floor
        };
        if revision > self.last_revision {
            CommandOutcome::NotApplied
        } else if revision == 0 || revision >= floor {
            CommandOutcome::Skipped
        } else {
            CommandOutcome::Forgotten {
                remembered_from: floor,
            }
        }
    }
}

#[test]
fn the_answers_match_a_model_over_the_full_log_through_gaps_refusals_snapshots_and_new_epochs() {
    let mut rng = SplitMix(0x00_6702_17E5);
    // How often each answer was given to a question, so the schedule provably reaches every branch.
    let mut asked = [0u32; 4]; // applied, not applied, skipped, forgotten
    let (mut forgotten_by_eviction, mut skipped_in_evicted_window) = (0u32, 0u32);
    for seed in 0..6u64 {
        let mut epoch = 10 + seed;
        let mut m = MemberVolume::new(1.0);
        m.declare_epoch(epoch).expect("declare");
        m.complete_join();
        let mut model = Model::new();
        for step in 0..20_000u32 {
            let context = format!("seed {seed} step {step}");
            match rng.draw() % 10 {
                // an accepted command, usually the next revision, sometimes after a gap
                0..=4 => {
                    let gap = if rng.draw().is_multiple_of(4) {
                        rng.draw() % 3
                    } else {
                        0
                    };
                    let revision = model.last_revision + 1 + gap;
                    let command = match rng.draw() % 3 {
                        0 => VolumeCommand::SetVolume((rng.draw() % 101) as u8),
                        1 => VolumeCommand::AdjustVolume((rng.draw() % 21) as i16 - 10),
                        _ => VolumeCommand::SetGroupMute(rng.draw().is_multiple_of(2)),
                    };
                    let receipt = m
                        .apply(stamp(epoch, revision), command)
                        .unwrap_or_else(|e| panic!("{context}: {e:?}"));
                    model.log.push((revision, command, receipt));
                    model.last_revision = revision;
                }
                // a refused command: out of range, so nothing is recorded and no revision is consumed
                5 => {
                    let result = m.apply(
                        stamp(epoch, model.last_revision + 1),
                        VolumeCommand::SetVolume(101),
                    );
                    assert_eq!(
                        result,
                        Err(VolumeError::VolumeOutOfRange { value: 101 }),
                        "{context}"
                    );
                }
                // a snapshot at a later revision (a rejoin) resets what can be said
                6 => {
                    if rng.draw().is_multiple_of(8) {
                        let revision = model.last_revision + rng.draw() % 50;
                        m.reconnect(GroupSnapshot {
                            epoch,
                            revision,
                            master_volume: (rng.draw() % 101) as u8,
                            group_mute: false,
                        })
                        .expect("reconnect");
                        model.reset(revision + 1, revision);
                        m.complete_join();
                    }
                }
                // a newer epoch starts a new numbering
                7 => {
                    if rng.draw().is_multiple_of(40) {
                        epoch += 1;
                        m.declare_epoch(epoch).expect("newer epoch");
                        model.reset(1, 0);
                    }
                }
                // ask about a random id, and check the words against what apply does with the same id
                _ => {
                    let revision = rng.draw() % (model.last_revision + 4);
                    let expected = model.expected(revision);
                    let got = m
                        .command_outcome(stamp(epoch, revision))
                        .expect("same epoch");
                    assert_eq!(got, expected, "{context}: revision {revision}");
                    let evicted = model.eviction_raised_floor();
                    match got {
                        CommandOutcome::Applied { .. } => asked[0] += 1,
                        CommandOutcome::NotApplied => asked[1] += 1,
                        CommandOutcome::Skipped => {
                            asked[2] += 1;
                            skipped_in_evicted_window += u32::from(evicted);
                        }
                        CommandOutcome::Forgotten { .. } => {
                            asked[3] += 1;
                            forgotten_by_eviction += u32::from(evicted);
                        }
                    }
                    let mut probe = m.clone();
                    let attempt = probe.apply(stamp(epoch, revision), VolumeCommand::SetVolume(1));
                    match got {
                        CommandOutcome::NotApplied => assert!(
                            attempt.is_ok(),
                            "{context}: a NotApplied id must accept a valid resend: {attempt:?}"
                        ),
                        CommandOutcome::Skipped | CommandOutcome::Forgotten { .. } => assert_eq!(
                            attempt,
                            Err(VolumeError::StaleRevision {
                                revision,
                                last: model.last_revision
                            }),
                            "{context}: a Skipped or Forgotten id must be refused as stale"
                        ),
                        CommandOutcome::Applied { command, .. } => {
                            if revision < model.last_revision {
                                assert_eq!(
                                    attempt,
                                    Err(VolumeError::StaleRevision {
                                        revision,
                                        last: model.last_revision
                                    }),
                                    "{context}: an older applied id is still refused as stale"
                                );
                            } else if command == VolumeCommand::SetVolume(1) {
                                assert!(
                                    matches!(attempt, Ok(r) if r.duplicate),
                                    "{context}: the last id replayed is a duplicate: {attempt:?}"
                                );
                            } else {
                                assert_eq!(
                                    attempt,
                                    Err(VolumeError::RevisionConflict { revision }),
                                    "{context}: the last id with another payload conflicts"
                                );
                            }
                        }
                    }
                }
            }
            // The invariants after every step, whatever the step was.
            let probe_revision = model.last_revision;
            assert_eq!(
                m.command_outcome(stamp(epoch, probe_revision)),
                Ok(model.expected(probe_revision)),
                "{context}: the last revision"
            );
        }
    }
    // Floors at about a third of what the schedule produces (applied 3533, not applied 835, skipped 1130,
    // forgotten 18416, forgotten by eviction 6979, skipped inside an evicted window 383 in the Python mirror).
    let [applied, not_applied, skipped, forgotten] = asked;
    assert!(
        applied >= 1000 && not_applied >= 250 && skipped >= 300 && forgotten >= 5000,
        "the schedule stopped reaching every answer: {asked:?}"
    );
    assert!(
        forgotten_by_eviction >= 2000 && skipped_in_evicted_window >= 100,
        "the schedule stopped reaching the eviction path: {forgotten_by_eviction} {skipped_in_evicted_window}"
    );
}
