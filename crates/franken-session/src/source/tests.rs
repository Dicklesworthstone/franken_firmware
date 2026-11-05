//! Tests for source ownership arbitration (`G01`, contract section 10).
//!
//! Every expectation is derived by hand from the contract; none was copied from running this code. The
//! independent Python reference in `tests/g01/source_reference.py` states the same scenarios and runs the
//! same seeded schedule, which is where the floors below come from.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

type Fingerprint = (Option<u64>, SourceEpoch, Option<SourceId>);

/// The six named sources of the scenarios.
fn sid(name: &str) -> SourceId {
    let (kind, label) = match name {
        "s" => (SourceKind::Spotify, "spotify-a"),
        "s2" => (SourceKind::Spotify, "spotify-b"),
        "a" => (SourceKind::AirPlay2, "airplay-a"),
        "b" => (SourceKind::AirPlay2, "airplay-b"),
        "l" => (SourceKind::LineIn, "linein-a"),
        "l2" => (SourceKind::LineIn, "linein-b"),
        other => panic!("unknown test source {other}"),
    };
    SourceId::new(kind, label).unwrap()
}

fn fingerprint(arbiter: &SourceArbiter) -> Fingerprint {
    (arbiter.bound, arbiter.epoch, arbiter.owner.clone())
}

fn token_variant(session: &UnifiedGroupSession, kind: &str) -> AuthorityToken {
    let mut token = AuthorityToken::issue(session, u64::MAX);
    match kind {
        "stale" => token.epoch -= 1,
        "future" => token.epoch += 1,
        "expired" => token.expires_at_ns = 1_000,
        "wrong_group" => token.group_id = "other".to_string(),
        "wrong_issuer" => token.issuer_id = "impostor".to_string(),
        other => panic!("unknown token variant {other}"),
    }
    token
}

struct Rig {
    session: UnifiedGroupSession,
    token: AuthorityToken,
    arbiter: SourceArbiter,
}

impl Rig {
    fn new() -> Self {
        Self::around(SourceArbiter::new(SourceConfig::default()))
    }

    fn with(config: SourceConfig) -> Self {
        Self::around(SourceArbiter::new(config))
    }

    fn around(arbiter: SourceArbiter) -> Self {
        let session = UnifiedGroupSession::new("grp", "coord", 1);
        let token = AuthorityToken::issue(&session, u64::MAX);
        Self {
            session,
            token,
            arbiter,
        }
    }

    /// Submit under `token`. A refused call must leave the arbiter exactly as it was.
    fn command_with(
        &mut self,
        token: &AuthorityToken,
        class: CommandClass,
        who: &str,
        at: u64,
    ) -> Result<Admitted, SourceError> {
        let command = SourceCommand {
            source: sid(who),
            class,
            expected_epoch: SourceEpoch::new(at),
        };
        let before = fingerprint(&self.arbiter);
        let result = self.arbiter.submit(&self.session, token, 5_000, &command);
        if result.is_err() {
            assert_eq!(
                fingerprint(&self.arbiter),
                before,
                "a refused {class} changed the arbiter"
            );
        }
        result
    }

    fn cmd(&mut self, class: CommandClass, who: &str, at: u64) -> Result<Admitted, SourceError> {
        let token = self.token.clone();
        self.command_with(&token, class, who, at)
    }

    fn start(&mut self, who: &str, at: u64) -> Result<Admitted, SourceError> {
        self.cmd(CommandClass::Start, who, at)
    }

    fn seek(&mut self, who: &str, at: u64) -> Result<Admitted, SourceError> {
        self.cmd(CommandClass::Seek, who, at)
    }

    fn stop(&mut self, who: &str, at: u64) -> Result<Admitted, SourceError> {
        self.cmd(CommandClass::Stop, who, at)
    }

    fn publish(&self, who: &str, at: u64) -> Result<(), SourceError> {
        self.arbiter
            .check_publish(&self.session, &sid(who), SourceEpoch::new(at))
    }

    fn advance_group(&mut self, to: u64) {
        self.session.begin_epoch(to);
        self.token = AuthorityToken::issue(&self.session, u64::MAX);
    }

    fn expect_view(&self, group: u64, epoch: u64, owner: Option<&str>) {
        assert_eq!(
            self.arbiter.view(&self.session),
            SourceView {
                group_epoch: group,
                epoch: SourceEpoch::new(epoch),
                owner: owner.map(sid),
            }
        );
    }
}

fn admitted(
    result: Result<Admitted, SourceError>,
    epoch: u64,
    owner: Option<&str>,
    replaced: Option<&str>,
    minted: bool,
) {
    let got = result.unwrap_or_else(|e| panic!("expected an admission, got {}: {e}", e.code()));
    assert_eq!(got.epoch, SourceEpoch::new(epoch), "epoch after");
    assert_eq!(got.owner, owner.map(sid), "owner after");
    assert_eq!(got.replaced, replaced.map(sid), "displaced source");
    assert_eq!(got.minted, minted, "minted a new stream");
}

fn refused<T: Debug>(result: Result<T, SourceError>, code: &str) {
    match result {
        Ok(value) => panic!("expected {code}, but it was admitted: {value:?}"),
        Err(error) => assert_eq!(error.code(), code, "{error}"),
    }
}

// ----------------------------------------------------------------------------- paired positives

#[test]
fn an_uncontested_start_plays_and_a_same_source_seek_is_applied() {
    let mut rig = Rig::new();
    rig.expect_view(1, 0, None);
    admitted(rig.start("s", 0), 1, Some("s"), None, true);
    rig.expect_view(1, 1, Some("s"));
    rig.publish("s", 1).unwrap();
    admitted(rig.seek("s", 1), 1, Some("s"), None, false);
    rig.publish("s", 1).unwrap();
    rig.expect_view(1, 1, Some("s"));
}

// ------------------------------------------------------------------ a replaced source cannot publish

#[test]
fn a_replaced_source_cannot_publish_and_the_refusal_names_the_cause() {
    let mut rig = Rig::new();
    admitted(rig.start("s", 0), 1, Some("s"), None, true);
    admitted(rig.start("a", 1), 2, Some("a"), Some("s"), true);
    refused(rig.publish("s", 1), "SOURCE_REPLACED");
    refused(rig.publish("s", 2), "NOT_SOURCE_OWNER");
    rig.publish("a", 2).unwrap();
    refused(rig.publish("a", 1), "SOURCE_EPOCH_STALE");
    let error = rig.publish("s", 1).unwrap_err();
    assert_eq!(
        error,
        SourceError::SourceReplaced {
            sender: sid("s"),
            epoch: 1,
            current: 2,
        }
    );
    assert_eq!(
        error.to_string(),
        "spotify:spotify-a was replaced: its epoch 1 is behind the current 2"
    );
}

fn offer(rig: &Rig, sink: &mut Vec<(&'static str, u64)>, who: &'static str, epoch: u64) {
    if rig.publish(who, epoch).is_ok() {
        sink.push((who, epoch));
    }
}

#[test]
fn output_receives_only_blocks_the_gate_admitted() {
    let mut rig = Rig::new();
    let mut sink = Vec::new();
    admitted(rig.start("s", 0), 1, Some("s"), None, true);
    offer(&rig, &mut sink, "s", 1);
    offer(&rig, &mut sink, "s", 1);
    admitted(rig.start("a", 1), 2, Some("a"), Some("s"), true);
    offer(&rig, &mut sink, "s", 1); // the replaced source's next publish
    offer(&rig, &mut sink, "a", 2);
    offer(&rig, &mut sink, "s", 1);
    offer(&rig, &mut sink, "s", 2); // claiming the new owner's epoch does not help
    assert_eq!(sink, vec![("s", 1), ("s", 1), ("a", 2)]);
}

#[test]
fn the_owner_starting_again_begins_a_new_stream_and_its_old_blocks_are_stale() {
    let mut rig = Rig::new();
    admitted(rig.start("s", 0), 1, Some("s"), None, true);
    admitted(rig.start("s", 1), 2, Some("s"), None, true);
    refused(rig.publish("s", 1), "SOURCE_EPOCH_STALE");
    rig.publish("s", 2).unwrap();
}

#[test]
fn stop_ends_the_stream_and_fences_its_late_blocks() {
    let mut rig = Rig::new();
    admitted(rig.start("s", 0), 1, Some("s"), None, true);
    admitted(rig.stop("s", 1), 2, None, None, true);
    refused(rig.publish("s", 1), "NO_ACTIVE_SOURCE");
    refused(rig.publish("s", 2), "NO_ACTIVE_SOURCE");
    refused(rig.seek("s", 2), "NO_ACTIVE_SOURCE");
    refused(
        rig.cmd(CommandClass::GroupChange, "a", 2),
        "NO_ACTIVE_SOURCE",
    );
    refused(rig.stop("a", 2), "NO_ACTIVE_SOURCE");
    admitted(rig.start("a", 2), 3, Some("a"), None, true);
}

// ------------------------------------------------------------------------ one source epoch per view

#[test]
fn two_starts_that_saw_the_same_epoch_admit_exactly_one() {
    let mut rig = Rig::new();
    admitted(rig.start("s", 0), 1, Some("s"), None, true);
    refused(rig.start("a", 0), "SOURCE_EPOCH_STALE");
    rig.expect_view(1, 1, Some("s"));
    rig.publish("s", 1).unwrap();
    refused(rig.publish("a", 1), "NOT_SOURCE_OWNER");
    // The loser learns the current epoch from the refusal and can retry deliberately.
    let error = rig.start("a", 0).unwrap_err();
    assert_eq!(
        error,
        SourceError::SourceEpochStale {
            expected: 0,
            current: 1,
        }
    );
}

#[test]
fn whichever_of_three_racing_starts_arrives_first_on_an_idle_group_wins() {
    let orders = [
        ["s", "a", "l"],
        ["s", "l", "a"],
        ["a", "s", "l"],
        ["a", "l", "s"],
        ["l", "s", "a"],
        ["l", "a", "s"],
    ];
    for order in orders {
        let mut rig = Rig::new();
        admitted(rig.start(order[0], 0), 1, Some(order[0]), None, true);
        refused(rig.start(order[1], 0), "SOURCE_EPOCH_STALE");
        refused(rig.start(order[2], 0), "SOURCE_EPOCH_STALE");
        rig.expect_view(1, 1, Some(order[0]));
    }
}

#[test]
fn racing_for_an_owned_group_the_first_admissible_command_wins() {
    let mut rig = Rig::new();
    admitted(rig.start("b", 0), 1, Some("b"), None, true);
    // All four saw epoch 1. The line-in start is rejected by policy, which does not use the epoch up.
    refused(rig.start("l", 1), "SOURCE_REJECTED");
    admitted(rig.start("s", 1), 2, Some("s"), Some("b"), true);
    refused(rig.start("a", 1), "SOURCE_EPOCH_STALE");
    refused(rig.seek("b", 1), "SOURCE_EPOCH_STALE");
    rig.expect_view(1, 2, Some("s"));
}

#[test]
fn a_seek_from_the_losing_epoch_is_not_applied() {
    let mut rig = Rig::new();
    admitted(rig.start("s", 0), 1, Some("s"), None, true);
    admitted(rig.start("a", 1), 2, Some("a"), Some("s"), true);
    refused(rig.seek("s", 1), "SOURCE_EPOCH_STALE");
    refused(rig.seek("s", 2), "SOURCE_REJECTED");
    admitted(rig.seek("a", 2), 2, Some("a"), None, false);
    rig.expect_view(1, 2, Some("a"));
}

#[test]
fn a_seek_and_a_start_that_race_are_ordered_by_arrival() {
    // The seek first: it is applied, and the start (which saw the same epoch) then takes the group.
    let mut first = Rig::new();
    admitted(first.start("s", 0), 1, Some("s"), None, true);
    admitted(first.seek("s", 1), 1, Some("s"), None, false);
    admitted(first.start("a", 1), 2, Some("a"), Some("s"), true);
    // The start first: the seek then comes from the losing epoch and is not applied.
    let mut second = Rig::new();
    admitted(second.start("s", 0), 1, Some("s"), None, true);
    admitted(second.start("a", 1), 2, Some("a"), Some("s"), true);
    refused(second.seek("s", 1), "SOURCE_EPOCH_STALE");
}

#[test]
fn an_epoch_from_the_future_is_refused() {
    let mut rig = Rig::new();
    admitted(rig.start("s", 0), 1, Some("s"), None, true);
    refused(rig.seek("s", 5), "SOURCE_EPOCH_FUTURE");
    refused(rig.start("a", 7), "SOURCE_EPOCH_FUTURE");
    refused(rig.publish("s", 3), "SOURCE_EPOCH_FUTURE");
    rig.expect_view(1, 1, Some("s"));
}

// ---------------------------------------------------------------------------------------- policy

/// The table written out by hand from section 10.1, independently of `SourcePolicyTable::STANDARD`.
const EXPECTED_CELLS: [(SourceKind, CommandClass, SourcePolicy); 12] = [
    (
        SourceKind::Spotify,
        CommandClass::Start,
        SourcePolicy::Replace,
    ),
    (
        SourceKind::Spotify,
        CommandClass::Seek,
        SourcePolicy::Reject,
    ),
    (
        SourceKind::Spotify,
        CommandClass::GroupChange,
        SourcePolicy::Reject,
    ),
    (
        SourceKind::Spotify,
        CommandClass::Stop,
        SourcePolicy::Reject,
    ),
    (
        SourceKind::AirPlay2,
        CommandClass::Start,
        SourcePolicy::Replace,
    ),
    (
        SourceKind::AirPlay2,
        CommandClass::Seek,
        SourcePolicy::Reject,
    ),
    (
        SourceKind::AirPlay2,
        CommandClass::GroupChange,
        SourcePolicy::Replace,
    ),
    (
        SourceKind::AirPlay2,
        CommandClass::Stop,
        SourcePolicy::Reject,
    ),
    (
        SourceKind::LineIn,
        CommandClass::Start,
        SourcePolicy::Reject,
    ),
    (SourceKind::LineIn, CommandClass::Seek, SourcePolicy::Reject),
    (
        SourceKind::LineIn,
        CommandClass::GroupChange,
        SourcePolicy::Reject,
    ),
    (SourceKind::LineIn, CommandClass::Stop, SourcePolicy::Reject),
];

fn expected_cell(kind: SourceKind, class: CommandClass) -> SourcePolicy {
    EXPECTED_CELLS
        .iter()
        .find(|(k, c, _)| *k == kind && *c == class)
        .map(|(_, _, policy)| *policy)
        .unwrap_or_else(|| panic!("no expectation for {kind:?} {class:?}"))
}

#[test]
fn the_policy_table_is_written_out_cell_by_cell() {
    assert_eq!(
        EXPECTED_CELLS.len(),
        SourceKind::ALL.len() * CommandClass::ALL.len()
    );
    for kind in SourceKind::ALL {
        for class in CommandClass::ALL {
            assert_eq!(
                SourcePolicyTable::STANDARD.get(kind, class),
                expected_cell(kind, class),
                "{kind:?} {class:?}"
            );
        }
    }
    assert_eq!(SourcePolicyTable::default(), SourcePolicyTable::STANDARD);
}

#[test]
fn changing_one_cell_changes_only_that_cell() {
    for changed_kind in SourceKind::ALL {
        for changed_class in CommandClass::ALL {
            let flipped = match SourcePolicyTable::STANDARD.get(changed_kind, changed_class) {
                SourcePolicy::Replace => SourcePolicy::Reject,
                SourcePolicy::Reject => SourcePolicy::Replace,
            };
            let table = SourcePolicyTable::STANDARD.with(changed_kind, changed_class, flipped);
            for kind in SourceKind::ALL {
                for class in CommandClass::ALL {
                    let want = if kind == changed_kind && class == changed_class {
                        flipped
                    } else {
                        expected_cell(kind, class)
                    };
                    assert_eq!(table.get(kind, class), want, "{kind:?} {class:?}");
                }
            }
        }
    }
}

#[test]
fn every_cell_decides_a_non_owners_command_as_the_table_says() {
    let incumbents = [("b", SourceKind::AirPlay2), ("l2", SourceKind::LineIn)];
    let requesters = [
        ("s", SourceKind::Spotify),
        ("a", SourceKind::AirPlay2),
        ("l", SourceKind::LineIn),
    ];
    for (incumbent, _) in incumbents {
        for (requester, kind) in requesters {
            for class in CommandClass::ALL {
                let mut rig = Rig::new();
                admitted(rig.start(incumbent, 0), 1, Some(incumbent), None, true);
                match expected_cell(kind, class) {
                    SourcePolicy::Reject => {
                        refused(rig.cmd(class, requester, 1), "SOURCE_REJECTED");
                        rig.expect_view(1, 1, Some(incumbent));
                        rig.publish(incumbent, 1).unwrap();
                    }
                    SourcePolicy::Replace => {
                        let after = if class == CommandClass::Stop {
                            None
                        } else {
                            Some(requester)
                        };
                        admitted(
                            rig.cmd(class, requester, 1),
                            2,
                            after,
                            Some(incumbent),
                            true,
                        );
                        rig.expect_view(1, 2, after);
                        match after {
                            Some(owner) => {
                                refused(rig.publish(incumbent, 1), "SOURCE_REPLACED");
                                rig.publish(owner, 2).unwrap();
                            }
                            None => {
                                // Nobody owns the group after a replacing stop.
                                refused(rig.publish(incumbent, 1), "NO_ACTIVE_SOURCE");
                                refused(rig.publish(requester, 2), "NO_ACTIVE_SOURCE");
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn a_line_in_start_does_not_take_a_group_but_an_idle_group_accepts_it() {
    let mut rig = Rig::new();
    admitted(rig.start("l", 0), 1, Some("l"), None, true);
    refused(rig.start("l2", 1), "SOURCE_REJECTED");
    admitted(rig.stop("l", 1), 2, None, None, true);
    admitted(rig.start("l2", 2), 3, Some("l2"), None, true);
}

#[test]
fn replacement_by_group_change_is_an_airplay_privilege() {
    let mut rig = Rig::new();
    admitted(rig.start("s", 0), 1, Some("s"), None, true);
    refused(
        rig.cmd(CommandClass::GroupChange, "s2", 1),
        "SOURCE_REJECTED",
    );
    admitted(
        rig.cmd(CommandClass::GroupChange, "a", 1),
        2,
        Some("a"),
        Some("s"),
        true,
    );
    admitted(
        rig.cmd(CommandClass::GroupChange, "a", 2),
        2,
        Some("a"),
        None,
        false,
    );
    refused(rig.publish("s", 1), "SOURCE_REPLACED");
}

#[test]
fn a_cell_set_to_replace_follows_the_same_rule_for_a_seek_and_for_a_stop() {
    let policy = SourcePolicyTable::STANDARD
        .with(
            SourceKind::AirPlay2,
            CommandClass::Seek,
            SourcePolicy::Replace,
        )
        .with(
            SourceKind::AirPlay2,
            CommandClass::Stop,
            SourcePolicy::Replace,
        );
    let config = SourceConfig {
        policy,
        ..SourceConfig::default()
    };
    let mut seeking = Rig::with(config);
    admitted(seeking.start("s", 0), 1, Some("s"), None, true);
    admitted(seeking.seek("a", 1), 2, Some("a"), Some("s"), true);
    refused(seeking.publish("s", 1), "SOURCE_REPLACED");
    let mut stopping = Rig::with(config);
    admitted(stopping.start("s", 0), 1, Some("s"), None, true);
    admitted(stopping.stop("a", 1), 2, None, Some("s"), true);
    refused(stopping.publish("s", 1), "NO_ACTIVE_SOURCE");
    stopping.expect_view(1, 2, None);
}

// ------------------------------------------------------------------------------- authority and epochs

#[test]
fn authority_is_judged_before_anything_about_the_source() {
    let mut rig = Rig::new();
    admitted(rig.start("s", 0), 1, Some("s"), None, true);
    // Every command below also presents a stale source epoch; the authority error is the one reported.
    let cases = [
        ("stale", "STALE_AUTHORITY"),
        ("future", "FUTURE_AUTHORITY"),
        ("expired", "AUTHORITY_EXPIRED"),
        ("wrong_group", "WRONG_GROUP"),
        ("wrong_issuer", "NOT_CONFIGURED_ISSUER"),
    ];
    for (kind, code) in cases {
        let token = token_variant(&rig.session, kind);
        refused(rig.command_with(&token, CommandClass::Start, "a", 0), code);
    }
    rig.expect_view(1, 1, Some("s"));
}

#[test]
fn the_clock_uncertainty_margin_makes_the_holder_stop_early() {
    let config = SourceConfig {
        clock_uncertainty_ns: 100,
        ..SourceConfig::default()
    };
    let mut rig = Rig::with(config);
    // The token ends at 5_050 ns and the calls are made at 5_000 ns: 5_000 + 100 >= 5_050.
    let mut token = rig.token.clone();
    token.expires_at_ns = 5_050;
    refused(
        rig.command_with(&token, CommandClass::Start, "s", 0),
        "AUTHORITY_EXPIRED",
    );
    let mut without_margin = Rig::new();
    let mut same_token = without_margin.token.clone();
    same_token.expires_at_ns = 5_050;
    admitted(
        without_margin.command_with(&same_token, CommandClass::Start, "s", 0),
        1,
        Some("s"),
        None,
        true,
    );
}

#[test]
fn a_group_epoch_advance_voids_the_program_until_a_source_starts_again() {
    let mut rig = Rig::new();
    admitted(rig.start("s", 0), 1, Some("s"), None, true);
    rig.advance_group(2);
    refused(rig.publish("s", 1), "GROUP_EPOCH_ADVANCED");
    // One epoch number was spent on the transition, and nobody owns the group.
    rig.expect_view(2, 2, None);
    refused(rig.seek("s", 1), "SOURCE_EPOCH_STALE");
    refused(rig.seek("s", 2), "NO_ACTIVE_SOURCE");
    refused(rig.start("s", 1), "SOURCE_EPOCH_STALE");
    admitted(rig.start("s", 2), 3, Some("s"), None, true);
    rig.publish("s", 3).unwrap();
    refused(rig.publish("s", 1), "SOURCE_EPOCH_STALE");
    rig.expect_view(2, 3, Some("s"));
}

#[test]
fn a_refusal_after_a_group_epoch_advance_does_not_bind_the_arbiter() {
    let mut rig = Rig::new();
    admitted(rig.start("l", 0), 1, Some("l"), None, true);
    rig.advance_group(2);
    refused(rig.start("s", 9), "SOURCE_EPOCH_FUTURE");
    refused(rig.seek("s", 0), "SOURCE_EPOCH_STALE");
    rig.expect_view(2, 2, None);
    // Still bound to group epoch 1: the old owner's block is refused for that reason.
    refused(rig.publish("l", 1), "GROUP_EPOCH_ADVANCED");
    admitted(rig.start("s", 2), 3, Some("s"), None, true);
    rig.expect_view(2, 3, Some("s"));
}

#[test]
fn resuming_above_a_durable_floor_never_reuses_an_old_epoch() {
    let mut rig = Rig::around(SourceArbiter::resume_after(
        SourceConfig::default(),
        SourceEpoch::new(7),
    ));
    rig.expect_view(1, 8, None);
    refused(rig.start("s", 7), "SOURCE_EPOCH_STALE");
    admitted(rig.start("s", 8), 9, Some("s"), None, true);
}

#[test]
fn an_exhausted_epoch_counter_refuses_to_mint() {
    let mut rig = Rig::around(SourceArbiter::resume_after(
        SourceConfig::default(),
        SourceEpoch::new(u64::MAX),
    ));
    rig.expect_view(1, u64::MAX, None);
    refused(rig.start("s", u64::MAX), "SOURCE_EPOCH_EXHAUSTED");
    rig.expect_view(1, u64::MAX, None);
}

// ------------------------------------------------------------------------------- labels and errors

#[test]
fn labels_are_validated_and_a_refusal_reports_the_length_only() {
    for bad in ["", "Phone", "a@b", "has space"] {
        assert_eq!(
            SourceId::new(SourceKind::Spotify, bad).unwrap_err().code(),
            "INVALID_SOURCE_LABEL",
            "{bad:?}"
        );
    }
    let too_long = "x".repeat(MAX_SOURCE_LABEL_BYTES + 1);
    assert_eq!(
        SourceId::new(SourceKind::Spotify, &too_long).unwrap_err(),
        SourceError::InvalidSourceLabel { len: 65 }
    );
    assert!(SourceId::new(SourceKind::AirPlay2, &"x".repeat(MAX_SOURCE_LABEL_BYTES)).is_ok());
    assert!(SourceId::new(SourceKind::LineIn, "a").is_ok());
    assert!(SourceId::new(SourceKind::LineIn, "a.b_c-d:9").is_ok());
    let error = SourceId::new(SourceKind::Spotify, "Pasted-Token!").unwrap_err();
    assert_eq!(error, SourceError::InvalidSourceLabel { len: 13 });
    assert!(!error.to_string().contains("Pasted"));
    assert_eq!(MAX_SOURCE_LABEL_BYTES, 64);
}

#[test]
fn refusal_codes_are_the_stable_names_and_the_texts_carry_identifiers_only() {
    let cases: [(SourceError, &str); 10] = [
        (
            SourceError::Authority(MembershipError::WrongGroup),
            "WRONG_GROUP",
        ),
        (
            SourceError::InvalidSourceLabel { len: 0 },
            "INVALID_SOURCE_LABEL",
        ),
        (
            SourceError::SourceEpochStale {
                expected: 1,
                current: 2,
            },
            "SOURCE_EPOCH_STALE",
        ),
        (
            SourceError::SourceEpochFuture {
                expected: 3,
                current: 2,
            },
            "SOURCE_EPOCH_FUTURE",
        ),
        (SourceError::SourceEpochExhausted, "SOURCE_EPOCH_EXHAUSTED"),
        (
            SourceError::SourceRejected {
                class: CommandClass::Seek,
                requester: sid("l"),
                owner: sid("s"),
            },
            "SOURCE_REJECTED",
        ),
        (SourceError::NoActiveSource, "NO_ACTIVE_SOURCE"),
        (
            SourceError::SourceReplaced {
                sender: sid("s"),
                epoch: 1,
                current: 2,
            },
            "SOURCE_REPLACED",
        ),
        (
            SourceError::NotSourceOwner {
                sender: sid("a"),
                owner: sid("s"),
            },
            "NOT_SOURCE_OWNER",
        ),
        (
            SourceError::GroupEpochAdvanced {
                arbiter_group_epoch: 1,
                group_epoch: 2,
            },
            "GROUP_EPOCH_ADVANCED",
        ),
    ];
    for (error, code) in &cases {
        assert_eq!(error.code(), *code);
    }
    assert_eq!(
        SourceError::Authority(MembershipError::WrongGroup).to_string(),
        MembershipError::WrongGroup.to_string()
    );
    let rejected = SourceError::SourceRejected {
        class: CommandClass::Start,
        requester: sid("l"),
        owner: sid("s"),
    };
    assert_eq!(
        rejected.to_string(),
        "line-in:linein-a may not start while spotify:spotify-a owns the group"
    );
    assert_eq!(
        SourceError::GroupEpochAdvanced {
            arbiter_group_epoch: 1,
            group_epoch: 2,
        }
        .to_string(),
        "the group epoch advanced from 1 to 2; the old program is void until a source starts again"
    );
}

// -------------------------------------------------------------------------- the seeded interleavings

struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }

    fn pick(&mut self, bound: u64) -> usize {
        usize::try_from(self.below(bound)).expect("a small index")
    }
}

/// What the schedule driver needs of an arbiter, so a transcription of the engine with a planted defect
/// can be driven exactly like the real one.
trait Judge {
    fn judge(
        &mut self,
        session: &UnifiedGroupSession,
        token: &AuthorityToken,
        now_ns: u64,
        command: &SourceCommand,
    ) -> Result<Admitted, SourceError>;

    fn gate(
        &self,
        session: &UnifiedGroupSession,
        source: &SourceId,
        epoch: SourceEpoch,
    ) -> Result<(), SourceError>;

    fn look(&self, session: &UnifiedGroupSession) -> SourceView;

    fn state(&self) -> Fingerprint;
}

impl Judge for SourceArbiter {
    fn judge(
        &mut self,
        session: &UnifiedGroupSession,
        token: &AuthorityToken,
        now_ns: u64,
        command: &SourceCommand,
    ) -> Result<Admitted, SourceError> {
        self.submit(session, token, now_ns, command)
    }

    fn gate(
        &self,
        session: &UnifiedGroupSession,
        source: &SourceId,
        epoch: SourceEpoch,
    ) -> Result<(), SourceError> {
        self.check_publish(session, source, epoch)
    }

    fn look(&self, session: &UnifiedGroupSession) -> SourceView {
        self.view(session)
    }

    fn state(&self) -> Fingerprint {
        fingerprint(self)
    }
}

#[derive(Default)]
struct Report {
    counts: BTreeMap<&'static str, u64>,
    violations: Vec<String>,
    trace: Vec<String>,
}

/// The four sources of the schedule, in draw order.
const SCHEDULE_SOURCES: [&str; 4] = ["s", "a", "b", "l"];

struct Driver<'a, J: Judge> {
    seed: u64,
    arbiter: &'a mut J,
    session: UnifiedGroupSession,
    token: AuthorityToken,
    rng: SplitMix64,
    sources: Vec<SourceId>,
    /// The epoch each source was last told, and the epoch under which it believes it owns the group.
    known: [u64; 4],
    granted: [Option<u64>; 4],
    /// The epoch of the stream a source owned before its latest grant (its late blocks).
    previous: [Option<u64>; 4],
    now: u64,
    minted_epochs: BTreeSet<u64>,
    /// After a group epoch advance only a Start can be admitted, until one has been.
    void: bool,
    report: Report,
}

impl<J: Judge> Driver<'_, J> {
    fn check(&mut self, ok: bool, text: String) {
        if !ok {
            self.report
                .violations
                .push(format!("seed {}: {text}", self.seed));
        }
    }

    fn bump(&mut self, key: &'static str) {
        *self.report.counts.entry(key).or_insert(0) += 1;
    }

    fn learn(&mut self, index: usize, receipt: &Admitted) {
        let new =
            (receipt.owner.as_ref() == Some(&self.sources[index])).then(|| receipt.epoch.get());
        if let Some(old) = self.granted[index]
            && new != Some(old)
        {
            self.previous[index] = Some(old);
        }
        self.known[index] = receipt.epoch.get();
        self.granted[index] = new;
    }

    /// Submit and judge by the receipt and the view taken just before. `None` when it was refused.
    fn command(
        &mut self,
        index: usize,
        class: CommandClass,
        expected: u64,
        stale_token: Option<AuthorityToken>,
    ) -> Option<Admitted> {
        let source = self.sources[index].clone();
        let before_view = self.arbiter.look(&self.session);
        let before_state = self.arbiter.state();
        let command = SourceCommand {
            source: source.clone(),
            class,
            expected_epoch: SourceEpoch::new(expected),
        };
        let result = {
            let token = stale_token.as_ref().unwrap_or(&self.token);
            self.arbiter.judge(&self.session, token, self.now, &command)
        };
        self.report.trace.push(format!("{result:?}"));
        let before_epoch = before_view.epoch.get();
        let receipt = match result {
            Ok(receipt) => receipt,
            Err(error) => {
                let unchanged = self.arbiter.state() == before_state;
                self.check(
                    unchanged,
                    format!("a refused {class} changed the arbiter ({})", error.code()),
                );
                let code = error.code();
                if stale_token.is_some() {
                    let is_authority = matches!(error, SourceError::Authority(_));
                    self.check(
                        is_authority,
                        format!("a token that is not current was refused as {code}"),
                    );
                } else if expected < before_epoch {
                    self.check(
                        code == "SOURCE_EPOCH_STALE",
                        format!(
                            "{class} at epoch {expected} < {before_epoch} was refused as {code}"
                        ),
                    );
                } else if expected > before_epoch {
                    self.check(
                        code == "SOURCE_EPOCH_FUTURE",
                        format!(
                            "{class} at epoch {expected} > {before_epoch} was refused as {code}"
                        ),
                    );
                } else {
                    let fine = matches!(
                        code,
                        "SOURCE_REJECTED" | "NO_ACTIVE_SOURCE" | "SOURCE_EPOCH_EXHAUSTED"
                    );
                    self.check(
                        fine,
                        format!("{class} at the current epoch was refused as {code}"),
                    );
                }
                match error {
                    SourceError::Authority(_) => self.bump("authority_refused"),
                    SourceError::SourceEpochStale { current, .. } => {
                        self.bump("stale_refused");
                        self.known[index] = current;
                    }
                    SourceError::SourceEpochFuture { .. } => self.bump("future_refused"),
                    SourceError::SourceRejected { .. } => self.bump("policy_refused"),
                    SourceError::NoActiveSource => self.bump("no_source_refused"),
                    _ => {}
                }
                return None;
            }
        };
        self.check(
            stale_token.is_none(),
            "a command under a token that is not current was admitted".to_string(),
        );
        self.check(
            class == CommandClass::Start || !self.void,
            format!("a {class} was admitted after a group epoch advance with no new Start"),
        );
        self.check(
            class != CommandClass::Start || receipt.minted,
            "a Start did not begin a new stream".to_string(),
        );
        self.check(
            class != CommandClass::Stop || (receipt.minted && receipt.owner.is_none()),
            "a Stop did not end the stream".to_string(),
        );
        self.check(
            expected == before_epoch,
            format!(
                "{class} admitted at epoch {expected} while the current one was {before_epoch}"
            ),
        );
        if receipt.minted {
            self.check(
                receipt.epoch.get() == before_epoch + 1,
                format!("minted epoch {} after {before_epoch}", receipt.epoch.get()),
            );
            let fresh = self.minted_epochs.insert(receipt.epoch.get());
            self.check(fresh, format!("epoch {} minted twice", receipt.epoch.get()));
        } else {
            self.check(
                receipt.epoch.get() == before_epoch,
                format!("a non-minting {class} moved the epoch"),
            );
        }
        if before_view.owner.as_ref() == Some(&source) {
            self.check(
                receipt.replaced.is_none(),
                "the owner replaced itself".to_string(),
            );
            self.check(
                class != CommandClass::Seek || !receipt.minted,
                "a seek minted an epoch".to_string(),
            );
        } else {
            let first_start = before_view.owner.is_none() && class == CommandClass::Start;
            let allowed = first_start
                || SourcePolicyTable::STANDARD.get(source.kind(), class) == SourcePolicy::Replace;
            self.check(
                allowed,
                format!("{class} by a non-owner admitted against policy"),
            );
            self.check(
                receipt.minted,
                format!("a takeover by {class} did not mint"),
            );
            self.check(
                receipt.replaced == before_view.owner,
                "the displaced source is not the previous owner".to_string(),
            );
        }
        let after = self.arbiter.look(&self.session);
        self.check(
            after.epoch == receipt.epoch && after.owner == receipt.owner,
            "receipt and view disagree".to_string(),
        );
        self.learn(index, &receipt);
        if class == CommandClass::Start {
            self.void = false;
        }
        if receipt.replaced.is_some() {
            self.bump("replacements");
        }
        self.bump(match class {
            CommandClass::Start => "starts_admitted",
            CommandClass::Seek => "seeks_applied",
            CommandClass::GroupChange => "group_changes_applied",
            CommandClass::Stop => "stops_admitted",
        });
        if class == CommandClass::Start && before_view.owner.as_ref() == Some(&source) {
            self.bump("owner_restarts");
        }
        Some(receipt)
    }

    fn publish(&mut self, index: usize) {
        let source = self.sources[index].clone();
        let mut epoch = self.granted[index].unwrap_or(self.known[index]);
        if self.rng.below(6) == 0
            && let Some(late) = self.previous[index]
        {
            epoch = late; // a late block of the stream this source owned before
        }
        let before_view = self.arbiter.look(&self.session);
        let bound_to_group = self.arbiter.state().0 == Some(self.session.current_epoch);
        let result = self
            .arbiter
            .gate(&self.session, &source, SourceEpoch::new(epoch));
        self.report.trace.push(format!("{result:?}"));
        match result {
            Err(error) => {
                let older_non_owner = before_view.owner.as_ref().is_some_and(|o| *o != source)
                    && epoch < before_view.epoch.get()
                    && bound_to_group;
                if older_non_owner {
                    let typed = matches!(error, SourceError::SourceReplaced { .. });
                    self.check(
                        typed,
                        format!(
                            "an older-epoch block from a non-owner was refused as {}",
                            error.code()
                        ),
                    );
                }
                match error {
                    SourceError::SourceReplaced { current, .. } => {
                        self.bump("publish_replaced");
                        self.granted[index] = None;
                        self.known[index] = current;
                    }
                    SourceError::NotSourceOwner { .. } => self.bump("publish_not_owner"),
                    SourceError::SourceEpochStale { .. }
                    | SourceError::SourceEpochFuture { .. } => {
                        self.bump("publish_stale");
                    }
                    SourceError::GroupEpochAdvanced { .. } => self.bump("publish_group_advanced"),
                    SourceError::NoActiveSource => self.bump("publish_no_source"),
                    other => panic!("a publish was refused as {}", other.code()),
                }
            }
            Ok(()) => {
                let sound =
                    before_view.owner.as_ref() == Some(&source) && epoch == before_view.epoch.get();
                self.check(
                    sound,
                    format!(
                        "a block from {source} at epoch {epoch} reached output; the owner is {:?} at {}",
                        before_view.owner.as_ref().map(ToString::to_string),
                        before_view.epoch.get()
                    ),
                );
                let void = self.void;
                self.check(
                    !void,
                    "a block reached output after a group epoch advance with no new Start"
                        .to_string(),
                );
                self.bump("published");
            }
        }
    }

    fn run(&mut self, steps: usize) {
        for _ in 0..steps {
            self.now += 1 + self.rng.below(5);
            let roll = self.rng.below(100);
            if roll < 28 {
                let index = self.rng.pick(4);
                let known = self.known[index];
                self.command(index, CommandClass::Start, known, None);
            } else if roll < 42 {
                let index = self.rng.pick(4);
                let known = self.known[index];
                self.command(index, CommandClass::Seek, known, None);
            } else if roll < 50 {
                let index = self.rng.pick(4);
                let known = self.known[index];
                self.command(index, CommandClass::GroupChange, known, None);
            } else if roll < 56 {
                let index = self.rng.pick(4);
                let known = self.known[index];
                self.command(index, CommandClass::Stop, known, None);
            } else if roll < 78 {
                let index = self.rng.pick(4);
                self.publish(index);
            } else if roll < 90 {
                let index = self.rng.pick(4);
                let view = self.arbiter.look(&self.session);
                self.known[index] = view.epoch.get();
                self.granted[index] =
                    (view.owner.as_ref() == Some(&self.sources[index])).then(|| view.epoch.get());
            } else if roll < 95 {
                let racers = 2 + self.rng.below(3);
                let expected = self.arbiter.look(&self.session).epoch.get();
                self.bump("race_rounds");
                let mut minted_in_round = 0;
                for _ in 0..racers {
                    let index = self.rng.pick(4);
                    let class = CommandClass::ALL[self.rng.pick(4)];
                    if let Some(receipt) = self.command(index, class, expected, None)
                        && receipt.minted
                    {
                        minted_in_round += 1;
                    }
                }
                self.check(
                    minted_in_round <= 1,
                    format!(
                        "{minted_in_round} commands that saw the same epoch were admitted as new epochs"
                    ),
                );
                if minted_in_round == 1 {
                    self.bump("race_winners");
                }
            } else if roll < 98 {
                self.session.begin_epoch(self.session.current_epoch + 1);
                self.token = AuthorityToken::issue(&self.session, u64::MAX);
                self.void = true;
                self.bump("group_advances");
            } else {
                let index = self.rng.pick(4);
                let stale = if self.session.current_epoch > 1 {
                    token_variant(&self.session, "stale")
                } else {
                    token_variant(&self.session, "wrong_issuer")
                };
                let known = self.known[index];
                self.command(index, CommandClass::Start, known, Some(stale));
            }
        }
    }
}

const SCHEDULE_SEEDS: u64 = 8;
const SCHEDULE_STEPS: usize = 600;

fn run_schedule<J: Judge>(seed: u64, steps: usize, arbiter: &mut J) -> Report {
    let session = UnifiedGroupSession::new("grp", "coord", 1);
    let token = AuthorityToken::issue(&session, u64::MAX);
    let mut driver = Driver {
        seed,
        arbiter,
        session,
        token,
        rng: SplitMix64(seed ^ 0x4730_3153),
        sources: SCHEDULE_SOURCES.iter().map(|name| sid(name)).collect(),
        known: [0; 4],
        granted: [None; 4],
        previous: [None; 4],
        now: 1_000,
        minted_epochs: BTreeSet::new(),
        void: false,
        report: Report::default(),
    };
    driver.run(steps);
    driver.report
}

#[test]
fn seeded_interleavings_admit_one_source_epoch_per_observed_epoch() {
    let mut totals: BTreeMap<&'static str, u64> = BTreeMap::new();
    for seed in 0..SCHEDULE_SEEDS {
        let mut arbiter = SourceArbiter::new(SourceConfig::default());
        let report = run_schedule(seed, SCHEDULE_STEPS, &mut arbiter);
        assert!(
            report.violations.is_empty(),
            "seed {seed}: {:?}",
            report.violations
        );
        for (key, n) in report.counts {
            *totals.entry(key).or_insert(0) += n;
        }
    }
    // Floors are about a third of what the independent Python mirror counts for the same seeds, so the
    // schedule has to reach every path and not merely avoid violating anything.
    let floors: [(&str, u64); 19] = [
        ("starts_admitted", 230),
        ("replacements", 100),
        ("owner_restarts", 80),
        ("seeks_applied", 45),
        ("group_changes_applied", 45),
        ("stops_admitted", 25),
        ("stale_refused", 400),
        ("policy_refused", 200),
        ("no_source_refused", 100),
        ("authority_refused", 30),
        ("published", 55),
        ("publish_replaced", 110),
        ("publish_not_owner", 75),
        ("publish_stale", 10),
        ("publish_group_advanced", 60),
        ("publish_no_source", 28),
        ("race_rounds", 70),
        ("race_winners", 40),
        ("group_advances", 50),
    ];
    for (key, floor) in floors {
        let got = totals.get(key).copied().unwrap_or(0);
        assert!(got >= floor, "{key}: {got} is below the floor {floor}");
    }
    // The sources never present an epoch above the current one, so the schedule never meets this refusal.
    assert_eq!(totals.get("future_refused"), None);
}

// ------------------------------------------- a transcription of the engine, and three planted defects

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flaw {
    Sound,
    /// A block is admitted whenever some source owns the group, whoever sent it and under any epoch.
    ReplacedSourcePublishes,
    /// A Start does not have to present the current epoch, so every racing Start can be admitted.
    RacingStartsBothAdmitted,
    /// A Seek is applied whenever some source owns the group, whoever sent it and under any epoch.
    LosingSeekApplied,
}

/// The engine again, written out a second time with plain integers and with the option of one defect.
/// With `Flaw::Sound` it must behave step for step like `SourceArbiter`.
struct Transcription {
    flaw: Flaw,
    table: SourcePolicyTable,
    bound: Option<u64>,
    epoch: u64,
    owner: Option<SourceId>,
}

type Decision = (bool, Option<SourceId>, Option<SourceId>);

impl Transcription {
    fn new(flaw: Flaw) -> Self {
        Self {
            flaw,
            table: SourcePolicyTable::STANDARD,
            bound: None,
            epoch: 0,
            owner: None,
        }
    }

    fn effective(&self, group: u64) -> (Option<SourceId>, u64) {
        match self.bound {
            Some(bound) if bound != group => (None, self.epoch.saturating_add(1)),
            _ => (self.owner.clone(), self.epoch),
        }
    }

    fn decide(
        &self,
        owner: Option<&SourceId>,
        command: &SourceCommand,
    ) -> Result<Decision, SourceError> {
        let source = &command.source;
        let class = command.class;
        match owner {
            None if class == CommandClass::Start => Ok((true, Some(source.clone()), None)),
            None => Err(SourceError::NoActiveSource),
            Some(held) if held == source => match class {
                CommandClass::Start => Ok((true, Some(source.clone()), None)),
                CommandClass::Stop => Ok((true, None, None)),
                CommandClass::Seek | CommandClass::GroupChange => {
                    Ok((false, Some(source.clone()), None))
                }
            },
            Some(held) => match self.table.get(source.kind(), class) {
                SourcePolicy::Reject => Err(SourceError::SourceRejected {
                    class,
                    requester: source.clone(),
                    owner: held.clone(),
                }),
                SourcePolicy::Replace => Ok((
                    true,
                    if class == CommandClass::Stop {
                        None
                    } else {
                        Some(source.clone())
                    },
                    Some(held.clone()),
                )),
            },
        }
    }
}

impl Judge for Transcription {
    fn judge(
        &mut self,
        session: &UnifiedGroupSession,
        token: &AuthorityToken,
        now_ns: u64,
        command: &SourceCommand,
    ) -> Result<Admitted, SourceError> {
        token
            .check_with_margin(session, now_ns, 0)
            .map_err(SourceError::Authority)?;
        let (owner, current) = self.effective(session.current_epoch);
        let class = command.class;
        if class == CommandClass::Seek && self.flaw == Flaw::LosingSeekApplied {
            if owner.is_none() {
                return Err(SourceError::NoActiveSource);
            }
            self.bound = Some(session.current_epoch);
            return Ok(Admitted {
                class,
                epoch: SourceEpoch::new(current),
                owner,
                replaced: None,
                minted: false,
            });
        }
        let expected = command.expected_epoch.get();
        let skips_the_epoch_check =
            class == CommandClass::Start && self.flaw == Flaw::RacingStartsBothAdmitted;
        if !skips_the_epoch_check {
            if expected < current {
                return Err(SourceError::SourceEpochStale { expected, current });
            }
            if expected > current {
                return Err(SourceError::SourceEpochFuture { expected, current });
            }
        }
        let (mints, new_owner, replaced) = self.decide(owner.as_ref(), command)?;
        let after = if mints {
            current
                .checked_add(1)
                .ok_or(SourceError::SourceEpochExhausted)?
        } else {
            current
        };
        self.bound = Some(session.current_epoch);
        self.epoch = after;
        self.owner.clone_from(&new_owner);
        Ok(Admitted {
            class,
            epoch: SourceEpoch::new(after),
            owner: new_owner,
            replaced,
            minted: mints,
        })
    }

    fn gate(
        &self,
        session: &UnifiedGroupSession,
        source: &SourceId,
        epoch: SourceEpoch,
    ) -> Result<(), SourceError> {
        if self.flaw == Flaw::ReplacedSourcePublishes {
            return if self.bound.is_some() && self.owner.is_some() {
                Ok(())
            } else {
                Err(SourceError::NoActiveSource)
            };
        }
        let epoch = epoch.get();
        let Some(bound) = self.bound else {
            return Err(SourceError::NoActiveSource);
        };
        if bound != session.current_epoch {
            return Err(SourceError::GroupEpochAdvanced {
                arbiter_group_epoch: bound,
                group_epoch: session.current_epoch,
            });
        }
        let Some(owner) = self.owner.as_ref() else {
            return Err(SourceError::NoActiveSource);
        };
        if epoch < self.epoch {
            return Err(if owner == source {
                SourceError::SourceEpochStale {
                    expected: epoch,
                    current: self.epoch,
                }
            } else {
                SourceError::SourceReplaced {
                    sender: source.clone(),
                    epoch,
                    current: self.epoch,
                }
            });
        }
        if epoch > self.epoch {
            return Err(SourceError::SourceEpochFuture {
                expected: epoch,
                current: self.epoch,
            });
        }
        if owner != source {
            return Err(SourceError::NotSourceOwner {
                sender: source.clone(),
                owner: owner.clone(),
            });
        }
        Ok(())
    }

    fn look(&self, session: &UnifiedGroupSession) -> SourceView {
        let (owner, epoch) = self.effective(session.current_epoch);
        SourceView {
            group_epoch: session.current_epoch,
            epoch: SourceEpoch::new(epoch),
            owner,
        }
    }

    fn state(&self) -> Fingerprint {
        (self.bound, SourceEpoch::new(self.epoch), self.owner.clone())
    }
}

#[test]
fn the_sound_transcription_behaves_step_for_step_like_the_engine() {
    for seed in 0..SCHEDULE_SEEDS {
        let mut engine = SourceArbiter::new(SourceConfig::default());
        let mut copy = Transcription::new(Flaw::Sound);
        let real = run_schedule(seed, SCHEDULE_STEPS, &mut engine);
        let twin = run_schedule(seed, SCHEDULE_STEPS, &mut copy);
        assert!(
            twin.violations.is_empty(),
            "seed {seed}: {:?}",
            twin.violations
        );
        assert_eq!(real.trace.len(), twin.trace.len(), "seed {seed}");
        for (step, (a, b)) in real.trace.iter().zip(&twin.trace).enumerate() {
            assert_eq!(a, b, "seed {seed}, outcome {step}");
        }
        assert_eq!(real.counts, twin.counts, "seed {seed}");
    }
}

#[test]
fn each_planted_defect_is_caught_by_the_schedule() {
    let plants = [
        (Flaw::ReplacedSourcePublishes, "reached output"),
        (Flaw::RacingStartsBothAdmitted, "saw the same epoch"),
        (Flaw::LosingSeekApplied, "seek admitted at epoch"),
    ];
    for (flaw, needle) in plants {
        let mut found: Vec<String> = Vec::new();
        for seed in 0..SCHEDULE_SEEDS {
            let mut copy = Transcription::new(flaw);
            found.extend(run_schedule(seed, SCHEDULE_STEPS, &mut copy).violations);
        }
        assert!(
            found.iter().any(|violation| violation.contains(needle)),
            "{flaw:?} was not caught as `{needle}`: {} violations, the first being {:?}",
            found.len(),
            found.first()
        );
    }
}

#[test]
fn the_planted_defects_also_break_the_hand_written_scenarios() {
    // A replaced source's publish is admitted.
    let mut copy = Transcription::new(Flaw::ReplacedSourcePublishes);
    let session = UnifiedGroupSession::new("grp", "coord", 1);
    let token = AuthorityToken::issue(&session, u64::MAX);
    let start = |who: &str, at: u64| SourceCommand {
        source: sid(who),
        class: CommandClass::Start,
        expected_epoch: SourceEpoch::new(at),
    };
    copy.judge(&session, &token, 5_000, &start("s", 0)).unwrap();
    copy.judge(&session, &token, 5_000, &start("a", 1)).unwrap();
    assert!(copy.gate(&session, &sid("s"), SourceEpoch::new(1)).is_ok());

    // Two starts that saw the same epoch are both admitted.
    let mut racing = Transcription::new(Flaw::RacingStartsBothAdmitted);
    racing
        .judge(&session, &token, 5_000, &start("s", 0))
        .unwrap();
    assert!(
        racing
            .judge(&session, &token, 5_000, &start("a", 0))
            .is_ok()
    );

    // A seek from the losing epoch is applied.
    let mut seeking = Transcription::new(Flaw::LosingSeekApplied);
    seeking
        .judge(&session, &token, 5_000, &start("s", 0))
        .unwrap();
    seeking
        .judge(&session, &token, 5_000, &start("a", 1))
        .unwrap();
    let stale_seek = SourceCommand {
        source: sid("s"),
        class: CommandClass::Seek,
        expected_epoch: SourceEpoch::new(1),
    };
    assert!(seeking.judge(&session, &token, 5_000, &stale_seek).is_ok());

    // The sound copy refuses all three.
    let mut sound = Transcription::new(Flaw::Sound);
    sound
        .judge(&session, &token, 5_000, &start("s", 0))
        .unwrap();
    sound
        .judge(&session, &token, 5_000, &start("a", 1))
        .unwrap();
    assert_eq!(
        sound
            .gate(&session, &sid("s"), SourceEpoch::new(1))
            .unwrap_err()
            .code(),
        "SOURCE_REPLACED"
    );
    assert_eq!(
        sound
            .judge(&session, &token, 5_000, &start("s", 0))
            .unwrap_err()
            .code(),
        "SOURCE_EPOCH_STALE"
    );
    assert_eq!(
        sound
            .judge(&session, &token, 5_000, &stale_seek)
            .unwrap_err()
            .code(),
        "SOURCE_EPOCH_STALE"
    );
}
