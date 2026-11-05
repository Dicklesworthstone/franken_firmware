//! Shared fixtures for the channel's tests. Compiled only for tests.

use franken_session::{
    ChannelRole, FencedControlCommand, GroupCommandPayload, UnifiedGroupSession,
};

/// A session at `epoch` with members `kitchen` (an S5) and `den` (an S12), both at volume 50 and
/// unmuted, a group master volume of 50, and a state revision of 2.
///
/// The two admissions use command numbers 1 and 2. The channel numbers its own commands from
/// `ChannelConfig::session_seq_base`, which the tests keep well above these.
///
/// The boards come from the synthetic fixture catalog: this exercises message handling on the host
/// and says nothing about any real board.
pub fn fixture_session(epoch: u64) -> UnifiedGroupSession {
    let catalog = franken_board_profile::synthetic_test_fixture_catalog();
    let board = |model: &str| {
        catalog
            .iter()
            .find(|p| p.model_number == model)
            .expect("the fixture catalog has this model")
            .clone()
    };
    let mut session = UnifiedGroupSession::new("grp", "coord", epoch);
    for (seq, member, model) in [(1, "kitchen", "S5"), (2, "den", "S12")] {
        session
            .apply_command(FencedControlCommand {
                epoch,
                command_seq: seq,
                payload: GroupCommandPayload::AdmitMember {
                    member_id: member.to_string(),
                    board: board(model),
                    role: ChannelRole::Stereo,
                },
            })
            .expect("a fixture member is admissible");
    }
    session
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fixture_is_the_documented_starting_state() {
        let s = fixture_session(10);
        assert_eq!(
            (s.current_epoch, s.state_revision, s.group_master_volume),
            (10, 2, 50)
        );
        assert_eq!(s.members.len(), 2);
        assert!(
            s.members
                .values()
                .all(|m| m.volume_0_to_100 == 50 && !m.muted)
        );
    }
}
