//! What the endpoint tells a controller about the group: the values behind the read actions and the
//! eventing (G03 / `ffw-xvv`).
//!
//! Everything here is read from the live [`UnifiedGroupSession`] at the moment it is asked, never from
//! a cache, so a read cannot be stale topology. The two things the session does not know are supplied
//! by the owner: the transport state (the session has no source model; that belongs to source
//! arbitration) and the directory of locations and room names (the session knows member ids only).

use std::collections::BTreeMap;

use franken_session::UnifiedGroupSession;

use super::xml::{Escape, escape};

/// AVTransport's `CurrentTransportState` as this endpoint can honestly report it. The session records
/// no source, so the owner says what the transport is; without that, nothing is claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportState {
    Playing,
    PausedPlayback,
    Stopped,
    Transitioning,
    NoMediaPresent,
}

impl TransportState {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Playing => "PLAYING",
            Self::PausedPlayback => "PAUSED_PLAYBACK",
            Self::Stopped => "STOPPED",
            Self::Transitioning => "TRANSITIONING",
            Self::NoMediaPresent => "NO_MEDIA_PRESENT",
        }
    }
}

/// Facts about members that the session does not hold. Both maps are keyed by member id and are the
/// owner's to fill; a member missing from a map is listed with an empty location, or its id as its
/// room name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Directory {
    /// Where each member's device description lives (`http://<address>:<port>/...`).
    pub locations: BTreeMap<String, String>,
    pub zone_names: BTreeMap<String, String>,
}

/// The `ZoneGroupState` document: one group, whose coordinator is the session's issuer, with every
/// member the session holds. The group id carries the epoch (`<group>:<epoch>`), so a controller that
/// compares ids sees a new group after the epoch moves.
#[must_use]
pub fn zone_group_state_xml(session: &UnifiedGroupSession, directory: &Directory) -> String {
    let attr = |s: &str| escape(s, Escape::Attribute);
    let mut out = String::from("<ZoneGroupState><ZoneGroups>");
    out.push_str(&format!(
        "<ZoneGroup Coordinator=\"{}\" ID=\"{}\">",
        attr(&session.coordinator_id),
        attr(&format!("{}:{}", session.group_id, session.current_epoch)),
    ));
    for member in session.members.values() {
        let location = directory
            .locations
            .get(&member.member_id)
            .map_or("", String::as_str);
        let name = directory
            .zone_names
            .get(&member.member_id)
            .map_or(member.member_id.as_str(), String::as_str);
        out.push_str(&format!(
            "<ZoneGroupMember UUID=\"{}\" Location=\"{}\" ZoneName=\"{}\" Invisible=\"0\" SWGen=\"{}\"/>",
            attr(&member.member_id),
            attr(location),
            attr(name),
            member.legacy_sw_gen_hint,
        ));
    }
    out.push_str("</ZoneGroup></ZoneGroups><VanishedDevices></VanishedDevices></ZoneGroupState>");
    out
}

/// The values the four evented services publish, at one moment. `volume` and `mute` are this
/// endpoint's own member; they are `None` when it is not (or no longer) in the group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventState {
    pub epoch: u64,
    /// The session's committed revision when this was read.
    pub revision: u64,
    pub volume: Option<u8>,
    pub mute: Option<bool>,
    pub group_volume: u8,
    /// True only when the group has members and every one is muted.
    pub group_mute: bool,
    pub transport: TransportState,
    pub zone_group_state: String,
}

impl EventState {
    #[must_use]
    pub fn read(
        session: &UnifiedGroupSession,
        member_id: &str,
        transport: TransportState,
        directory: &Directory,
    ) -> Self {
        let member = session.members.get(member_id);
        Self {
            epoch: session.current_epoch,
            revision: session.state_revision,
            volume: member.map(|m| m.volume_0_to_100),
            mute: member.map(|m| m.muted),
            group_volume: session.group_master_volume,
            group_mute: !session.members.is_empty() && session.members.values().all(|m| m.muted),
            transport,
            zone_group_state: zone_group_state_xml(session, directory),
        }
    }
}

#[cfg(test)]
mod tests {
    use franken_session::{ChannelRole, FencedControlCommand, GroupCommandPayload};

    use super::*;
    use crate::fsonos::xml::{Event, XmlLimits, XmlReader};

    const EPOCH: u64 = 10;

    fn session() -> UnifiedGroupSession {
        let catalog = franken_board_profile::synthetic_test_fixture_catalog();
        let board = |model: &str| {
            catalog
                .iter()
                .find(|p| p.model_number == model)
                .expect("fixture model")
                .clone()
        };
        let mut s = UnifiedGroupSession::new("grp", "coord", EPOCH);
        for (seq, member, model) in [(1, "kitchen", "S5"), (2, "den", "S12")] {
            s.apply_command(FencedControlCommand {
                epoch: EPOCH,
                command_seq: seq,
                payload: GroupCommandPayload::AdmitMember {
                    member_id: member.to_string(),
                    board: board(model),
                    role: ChannelRole::Stereo,
                },
            })
            .expect("fixture member admits");
        }
        s
    }

    fn directory() -> Directory {
        Directory {
            locations: BTreeMap::from([(
                "kitchen".to_string(),
                "http://192.0.2.10:1400/xml/device_description.xml".to_string(),
            )]),
            zone_names: BTreeMap::from([("kitchen".to_string(), "Kitchen & Den".to_string())]),
        }
    }

    #[test]
    fn the_transport_states_are_the_upnp_words() {
        let words: Vec<&str> = [
            TransportState::Playing,
            TransportState::PausedPlayback,
            TransportState::Stopped,
            TransportState::Transitioning,
            TransportState::NoMediaPresent,
        ]
        .into_iter()
        .map(|t| t.as_str())
        .collect();
        assert_eq!(
            words,
            [
                "PLAYING",
                "PAUSED_PLAYBACK",
                "STOPPED",
                "TRANSITIONING",
                "NO_MEDIA_PRESENT"
            ]
        );
    }

    #[test]
    fn the_topology_document_lists_the_group_the_session_holds() {
        let xml = zone_group_state_xml(&session(), &directory());
        assert_eq!(
            xml,
            "<ZoneGroupState><ZoneGroups>\
             <ZoneGroup Coordinator=\"coord\" ID=\"grp:10\">\
             <ZoneGroupMember UUID=\"den\" Location=\"\" ZoneName=\"den\" Invisible=\"0\" SWGen=\"2\"/>\
             <ZoneGroupMember UUID=\"kitchen\" Location=\"http://192.0.2.10:1400/xml/device_description.xml\" \
             ZoneName=\"Kitchen &amp; Den\" Invisible=\"0\" SWGen=\"1\"/>\
             </ZoneGroup></ZoneGroups><VanishedDevices></VanishedDevices></ZoneGroupState>"
        );
    }

    #[test]
    fn the_topology_document_is_well_formed_and_every_member_has_the_required_attributes() {
        let xml = zone_group_state_xml(&session(), &directory());
        let mut reader = XmlReader::new(
            xml.as_bytes(),
            XmlLimits {
                max_bytes: 4096,
                ..XmlLimits::soap_request()
            },
        )
        .expect("within bounds");
        let mut members = 0;
        while let Some(event) = reader.next_event().expect("well formed") {
            if let Event::Start {
                name, attributes, ..
            } = event
                && name == "ZoneGroupMember"
            {
                members += 1;
                for required in ["UUID", "Location"] {
                    assert!(attributes.iter().any(|(k, _)| k == required), "{required}");
                }
            }
        }
        assert_eq!(members, 2);
    }

    #[test]
    fn the_group_id_follows_the_epoch_so_a_moved_group_is_a_new_group() {
        let mut s = session();
        let before = zone_group_state_xml(&s, &directory());
        s.apply_command(FencedControlCommand {
            epoch: 11,
            command_seq: 3,
            payload: GroupCommandPayload::MarkMemberClockLocked {
                member_id: "kitchen".to_string(),
            },
        })
        .expect("a newer epoch is adopted");
        let after = zone_group_state_xml(&s, &directory());
        assert!(before.contains("ID=\"grp:10\"") && after.contains("ID=\"grp:11\""));
    }

    #[test]
    fn a_hostile_member_name_is_escaped_in_the_document() {
        let mut dir = directory();
        dir.zone_names
            .insert("kitchen".to_string(), "\"/><Injected a=\"1".to_string());
        let xml = zone_group_state_xml(&session(), &dir);
        assert!(!xml.contains("<Injected"), "{xml}");
        assert!(xml.contains("&quot;/&gt;&lt;Injected a=&quot;1"));
    }

    #[test]
    fn the_event_state_reads_the_live_session() {
        let mut s = session();
        let state = EventState::read(&s, "kitchen", TransportState::Stopped, &directory());
        assert_eq!(
            (state.epoch, state.revision, state.volume, state.mute),
            (EPOCH, 2, Some(50), Some(false))
        );
        assert_eq!((state.group_volume, state.group_mute), (50, false));
        s.apply_command(FencedControlCommand {
            epoch: EPOCH,
            command_seq: 3,
            payload: GroupCommandPayload::SetMemberMute {
                member_id: "kitchen".to_string(),
                muted: true,
            },
        })
        .expect("mute applies");
        s.apply_command(FencedControlCommand {
            epoch: EPOCH,
            command_seq: 4,
            payload: GroupCommandPayload::SetMemberMute {
                member_id: "den".to_string(),
                muted: true,
            },
        })
        .expect("mute applies");
        let muted = EventState::read(&s, "kitchen", TransportState::Stopped, &directory());
        assert_eq!(
            (muted.revision, muted.mute, muted.group_mute),
            (4, Some(true), true)
        );
    }

    #[test]
    fn an_endpoint_that_is_not_in_the_group_reports_no_volume_or_mute() {
        let state = EventState::read(
            &session(),
            "absent",
            TransportState::NoMediaPresent,
            &directory(),
        );
        assert_eq!((state.volume, state.mute), (None, None));
    }

    #[test]
    fn an_empty_group_is_not_muted() {
        let empty = UnifiedGroupSession::new("grp", "coord", EPOCH);
        let state = EventState::read(
            &empty,
            "kitchen",
            TransportState::NoMediaPresent,
            &Directory::default(),
        );
        assert!(!state.group_mute);
        assert!(
            state
                .zone_group_state
                .contains("<ZoneGroup Coordinator=\"coord\"")
        );
    }
}
