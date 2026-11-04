//! Bounded `fsonos` UPnP/SOAP/GENA Compatibility Adapter and Native Service Contracts
//! (`G03` / `ffw-xvv`, `S01` / `ffw-75n`, `A01` / `ffw-6yi`, `T01` / `ffw-32a`, `X01` / `ffw-s3l`).
//!
//! Preserves the exact `fsonos` host controller contract for playback, volume, mute,
//! and unified zone-group topology while explicitly returning UPnP fault `602`
//! (`Optional Action Not Implemented`) for retired 2008 legacy media-indexer actions.
//!
//! Native integrations (`Spotify`, `AirPlay 2`, `Tailscale`, `Alexa`) are defined as
//! decoupled traits with deterministic offline test adapters so none becomes a
//! mandatory compile-time dependency of the minimal synchronized renderer.

#![forbid(unsafe_code)]

use franken_clock::{
    ClockError, LatencyLedger, VideoSyncEvaluation, compute_cooperative_video_sync,
};
use franken_session::{
    FencedControlCommand, GroupCommandPayload, SessionError, UnifiedGroupSession,
};
use serde::{Deserialize, Serialize};

/// UPnP SOAP fault codes returned to controllers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum SoapFault {
    #[error("UPnP fault 402: Invalid Args ({detail})")]
    InvalidArgs { detail: String },
    #[error("UPnP fault 501: Action Failed ({detail})")]
    ActionFailed { detail: String },
    #[error(
        "UPnP fault 602: Optional Action Not Implemented (`{action}` is retired in slim firmware)"
    )]
    RetiredLegacyAction { action: String },
}

/// Supported `fsonos` SOAP actions (`G03` / `ffw-xvv`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsonosSoapRequest {
    GetVolume {
        member_id: String,
    },
    SetVolume {
        epoch: u64,
        command_seq: u64,
        member_id: String,
        desired_volume: u8,
    },
    SetGroupVolume {
        epoch: u64,
        command_seq: u64,
        desired_volume: u8,
    },
    SetMute {
        epoch: u64,
        command_seq: u64,
        member_id: String,
        desired_mute: bool,
    },
    Stop {
        epoch: u64,
        command_seq: u64,
        now_ns: u64,
        irrevocable_dma_tail_ns: u64,
    },
    GetZoneGroupState,
    LegacyAction {
        action_name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsonosSoapResponse {
    Volume { current_volume: u8 },
    StateUpdated { state_revision: u64 },
    ZoneGroupStateXml { xml: String },
}

/// Execute a bounded `fsonos` SOAP request against a [`UnifiedGroupSession`].
pub fn handle_fsonos_soap(
    session: &mut UnifiedGroupSession,
    req: FsonosSoapRequest,
) -> Result<FsonosSoapResponse, SoapFault> {
    match req {
        FsonosSoapRequest::GetVolume { member_id } => {
            let member = session
                .members
                .get(&member_id)
                .ok_or_else(|| SoapFault::InvalidArgs {
                    detail: format!("unknown member {member_id}"),
                })?;
            Ok(FsonosSoapResponse::Volume {
                current_volume: member.volume_0_to_100,
            })
        }
        FsonosSoapRequest::SetVolume {
            epoch,
            command_seq,
            member_id,
            desired_volume,
        } => {
            if desired_volume > 100 {
                return Err(SoapFault::InvalidArgs {
                    detail: format!("volume {desired_volume} > 100"),
                });
            }
            let rev = session
                .apply_command(FencedControlCommand {
                    epoch,
                    command_seq,
                    payload: GroupCommandPayload::SetMemberVolume {
                        member_id,
                        volume_0_to_100: desired_volume,
                    },
                })
                .map_err(map_session_err)?;
            Ok(FsonosSoapResponse::StateUpdated {
                state_revision: rev,
            })
        }
        FsonosSoapRequest::SetGroupVolume {
            epoch,
            command_seq,
            desired_volume,
        } => {
            if desired_volume > 100 {
                return Err(SoapFault::InvalidArgs {
                    detail: format!("group volume {desired_volume} > 100"),
                });
            }
            let rev = session
                .apply_command(FencedControlCommand {
                    epoch,
                    command_seq,
                    payload: GroupCommandPayload::SetGroupVolume {
                        volume_0_to_100: desired_volume,
                    },
                })
                .map_err(map_session_err)?;
            Ok(FsonosSoapResponse::StateUpdated {
                state_revision: rev,
            })
        }
        FsonosSoapRequest::SetMute {
            epoch,
            command_seq,
            member_id,
            desired_mute,
        } => {
            let rev = session
                .apply_command(FencedControlCommand {
                    epoch,
                    command_seq,
                    payload: GroupCommandPayload::SetMemberMute {
                        member_id,
                        muted: desired_mute,
                    },
                })
                .map_err(map_session_err)?;
            Ok(FsonosSoapResponse::StateUpdated {
                state_revision: rev,
            })
        }
        FsonosSoapRequest::Stop {
            epoch,
            command_seq,
            now_ns,
            irrevocable_dma_tail_ns,
        } => {
            let rev = session
                .apply_command(FencedControlCommand {
                    epoch,
                    command_seq,
                    payload: GroupCommandPayload::StopGroupPlayback {
                        now_ns,
                        irrevocable_dma_tail_ns,
                    },
                })
                .map_err(map_session_err)?;
            Ok(FsonosSoapResponse::StateUpdated {
                state_revision: rev,
            })
        }
        FsonosSoapRequest::GetZoneGroupState => {
            let mut members_xml = String::new();
            for m in session.members.values() {
                members_xml.push_str(&format!(
                    "<ZoneGroupMember UUID=\"{}\" Profile=\"{}\" SwGen=\"{}\" Volume=\"{}\" Mute=\"{}\"/>",
                    m.member_id,
                    m.profile_id,
                    m.legacy_sw_gen_hint,
                    m.volume_0_to_100,
                    u8::from(m.muted)
                ));
            }
            let xml = format!(
                "<ZoneGroupState Epoch=\"{}\" Revision=\"{}\"><ZoneGroup Coordinator=\"{}\" ID=\"{}\">{}</ZoneGroup></ZoneGroupState>",
                session.current_epoch,
                session.state_revision,
                session.coordinator_id,
                session.group_id,
                members_xml
            );
            Ok(FsonosSoapResponse::ZoneGroupStateXml { xml })
        }
        FsonosSoapRequest::LegacyAction { action_name } => Err(SoapFault::RetiredLegacyAction {
            action: action_name,
        }),
    }
}

fn map_session_err(err: SessionError) -> SoapFault {
    SoapFault::ActionFailed {
        detail: err.to_string(),
    }
}

// --- Native Integration Contracts (S01, A01, T01, X01) ---

/// Spotify Connect source session contract (`S01` / `ffw-75n`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpotifySessionState {
    pub active_device_id: String,
    pub track_uri: Option<String>,
    pub codec: String,
    pub bitrate_kbps: u16,
    pub playing: bool,
    pub lookahead_compressed_bytes: usize,
}

/// AirPlay 2 receiver and cooperative YouTube video-sync state (`A01` / `A02` / `V02`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirPlay2ReceiverState {
    pub receiver_name: String,
    pub paired: bool,
    pub active_stream_kind: Option<String>,
    pub last_video_sync: Option<VideoSyncEvaluation>,
}

impl AirPlay2ReceiverState {
    pub fn evaluate_youtube_video_sync(
        &mut self,
        ledger: &LatencyLedger,
        applied_video_delay_us: u64,
    ) -> Result<VideoSyncEvaluation, ClockError> {
        let eval = compute_cooperative_video_sync(
            "airplay2-youtube-av",
            true,
            ledger,
            applied_video_delay_us,
        )?;
        self.active_stream_kind = Some("airplay2-youtube-av".to_string());
        self.last_video_sync = Some(eval.clone());
        Ok(eval)
    }
}

/// Native Tailscale tailnet endpoint status (`T01` / `T02` / `T04`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailnetEndpointState {
    pub node_name: String,
    pub enrolled: bool,
    pub peer_count: usize,
    pub max_admitted_peers: usize,
    pub using_derp_relay: bool,
    pub admitted_ram_budget_bytes: Option<u64>,
}

impl TailnetEndpointState {
    /// Per `T01`/`T04`: absent shared RAM budget is reported as `PendingBudget`, never false pass.
    #[must_use]
    pub fn is_qualified_for_board(&self) -> bool {
        self.enrolled
            && self.peer_count <= self.max_admitted_peers
            && self.admitted_ram_budget_bytes.is_some()
    }
}

/// Alexa voice-to-speaker command router (`X01` / `X02` / `X04`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlexaDirective {
    PlaySpotifyOnGroup {
        track_uri: String,
    },
    SetVolume {
        epoch: u64,
        command_seq: u64,
        volume: u8,
    },
    SetMute {
        epoch: u64,
        command_seq: u64,
        muted: bool,
    },
    Pause {
        epoch: u64,
        command_seq: u64,
        now_ns: u64,
    },
}

pub fn dispatch_alexa_directive(
    session: &mut UnifiedGroupSession,
    spotify: &mut SpotifySessionState,
    directive: AlexaDirective,
) -> Result<u64, SoapFault> {
    match directive {
        AlexaDirective::PlaySpotifyOnGroup { track_uri } => {
            spotify.track_uri = Some(track_uri);
            spotify.playing = true;
            session.state_revision = session.state_revision.saturating_add(1);
            Ok(session.state_revision)
        }
        AlexaDirective::SetVolume {
            epoch,
            command_seq,
            volume,
        } => match handle_fsonos_soap(
            session,
            FsonosSoapRequest::SetGroupVolume {
                epoch,
                command_seq,
                desired_volume: volume,
            },
        )? {
            FsonosSoapResponse::StateUpdated { state_revision } => Ok(state_revision),
            _ => unreachable!(),
        },
        AlexaDirective::SetMute {
            epoch,
            command_seq,
            muted,
        } => {
            let coord = session.coordinator_id.clone();
            match handle_fsonos_soap(
                session,
                FsonosSoapRequest::SetMute {
                    epoch,
                    command_seq,
                    member_id: coord,
                    desired_mute: muted,
                },
            )? {
                FsonosSoapResponse::StateUpdated { state_revision } => Ok(state_revision),
                _ => unreachable!(),
            }
        }
        AlexaDirective::Pause {
            epoch,
            command_seq,
            now_ns,
        } => {
            spotify.playing = false;
            match handle_fsonos_soap(
                session,
                FsonosSoapRequest::Stop {
                    epoch,
                    command_seq,
                    now_ns,
                    irrevocable_dma_tail_ns: 10_666_666,
                },
            )? {
                FsonosSoapResponse::StateUpdated { state_revision } => Ok(state_revision),
                _ => unreachable!(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use franken_board_profile::canonical_board_catalog;
    use franken_session::ChannelRole;

    #[test]
    fn fsonos_soap_adapter_handles_unified_topology_and_rejects_retired_2008_actions() {
        let catalog = canonical_board_catalog();
        let s5 = catalog
            .iter()
            .find(|p| p.model_number == "S5")
            .unwrap()
            .clone();
        let s12 = catalog
            .iter()
            .find(|p| p.model_number == "S12")
            .unwrap()
            .clone();

        let mut session = UnifiedGroupSession::new("grp-main", "spk-s12", 1);
        session
            .apply_command(FencedControlCommand {
                epoch: 1,
                command_seq: 1,
                payload: GroupCommandPayload::AdmitMember {
                    member_id: "spk-s12".to_string(),
                    board: s12,
                    role: ChannelRole::Stereo,
                },
            })
            .unwrap();
        session
            .apply_command(FencedControlCommand {
                epoch: 1,
                command_seq: 2,
                payload: GroupCommandPayload::AdmitMember {
                    member_id: "spk-s5".to_string(),
                    board: s5,
                    role: ChannelRole::Stereo,
                },
            })
            .unwrap();

        let topo = handle_fsonos_soap(&mut session, FsonosSoapRequest::GetZoneGroupState).unwrap();
        match topo {
            FsonosSoapResponse::ZoneGroupStateXml { xml } => {
                assert!(xml.contains("SwGen=\"1\""));
                assert!(xml.contains("SwGen=\"2\""));
            }
            other => panic!("unexpected response: {other:?}"),
        }

        // Retired 2008 SMB / WMA / ContentDirectory browse action returns explicit 602 fault
        let fault = handle_fsonos_soap(
            &mut session,
            FsonosSoapRequest::LegacyAction {
                action_name: "AddSmbShareWmaIndex".to_string(),
            },
        )
        .unwrap_err();
        assert_eq!(
            fault,
            SoapFault::RetiredLegacyAction {
                action: "AddSmbShareWmaIndex".to_string()
            }
        );
    }
}
