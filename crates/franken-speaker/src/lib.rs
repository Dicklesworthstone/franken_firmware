//! Speaker Composition Root, Readiness/Recovery UX State Machine, and Virtual House Harness
//! (`P01` / `ffw-h3g`, `Q01` / `ffw-gmq`, `UX01` / `ffw-389`).

#![forbid(unsafe_code)]

use franken_board_profile::{BoardProfile, canonical_board_catalog};
use franken_clock::{
    ClockExchangeSample, DEFAULT_MAX_ADMITTED_UNCERTAINTY_US, GroupClockEstimator, LatencyLedger,
};
use franken_control::{
    AirPlay2ReceiverState, AlexaDirective, FsonosSoapRequest, FsonosSoapResponse,
    SpotifySessionState, dispatch_alexa_directive, handle_fsonos_soap,
};
use franken_dsp::{BoardProtectionDsp, BoundedDriftResampler, FRAMES_PER_BLOCK, StereoAudioBlock};
use franken_hal::{AudioHalDevice, state as hal_state};
use franken_platform::MemoryBudgetLedger;
use franken_session::{
    ChannelRole, FencedControlCommand, GroupCommandPayload, UnifiedGroupSession,
};
use franken_stream::{
    AuthenticatedStreamPacket, BoundedJitterBuffer, PlayoutMode, PlayoutPullDecision, ReplayWindow,
};
use franken_test_support::{
    BoundedDiagnosticSink, DiagnosticEvent, NetworkSchedule, NetworkScheduleConfig,
    ReadinessOracle, SampleContinuityOracle,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// User-observable readiness and recovery state (`UX01` / `ffw-389`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeakerReadinessState {
    BootstrappingMuted,
    VerifyingBoardAndClock,
    ReadySynchronized,
    DegradedStandaloneRecovery { reason: String },
    FaultedSafeMuted { reason: String },
}

/// Per-speaker node in the Virtual House simulator (`Q01` / `ffw-gmq`).
pub struct VirtualSpeakerNode {
    pub member_id: String,
    pub board: BoardProfile,
    pub readiness: SpeakerReadinessState,
    pub readiness_oracle: ReadinessOracle,
    pub continuity_oracle: SampleContinuityOracle,
    pub clock: GroupClockEstimator,
    pub replay_window: ReplayWindow,
    pub jitter_buffer: BoundedJitterBuffer,
    pub resampler: BoundedDriftResampler,
    pub dsp: BoardProtectionDsp,
    pub hal: AudioHalDevice<hal_state::Running>,
    pub rendered_blocks: u64,
    pub authentic_blocks: u64,
    pub concealed_blocks: u64,
    pub max_skew_us: u64,
}

impl VirtualSpeakerNode {
    pub fn bring_up_admitted(
        member_id: &str,
        board: BoardProfile,
        initial_epoch: u64,
    ) -> Result<Self, String> {
        let mut readiness_oracle = ReadinessOracle::new();
        board
            .verify_integrity()
            .map_err(|e| format!("board integrity failed: {e:?}"))?;
        readiness_oracle.board_profile_verified = true;

        let budget = MemoryBudgetLedger::for_board(&board);
        budget
            .verify_budget()
            .map_err(|e| format!("memory budget failed: {e}"))?;

        let closed = AudioHalDevice::open_for_profile(board.clone(), 8, 2)
            .map_err(|e| format!("HAL open failed: {e}"))?;
        let mut prepared = closed.prepare();
        prepared
            .prime_silence_block()
            .map_err(|e| format!("silence prime 1 failed: {e}"))?;
        prepared
            .prime_silence_block()
            .map_err(|e| format!("silence prime 2 failed: {e}"))?;
        readiness_oracle.amplifier_muted_until_primed = true;

        let running = prepared
            .start_unmuted()
            .map_err(|(_, e)| format!("HAL unmute failed: {e}"))?;

        let mut clock = GroupClockEstimator::new(8, DEFAULT_MAX_ADMITTED_UNCERTAINTY_US);
        for seq in 1..=4 {
            let t1 = (seq as i64) * 10_000_000;
            let sample = ClockExchangeSample::from_four_timestamps(
                seq,
                t1,
                t1 + 400_000,
                t1 + 450_000,
                t1 + 850_000,
            )
            .map_err(|e| e.to_string())?;
            clock.ingest_sample(sample);
        }
        readiness_oracle.clock_locked = clock.is_locked();
        readiness_oracle
            .assert_can_enter_ready()
            .map_err(|e| e.to_string())?;

        let dsp = BoardProtectionDsp::new(board.clone()).map_err(|e| e.to_string())?;

        Ok(Self {
            member_id: member_id.to_string(),
            board,
            readiness: SpeakerReadinessState::ReadySynchronized,
            readiness_oracle,
            continuity_oracle: SampleContinuityOracle::new(),
            clock,
            replay_window: ReplayWindow::new(initial_epoch),
            jitter_buffer: BoundedJitterBuffer::new(PlayoutMode::Music500ms, 128),
            resampler: BoundedDriftResampler::new(),
            dsp,
            hal: running,
            rendered_blocks: 0,
            authentic_blocks: 0,
            concealed_blocks: 0,
            max_skew_us: 0,
        })
    }
}

/// Summary report emitted by a Virtual House multi-room simulation run (`Q01`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualHouseReport {
    pub group_id: String,
    pub unified_mixed_s1_s2: bool,
    pub total_blocks_streamed: u64,
    pub max_inter_speaker_skew_us: u64,
    pub within_2ms_skew_target: bool,
    pub video_sync_residual_us: i64,
    pub video_sync_within_40ms_gate: bool,
    pub dropped_log_events: u64,
    pub members: BTreeMap<String, MemberSimulationStats>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberSimulationStats {
    pub profile_id: String,
    pub legacy_sw_gen: u8,
    pub hardware_channels: u8,
    pub rendered_blocks: u64,
    pub authentic_blocks: u64,
    pub concealed_blocks: u64,
    pub verified_continuous_frames: u64,
    pub quarantined_dma_slots: usize,
    pub readiness: SpeakerReadinessState,
}

/// Run a complete deterministic Virtual House simulation across 5 mixed-generation Sonos models
/// (`S5` PowerPC S1, `S1` MIPS S1, `S12` MIPS S2, `S3` PowerPC S1, `Sub` PowerPC S1).
pub fn run_virtual_house_campaign(
    seed: u64,
    total_blocks: u64,
) -> Result<VirtualHouseReport, String> {
    let catalog = canonical_board_catalog();
    let find_board = |model: &str| -> BoardProfile {
        catalog
            .iter()
            .find(|p| p.model_number == model)
            .expect("canonical model present")
            .clone()
    };

    let fleet_specs = [
        ("spk-office-s5", find_board("S5"), ChannelRole::Stereo),
        ("spk-bedroom-s1", find_board("S1"), ChannelRole::Stereo),
        ("spk-kitchen-s12", find_board("S12"), ChannelRole::Stereo),
        ("spk-den-s3", find_board("S3"), ChannelRole::Stereo),
        ("spk-living-sub", find_board("Sub"), ChannelRole::SubLfe),
    ];

    let epoch = 1u64;
    let mut session = UnifiedGroupSession::new("grp-virtual-house", "spk-kitchen-s12", epoch);
    let mut nodes: BTreeMap<String, VirtualSpeakerNode> = BTreeMap::new();
    let mut sink = BoundedDiagnosticSink::new(512, 256 * 1024);

    let mut cmd_seq = 1u64;
    for (member_id, board, role) in fleet_specs {
        session
            .apply_command(FencedControlCommand {
                epoch,
                command_seq: cmd_seq,
                payload: GroupCommandPayload::AdmitMember {
                    member_id: member_id.to_string(),
                    board: board.clone(),
                    role,
                },
            })
            .map_err(|e| e.to_string())?;
        cmd_seq += 1;

        let node = VirtualSpeakerNode::bring_up_admitted(member_id, board, epoch)?;
        session
            .apply_command(FencedControlCommand {
                epoch,
                command_seq: cmd_seq,
                payload: GroupCommandPayload::MarkMemberClockLocked {
                    member_id: member_id.to_string(),
                },
            })
            .map_err(|e| e.to_string())?;
        cmd_seq += 1;
        nodes.insert(member_id.to_string(), node);
    }

    let mut spotify = SpotifySessionState {
        active_device_id: "spk-kitchen-s12".to_string(),
        track_uri: None,
        codec: "ogg-vorbis-320k".to_string(),
        bitrate_kbps: 320,
        playing: false,
        lookahead_compressed_bytes: 512 * 1024,
    };
    dispatch_alexa_directive(
        &mut session,
        &mut spotify,
        AlexaDirective::PlaySpotifyOnGroup {
            track_uri: "spotify:track:franken_test_01".to_string(),
        },
    )
    .map_err(|e| e.to_string())?;

    let stream_key = [0xA5u8; 32];
    let block_period_ns: u64 = 5_333_333; // 256 / 48_000 s
    let playout_horizon_ns: u64 = 500_000_000; // 500 ms

    // Create deterministic per-member network schedules
    let mut schedules: BTreeMap<String, NetworkSchedule> = nodes
        .keys()
        .enumerate()
        .map(|(idx, id)| {
            let cfg = NetworkScheduleConfig {
                seed: seed.wrapping_add(idx as u64 * 101),
                ..NetworkScheduleConfig::default()
            };
            (id.clone(), NetworkSchedule::new(cfg))
        })
        .collect();

    // Stream & render loop
    let mut max_inter_speaker_skew_us = 0u64;
    for blk_idx in 0..total_blocks {
        let start_frame = blk_idx * (FRAMES_PER_BLOCK as u64);
        let send_time_ns = blk_idx * block_period_ns;
        let pts_ns = send_time_ns + playout_horizon_ns;
        let consume_by_ns = pts_ns - block_period_ns;

        let mut src_block = StereoAudioBlock::silence(start_frame);
        let amp = ((blk_idx % 32) as f32) * 0.02 + 0.05;
        src_block.left = [amp; FRAMES_PER_BLOCK];
        src_block.right = [-amp; FRAMES_PER_BLOCK];

        let pkt = AuthenticatedStreamPacket {
            session_epoch: epoch,
            seq: blk_idx,
            start_frame,
            presentation_time_ns: pts_ns,
            consume_by_ns,
            fec_group_id: (blk_idx / 4) as u16,
            fec_index: (blk_idx % 4) as u8,
            payload: src_block.to_be_i16_bytes(),
        };
        let wire = pkt.encode_signed(&stream_key).map_err(|e| e.to_string())?;

        let mut member_dac_cursor_ns = Vec::with_capacity(nodes.len());
        for (member_id, node) in &mut nodes {
            let sched = schedules.get_mut(member_id).unwrap();
            let decision = sched.evaluate_packet(blk_idx, send_time_ns);
            if !decision.dropped
                && let Some(deliver_ns) = decision.deliver_time_ns
            {
                let verified = AuthenticatedStreamPacket::decode_and_verify(&wire, &stream_key)
                    .map_err(|e| e.to_string())?;
                if node
                    .replay_window
                    .check_and_record(verified.session_epoch, verified.seq)
                    .is_ok()
                {
                    let _ = node.jitter_buffer.push_packet(&verified, deliver_ns);
                }
            }

            let gain = session
                .effective_member_gain(member_id)
                .map_err(|e| e.to_string())?;
            node.dsp.set_volume_gain(gain);

            let pull = node.jitter_buffer.pull_for_frame(start_frame);
            let stereo_in = match pull {
                PlayoutPullDecision::AuthenticBlock(b)
                | PlayoutPullDecision::FecRecoveredBlock(b) => {
                    node.authentic_blocks += 1;
                    b
                }
                PlayoutPullDecision::PlcConcealedBlock { block, .. } => {
                    node.concealed_blocks += 1;
                    block
                }
            };

            let resampled = node
                .resampler
                .process_stereo(&stereo_in, node.clock.estimated_drift_ppm())
                .map_err(|e| e.to_string())?;
            let hw_out = node.dsp.render_block(&resampled);
            node.continuity_oracle
                .observe_block(
                    hw_out.start_frame,
                    hw_out.frames as u64,
                    &hw_out.channel_samples[0],
                )
                .map_err(|e| e.to_string())?;

            let lease = node.hal.submit_dma_block().map_err(|e| e.to_string())?;
            lease.complete();
            node.rendered_blocks += 1;

            let local_dac_ns = node
                .clock
                .map_presentation_to_local_dac_ns(pts_ns, &node.board)
                .map_err(|e| e.to_string())?;
            // Effective electrical output time adds back the board's calibrated delay
            let electrical_out_ns =
                local_dac_ns + u64::from(node.board.calibrated_output_delay_us) * 1_000;
            member_dac_cursor_ns.push(electrical_out_ns);
        }

        if let (Some(&min_ns), Some(&max_ns)) = (
            member_dac_cursor_ns.iter().min(),
            member_dac_cursor_ns.iter().max(),
        ) {
            let skew_us = (max_ns - min_ns) / 1_000;
            max_inter_speaker_skew_us = max_inter_speaker_skew_us.max(skew_us);
        }
    }

    // Exercise fsonos SOAP group volume update
    match handle_fsonos_soap(
        &mut session,
        FsonosSoapRequest::SetGroupVolume {
            epoch,
            command_seq: cmd_seq,
            desired_volume: 65,
        },
    )
    .map_err(|e| e.to_string())?
    {
        FsonosSoapResponse::StateUpdated { .. } => {}
        other => return Err(format!("unexpected SOAP response: {other:?}")),
    }

    // Exercise cooperative AirPlay 2 / YouTube video lip-sync evaluation
    let mut airplay = AirPlay2ReceiverState {
        receiver_name: "Kitchen S12".to_string(),
        paired: true,
        active_stream_kind: None,
        last_video_sync: None,
    };
    let video_eval = airplay
        .evaluate_youtube_video_sync(
            &LatencyLedger {
                network_ingress_us: 2_500,
                jitter_buffer_target_us: 45_000,
                dsp_block_period_us: 5_333,
                dma_queue_us: 5_333,
                calibrated_dac_delay_us: 1_400,
                calibration_uncertainty_us: 200,
            },
            58_000,
        )
        .map_err(|e| e.to_string())?;

    sink.try_emit(DiagnosticEvent {
        schema_version: String::new(),
        timestamp_mono_ns: total_blocks * block_period_ns,
        run_id: format!("vh-seed-{seed}"),
        case_id: "Q01-virtual-house".to_string(),
        correlation_id: "corr-vh-1".to_string(),
        member_id: "spk-kitchen-s12".to_string(),
        group_id: session.group_id.clone(),
        source_epoch: session.current_epoch,
        state_revision: session.state_revision,
        event_kind: "campaign_complete".to_string(),
        message: "virtual house multi-room simulation finished".to_string(),
        queue_depth: 0,
        latency_us: max_inter_speaker_skew_us,
    });

    let mut member_stats = BTreeMap::new();
    for (id, node) in &nodes {
        let hal_t = node.hal.telemetry();
        member_stats.insert(
            id.clone(),
            MemberSimulationStats {
                profile_id: node.board.profile_id.clone(),
                legacy_sw_gen: node.board.legacy_sw_gen_hint,
                hardware_channels: node.board.hardware_channels,
                rendered_blocks: node.rendered_blocks,
                authentic_blocks: node.authentic_blocks,
                concealed_blocks: node.concealed_blocks,
                verified_continuous_frames: node.continuity_oracle.verified_frames(),
                quarantined_dma_slots: hal_t.quarantined_dma_slots,
                readiness: node.readiness.clone(),
            },
        );
    }

    Ok(VirtualHouseReport {
        group_id: session.group_id.clone(),
        unified_mixed_s1_s2: session.is_unified_mixed_generation_group(),
        total_blocks_streamed: total_blocks,
        max_inter_speaker_skew_us,
        within_2ms_skew_target: max_inter_speaker_skew_us <= 2_000,
        video_sync_residual_us: video_eval.residual_av_skew_us,
        video_sync_within_40ms_gate: video_eval.within_40ms_p99_gate,
        dropped_log_events: sink.dropped_event_count(),
        members: member_stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_house_streams_mixed_s1_s2_fleet_with_zero_output_discontinuities() {
        let report = run_virtual_house_campaign(0x2026_1104, 200).unwrap();
        assert!(report.unified_mixed_s1_s2);
        assert!(report.within_2ms_skew_target);
        assert!(report.video_sync_within_40ms_gate);
        assert_eq!(report.members.len(), 5);
        for (id, stats) in &report.members {
            assert_eq!(stats.rendered_blocks, 200, "member {id} missed blocks");
            assert_eq!(
                stats.verified_continuous_frames,
                200 * (FRAMES_PER_BLOCK as u64),
                "member {id} had frame discontinuity"
            );
            assert_eq!(stats.quarantined_dma_slots, 0);
            assert_eq!(stats.readiness, SpeakerReadinessState::ReadySynchronized);
        }
    }
}
