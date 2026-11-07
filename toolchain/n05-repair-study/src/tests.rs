use super::*;
use franken_stream::playout::{
    Admission, ClockView, MediaPacket, Outcome, PlayoutConfig, PlayoutEngine, PlayoutProfile, Poll,
    RepairBlock,
};

fn input(scenario: Scenario, strategy: Strategy) -> StudyInput {
    StudyInput {
        scenario,
        strategy,
        seed: 0x5eed05,
    }
}
fn source(window: usize) -> Vec<CodingSymbol> {
    (0..4)
        .map(|esi| {
            symbol(
                context(window),
                esi as u32,
                source_payload(window * 4 + esi),
            )
        })
        .collect()
}
fn view(now: u64) -> ClockView {
    ClockView {
        group_ns: now,
        uncertainty_ns: UNCERTAINTY_NS,
        usable: true,
    }
}

#[test]
fn n05_same_media_trace_packetization_cutoffs_and_allowance() {
    for scenario in Scenario::ALL {
        let results: Vec<_> = Strategy::ALL
            .into_iter()
            .map(|s| run(input(scenario, s)).unwrap())
            .collect();
        for result in &results {
            assert_eq!(result.source_trace_sha256, results[0].source_trace_sha256);
            assert_eq!(result.payload_sha256, results[0].payload_sha256);
            assert_eq!(result.resources.work_allowance_per_window_ns, 20_000_000);
            assert!(result.resources.max_window_work_ns <= 20_000_000);
            assert_eq!(result.output.len(), 64);
            for (block, out) in result.output.iter().enumerate() {
                let presentation = 500_000_000 + block as u64 * 256 * 1_000_000_000 / 48_000;
                assert_eq!(out.block, block);
                assert_eq!(out.consume_by_ns, presentation - 2_500_000);
                assert_eq!(out.presentation_ns, presentation);
                assert_eq!(
                    out.late_by_ns, 0,
                    "guarded repair work cannot defer a pending consumption"
                );
                assert_eq!(
                    out.render_late_by_ns, 0,
                    "same-thread downstream work must also be protected"
                );
            }
            assert_eq!(
                result.repair.attempts,
                result.repair.admitted + result.repair.late + result.repair.duplicate
            );
            if matches!(scenario, Scenario::Independent | Scenario::Burst) {
                assert_eq!(result.resources.source_duplicates_seen, 3);
                assert_eq!(result.resources.source_duplicates_admitted_as_duplicate, 3);
            }
        }
    }
}

#[test]
fn n05_rfc6330_positive_two_erasure_recovery_and_zero_loss_cost() {
    let clean = run(input(Scenario::Clean, Strategy::Raptorq)).unwrap();
    assert_eq!(clean.resources.repair_air_bytes, 64 * 1108);
    assert!(clean.resources.sender_encode_host_elapsed_ns > 0);
    assert_eq!(clean.resources.library_attempts, 0);
    let plain = run(input(Scenario::PositiveRecovery, Strategy::Concealment)).unwrap();
    assert_eq!(plain.unrecovered_blocks, [4, 5]);
    let fec = run(input(Scenario::PositiveRecovery, Strategy::Raptorq)).unwrap();
    assert_eq!(fec.repair.admitted, 2);
    assert!(fec.unrecovered_blocks.is_empty());
    assert_eq!(fec.resources.library_attempts, 1);
    assert!(fec.resources.decode_work.peeled + fec.resources.decode_work.gauss_ops > 0);
}

#[test]
fn n05_entire_coding_window_is_unrecoverable_not_a_fec_win() {
    for strategy in Strategy::ALL {
        let result = run(input(Scenario::CodingWindowOutage, strategy)).unwrap();
        assert_eq!(result.unrecovered_blocks, [4, 5, 6, 7]);
        assert_eq!(result.output[8].outcome, "real");
        if strategy == Strategy::Raptorq {
            assert_eq!(result.repair.no_information_window_ids, [1]);
        }
    }
    let burst = run(input(Scenario::Burst, Strategy::Raptorq)).unwrap();
    assert_eq!(burst.unrecovered_blocks, (19..36).collect::<Vec<_>>());
    assert_eq!(burst.repair.no_information_window_ids, [5, 6, 7, 8]);
    assert_eq!(burst.repair.insufficient_window_ids, [4]);
    assert_eq!(burst.repair.decode_window_ids, [9]);
}

#[test]
fn n05_late_and_exhausted_repairs_never_starve_the_next_block() {
    for scenario in [
        Scenario::LateRepair,
        Scenario::WorkExhausted,
        Scenario::Cancelled,
    ] {
        for strategy in [Strategy::Retransmit, Strategy::Raptorq, Strategy::Hybrid] {
            let result = run(input(scenario, strategy)).unwrap();
            assert_eq!(result.unrecovered_blocks, [4, 5]);
            assert_eq!(result.output[6].outcome, "real");
            assert_eq!(result.output[6].late_by_ns, 0);
            if scenario == Scenario::LateRepair {
                assert_eq!(result.repair.admitted, 0);
                if strategy == Strategy::Retransmit {
                    assert_eq!(result.repair.late, 0);
                    assert_eq!(result.repair.deadline_refusals, 2);
                    assert_eq!(result.resources.repair_air_bytes, 0);
                    assert_eq!(result.resources.feedback_air_bytes, 0);
                } else {
                    assert_eq!(result.repair.deadline_refusals, 1);
                }
            } else {
                // A second damaged window must recover in THIS run after the refused/cancelled job.
                assert_eq!(result.repair.admitted, 2);
                assert_eq!(result.output[12].outcome, "real");
                assert_eq!(result.output[13].outcome, "real");
                if scenario == Scenario::WorkExhausted {
                    assert!(result.repair.work_refusals > 0);
                } else {
                    assert_eq!(result.repair.cancelled_windows, 1);
                }
            }
        }
    }
}

#[test]
fn n05_partial_salvage_keeps_the_still_live_block_and_n04_counts_late() {
    for strategy in [Strategy::Retransmit, Strategy::Raptorq, Strategy::Hybrid] {
        let result = run(input(Scenario::PartialSalvage, strategy)).unwrap();
        assert_eq!(result.unrecovered_blocks, [4]);
        assert_eq!(
            result.repair.late,
            u64::from(strategy != Strategy::Retransmit)
        );
        assert_eq!(result.repair.admitted, 1);
        if strategy == Strategy::Retransmit {
            assert_eq!(result.repair.deadline_refusals, 1);
            assert_eq!(result.resources.repair_air_bytes, 1104);
            assert_eq!(result.resources.work_charged_ns, REQUEST_COST_NS);
        }
        assert!(result.output.iter().all(|block| block.late_by_ns == 0));
        assert_eq!(result.output[5].outcome, "real");
        assert_eq!(result.output[5].late_by_ns, 0);
        assert_eq!(result.output[6].outcome, "real");
        assert_eq!(result.output[6].late_by_ns, 0);
    }
}

#[test]
fn n05_actual_decoded_bytes_rejected_after_consume_before_dac() {
    let source = source(0);
    let mut received = source[2..].to_vec();
    received.extend(encode_repairs(context(0), &source, 42).unwrap());
    let decoded = decode_window(context(0), 42, &received).unwrap();
    assert_eq!(
        decoded.source,
        source.iter().map(|s| s.payload.clone()).collect::<Vec<_>>()
    );
    for delta in [-1_i64, 0, 1] {
        let mut engine = PlayoutEngine::new(
            PlayoutProfile::MUSIC,
            PlayoutConfig {
                work_ns: WORK_NS,
                lead_ns: LEAD_NS,
                tolerance_ns: 0,
            },
        )
        .unwrap();
        engine.begin_stream(1, 0, ORIGIN_NS).unwrap();
        let at = cutoff(0).checked_add_signed(delta).unwrap();
        assert!(at < presentation(0));
        let admission = engine.on_repair(
            view(at),
            &RepairBlock {
                epoch: 1,
                start_frame: 0,
                frames: 256,
                payload: &decoded.source[0],
            },
        );
        assert_eq!(
            admission,
            if delta < 0 {
                Admission::Admitted
            } else {
                Admission::Late
            }
        );
        let now = at.max(cutoff(0));
        let mut bytes = [0; 1024];
        assert!(
            matches!(engine.decide(view(now), &mut bytes), Poll::Decision(d) if d.outcome == if delta < 0 { Outcome::Real } else { Outcome::MutedNoHistory })
        );
        assert_eq!(
            engine.on_packet(
                view(now),
                &MediaPacket {
                    epoch: 1,
                    start_frame: 256,
                    presentation_ns: presentation(1),
                    frames: 256,
                    payload: &decoded.source[1]
                }
            ),
            Admission::Admitted
        );
        assert!(
            matches!(engine.decide(view(cutoff(1)), &mut bytes), Poll::Decision(d) if d.block == 1 && d.outcome == Outcome::Real)
        );
        assert_eq!(engine.snapshot().cursor, 2);
    }
}

#[test]
fn n05_malformed_metadata_does_not_enter_the_coder() {
    let source = source(0);
    let mut received = source[2..].to_vec();
    received.extend(encode_repairs(context(0), &source, 7).unwrap());
    assert!(decode_window(context(0), 7, &received).is_ok());
    for which in 0..8 {
        let mut bad = received.clone();
        match which {
            0 => bad[2].meta.stream = 2,
            1 => bad[2].meta.epoch = 2,
            2 => bad[2].meta.window = 1,
            3 => bad[2].meta.source_symbols = usize::MAX,
            4 => bad[2].meta.symbol_bytes = usize::MAX,
            5 => bad[2].meta.esi = u32::MAX,
            6 => bad[2].meta.esi = bad[0].meta.esi,
            _ => {
                bad[2].payload.pop();
            }
        }
        assert!(matches!(
            decode_window(context(0), 7, &bad),
            Err(DecodeReject::Metadata(_))
        ));
    }
    let mut excess = received.clone();
    excess.extend(received.clone());
    assert_eq!(
        decode_window(context(0), 7, &excess).unwrap_err(),
        DecodeReject::Metadata(SymbolReject::Count)
    );
}

#[test]
fn n05_restart_reproduces_trace_without_retaining_cancelled_window() {
    let result = run(input(Scenario::Cancelled, Strategy::Raptorq)).unwrap();
    assert_eq!(result.repair.cancelled_windows, 1);
    assert_eq!(result.repair.decode_window_ids, [3]);
    assert_eq!(result.repair.admitted, 2);
    let restarted = run(input(Scenario::PositiveRecovery, Strategy::Raptorq)).unwrap();
    let fresh = run(input(Scenario::PositiveRecovery, Strategy::Raptorq)).unwrap();
    assert_eq!(restarted.source_trace_sha256, fresh.source_trace_sha256);
    assert_eq!(
        restarted
            .output
            .iter()
            .map(|b| &b.payload_sha256)
            .collect::<Vec<_>>(),
        fresh
            .output
            .iter()
            .map(|b| &b.payload_sha256)
            .collect::<Vec<_>>()
    );
}

#[test]
fn n05_inline_overrun_control_exposes_why_work_admission_matters() {
    for strategy in [Strategy::Retransmit, Strategy::Raptorq] {
        let guarded = run(input(Scenario::WorkExhausted, strategy)).unwrap();
        let bypassed = run_control(input(Scenario::WorkExhausted, strategy), false, 0).unwrap();
        assert_eq!(guarded.output[6].outcome, "real");
        assert_eq!(guarded.output[6].late_by_ns, 0);
        assert_eq!(bypassed.output[6].outcome, "muted_overdue");
        assert!(bypassed.output[6].late_by_ns > 100_000_000);
        println!(
            "N05-GATE-OBSERVED {}",
            serde_json::json!({"schema":"n05.gate-control.v1", "strategy":strategy,
            "guarded_next_outcome":guarded.output[6].outcome,"guarded_next_late_ns":guarded.output[6].late_by_ns,
            "bypassed_next_outcome":bypassed.output[6].outcome,"bypassed_next_late_ns":bypassed.output[6].late_by_ns,
            "planted_virtual_job_ns":600_000_000,"shared_window_allowance_ns":20_000_000})
        );
    }
}

#[test]
fn n05_host_reserve_violation_never_retimes_trace() {
    let normal = run(input(Scenario::Burst, Strategy::Raptorq)).unwrap();
    let slow = run_control(input(Scenario::Burst, Strategy::Raptorq), true, 9_000_000).unwrap();
    assert_eq!(normal.source_trace_sha256, slow.source_trace_sha256);
    assert_eq!(normal.unrecovered_blocks, slow.unrecovered_blocks);
    assert_eq!(normal.unrecovered_blocks, (19..36).collect::<Vec<_>>());
    assert!(slow.resources.work_overruns >= 16);
    assert_eq!(
        normal
            .output
            .iter()
            .map(|b| &b.payload_sha256)
            .collect::<Vec<_>>(),
        slow.output
            .iter()
            .map(|b| &b.payload_sha256)
            .collect::<Vec<_>>()
    );
}

#[test]
fn n05_hybrid_executes_fec_then_a_bounded_tail_for_remaining_originals() {
    let clean = run(input(Scenario::Clean, Strategy::Hybrid)).unwrap();
    assert_eq!(clean.resources.repair_air_bytes, 64 * 1108);
    assert_eq!(clean.tail.requested, 0);
    let positive = run(input(Scenario::PositiveRecovery, Strategy::Hybrid)).unwrap();
    assert_eq!(positive.resources.library_attempts, 1);
    assert_eq!(positive.repair.admitted, 2);
    assert_eq!(positive.tail.admitted, 0);
    let burst = run(input(Scenario::Burst, Strategy::Hybrid)).unwrap();
    assert_eq!(burst.unrecovered_blocks, [19]);
    assert_eq!(burst.tail.recovered_blocks, (20..36).collect::<Vec<_>>());
    assert_eq!(burst.tail.requested, 17);
    assert_eq!(burst.tail.admitted, 17);
    assert_eq!(burst.tail.received, 16);
    assert_eq!(burst.tail.admitted_to_playout, 16);
    assert_eq!(burst.tail.late, 0);
    assert_eq!(burst.tail.duplicate, 0);
    assert_eq!(burst.tail.feedback_messages, 5);
    assert_eq!(burst.tail.max_outstanding, 4);
    assert_eq!(burst.resources.work_charged_ns, 17_850_000);
    assert_eq!(burst.resources.repair_air_bytes, 89_680);
    let outage = run(input(Scenario::CodingWindowOutage, Strategy::Hybrid)).unwrap();
    assert_eq!(outage.tail.admitted, 4);
    assert_eq!(outage.tail.received, 0);
    assert_eq!(outage.unrecovered_blocks, [4, 5, 6, 7]);
}

#[test]
fn n05_hybrid_deadline_work_cancel_and_restart_keep_real_recovery() {
    for scenario in [
        Scenario::LateRepair,
        Scenario::PartialSalvage,
        Scenario::WorkExhausted,
        Scenario::Cancelled,
    ] {
        let result = run(input(scenario, Strategy::Hybrid)).unwrap();
        assert_eq!(result.tail.admitted, 0);
        assert_eq!(result.tail.air_bytes, 0);
        assert_eq!(result.tail.feedback_air_bytes, 0);
        assert_eq!(result.tail.work_charged_ns, 0);
        assert_eq!(result.tail.admitted_to_playout, 0);
        assert_eq!(result.resources.max_render_late_by_ns, 0);
        if matches!(scenario, Scenario::WorkExhausted | Scenario::Cancelled) {
            assert_eq!(result.repair.admitted, 2);
            assert_eq!(result.output[12].outcome, "real");
            assert_eq!(result.output[13].outcome, "real");
        }
    }
    let restarted = run(input(Scenario::PositiveRecovery, Strategy::Hybrid)).unwrap();
    assert!(restarted.unrecovered_blocks.is_empty());
    assert_eq!(restarted.resources.library_attempts, 1);
    assert_eq!(restarted.tail.requested, 0);
}

#[test]
fn n05_retransmit_and_hybrid_tail_share_the_same_admission_ledger() {
    let baseline = run(input(Scenario::LateRepair, Strategy::Retransmit)).unwrap();
    let hybrid = run(input(Scenario::LateRepair, Strategy::Hybrid)).unwrap();
    assert_eq!(baseline.repair.deadline_refusals, 2);
    assert_eq!(hybrid.tail.refused_deadline, 2);
    assert_eq!(baseline.resources.repair_air_bytes, 0);
    assert_eq!(baseline.resources.feedback_air_bytes, 0);
    assert_eq!(baseline.resources.work_charged_ns, 0);
    assert_eq!(hybrid.tail.air_bytes, 0);
    assert_eq!(hybrid.tail.feedback_air_bytes, 0);
    assert_eq!(hybrid.tail.work_charged_ns, 0);
    // The strict rule refuses BEFORE dispatch. The explicit bypass still exercises
    // actual N04 Late admission, rather than deleting the late-accounting capability.
    let bypass = run_control(input(Scenario::LateRepair, Strategy::Retransmit), false, 0).unwrap();
    assert_eq!(bypass.repair.late, 2);
    assert_eq!(bypass.repair.admitted, 0);
    assert_eq!(bypass.resources.repair_air_bytes, 2208);
    assert_eq!(bypass.resources.feedback_air_bytes, FEEDBACK_BYTES);
    assert_eq!(bypass.resources.work_charged_ns, 2 * REQUEST_COST_NS);
    assert_eq!(bypass.output[6].outcome, "real");
    assert_eq!(baseline.unrecovered_blocks, bypass.unrecovered_blocks);
    let permitted = run(input(Scenario::PositiveRecovery, Strategy::Retransmit)).unwrap();
    assert_eq!(permitted.repair.admitted, 2);
    assert_eq!(permitted.resources.repair_air_bytes, 2208);
    assert_eq!(permitted.resources.feedback_air_bytes, FEEDBACK_BYTES);
}

#[test]
fn n05_hybrid_tail_actual_late_and_duplicate_use_n04_admission() {
    let guarded = run(input(Scenario::LateRepair, Strategy::Hybrid)).unwrap();
    assert_eq!(guarded.tail.admitted, 0);
    let late = run_control(input(Scenario::LateRepair, Strategy::Hybrid), false, 0).unwrap();
    assert_eq!(late.tail.admitted, 2);
    assert_eq!(late.tail.received, 2);
    assert_eq!(late.tail.admitted_to_playout, 0);
    assert_eq!(late.tail.late, 2);
    assert_eq!(late.tail.duplicate, 0);
    assert!(late.tail.recovered_blocks.is_empty());
    assert_eq!(late.unrecovered_blocks, [4, 5]);
    assert_eq!(late.output[6].outcome, "real");
    let normal = run(input(Scenario::Burst, Strategy::Hybrid)).unwrap();
    let duplicate = run_tail_duplicate_control(input(Scenario::Burst, Strategy::Hybrid)).unwrap();
    assert_eq!(duplicate.tail.received, 32);
    assert_eq!(duplicate.tail.admitted_to_playout, 16);
    assert_eq!(duplicate.tail.late, 0);
    assert_eq!(duplicate.tail.duplicate, 16);
    assert_eq!(
        duplicate.tail.recovered_blocks,
        normal.tail.recovered_blocks
    );
    assert_eq!(duplicate.unrecovered_blocks, normal.unrecovered_blocks);
    assert_eq!(
        duplicate.resources.repair_air_bytes,
        normal.resources.repair_air_bytes
    );
    assert_eq!(
        duplicate.resources.work_charged_ns,
        normal.resources.work_charged_ns
    );
    assert_eq!(
        duplicate
            .output
            .iter()
            .map(|b| &b.payload_sha256)
            .collect::<Vec<_>>(),
        normal
            .output
            .iter()
            .map(|b| &b.payload_sha256)
            .collect::<Vec<_>>()
    );
    for (kind, result) in [("late", late), ("duplicate", duplicate)] {
        assert_eq!(
            result.tail.received,
            result.tail.admitted_to_playout + result.tail.late + result.tail.duplicate
        );
        println!(
            "N05-TAIL-OBSERVED {}",
            serde_json::json!({
                "schema":"n05.tail-control.v1", "kind":kind, "accounting":result.tail,
                "next_block_real":result.output[6].outcome=="real", "unrecovered_blocks":result.unrecovered_blocks
            })
        );
    }
}
