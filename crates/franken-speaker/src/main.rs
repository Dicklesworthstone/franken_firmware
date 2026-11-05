//! FrankenSpeaker CLI & Virtual House runner (`franken-speaker`).

#![forbid(unsafe_code)]

use franken_board_profile::canonical_board_catalog;
#[cfg(feature = "harness")]
use franken_speaker::run_virtual_house_campaign;
use std::env;
use std::process::ExitCode;

/// The campaign `--virtual-house` runs. The tests below run the same one, so they judge what the command line does.
#[cfg(feature = "harness")]
const SEED: u64 = 0x2026_1104;
#[cfg(feature = "harness")]
const BLOCKS: u64 = 250;

/// Whether a Virtual House report meets every gate the exit code of `--virtual-house` stands for: the fleet is a
/// unified mixed S1/S2 group, the skew target was met by a measurement, the video-sync bound holds, and the
/// evidence is complete. A report whose critical evidence could not be stored (`evidence_complete == false`) is
/// incomplete and, in the words of its own documentation, "must not be read as a clean pass", so it cannot exit 0.
#[cfg(feature = "harness")]
fn virtual_house_passes(report: &franken_speaker::VirtualHouseReport) -> bool {
    report.unified_mixed_s1_s2
        && report.within_2ms_skew_target
        && report.video_sync_within_40ms_gate
        && report.evidence_complete
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    // The harness is a test tool: only a build with the `harness` feature runs it by default.
    let default_mode = if cfg!(feature = "harness") {
        "--virtual-house"
    } else {
        "--catalog"
    };
    let mode = args.get(1).map(String::as_str).unwrap_or(default_mode);

    match mode {
        "--catalog" => {
            let catalog = canonical_board_catalog();
            match serde_json::to_string_pretty(&catalog) {
                Ok(json) => {
                    println!("{json}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("serialization error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        #[cfg(feature = "harness")]
        "--virtual-house" | "--self-test" => match run_virtual_house_campaign(SEED, BLOCKS) {
            Ok(report) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_default()
                );
                if virtual_house_passes(&report) {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Err(err) => {
                eprintln!("virtual house failure: {err}");
                ExitCode::FAILURE
            }
        },
        #[cfg(not(feature = "harness"))]
        "--virtual-house" | "--self-test" => {
            eprintln!(
                "this build has no Virtual House harness; rebuild with `--features harness` to run {mode}"
            );
            ExitCode::from(2)
        }
        other => {
            eprintln!(
                "Usage: franken-speaker [--catalog|--virtual-house|--self-test] (got {other}); \
                 --virtual-house and --self-test need a build with `--features harness`"
            );
            ExitCode::from(2)
        }
    }
}

#[cfg(all(test, feature = "harness"))]
mod tests {
    use super::*;
    use franken_speaker::VirtualHouseReport;
    use std::sync::OnceLock;

    /// The report `--virtual-house` prints, computed once for all the tests below.
    fn nominal() -> &'static VirtualHouseReport {
        static REPORT: OnceLock<VirtualHouseReport> = OnceLock::new();
        REPORT.get_or_init(|| {
            run_virtual_house_campaign(SEED, BLOCKS).expect("the campaign `--virtual-house` runs")
        })
    }

    #[test]
    fn the_nominal_virtual_house_campaign_still_exits_zero() {
        let report = nominal();
        // A healthy sink stores the campaign summary, so requiring complete evidence costs the nominal run nothing.
        assert!(report.evidence_complete);
        assert!(report.unified_mixed_s1_s2);
        assert!(report.within_2ms_skew_target);
        assert!(report.video_sync_within_40ms_gate);
        assert!(virtual_house_passes(report));
    }

    #[test]
    fn a_report_with_incomplete_evidence_cannot_exit_zero_although_the_old_condition_passed_it() {
        // Planted: the nominal report with only its evidence flag cleared, which is what a sink that could not store
        // the campaign summary produces (the harness's own tests show a zero-capacity sink doing exactly that).
        let mut report = nominal().clone();
        report.evidence_complete = false;
        assert!(
            report.unified_mixed_s1_s2
                && report.within_2ms_skew_target
                && report.video_sync_within_40ms_gate,
            "the exit condition as it stood, without the evidence term, called this a pass"
        );
        assert!(!virtual_house_passes(&report));
    }

    #[test]
    fn each_of_the_four_gates_alone_is_enough_to_fail_the_exit() {
        for gate in [
            "unified_mixed_s1_s2",
            "within_2ms_skew_target",
            "video_sync_within_40ms_gate",
            "evidence_complete",
        ] {
            let mut report = nominal().clone();
            match gate {
                "unified_mixed_s1_s2" => report.unified_mixed_s1_s2 = false,
                "within_2ms_skew_target" => report.within_2ms_skew_target = false,
                "video_sync_within_40ms_gate" => report.video_sync_within_40ms_gate = false,
                "evidence_complete" => report.evidence_complete = false,
                other => panic!("unknown gate {other}"),
            }
            assert!(!virtual_house_passes(&report), "{gate}");
        }
    }
}
