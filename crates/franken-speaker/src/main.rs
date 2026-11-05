//! FrankenSpeaker CLI & Virtual House runner (`franken-speaker`).

#![forbid(unsafe_code)]

use franken_board_profile::canonical_board_catalog;
#[cfg(feature = "harness")]
use franken_speaker::run_virtual_house_campaign;
use std::env;
use std::process::ExitCode;

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
        "--virtual-house" | "--self-test" => match run_virtual_house_campaign(0x2026_1104, 250) {
            Ok(report) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_default()
                );
                if report.unified_mixed_s1_s2
                    && report.within_2ms_skew_target
                    && report.video_sync_within_40ms_gate
                {
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
