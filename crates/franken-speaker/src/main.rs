//! FrankenSpeaker CLI & Virtual House runner (`franken-speaker`).

#![forbid(unsafe_code)]

use franken_board_profile::canonical_board_catalog;
use franken_speaker::run_virtual_house_campaign;
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("--virtual-house");

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
        other => {
            eprintln!(
                "Usage: franken-speaker [--virtual-house|--self-test|--catalog] (got {other})"
            );
            ExitCode::from(2)
        }
    }
}
