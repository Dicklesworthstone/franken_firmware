//! Runs the bounded N05 worker on the Cargo/RCH host. Passing this test means only that
//! observations were collected. The external Python judge requires these observations AND
//! all required unit/allocation results from this same source-bound Cargo log.
#![forbid(unsafe_code)]

use std::io::Write;
use std::path::Path;
use std::process::Command;

#[test]
fn n05_remote_worker_observations_complete() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let output = Command::new("python3")
        .arg(root.join("tests/n05/run_cases.py"))
        .args(["--tier", "full", "--observe-only", "--worker"])
        .arg(env!("CARGO_BIN_EXE_n05_repair_study"))
        .current_dir(root)
        .output()
        .expect("execute Python observation collector on the Cargo/RCH host");
    // Forward real evidence even on failure. Never suppress stderr or manufacture receipts.
    std::io::stdout().lock().write_all(&output.stdout).unwrap();
    std::io::stderr().lock().write_all(&output.stderr).unwrap();
    assert!(
        output.stdout.len() <= 2 * 1024 * 1024,
        "critical observation output exceeded cap"
    );
    assert!(
        output.stderr.len() <= 256 * 1024,
        "critical worker stderr exceeded cap"
    );
    assert!(
        output.status.success(),
        "observation collection failed: {}",
        output.status
    );
    let text = std::str::from_utf8(&output.stdout).expect("UTF-8 observation protocol");
    let ends: Vec<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix("N05-RUN-END "))
        .collect();
    assert_eq!(
        ends.len(),
        1,
        "exactly one complete observation campaign required"
    );
    let end: serde_json::Value = serde_json::from_str(ends[0]).expect("versioned campaign end");
    assert_eq!(end["schema"], "n05.observation-run.v1");
    assert_eq!(end["mode"], "observe-only");
    assert_eq!(
        end["qualified"], false,
        "collection must never self-qualify"
    );
    assert_eq!(
        end["observations"], 37,
        "36 strategy observations plus actual restart required"
    );
    assert_eq!(end["observed_cases"], 9);
    assert_eq!(end["failed"], 0);
    assert_eq!(end["critical_evidence_lost"], 0);
}
