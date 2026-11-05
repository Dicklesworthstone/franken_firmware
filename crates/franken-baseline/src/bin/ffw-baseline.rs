//! `ffw-baseline`: run the E02 analyzer over a capture file and print the report as one line of JSON on stdout, then one
//! concise human summary line on stderr (see `franken_baseline::summary`).
//!
//! ```text
//! ffw-baseline series  <capture>                       time-series report
//! ffw-baseline memory  <snapshots>                     memory ledger report
//! ffw-baseline compare <current> [--baseline <capture>] [--margin-pct N]
//! ```
//!
//! Exit codes: 0 a report was written; 2 bad usage or unreadable or malformed input (a one-line
//! diagnostic on stderr, no report and no summary); 3 `compare` refused to make a comparative claim (the reason is in the
//! JSON, and the summary says refused).
//! Nothing here touches a device, a network or the clock: it reads the files it is given.

use std::process::ExitCode;

use franken_baseline::capture::Capture;
use franken_baseline::compare::{Baseline, compare};
use franken_baseline::json::Json;
use franken_baseline::memory::{account, parse_memory};
use franken_baseline::parse::{bounded, parse_u64};
use franken_baseline::series::analyze;
use franken_baseline::summary;

const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const USAGE: &str = "usage: ffw-baseline series <capture> | memory <snapshots> | \
compare <current> [--baseline <capture>] [--margin-pct N]";

/// The last path component only: diagnostics never repeat a directory layout.
fn short(path: &str) -> String {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    bounded(name)
}

fn read(path: &str) -> Result<String, String> {
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("cannot stat {}: {:?}", short(path), e.kind()))?;
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!(
            "{} is larger than {MAX_FILE_BYTES} bytes",
            short(path)
        ));
    }
    std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {:?}", short(path), e.kind()))
}

fn load_series(path: &str) -> Result<franken_baseline::series::SeriesReport, String> {
    let text = read(path)?;
    let capture = Capture::parse(&text).map_err(|e| format!("{}: {e}", short(path)))?;
    Ok(analyze(&capture))
}

fn emit(json: &Json) {
    println!("{}", json.render());
}

/// The one human summary line, on stderr after the JSON report on stdout.
fn note(line: &str) {
    eprintln!("{line}");
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    let Some(cmd) = args.first() else {
        return Err(USAGE.to_string());
    };
    match cmd.as_str() {
        "series" => {
            let [_, path] = args else {
                return Err(USAGE.to_string());
            };
            let report = load_series(path)?.to_json();
            emit(&report);
            note(&summary::series(&report));
            Ok(ExitCode::SUCCESS)
        }
        "memory" => {
            let [_, path] = args else {
                return Err(USAGE.to_string());
            };
            let text = read(path)?;
            let capture = parse_memory(&text).map_err(|e| format!("{}: {e}", short(path)))?;
            let report = account(&capture).to_json();
            emit(&report);
            note(&summary::memory(&report));
            Ok(ExitCode::SUCCESS)
        }
        "compare" => run_compare(&args[1..]),
        _ => Err(USAGE.to_string()),
    }
}

fn run_compare(args: &[String]) -> Result<ExitCode, String> {
    let mut current: Option<&String> = None;
    let mut baseline_path: Option<&String> = None;
    let mut margin_pct: u64 = 10;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--baseline" => baseline_path = Some(it.next().ok_or_else(|| USAGE.to_string())?),
            "--margin-pct" => {
                let v = it.next().ok_or_else(|| USAGE.to_string())?;
                margin_pct =
                    parse_u64(v).ok_or_else(|| "--margin-pct needs an integer".to_string())?;
            }
            _ if arg.starts_with("--") => return Err(USAGE.to_string()),
            _ => {
                if current.is_some() {
                    return Err(USAGE.to_string());
                }
                current = Some(arg);
            }
        }
    }
    let current = current.ok_or_else(|| USAGE.to_string())?;
    let current_report = load_series(current)?;
    let current_summary = current_report.summary();

    // A baseline that cannot be a baseline is reported as the refusal reason, not as an input error.
    let mut baseline_refusal: Option<&'static str> = None;
    let mut baseline: Option<Baseline> = None;
    if let Some(path) = baseline_path {
        match Baseline::new(load_series(path)?.summary()) {
            Ok(b) => baseline = Some(b),
            Err(e) => baseline_refusal = Some(e.as_str()),
        }
    }

    let (claim, reason, comparison) = match baseline_refusal {
        Some(reason) => ("refused", Json::str(reason), Json::Null),
        None => match compare(&current_summary, baseline.as_ref(), margin_pct) {
            Ok(c) => ("made", Json::Null, c.to_json()),
            Err(refused) => ("refused", Json::str(refused.as_str()), Json::Null),
        },
    };
    let report = Json::obj(vec![
        ("schema", Json::str("ffw.baseline.comparison.v1")),
        ("claim", Json::str(claim)),
        ("reason", reason),
        ("comparison", comparison),
        (
            "current_evidence",
            Json::str(current_summary.evidence.as_str()),
        ),
        ("current_profile", Json::str(&current_summary.profile)),
    ]);
    emit(&report);
    note(&summary::comparison(&report));
    Ok(if claim == "made" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(2)
        }
    }
}
