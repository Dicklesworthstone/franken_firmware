//! The concise human summary line (bead ffw-za4, Logging clause: "versioned structured JSONL plus concise human summary").
//!
//! `ffw-baseline` prints its report as one line of JSON on stdout and then ONE summary line on stderr. The line is
//! derived only from the report's own fields, read back out of the [`Json`] value that was just printed, so it can
//! say nothing the report does not. What that means for the reader:
//!
//! * A value the report does not carry reads `?`, never a guess.
//! * `null` is not zero. A dropout count the capture cannot give reads `unknown`; a cause the capture cannot tell reads
//!   `undetermined`; a figure the kernel did not provide reads `unknown`; a reserve nobody declared reads `not declared`.
//! * A refused comparison reads `claim refused`, with the report's own reason word.
//! * Only numbers and the fixed words the analyzer itself chose appear: no profile, series name, snapshot label or process
//!   name, so no input text can leave through the summary whatever the input held.
//!
//! The wording is fixed by the table in `docs/contracts/e02.md` ("The summary line"); `tests/e02/oracle.py` derives the same
//! line independently from its own report and compares it with a hand-written line in `tests/e02/cases.json`.

use crate::json::Json;

/// How a value the report does not carry reads. The summary never makes one up.
const MISSING: &str = "?";

/// The causes of a dropout, in the order the summary lists them.
const CAUSES: [&str; 6] = [
    "source_outage",
    "network_lateness",
    "cpu_deadline_miss",
    "output_underrun",
    "ambiguous",
    "undetermined",
];

fn at<'a>(report: &'a Json, path: &[&str]) -> Option<&'a Json> {
    let mut cur = report;
    for key in path {
        cur = cur.get(key)?;
    }
    Some(cur)
}

/// A string field of the report.
fn word(report: &Json, path: &[&str]) -> String {
    match at(report, path) {
        Some(Json::Str(s)) => s.clone(),
        _ => MISSING.to_string(),
    }
}

/// An integer field of the report.
fn int(report: &Json, path: &[&str]) -> String {
    match at(report, path) {
        Some(Json::Int(n)) => n.to_string(),
        _ => MISSING.to_string(),
    }
}

/// A size in KiB that may be `null`; `null_word` says what null means for this field.
fn kib(report: &Json, path: &[&str], null_word: &str) -> String {
    match at(report, path) {
        Some(Json::Int(n)) => format!("{n} KiB"),
        Some(Json::Null) => null_word.to_string(),
        _ => MISSING.to_string(),
    }
}

/// The length of an array field of the report.
fn count(report: &Json, path: &[&str]) -> String {
    match at(report, path) {
        Some(Json::Arr(items)) => items.len().to_string(),
        _ => MISSING.to_string(),
    }
}

fn reasons(report: &Json) -> String {
    let Some(Json::Arr(list)) = at(report, &["absolute", "reasons"]) else {
        return format!(" ({MISSING})");
    };
    let items: Vec<String> = list
        .iter()
        .map(|r| match word(r, &["kind"]).as_str() {
            "coverage_below_min" => format!(
                "coverage_below_min: have {} ppm, min {} ppm",
                int(r, &["have_ppm"]),
                int(r, &["min_ppm"])
            ),
            "dropouts_exceed_max" => format!(
                "dropouts_exceed_max: have {}, max {}",
                int(r, &["have"]),
                int(r, &["max"])
            ),
            other => other.to_string(),
        })
        .collect();
    if items.is_empty() {
        String::new()
    } else {
        format!(" ({})", items.join("; "))
    }
}

fn dropouts(report: &Json) -> String {
    match at(report, &["dropouts", "known"]) {
        Some(Json::Bool(false)) => "unknown".to_string(),
        Some(Json::Bool(true)) => {
            let intervals = int(report, &["dropouts", "totals", "intervals"]);
            match at(report, &["dropouts", "totals", "censored_spans"]) {
                Some(Json::Int(n)) if *n > 0 => format!("{intervals}, {n} censored"),
                _ => intervals,
            }
        }
        _ => MISSING.to_string(),
    }
}

fn causes(report: &Json) -> String {
    match at(report, &["dropouts", "known"]) {
        Some(Json::Bool(false)) => "unknown".to_string(),
        Some(Json::Bool(true)) => {
            let mut listed: Vec<String> = Vec::new();
            for name in CAUSES {
                match at(report, &["dropouts", "totals", name]) {
                    Some(Json::Int(n)) if *n > 0 => listed.push(format!("{name} {n}")),
                    _ => {}
                }
            }
            if listed.is_empty() {
                "none".to_string()
            } else {
                listed.join(", ")
            }
        }
        _ => MISSING.to_string(),
    }
}

/// The summary of a series report (`ffw-baseline series`).
pub fn series(report: &Json) -> String {
    let verdict = word(report, &["absolute", "verdict"]);
    let reasons = reasons(report);
    let evidence = word(report, &["evidence"]);
    let measured = match at(report, &["measured_on_device"]) {
        Some(Json::Bool(true)) => "measured on a device",
        Some(Json::Bool(false)) => "not measured on a device",
        _ => MISSING,
    };
    let coverage = int(report, &["denominators", "coverage_ppm"]);
    let observed = int(report, &["denominators", "intervals_observed"]);
    let total = int(report, &["denominators", "intervals_total"]);
    let censored = int(report, &["denominators", "intervals_censored"]);
    let holes = count(report, &["holes"]);
    let truncated = match at(report, &["truncated"]) {
        Some(Json::Null) => "no".to_string(),
        Some(t) => format!("{} ns missing", int(t, &["missing_ns"])),
        None => MISSING.to_string(),
    };
    let dropouts = dropouts(report);
    let causes = causes(report);
    let findings = count(report, &["findings"]);
    let dropped = int(report, &["findings_dropped"]);
    format!(
        "ffw-baseline series: verdict {verdict}{reasons}; evidence {evidence}, {measured}; \
coverage {coverage} ppm ({observed} of {total} intervals observed, {censored} censored); \
holes {holes}; truncated {truncated}; dropouts {dropouts}; causes {causes}; \
findings {findings}, {dropped} dropped"
    )
}

/// The sum of `field` over every snapshot, or `None` if any snapshot lacks it.
fn over_snapshots(report: &Json, field: impl Fn(&Json) -> Option<i128>) -> Option<i128> {
    match at(report, &["snapshots"]) {
        Some(Json::Arr(list)) => list.iter().map(field).sum(),
        _ => None,
    }
}

/// The summary of a memory report (`ffw-baseline memory`).
pub fn memory(report: &Json) -> String {
    let snapshots = count(report, &["snapshots"]);
    let used = kib(report, &["peaks", "max_used_kib"], "unknown");
    let pss = kib(report, &["peaks", "max_process_pss_sum_kib"], "unknown");
    let hwm = kib(report, &["peaks", "max_vm_hwm_kib"], "unknown");
    let verdict = word(report, &["headroom", "verdict"]);
    let reserve = kib(report, &["headroom", "reserve_kib"], "unknown");
    let required = kib(
        report,
        &["headroom", "required_reserve_kib"],
        "not declared",
    );
    let findings = over_snapshots(report, |s| match at(s, &["findings"]) {
        Some(Json::Arr(items)) => i128::try_from(items.len()).ok(),
        _ => None,
    });
    let dropped = over_snapshots(report, |s| match at(s, &["findings_dropped"]) {
        Some(Json::Int(n)) => Some(*n),
        _ => None,
    });
    let show = |n: Option<i128>| n.map_or_else(|| MISSING.to_string(), |v| v.to_string());
    let (findings, dropped) = (show(findings), show(dropped));
    format!(
        "ffw-baseline memory: snapshots {snapshots}; peak used {used}; max PSS sum {pss}; \
max VmHWM {hwm}; headroom {verdict} (reserve {reserve}, required {required}); \
findings {findings}, {dropped} dropped"
    )
}

/// The summary of a comparison (`ffw-baseline compare`).
pub fn comparison(report: &Json) -> String {
    let evidence = word(report, &["current_evidence"]);
    match at(report, &["claim"]) {
        Some(Json::Str(claim)) if claim == "made" => format!(
            "ffw-baseline compare: claim made, {}; baseline_per_hour_milli {}, current_per_hour_milli {}, \
margin {} pct; current evidence {evidence}",
            word(report, &["comparison", "verdict"]),
            int(report, &["comparison", "baseline_per_hour_milli"]),
            int(report, &["comparison", "current_per_hour_milli"]),
            int(report, &["comparison", "margin_pct"]),
        ),
        Some(Json::Str(claim)) if claim == "refused" => format!(
            "ffw-baseline compare: claim refused ({}); current evidence {evidence}",
            word(report, &["reason"])
        ),
        _ => format!("ffw-baseline compare: claim {MISSING}; current evidence {evidence}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn totals(intervals: i128, censored: i128, causes: [i128; 6]) -> Json {
        let mut fields = vec![
            ("intervals", Json::Int(intervals)),
            ("censored_spans", Json::Int(censored)),
        ];
        for (name, n) in CAUSES.into_iter().zip(causes) {
            fields.push((name, Json::Int(n)));
        }
        Json::obj(fields)
    }

    /// A series report with the fields the summary reads, written by hand. The values are not taken from the analyzer.
    fn series_report(
        known: bool,
        totals: Json,
        trunc: Json,
        verdict: &str,
        reasons: Vec<Json>,
    ) -> Json {
        Json::obj(vec![
            ("evidence", Json::str("synthetic")),
            ("measured_on_device", Json::Bool(false)),
            (
                "denominators",
                Json::obj(vec![
                    ("coverage_ppm", Json::Int(1_000_000)),
                    ("intervals_observed", Json::Int(10)),
                    ("intervals_total", Json::Int(10)),
                    ("intervals_censored", Json::Int(0)),
                ]),
            ),
            ("holes", Json::Arr(vec![])),
            ("truncated", trunc),
            (
                "dropouts",
                Json::obj(vec![("known", Json::Bool(known)), ("totals", totals)]),
            ),
            ("findings", Json::Arr(vec![])),
            ("findings_dropped", Json::Int(0)),
            (
                "absolute",
                Json::obj(vec![
                    ("verdict", Json::str(verdict)),
                    ("reasons", Json::Arr(reasons)),
                ]),
            ),
        ])
    }

    #[test]
    fn a_qualified_series_reads_plainly() {
        let r = series_report(true, totals(0, 0, [0; 6]), Json::Null, "qualified", vec![]);
        assert_eq!(
            series(&r),
            "ffw-baseline series: verdict qualified; evidence synthetic, not measured on a device; \
coverage 1000000 ppm (10 of 10 intervals observed, 0 censored); holes 0; truncated no; dropouts 0; \
causes none; findings 0, 0 dropped"
        );
    }

    #[test]
    fn reasons_are_listed_with_their_own_numbers() {
        let reasons = vec![
            Json::obj(vec![
                ("kind", Json::str("coverage_below_min")),
                ("have_ppm", Json::Int(666_666)),
                ("min_ppm", Json::Int(900_000)),
            ]),
            Json::obj(vec![
                ("kind", Json::str("dropouts_exceed_max")),
                ("have", Json::Int(5)),
                ("max", Json::Int(0)),
            ]),
            Json::obj(vec![("kind", Json::str("dropouts_unknown"))]),
        ];
        let r = series_report(
            true,
            totals(5, 0, [1, 1, 1, 1, 1, 0]),
            Json::Null,
            "not_qualified",
            reasons,
        );
        let line = series(&r);
        assert!(line.starts_with(
            "ffw-baseline series: verdict not_qualified (coverage_below_min: have 666666 ppm, min 900000 ppm; \
dropouts_exceed_max: have 5, max 0; dropouts_unknown); evidence synthetic"
        ));
        assert!(line.contains(
            "dropouts 5; causes source_outage 1, network_lateness 1, cpu_deadline_miss 1, output_underrun 1, ambiguous 1;"
        ));
    }

    #[test]
    fn unknown_dropouts_read_as_unknown_never_as_zero() {
        let r = series_report(
            false,
            totals(0, 0, [0; 6]),
            Json::Null,
            "not_qualified",
            vec![],
        );
        let line = series(&r);
        assert!(line.contains("dropouts unknown; causes unknown;"), "{line}");
        assert!(!line.contains("dropouts 0"), "{line}");
        assert!(!line.contains("causes none"), "{line}");
    }

    #[test]
    fn an_undetermined_cause_is_counted_and_named_as_such() {
        let r = series_report(
            true,
            totals(1, 0, [0, 0, 0, 0, 0, 1]),
            Json::Null,
            "not_assessed",
            vec![],
        );
        assert!(series(&r).contains("dropouts 1; causes undetermined 1;"));
    }

    #[test]
    fn censoring_and_truncation_are_shown() {
        let r = series_report(
            true,
            totals(0, 1, [0; 6]),
            Json::obj(vec![("missing_ns", Json::Int(4_000_000_000))]),
            "not_qualified",
            vec![],
        );
        let line = series(&r);
        assert!(line.contains("truncated 4000000000 ns missing;"), "{line}");
        assert!(line.contains("dropouts 0, 1 censored;"), "{line}");
    }

    #[test]
    fn a_measured_run_says_so() {
        let mut r = series_report(true, totals(0, 0, [0; 6]), Json::Null, "qualified", vec![]);
        if let Json::Obj(fields) = &mut r {
            for (key, value) in fields.iter_mut() {
                if key.as_str() == "evidence" {
                    *value = Json::str("physical");
                }
                if key.as_str() == "measured_on_device" {
                    *value = Json::Bool(true);
                }
            }
        }
        assert!(series(&r).contains("evidence physical, measured on a device;"));
    }

    fn memory_report(used: Json, pss: Json, required: Json, snaps: Vec<Json>) -> Json {
        Json::obj(vec![
            ("snapshots", Json::Arr(snaps)),
            (
                "peaks",
                Json::obj(vec![
                    ("max_used_kib", used),
                    ("max_process_pss_sum_kib", pss),
                    ("max_vm_hwm_kib", Json::Int(3400)),
                ]),
            ),
            (
                "headroom",
                Json::obj(vec![
                    ("required_reserve_kib", required),
                    ("reserve_kib", Json::Int(17_000)),
                    ("verdict", Json::str("not_assessed")),
                ]),
            ),
        ])
    }

    fn snapshot(findings: usize, dropped: i128) -> Json {
        Json::obj(vec![
            ("findings", Json::Arr(vec![Json::Null; findings])),
            ("findings_dropped", Json::Int(dropped)),
        ])
    }

    #[test]
    fn memory_figures_the_kernel_did_not_give_read_as_unknown_and_an_undeclared_reserve_says_so() {
        let r = memory_report(
            Json::Int(13_000),
            Json::Null,
            Json::Null,
            vec![snapshot(1, 0), snapshot(0, 0)],
        );
        assert_eq!(
            memory(&r),
            "ffw-baseline memory: snapshots 2; peak used 13000 KiB; max PSS sum unknown; max VmHWM 3400 KiB; \
headroom not_assessed (reserve 17000 KiB, required not declared); findings 1, 0 dropped"
        );
    }

    #[test]
    fn memory_findings_are_summed_over_every_snapshot() {
        let r = memory_report(
            Json::Int(1),
            Json::Int(2),
            Json::Int(4096),
            vec![snapshot(3, 2), snapshot(4, 5)],
        );
        let line = memory(&r);
        assert!(line.ends_with("findings 7, 7 dropped"), "{line}");
        assert!(line.contains("required 4096 KiB"), "{line}");
    }

    #[test]
    fn a_made_comparison_and_a_refused_one() {
        let made = Json::obj(vec![
            ("claim", Json::str("made")),
            ("reason", Json::Null),
            (
                "comparison",
                Json::obj(vec![
                    ("baseline_per_hour_milli", Json::Int(2000)),
                    ("current_per_hour_milli", Json::Int(1000)),
                    ("margin_pct", Json::Int(10)),
                    ("verdict", Json::str("better")),
                ]),
            ),
            ("current_evidence", Json::str("physical")),
        ]);
        assert_eq!(
            comparison(&made),
            "ffw-baseline compare: claim made, better; baseline_per_hour_milli 2000, current_per_hour_milli 1000, \
margin 10 pct; current evidence physical"
        );
        let refused = Json::obj(vec![
            ("claim", Json::str("refused")),
            ("reason", Json::str("no_baseline")),
            ("comparison", Json::Null),
            ("current_evidence", Json::str("synthetic")),
        ]);
        assert_eq!(
            comparison(&refused),
            "ffw-baseline compare: claim refused (no_baseline); current evidence synthetic"
        );
    }

    #[test]
    fn a_missing_field_reads_as_a_question_mark_and_nothing_is_invented() {
        let empty = Json::obj(vec![]);
        let line = series(&empty);
        assert!(line.contains("verdict ? (?);"), "{line}");
        assert!(
            line.contains("coverage ? ppm (? of ? intervals observed, ? censored)"),
            "{line}"
        );
        assert!(line.contains("dropouts ?; causes ?;"), "{line}");
        assert_eq!(
            memory(&empty),
            "ffw-baseline memory: snapshots ?; peak used ?; max PSS sum ?; max VmHWM ?; headroom ? (reserve ?, required ?); findings ?, ? dropped"
        );
        assert_eq!(
            comparison(&empty),
            "ffw-baseline compare: claim ?; current evidence ?"
        );
    }

    #[test]
    fn the_line_carries_no_input_text() {
        // A report whose profile, series name, label and process name were all site identifiers (as if nothing had
        // screened them): the summary does not read those fields at all.
        let mut r = series_report(true, totals(0, 0, [0; 6]), Json::Null, "qualified", vec![]);
        if let Json::Obj(fields) = &mut r {
            fields.push(("profile".to_string(), Json::str("192.0.2.17")));
            fields.push((
                "counters".to_string(),
                Json::Arr(vec![Json::obj(vec![("name", Json::str("SN0000EXAMPLE"))])]),
            ));
        }
        let line = series(&r);
        for planted in ["192.0.2.17", "SN0000EXAMPLE"] {
            assert!(!line.contains(planted), "{line}");
        }
        let mut m = memory_report(Json::Int(1), Json::Int(2), Json::Null, vec![snapshot(0, 0)]);
        if let Json::Obj(fields) = &mut m {
            fields.push((
                "processes".to_string(),
                Json::Arr(vec![Json::obj(vec![(
                    "name",
                    Json::str("00-00-5E-00-53-01"),
                )])]),
            ));
        }
        assert!(!memory(&m).contains("00-00-5E-00-53-01"));
    }
}
