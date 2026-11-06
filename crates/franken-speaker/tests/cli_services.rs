//! The real `franken-speaker` binary, run with `--services` (`P01` BLK-006).
//!
//! These tests start the binary Cargo built for this test run, with the Cargo features this run was given, and read what it
//! prints. They are the proof that the build's service selection reaches the composition root's output and not only a library
//! function nothing calls: a build with a service feature on prints that service as selected, unimplemented and unqualified, a
//! build without it prints it as absent, and neither ever prints "ready". The expected lines are written out in full, once per
//! service and per configuration, so they do not come from the code under test.
//!
//! They run in whatever configuration Cargo is given: `cargo test -p franken-speaker` (every service absent) and
//! `cargo test -p franken-speaker --features spotify_connect,airplay2,tailnet_native,alexa_bridge,artwork` (every service
//! selected). In each, the five tests for the other configuration are not compiled.

use std::process::{Command, Output};

use franken_speaker::services::{NativeService, ServiceReport};

const SERVICES: [&str; 5] = [
    "spotify_connect",
    "airplay2",
    "tailnet_native",
    "alexa_bridge",
    "artwork",
];

fn speaker(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_franken-speaker"))
        .args(args)
        .output()
        .expect("the franken-speaker binary starts")
}

fn stdout_lines(out: &Output) -> Vec<String> {
    String::from_utf8(out.stdout.clone())
        .expect("--services prints text")
        .lines()
        .map(str::to_string)
        .collect()
}

// ------------------------------------------------------------------------------ the same in every configuration

#[test]
fn services_option_exits_zero_with_one_line_per_service_in_order_and_nothing_on_stderr() {
    let out = speaker(&["--services"]);
    assert!(out.status.success(), "exit {:?}", out.status.code());
    assert!(out.stderr.is_empty(), "stderr: {:?}", out.stderr);
    let lines = stdout_lines(&out);
    assert_eq!(lines.len(), SERVICES.len(), "{lines:?}");
    for (line, name) in lines.iter().zip(SERVICES) {
        assert!(
            line.starts_with(&format!("FFW_SERVICE:{name} ")),
            "{line:?} is not the line for {name}"
        );
    }
}

#[test]
fn no_service_line_says_ready_and_each_is_absent_or_selected_unimplemented_unqualified() {
    let out = speaker(&["--services"]);
    for line in stdout_lines(&out) {
        assert!(!line.contains("ready"), "{line:?}");
        let standing = line.split_once(' ').expect("a standing follows the name").1;
        assert!(
            standing == "absent" || standing == "selected unimplemented unqualified",
            "{line:?}"
        );
    }
}

#[test]
fn every_printed_line_parses_back_to_the_report_this_build_gives_for_that_service() {
    // The binary is one process and this test another; both were built by Cargo with the same features, so the report the
    // library gives here is what the binary must have printed.
    let out = speaker(&["--services"]);
    let lines = stdout_lines(&out);
    assert_eq!(lines.len(), NativeService::ALL.len());
    for (line, service) in lines.iter().zip(NativeService::ALL) {
        let printed = ServiceReport::from_marker(line)
            .unwrap_or_else(|| panic!("{line:?} is not a line the report prints"));
        assert_eq!(printed.service, service);
        assert_eq!(printed.check(), Ok(()), "{line:?}");
        assert_eq!(printed, ServiceReport::of(service), "{line:?}");
        assert!(!printed.ready() && !printed.qualified && !printed.implemented);
    }
}

#[test]
fn services_option_is_the_same_on_every_run() {
    let first = speaker(&["--services"]);
    let second = speaker(&["--services"]);
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn the_catalog_option_still_prints_the_catalog_as_json_and_not_the_services() {
    let out = speaker(&["--catalog"]);
    assert!(out.status.success(), "exit {:?}", out.status.code());
    let catalog: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("--catalog prints JSON");
    assert!(!catalog.is_null());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("FFW_SERVICE:"));
}

#[cfg(not(feature = "harness"))]
#[test]
fn with_no_option_a_build_without_the_harness_still_prints_the_catalog() {
    let plain = speaker(&[]);
    let catalog = speaker(&["--catalog"]);
    assert!(plain.status.success());
    assert_eq!(plain.stdout, catalog.stdout);
}

#[cfg(not(feature = "harness"))]
#[test]
fn the_harness_options_are_still_refused_without_the_harness() {
    for option in ["--virtual-house", "--self-test"] {
        let out = speaker(&[option]);
        assert_eq!(out.status.code(), Some(2), "{option}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("no Virtual House harness"),
            "{option}"
        );
    }
}

#[cfg(not(any(target_arch = "mips", target_arch = "powerpc")))]
#[test]
fn platform_startup_is_still_refused_on_a_build_with_no_kernel_backend() {
    let out = speaker(&["--platform-startup"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no kernel backend"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("FFW_SERVICE:"));
}

#[test]
fn an_unknown_option_is_still_refused_and_the_usage_lists_the_services_option() {
    let out = speaker(&["--no-such-option"]);
    assert_eq!(out.status.code(), Some(2));
    let usage = String::from_utf8_lossy(&out.stderr);
    assert!(usage.contains("--no-such-option"), "{usage}");
    assert!(usage.contains("--services"), "{usage}");
    assert!(out.stdout.is_empty());
}

// ------------------------------------------------------------ one pair per service: selected and not selected

#[cfg(feature = "spotify_connect")]
#[test]
fn cli_spotify_connect_selected_prints_selected_unimplemented_unqualified() {
    let lines = stdout_lines(&speaker(&["--services"]));
    assert_eq!(
        lines[0],
        "FFW_SERVICE:spotify_connect selected unimplemented unqualified"
    );
}

#[cfg(not(feature = "spotify_connect"))]
#[test]
fn cli_spotify_connect_not_selected_prints_absent() {
    let lines = stdout_lines(&speaker(&["--services"]));
    assert_eq!(lines[0], "FFW_SERVICE:spotify_connect absent");
}

#[cfg(feature = "airplay2")]
#[test]
fn cli_airplay2_selected_prints_selected_unimplemented_unqualified() {
    let lines = stdout_lines(&speaker(&["--services"]));
    assert_eq!(
        lines[1],
        "FFW_SERVICE:airplay2 selected unimplemented unqualified"
    );
}

#[cfg(not(feature = "airplay2"))]
#[test]
fn cli_airplay2_not_selected_prints_absent() {
    let lines = stdout_lines(&speaker(&["--services"]));
    assert_eq!(lines[1], "FFW_SERVICE:airplay2 absent");
}

#[cfg(feature = "tailnet_native")]
#[test]
fn cli_tailnet_native_selected_prints_selected_unimplemented_unqualified() {
    let lines = stdout_lines(&speaker(&["--services"]));
    assert_eq!(
        lines[2],
        "FFW_SERVICE:tailnet_native selected unimplemented unqualified"
    );
}

#[cfg(not(feature = "tailnet_native"))]
#[test]
fn cli_tailnet_native_not_selected_prints_absent() {
    let lines = stdout_lines(&speaker(&["--services"]));
    assert_eq!(lines[2], "FFW_SERVICE:tailnet_native absent");
}

#[cfg(feature = "alexa_bridge")]
#[test]
fn cli_alexa_bridge_selected_prints_selected_unimplemented_unqualified() {
    let lines = stdout_lines(&speaker(&["--services"]));
    assert_eq!(
        lines[3],
        "FFW_SERVICE:alexa_bridge selected unimplemented unqualified"
    );
}

#[cfg(not(feature = "alexa_bridge"))]
#[test]
fn cli_alexa_bridge_not_selected_prints_absent() {
    let lines = stdout_lines(&speaker(&["--services"]));
    assert_eq!(lines[3], "FFW_SERVICE:alexa_bridge absent");
}

#[cfg(feature = "artwork")]
#[test]
fn cli_artwork_selected_prints_selected_unimplemented_unqualified() {
    let lines = stdout_lines(&speaker(&["--services"]));
    assert_eq!(
        lines[4],
        "FFW_SERVICE:artwork selected unimplemented unqualified"
    );
}

#[cfg(not(feature = "artwork"))]
#[test]
fn cli_artwork_not_selected_prints_absent() {
    let lines = stdout_lines(&speaker(&["--services"]));
    assert_eq!(lines[4], "FFW_SERVICE:artwork absent");
}
