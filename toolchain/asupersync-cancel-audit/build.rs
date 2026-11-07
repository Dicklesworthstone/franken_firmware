//! Refuses to build unless this harness is what it says it is, and tells the audit where the pinned asupersync is.
//!
//! The original audit was written inside the asupersync package, where `CARGO_MANIFEST_DIR` is the asupersync source root: many of
//! its tests read `src/**` and `tests/*` beneath it, and one census walks all of `src`. Here asupersync is a dependency, so Cargo has
//! fetched it into its own git checkout and this package's manifest directory is not that root. This script finds that checkout,
//! proves with read-only `git` that it is the pinned commit with nothing the audit reads changed, added or hidden
//! (`provenance/verify.rs`), checks that `Cargo.lock` pins the dependency it compiled to that same commit, and exports the path as
//! `ASUP_ROOT`, which `tests/cancel_audit.rs` hands to the unchanged audit in place of `CARGO_MANIFEST_DIR`.
//! It does not run Cargo, and there is no override: if nothing checks out, the build fails.

#[path = "provenance/verify.rs"]
mod verify;

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=provenance");
    println!("cargo::rerun-if-changed=Cargo.toml");
    println!("cargo::rerun-if-changed=Cargo.lock");
    println!("cargo::rerun-if-env-changed=CARGO_HOME");

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("provenance/expected.json"))
            .expect("provenance/expected.json parses");
    let rev = expected["asupersync"]["rev"]
        .as_str()
        .expect("expected.json names the pinned rev");

    // This harness itself: the original audit sources are the pinned bytes, the feature set is the original lane's, and the
    // dependency Cargo resolved is the pinned commit.
    let mut problems: Vec<String> = Vec::new();
    for (rel, want) in
        verify::string_map(&expected, "harness_files").expect("expected.json harness_files")
    {
        if let Err(violation) = verify::check_bytes(
            &rel,
            fs::read(manifest_dir.join(&rel)).ok().as_deref(),
            &want,
        ) {
            problems.push(violation.to_string());
        }
    }
    let wanted: BTreeSet<String> = expected["features"]
        .as_array()
        .expect("expected.json features")
        .iter()
        .filter_map(|feature| feature.as_str().map(str::to_owned))
        .collect();
    match fs::read_to_string(manifest_dir.join("Cargo.toml"))
        .map_err(|error| error.to_string())
        .and_then(|text| verify::declared_features(&text))
    {
        Ok(declared) => {
            if let Err(violation) = verify::check_features(&declared, &wanted) {
                problems.push(violation.to_string());
            }
        }
        Err(error) => problems.push(format!(
            "cannot read the asupersync features this harness requests: {error}"
        )),
    }
    match fs::read_to_string(manifest_dir.join("Cargo.lock")) {
        Ok(lock) => {
            if let Err(violation) = verify::check_lock_source(&lock, rev) {
                problems.push(violation.to_string());
            }
        }
        Err(error) => problems.push(format!("cannot read Cargo.lock: {error}")),
    }
    assert!(
        problems.is_empty(),
        "the harness is not the pinned focused audit:\n  - {}",
        problems.join("\n  - ")
    );

    // The asupersync Cargo fetched: found, then proven to be the pinned commit.
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
    let mut tried: Vec<String> = Vec::new();
    for root in verify::candidate_roots(cargo_home, rev) {
        match verify::verify_checkout(&root, rev) {
            Ok(()) => {
                println!("cargo::rustc-env=ASUP_ROOT={}", root.display());
                return;
            }
            Err(violation) => tried.push(format!("{}: {violation}", root.display())),
        }
    }
    panic!(
        "no Cargo git checkout is the pinned asupersync {rev}; tried {} candidate(s):\n  - {}\nA checkout must keep its Git metadata \
         (Cargo's does); if this layout is not where Cargo put it, say so rather than pointing the audit at another directory.",
        tried.len(),
        tried.join("\n  - ")
    );
}
