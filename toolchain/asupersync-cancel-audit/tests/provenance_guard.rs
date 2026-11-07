//! Proves the integrity checks that build.rs applies: each accepts the real thing and refuses what it must.
//!
//! The first four tests are the checks on THIS harness and the asupersync it was built against. The rest are planted defects with
//! their permitted positives: an altered or missing original audit, a narrower or wider feature set (including the defaults-only
//! lane the original does not run), and a candidate asupersync directory that is the wrong commit, has a changed, extra or
//! hidden file the audit reads, has no Git metadata of its own, or is not the commit `Cargo.lock` pins. The directory cases use
//! real Git repositories created under the system temp directory with a name that is new on every run; none is ever deleted.

#[path = "../provenance/verify.rs"]
mod verify;

use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use verify::Violation;

const AUDIT: &str = "tests/runtime_abort_vs_cancel_semantics_audit.rs";
const HELPER: &str = "tests/runtime_abort_vs_cancel_semantics_audit/stream_cancellation.rs";

fn harness() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn expected() -> Value {
    serde_json::from_str(include_str!("../provenance/expected.json"))
        .expect("provenance/expected.json parses")
}

fn pinned_rev() -> String {
    expected()["asupersync"]["rev"]
        .as_str()
        .expect("the pinned rev")
        .to_owned()
}

fn wanted_features() -> BTreeSet<String> {
    expected()["features"]
        .as_array()
        .expect("features")
        .iter()
        .map(|feature| feature.as_str().expect("feature name").to_owned())
        .collect()
}

fn features(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn count_tests(source: &str) -> usize {
    source
        .lines()
        .filter(|line| line.trim() == "#[test]")
        .count()
}

#[test]
fn the_original_audit_sources_in_this_harness_are_the_pinned_bytes() {
    for (rel, want) in verify::string_map(&expected(), "harness_files").expect("harness_files") {
        let bytes = fs::read(harness().join(&rel)).ok();
        assert_eq!(
            verify::check_bytes(&rel, bytes.as_deref(), &want),
            Ok(()),
            "{rel}"
        );
    }
}

#[test]
fn the_asupersync_directory_the_audit_reads_is_the_pinned_commit_and_clean() {
    // ASUP_ROOT is what build.rs exported after the same check; this re-runs it where the audit runs, and also checks that the
    // lock this build used pins asupersync to that commit.
    let root = Path::new(env!("ASUP_ROOT"));
    assert_eq!(
        verify::verify_checkout(root, &pinned_rev()),
        Ok(()),
        "{}",
        root.display()
    );
    let lock = fs::read_to_string(harness().join("Cargo.lock")).expect("Cargo.lock");
    assert_eq!(verify::check_lock_source(&lock, &pinned_rev()), Ok(()));
}

#[test]
fn the_harness_requests_exactly_the_original_lanes_feature_set() {
    let manifest = fs::read_to_string(harness().join("Cargo.toml")).expect("Cargo.toml");
    let declared =
        verify::declared_features(&manifest).expect("the asupersync line lists features");
    assert_eq!(
        verify::check_features(&declared, &wanted_features()),
        Ok(())
    );
    // test-internals is the one that decides whether Cx::for_testing and friends exist; the original gets it from conformance.
    assert!(declared.contains("test-internals"));
}

#[test]
fn the_harness_sources_define_the_original_test_count() {
    let facts = expected();
    let tests = &facts["tests"];
    let audit = count_tests(&fs::read_to_string(harness().join(AUDIT)).expect("audit"));
    let helper = count_tests(&fs::read_to_string(harness().join(HELPER)).expect("helper"));
    assert_eq!(u64::try_from(audit).ok(), tests["audit"].as_u64());
    assert_eq!(
        u64::try_from(helper).ok(),
        tests["stream_cancellation"].as_u64()
    );
    assert_eq!(u64::try_from(audit + helper).ok(), tests["total"].as_u64());
}

#[test]
fn an_altered_audit_source_is_rejected_and_the_original_is_accepted() {
    let want = verify::string_map(&expected(), "harness_files")
        .expect("harness_files")
        .into_iter()
        .find(|(rel, _)| rel == AUDIT)
        .expect("the audit is pinned")
        .1;
    let original = fs::read(harness().join(AUDIT)).expect("audit");
    assert_eq!(verify::check_bytes(AUDIT, Some(&original), &want), Ok(()));
    let mut altered = original.clone();
    altered.extend_from_slice(b"\n// a weakened assertion would go here\n");
    assert!(matches!(
        verify::check_bytes(AUDIT, Some(&altered), &want),
        Err(Violation::Altered { .. })
    ));
    // One flipped byte in the middle is enough: the check is on the bytes, not on a count of tests.
    let mut flipped = original;
    let middle = flipped.len() / 2;
    flipped[middle] ^= 0x01;
    assert!(matches!(
        verify::check_bytes(AUDIT, Some(&flipped), &want),
        Err(Violation::Altered { .. })
    ));
}

#[test]
fn a_missing_audit_source_is_rejected() {
    let want = verify::sha256_hex(b"anything");
    assert_eq!(
        verify::check_bytes(AUDIT, None, &want),
        Err(Violation::Missing {
            what: AUDIT.to_owned()
        })
    );
}

#[test]
fn a_feature_set_missing_test_internals_is_rejected() {
    let mut declared = wanted_features();
    assert!(declared.remove("test-internals"));
    assert_eq!(
        verify::check_features(&declared, &wanted_features()),
        Err(Violation::FeatureMismatch {
            missing: vec!["test-internals".to_owned()],
            extra: Vec::new()
        })
    );
}

#[test]
fn an_extra_feature_is_rejected() {
    let mut declared = wanted_features();
    declared.insert("http2-streaming".to_owned());
    assert_eq!(
        verify::check_features(&declared, &wanted_features()),
        Err(Violation::FeatureMismatch {
            missing: Vec::new(),
            extra: vec!["http2-streaming".to_owned()]
        })
    );
}

#[test]
fn the_default_features_lane_is_rejected_as_narrower() {
    // The lane one might assume: asupersync's own defaults and nothing the dev-dependencies add.
    let defaults = features(&[
        "native-runtime",
        "nightly-outcome-try",
        "proc-macros",
        "runtime-core",
    ]);
    match verify::check_features(&defaults, &wanted_features()) {
        Err(Violation::FeatureMismatch { missing, extra }) => {
            assert_eq!(
                missing,
                ["fuzz", "metrics", "test-internals", "tracing-integration"]
            );
            assert!(extra.is_empty());
        }
        other => panic!("a defaults-only lane must be refused, got {other:?}"),
    }
    // and the parser reads a manifest line the way build.rs needs it to
    let line = "asupersync = { git = \"x\", rev = \"y\", default-features = false, features = [\"a\", \"b\"] }\n";
    assert_eq!(verify::declared_features(line), Ok(features(&["a", "b"])));
    assert!(verify::declared_features("[dependencies]\nserde = \"1\"\n").is_err());
}

static CASE: AtomicUsize = AtomicUsize::new(0);

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().expect("a parent directory")).expect("create directory");
    fs::write(path, bytes).expect("write file");
}

fn git_in(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=guard",
            "-c",
            "user.email=guard@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A small Git repository shaped like the parts of asupersync the audit reads, committed once; returns it and its HEAD. Each call
/// makes a directory that is new (process id, clock, counter) under the system temp directory, so a re-run never meets an earlier
/// run's changes, and none is ever deleted.
fn stand_in_repo() -> (PathBuf, String) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock")
        .as_nanos();
    let root = std::env::temp_dir().join("asup-audit-guard").join(format!(
        "{}-{nanos}-{}",
        std::process::id(),
        CASE.fetch_add(1, Ordering::SeqCst)
    ));
    write(&root, ".gitignore", b"src/hidden.rs\n");
    write(&root, "Cargo.toml", b"[package]\nname = \"stand-in\"\n");
    write(&root, "Cargo.lock", b"# lock\n");
    write(
        &root,
        "conformance/Cargo.toml",
        b"[package]\nname = \"conformance\"\n",
    );
    write(&root, "src/a.rs", b"pub fn a() {}\n");
    write(&root, "src/sub/b.rs", b"pub fn b() {}\n");
    write(&root, "tests/prior_audit.rs", b"// a prior audit\n");
    git_in(&root, &["init", "-q"]);
    git_in(&root, &["add", "-A"]);
    git_in(&root, &["commit", "-q", "-m", "init"]);
    let rev = git_in(&root, &["rev-parse", "HEAD"]);
    (root, rev)
}

fn refused_with(result: Result<(), Violation>, needle: &str) {
    match result {
        Err(Violation::Identity { reason }) => {
            assert!(reason.contains(needle), "`{needle}` not in: {reason}");
        }
        other => panic!("expected an identity refusal mentioning `{needle}`, got {other:?}"),
    }
}

#[test]
fn a_checkout_at_another_revision_is_rejected_and_the_pinned_one_is_accepted() {
    let (root, first) = stand_in_repo();
    write(&root, "src/a.rs", b"pub fn a() { /* second */ }\n");
    git_in(&root, &["commit", "-q", "-am", "second"]);
    let second = git_in(&root, &["rev-parse", "HEAD"]);
    assert_ne!(first, second);
    assert_eq!(verify::verify_checkout(&root, &second), Ok(()));
    refused_with(verify::verify_checkout(&root, &first), "HEAD is");
    refused_with(verify::verify_checkout(&root, &"0".repeat(40)), "HEAD is");
}

fn modify_source(root: &Path) {
    write(root, "src/a.rs", b"pub fn a() { /* edited */ }\n");
}
fn add_untracked_source(root: &Path) {
    write(root, "src/extra.rs", b"pub fn extra() {}\n");
}
fn add_ignored_source(root: &Path) {
    write(root, "src/hidden.rs", b"pub fn hidden() {}\n");
}
fn modify_prior_audit(root: &Path) {
    write(root, "tests/prior_audit.rs", b"// weakened\n");
}
fn modify_manifest(root: &Path) {
    write(root, "Cargo.toml", b"[package]\nname = \"other\"\n");
}
fn modify_conformance_manifest(root: &Path) {
    write(
        root,
        "conformance/Cargo.toml",
        b"[package]\nname = \"other\"\n",
    );
}

#[test]
fn every_departure_from_the_pinned_clean_checkout_is_rejected_by_name() {
    // (what is done to a fresh clean checkout, text the refusal must contain). Each repository is accepted before it is touched,
    // so the refusal is the change and not the repository.
    type CheckoutDeparture = fn(&Path);
    let cases: [(CheckoutDeparture, &str); 6] = [
        (modify_source, "src/a.rs"),
        (add_untracked_source, "src/extra.rs"),
        (add_ignored_source, "src/hidden.rs"),
        (modify_prior_audit, "tests/prior_audit.rs"),
        (modify_manifest, "Cargo.toml"),
        (modify_conformance_manifest, "conformance/Cargo.toml"),
    ];
    for (departure, needle) in cases {
        let (root, rev) = stand_in_repo();
        assert_eq!(verify::verify_checkout(&root, &rev), Ok(()), "{needle}");
        departure(&root);
        refused_with(verify::verify_checkout(&root, &rev), needle);
    }
}

#[test]
fn a_directory_without_its_own_git_metadata_is_rejected_even_inside_another_repository() {
    let (repo, rev) = stand_in_repo();
    // Cargo leaves a marker file at the root of its checkouts; it is not something the audit reads.
    write(&repo, ".cargo-ok", b"{}");
    assert_eq!(verify::verify_checkout(&repo, &rev), Ok(()));
    // a copy of the tree inside the repository, with no .git of its own, would otherwise be judged by the repository above it
    write(&repo, "inner/src/a.rs", b"pub fn a() {}\n");
    refused_with(
        verify::verify_checkout(&repo.join("inner"), &rev),
        "no .git",
    );
    let plain = std::env::temp_dir()
        .join("asup-audit-guard")
        .join("plain-no-git");
    fs::create_dir_all(&plain).expect("create directory");
    refused_with(verify::verify_checkout(&plain, &rev), "no .git");
}

#[test]
fn the_lock_must_pin_asupersync_to_the_inspected_commit() {
    let rev = "14032b8f2c832ee7ef1946404f5efb18162af045";
    let other = "4f1725c49157300b37c1a11de99b0cd7ba2595a8";
    let lock = |source: &str| {
        format!(
            "[[package]]\nname = \"asupersync-macros\"\nversion = \"0.6.0\"\nsource = \"git+https://example.invalid/x?rev={other}#{other}\"\n\n[[package]]\nname = \"asupersync\"\nversion = \"0.6.2\"\n{source}\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n"
        )
    };
    let git_source = |sha: &str| {
        format!("source = \"git+https://github.com/Dicklesworthstone/asupersync?rev={rev}#{sha}\"")
    };
    assert_eq!(
        verify::check_lock_source(&lock(&git_source(rev)), rev),
        Ok(())
    );
    for (_what, text) in [
        ("another commit", lock(&git_source(other))),
        (
            "a registry source",
            lock("source = \"registry+https://github.com/rust-lang/crates.io-index\""),
        ),
        ("a path dependency (no source line)", lock("")),
        (
            "no asupersync package, only a look-alike",
            "[[package]]\nname = \"asupersync-macros\"\nversion = \"0.6.0\"\nsource = \"git+https://example.invalid/x?rev=14032b8f2c832ee7ef1946404f5efb18162af045#14032b8f2c832ee7ef1946404f5efb18162af045\"\n".to_owned(),
        ),
    ] {
        refused_with(verify::check_lock_source(&text, rev), "asupersync");
    }
}

#[test]
fn candidate_roots_selects_only_asupersync_checkouts_of_the_pinned_rev() {
    let home = std::env::temp_dir()
        .join("asup-audit-guard")
        .join("cargo_home");
    let rev = "14032b8f2c832ee7ef1946404f5efb18162af045";
    for dir in [
        "git/checkouts/asupersync-aaaaaaaaaaaaaaaa/14032b8",
        "git/checkouts/asupersync-aaaaaaaaaaaaaaaa/deadbee",
        "git/checkouts/asupersync-bbbbbbbbbbbbbbbb/14032b8f2c8",
        "git/checkouts/serde-cccccccccccccccc/14032b8",
        "git/checkouts/asupersync-dddddddddddddddd/14032",
    ] {
        fs::create_dir_all(home.join(dir)).expect("create directory");
    }
    let mut got = verify::candidate_roots(Some(home.clone()), rev);
    got.sort();
    assert_eq!(
        got,
        [
            home.join("git/checkouts/asupersync-aaaaaaaaaaaaaaaa/14032b8"),
            home.join("git/checkouts/asupersync-bbbbbbbbbbbbbbbb/14032b8f2c8"),
        ],
        "another crate's checkout, another revision, and a too-short prefix are not candidates"
    );
    assert!(verify::candidate_roots(None, rev).is_empty());
}
