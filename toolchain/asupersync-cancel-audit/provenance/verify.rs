//! The checks that decide whether this harness is running asupersync's original cancellation audit against the pinned asupersync.
//!
//! `build.rs` applies them and refuses to build otherwise; `tests/provenance_guard.rs` proves each one accepts what it must and
//! refuses what it must. Nothing here builds, fetches or writes; the only outside process is read-only `git`.
//!
//! Each consumer includes this file with `#[path]` and uses a different subset of it, hence the `dead_code` allowance.
#![allow(dead_code)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Why a check refused. Every variant names the thing that was wrong, so a failed build says which rule it broke.
#[derive(Debug, PartialEq, Eq)]
pub enum Violation {
    Missing {
        what: String,
    },
    Altered {
        what: String,
        got: String,
        want: String,
    },
    FeatureMismatch {
        missing: Vec<String>,
        extra: Vec<String>,
    },
    /// The directory the audit would read is not provably the pinned commit, clean.
    Identity {
        reason: String,
    },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { what } => write!(f, "missing: {what}"),
            Self::Altered { what, got, want } => {
                write!(
                    f,
                    "{what} is not the pinned original (sha256 {got}, want {want})"
                )
            }
            Self::FeatureMismatch { missing, extra } => {
                write!(
                    f,
                    "asupersync feature set differs from the original lane: missing {missing:?}, extra {extra:?}"
                )
            }
            Self::Identity { reason } => write!(f, "not the pinned asupersync: {reason}"),
        }
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn missing(what: &str) -> Violation {
    Violation::Missing {
        what: format!("provenance/expected.json `{what}`"),
    }
}

fn identity(reason: String) -> Violation {
    Violation::Identity { reason }
}

/// `actual` is the file's bytes, or `None` if it could not be read. A file that is absent or differs is refused.
pub fn check_bytes(what: &str, actual: Option<&[u8]>, want_hex: &str) -> Result<(), Violation> {
    let Some(bytes) = actual else {
        return Err(Violation::Missing {
            what: what.to_owned(),
        });
    };
    let got = sha256_hex(bytes);
    if got == want_hex {
        Ok(())
    } else {
        Err(Violation::Altered {
            what: what.to_owned(),
            got,
            want: want_hex.to_owned(),
        })
    }
}

/// The feature set must be equal, not merely sufficient: a missing feature is a narrower lane and an extra one a wider lane.
pub fn check_features(
    declared: &BTreeSet<String>,
    expected: &BTreeSet<String>,
) -> Result<(), Violation> {
    let missing: Vec<String> = expected.difference(declared).cloned().collect();
    let extra: Vec<String> = declared.difference(expected).cloned().collect();
    if missing.is_empty() && extra.is_empty() {
        Ok(())
    } else {
        Err(Violation::FeatureMismatch { missing, extra })
    }
}

/// The features this harness's manifest asks of asupersync, read from its one-line `asupersync = { .. features = [..] }`.
pub fn declared_features(manifest: &str) -> Result<BTreeSet<String>, String> {
    let line = manifest
        .lines()
        .find(|line| line.trim_start().starts_with("asupersync = {"))
        .ok_or("no `asupersync = {` line in the manifest")?;
    let open = "features = [";
    let start = line
        .find(open)
        .ok_or("no features list on the asupersync line")?
        + open.len();
    let end = line[start..]
        .find(']')
        .ok_or("unterminated features list")?
        + start;
    Ok(line[start..end]
        .split(',')
        .map(|item| item.trim().trim_matches('"').to_owned())
        .filter(|item| !item.is_empty())
        .collect())
}

/// A JSON object of strings from `provenance/expected.json`, as `(key, value)` pairs.
pub fn string_map(expected: &Value, key: &str) -> Result<Vec<(String, String)>, Violation> {
    let object = expected
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| missing(key))?;
    object
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|text| (name.clone(), text.to_owned()))
                .ok_or_else(|| missing(&format!("{key}.{name}")))
        })
        .collect()
}

/// The paths the audit reads beneath the asupersync root: every `.rs` under `src` (the census walks all of it), the prior audits
/// under `tests`, and the manifests that fix the feature table. All of them must equal the pinned commit.
const READ_BY_THE_AUDIT: [&str; 5] = [
    "src",
    "tests",
    "Cargo.toml",
    "Cargo.lock",
    "conformance/Cargo.toml",
];

/// Read-only `git -C root ...`. Fails closed: git absent, refusing the directory (for example on ownership), or exiting non-zero is
/// a refusal with git's own words, never a pass.
fn git(root: &Path, args: &[&str]) -> Result<String, Violation> {
    let output = Command::new("git")
        .arg("--no-optional-locks")
        .arg("-C")
        .arg(root)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .map_err(|error| identity(format!("cannot run git: {error}")))?;
    if !output.status.success() {
        return Err(identity(format!(
            "`git {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Is `root` the pinned asupersync commit, with nothing the audit reads changed, added or hidden? It must have its OWN `.git` (a
/// directory merely inside some other repository is not taken for it), `HEAD` must be exactly `rev`, and `git status` over the
/// paths the audit reads must be empty, counting untracked files (a stray `.rs` is read by the census) and ignored ones.
/// Cargo's git checkout of the pinned rev satisfies this; a copy, a modified checkout or a different revision does not.
pub fn verify_checkout(root: &Path, rev: &str) -> Result<(), Violation> {
    if !root.join(".git").exists() {
        return Err(identity(format!(
            "{} has no .git metadata of its own",
            root.display()
        )));
    }
    let head = git(root, &["rev-parse", "HEAD"])?;
    if head.trim() != rev {
        return Err(identity(format!("HEAD is {}, want {rev}", head.trim())));
    }
    let mut status: Vec<&str> = vec![
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=traditional",
        "--",
    ];
    status.extend(READ_BY_THE_AUDIT);
    let dirty = git(root, &status)?;
    if !dirty.trim().is_empty() {
        let shown: Vec<&str> = dirty.lines().take(8).collect();
        return Err(identity(format!(
            "{} path(s) the audit reads differ from HEAD: {}",
            dirty.lines().count(),
            shown.join("; ")
        )));
    }
    Ok(())
}

/// The dependency Cargo compiled is the one that was inspected: this harness's `Cargo.lock` must pin the `asupersync` package to
/// the git commit `rev` (`source = "git+<url>?rev=<rev>#<rev>"`).
pub fn check_lock_source(lock: &str, rev: &str) -> Result<(), Violation> {
    let mut in_asupersync = false;
    for line in lock.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            in_asupersync = false;
        } else if line == "name = \"asupersync\"" {
            in_asupersync = true;
        } else if in_asupersync && line.starts_with("source = ") {
            return if line.starts_with("source = \"git+") && line.ends_with(&format!("#{rev}\"")) {
                Ok(())
            } else {
                Err(identity(format!(
                    "Cargo.lock pins asupersync to {line}, want a git source at {rev}"
                )))
            };
        }
    }
    Err(identity(
        "Cargo.lock has no git-sourced asupersync package".to_owned(),
    ))
}

/// Directories that could be the pinned asupersync, in the order they should be tried: every
/// `<cargo home>/git/checkouts/asupersync-*/<short rev>` whose short rev is a prefix (seven or more characters) of `rev`.
/// There is no override: nothing here trusts a candidate, `verify_checkout` decides, and a layout this does not find fails the
/// build with the candidates tried rather than reading some other directory.
pub fn candidate_roots(cargo_home: Option<PathBuf>, rev: &str) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    let Some(home) = cargo_home else {
        return found;
    };
    let Ok(repos) = fs::read_dir(home.join("git").join("checkouts")) else {
        return found;
    };
    for repo in repos.flatten() {
        if !repo
            .file_name()
            .to_string_lossy()
            .starts_with("asupersync-")
        {
            continue;
        }
        let Ok(shorts) = fs::read_dir(repo.path()) else {
            continue;
        };
        for short in shorts.flatten() {
            let name = short.file_name().to_string_lossy().into_owned();
            if name.len() >= 7 && rev.starts_with(&name) {
                found.push(short.path());
            }
        }
    }
    found
}
