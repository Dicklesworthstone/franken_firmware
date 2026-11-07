//! A source scan: no production file names the plain development stepper or the in-memory journal stepper except the files
//! that define and re-export them and the Q01 campaign harness (N02 / `ffw-ugf`, G03 / `ffw-xvv`).
//!
//! The request handler takes its stepper in its `Context`, and the owner builds it. The plain development stepper stores
//! nothing, and the in-memory one stores nothing that survives the process. A production owner must therefore have to *write
//! the name* of a non-durable stepper to get one, and this scan is what makes writing it somewhere new visible: the name may
//! appear in the file that defines it (`channel/pipeline/persist.rs`), the file that re-exports it (`channel/pipeline.rs`), and
//! the harness (`franken-speaker/src/control_adapter.rs`, fixture keys and no journal). Test modules and the `tests/`
//! directories are not production, and are not scanned.
//!
//! The scan reads the production part of every `crates/*/src/**/*.rs`: everything before the file's `#[cfg(test)]` tests
//! module. It is a source scan and sees names, not types: it does not prove that a production owner holds a durable stepper,
//! only that none of them wrote the name of one that is not.

use std::fs;
use std::path::{Path, PathBuf};

const NAMES: [&str; 2] = ["DevelopmentVolatile", "MemoryJournalStepper"];
const DEFINES: &str = "franken-control/src/channel/pipeline/persist.rs";
const REEXPORTS: &str = "franken-control/src/channel/pipeline.rs";
const HARNESS: &str = "franken-speaker/src/control_adapter.rs";

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Everything before the conventional tests module; the whole text if there is none.
fn production_part(text: &str) -> &str {
    match text.find("#[cfg(test)]\nmod tests") {
        Some(at) => &text[..at],
        None => text,
    }
}

fn names_a_development_stepper(text: &str) -> bool {
    NAMES.iter().any(|name| text.contains(name))
}

#[test]
fn the_scan_reads_the_production_part_only_and_notices_a_name_there() {
    let in_production =
        "fn a() { let _ = DevelopmentVolatile; }\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n";
    assert!(names_a_development_stepper(production_part(in_production)));
    let in_memory = "fn a() { MemoryJournalStepper::new(); }\n";
    assert!(names_a_development_stepper(production_part(in_memory)));
    // The permitted positive: a name that appears only in the tests module is not production.
    let in_tests = "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() { DevelopmentVolatile; }\n}\n";
    assert!(!names_a_development_stepper(production_part(in_tests)));
    assert!(!names_a_development_stepper(production_part(
        "fn a() { Durable::new(j); }\n"
    )));
}

#[test]
fn no_production_file_but_the_harness_names_a_non_durable_stepper() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crates directory");
    let mut files = Vec::new();
    for entry in fs::read_dir(crates)
        .expect("the crates directory is readable")
        .flatten()
    {
        rust_files(&entry.path().join("src"), &mut files);
    }
    assert!(
        files.len() > 20,
        "the scan saw {} source files: it is looking in the wrong place",
        files.len()
    );
    let (mut offenders, mut defined, mut reexported, mut harnessed) =
        (Vec::new(), false, false, false);
    for file in &files {
        let text = fs::read_to_string(file).expect("a source file is UTF-8");
        let names = names_a_development_stepper(production_part(&text));
        let relative = file
            .strip_prefix(crates)
            .expect("under the crates directory")
            .to_string_lossy()
            .replace('\\', "/");
        match relative.as_str() {
            DEFINES => defined = names,
            REEXPORTS => reexported = names,
            HARNESS => harnessed = production_part(&text).contains("DevelopmentVolatile"),
            _ if names => offenders.push(relative),
            _ => {}
        }
    }
    assert!(
        offenders.is_empty(),
        "production files that name a non-durable stepper: {offenders:?}"
    );
    // The scan saw what it should have: the definition, the re-export and the harness all name it.
    assert!(
        defined && reexported && harnessed,
        "the scan did not find the definition ({defined}), the re-export ({reexported}) and the harness ({harnessed})"
    );
}
