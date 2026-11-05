//! `seed_corpus OUT_DIR`: write the seed corpus (one directory per target) and print one line per target.
//!
//! The files are derived from the committed golden vectors and are not committed themselves.

use franken_stream_fuzz::seed::{all, TARGETS};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let [_, out] = args.as_slice() else {
        eprintln!("usage: seed_corpus OUT_DIR");
        return ExitCode::from(2);
    };
    let out = PathBuf::from(out);
    let mut counts: BTreeMap<&str, (usize, usize)> = TARGETS.iter().map(|t| (*t, (0, 0))).collect();
    for seed in all() {
        let dir = out.join(seed.target);
        if let Err(err) = fs::create_dir_all(&dir) {
            eprintln!("cannot create {}: {err}", dir.display());
            return ExitCode::FAILURE;
        }
        if let Err(err) = fs::write(dir.join(&seed.name), &seed.bytes) {
            eprintln!("cannot write seed {}/{}: {err}", seed.target, seed.name);
            return ExitCode::FAILURE;
        }
        let entry = counts.entry(seed.target).or_insert((0, 0));
        entry.0 += 1;
        entry.1 = entry.1.max(seed.bytes.len());
    }
    for (target, (files, max_bytes)) in counts {
        println!("N01-FUZZ-SEEDS {target} files={files} max_bytes={max_bytes}");
    }
    ExitCode::SUCCESS
}
