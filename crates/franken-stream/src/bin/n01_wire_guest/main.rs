//! N01 golden-vector replay for a guest (`ffw-ey5`, contract section 7).
//!
//! Replays every committed wire and negotiation vector through the real decoder, encoder, receiver and negotiation
//! code and prints one `N01-...` line per result, ending with `N01-DONE`. It reads no file and opens no socket: the
//! vectors are compiled in, so a bare QEMU guest can run it. Exit 0 only if no comparison of its own failed.
//!
//! This binary proves nothing about the machine it runs on beyond what its first line says (`N01-GUEST`: the
//! target's byte order and a byte-order probe). Whether that machine was a big-endian guest is the receipt of
//! whatever ran it; `tests/n01/guest_transcript.py` judges the log and requires `--endian big` for a MIPS or
//! PowerPC run. It is a `[[bin]]` and not an example so that a cross-build sees only the package's normal
//! dependencies.

mod replay;

use std::process::ExitCode;

fn main() -> ExitCode {
    match replay::transcript() {
        Ok(transcript) => {
            for line in &transcript.lines {
                println!("{line}");
            }
            if transcript.mismatches == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(problem) => {
            println!("N01-MISMATCH the replay could not run: {problem}");
            ExitCode::FAILURE
        }
    }
}
