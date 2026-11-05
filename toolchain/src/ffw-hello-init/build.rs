//! Captures the identity of the compile that produced the E03 probe (bead ffw-q2p: "the probe must
//! record its target triple, compiler version, linker, and libc"; bead ffw-ll1: the receipt records
//! `rustc -vV` from the build side) so the booted binary can print it.
//!
//! Build scripts run on the host. This reads only what cargo itself passes (`TARGET`, `RUSTC`,
//! `CARGO_ENCODED_RUSTFLAGS`) and never fails the build: anything it cannot read is spelled
//! `unknown`/`unspecified`, which the verifier then refuses to treat as an identity. Every token is
//! restricted to `[A-Za-z0-9._+-]` and capped, because the guest prints it on one bounded serial line.
//!
//! The linker *name* is not visible to a build script (cargo does not export `target.<triple>.linker`);
//! only the flavor arrives through rustflags. The runner records the configured linker from the
//! committed `.cargo/config.toml` as a configuration claim, not an attestation.

use std::process::Command;

const MAX_TOKEN: usize = 40;

fn token(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(MAX_TOKEN)
        .collect();
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned
    }
}

/// The value of `key: value` in `rustc -vV` output, or `"unknown"`.
fn verbose_field(text: &str, key: &str) -> String {
    text.lines()
        .find_map(|line| {
            line.strip_prefix(key)
                .and_then(|rest| rest.strip_prefix(':'))
        })
        .map_or_else(|| "unknown".to_string(), |value| value.trim().to_string())
}

fn linker_flavor(encoded_rustflags: &str) -> String {
    for flag in encoded_rustflags.split('\u{1f}') {
        let flag = flag.strip_prefix("-C").unwrap_or(flag);
        if let Some(value) = flag.strip_prefix("linker-flavor=") {
            return token(value);
        }
    }
    "unspecified".to_string()
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");

    let target = token(&std::env::var("TARGET").unwrap_or_default());
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let verbose = Command::new(&rustc)
        .arg("-vV")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .unwrap_or_default();
    let release = verbose_field(&verbose, "release");
    let hash = verbose_field(&verbose, "commit-hash");
    // The short commit is what `rustc --version` prints (the first nine hex digits of the full hash).
    let short_commit: String = hash.chars().take(9).collect();
    let flavor = linker_flavor(&std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default());

    println!("cargo:rustc-env=FFW_BUILD_TARGET={target}");
    println!("cargo:rustc-env=FFW_BUILD_RUSTC={}", token(&release));
    println!(
        "cargo:rustc-env=FFW_BUILD_RUSTC_COMMIT={}",
        token(&short_commit)
    );
    println!("cargo:rustc-env=FFW_BUILD_LINKER_FLAVOR={flavor}");
    println!("cargo:rustc-env=FFW_RUSTC_HASH={}", token(&hash));
    println!(
        "cargo:rustc-env=FFW_RUSTC_DATE={}",
        token(&verbose_field(&verbose, "commit-date"))
    );
    println!(
        "cargo:rustc-env=FFW_RUSTC_HOST={}",
        token(&verbose_field(&verbose, "host"))
    );
    println!(
        "cargo:rustc-env=FFW_RUSTC_LLVM={}",
        token(&verbose_field(&verbose, "LLVM version"))
    );
}
