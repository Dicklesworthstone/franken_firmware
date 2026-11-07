#![forbid(unsafe_code)]

fn main() {
    // These are Cargo's actual selected build settings, not guessed from debug_assertions.
    for (input, output) in [
        ("OPT_LEVEL", "N05_OPT_LEVEL"),
        ("DEBUG", "N05_DEBUG"),
        ("PROFILE", "N05_CARGO_PROFILE"),
    ] {
        let value = std::env::var(input).expect("Cargo supplies the selected build profile");
        println!("cargo:rustc-env={output}={value}");
    }
}
