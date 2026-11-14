//! Isolated journal file worker; transport is inherited stdin/stdout.
#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return std::process::ExitCode::from(2);
    }
    #[cfg(unix)]
    if let Some(profile) = args[2].to_str()
        && franken_speaker::journal_process::run_worker(std::path::Path::new(&args[1]), profile)
            .is_ok()
    {
        return std::process::ExitCode::SUCCESS;
    }
    std::process::ExitCode::from(1)
}
