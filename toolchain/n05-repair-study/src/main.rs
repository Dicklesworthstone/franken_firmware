#![forbid(unsafe_code)]
use n05_repair_study::{StudyInput, run};
use std::io::{Read, Write};
fn main() {
    let result = (|| -> Result<(), String> {
        let mut input = String::new();
        std::io::stdin()
            .take(4097)
            .read_to_string(&mut input)
            .map_err(|_| "stdin unavailable")?;
        if input.len() > 4096 {
            return Err("input exceeds 4096 bytes".into());
        }
        let request: StudyInput =
            serde_json::from_str(&input).map_err(|_| "invalid study input")?;
        let result = run(request)?;
        serde_json::to_writer(std::io::stdout().lock(), &result)
            .map_err(|_| "result sink unavailable")?;
        std::io::stdout()
            .write_all(b"\n")
            .map_err(|_| "result sink unavailable")?;
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("N05 incomplete: {error}");
        std::process::exit(1);
    }
}
