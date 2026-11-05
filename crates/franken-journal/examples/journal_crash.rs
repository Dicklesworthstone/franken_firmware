//! Process-restart crash driver for the U01 journal (`scripts/e2e/u01` runs it).
//!
//!   journal_crash init <image>
//!   journal_crash run  <image> <vectors.json> <script-id> [--die-after-bytes N]
//!   journal_crash dump <image>
//!
//! `init` creates a fresh two-segment file image of erased bytes (it refuses to overwrite). `run` opens the journal on a
//! file-backed storage and replays one scripted scenario of the shared vectors, printing `ack <i>` after step `i` has
//! returned. With `--die-after-bytes N` the storage kills the process (`abort`, no unwinding, no flush) in the middle of
//! the write or erase that crosses the N-th byte, after writing the bytes before it: a real process death mid-write.
//! `dump` reopens the image (recovery runs) and prints the recovered state as `state <hex>` and `source <name>`.
//!
//! A process kill is not a power cut: bytes already handed to the OS survive it, synced or not. That is the same
//! experiment as a power cut that keeps a prefix of the unsynced writes, which the in-memory fake covers exhaustively.

use franken_journal::{Journal, JournalError, Limits, Namespace, Source, Storage, StorageFault};
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::ExitCode;

struct FileStorage {
    file: std::fs::File,
    segment: usize,
    die_after: Option<usize>,
    written: usize,
}

impl FileStorage {
    fn open(path: &str, segment: usize, die_after: Option<usize>) -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        if file.metadata()?.len() != (2 * segment) as u64 {
            return Err(std::io::Error::other(
                "the image is not exactly two segments",
            ));
        }
        Ok(Self {
            file,
            segment,
            die_after,
            written: 0,
        })
    }

    /// Write `data` at `offset`; if the byte budget runs out inside it, write the part that fits and die.
    fn put(&mut self, offset: usize, data: &[u8]) -> Result<(), StorageFault> {
        let left = self
            .die_after
            .map(|limit| limit.saturating_sub(self.written));
        let (keep, dying) = match left {
            Some(left) if data.len() > left => (left, true),
            _ => (data.len(), false),
        };
        self.file
            .seek(SeekFrom::Start(offset as u64))
            .map_err(|_| StorageFault::Io)?;
        self.file
            .write_all(&data[..keep])
            .map_err(|_| StorageFault::Io)?;
        self.written += keep;
        if dying {
            std::process::abort();
        }
        Ok(())
    }
}

impl Storage for FileStorage {
    fn segment_bytes(&self) -> usize {
        self.segment
    }

    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), StorageFault> {
        let mut file = &self.file;
        file.seek(SeekFrom::Start(offset as u64))
            .map_err(|_| StorageFault::Io)?;
        file.read_exact(out).map_err(|_| StorageFault::OutOfRange)
    }

    fn program(&mut self, offset: usize, data: &[u8]) -> Result<(), StorageFault> {
        let mut current = vec![0u8; data.len()];
        self.read(offset, &mut current)?;
        if data.iter().zip(&current).any(|(new, old)| new & !old != 0) {
            return Err(StorageFault::BitsCannotRise);
        }
        self.put(offset, data)
    }

    fn erase(&mut self, segment: usize) -> Result<(), StorageFault> {
        if segment > 1 {
            return Err(StorageFault::OutOfRange);
        }
        let blank = vec![0xFFu8; self.segment];
        self.put(segment * self.segment, &blank)
    }

    fn sync(&mut self) -> Result<(), StorageFault> {
        self.file.sync_all().map_err(|_| StorageFault::SyncFailed)
    }
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap_or(0))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Apply one scripted step (the vectors' JSON form). `Ok` means the step returned, whether it committed or was rejected.
fn apply(journal: &mut Journal<FileStorage>, step: &Value) -> Result<(), JournalError> {
    let args = step["args"].as_array().cloned().unwrap_or_default();
    let bytes = |i: usize| unhex(args.get(i).and_then(Value::as_str).unwrap_or(""));
    let int = |i: usize| args.get(i).and_then(Value::as_u64).unwrap_or(0);
    let ns = |i: usize| {
        Namespace::from_u8(u8::try_from(int(i)).unwrap_or(0)).unwrap_or(Namespace::Settings)
    };
    let outcome = match step["op"].as_str().unwrap_or("") {
        "put" => journal.put(ns(0), &bytes(1), &bytes(2)).map(|_| ()),
        "delete" => journal.delete(ns(0), &bytes(1)).map(|_| ()),
        "reset_settings" => journal.reset_settings().map(|_| ()),
        "clear_calibration" => journal.clear_calibration().map(|_| ()),
        "install" => journal.install(&bytes(0), int(1), &bytes(2)).map(|_| ()),
        "revoke" => journal.revoke(&bytes(0)).map(|_| ()),
        "reset_pairing" => journal.reset_pairing().map(|_| ()),
        "raise_mark" => journal.raise_mark(&bytes(0), int(1)).map(|_| ()),
        "stage_setting" => journal.stage_setting(&bytes(0), &bytes(1)),
        "flush_settings" => journal.flush_settings(int(0)).map(|_| ()),
        other => {
            eprintln!("unknown step {other}");
            return Err(JournalError::BadOp);
        }
    };
    match outcome {
        Err(err @ (JournalError::Storage(_) | JournalError::Poisoned)) => Err(err),
        _ => Ok(()), // committed, no-op, or rejected by a rule: the step returned
    }
}

fn run(image: &str, vectors: &str, id: &str, die_after: Option<usize>) -> Result<(), String> {
    let lim = Limits::tiny();
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(vectors).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let script = doc["scripts"]
        .as_array()
        .and_then(|all| all.iter().find(|s| s["id"] == id))
        .ok_or_else(|| format!("no script {id}"))?;
    let storage =
        FileStorage::open(image, lim.segment_bytes, die_after).map_err(|e| e.to_string())?;
    let (mut journal, _rec) =
        Journal::open(storage, lim).map_err(|e| format!("open: {}", e.code()))?;
    println!("opened");
    for (i, step) in script["steps"]
        .as_array()
        .ok_or("no steps")?
        .iter()
        .enumerate()
    {
        apply(&mut journal, step).map_err(|e| format!("step {}: {}", i + 1, e.code()))?;
        println!("ack {}", i + 1);
    }
    println!("done");
    Ok(())
}

fn dump(image: &str) -> Result<(), String> {
    let lim = Limits::tiny();
    let storage = FileStorage::open(image, lim.segment_bytes, None).map_err(|e| e.to_string())?;
    let (journal, rec) = Journal::open(storage, lim).map_err(|e| format!("open: {}", e.code()))?;
    let source = match rec.source {
        Source::Blank => "blank",
        Source::Unrecoverable => "unrecoverable",
        Source::Segment => "segment",
    };
    println!(
        "state {}",
        hex(&journal
            .state()
            .canonical_bytes()
            .map_err(|e| e.code().to_string())?)
    );
    println!("source {source}");
    Ok(())
}

fn init(image: &str) -> Result<(), String> {
    let lim = Limits::tiny();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(image)
        .map_err(|e| e.to_string())?;
    file.write_all(&vec![0xFFu8; 2 * lim.segment_bytes])
        .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("init") if args.len() == 3 => init(&args[2]),
        Some("dump") if args.len() == 3 => dump(&args[2]),
        Some("run") if args.len() == 5 || (args.len() == 7 && args[5] == "--die-after-bytes") => {
            let die = if args.len() == 7 { args[6].parse::<usize>().ok() } else { None };
            run(&args[2], &args[3], &args[4], die)
        }
        _ => Err("usage: journal_crash init <image> | run <image> <vectors.json> <script-id> [--die-after-bytes N] | dump <image>".to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}
