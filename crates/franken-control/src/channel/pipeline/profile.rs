//! Checks of the control channel against the runtime profile it must live in (N02 / `ffw-ugf`, acceptance
//! row 17; the profile itself is P03's): **single-thread cooperative, bounded, no 64-bit atomics, finite caps**.
//!
//! Tests only. Two things are checked, both by running code rather than by reading it:
//!
//! * **The sources.** [`violations`] reads the production part of every channel source file (the part before
//!   `mod tests`, with comments and string literals blanked out) and reports any thread, lock, atomic, `Arc`,
//!   clock read, file, socket, process, environment or `unsafe` use. The channel is handed the time and has
//!   no I/O, so there is nothing for it to report. The scanner is shown to work: it passes the real sources,
//!   flags one planted violation of each category, and ignores the same words in comments and strings.
//! * **The caps.** [`census`] reads the size of every structure the channel keeps (the two queues, the ledger,
//!   its floors, the rate buckets, the facts waiting for a log, the log) after every operation of a
//!   six-thousand-operation flood, and requires each to stay within the cap its configuration or
//!   `MAX_PEERS` gives it. It is shown to work too: an authority that admits every identity, which breaks the
//!   contract in `peer.rs` ("the set of distinct identities that can ever authenticate is bounded"), takes
//!   the per-peer tables past their caps and the census says so.
//!
//! What this is not: a measurement of heap or stack, a thread census, or a target build. The channel
//! allocates small buffers on every request (the bytes it verifies, copies of identifiers, a result
//! vector), bounded by the queue and request sizes but not counted here. The no-atomic64 property is
//! shown for device targets by the `-Z build-std` builds, which are central runs, not by this file.

use franken_session::{AuthorityToken, UnifiedGroupSession};

use super::ControlChannel;
use crate::channel::diag::{ChannelLog, LogConfig, LogKey};
use crate::channel::limiter::RateLimit;
use crate::channel::peer::ephemeral::{EphemeralPeers, test_key};
use crate::channel::peer::{
    AuthFailure, AuthProof, Authenticated, MAX_PEERS, PeerAuthority, PeerId, PeerRole,
    compute_proof,
};
use crate::channel::pipeline::{ChannelConfig, Rejection, SubmitResult};
use crate::channel::request::{AckBody, AckRequest, ControlCommand, ControlRequest, RequestBody};
use crate::channel::testkit::fixture_session;

const EPOCH: u64 = 10;
const MS: u64 = 1_000_000;

// ---------------------------------------------------------------------- the source scan

/// `(category, pattern, whole word)`. A whole-word pattern is not matched inside a longer identifier.
const FORBIDDEN: &[(&str, &str, bool)] = &[
    ("atomic", "Atomic", false),
    ("thread", "std::thread", false),
    ("thread", "thread::", false),
    ("thread", "thread_local", false),
    ("lock", "Mutex", false),
    ("lock", "RwLock", false),
    ("lock", "Condvar", false),
    ("lock", "std::sync", false),
    ("lock", "OnceLock", false),
    ("lock", "LazyLock", false),
    ("lock", "Arc", true),
    ("clock", "Instant", true),
    ("clock", "SystemTime", false),
    ("clock", "UNIX_EPOCH", false),
    ("io", "std::fs", false),
    ("io", "std::net", false),
    ("io", "std::process", false),
    ("io", "std::env", false),
    ("unsafe", "unsafe", true),
];

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn contains_word(line: &str, word: &str) -> bool {
    line.match_indices(word).any(|(start, _)| {
        let before = line[..start].chars().next_back();
        let after = line[start + word.len()..].chars().next();
        !before.is_some_and(is_word_char) && !after.is_some_and(is_word_char)
    })
}

/// The lines of the production part of `source`, with comments and string literals blanked. A string
/// that continues over a line end stays a string on the next line.
fn code_lines(source: &str) -> Vec<String> {
    let production = source
        .split("#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or(source);
    let mut in_string = false;
    let mut lines = Vec::new();
    for line in production.lines() {
        let mut out = String::with_capacity(line.len());
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            if in_string {
                match c {
                    '\\' => {
                        chars.next();
                    }
                    '"' => {
                        in_string = false;
                        out.push(' ');
                    }
                    _ => {}
                }
            } else if c == '"' {
                in_string = true;
                out.push(' ');
            } else if c == '/' && chars.peek() == Some(&'/') {
                break;
            } else {
                out.push(c);
            }
        }
        lines.push(out);
    }
    lines
}

/// Every `(line, category)` at which `source` does something the profile forbids.
fn violations(source: &str) -> Vec<(usize, &'static str)> {
    let mut found = Vec::new();
    for (index, line) in code_lines(source).iter().enumerate() {
        for (category, pattern, whole_word) in FORBIDDEN {
            let hit = if *whole_word {
                contains_word(line, pattern)
            } else {
                line.contains(pattern)
            };
            if hit && !found.contains(&(index + 1, *category)) {
                found.push((index + 1, *category));
            }
        }
    }
    found
}

const SOURCES: &[(&str, &str)] = &[
    ("limiter.rs", include_str!("../limiter.rs")),
    ("peer.rs", include_str!("../peer.rs")),
    ("custody.rs", include_str!("../custody.rs")),
    ("request.rs", include_str!("../request.rs")),
    ("reply.rs", include_str!("../reply.rs")),
    ("wire.rs", include_str!("../wire.rs")),
    ("endpoint.rs", include_str!("../endpoint.rs")),
    ("ledger.rs", include_str!("../ledger.rs")),
    ("diag.rs", include_str!("../diag.rs")),
    ("mod.rs", include_str!("../mod.rs")),
    ("pipeline.rs", include_str!("../pipeline.rs")),
    ("pipeline/ack.rs", include_str!("ack.rs")),
    ("pipeline/persist.rs", include_str!("persist.rs")),
    ("pipeline/restart.rs", include_str!("restart.rs")),
];

/// The scanner's verdict on the real sources: a list of `file:line: category`, empty if clean.
fn scan_the_channel() -> Vec<String> {
    let mut report = Vec::new();
    for (name, source) in SOURCES {
        for (line, category) in violations(source) {
            report.push(format!("{name}:{line}: {category}"));
        }
    }
    report
}

#[test]
fn the_channel_sources_use_no_thread_lock_atomic_clock_io_or_unsafe() {
    for (name, source) in SOURCES {
        assert!(source.len() > 500, "{name} was not read");
        assert!(
            code_lines(source).len() > 20,
            "{name} has no production code to scan"
        );
    }
    assert_eq!(scan_the_channel(), Vec::<String>::new());
}

#[test]
fn the_scanner_flags_each_planted_violation_and_ignores_the_same_words_in_comments_and_strings() {
    // The real sources are clean first, so a flag below is the scanner seeing the plant.
    assert_eq!(scan_the_channel(), Vec::<String>::new());

    let planted: &[(&str, &str)] = &[
        ("atomic", "static COUNT: AtomicU64 = AtomicU64::new(0);"),
        ("atomic", "let n = AtomicUsize::new(1);"),
        ("thread", "let h = std::thread::spawn(|| ());"),
        ("thread", "thread_local! { static X: u8 = 0; }"),
        ("lock", "let m = Mutex::new(0);"),
        ("lock", "let shared = Arc::new(1);"),
        ("lock", "use std::sync::mpsc;"),
        ("clock", "let t = Instant::now();"),
        ("clock", "let t = SystemTime::now();"),
        ("io", "let f = std::fs::File::open(path);"),
        ("io", "let s = std::net::TcpStream::connect(addr);"),
        ("unsafe", "unsafe { *pointer }"),
    ];
    for (category, line) in planted {
        let source = format!("fn f() {{\n    {line}\n}}\n");
        assert_eq!(
            violations(&source)
                .iter()
                .map(|(_, c)| *c)
                .collect::<Vec<_>>(),
            vec![*category],
            "`{line}` should be flagged as {category}, and as nothing else"
        );
    }

    // The paired positive: the same words as comments, documentation, strings and part of longer
    // identifiers are not code.
    let decoys = "\
/// An AtomicU64 or a Mutex would be wrong here; so would std::thread::spawn.
// Instant::now() is never called: time is handed in.
fn f() {
    let note = \"std::fs and unsafe and Arc<T> are only words in a string\";
    let continued = \"a string that runs on \\
        over a line end and mentions SystemTime::now()\";
    let unsafe_code = 1; // forbid(unsafe_code) is a lint name, not a keyword
    let atomically = 2;
    let archive = 3;
    let instantly = 4;
}
";
    assert_eq!(violations(decoys), Vec::<(usize, &str)>::new());

    // Test code after `mod tests` is not production code.
    let tests_after =
        "fn f() {}\n#[cfg(test)]\nmod tests {\n    fn t() { let _ = Mutex::new(0); }\n}\n";
    assert_eq!(violations(tests_after), Vec::<(usize, &str)>::new());
}

// ---------------------------------------------------------------------- the cap census

/// The size of every structure the channel keeps, against its cap. `Err("CAP: ...")` names the first over.
fn census<A: PeerAuthority>(channel: &ControlChannel<A>) -> Result<(), String> {
    let c = channel.config();
    let log = channel.log().map(|l| l.stats());
    let mut rows: Vec<(&str, usize, usize)> = vec![
        (
            "ordinary queue",
            channel.ordinary.len(),
            c.ordinary_capacity,
        ),
        (
            "priority queue",
            channel.priority.len(),
            c.priority_shared_capacity + c.priority_local_reserved,
        ),
        ("ledger", channel.ledger.len(), c.ledger_capacity),
        ("ledger floors", channel.ledger.tracked_peers(), MAX_PEERS),
        ("rate buckets", channel.buckets.len(), 2 * MAX_PEERS),
        ("facts waiting for a log", channel.facts.len(), 0),
    ];
    if let Some(log) = log {
        rows.push(("log records", log.stored, LOG_RECORDS));
        rows.push(("log bytes", log.bytes, LOG_BYTES));
    }
    for (name, len, cap) in rows {
        if len > cap {
            return Err(format!("CAP: {name} holds {len}, its cap is {cap}"));
        }
    }
    Ok(())
}

const LOG_RECORDS: usize = 64;
const LOG_BYTES: usize = 16_384;
const FLOOD: u64 = 6_000;

fn config() -> ChannelConfig {
    let mut c = ChannelConfig::provisional();
    c.ordinary_rate = RateLimit::new(100_000, MS).unwrap();
    c.priority_rate = RateLimit::new(100_000, MS).unwrap();
    c.session_seq_base = 1_000;
    c
}

fn request(
    peer: &str,
    seq: u64,
    revision: Option<u64>,
    command: ControlCommand,
) -> Result<ControlRequest, String> {
    let id = PeerId::parse(peer).map_err(|e| format!("setup: {e}"))?;
    let body =
        RequestBody::new(id, seq, EPOCH, revision, command).map_err(|e| format!("setup: {e}"))?;
    let proof = compute_proof(&test_key(peer), &body.signing_bytes());
    Ok(ControlRequest::new(body, proof))
}

fn start<A: PeerAuthority>(
    authority: A,
) -> Result<(ControlChannel<A>, UnifiedGroupSession), String> {
    let session = fixture_session(EPOCH);
    let mut channel =
        ControlChannel::new(authority, config()).map_err(|e| format!("setup: {e}"))?;
    channel.enable_log(ChannelLog::new(
        LogConfig::new("run-1", "census", LOG_RECORDS, LOG_BYTES)
            .map_err(|e| format!("setup: {e}"))?,
        LogKey::new([7; 32]),
    ));
    let token = AuthorityToken::issue(&session, 1_000_000 * MS);
    channel
        .install_lease(&session, token, 0)
        .map_err(|e| format!("setup: {e}"))?;
    Ok((channel, session))
}

/// Six thousand operations against the real directory: forged requests from identities nobody admitted,
/// ordinary commands from two controllers (more than the queue holds), priority commands from the local
/// user, acknowledgements, and a `step` every seventh operation, over a minute of simulated time (so
/// pending commands expire and outcomes age out). After each one, every structure must be within its cap.
fn flood_the_real_directory() -> Result<(), String> {
    let mut peers = EphemeralPeers::new();
    for (name, role, bound) in [
        ("ctl-a", PeerRole::Controller, Some(EPOCH)),
        ("ctl-b", PeerRole::Controller, Some(EPOCH)),
        ("panel", PeerRole::LocalUser, None),
    ] {
        let id = PeerId::parse(name).map_err(|e| format!("setup: {e}"))?;
        peers
            .admit(&id, role, &test_key(name), bound, 1)
            .map_err(|e| format!("setup: {e:?}"))?;
    }
    let (mut channel, mut session) = start(peers)?;
    let mut now = 0u64;
    for i in 1..=FLOOD {
        now += 10 * MS;
        let revision = Some(session.state_revision);
        let volume = 40 + u8::try_from(i % 50).map_err(|e| format!("setup: {e}"))?;
        match i % 4 {
            0 => {
                // An identity nobody admitted: refused, and it must leave no per-identity state.
                let forged = request(
                    &format!("x{i}"),
                    i,
                    revision,
                    ControlCommand::SetGroupVolume { volume },
                )?;
                let result = channel.submit(now, forged);
                let unknown =
                    SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::UnknownPeer));
                if result != unknown {
                    return Err(format!("setup: a forged request gave {result:?}"));
                }
            }
            1 | 2 => {
                let peer = if i % 4 == 1 { "ctl-a" } else { "ctl-b" };
                channel.submit(
                    now,
                    request(peer, i, revision, ControlCommand::SetGroupVolume { volume })?,
                );
            }
            _ => {
                let mute = ControlCommand::SetMemberMute {
                    member_id: "kitchen".to_string(),
                    muted: i % 2 == 0,
                };
                channel.submit(now, request("panel", i, None, mute)?);
            }
        }
        if i % 7 == 0 {
            channel.step(now, &mut session);
        }
        if i % 11 == 0 {
            let body = AckBody::new(
                PeerId::parse("ctl-a").map_err(|e| format!("setup: {e}"))?,
                i / 2 + 1,
                EPOCH,
            )
            .map_err(|e| format!("setup: {e}"))?;
            let proof = compute_proof(&test_key("ctl-a"), &body.signing_bytes());
            channel.acknowledge(now, &session, &AckRequest::new(body, proof));
        }
        census(&channel).map_err(|e| format!("{e} (operation {i})"))?;
    }
    for _ in 0..20 {
        now += 10 * MS;
        channel.step(now, &mut session);
    }
    census(&channel)?;
    let stats = channel.stats();
    if stats.accounted() != stats.received || stats.acks_accounted() != stats.acks_received {
        return Err(format!(
            "ACCOUNTING: {} of {} requests, {} of {} acks",
            stats.accounted(),
            stats.received,
            stats.acks_accounted(),
            stats.acks_received
        ));
    }
    Ok(())
}

/// An authority that breaks the contract in `peer.rs`: it admits every identity that signs with the key
/// derived from its own name, so the set of identities is not bounded.
struct AnyoneGoes;

impl PeerAuthority for AnyoneGoes {
    fn authenticate(
        &self,
        peer: &PeerId,
        message: &[u8],
        proof: &AuthProof,
    ) -> Result<Authenticated, AuthFailure> {
        if compute_proof(&test_key(peer.as_str()), message) != *proof {
            return Err(AuthFailure::BadProof);
        }
        Ok(Authenticated {
            peer: peer.clone(),
            role: PeerRole::Controller,
            bound_epoch: Some(EPOCH),
            version: 1,
        })
    }

    fn is_current(&self, _auth: &Authenticated) -> bool {
        true
    }
}

/// The same census, against an authority that admits two hundred distinct identities, one command each.
fn flood_an_authority_that_admits_everyone() -> Result<(), String> {
    let (mut channel, mut session) = start(AnyoneGoes)?;
    let mut now = 0u64;
    for i in 1..=200u64 {
        now += 10 * MS;
        let revision = Some(session.state_revision);
        channel.submit(
            now,
            request(
                &format!("y{i}"),
                1,
                revision,
                ControlCommand::SetGroupVolume { volume: 60 },
            )?,
        );
        if i % 3 == 0 {
            channel.step(now, &mut session);
        }
        census(&channel).map_err(|e| format!("{e} (identity {i})"))?;
    }
    Ok(())
}

#[test]
fn a_flood_never_takes_any_structure_past_its_cap() {
    assert_eq!(flood_the_real_directory(), Ok(()));
}

#[test]
fn an_authority_that_admits_every_identity_takes_the_per_peer_tables_past_their_caps() {
    // The real directory passes first, so a failure below is the census seeing the plant.
    assert_eq!(flood_the_real_directory(), Ok(()));
    let verdict = flood_an_authority_that_admits_everyone();
    assert!(
        verdict
            .as_ref()
            .is_err_and(|e| e.starts_with("CAP: rate buckets holds 33, its cap is 32")),
        "the census did not catch the unbounded authority at the first identity past the cap: {verdict:?}"
    );
}
