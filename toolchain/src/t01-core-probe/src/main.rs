//! T01-X02 core-footprint probe (ffw-32a).
//!
//! A linked, runnable binary that drives the seven tailscale-rs core crates (`ts_keys`, `ts_noise`, `ts_tunnel`, `ts_disco_protocol`,
//! `ts_control_serde`, `ts_packetfilter_state`, `ts_overlay_router`, pin `d34658bb`, v0.6.1) through their real public APIs on bounded,
//! deterministic inputs taken from `tests/tailscale-fixtures/synthetic/`, then reads its own resource use from `/proc/self`.
//!
//! Output grammar (agreed with the X02 judge, thread ffw-32a, YellowBrook 15333), one line each, ASCII only, every line starting `T01X02 `:
//!
//! * `T01X02 PHASE <NAME> ok <k=v ...>` or `T01X02 PHASE <NAME> fail <k=v ...>`, one per phase when it ends, in the fixed order of
//!   [`PHASES`] (one phase per core crate, then `CRYPTO_KAT` from `kat.rs` last). The facts are space-separated `key=value`
//!   pairs: key `[a-z][a-z0-9_]*`, value printable ASCII with no space and no `=`, no repeated key. A phase whose facts break that is printed
//!   as `fail reason=bad_facts`. A failure of this file's phases is `fail reason=<word>`;
//! * `T01X02 VmHWM <n>`, `T01X02 VmRSS <n>` (kB, as `/proc/self/status` reports them), `T01X02 utime <n>`, `T01X02 stime <n>` (raw clock
//!   ticks, `/proc/self/stat` fields 14 and 15), in that order, after the last PHASE. A reading that is absent or does not parse as a canonical
//!   integer prints `UNKNOWN`, never `0`;
//! * `T01X02 END ok=<n> fail=<n> unknown=<n>` last: `ok` and `fail` count PHASE lines, `unknown` counts `UNKNOWN` resource lines. The exit
//!   status is 0 whenever END was printed: the verdict is the transcript, judged elsewhere.
//!
//! What it is not: a tailnet client. There is no network, no async runtime and no enrollment. Two `ts_tunnel` endpoints exchange packets
//! with each other in memory only (a handshake, then transport data in both directions), and the outbound overlay router routes packets in
//! memory. It says nothing about the fit of a full client and it does not close T01.
//!
//! Limits, kept in the transcript's contract text as agreed (CrimsonMouse 15589, points 3-6 of the no-claim list; 4 corrected for its
//! entropy citations by RedPuma F4 and extended by the gate of v3, 7 and 8 added by v3):
//! 3. Packet-filter decisions are not evaluated. The 12 `filter_cases` of `netmap.json` are checked for shape only: evaluation lives in
//!    `ts_packetfilter`, outside the seven core crates. `TS_PACKETFILTER_STATE` exercises `should_clear_storage` only.
//! 4. `TS_NOISE` and the handshake inside `TS_TUNNEL` need the operating system's random source. `TS_NOISE` draws its ephemeral keys at
//!    `ts_noise/src/ik.rs:62,102`; the `TS_TUNNEL` handshake is `ikpsk2`, which draws at `ts_noise/src/ikpsk2.rs:72,120`, and
//!    `SessionId::random()` (`ts_tunnel/src/ids.rs:56`, `messages.rs:31-32`) draws more. On the MIPS guest kernel (Debian 4.19.249)
//!    `getrandom(.., 0)` blocks until the pool is ready, about 1 s at HZ=250 by the kernel source (facts: thread ffw-32a, 15799). So the
//!    probe runs the same draw once (`NodeKeyPair::random()`) on a worker thread before `TS_NOISE` and waits at most 40 s: when it returns,
//!    `TS_NOISE` prints the measured `rng_wait_ms`; when it does not, `TS_NOISE` and the `TS_TUNNEL` handshake print
//!    `fail reason=rng_blocked`, every other phase still runs, and END is printed. No substitute bytes, no urandom, no seed. A stall before
//!    the gate shows as a missing line, because the PHASE lines are line-buffered.
//! 5. The key-expiry policy is the native design's, not a crate API; `key_expiry.json` only supplies the clock values that drive the
//!    endpoint's event dispatcher. The ticks are raw `/proc` ticks; the tick rate is not read here.
//! 6. `Cargo.toml` assumes the pinned tailscale-rs tree sits at `<sync root>/tailscale-rs/` and the fixtures at
//!    `<sync root>/tests/tailscale-fixtures/synthetic/` (they are embedded at build time).
//! 7. `ts_bart`'s `lut` default feature stays on: `ts_overlay_router` takes `ts_bart` with its defaults, so `default-features = false` in
//!    `Cargo.toml` removes nothing. Its 32 KiB lookup table is in the binary and in `VmHWM`.
//! 8. An RNG *error* (as opposed to a wait) is not handled: `x25519-dalek` calls `getrandom::fill(..).expect("getrandom failure")`, and
//!    under the release profile's `panic = "abort"` the process aborts and prints no END. The gate bounds a wait, not an error; catching an
//!    error would need a direct `getrandom` dependency, which this probe does not have.
//!
//! Every phase result printed is a count or a wire size, never a random byte. `sent` and `offered` are what the probe handed in;
//! `refused` and `dropped` are offered minus delivered; `recv`, `bytes`, `wire_packets`, `wire_bytes`, `routed`, the bucket counts,
//! `encoded_bytes` and `decoded_regions` are tallied from what the crates returned. `wire_bytes` of `TS_TUNNEL` is checked as a key only: its
//! predicted value is 348 (148 initiation + 92 response + 3 x 36 transport, arithmetic from the pinned structs, RedPuma F3), to be pinned
//! only after a central run prints it.
#![forbid(unsafe_code)]

mod kat;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
    process::ExitCode,
    str::FromStr,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use serde_json::error::Category;
use ts_bart::{RoutingTable, Table};
use ts_control_serde::{DerpIpUsage, DerpMap, DerpRegion, DerpRegionId, DerpServer};
use ts_disco_protocol::{
    CallMeMaybe, Endpoint as DiscoEndpoint, Header, MessageType, Packet, Ping, Pong,
    is_disco_message,
};
use ts_keys::{
    DiscoKeyPair, DiscoPrivateKey, DiscoPublicKey, Export, ExportableKey, MachineKeyPair,
    MachinePrivateKey, MachinePublicKey, NodeKeyPair, NodePrivateKey, NodePublicKey,
};
use ts_noise::{
    core::Role,
    ik::{ReceivedHandshake, SentHandshake},
};
use ts_overlay_router::outbound::{RouteAction, Router};
use ts_packet::PacketMut;
use ts_packetfilter_state::should_clear_storage;
use ts_tunnel::{Endpoint as TunnelEndpoint, PeerConfig, PeerId};

/// The phases, in the order they run and print: one per core crate, then `CRYPTO_KAT` (DarkPeak's `kat.rs`) last. The judge's table has
/// exactly these eight, so a passing run prints `END ok=8`.
const PHASES: [&str; 8] = [
    "TS_KEYS",
    "TS_NOISE",
    "TS_TUNNEL",
    "TS_CONTROL_SERDE",
    "TS_PACKETFILTER_STATE",
    "TS_DISCO_PROTOCOL",
    "TS_OVERLAY_ROUTER",
    "CRYPTO_KAT",
];

/// What a phase hands back: `Ok(facts)` prints `T01X02 PHASE <NAME> ok <facts>`, `Err(facts)` prints `T01X02 PHASE <NAME> fail <facts>`.
/// `facts` is one or more space-separated `key=value` pairs (key `[a-z][a-z0-9_]*`, value printable ASCII with no space and no `=`, no
/// repeated key); anything else is printed as `fail reason=bad_facts`.
pub type PhaseResult = Result<String, String>;

/// This file's phases fail with one reason word; it becomes the `reason=<word>` fact.
fn lift(outcome: Result<String, &'static str>) -> PhaseResult {
    outcome.map_err(|reason| format!("reason={reason}"))
}

/// The judge's fact rules: at least one pair, pairs separated by single spaces, key `[a-z][a-z0-9_]*`, value one or more printable ASCII
/// characters (no space, no `=`), no key twice.
fn facts_well_formed(facts: &str) -> bool {
    let mut keys: Vec<&str> = Vec::new();
    for pair in facts.split(' ') {
        let Some((key, value)) = pair.split_once('=') else {
            return false;
        };
        let mut chars = key.chars();
        let first_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase());
        let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        let value_ok = !value.is_empty()
            && value
                .bytes()
                .all(|b| (0x21..=0x7e).contains(&b) && b != b'=');
        if !first_ok || !rest_ok || !value_ok || keys.contains(&key) {
            return false;
        }
        keys.push(key);
    }
    !keys.is_empty()
}

const IDENTITY_SCHEMA: &str = "ffw.t01.fixture.identity.v1";
const NETMAP_SCHEMA: &str = "ffw.t01.fixture.netmap.v1";
const DERP_MAP_SCHEMA: &str = "ffw.t01.fixture.derp_map.v1";
const KEY_EXPIRY_SCHEMA: &str = "ffw.t01.fixture.key_expiry.v1";

/// A fixture file is a few kilobytes; anything near this is not one.
const MAX_FIXTURE_BYTES: usize = 64 * 1024;
const MAX_JSON_DEPTH: usize = 16;
/// `/proc/self/status` and `/proc/self/stat` are well under this.
const PROC_READ_CAP: u64 = 64 * 1024;
const STATUS_PATH: &str = "/proc/self/status";
const STAT_PATH: &str = "/proc/self/stat";

const NOISE_PROLOGUE: &[u8] = b"T01X02-PROBE";
const TX_ID: [u8; 12] = [0xa5; 12];
const PING_PADDING: usize = 8;
const DISCO_PORT_BASE: u16 = 41641;
/// The longest the first draw of operating-system randomness may take before the RNG gate gives up (CrimsonMouse 15858). The kernel source
/// puts the wait on the MIPS guest at about one second; the supervised child has 180 s in all.
const RNG_WAIT: Duration = Duration::from_secs(40);
/// The gate's worker needs the stack of one key generation, not a default thread's.
const RNG_THREAD_STACK: usize = 512 * 1024;

// ---- the report ---------------------------------------------------------------------------------------------------------------------

/// What a run printed and counted.
pub struct Report {
    /// Every line, in order, as printed.
    #[allow(dead_code)]
    pub lines: Vec<String>,
    pub ok: usize,
    pub fail: usize,
    pub unknown: usize,
    live: bool,
}

impl Report {
    fn new(live: bool) -> Self {
        Self {
            lines: Vec::new(),
            ok: 0,
            fail: 0,
            unknown: 0,
            live,
        }
    }

    fn line(&mut self, text: String) {
        if self.live {
            println!("{text}");
        }
        self.lines.push(text);
    }

    fn phase(&mut self, name: &str, outcome: PhaseResult) {
        let (passed, facts) = match outcome {
            Ok(facts) => (true, facts),
            Err(facts) => (false, facts),
        };
        if !facts_well_formed(&facts) {
            self.fail += 1;
            self.line(format!("T01X02 PHASE {name} fail reason=bad_facts"));
        } else if passed {
            self.ok += 1;
            self.line(format!("T01X02 PHASE {name} ok {facts}"));
        } else {
            self.fail += 1;
            self.line(format!("T01X02 PHASE {name} fail {facts}"));
        }
    }

    fn reading(&mut self, name: &str, value: Option<u64>) {
        match value {
            Some(number) => self.line(format!("T01X02 {name} {number}")),
            None => {
                self.unknown += 1;
                self.line(format!("T01X02 {name} UNKNOWN"));
            }
        }
    }

    fn end(&mut self) {
        let text = format!(
            "T01X02 END ok={} fail={} unknown={}",
            self.ok, self.fail, self.unknown
        );
        self.line(text);
    }

    /// True when any phase failed. Unknown readings alone do not fail a run.
    #[allow(dead_code)]
    pub fn failed(&self) -> bool {
        self.fail > 0
    }
}

// ---- the inputs ---------------------------------------------------------------------------------------------------------------------

/// The four fixture files as text. The binary embeds the committed ones; a test hands in a corrupted copy.
#[derive(Clone, Copy)]
pub struct Inputs<'a> {
    pub identity: &'a str,
    pub derp_map: &'a str,
    pub netmap: &'a str,
    pub key_expiry: &'a str,
}

impl Inputs<'static> {
    /// The committed synthetic fixtures, embedded at build time so the guest needs no filesystem.
    pub fn embedded() -> Self {
        Self {
            identity: include_str!("../../../../tests/tailscale-fixtures/synthetic/identity.json"),
            derp_map: include_str!("../../../../tests/tailscale-fixtures/synthetic/derp_map.json"),
            netmap: include_str!("../../../../tests/tailscale-fixtures/synthetic/netmap.json"),
            key_expiry: include_str!(
                "../../../../tests/tailscale-fixtures/synthetic/key_expiry.json"
            ),
        }
    }
}

/// Where the resource readings come from. The host reads `/proc`; a test injects text or nothing.
pub trait ProcSource {
    /// The whole text of `path`, or `None` when it cannot be read.
    fn read(&self, path: &str) -> Option<String>;
}

/// The real `/proc`.
pub struct HostProc;

impl ProcSource for HostProc {
    fn read(&self, path: &str) -> Option<String> {
        let file = std::fs::File::open(path).ok()?;
        let mut text = String::new();
        file.take(PROC_READ_CAP).read_to_string(&mut text).ok()?;
        Some(text)
    }
}

// ---- entry points -------------------------------------------------------------------------------------------------------------------

/// The probe on the embedded fixtures and the real `/proc`, printing each line as it is produced.
pub fn run_probe() -> Report {
    run_probe_with(&Inputs::embedded(), &HostProc, true)
}

/// The probe on the given inputs and `/proc` source, behind the real RNG gate. `live` prints each line as it is produced.
pub fn run_probe_with(inputs: &Inputs<'_>, source: &dyn ProcSource, live: bool) -> Report {
    run_probe_gated(inputs, source, live, &rng_gate)
}

/// The probe with the RNG gate injected: `gate` is called once, after `TS_KEYS` and before `TS_NOISE`, and what it returns decides
/// whether the phases that draw randomness run (`TS_NOISE`, and the handshake inside `TS_TUNNEL`).
pub fn run_probe_gated(
    inputs: &Inputs<'_>,
    source: &dyn ProcSource,
    live: bool,
    gate: &dyn Fn() -> Rng,
) -> Report {
    let mut report = Report::new(live);
    report.phase(PHASES[0], lift(ts_keys(inputs)));
    let rng = gate();
    report.phase(PHASES[1], lift(noise_ik(inputs, rng)));
    report.phase(PHASES[2], lift(ts_tunnel(inputs, rng)));
    report.phase(PHASES[3], lift(derp_regions(inputs)));
    report.phase(PHASES[4], lift(netmap_rules(inputs)));
    report.phase(PHASES[5], lift(disco_codec(inputs)));
    report.phase(PHASES[6], lift(overlay_router()));
    report.phase(PHASES[7], kat::run_kat());
    read_resources(&mut report, source);
    report.end();
    report
}

fn main() -> ExitCode {
    // The verdict is the transcript (the judge counts the PHASE lines itself), so the process exits 0 once END has been printed.
    let _report = run_probe();
    ExitCode::SUCCESS
}

// ---- the RNG gate -------------------------------------------------------------------------------------------------------------------
//
// `getrandom(.., 0)` blocks until the kernel's pool is ready (Debian 4.19.249 on the MIPS guest: `random.c` `getrandom` -> `wait_for_random_bytes`).
// Every draw in the crypto crates goes through it, so the first one can stall a whole phase with no output. The gate makes that first draw on
// a worker thread, with the same call the phases use, and waits for it at most `limit`. It never substitutes bytes.

/// What the gate found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rng {
    /// The first draw returned after `wait_ms` milliseconds (measured, not written down).
    Ready { wait_ms: u64 },
    /// The first draw had not returned within the bound.
    Blocked,
    /// The worker could not be started, or ended without drawing.
    Failed,
}

impl Rng {
    /// The measured wait, or the reason word of the phase that needs randomness and cannot have it.
    fn wait_ms(self) -> Result<u64, &'static str> {
        match self {
            Rng::Ready { wait_ms } => Ok(wait_ms),
            Rng::Blocked => Err("rng_blocked"),
            Rng::Failed => Err("rng_gate_failed"),
        }
    }
}

/// Run `draw` on a worker thread and wait for it at most `limit`. A worker that is still blocked at the bound is left behind (it dies with
/// the process); nothing is drawn on its behalf.
fn rng_gate_with<F>(draw: F, limit: Duration) -> Rng
where
    F: FnOnce() + Send + 'static,
{
    let started = Instant::now();
    let (done, finished) = mpsc::channel::<()>();
    let worker = thread::Builder::new()
        .name("rng-gate".to_owned())
        .stack_size(RNG_THREAD_STACK)
        .spawn(move || {
            draw();
            // The gate may have given up already, and then nobody listens: that is not an error.
            let _ = done.send(());
        });
    if worker.is_err() {
        return Rng::Failed;
    }
    match finished.recv_timeout(limit) {
        Ok(()) => Rng::Ready {
            wait_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        },
        Err(mpsc::RecvTimeoutError::Timeout) => Rng::Blocked,
        Err(mpsc::RecvTimeoutError::Disconnected) => Rng::Failed,
    }
}

/// The real gate: the call the crypto phases make first, bounded by `RNG_WAIT`.
fn rng_gate() -> Rng {
    rng_gate_with(
        || {
            let _ = NodeKeyPair::random();
        },
        RNG_WAIT,
    )
}

// ---- resource readings --------------------------------------------------------------------------------------------------------------

fn read_resources(report: &mut Report, source: &dyn ProcSource) {
    let status = source.read(STATUS_PATH);
    let stat = source.read(STAT_PATH);
    let hwm = status.as_deref().and_then(|text| status_kb(text, "VmHWM"));
    let rss = status.as_deref().and_then(|text| status_kb(text, "VmRSS"));
    let (utime, stime) = stat.as_deref().map_or((None, None), stat_ticks);
    report.reading("VmHWM", hwm);
    report.reading("VmRSS", rss);
    report.reading("utime", utime);
    report.reading("stime", stime);
}

/// A canonical ASCII integer: digits only, no sign, no leading zero unless it is `0` itself, and it fits a `u64`.
fn canonical_u64(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if bytes.len() > 1 && bytes[0] == b'0' {
        return None;
    }
    text.parse::<u64>().ok()
}

/// The value of a `<key>:  <n> kB` line of `/proc/self/status`; any other unit or shape is `None`.
fn status_kb(text: &str, key: &str) -> Option<u64> {
    for line in text.lines() {
        let Some(rest) = line.strip_prefix(key).and_then(|r| r.strip_prefix(':')) else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let number = parts.next()?;
        if parts.next() != Some("kB") || parts.next().is_some() {
            return None;
        }
        return canonical_u64(number);
    }
    None
}

/// `utime` and `stime` (fields 14 and 15) of `/proc/self/stat`. The command name (field 2) is in parentheses and may hold spaces and
/// parentheses, so the fields are counted from the LAST closing parenthesis: the state (field 3) is the first one after it.
fn stat_ticks(text: &str) -> (Option<u64>, Option<u64>) {
    let Some(close) = text.rfind(')') else {
        return (None, None);
    };
    let fields: Vec<&str> = text[close + 1..].split_whitespace().collect();
    let tick = |index: usize| fields.get(index).and_then(|field| canonical_u64(field));
    (tick(11), tick(12))
}

// ---- a minimal JSON reader ----------------------------------------------------------------------------------------------------------
//
// The fixtures are JSON and the seven crates offer no entry point that reads it without a data-format crate, which is not among them, so the
// probe reads the four files itself: objects, arrays, strings without escapes, integers, booleans and null. Anything else is refused.

#[derive(Debug, Clone, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(text) => Some(text.as_str()),
            _ => None,
        }
    }

    fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    fn as_int(&self) -> Option<i64> {
        match self {
            Json::Int(number) => Some(*number),
            _ => None,
        }
    }

    fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(flag) => Some(*flag),
            _ => None,
        }
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

fn parse_json(text: &str) -> Result<Json, &'static str> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        at: 0,
    };
    let value = parser.value(0)?;
    parser.skip_space();
    if parser.at != parser.bytes.len() {
        return Err("json_trailing");
    }
    Ok(value)
}

impl Parser<'_> {
    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.at += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn eat(&mut self, byte: u8) -> Result<(), &'static str> {
        if self.peek() == Some(byte) {
            self.at += 1;
            Ok(())
        } else {
            Err("json_syntax")
        }
    }

    fn word(&mut self, word: &[u8], value: Json) -> Result<Json, &'static str> {
        if self.bytes[self.at..].starts_with(word) {
            self.at += word.len();
            Ok(value)
        } else {
            Err("json_syntax")
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, &'static str> {
        if depth > MAX_JSON_DEPTH {
            return Err("json_depth");
        }
        self.skip_space();
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Json::Str),
            Some(b't') => self.word(b"true", Json::Bool(true)),
            Some(b'f') => self.word(b"false", Json::Bool(false)),
            Some(b'n') => self.word(b"null", Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err("json_syntax"),
        }
    }

    fn string(&mut self) -> Result<String, &'static str> {
        self.eat(b'"')?;
        let start = self.at;
        loop {
            match self.peek() {
                None => return Err("json_unterminated"),
                Some(b'"') => break,
                Some(b'\\') => return Err("json_escape"),
                Some(byte) if byte < 0x20 => return Err("json_control"),
                Some(_) => self.at += 1,
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at]).map_err(|_| "json_utf8")?;
        self.at += 1;
        Ok(text.to_owned())
    }

    fn number(&mut self) -> Result<Json, &'static str> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        let digits = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        let count = self.at - digits;
        if count == 0 || (count > 1 && self.bytes[digits] == b'0') {
            return Err("json_number");
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err("json_float");
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at]).map_err(|_| "json_utf8")?;
        text.parse::<i64>()
            .map(Json::Int)
            .map_err(|_| "json_number")
    }

    fn array(&mut self, depth: usize) -> Result<Json, &'static str> {
        self.eat(b'[')?;
        let mut items = Vec::new();
        self.skip_space();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err("json_syntax"),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, &'static str> {
        self.eat(b'{')?;
        let mut fields = Vec::new();
        self.skip_space();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Json::Obj(fields));
        }
        loop {
            self.skip_space();
            let key = self.string()?;
            self.skip_space();
            self.eat(b':')?;
            let value = self.value(depth + 1)?;
            fields.push((key, value));
            self.skip_space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Json::Obj(fields));
                }
                _ => return Err("json_syntax"),
            }
        }
    }
}

fn parse_fixture(text: &str, schema: &str) -> Result<Json, &'static str> {
    if text.len() > MAX_FIXTURE_BYTES {
        return Err("fixture_too_big");
    }
    let root = parse_json(text)?;
    if f_str(&root, "schema")? != schema {
        return Err("fixture_schema");
    }
    Ok(root)
}

fn f_str<'a>(object: &'a Json, key: &str) -> Result<&'a str, &'static str> {
    object.get(key).and_then(Json::as_str).ok_or("field_string")
}

fn f_arr<'a>(object: &'a Json, key: &str) -> Result<&'a [Json], &'static str> {
    object.get(key).and_then(Json::as_arr).ok_or("field_array")
}

fn f_int(object: &Json, key: &str) -> Result<i64, &'static str> {
    object.get(key).and_then(Json::as_int).ok_or("field_int")
}

fn f_bool(object: &Json, key: &str) -> Result<bool, &'static str> {
    object.get(key).and_then(Json::as_bool).ok_or("field_bool")
}

// ---- identity -----------------------------------------------------------------------------------------------------------------------

struct Node {
    id: String,
    machine_key: String,
    node_key: String,
    disco_key: String,
    address: Ipv4Addr,
}

fn load_identity(text: &str) -> Result<Vec<Node>, &'static str> {
    let root = parse_fixture(text, IDENTITY_SCHEMA)?;
    let mut nodes = Vec::new();
    for entry in f_arr(&root, "nodes")? {
        let first = f_arr(entry, "addresses")?
            .first()
            .ok_or("address_missing")?;
        let address = Ipv4Addr::from_str(first.as_str().ok_or("address_text")?)
            .map_err(|_| "address_parse")?;
        let octets = address.octets();
        if octets[0] != 100 || (octets[1] & 0xc0) != 64 {
            return Err("address_range");
        }
        nodes.push(Node {
            id: f_str(entry, "id")?.to_owned(),
            machine_key: f_str(entry, "machine_key")?.to_owned(),
            node_key: f_str(entry, "node_key")?.to_owned(),
            disco_key: f_str(entry, "disco_key")?.to_owned(),
            address,
        });
    }
    if nodes.len() < 3 {
        return Err("too_few_nodes");
    }
    Ok(nodes)
}

fn find_node<'a>(nodes: &'a [Node], id: &str) -> Result<&'a Node, &'static str> {
    nodes
        .iter()
        .find(|node| node.id == id)
        .ok_or("node_missing")
}

/// The 64 hex digits after `<prefix>:`.
fn key_digits<'a>(key: &'a str, prefix: &str) -> Result<&'a str, &'static str> {
    key.strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix(':'))
        .ok_or("key_prefix")
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex32(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.as_chunks::<2>().0) {
        *slot = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(out)
}

/// The digits and bytes of a placeholder key string, used as the seed of a private key of the same node.
fn seed_of<'a>(key: &'a str, prefix: &str) -> Result<(&'a str, [u8; 32]), &'static str> {
    let digits = key_digits(key, prefix)?;
    let bytes = hex32(digits).ok_or("key_hex")?;
    Ok((digits, bytes))
}

fn node_pair(node: &Node) -> Result<NodeKeyPair, &'static str> {
    let (digits, _) = seed_of(&node.node_key, "nodekey")?;
    let private =
        NodePrivateKey::from_str(&format!("privkey:{digits}")).map_err(|_| "node_private")?;
    Ok(NodeKeyPair::from(private))
}

fn disco_pair(node: &Node) -> Result<DiscoKeyPair, &'static str> {
    let (digits, _) = seed_of(&node.disco_key, "discokey")?;
    let private =
        DiscoPrivateKey::from_str(&format!("privkey:{digits}")).map_err(|_| "disco_private")?;
    Ok(DiscoKeyPair::from(private))
}

/// A node keypair that belongs to no fixture node: a fixed seed.
fn spare_pair(seed: u8) -> NodeKeyPair {
    NodeKeyPair::from(Export::<NodePrivateKey>::from_bytes([seed; 32]).import())
}

// ---- phase: keys_parse --------------------------------------------------------------------------------------------------------------

fn keys_parse(inputs: &Inputs<'_>) -> Result<String, &'static str> {
    let nodes = load_identity(inputs.identity)?;
    let mut digits_seen = BTreeSet::new();
    for node in &nodes {
        let machine = MachinePublicKey::from_str(&node.machine_key).map_err(|_| "machine_key")?;
        let node_key = NodePublicKey::from_str(&node.node_key).map_err(|_| "node_key")?;
        let disco = DiscoPublicKey::from_str(&node.disco_key).map_err(|_| "disco_key")?;
        let originals = [&node.machine_key, &node.node_key, &node.disco_key];
        let shown = [machine.to_string(), node_key.to_string(), disco.to_string()];
        if shown
            .iter()
            .zip(originals)
            .any(|(text, original)| text != original)
        {
            return Err("display_roundtrip");
        }
        // A key of one kind must not parse as another kind, and a key one character short must not parse at all.
        let confused = MachinePublicKey::from_str(&node.node_key).is_ok()
            || NodePublicKey::from_str(&node.disco_key).is_ok()
            || DiscoPublicKey::from_str(&node.machine_key).is_ok();
        if confused {
            return Err("kind_confusion");
        }
        let short = node.node_key.get(..node.node_key.len().saturating_sub(1));
        if short.is_some_and(|text| NodePublicKey::from_str(text).is_ok()) {
            return Err("short_key_accepted");
        }
        for original in originals {
            digits_seen.insert(original.split_once(':').map_or("", |(_, digits)| digits));
        }
    }
    if digits_seen.len() != nodes.len() * 3 {
        return Err("keys_not_distinct");
    }
    Ok(format!("nodes={} keys={}", nodes.len(), digits_seen.len()))
}

// ---- phase: keys_derive -------------------------------------------------------------------------------------------------------------

/// One key kind: the private key from the text form and from the raw bytes must agree, the pair must carry the same public key, the
/// exportable form must return the seed, and the printed private key must not show a digit of it.
macro_rules! derive_kind {
    ($private:ty, $pair:ty, $digits:expr, $seed:expr, $publics:expr) => {{
        let from_text =
            <$private>::from_str(&format!("privkey:{}", $digits)).map_err(|_| "private_parse")?;
        let from_bytes = Export::<$private>::from_bytes($seed).import();
        if from_text.public_key() != from_bytes.public_key() {
            return Err("derive_paths_differ");
        }
        let pair = <$pair>::from(from_text.clone());
        if pair.public != from_bytes.public_key() {
            return Err("pair_public");
        }
        if pair.export().as_bytes() != &$seed {
            return Err("export_bytes");
        }
        let shown = from_text.to_string();
        if shown.contains($digits) || !shown.ends_with("[redacted]") {
            return Err("private_not_redacted");
        }
        $publics.insert(pair.public.to_string());
    }};
}

fn keys_derive(inputs: &Inputs<'_>) -> Result<String, &'static str> {
    let nodes = load_identity(inputs.identity)?;
    let mut publics = BTreeSet::new();
    for node in &nodes {
        let (node_digits, node_seed) = seed_of(&node.node_key, "nodekey")?;
        let (machine_digits, machine_seed) = seed_of(&node.machine_key, "mkey")?;
        let (disco_digits, disco_seed) = seed_of(&node.disco_key, "discokey")?;
        derive_kind!(NodePrivateKey, NodeKeyPair, node_digits, node_seed, publics);
        derive_kind!(
            MachinePrivateKey,
            MachineKeyPair,
            machine_digits,
            machine_seed,
            publics
        );
        derive_kind!(
            DiscoPrivateKey,
            DiscoKeyPair,
            disco_digits,
            disco_seed,
            publics
        );
    }
    if publics.len() != nodes.len() * 3 {
        return Err("derived_not_distinct");
    }
    Ok(format!("derived={}", publics.len()))
}

/// `TS_KEYS`: the placeholder keys parse and print back, and the private keys derived from them agree on every path.
fn ts_keys(inputs: &Inputs<'_>) -> Result<String, &'static str> {
    let parsed = keys_parse(inputs)?;
    let derived = keys_derive(inputs)?;
    Ok(format!("{parsed} {derived}"))
}

// ---- phase: disco_codec -------------------------------------------------------------------------------------------------------------

fn nonce(tag: u8) -> [u8; Header::NONCE_LEN] {
    let mut out = [0_u8; Header::NONCE_LEN];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = tag.wrapping_add(index as u8);
    }
    out
}

/// Flip one bit of `bytes` at `at` (a copy); an index past the end flips nothing.
fn flipped(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut copy = bytes.to_vec();
    if let Some(byte) = copy.get_mut(at) {
        *byte ^= 0x01;
    }
    copy
}

/// Seal one message of type `$msg` from `$from` to `$to` into `$buf` (sized for it).
macro_rules! disco_seal {
    ($buf:expr, $msg:ty, $from:expr, $to:expr, $tag:expr, $init:expr) => {{
        let packet = Packet::init_from_bytes::<$msg>(&mut $buf, $init).map_err(|_| "disco_init")?;
        packet
            .encrypt_in_place(&$from.private, &$to.public, nonce($tag))
            .map(|_| ())
            .map_err(|_| "disco_encrypt")?;
    }};
}

/// True when the wire bytes cannot be opened by `$to`: the parse fails or the decryption does.
macro_rules! disco_refused {
    ($wire:expr, $to:expr) => {{
        match Packet::from_encrypted_bytes_mut(&mut $wire) {
            Ok(sealed) => sealed.decrypt_in_place(&$to.private).is_err(),
            Err(_) => true,
        }
    }};
}

fn disco_codec(inputs: &Inputs<'_>) -> Result<String, &'static str> {
    let nodes = load_identity(inputs.identity)?;
    let node_a = find_node(&nodes, "node-a")?;
    let node_b = find_node(&nodes, "node-b")?;
    let node_c = find_node(&nodes, "node-c")?;
    let (a, b, c) = (
        disco_pair(node_a)?,
        disco_pair(node_b)?,
        disco_pair(node_c)?,
    );
    let a_node_public = node_pair(node_a)?.public;

    // Ping, with padding.
    let mut ping_buf = vec![0_u8; Packet::size_for_message(Ping::size_with_padding(PING_PADDING))];
    disco_seal!(ping_buf, Ping, a, b, 1, |ping| {
        ping.tx_id = TX_ID;
        ping.node_key = a_node_public;
    });
    if !is_disco_message(&ping_buf) || is_disco_message(&flipped(&ping_buf, 0)) {
        return Err("ping_magic");
    }
    let mut wire = ping_buf.clone();
    {
        let sealed = Packet::from_encrypted_bytes_mut(&mut wire).map_err(|_| "ping_parse")?;
        if *sealed.sender_pubkey() != a.public {
            return Err("ping_sender");
        }
        let opened = sealed
            .decrypt_in_place(&b.private)
            .map_err(|_| "ping_decrypt")?;
        if opened.ty() != Some(MessageType::Ping) || opened.as_msg::<Pong>().is_some() {
            return Err("ping_type");
        }
        let message = opened.as_msg::<Ping>().ok_or("ping_body")?;
        if message.tx_id != TX_ID
            || message.node_key != a_node_public
            || message.padding.len() != PING_PADDING
        {
            return Err("ping_fields");
        }
    }
    let mut tampered = flipped(&ping_buf, ping_buf.len() - 1);
    let mut wrong_receiver = ping_buf.clone();
    if !disco_refused!(tampered, b) {
        return Err("ping_tamper_accepted");
    }
    if !disco_refused!(wrong_receiver, c) {
        return Err("ping_wrong_receiver_accepted");
    }

    // Pong, carrying a socket address.
    let pong_addr = SocketAddr::new(IpAddr::V4(node_a.address), DISCO_PORT_BASE + 100);
    let mut pong_buf = vec![0_u8; Packet::size_for_message(Pong::size())];
    disco_seal!(pong_buf, Pong, b, a, 2, |pong| {
        *pong = Pong {
            tx_id: TX_ID,
            src: DiscoEndpoint::from_socket_addr(pong_addr),
        };
    });
    let mut wire = pong_buf.clone();
    {
        let sealed = Packet::from_encrypted_bytes_mut(&mut wire).map_err(|_| "pong_parse")?;
        let opened = sealed
            .decrypt_in_place(&a.private)
            .map_err(|_| "pong_decrypt")?;
        if opened.ty() != Some(MessageType::Pong) {
            return Err("pong_type");
        }
        let message = opened.as_msg::<Pong>().ok_or("pong_body")?;
        if message.tx_id != TX_ID || message.src.socket_addr() != pong_addr {
            return Err("pong_fields");
        }
    }

    // CallMeMaybe, one endpoint per fixture node.
    let mut addrs = Vec::new();
    for (index, node) in nodes.iter().enumerate() {
        let port = DISCO_PORT_BASE + u16::try_from(index).map_err(|_| "endpoint_count")?;
        addrs.push(SocketAddr::new(IpAddr::V4(node.address), port));
    }
    let mut cmm_buf =
        vec![0_u8; Packet::size_for_message(CallMeMaybe::size_for_endpoint_count(addrs.len()))];
    disco_seal!(cmm_buf, CallMeMaybe, a, b, 3, |cmm| {
        for (slot, addr) in cmm.endpoints.iter_mut().zip(addrs.iter()) {
            *slot = DiscoEndpoint::from_socket_addr(*addr);
        }
    });
    let mut wire = cmm_buf.clone();
    {
        let sealed = Packet::from_encrypted_bytes_mut(&mut wire).map_err(|_| "cmm_parse")?;
        let opened = sealed
            .decrypt_in_place(&b.private)
            .map_err(|_| "cmm_decrypt")?;
        if opened.ty() != Some(MessageType::CallMeMaybe) {
            return Err("cmm_type");
        }
        let message = opened.as_msg::<CallMeMaybe>().ok_or("cmm_body")?;
        let same = message.endpoints.len() == addrs.len()
            && message
                .endpoints
                .iter()
                .zip(addrs.iter())
                .all(|(endpoint, addr)| endpoint.socket_addr() == *addr);
        if !same {
            return Err("cmm_fields");
        }
    }
    Ok(format!(
        "messages=3 ping_bytes={} pong_bytes={} cmm_bytes={} endpoints={}",
        ping_buf.len(),
        pong_buf.len(),
        cmm_buf.len(),
        addrs.len()
    ))
}

// ---- phase: noise_ik ----------------------------------------------------------------------------------------------------------------

fn noise_ik(inputs: &Inputs<'_>, rng: Rng) -> Result<String, &'static str> {
    // No draw is made unless the gate found the pool ready: a blocked gate is this phase's failure, `rng_blocked`.
    let wait_ms = rng.wait_ms()?;
    let nodes = load_identity(inputs.identity)?;
    let initiator = node_pair(find_node(&nodes, "node-a")?)?;
    let responder = node_pair(find_node(&nodes, "node-b")?)?;
    let initiator_keys = initiator.to_x25519_dalek();
    let responder_keys = responder.to_x25519_dalek();

    let mut init = [0_u8; SentHandshake::INIT_SIZE];
    let sent = SentHandshake::new(
        initiator_keys.clone(),
        responder.public.to_x25519_dalek(),
        NOISE_PROLOGUE,
        &mut init,
    );

    // The responder consumes the packet in place, so every attempt gets its own copy.
    let mut damaged = init;
    damaged[SentHandshake::INIT_SIZE / 2] ^= 0x01;
    if ReceivedHandshake::new(&mut damaged, NOISE_PROLOGUE, &responder_keys).is_some() {
        return Err("init_tamper_accepted");
    }
    let mut other_prologue = init;
    if ReceivedHandshake::new(&mut other_prologue, b"other", &responder_keys).is_some() {
        return Err("prologue_ignored");
    }
    let mut good = init;
    let received = ReceivedHandshake::new(&mut good, NOISE_PROLOGUE, &responder_keys)
        .ok_or("init_rejected")?;
    if received.peer_static_pub != initiator_keys.public {
        return Err("peer_static");
    }
    let mut resp = [0_u8; ReceivedHandshake::RESP_SIZE];
    let responder_session = received.finish(&mut resp);

    // A damaged response leaves the initiator able to try again; the intact one completes.
    let mut bad_resp = resp;
    bad_resp[0] ^= 0x01;
    let sent = match sent.try_finish(&mut bad_resp, initiator_keys.clone()) {
        Ok(_) => return Err("resp_tamper_accepted"),
        Err(again) => again,
    };
    let initiator_session = match sent.try_finish(&mut resp, initiator_keys) {
        Ok(session) => session,
        Err(_) => return Err("resp_rejected"),
    };

    if initiator_session.initiator_to_responder != responder_session.initiator_to_responder
        || initiator_session.responder_to_initiator != responder_session.responder_to_initiator
    {
        return Err("session_keys_differ");
    }
    if initiator_session.initiator_to_responder == initiator_session.responder_to_initiator {
        return Err("session_keys_equal");
    }
    if initiator_session.role != Role::Initiator || responder_session.role != Role::Responder {
        return Err("roles");
    }
    Ok(format!(
        "init_bytes={} resp_bytes={} sessions=2 rng_wait_ms={wait_ms}",
        SentHandshake::INIT_SIZE,
        ReceivedHandshake::RESP_SIZE
    ))
}

// ---- netmap -------------------------------------------------------------------------------------------------------------------------

/// The self node and the peers of the network map, checked against the fixture's own cap and uniqueness.
fn netmap_peers(root: &Json) -> Result<(String, Vec<String>), &'static str> {
    let self_id = f_str(root, "self")?.to_owned();
    let cap = f_int(root, "peer_cap")?;
    let mut peers: Vec<String> = Vec::new();
    for peer in f_arr(root, "peers")? {
        let id = f_str(peer, "id")?;
        f_bool(peer, "online")?;
        f_int(peer, "key_expiry")?;
        if id == self_id || peers.iter().any(|seen| seen == id) {
            return Err("peer_duplicate");
        }
        peers.push(id.to_owned());
    }
    if i64::try_from(peers.len()).map_err(|_| "peer_count")? > cap {
        return Err("peer_cap");
    }
    Ok((self_id, peers))
}

// ---- phase: tunnel_peers ------------------------------------------------------------------------------------------------------------

fn tunnel_peers(inputs: &Inputs<'_>) -> Result<String, &'static str> {
    let nodes = load_identity(inputs.identity)?;
    let root = parse_fixture(inputs.netmap, NETMAP_SCHEMA)?;
    let (self_id, peer_ids) = netmap_peers(&root)?;
    let mut endpoint = TunnelEndpoint::new(node_pair(find_node(&nodes, &self_id)?)?);

    let mut peers = Vec::new();
    for (index, id) in peer_ids.iter().enumerate() {
        let handle = PeerId(u32::try_from(index + 1).map_err(|_| "peer_id")?);
        let key = node_pair(find_node(&nodes, id)?)?.public;
        if endpoint
            .upsert_peer(PeerConfig::new(handle, key, [0_u8; 32]))
            .is_some()
        {
            return Err("peer_duplicate");
        }
        peers.push((handle, key));
    }
    let Some(&(first_id, first_key)) = peers.first() else {
        return Err("no_peers");
    };
    for &(handle, key) in &peers {
        if endpoint.peer_key(handle) != Some(key) || endpoint.peer_id(key) != Some(handle) {
            return Err("peer_lookup");
        }
    }

    // Re-keying an existing peer hands back the old configuration and moves the key index; removal is reported once.
    let spare = spare_pair(0x42).public;
    let old = endpoint
        .upsert_peer(PeerConfig::new(first_id, spare, [0_u8; 32]))
        .ok_or("rekey_none")?;
    if old.key != first_key || old.id != first_id {
        return Err("rekey_old_config");
    }
    if endpoint.peer_id(spare) != Some(first_id) || endpoint.peer_id(first_key).is_some() {
        return Err("rekey_index");
    }
    if !endpoint.remove_peer(first_id) || endpoint.remove_peer(first_id) {
        return Err("remove_peer");
    }
    if endpoint.peer_key(first_id).is_some() || endpoint.peer_id(spare).is_some() {
        return Err("removed_still_present");
    }
    Ok(format!("peers={} rekeyed=1 removed=1", peers.len()))
}

// ---- phase: tunnel_clock ------------------------------------------------------------------------------------------------------------

fn tunnel_clock(inputs: &Inputs<'_>) -> Result<String, &'static str> {
    let root = parse_fixture(inputs.key_expiry, KEY_EXPIRY_SCHEMA)?;
    let steps = f_arr(&root, "steps")?;
    if steps.is_empty() {
        return Err("no_steps");
    }
    let mut endpoint = TunnelEndpoint::new(spare_pair(0x07));
    let base = Instant::now();
    let mut dispatched = 0_usize;
    for step in steps {
        f_str(step, "id")?;
        if f_arr(step, "expect")?.len() != 3 {
            return Err("expect_shape");
        }
        let now = u64::try_from(f_int(step, "now")?).map_err(|_| "now_negative")?;
        let at = base
            .checked_add(Duration::from_secs(now))
            .ok_or("instant_overflow")?;
        if !endpoint.dispatch_events(at).to_peers.is_empty() {
            return Err("unexpected_packets");
        }
        dispatched += 1;
    }
    let idle = if endpoint.next_event().is_none() {
        "yes"
    } else {
        "no"
    };
    Ok(format!("steps={dispatched} idle={idle}"))
}

/// What two in-memory endpoints moved, tallied from what the crate returned, never written down.
#[derive(Default)]
struct Moved {
    /// Cleartext packets handed to `send`.
    sent: usize,
    /// Cleartext packets `recv` delivered locally.
    recv: usize,
    /// Bytes of those delivered packets.
    bytes: usize,
    /// Packets (handshake and transport) that went across the in-memory wire, and their bytes.
    wire_packets: usize,
    wire_bytes: usize,
    /// Damaged transport packets offered that delivered nothing.
    refused: usize,
}

/// A four-byte cleartext packet of one repeated byte, the shape the crate's own tests use.
fn payload(tag: u8) -> PacketMut {
    PacketMut::from(vec![tag; 4])
}

/// The packets a call handed to the one peer `id`; packets for any other peer are an error.
fn for_peer(
    mut map: HashMap<PeerId, Vec<PacketMut>>,
    id: PeerId,
) -> Result<Vec<PacketMut>, &'static str> {
    if map.keys().any(|key| *key != id) {
        return Err("packets_for_other_peer");
    }
    Ok(map.remove(&id).unwrap_or_default())
}

fn local_count(map: &HashMap<PeerId, Vec<PacketMut>>) -> usize {
    map.values().map(Vec::len).sum()
}

fn wire_tally(moved: &mut Moved, packets: &[PacketMut]) {
    moved.wire_packets += packets.len();
    moved.wire_bytes += packets.iter().map(PacketMut::len).sum::<usize>();
}

fn delivered(moved: &mut Moved, packets: &[PacketMut]) {
    moved.recv += packets.len();
    moved.bytes += packets.iter().map(PacketMut::len).sum::<usize>();
}

/// The damage of the planted control: one bit of the last byte, which is the last byte of the transport packet's authentication tag.
fn flip_last_byte(packet: &mut PacketMut) {
    if let Some(last) = packet.last_mut() {
        *last ^= 0x01;
    }
}

/// Two endpoints configured as each other's only peer, joined by an in-memory wire. `a` sends two packets, which makes it start a handshake
/// and hold the packets; `b` answers; `a` completes the handshake and releases the packets as transport data; a copy of the first transport
/// packet damaged by `tamper` is offered to `b` and must deliver nothing; the intact packets are then delivered byte for byte, and `b`
/// replies on the same session. A `tamper` that damages nothing makes the control fail, which is how a test plants a fault in the control.
fn transport_round_trip(
    a_keys: NodeKeyPair,
    b_keys: NodeKeyPair,
    tamper: &dyn Fn(&mut PacketMut),
) -> Result<String, &'static str> {
    let id = PeerId(1);
    let psk = [0x5a_u8; 32];
    let mut a = TunnelEndpoint::new(a_keys.clone());
    let mut b = TunnelEndpoint::new(b_keys.clone());
    let a_has_b = a.upsert_peer(PeerConfig::new(id, b_keys.public, psk));
    let b_has_a = b.upsert_peer(PeerConfig::new(id, a_keys.public, psk));
    if a_has_b.is_some() || b_has_a.is_some() {
        return Err("peer_duplicate");
    }
    let base = Instant::now();
    let at = |secs: u64| base + Duration::from_secs(secs);
    let mut moved = Moved::default();

    // 1. Two packets for the peer: the endpoint answers with a handshake initiation and keeps the packets.
    let first = vec![payload(1), payload(2)];
    moved.sent += first.len();
    let initiation = for_peer(a.send(at(0), [(id, first.clone())]).to_peers, id)?;
    if initiation.len() != 1 {
        return Err("initiation_count");
    }
    wire_tally(&mut moved, &initiation);

    // 2. The peer answers the initiation with a handshake response and delivers nothing.
    let received = b.recv(at(1), initiation);
    if local_count(&received.to_local) != 0 {
        return Err("initiation_delivered_data");
    }
    let response = for_peer(received.to_peers, id)?;
    if response.len() != 1 {
        return Err("response_count");
    }
    wire_tally(&mut moved, &response);

    // 3. The first endpoint completes the handshake and releases its two packets as transport data.
    let received = a.recv(at(2), response);
    if local_count(&received.to_local) != 0 {
        return Err("response_delivered_data");
    }
    let data = for_peer(received.to_peers, id)?;
    if data.len() != first.len() {
        return Err("transport_count");
    }
    wire_tally(&mut moved, &data);

    // 4. Control: a copy of the first transport packet with a byte damaged is refused and delivers nothing.
    let mut damaged = data.first().ok_or("transport_missing")?.clone();
    tamper(&mut damaged);
    let leaked = local_count(&b.recv(at(3), vec![damaged]).to_local);
    if leaked != 0 {
        return Err("tamper_accepted");
    }
    moved.refused += 1 - leaked;

    // 5. The intact packets are delivered, in order, byte for byte (the damaged copy did not use up their counters).
    let got = for_peer(b.recv(at(4), data).to_local, id)?;
    if got != first {
        return Err("payload_mismatch");
    }
    delivered(&mut moved, &got);

    // 6. The peer answers on the same session.
    let reply = vec![payload(4)];
    moved.sent += reply.len();
    let back = for_peer(b.send(at(5), [(id, reply.clone())]).to_peers, id)?;
    if back.len() != 1 {
        return Err("reply_count");
    }
    wire_tally(&mut moved, &back);
    let got = for_peer(a.recv(at(6), back).to_local, id)?;
    if got != reply {
        return Err("reply_mismatch");
    }
    delivered(&mut moved, &got);

    if moved.sent != moved.recv {
        return Err("sent_not_received");
    }
    Ok(format!(
        "sent={} recv={} bytes={} wire_packets={} wire_bytes={} refused={}",
        moved.sent, moved.recv, moved.bytes, moved.wire_packets, moved.wire_bytes, moved.refused
    ))
}

fn tunnel_transport(inputs: &Inputs<'_>, rng: Rng) -> Result<String, &'static str> {
    // The handshake draws ephemeral keys and a session id: not without a pool the gate found ready.
    rng.wait_ms()?;
    let nodes = load_identity(inputs.identity)?;
    let a = node_pair(find_node(&nodes, "node-a")?)?;
    let b = node_pair(find_node(&nodes, "node-b")?)?;
    transport_round_trip(a, b, &flip_last_byte)
}

/// `TS_TUNNEL`: the peer table (add, look up, re-key, remove), the virtual-clock timeline run through the event dispatcher, then a real
/// handshake and transport round trip between two endpoints in memory. The first two draw no randomness; the third needs the gate's `rng`
/// to be ready and otherwise fails the phase with `rng_blocked`.
fn ts_tunnel(inputs: &Inputs<'_>, rng: Rng) -> Result<String, &'static str> {
    let peers = tunnel_peers(inputs)?;
    let clock = tunnel_clock(inputs)?;
    let transport = tunnel_transport(inputs, rng)?;
    Ok(format!("{peers} {clock} {transport}"))
}

// ---- phase: netmap_rules ------------------------------------------------------------------------------------------------------------

fn netmap_rules(inputs: &Inputs<'_>) -> Result<String, &'static str> {
    let root = parse_fixture(inputs.netmap, NETMAP_SCHEMA)?;
    let (self_id, peers) = netmap_peers(&root)?;
    let mut known: BTreeSet<&str> = BTreeSet::new();
    known.insert(self_id.as_str());
    for peer in &peers {
        known.insert(peer.as_str());
    }

    let mut rule_ids: Vec<&str> = Vec::new();
    for rule in f_arr(&root, "packet_filter")? {
        let id = f_str(rule, "id")?;
        if rule_ids.contains(&id) {
            return Err("rule_duplicate");
        }
        rule_ids.push(id);
        for side in ["srcs", "dsts"] {
            for party in f_arr(rule, side)? {
                let party = party.as_str().ok_or("rule_party")?;
                if !known.contains(party) {
                    return Err("rule_unknown_node");
                }
            }
        }
        for port in f_arr(rule, "ports")? {
            match port {
                Json::Int(number) if (0..=65535).contains(number) => {}
                Json::Str(text) if text == "*" => {}
                _ => return Err("rule_port"),
            }
        }
        if !matches!(f_str(rule, "proto")?, "tcp" | "udp" | "*") {
            return Err("rule_proto");
        }
    }
    let mut cases = 0_usize;
    for case in f_arr(&root, "filter_cases")? {
        for key in ["id", "src", "dst", "proto"] {
            f_str(case, key)?;
        }
        f_int(case, "port")?;
        if !matches!(f_str(case, "expect")?, "allow" | "deny") {
            return Err("case_expect");
        }
        cases += 1;
    }

    // The crate's one pure entry point that needs no filter types: the "clear everything" marker is the key `*` with no value.
    let mut storage: BTreeMap<&str, Option<usize>> = BTreeMap::new();
    for (index, id) in rule_ids.iter().copied().enumerate() {
        storage.insert(id, Some(index));
    }
    if should_clear_storage(&storage) {
        return Err("clear_without_marker");
    }
    storage.insert("*", None);
    if !should_clear_storage(&storage) {
        return Err("clear_marker_missed");
    }
    storage.insert("*", Some(0));
    if should_clear_storage(&storage) {
        return Err("clear_marker_with_value");
    }
    Ok(format!(
        "peers={} rules={} cases={cases} clear_checks=3",
        peers.len(),
        rule_ids.len()
    ))
}

// ---- phase: derp_regions ------------------------------------------------------------------------------------------------------------

struct RegionRow {
    id: u32,
    name: String,
    reachable: bool,
    hosts: Vec<String>,
    server_names: Vec<String>,
}

#[allow(deprecated)]
fn derp_regions(inputs: &Inputs<'_>) -> Result<String, &'static str> {
    let root = parse_fixture(inputs.derp_map, DERP_MAP_SCHEMA)?;
    let mut rows = Vec::new();
    for region in f_arr(&root, "regions")? {
        let id = u32::try_from(f_int(region, "id")?).map_err(|_| "region_id_range")?;
        let reachable = f_bool(region, "reachable")?;
        let mut hosts = Vec::new();
        let mut server_names = Vec::new();
        for (index, host) in f_arr(region, "nodes")?.iter().enumerate() {
            hosts.push(host.as_str().ok_or("host_text")?.to_owned());
            let letter = u8::try_from(index)
                .ok()
                .filter(|letter| *letter < 26)
                .ok_or("too_many_servers")?;
            server_names.push(format!("{id}{}", char::from(b'a' + letter)));
        }
        rows.push(RegionRow {
            id,
            name: f_str(region, "name")?.to_owned(),
            reachable,
            hosts,
            server_names,
        });
    }
    // The route cases are read for shape only: the route policy is the native design's, not the crate's.
    let mut cases = 0_usize;
    for key in ["route_cases", "no_region_cases"] {
        for case in f_arr(&root, key)? {
            f_str(case, "id")?;
            f_str(case, "peer")?;
            f_str(case, "expect")?;
            cases += 1;
        }
    }

    let mut map = DerpMap::default();
    for row in &rows {
        let id = DerpRegionId::from(NonZeroU32::new(row.id).ok_or("region_id_zero")?);
        let nodes = row
            .hosts
            .iter()
            .zip(row.server_names.iter())
            .map(|(hostname, name)| DerpServer {
                name,
                region_id: id,
                hostname,
                cert_name: None,
                ipv4: DerpIpUsage::UseDns,
                ipv6: DerpIpUsage::UseDns,
                stun_port: Default::default(),
                stun_only: false,
                derp_port: 443,
                insecure_for_tests: false,
                stun_test_ip: None,
                can_port_80: false,
            })
            .collect();
        let region = DerpRegion {
            id,
            code: &row.name,
            name: &row.name,
            latitude: 0.0,
            longitude: 0.0,
            avoid: false,
            no_measure_no_home: false,
            nodes,
        };
        if map.regions.insert(id, region).is_some() {
            return Err("region_duplicate");
        }
    }
    if map.regions.len() != rows.len() || rows.is_empty() {
        return Err("region_count");
    }
    let mut servers = 0_usize;
    let mut reachable = 0_usize;
    for row in &rows {
        let id = DerpRegionId::from(NonZeroU32::new(row.id).ok_or("region_id_zero")?);
        let region = map.regions.get(&id).ok_or("region_lookup")?;
        if u32::from(region.id) != row.id
            || region.name != row.name
            || region.nodes.len() != row.hosts.len()
        {
            return Err("region_fields");
        }
        servers += region.nodes.len();
        reachable += usize::from(row.reachable);
    }
    let wire = derp_wire_round_trip(&rows)?;
    Ok(format!(
        "regions={} servers={servers} reachable={reachable} route_cases={cases} {wire}",
        rows.len()
    ))
}

/// The error category of `serde_json`, by name.
fn category_name(category: Category) -> &'static str {
    match category {
        Category::Io => "io",
        Category::Syntax => "syntax",
        Category::Data => "data",
        Category::Eof => "eof",
    }
}

/// Decode a `DerpMap` from control-plane JSON; a refusal is named by its `serde_json` category.
fn derp_decode(text: &str) -> Result<DerpMap<'_>, &'static str> {
    serde_json::from_str::<DerpMap<'_>>(text).map_err(|error| category_name(error.classify()))
}

/// The control-plane wire form (the shape of `ts_control_serde/tests/data/derp_map_odr.json`) of the regions read from `derp_map.json`.
/// Every string comes from the JSON reader above, which refuses escapes and quotes, so none needs escaping here.
fn derp_wire_text(rows: &[RegionRow]) -> String {
    let mut regions = Vec::new();
    for row in rows {
        let mut nodes = Vec::new();
        for (host, server) in row.hosts.iter().zip(row.server_names.iter()) {
            nodes.push(format!(
                "{{\"Name\":\"{server}\",\"RegionID\":{},\"HostName\":\"{host}\"}}",
                row.id
            ));
        }
        regions.push(format!(
            "\"{id}\":{{\"RegionID\":{id},\"RegionCode\":\"{name}\",\"RegionName\":\"{name}\",\"Nodes\":[{nodes}]}}",
            id = row.id,
            name = row.name,
            nodes = nodes.join(",")
        ));
    }
    format!(
        "{{\"Regions\":{{{}}},\"omitDefaultRegions\":true}}",
        regions.join(",")
    )
}

/// The decoded map must hold exactly the regions, servers and host names that were written into the wire text.
fn derp_matches(map: &DerpMap<'_>, rows: &[RegionRow]) -> Result<(), &'static str> {
    if !map.omit_default_regions || map.regions.len() != rows.len() {
        return Err("decoded_shape");
    }
    for row in rows {
        let id = DerpRegionId::from(NonZeroU32::new(row.id).ok_or("region_id_zero")?);
        let region = map.regions.get(&id).ok_or("decoded_region_missing")?;
        if region.name != row.name
            || region.code != row.name
            || region.nodes.len() != row.hosts.len()
        {
            return Err("decoded_region");
        }
        for (server, (host, name)) in region
            .nodes
            .iter()
            .zip(row.hosts.iter().zip(row.server_names.iter()))
        {
            if server.hostname != host || server.name != name || server.region_id != id {
                return Err("decoded_server");
            }
        }
    }
    Ok(())
}

/// Decode the wire text, encode the result, decode that, and require the second decode to hold the same regions and to encode to the same
/// bytes as the first. Then two planted refusals, each named by what `serde_json` reports: the text cut one byte short ends early, and the
/// first `:` replaced by `;` is not JSON.
fn derp_wire_round_trip(rows: &[RegionRow]) -> Result<String, &'static str> {
    let wire = derp_wire_text(rows);
    let first = derp_decode(&wire)?;
    derp_matches(&first, rows)?;
    let encoded = serde_json::to_string(&first).map_err(|_| "encode")?;
    let second = derp_decode(&encoded)?;
    derp_matches(&second, rows)?;
    let re_encoded = serde_json::to_string(&second).map_err(|_| "encode")?;
    if re_encoded != encoded {
        return Err("encoding_not_stable");
    }
    let truncated = wire.get(..wire.len().saturating_sub(1)).ok_or("truncate")?;
    let ended_early = match derp_decode(truncated) {
        Err(name) => name,
        Ok(_) => return Err("truncated_accepted"),
    };
    let garbled = wire.replacen(':', ";", 1);
    let not_json = match derp_decode(&garbled) {
        Err(name) => name,
        Ok(_) => return Err("garbled_accepted"),
    };
    if ended_early != "eof" || not_json != "syntax" {
        return Err("refusal_misnamed");
    }
    Ok(format!(
        "wire_bytes={} encoded_bytes={} decoded_regions={} refused_truncated={ended_early} refused_garbled={not_json}",
        wire.len(),
        encoded.len(),
        second.regions.len()
    ))
}

// ---- phase: overlay_router ----------------------------------------------------------------------------------------------------------

/// A minimal IPv4 packet (version/IHL byte and destination address, the two things the router reads) followed by `body`.
fn v4_packet(dst: Ipv4Addr, body: &[u8]) -> PacketMut {
    let mut packet = PacketMut::new(20);
    packet[0] = 0x45;
    packet[16..20].copy_from_slice(&dst.octets());
    packet.extend_from_slice(body);
    packet
}

/// The bucket (the loopback id, read through `u32::from`) each of four offered packets reaches, `None` where a packet vanishes. The outbound
/// router is given `100.100.100.100/32 -> Loopback(42)`, `100.64.0.0/24 -> Loopback(7)` and, when `with_drop`, `100.64.0.9/32 -> Drop`, and
/// is offered `100.100.100.100`, `100.64.0.77`, `100.64.0.9` and `8.8.8.8`, in that order. With the notch the answer is
/// `[Some(42), Some(7), None, None]`: the third address is carved out of the /24 by the longer `Drop` prefix, and the fourth has no route.
/// Without it the third address reaches bucket 7, which is what makes the `Drop` route observable (RedPuma F1). Nothing leaves by
/// WireGuard, because no route names a peer.
fn route_buckets(with_drop: bool) -> Result<[Option<u32>; 4], &'static str> {
    let mut routes: Table<RouteAction> = Table::default();
    routes.insert(
        "100.100.100.100/32".parse().map_err(|_| "route_prefix")?,
        RouteAction::Loopback(42.into()),
    );
    routes.insert(
        "100.64.0.0/24".parse().map_err(|_| "route_prefix")?,
        RouteAction::Loopback(7.into()),
    );
    if with_drop {
        routes.insert(
            "100.64.0.9/32".parse().map_err(|_| "route_prefix")?,
            RouteAction::Drop,
        );
    }
    let mut router = Router::default();
    let _previous = router.swap(routes);

    let packets = [
        v4_packet(Ipv4Addr::new(100, 100, 100, 100), b"magic address"),
        v4_packet(Ipv4Addr::new(100, 64, 0, 77), b"through the /24"),
        v4_packet(Ipv4Addr::new(100, 64, 0, 9), b"notched out of the /24"),
        v4_packet(Ipv4Addr::new(8, 8, 8, 8), b"no route"),
    ];
    let out = router.route(packets.to_vec());
    if out.to_wireguard.values().any(|held| !held.is_empty()) {
        return Err("unexpected_wireguard");
    }
    let mut buckets = [None; 4];
    for (slot, packet) in buckets.iter_mut().zip(packets.iter()) {
        *slot = out
            .loopback
            .iter()
            .find(|(_, held)| held.contains(packet))
            .map(|(id, _)| u32::from(*id));
    }
    Ok(buckets)
}

/// The inbound router on an empty batch, then the outbound router's buckets with and without the `Drop` route (`route_buckets`). The facts
/// say how many of the four offered packets reached each bucket and where the third address goes when the notch is missing.
fn overlay_router() -> Result<String, &'static str> {
    let inbound = ts_overlay_router::inbound::Router::default();
    let inbound_out = inbound.route(std::iter::empty());
    let inbound_routed: usize = inbound_out.values().map(Vec::len).sum();
    if inbound_routed != 0 {
        return Err("inbound_not_empty");
    }

    let buckets = route_buckets(true)?;
    if buckets != [Some(42), Some(7), None, None] {
        return Err("route_buckets");
    }
    let unnotched = route_buckets(false)?[2]
        .filter(|id| *id == 7)
        .ok_or("drop_unobserved")?;
    let offered = buckets.len();
    let routed = buckets.iter().flatten().count();
    let in_42 = buckets.iter().filter(|id| **id == Some(42)).count();
    let in_7 = buckets.iter().filter(|id| **id == Some(7)).count();
    Ok(format!(
        "offered={offered} routed={routed} dropped={} bucket_42={in_42} bucket_7={in_7} unnotched_bucket={unnotched} inbound_routed={inbound_routed}",
        offered - routed
    ))
}

// ---- tests --------------------------------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A `/proc` that holds canned text.
    struct FakeProc {
        status: Option<&'static str>,
        stat: Option<&'static str>,
    }

    impl ProcSource for FakeProc {
        fn read(&self, path: &str) -> Option<String> {
            match path {
                STATUS_PATH => self.status.map(str::to_owned),
                STAT_PATH => self.stat.map(str::to_owned),
                _ => None,
            }
        }
    }

    const GOOD_STATUS: &str =
        "Name:\tt01\nVmPeak:\t  9000 kB\nVmHWM:\t  4321 kB\nVmRSS:\t  4000 kB\n";
    const GOOD_STAT: &str = "1 (t01 core) probe) S 1 1 1 0 -1 4194304 100 0 0 0 7 3 0 0 20 0 1 0 5";

    fn good_proc() -> FakeProc {
        FakeProc {
            status: Some(GOOD_STATUS),
            stat: Some(GOOD_STAT),
        }
    }

    fn missing_proc() -> FakeProc {
        FakeProc {
            status: None,
            stat: None,
        }
    }

    fn phase_line<'a>(report: &'a Report, name: &str) -> &'a str {
        let prefix = format!("T01X02 PHASE {name} ");
        report
            .lines
            .iter()
            .map(String::as_str)
            .find(|line| line.starts_with(&prefix))
            .expect("phase line present")
    }

    fn is_ok(report: &Report, name: &str) -> bool {
        phase_line(report, name).contains(" ok ")
    }

    fn is_fail(report: &Report, name: &str) -> bool {
        phase_line(report, name).contains(" fail reason=")
    }

    const READING_NAMES: [&str; 4] = ["VmHWM", "VmRSS", "utime", "stime"];

    /// `T01X02 <VmHWM|VmRSS|utime|stime> <canonical integer or UNKNOWN>`.
    fn well_formed_reading(line: &str) -> bool {
        let Some(rest) = line.strip_prefix("T01X02 ") else {
            return false;
        };
        let Some((name, value)) = rest.split_once(' ') else {
            return false;
        };
        READING_NAMES.contains(&name) && (value == "UNKNOWN" || canonical_u64(value).is_some())
    }

    fn is_reading(line: &str) -> bool {
        READING_NAMES
            .iter()
            .any(|name| line.starts_with(&format!("T01X02 {name} ")))
    }

    fn readings(report: &Report) -> Vec<&str> {
        report
            .lines
            .iter()
            .map(String::as_str)
            .filter(|line| is_reading(line))
            .collect()
    }

    fn end_line(report: &Report) -> String {
        format!(
            "T01X02 END ok={} fail={} unknown={}",
            report.ok, report.fail, report.unknown
        )
    }

    /// The text with one ASCII character replaced: `extra` characters past the end of the first `anchor`.
    fn corrupt_after(text: &str, anchor: &str, extra: usize, replacement: char) -> String {
        let at = text.find(anchor).expect("anchor present") + anchor.len() + extra;
        assert!(text.is_char_boundary(at) && text.is_char_boundary(at + 1));
        let mut out = text.to_owned();
        out.replace_range(at..at + 1, &replacement.to_string());
        assert_ne!(out, text, "the corruption changed nothing");
        out
    }

    #[test]
    fn positive_run_probe_every_phase_ok_and_resources_well_formed() {
        let report = run_probe();
        assert_eq!(report.fail, 0, "failed phases: {:#?}", report.lines);
        assert_eq!(report.ok, PHASES.len());
        let phases: Vec<&str> = report
            .lines
            .iter()
            .map(String::as_str)
            .filter(|line| line.starts_with("T01X02 PHASE "))
            .collect();
        assert_eq!(phases.len(), PHASES.len());
        for (line, name) in phases.iter().zip(PHASES) {
            let prefix = format!("T01X02 PHASE {name} ok ");
            assert!(line.starts_with(&prefix), "unexpected line: {line}");
            assert!(line.len() > prefix.len(), "no facts: {line}");
            assert!(line.is_ascii());
        }
        // The facts that come from the committed fixtures are exact; sizes that the protocol fixes are checked as keys only.
        assert!(phase_line(&report, "TS_KEYS").ends_with("nodes=4 keys=12 derived=12"));
        let noise = phase_line(&report, "TS_NOISE");
        assert!(noise.contains(" init_bytes="));
        assert!(noise.contains(" sessions=2 rng_wait_ms="));
        let waited = noise.rsplit("rng_wait_ms=").next().unwrap_or("");
        assert!(
            waited.parse::<u64>().is_ok(),
            "rng_wait_ms is not an integer: {noise}"
        );
        // `sent` is the input (3 packets offered); `recv`, `bytes` and the wire tallies come back from the crate: 3 delivered, 4 bytes
        // each, 5 wire packets (initiation, response, 2 transport, 1 reply), and the one damaged copy refused (`refused` is offered minus
        // delivered). `wire_bytes` is checked as a key only: the predicted value is 348 = 148 + 92 + 3 x 36 (RedPuma F3, arithmetic from the
        // pinned structs), to be pinned only after a central run prints it.
        let tunnel = phase_line(&report, "TS_TUNNEL");
        assert!(tunnel.contains("peers=3 rekeyed=1 removed=1 steps=12 idle="));
        assert!(tunnel.contains(" sent=3 recv=3 bytes=12 wire_packets=5 wire_bytes="));
        assert!(tunnel.ends_with(" refused=1"));
        let serde = phase_line(&report, "TS_CONTROL_SERDE");
        assert!(serde.contains("regions=3 servers=3 reachable=2 route_cases=9 wire_bytes="));
        assert!(serde.ends_with(" decoded_regions=3 refused_truncated=eof refused_garbled=syntax"));
        assert!(
            phase_line(&report, "TS_PACKETFILTER_STATE")
                .ends_with("peers=3 rules=3 cases=12 clear_checks=3")
        );
        assert!(phase_line(&report, "TS_DISCO_PROTOCOL").ends_with(" endpoints=4"));
        assert!(phase_line(&report, "TS_OVERLAY_ROUTER").ends_with(
            "offered=4 routed=2 dropped=2 bucket_42=1 bucket_7=1 unnotched_bucket=7 inbound_routed=0"
        ));
        let kat = phase_line(&report, "CRYPTO_KAT");
        assert!(kat.contains(" x25519=7/7 "));
        assert!(kat.ends_with(" plant=caught"));

        let resource = readings(&report);
        assert_eq!(resource.len(), 4);
        assert!(resource.iter().all(|line| well_formed_reading(line)));
        // Order: every PHASE line, then the four readings in the agreed order, then END, and nothing else.
        let kinds: Vec<&str> = report
            .lines
            .iter()
            .map(|line| line.split(' ').nth(1).unwrap_or(""))
            .collect();
        let mut expected: Vec<&str> = vec!["PHASE"; PHASES.len()];
        expected.extend(READING_NAMES);
        expected.push("END");
        assert_eq!(kinds, expected);
        // Framing: ASCII, one marker per line and at its start, no control character.
        for line in &report.lines {
            assert!(line.is_ascii() && line.starts_with("T01X02 "), "{line}");
            assert_eq!(line.matches("T01X02").count(), 1, "{line}");
            assert!(
                line.bytes().all(|byte| (0x20..0x7f).contains(&byte)),
                "{line}"
            );
        }
        // On Linux the four readings exist; elsewhere (no /proc) they may be UNKNOWN, which is still well formed.
        #[cfg(target_os = "linux")]
        assert_eq!(report.unknown, 0, "readings: {resource:?}");
        assert_eq!(
            report.lines.last().map(String::as_str),
            Some(end_line(&report).as_str())
        );
        assert!(!report.failed());
    }

    #[test]
    fn corrupted_identity_key_fails_its_phase_and_ends_nonzero() {
        let embedded = Inputs::embedded();
        // `"mkey:0` skips the bare `"mkey:"` in the fixture's key_format note and lands in the first real key.
        let identity = corrupt_after(embedded.identity, "\"mkey:0", 4, 'g');
        let inputs = Inputs {
            identity: &identity,
            ..embedded
        };
        let report = run_probe_with(&inputs, &good_proc(), false);
        assert!(is_fail(&report, "TS_KEYS"), "{:#?}", report.lines);
        assert!(phase_line(&report, "TS_KEYS").ends_with("fail reason=machine_key"));
        // The machine key is used by no other phase and the other fixtures are untouched, so every other phase still passes.
        for name in PHASES.iter().skip(1) {
            assert!(is_ok(&report, name), "{name}: {:#?}", report.lines);
        }
        assert_eq!(report.fail, 1);
        assert!(report.failed());
        assert!(end_line(&report).contains(" fail=1 ") && !end_line(&report).contains(" fail=0 "));
        assert_eq!(
            report.lines.last().map(String::as_str),
            Some(end_line(&report).as_str())
        );
    }

    #[test]
    fn corrupted_derp_region_id_fails_derp_regions_only() {
        let embedded = Inputs::embedded();
        let derp_map = corrupt_after(embedded.derp_map, "{\"id\": ", 0, '0');
        let inputs = Inputs {
            derp_map: &derp_map,
            ..embedded
        };
        let report = run_probe_with(&inputs, &good_proc(), false);
        assert!(phase_line(&report, "TS_CONTROL_SERDE").ends_with("fail reason=region_id_zero"));
        assert!(is_ok(&report, "TS_KEYS"));
        assert!(is_ok(&report, "TS_NOISE"));
        assert_eq!(report.fail, 1);
        assert!(report.failed());
        assert!(end_line(&report).contains(" fail=1 "));
    }

    #[test]
    fn corrupted_netmap_rule_source_fails_netmap_rules_only() {
        let embedded = Inputs::embedded();
        let netmap = corrupt_after(embedded.netmap, "\"srcs\": [\"node-", 0, 'q');
        let inputs = Inputs {
            netmap: &netmap,
            ..embedded
        };
        let report = run_probe_with(&inputs, &good_proc(), false);
        assert!(
            phase_line(&report, "TS_PACKETFILTER_STATE").ends_with("fail reason=rule_unknown_node")
        );
        assert!(is_ok(&report, "TS_TUNNEL"));
        assert_eq!(report.fail, 1);
        assert!(report.failed());
    }

    #[test]
    fn corrupted_key_expiry_fails_tunnel_clock_only() {
        let embedded = Inputs::embedded();
        let key_expiry = corrupt_after(embedded.key_expiry, "\"now\": ", 0, 'x');
        let inputs = Inputs {
            key_expiry: &key_expiry,
            ..embedded
        };
        let report = run_probe_with(&inputs, &good_proc(), false);
        assert!(phase_line(&report, "TS_TUNNEL").ends_with("fail reason=json_syntax"));
        assert_eq!(report.fail, 1);
        assert!(report.failed());
    }

    #[test]
    fn a_missing_proc_prints_unknown_never_zero() {
        let report = run_probe_with(&Inputs::embedded(), &missing_proc(), false);
        let resource = readings(&report);
        assert_eq!(resource.len(), 4);
        assert!(resource.iter().all(|line| line.ends_with(" UNKNOWN")));
        assert!(resource.iter().all(|line| !line.ends_with(" 0")));
        assert!(resource.iter().all(|line| well_formed_reading(line)));
        assert_eq!(report.unknown, 4);
        assert_eq!(report.fail, 0);
        assert!(end_line(&report).ends_with(" unknown=4"));
        assert!(!report.failed());
    }

    #[test]
    fn an_unparsable_proc_reading_is_unknown_and_the_others_survive() {
        // Wrong unit, non-canonical number, no kB, and a stat line cut short.
        let wrong_unit = FakeProc {
            status: Some("VmHWM:\t  12 MB\nVmRSS:\t 0007 kB\n"),
            stat: Some("1 (x) S 1"),
        };
        let report = run_probe_with(&Inputs::embedded(), &wrong_unit, false);
        assert_eq!(report.unknown, 4);
        // Only the one reading that is intact is read.
        let partial = FakeProc {
            status: Some("VmHWM:\t12 kB\n"),
            stat: None,
        };
        let report = run_probe_with(&Inputs::embedded(), &partial, false);
        let resource = readings(&report);
        assert_eq!(resource[0], "T01X02 VmHWM 12");
        assert_eq!(resource[1], "T01X02 VmRSS UNKNOWN");
        assert_eq!(report.unknown, 3);
    }

    #[test]
    fn canned_proc_text_parses_to_exact_integers() {
        let report = run_probe_with(&Inputs::embedded(), &good_proc(), false);
        let resource = readings(&report);
        assert_eq!(resource[0], "T01X02 VmHWM 4321");
        assert_eq!(resource[1], "T01X02 VmRSS 4000");
        // The command name holds a space and a closing parenthesis; the fields are counted after the last one.
        assert_eq!(resource[2], "T01X02 utime 7");
        assert_eq!(resource[3], "T01X02 stime 3");
        assert_eq!(report.unknown, 0);
        assert_eq!(status_kb("VmHWMx:\t5 kB\nVmHWM:\t6 kB\n", "VmHWM"), Some(6));
        assert_eq!(status_kb("VmHWM:\t5 kB extra\n", "VmHWM"), None);
        assert_eq!(status_kb("VmHWM 5 kB\n", "VmHWM"), None);
    }

    #[test]
    fn fact_rules_follow_the_judge_grammar() {
        for good in [
            "a=1",
            "nodes=4 keys=12",
            "x25519=2/2 chacha20poly1305=1/1 blake2s=3/3",
            "reason=rfc7748_5_2_v1",
            "k_2=a.b-c:d",
        ] {
            assert!(facts_well_formed(good), "{good}");
        }
        for bad in [
            "", " ", "a", "a=", "=1", "a=1 a=2", "a=1  b=2", "a=1 ", "A=1", "1a=1", "a-b=1",
            "a=b=c", "a=\u{e9}", "a=1\tb=2",
        ] {
            assert!(!facts_well_formed(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_phase_with_malformed_facts_is_printed_as_bad_facts_and_counts_as_a_failure() {
        let mut report = Report::new(false);
        report.phase("TS_KEYS", Ok("a=b=c".to_owned()));
        report.phase("CRYPTO_KAT", Err("reason=rfc7748_5_2_v1".to_owned()));
        report.phase("TS_NOISE", Ok("n=1".to_owned()));
        assert_eq!(
            report.lines,
            [
                "T01X02 PHASE TS_KEYS fail reason=bad_facts",
                "T01X02 PHASE CRYPTO_KAT fail reason=rfc7748_5_2_v1",
                "T01X02 PHASE TS_NOISE ok n=1",
            ]
        );
        assert_eq!((report.ok, report.fail), (1, 2));
    }

    #[test]
    fn a_damaged_transport_byte_is_refused_and_a_control_that_damages_nothing_is_caught() {
        let a = spare_pair(0x11);
        let b = spare_pair(0x22);
        // The planted fault is in the control itself: it damages nothing, so the "damaged" copy is delivered, and the phase must fail.
        let nothing = |_: &mut PacketMut| {};
        assert_eq!(
            transport_round_trip(a.clone(), b.clone(), &nothing),
            Err("tamper_accepted")
        );
        // With the real damage the copy is refused, and the tallies say what moved.
        let facts = transport_round_trip(a, b, &flip_last_byte).expect("round trip");
        assert!(
            facts.starts_with("sent=3 recv=3 bytes=12 wire_packets=5 wire_bytes="),
            "{facts}"
        );
        assert!(facts.ends_with(" refused=1"), "{facts}");
    }

    #[test]
    fn malformed_derp_json_is_refused_by_name() {
        assert_eq!(derp_decode("{").err(), Some("eof"));
        assert_eq!(derp_decode("{\"Regions\" 1}").err(), Some("syntax"));
        assert_eq!(derp_decode("5").err(), Some("data"));
        assert!(derp_decode("{\"Regions\":{},\"omitDefaultRegions\":false}").is_ok());
    }

    #[test]
    fn the_router_reads_the_destination_that_the_helper_wrote() {
        let packet = v4_packet(Ipv4Addr::new(100, 100, 100, 100), b"x");
        assert_eq!(
            packet.get_dst_addr(),
            Some(IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100)))
        );
        assert_eq!(packet.len(), 21);
    }

    /// A draw that returns at once.
    fn ready_draw() {}

    /// A gate whose draw does not return until the returned sender is dropped: the bound is the argument (a small one in these tests, not
    /// the 40 s of `RNG_WAIT`). Dropping the sender afterwards lets the worker end.
    fn blocked_gate(bound: Duration) -> (Rng, mpsc::Sender<()>) {
        let (hold, held) = mpsc::channel::<()>();
        let rng = rng_gate_with(
            move || {
                let _ = held.recv();
            },
            bound,
        );
        (rng, hold)
    }

    #[test]
    fn a_ready_gate_reports_an_integer_wait_and_the_noise_phase_prints_it() {
        let rng = rng_gate_with(ready_draw, Duration::from_secs(5));
        let Rng::Ready { wait_ms } = rng else {
            panic!("a draw that returns at once was not ready: {rng:?}");
        };
        assert!(wait_ms < 5_000, "{wait_ms}");
        let facts = noise_ik(&Inputs::embedded(), rng).expect("the noise phase with a ready gate");
        assert!(
            facts.ends_with(&format!(" sessions=2 rng_wait_ms={wait_ms}")),
            "{facts}"
        );
        assert!(facts_well_formed(&facts));
    }

    #[test]
    fn a_gate_that_never_becomes_ready_is_rng_blocked_within_the_bound_and_does_not_hang() {
        let started = Instant::now();
        let (rng, hold) = blocked_gate(Duration::from_millis(100));
        let took = started.elapsed();
        assert_eq!(rng, Rng::Blocked);
        assert!(
            took >= Duration::from_millis(90),
            "returned before the bound: {took:?}"
        );
        assert!(
            took < Duration::from_secs(5),
            "did not return near the bound: {took:?}"
        );
        // Both phases that need randomness refuse before drawing any, with the named reason.
        assert_eq!(rng.wait_ms(), Err("rng_blocked"));
        assert_eq!(noise_ik(&Inputs::embedded(), rng), Err("rng_blocked"));
        assert_eq!(
            tunnel_transport(&Inputs::embedded(), rng),
            Err("rng_blocked")
        );
        drop(hold);
    }

    #[test]
    fn a_blocked_gate_fails_exactly_the_two_phases_that_need_randomness_and_the_run_still_ends() {
        let gate = || {
            let (rng, hold) = blocked_gate(Duration::from_millis(100));
            drop(hold);
            rng
        };
        let report = run_probe_gated(&Inputs::embedded(), &good_proc(), false, &gate);
        assert_eq!(
            phase_line(&report, "TS_NOISE"),
            "T01X02 PHASE TS_NOISE fail reason=rng_blocked"
        );
        assert_eq!(
            phase_line(&report, "TS_TUNNEL"),
            "T01X02 PHASE TS_TUNNEL fail reason=rng_blocked"
        );
        for name in PHASES {
            if name != "TS_NOISE" && name != "TS_TUNNEL" {
                assert!(is_ok(&report, name), "{name}: {:#?}", report.lines);
            }
        }
        assert_eq!((report.ok, report.fail), (6, 2));
        assert_eq!(
            report.lines.last().map(String::as_str),
            Some("T01X02 END ok=6 fail=2 unknown=0")
        );
    }

    #[test]
    fn the_same_run_with_a_ready_gate_is_not_rng_blocked() {
        // Remove-the-plant control for the test above: only the gate differs.
        let gate = || rng_gate_with(ready_draw, Duration::from_secs(5));
        let report = run_probe_gated(&Inputs::embedded(), &good_proc(), false, &gate);
        assert_eq!(report.fail, 0, "{:#?}", report.lines);
        assert!(!report.lines.iter().any(|line| line.contains("rng_blocked")));
        assert!(phase_line(&report, "TS_NOISE").contains(" rng_wait_ms="));
        assert_eq!(
            report.lines.last().map(String::as_str),
            Some("T01X02 END ok=8 fail=0 unknown=0")
        );
    }

    #[test]
    fn a_worker_that_dies_without_drawing_is_a_gate_failure_not_a_wait() {
        let rng = rng_gate_with(|| panic!("the draw failed"), Duration::from_secs(5));
        assert_eq!(rng, Rng::Failed);
        assert_eq!(rng.wait_ms(), Err("rng_gate_failed"));
    }

    #[test]
    fn the_router_buckets_follow_the_longest_prefix_and_the_drop_notch() {
        assert_eq!(route_buckets(true), Ok([Some(42), Some(7), None, None]));
    }

    #[test]
    fn without_the_drop_route_the_third_address_lands_in_bucket_7() {
        // The plant: no `100.64.0.9/32 -> Drop`. Only the third address moves, from vanishing to the /24's bucket.
        assert_eq!(route_buckets(false), Ok([Some(42), Some(7), Some(7), None]));
        assert_ne!(route_buckets(false), route_buckets(true));
    }

    #[test]
    fn canonical_integers_only() {
        assert_eq!(canonical_u64("0"), Some(0));
        assert_eq!(canonical_u64("4294967296"), Some(4_294_967_296));
        assert_eq!(canonical_u64(""), None);
        assert_eq!(canonical_u64("007"), None);
        assert_eq!(canonical_u64("+7"), None);
        assert_eq!(canonical_u64("-7"), None);
        assert_eq!(canonical_u64("7 "), None);
        assert_eq!(canonical_u64("99999999999999999999999"), None);
    }

    #[test]
    fn the_json_reader_refuses_what_the_fixtures_never_use() {
        assert!(parse_json("{\"a\": [1, 2, {\"b\": null}]}").is_ok());
        assert_eq!(parse_json("[1,]"), Err("json_syntax"));
        assert_eq!(parse_json("{\"a\": 1} x"), Err("json_trailing"));
        assert_eq!(parse_json("\"a\\nb\""), Err("json_escape"));
        assert_eq!(parse_json("1.5"), Err("json_float"));
        assert_eq!(parse_json("01"), Err("json_number"));
        assert_eq!(parse_json("\"open"), Err("json_unterminated"));
        let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));
        assert_eq!(parse_json(&deep), Err("json_depth"));
    }

    #[test]
    fn hex32_needs_exactly_sixty_four_hex_digits() {
        let digits = "00000000000000000000000000000000000000000000000000000000000000a1";
        assert_eq!(hex32(digits).map(|bytes| bytes[31]), Some(0xa1));
        assert_eq!(hex32(&digits[1..]), None);
        assert_eq!(hex32(&digits.replace('a', "g")), None);
    }

    #[test]
    fn hex32_decodes_every_pair_in_order() {
        // The pairs 00 01 02 .. 1f: a swapped nibble (0x01 would become 0x10), a swapped pair or a reversed walk changes a byte.
        let digits = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let want: [u8; 32] = std::array::from_fn(|index| index as u8);
        assert_eq!(hex32(digits), Some(want));
        assert_eq!(hex32(&digits.to_uppercase()), Some(want));
    }
}
