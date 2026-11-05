//! The time-series capture format, `ffw.baseline.capture.v1`.
//!
//! One record per line, `tag key=value ...`; blank lines and lines starting with `#` are ignored.
//!
//! ```text
//! ffw.baseline.capture.v1
//! meta evidence=synthetic profile=clean-v1 cadence_ms=1000 declared_ms=10000 playout_ms=500
//! counter name=xruns role=dev_underruns width=32 max_rate_per_s=1000
//! gauge name=playing role=playing
//! sample mono_ns=1000000000 wall_ns=1700000000000000000 dev_frames=0 xruns=0 playing=1
//! ```
//!
//! * `meta` (exactly one, first): `evidence`, `profile`, `cadence_ms`, `declared_ms` are required.
//!   Optional, with defaults: `hole_factor_pct=150`, `playout_ms=0`, `wall_step_ms=1000`,
//!   `spike_factor=8`, `device_width=64`, and, with no default, `device_rate_hz`,
//!   `device_stall_frames`, `min_coverage_ppm`, `max_dropout_intervals`. The last two are the
//!   acceptance thresholds, declared before the run.
//! * `counter`: a cumulative count. `role` is one of `dev_underruns`, `late_packets`, `cpu_misses`,
//!   `source_bytes`, `other`; each role except `other` at most once. `width` is 32 or 64.
//!   `max_rate_per_s` (default 0) is the fastest the counter can plausibly grow; it is what lets a
//!   32-bit wraparound be told from a reset, and with 0 a decrease is always a reset.
//! * `gauge`: an instantaneous value. `role=playing` is the 0/1 playback state; `role=value` needs
//!   `max`, the largest plausible reading.
//! * `sample`: `mono_ns` is required; `wall_ns` and `dev_frames` are optional; any other key must be a
//!   declared counter or gauge. A series missing from a sample is a missing value, not a zero.
//!
//! Declarations come before the first sample. Timestamps are integers; there are no floats anywhere.

use std::collections::BTreeMap;

use crate::clock::{DeviceFrames, MonoNs, WallNs};
use crate::parse::{Kv, ParseError, ParseKind, bounded, is_ident, is_label, parse_i64, parse_u64};

pub const HEADER: &str = "ffw.baseline.capture.v1";
pub const MAX_SAMPLES: usize = 2_000_000;
pub const MAX_LINE_BYTES: usize = 4096;
const NS_PER_MS: u64 = 1_000_000;
const RESERVED: [&str; 3] = ["mono_ns", "wall_ns", "dev_frames"];

/// What kind of run produced the capture. It travels with every report so that nothing downstream
/// can mistake a synthetic or simulated run for a measurement of the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    Synthetic,
    HostSimulation,
    GuestExecution,
    RealService,
    Physical,
}

impl Evidence {
    pub fn parse(s: &str) -> Option<Evidence> {
        match s {
            "synthetic" => Some(Evidence::Synthetic),
            "host-simulation" => Some(Evidence::HostSimulation),
            "guest-execution" => Some(Evidence::GuestExecution),
            "real-service" => Some(Evidence::RealService),
            "physical" => Some(Evidence::Physical),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Evidence::Synthetic => "synthetic",
            Evidence::HostSimulation => "host-simulation",
            Evidence::GuestExecution => "guest-execution",
            Evidence::RealService => "real-service",
            Evidence::Physical => "physical",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub evidence: Evidence,
    pub profile: String,
    pub cadence_ns: u64,
    pub declared_ns: u64,
    pub hole_factor_pct: u64,
    pub playout_ns: u64,
    pub wall_step_ns: u64,
    pub spike_factor: u64,
    pub device_rate_hz: Option<u64>,
    pub device_width: u8,
    pub device_stall_frames: Option<u64>,
    pub min_coverage_ppm: Option<u64>,
    pub max_dropout_intervals: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterRole {
    DevUnderruns,
    LatePackets,
    CpuMisses,
    SourceBytes,
    Other,
}

impl CounterRole {
    fn parse(s: &str) -> Option<CounterRole> {
        match s {
            "dev_underruns" => Some(CounterRole::DevUnderruns),
            "late_packets" => Some(CounterRole::LatePackets),
            "cpu_misses" => Some(CounterRole::CpuMisses),
            "source_bytes" => Some(CounterRole::SourceBytes),
            "other" => Some(CounterRole::Other),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CounterRole::DevUnderruns => "dev_underruns",
            CounterRole::LatePackets => "late_packets",
            CounterRole::CpuMisses => "cpu_misses",
            CounterRole::SourceBytes => "source_bytes",
            CounterRole::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GaugeRole {
    Playing,
    Value,
}

impl GaugeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            GaugeRole::Playing => "playing",
            GaugeRole::Value => "value",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterDecl {
    pub name: String,
    pub role: CounterRole,
    pub width: u8,
    pub max_rate_per_s: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GaugeDecl {
    pub name: String,
    pub role: GaugeRole,
    pub max: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub line: usize,
    pub mono: MonoNs,
    pub wall: Option<WallNs>,
    pub dev: Option<DeviceFrames>,
    pub values: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capture {
    pub meta: Meta,
    pub counters: Vec<CounterDecl>,
    pub gauges: Vec<GaugeDecl>,
    pub samples: Vec<Sample>,
}

fn bad_value(line: usize, key: &str) -> ParseError {
    ParseError::new(line, ParseKind::BadValue(key.to_string()))
}

fn ms_to_ns(line: usize, key: &'static str, ms: u64) -> Result<u64, ParseError> {
    ms.checked_mul(NS_PER_MS)
        .ok_or_else(|| bad_value(line, key))
}

fn parse_meta(mut kv: Kv<'_>) -> Result<Meta, ParseError> {
    let line = kv.line();
    let evidence =
        Evidence::parse(kv.req("evidence")?).ok_or_else(|| bad_value(line, "evidence"))?;
    let profile = kv.req("profile")?;
    if !is_label(profile) {
        return Err(ParseError::new(
            line,
            ParseKind::BadIdentifier(bounded(profile)),
        ));
    }
    let cadence_ms = kv.req_u64("cadence_ms")?;
    let declared_ms = kv.req_u64("declared_ms")?;
    let hole_factor_pct = kv.opt_u64("hole_factor_pct")?.unwrap_or(150);
    let playout_ms = kv.opt_u64("playout_ms")?.unwrap_or(0);
    let wall_step_ms = kv.opt_u64("wall_step_ms")?.unwrap_or(1000);
    let spike_factor = kv.opt_u64("spike_factor")?.unwrap_or(8);
    let device_rate_hz = kv.opt_u64("device_rate_hz")?;
    let device_width = kv.opt_u64("device_width")?.unwrap_or(64);
    let device_stall_frames = kv.opt_u64("device_stall_frames")?;
    let min_coverage_ppm = kv.opt_u64("min_coverage_ppm")?;
    let max_dropout_intervals = kv.opt_u64("max_dropout_intervals")?;
    kv.finish()?;

    if cadence_ms == 0 {
        return Err(bad_value(line, "cadence_ms"));
    }
    if declared_ms == 0 {
        return Err(bad_value(line, "declared_ms"));
    }
    if hole_factor_pct < 100 {
        return Err(bad_value(line, "hole_factor_pct"));
    }
    if spike_factor < 2 {
        return Err(bad_value(line, "spike_factor"));
    }
    if device_rate_hz == Some(0) {
        return Err(bad_value(line, "device_rate_hz"));
    }
    // A zero threshold would call every interval a stall.
    if device_stall_frames == Some(0) {
        return Err(bad_value(line, "device_stall_frames"));
    }
    if device_width != 32 && device_width != 64 {
        return Err(bad_value(line, "device_width"));
    }
    if min_coverage_ppm.is_some_and(|p| p > 1_000_000) {
        return Err(bad_value(line, "min_coverage_ppm"));
    }
    let cadence_ns = ms_to_ns(line, "cadence_ms", cadence_ms)?;
    let declared_ns = ms_to_ns(line, "declared_ms", declared_ms)?;
    if declared_ns < cadence_ns {
        return Err(bad_value(line, "declared_ms"));
    }
    Ok(Meta {
        evidence,
        profile: profile.to_string(),
        cadence_ns,
        declared_ns,
        hole_factor_pct,
        playout_ns: ms_to_ns(line, "playout_ms", playout_ms)?,
        wall_step_ns: ms_to_ns(line, "wall_step_ms", wall_step_ms)?,
        spike_factor,
        device_rate_hz,
        // 32 or 64, checked above.
        device_width: if device_width == 32 { 32 } else { 64 },
        device_stall_frames,
        min_coverage_ppm,
        max_dropout_intervals,
    })
}

fn check_name(line: usize, name: &str, taken: &[&str]) -> Result<(), ParseError> {
    if !is_ident(name) {
        return Err(ParseError::new(
            line,
            ParseKind::BadIdentifier(bounded(name)),
        ));
    }
    if RESERVED.contains(&name) {
        return Err(ParseError::new(
            line,
            ParseKind::ReservedName(name.to_string()),
        ));
    }
    if taken.contains(&name) {
        return Err(ParseError::new(
            line,
            ParseKind::DuplicateName(name.to_string()),
        ));
    }
    Ok(())
}

fn parse_counter(
    mut kv: Kv<'_>,
    counters: &[CounterDecl],
    gauges: &[GaugeDecl],
) -> Result<CounterDecl, ParseError> {
    let line = kv.line();
    let name = kv.req("name")?;
    let role = CounterRole::parse(kv.req("role")?).ok_or_else(|| bad_value(line, "role"))?;
    let width = kv.req_u64("width")?;
    let max_rate_per_s = kv.opt_u64("max_rate_per_s")?.unwrap_or(0);
    kv.finish()?;
    let taken: Vec<&str> = counters
        .iter()
        .map(|c| c.name.as_str())
        .chain(gauges.iter().map(|g| g.name.as_str()))
        .collect();
    check_name(line, name, &taken)?;
    if width != 32 && width != 64 {
        return Err(bad_value(line, "width"));
    }
    if role != CounterRole::Other && counters.iter().any(|c| c.role == role) {
        return Err(ParseError::new(
            line,
            ParseKind::DuplicateRole(role.as_str().to_string()),
        ));
    }
    Ok(CounterDecl {
        name: name.to_string(),
        role,
        width: if width == 32 { 32 } else { 64 },
        max_rate_per_s,
    })
}

fn parse_gauge(
    mut kv: Kv<'_>,
    counters: &[CounterDecl],
    gauges: &[GaugeDecl],
) -> Result<GaugeDecl, ParseError> {
    let line = kv.line();
    let name = kv.req("name")?;
    let role = match kv.req("role")? {
        "playing" => GaugeRole::Playing,
        "value" => GaugeRole::Value,
        _ => return Err(bad_value(line, "role")),
    };
    let declared_max = kv.opt_u64("max")?;
    kv.finish()?;
    let taken: Vec<&str> = counters
        .iter()
        .map(|c| c.name.as_str())
        .chain(gauges.iter().map(|g| g.name.as_str()))
        .collect();
    check_name(line, name, &taken)?;
    let max = match (role, declared_max) {
        (GaugeRole::Playing, None) => 1,
        (GaugeRole::Playing, Some(1)) => 1,
        (GaugeRole::Playing, Some(_)) => return Err(bad_value(line, "max")),
        (GaugeRole::Value, Some(m)) if m > 0 => m,
        (GaugeRole::Value, Some(_)) => return Err(bad_value(line, "max")),
        (GaugeRole::Value, None) => {
            return Err(ParseError::new(line, ParseKind::MissingKey("max")));
        }
    };
    if role == GaugeRole::Playing && gauges.iter().any(|g| g.role == GaugeRole::Playing) {
        return Err(ParseError::new(
            line,
            ParseKind::DuplicateRole("playing".to_string()),
        ));
    }
    Ok(GaugeDecl {
        name: name.to_string(),
        role,
        max,
    })
}

fn parse_sample(
    mut kv: Kv<'_>,
    counters: &[CounterDecl],
    gauges: &[GaugeDecl],
) -> Result<Sample, ParseError> {
    let line = kv.line();
    let mono = kv.req_u64("mono_ns")?;
    let wall =
        match kv.take("wall_ns") {
            None => None,
            Some(v) => Some(parse_i64(v).ok_or_else(|| {
                ParseError::new(line, ParseKind::BadInteger("wall_ns".to_string()))
            })?),
        };
    let dev = kv.opt_u64("dev_frames")?;
    let mut values = BTreeMap::new();
    for (k, v) in kv.take_rest() {
        let declared = counters.iter().any(|c| c.name == k) || gauges.iter().any(|g| g.name == k);
        if !declared {
            return Err(ParseError::new(
                line,
                ParseKind::UndeclaredSeries(bounded(k)),
            ));
        }
        let n =
            parse_u64(v).ok_or_else(|| ParseError::new(line, ParseKind::BadInteger(bounded(k))))?;
        values.insert(k.to_string(), n);
    }
    Ok(Sample {
        line,
        mono: MonoNs(mono),
        wall: wall.map(WallNs),
        dev: dev.map(DeviceFrames),
        values,
    })
}

impl Capture {
    pub fn parse(text: &str) -> Result<Capture, ParseError> {
        let mut header_seen = false;
        let mut meta: Option<Meta> = None;
        let mut counters: Vec<CounterDecl> = Vec::new();
        let mut gauges: Vec<GaugeDecl> = Vec::new();
        let mut samples: Vec<Sample> = Vec::new();

        for (idx, raw) in text.lines().enumerate() {
            let no = idx + 1;
            if raw.len() > MAX_LINE_BYTES {
                return Err(ParseError::new(no, ParseKind::LineTooLong));
            }
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if !header_seen {
                if line == HEADER {
                    header_seen = true;
                    continue;
                }
                return Err(ParseError::new(no, ParseKind::BadHeader));
            }
            let mut tokens = line.split_whitespace();
            let tag = tokens.next().unwrap_or("");
            let kv = Kv::new(no, tokens)?;
            match tag {
                "meta" => {
                    if meta.is_some() {
                        return Err(ParseError::new(no, ParseKind::DuplicateMeta));
                    }
                    meta = Some(parse_meta(kv)?);
                }
                "counter" | "gauge" | "sample" => {
                    if meta.is_none() {
                        return Err(ParseError::new(no, ParseKind::MissingMeta));
                    }
                    match tag {
                        "counter" | "gauge" => {
                            if !samples.is_empty() {
                                return Err(ParseError::new(no, ParseKind::DeclAfterSample));
                            }
                            if tag == "counter" {
                                let decl = parse_counter(kv, &counters, &gauges)?;
                                counters.push(decl);
                            } else {
                                let decl = parse_gauge(kv, &counters, &gauges)?;
                                gauges.push(decl);
                            }
                        }
                        _ => {
                            if samples.len() >= MAX_SAMPLES {
                                return Err(ParseError::new(no, ParseKind::TooManySamples));
                            }
                            samples.push(parse_sample(kv, &counters, &gauges)?);
                        }
                    }
                }
                other => {
                    return Err(ParseError::new(no, ParseKind::UnknownTag(bounded(other))));
                }
            }
        }
        if !header_seen {
            return Err(ParseError::new(0, ParseKind::EmptyInput));
        }
        let Some(meta) = meta else {
            return Err(ParseError::new(0, ParseKind::MissingMeta));
        };
        if samples.is_empty() {
            return Err(ParseError::new(0, ParseKind::NoSamples));
        }
        Ok(Capture {
            meta,
            counters,
            gauges,
            samples,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const META: &str = "meta evidence=synthetic profile=t.v1 cadence_ms=1000 declared_ms=10000\n";

    fn doc(body: &str) -> String {
        format!("{HEADER}\n{META}{body}")
    }

    fn err(text: &str) -> ParseError {
        Capture::parse(text).expect_err("must fail")
    }

    #[test]
    fn a_minimal_capture_parses_with_documented_defaults() {
        let c = Capture::parse(&doc("sample mono_ns=5\n")).expect("parse");
        let m = &c.meta;
        assert_eq!(m.evidence, Evidence::Synthetic);
        assert_eq!(m.profile, "t.v1");
        assert_eq!(
            (m.cadence_ns, m.declared_ns),
            (1_000_000_000, 10_000_000_000)
        );
        assert_eq!(m.hole_factor_pct, 150);
        assert_eq!((m.playout_ns, m.wall_step_ns), (0, 1_000_000_000));
        assert_eq!((m.spike_factor, m.device_width), (8, 64));
        assert_eq!(m.device_rate_hz, None);
        assert_eq!((m.min_coverage_ppm, m.max_dropout_intervals), (None, None));
        assert_eq!(c.samples.len(), 1);
        assert_eq!(c.samples[0].mono, MonoNs(5));
        assert_eq!(c.samples[0].wall, None);
        assert_eq!(c.samples[0].line, 3);
    }

    #[test]
    fn declarations_and_samples_round_trip() {
        let body = "# a comment\n\
counter name=xruns role=dev_underruns width=32 max_rate_per_s=1000\n\
counter name=misc role=other width=64\n\
gauge name=playing role=playing\n\
gauge name=lat_us role=value max=500000\n\
sample mono_ns=100 wall_ns=-7 dev_frames=48000 xruns=3 playing=1 lat_us=250\n\
sample mono_ns=200 xruns=4\n";
        let c = Capture::parse(&doc(body)).expect("parse");
        assert_eq!(c.counters.len(), 2);
        assert_eq!(c.counters[0].role, CounterRole::DevUnderruns);
        assert_eq!(
            (c.counters[0].width, c.counters[0].max_rate_per_s),
            (32, 1000)
        );
        assert_eq!((c.counters[1].width, c.counters[1].max_rate_per_s), (64, 0));
        assert_eq!(c.gauges[0].role, GaugeRole::Playing);
        assert_eq!(c.gauges[0].max, 1);
        assert_eq!(c.gauges[1].max, 500_000);
        let s0 = &c.samples[0];
        assert_eq!(s0.wall, Some(WallNs(-7)));
        assert_eq!(s0.dev, Some(DeviceFrames(48_000)));
        assert_eq!(s0.values.get("xruns"), Some(&3));
        assert_eq!(s0.values.get("lat_us"), Some(&250));
        // The second sample simply lacks the other series: missing, not zero.
        let s1 = &c.samples[1];
        assert_eq!(s1.values.get("playing"), None);
        assert_eq!(s1.values.get("xruns"), Some(&4));
    }

    #[test]
    fn structural_errors_are_typed() {
        assert_eq!(err("").kind, ParseKind::EmptyInput);
        assert_eq!(err("meta evidence=synthetic\n").kind, ParseKind::BadHeader);
        assert_eq!(err(&format!("{HEADER}\n")).kind, ParseKind::MissingMeta);
        assert_eq!(err(&doc("")).kind, ParseKind::NoSamples);
        assert_eq!(
            err(&format!("{HEADER}\nsample mono_ns=1\n")),
            ParseError::new(2, ParseKind::MissingMeta)
        );
        assert_eq!(
            err(&doc(&format!("{META}sample mono_ns=1\n"))),
            ParseError::new(3, ParseKind::DuplicateMeta)
        );
        assert_eq!(
            err(&doc(
                "sample mono_ns=1\ncounter name=c role=other width=32\n"
            )),
            ParseError::new(4, ParseKind::DeclAfterSample)
        );
        assert_eq!(
            err(&doc("frobnicate x=1\n")),
            ParseError::new(3, ParseKind::UnknownTag("frobnicate".to_string()))
        );
    }

    #[test]
    fn declaration_errors_are_typed() {
        let c = "counter name=a role=late_packets width=32\n";
        assert_eq!(
            err(&doc(&format!("{c}counter name=a role=other width=32\n"))).kind,
            ParseKind::DuplicateName("a".to_string())
        );
        assert_eq!(
            err(&doc(&format!("{c}gauge name=a role=value max=5\n"))).kind,
            ParseKind::DuplicateName("a".to_string())
        );
        assert_eq!(
            err(&doc(&format!(
                "{c}counter name=b role=late_packets width=32\n"
            )))
            .kind,
            ParseKind::DuplicateRole("late_packets".to_string())
        );
        assert_eq!(
            err(&doc("counter name=mono_ns role=other width=32\n")).kind,
            ParseKind::ReservedName("mono_ns".to_string())
        );
        assert_eq!(
            err(&doc("counter name=1x role=other width=32\n")).kind,
            ParseKind::BadIdentifier("1x".to_string())
        );
        assert_eq!(
            err(&doc("counter name=a role=other width=16\n")).kind,
            ParseKind::BadValue("width".to_string())
        );
        assert_eq!(
            err(&doc("counter name=a role=weird width=32\n")).kind,
            ParseKind::BadValue("role".to_string())
        );
        assert_eq!(
            err(&doc("gauge name=g role=value\n")).kind,
            ParseKind::MissingKey("max")
        );
        assert_eq!(
            err(&doc("gauge name=g role=playing max=2\n")).kind,
            ParseKind::BadValue("max".to_string())
        );
        assert_eq!(
            err(&doc(
                "gauge name=g role=playing\ngauge name=h role=playing\n"
            ))
            .kind,
            ParseKind::DuplicateRole("playing".to_string())
        );
    }

    #[test]
    fn sample_errors_are_typed() {
        assert_eq!(
            err(&doc("sample xruns=1\n")).kind,
            ParseKind::MissingKey("mono_ns")
        );
        assert_eq!(
            err(&doc("sample mono_ns=1 xruns=1\n")).kind,
            ParseKind::UndeclaredSeries("xruns".to_string())
        );
        assert_eq!(
            err(&doc("sample mono_ns=-1\n")).kind,
            ParseKind::BadInteger("mono_ns".to_string())
        );
        assert_eq!(
            err(&doc("sample mono_ns=1 wall_ns=x\n")).kind,
            ParseKind::BadInteger("wall_ns".to_string())
        );
        assert_eq!(
            err(&doc(
                "counter name=c role=other width=32\nsample mono_ns=1 c=1.5\n"
            ))
            .kind,
            ParseKind::BadInteger("c".to_string())
        );
        assert_eq!(
            err(&doc("sample mono_ns=1 mono_ns=2\n")).kind,
            ParseKind::DuplicateKey("mono_ns".to_string())
        );
    }

    #[test]
    fn meta_errors_are_typed() {
        let with = |meta: &str| format!("{HEADER}\n{meta}\nsample mono_ns=1\n");
        let base = "meta evidence=synthetic profile=p cadence_ms=1000 declared_ms=10000";
        assert_eq!(
            err(&with("meta evidence=synthetic profile=p cadence_ms=1000")).kind,
            ParseKind::MissingKey("declared_ms")
        );
        assert_eq!(
            err(&with(&format!("{base} colour=red"))).kind,
            ParseKind::UnknownKey("colour".to_string())
        );
        for (extra, key) in [
            ("hole_factor_pct=99", "hole_factor_pct"),
            ("spike_factor=1", "spike_factor"),
            ("device_rate_hz=0", "device_rate_hz"),
            ("device_stall_frames=0", "device_stall_frames"),
            ("device_width=16", "device_width"),
            ("min_coverage_ppm=1000001", "min_coverage_ppm"),
        ] {
            assert_eq!(
                err(&with(&format!("{base} {extra}"))).kind,
                ParseKind::BadValue(key.to_string()),
                "{extra}"
            );
        }
        assert_eq!(
            err(&with(
                "meta evidence=synthetic profile=p cadence_ms=0 declared_ms=10"
            ))
            .kind,
            ParseKind::BadValue("cadence_ms".to_string())
        );
        // Declared duration shorter than one cadence step.
        assert_eq!(
            err(&with(
                "meta evidence=synthetic profile=p cadence_ms=1000 declared_ms=999"
            ))
            .kind,
            ParseKind::BadValue("declared_ms".to_string())
        );
        assert_eq!(
            err(&with(
                "meta evidence=imaginary profile=p cadence_ms=1 declared_ms=1"
            ))
            .kind,
            ParseKind::BadValue("evidence".to_string())
        );
        // Milliseconds that overflow when converted to nanoseconds.
        assert_eq!(
            err(&with(
                "meta evidence=synthetic profile=p cadence_ms=1 declared_ms=18446744073709551615"
            ))
            .kind,
            ParseKind::BadValue("declared_ms".to_string())
        );
    }

    #[test]
    fn oversized_lines_are_refused() {
        let long = format!("{HEADER}\n# {}\n", "x".repeat(MAX_LINE_BYTES + 1));
        assert_eq!(err(&long), ParseError::new(2, ParseKind::LineTooLong));
    }
}
