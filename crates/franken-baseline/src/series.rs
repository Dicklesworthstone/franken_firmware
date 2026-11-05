//! The time-series analyzer: capture in, typed report out. All integer arithmetic.
//!
//! The rules, in the order they are applied.
//!
//! 1. Admission. A sample whose monotonic time does not exceed the previous accepted sample's is
//!    rejected and counted; samples are never re-ordered.
//! 2. Intervals and holes. An interval between consecutive accepted samples is a coverage hole when
//!    `dt * 100 > cadence * hole_factor_pct`. Nothing inside a hole is interpolated: the report says
//!    where it is, how long, and how many samples it swallowed.
//! 3. Counters. Per counter, over the samples that carry it: a rise is a plain delta; a fall is a
//!    32-bit wraparound only if the wrapped delta is no more than `max_rate_per_s * dt` can produce,
//!    otherwise a reset. A reset has no rate (the counter's value after it is only a lower bound on
//!    events since). A span that is a hole or a reset is censored: its events are reported as
//!    `unlocated_events_min` and kept out of every rate and out of the per-interval evidence.
//! 4. Clock domains. Intervals, holes and rates use only the monotonic clock. The wall clock is compared
//!    with the monotonic span of the same interval to report steps; the device sample clock is compared
//!    with it to report drift and, if a stall threshold was declared, stalls.
//! 5. Dropouts. A dropout interval is an uncensored interval in which the device-underrun counter rose
//!    or the device clock fell short by at least the declared stall. With neither signal in the capture
//!    the dropout count is `unknown`, never zero.
//! 6. Causes. For each dropout interval, the window is the interval plus every earlier interval ending
//!    within `playout` of its start (the interval just before it always qualifies). A candidate cause
//!    (source outage, network lateness, CPU deadline miss) is judged only from its own signal, and only
//!    if that signal is complete over the whole window. Exactly one present cause is `determined`, with
//!    the candidates that could not be observed listed as unexcluded; two or more is `ambiguous`; none
//!    present and every candidate observed and quiet is `output_underrun` (only for a counted
//!    underrun); anything else is `undetermined`, naming the missing signals. No cause is ever guessed.
//! 7. Absolute verdict. Only against thresholds the capture declared before the run.

use crate::capture::{
    Capture, CounterDecl, CounterRole, Evidence, GaugeDecl, GaugeRole, Meta, Sample,
};
use crate::clock::{DeviceFrames, MonoNs, MonoSpanNs};
use crate::compare::AbsoluteSummary;
use crate::finding::{FindingKind, Findings};
use crate::json::Json;

/// Nanoseconds per hour times 1000, so `events * this / ns` is events per hour times 1000.
const NS_PER_HOUR_X1000: u128 = 3_600_000_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaKind {
    Plain,
    Wrap,
    Reset,
}

/// `events` is the count over the span for `Plain` and `Wrap`, and for `Reset` the counter's value after
/// the reset, which is only a lower bound on the events since it restarted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delta {
    pub kind: DeltaKind,
    pub events: u64,
}

/// Classify a counter going from `prev` to `cur` over `dt` of monotonic time. A decrease is never a
/// negative count: it is a wraparound (only for a 32-bit counter whose wrapped delta is physically
/// possible at `max_rate_per_s`) or else a reset.
pub fn classify_delta(
    prev: u64,
    cur: u64,
    width_bits: u8,
    max_rate_per_s: u64,
    dt: MonoSpanNs,
) -> Delta {
    if cur >= prev {
        return Delta {
            kind: DeltaKind::Plain,
            events: cur - prev,
        };
    }
    if width_bits == 32 && max_rate_per_s > 0 {
        let wrapped = (1u128 << 32) + u128::from(cur) - u128::from(prev);
        let ceiling = u128::from(max_rate_per_s) * u128::from(dt.0);
        if wrapped * 1_000_000_000 <= ceiling {
            return Delta {
                kind: DeltaKind::Wrap,
                events: u64::try_from(wrapped).unwrap_or(u64::MAX),
            };
        }
    }
    Delta {
        kind: DeltaKind::Reset,
        events: cur,
    }
}

/// An interval is a coverage hole when it is longer than `pct` percent of the nominal cadence.
pub fn is_hole(dt: MonoSpanNs, cadence_ns: u64, pct: u64) -> bool {
    u128::from(dt.0) * 100 > u128::from(cadence_ns) * u128::from(pct)
}

/// Samples a hole most likely swallowed: the interval in whole cadences, rounded to nearest, minus the
/// one sample that ends it.
pub fn missing_samples_est(dt: MonoSpanNs, cadence_ns: u64) -> u64 {
    let rounded = (u128::from(dt.0) + u128::from(cadence_ns) / 2) / u128::from(cadence_ns);
    u64::try_from(rounded.saturating_sub(1)).unwrap_or(u64::MAX)
}

/// Nearest-rank percentile `num/den` of an ascending, non-empty slice: the value at 1-based rank
/// `ceil(num * n / den)`.
pub fn nearest_rank(sorted: &[u64], num: u64, den: u64) -> u64 {
    let n = sorted.len() as u128;
    let rank = (u128::from(num) * n).div_ceil(u128::from(den)).max(1);
    let idx = usize::try_from(rank - 1).unwrap_or(0).min(sorted.len() - 1);
    sorted[idx]
}

// ------------------------------------------------------------------------------------------------
// Report types

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    DevUnderruns,
    DeviceClock,
    SourceBytes,
    PlayingState,
    LatePackets,
    CpuMisses,
}

impl Signal {
    pub fn as_str(self) -> &'static str {
        match self {
            Signal::DevUnderruns => "dev_underruns",
            Signal::DeviceClock => "device_clock",
            Signal::SourceBytes => "source_bytes",
            Signal::PlayingState => "playing_state",
            Signal::LatePackets => "late_packets",
            Signal::CpuMisses => "cpu_misses",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The capture does not declare, or never samples, the signal.
    NotCarried,
    /// The signal is carried but has a gap or reset somewhere in the dropout's window.
    IncompleteInWindow,
}

impl Why {
    pub fn as_str(self) -> &'static str {
        match self {
            Why::NotCarried => "not_carried",
            Why::IncompleteInWindow => "incomplete_in_window",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingSignal {
    pub signal: Signal,
    pub why: Why,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CauseClass {
    SourceOutage,
    NetworkLateness,
    CpuDeadlineMiss,
}

impl CauseClass {
    pub fn as_str(self) -> &'static str {
        match self {
            CauseClass::SourceOutage => "source_outage",
            CauseClass::NetworkLateness => "network_lateness",
            CauseClass::CpuDeadlineMiss => "cpu_deadline_miss",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cause {
    /// Exactly one candidate's signal fired; `unexcluded` are candidates that could not be observed.
    Determined {
        cause: CauseClass,
        unexcluded: Vec<MissingSignal>,
    },
    /// Two or more candidates fired; the capture cannot say which one mattered.
    Ambiguous { present: Vec<CauseClass> },
    /// A counted device underrun with every upstream candidate observed and quiet.
    OutputUnderrun,
    /// No candidate fired and at least one could not be observed.
    Undetermined { missing: Vec<MissingSignal> },
}

impl Cause {
    pub fn class_str(&self) -> &'static str {
        match self {
            Cause::Determined { cause, .. } => cause.as_str(),
            Cause::Ambiguous { .. } => "ambiguous",
            Cause::OutputUnderrun => "output_underrun",
            Cause::Undetermined { .. } => "undetermined",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dropout {
    pub from: MonoNs,
    pub to: MonoNs,
    pub underrun_events: u64,
    pub stall_deficit_frames: Option<u64>,
    pub cause: Cause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CensorReason {
    Hole,
    Reset,
}

/// Events of the dropout counter inside a span the capture cannot locate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CensoredDropout {
    pub from: MonoNs,
    pub to: MonoNs,
    pub events_min: u64,
    pub reason: CensorReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropoutReport {
    /// False when the capture carries no signal that could show a dropout: then there is no count.
    pub known: bool,
    pub missing: Vec<Signal>,
    pub observed: Vec<Dropout>,
    pub censored: Vec<CensoredDropout>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hole {
    pub from: MonoNs,
    pub to: MonoNs,
    pub dt: MonoSpanNs,
    pub missing_samples_est: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WallStepRec {
    pub at: MonoNs,
    pub delta_ns: i128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WallReport {
    pub carried: bool,
    pub steps: Vec<WallStepRec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceReport {
    pub carried: bool,
    pub rate_hz: Option<u64>,
    pub expected_frames: u64,
    pub observed_frames: u64,
    /// `(observed - expected) / expected` in parts per million, truncated toward zero.
    pub drift_ppm: Option<i128>,
    pub resets: u64,
    pub wraps: u64,
    pub stall_intervals: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterReport {
    pub name: String,
    pub role: CounterRole,
    pub width: u8,
    pub points: usize,
    pub missing_values: usize,
    pub observed_events: u64,
    pub observed_ns: u64,
    /// Events per hour times 1000 over the uncensored time; `None` with no uncensored time.
    pub per_hour_milli: Option<u128>,
    pub censored_spans: u64,
    pub censored_ns: u64,
    pub unlocated_events_min: u64,
    pub resets: u64,
    pub wraps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GaugeStats {
    pub n: usize,
    pub min: u64,
    pub max: u64,
    pub p50: u64,
    pub p99: u64,
    /// Readings above `spike_factor` times the median. They stay in every figure above.
    pub spikes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GaugeReport {
    pub name: String,
    pub role: GaugeRole,
    /// Plausible readings only.
    pub points: usize,
    /// Readings above the declared maximum; excluded from everything else.
    pub implausible: usize,
    pub stats: Option<GaugeStats>,
    pub playing_samples: usize,
    pub idle_samples: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denominators {
    pub declared_ns: u64,
    pub cadence_ns: u64,
    pub expected_samples: u64,
    pub samples_total: usize,
    pub samples_accepted: usize,
    pub samples_rejected_non_monotonic: usize,
    pub intervals_total: usize,
    pub intervals_observed: usize,
    pub intervals_censored: usize,
    pub observed_ns: u64,
    pub censored_ns: u64,
    pub coverage_ppm: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    CoverageBelowMin { have_ppm: u64, min_ppm: u64 },
    DropoutsUnknown,
    DropoutsExceedMax { have: u64, max: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbsoluteVerdict {
    NotAssessed,
    Qualified,
    NotQualified(Vec<Reason>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Absolute {
    pub min_coverage_ppm: Option<u64>,
    pub max_dropout_intervals: Option<u64>,
    pub verdict: AbsoluteVerdict,
}

#[derive(Debug, Clone)]
pub struct SeriesReport {
    pub evidence: Evidence,
    pub profile: String,
    pub denominators: Denominators,
    pub holes: Vec<Hole>,
    /// Nanoseconds of declared capture time after the last sample, when that exceeds one hole threshold.
    pub truncated_missing_ns: Option<u64>,
    pub wall: WallReport,
    pub device: DeviceReport,
    pub counters: Vec<CounterReport>,
    pub gauges: Vec<GaugeReport>,
    pub dropouts: DropoutReport,
    pub findings: Findings,
    pub absolute: Absolute,
}

// ------------------------------------------------------------------------------------------------
// Analysis

struct CounterSpan {
    from: usize,
    to: usize,
    delta: Delta,
    censored: bool,
}

struct CounterAnalysis {
    report: CounterReport,
    role: CounterRole,
    /// Events in the interval ending at accepted sample `i`; `None` unless both ends carry the counter,
    /// the span is that single interval, and it is neither a hole nor a reset.
    by_interval: Vec<Option<u64>>,
    spans: Vec<CounterSpan>,
}

impl CounterAnalysis {
    fn carried(&self) -> bool {
        self.report.points >= 2
    }
}

fn analyze_counter(
    decl: &CounterDecl,
    acc: &[&Sample],
    meta: &Meta,
    findings: &mut Findings,
) -> CounterAnalysis {
    let width_max: u64 = if decl.width == 32 {
        u64::from(u32::MAX)
    } else {
        u64::MAX
    };
    let mut points: Vec<(usize, u64)> = Vec::new();
    for (i, s) in acc.iter().enumerate() {
        if let Some(&v) = s.values.get(&decl.name) {
            if v > width_max {
                findings.push(
                    FindingKind::ValueOutOfWidth,
                    format!("counter={} line={}", decl.name, s.line),
                    &[
                        ("value", i128::from(v)),
                        ("width_bits", i128::from(decl.width)),
                    ],
                );
            } else {
                points.push((i, v));
            }
        }
    }

    let mut report = CounterReport {
        name: decl.name.clone(),
        role: decl.role,
        width: decl.width,
        points: points.len(),
        missing_values: acc.len() - points.len(),
        observed_events: 0,
        observed_ns: 0,
        per_hour_milli: None,
        censored_spans: 0,
        censored_ns: 0,
        unlocated_events_min: 0,
        resets: 0,
        wraps: 0,
    };
    let mut by_interval: Vec<Option<u64>> = vec![None; acc.len()];
    let mut spans: Vec<CounterSpan> = Vec::new();

    for w in points.windows(2) {
        let (i0, v0) = w[0];
        let (i1, v1) = w[1];
        let dt = acc[i1].mono.since(acc[i0].mono).unwrap_or(MonoSpanNs(0));
        let delta = classify_delta(v0, v1, decl.width, decl.max_rate_per_s, dt);
        let censored =
            delta.kind == DeltaKind::Reset || is_hole(dt, meta.cadence_ns, meta.hole_factor_pct);
        match delta.kind {
            DeltaKind::Reset => {
                report.resets += 1;
                findings.push(
                    FindingKind::CounterReset,
                    format!("counter={} line={}", decl.name, acc[i1].line),
                    &[("from", i128::from(v0)), ("to", i128::from(v1))],
                );
            }
            DeltaKind::Wrap => {
                report.wraps += 1;
                findings.push(
                    FindingKind::CounterWrap,
                    format!("counter={} line={}", decl.name, acc[i1].line),
                    &[("from", i128::from(v0)), ("to", i128::from(v1))],
                );
            }
            DeltaKind::Plain => {}
        }
        if censored {
            report.censored_spans += 1;
            report.censored_ns = report.censored_ns.saturating_add(dt.0);
            report.unlocated_events_min = report.unlocated_events_min.saturating_add(delta.events);
        } else {
            report.observed_events = report.observed_events.saturating_add(delta.events);
            report.observed_ns = report.observed_ns.saturating_add(dt.0);
            if i1 == i0 + 1 {
                by_interval[i1] = Some(delta.events);
            }
        }
        spans.push(CounterSpan {
            from: i0,
            to: i1,
            delta,
            censored,
        });
    }
    report.per_hour_milli = if report.observed_ns > 0 {
        Some(
            u128::from(report.observed_events) * NS_PER_HOUR_X1000 / u128::from(report.observed_ns),
        )
    } else {
        None
    };
    CounterAnalysis {
        report,
        role: decl.role,
        by_interval,
        spans,
    }
}

struct GaugeAnalysis {
    report: GaugeReport,
    /// For the playing gauge: the state at each accepted sample; `None` where it is missing.
    playing_at: Vec<Option<bool>>,
}

fn analyze_gauge(
    decl: &GaugeDecl,
    acc: &[&Sample],
    meta: &Meta,
    findings: &mut Findings,
) -> GaugeAnalysis {
    let mut values: Vec<u64> = Vec::new();
    let mut implausible = 0usize;
    let mut playing_at: Vec<Option<bool>> = vec![None; acc.len()];
    for (i, s) in acc.iter().enumerate() {
        let Some(&v) = s.values.get(&decl.name) else {
            continue;
        };
        if v > decl.max {
            implausible += 1;
            findings.push(
                FindingKind::ImplausibleValue,
                format!("gauge={} line={}", decl.name, s.line),
                &[("value", i128::from(v)), ("max", i128::from(decl.max))],
            );
            continue;
        }
        values.push(v);
        if decl.role == GaugeRole::Playing {
            playing_at[i] = Some(v == 1);
        }
    }

    let mut report = GaugeReport {
        name: decl.name.clone(),
        role: decl.role,
        points: values.len(),
        implausible,
        stats: None,
        playing_samples: 0,
        idle_samples: 0,
    };
    if decl.role == GaugeRole::Playing {
        report.playing_samples = playing_at.iter().filter(|p| **p == Some(true)).count();
        report.idle_samples = playing_at.iter().filter(|p| **p == Some(false)).count();
    } else if !values.is_empty() {
        let mut sorted = values.clone();
        sorted.sort_unstable();
        let p50 = nearest_rank(&sorted, 50, 100);
        let p99 = nearest_rank(&sorted, 99, 100);
        let spikes = if p50 > 0 {
            sorted
                .iter()
                .filter(|v| u128::from(**v) > u128::from(p50) * u128::from(meta.spike_factor))
                .count()
        } else {
            0
        };
        report.stats = Some(GaugeStats {
            n: sorted.len(),
            min: sorted[0],
            max: sorted[sorted.len() - 1],
            p50,
            p99,
            spikes,
        });
    }
    GaugeAnalysis { report, playing_at }
}

/// Evidence from one counter over a dropout window: `Ok(true)` fired, `Ok(false)` quiet.
fn counter_evidence(
    counter: Option<&CounterAnalysis>,
    window: &[usize],
    signal: Signal,
) -> Result<bool, MissingSignal> {
    let c = match counter {
        Some(c) if c.carried() => c,
        _ => {
            return Err(MissingSignal {
                signal,
                why: Why::NotCarried,
            });
        }
    };
    let mut total: u64 = 0;
    for &e in window {
        match c.by_interval[e] {
            Some(events) => total = total.saturating_add(events),
            None => {
                return Err(MissingSignal {
                    signal,
                    why: Why::IncompleteInWindow,
                });
            }
        }
    }
    Ok(total > 0)
}

/// Source outage: an interval in the window in which no source bytes arrived while playback was on at
/// both ends. Needs the source counter and the playing state, complete over the whole window.
fn source_evidence(
    source: Option<&CounterAnalysis>,
    playing: Option<&Vec<Option<bool>>>,
    window: &[usize],
) -> Result<bool, Vec<MissingSignal>> {
    let mut missing: Vec<MissingSignal> = Vec::new();
    let counter = match source {
        Some(c) if c.carried() => {
            if window.iter().all(|&e| c.by_interval[e].is_some()) {
                Some(c)
            } else {
                missing.push(MissingSignal {
                    signal: Signal::SourceBytes,
                    why: Why::IncompleteInWindow,
                });
                None
            }
        }
        _ => {
            missing.push(MissingSignal {
                signal: Signal::SourceBytes,
                why: Why::NotCarried,
            });
            None
        }
    };
    let state = match playing {
        Some(p) => {
            if window.iter().all(|&e| p[e].is_some() && p[e - 1].is_some()) {
                Some(p)
            } else {
                missing.push(MissingSignal {
                    signal: Signal::PlayingState,
                    why: Why::IncompleteInWindow,
                });
                None
            }
        }
        None => {
            missing.push(MissingSignal {
                signal: Signal::PlayingState,
                why: Why::NotCarried,
            });
            None
        }
    };
    match (counter, state) {
        (Some(c), Some(p)) if missing.is_empty() => {
            let outage = window.iter().any(|&e| {
                c.by_interval[e] == Some(0) && p[e - 1] == Some(true) && p[e] == Some(true)
            });
            Ok(outage)
        }
        _ => Err(missing),
    }
}

/// The window of accepted-sample indices whose intervals count as evidence for the dropout interval
/// ending at `e`: that interval, and every earlier one whose end is within `playout_ns` of its start.
fn cause_window(acc: &[&Sample], e: usize, playout_ns: u64) -> Vec<usize> {
    let start = u128::from(acc[e - 1].mono.0);
    let mut window = vec![e];
    let mut k = e - 1;
    while k >= 1 {
        if u128::from(acc[k].mono.0) + u128::from(playout_ns) >= start {
            window.push(k);
            k -= 1;
        } else {
            break;
        }
    }
    window
}

struct CauseInputs<'a> {
    late: Option<&'a CounterAnalysis>,
    cpu: Option<&'a CounterAnalysis>,
    source: Option<&'a CounterAnalysis>,
    playing: Option<&'a Vec<Option<bool>>>,
}

fn classify_cause(
    inputs: &CauseInputs<'_>,
    acc: &[&Sample],
    e: usize,
    playout_ns: u64,
    underrun_events: u64,
) -> Cause {
    let window = cause_window(acc, e, playout_ns);
    let mut present: Vec<CauseClass> = Vec::new();
    let mut unobserved: Vec<MissingSignal> = Vec::new();

    match source_evidence(inputs.source, inputs.playing, &window) {
        Ok(true) => present.push(CauseClass::SourceOutage),
        Ok(false) => {}
        Err(missing) => unobserved.extend(missing),
    }
    match counter_evidence(inputs.late, &window, Signal::LatePackets) {
        Ok(true) => present.push(CauseClass::NetworkLateness),
        Ok(false) => {}
        Err(m) => unobserved.push(m),
    }
    match counter_evidence(inputs.cpu, &window, Signal::CpuMisses) {
        Ok(true) => present.push(CauseClass::CpuDeadlineMiss),
        Ok(false) => {}
        Err(m) => unobserved.push(m),
    }

    match present.len() {
        0 => {
            if !unobserved.is_empty() {
                Cause::Undetermined {
                    missing: unobserved,
                }
            } else if underrun_events > 0 {
                Cause::OutputUnderrun
            } else {
                // A device stall with no underrun counter cannot be told from a clock fault.
                Cause::Undetermined {
                    missing: vec![MissingSignal {
                        signal: Signal::DevUnderruns,
                        why: Why::NotCarried,
                    }],
                }
            }
        }
        1 => Cause::Determined {
            cause: present[0],
            unexcluded: unobserved,
        },
        _ => Cause::Ambiguous { present },
    }
}

/// Analyze a parsed capture.
pub fn analyze(cap: &Capture) -> SeriesReport {
    let meta = &cap.meta;
    let mut findings = Findings::default();

    // 1. Admission.
    let mut acc: Vec<&Sample> = Vec::with_capacity(cap.samples.len());
    let mut rejected = 0usize;
    for s in &cap.samples {
        if let Some(prev) = acc.last().filter(|p| s.mono <= p.mono) {
            rejected += 1;
            findings.push(
                FindingKind::NonMonotonicClock,
                format!("line={}", s.line),
                &[
                    ("mono_ns", i128::from(s.mono.0)),
                    ("previous_mono_ns", i128::from(prev.mono.0)),
                ],
            );
            continue;
        }
        acc.push(s);
    }
    let n = acc.len();

    // 2. Intervals and holes.
    let mut holes: Vec<Hole> = Vec::new();
    let mut observed_ns: u64 = 0;
    let mut censored_ns: u64 = 0;
    for e in 1..n {
        let dt = acc[e].mono.since(acc[e - 1].mono).unwrap_or(MonoSpanNs(0));
        if is_hole(dt, meta.cadence_ns, meta.hole_factor_pct) {
            censored_ns = censored_ns.saturating_add(dt.0);
            holes.push(Hole {
                from: acc[e - 1].mono,
                to: acc[e].mono,
                dt,
                missing_samples_est: missing_samples_est(dt, meta.cadence_ns),
            });
        } else {
            observed_ns = observed_ns.saturating_add(dt.0);
        }
    }
    let intervals_total = n - 1;
    let intervals_censored = holes.len();

    // Truncation: the capture ends well before the declared duration.
    let first = u128::from(acc[0].mono.0);
    let last = u128::from(acc[n - 1].mono.0);
    let expected_end = first + u128::from(meta.declared_ns);
    let truncated_missing_ns = if expected_end > last {
        let missing = expected_end - last;
        if missing * 100 > u128::from(meta.cadence_ns) * u128::from(meta.hole_factor_pct) {
            Some(u64::try_from(missing).unwrap_or(u64::MAX))
        } else {
            None
        }
    } else {
        None
    };
    let coverage_ppm = u64::try_from(
        (u128::from(observed_ns) * 1_000_000 / u128::from(meta.declared_ns)).min(1_000_000),
    )
    .unwrap_or(1_000_000);

    // 3. Counters and gauges.
    let counters: Vec<CounterAnalysis> = cap
        .counters
        .iter()
        .map(|d| analyze_counter(d, &acc, meta, &mut findings))
        .collect();
    let gauges: Vec<GaugeAnalysis> = cap
        .gauges
        .iter()
        .map(|d| analyze_gauge(d, &acc, meta, &mut findings))
        .collect();
    let by_role = |role: CounterRole| counters.iter().find(|c| c.role == role);
    let underrun = by_role(CounterRole::DevUnderruns);
    let playing = gauges
        .iter()
        .find(|g| g.report.role == GaugeRole::Playing && g.report.points > 0)
        .map(|g| &g.playing_at);

    // 4. Clock domains: wall steps, then the device clock.
    let mut wall = WallReport {
        carried: acc.iter().any(|s| s.wall.is_some()),
        steps: Vec::new(),
    };
    for e in 1..n {
        if let (Some(w1), Some(w0)) = (acc[e].wall, acc[e - 1].wall) {
            let dt = acc[e].mono.since(acc[e - 1].mono).unwrap_or(MonoSpanNs(0));
            let step = w1.step_from(w0, dt);
            if step.unsigned_abs() > u128::from(meta.wall_step_ns) {
                wall.steps.push(WallStepRec {
                    at: acc[e].mono,
                    delta_ns: step,
                });
                findings.push(
                    FindingKind::WallStep,
                    format!("line={}", acc[e].line),
                    &[("delta_ns", step)],
                );
            }
        }
    }

    let dev_points: Vec<(usize, u64)> = acc
        .iter()
        .enumerate()
        .filter_map(|(i, s)| s.dev.map(|d| (i, d.0)))
        .collect();
    let mut device = DeviceReport {
        carried: false,
        rate_hz: meta.device_rate_hz,
        expected_frames: 0,
        observed_frames: 0,
        drift_ppm: None,
        resets: 0,
        wraps: 0,
        stall_intervals: 0,
    };
    let mut stall_at: Vec<Option<u64>> = vec![None; n];
    match meta.device_rate_hz {
        Some(rate) if dev_points.len() >= 2 => {
            device.carried = true;
            for w in dev_points.windows(2) {
                let (i0, v0) = w[0];
                let (i1, v1) = w[1];
                let dt = acc[i1].mono.since(acc[i0].mono).unwrap_or(MonoSpanNs(0));
                let delta = classify_delta(v0, v1, meta.device_width, rate.saturating_mul(2), dt);
                match delta.kind {
                    DeltaKind::Reset => {
                        device.resets += 1;
                        findings.push(
                            FindingKind::DeviceClockReset,
                            format!("line={}", acc[i1].line),
                            &[("from", i128::from(v0)), ("to", i128::from(v1))],
                        );
                        continue;
                    }
                    DeltaKind::Wrap => device.wraps += 1,
                    DeltaKind::Plain => {}
                }
                if is_hole(dt, meta.cadence_ns, meta.hole_factor_pct) {
                    continue;
                }
                let expected = DeviceFrames::expected_over(rate, dt);
                let actual = delta.events;
                device.expected_frames = device.expected_frames.saturating_add(expected);
                device.observed_frames = device.observed_frames.saturating_add(actual);
                let stalled = meta.device_stall_frames.filter(|&threshold| {
                    i1 == i0 + 1 && expected >= actual && expected - actual >= threshold
                });
                if stalled.is_some() {
                    stall_at[i1] = Some(expected - actual);
                    device.stall_intervals += 1;
                }
            }
            if device.expected_frames > 0 {
                let diff = i128::from(device.observed_frames) - i128::from(device.expected_frames);
                device.drift_ppm = Some(diff * 1_000_000 / i128::from(device.expected_frames));
            }
        }
        Some(_) => {}
        None => {
            if !dev_points.is_empty() {
                findings.push(
                    FindingKind::DeviceRateMissing,
                    "device_clock".to_string(),
                    &[(
                        "points",
                        i128::try_from(dev_points.len()).unwrap_or(i128::MAX),
                    )],
                );
            }
        }
    }

    // 5. Dropouts.
    let carried_underrun = underrun.is_some_and(CounterAnalysis::carried);
    let carried_stall = meta.device_stall_frames.is_some() && device.carried;
    let known = carried_underrun || carried_stall;
    let mut observed: Vec<Dropout> = Vec::new();
    let mut censored: Vec<CensoredDropout> = Vec::new();
    if known {
        let inputs = CauseInputs {
            late: by_role(CounterRole::LatePackets),
            cpu: by_role(CounterRole::CpuMisses),
            source: by_role(CounterRole::SourceBytes),
            playing,
        };
        for e in 1..n {
            let events = if carried_underrun {
                underrun.and_then(|c| c.by_interval[e]).unwrap_or(0)
            } else {
                0
            };
            let stall = stall_at[e];
            if events > 0 || stall.is_some() {
                observed.push(Dropout {
                    from: acc[e - 1].mono,
                    to: acc[e].mono,
                    underrun_events: events,
                    stall_deficit_frames: stall,
                    cause: classify_cause(&inputs, &acc, e, meta.playout_ns, events),
                });
            }
        }
        if let Some(c) = underrun.filter(|c| c.carried()) {
            for span in c.spans.iter().filter(|s| s.censored && s.delta.events > 0) {
                censored.push(CensoredDropout {
                    from: acc[span.from].mono,
                    to: acc[span.to].mono,
                    events_min: span.delta.events,
                    reason: if span.delta.kind == DeltaKind::Reset {
                        CensorReason::Reset
                    } else {
                        CensorReason::Hole
                    },
                });
            }
        }
    }
    let missing = if known {
        Vec::new()
    } else {
        vec![Signal::DevUnderruns, Signal::DeviceClock]
    };
    let dropouts = DropoutReport {
        known,
        missing,
        observed,
        censored,
    };

    // 6. Absolute verdict, against thresholds declared in the capture.
    let mut reasons: Vec<Reason> = Vec::new();
    if let Some(min) = meta.min_coverage_ppm.filter(|&m| coverage_ppm < m) {
        reasons.push(Reason::CoverageBelowMin {
            have_ppm: coverage_ppm,
            min_ppm: min,
        });
    }
    if let Some(max) = meta.max_dropout_intervals {
        if dropouts.known {
            let have = (dropouts.observed.len() + dropouts.censored.len()) as u64;
            if have > max {
                reasons.push(Reason::DropoutsExceedMax { have, max });
            }
        } else {
            reasons.push(Reason::DropoutsUnknown);
        }
    }
    let assessed = meta.min_coverage_ppm.is_some() || meta.max_dropout_intervals.is_some();
    let verdict = if !assessed {
        AbsoluteVerdict::NotAssessed
    } else if reasons.is_empty() {
        AbsoluteVerdict::Qualified
    } else {
        AbsoluteVerdict::NotQualified(reasons)
    };

    let denominators = Denominators {
        declared_ns: meta.declared_ns,
        cadence_ns: meta.cadence_ns,
        expected_samples: meta.declared_ns / meta.cadence_ns + 1,
        samples_total: cap.samples.len(),
        samples_accepted: n,
        samples_rejected_non_monotonic: rejected,
        intervals_total,
        intervals_observed: intervals_total - intervals_censored,
        intervals_censored,
        observed_ns,
        censored_ns,
        coverage_ppm,
    };

    SeriesReport {
        evidence: meta.evidence,
        profile: meta.profile.clone(),
        denominators,
        holes,
        truncated_missing_ns,
        wall,
        device,
        counters: counters.into_iter().map(|c| c.report).collect(),
        gauges: gauges.into_iter().map(|g| g.report).collect(),
        dropouts,
        findings,
        absolute: Absolute {
            min_coverage_ppm: meta.min_coverage_ppm,
            max_dropout_intervals: meta.max_dropout_intervals,
            verdict,
        },
    }
}

// ------------------------------------------------------------------------------------------------
// Output

fn signals_json(list: &[MissingSignal]) -> Json {
    Json::Arr(
        list.iter()
            .map(|m| {
                Json::obj(vec![
                    ("signal", Json::str(m.signal.as_str())),
                    ("why", Json::str(m.why.as_str())),
                ])
            })
            .collect(),
    )
}

fn cause_json(cause: &Cause) -> Json {
    let mut fields: Vec<(&str, Json)> = vec![("class", Json::str(cause.class_str()))];
    match cause {
        Cause::Determined { unexcluded, .. } => {
            fields.push(("unexcluded", signals_json(unexcluded)))
        }
        Cause::Ambiguous { present } => fields.push((
            "present",
            Json::Arr(present.iter().map(|p| Json::str(p.as_str())).collect()),
        )),
        Cause::OutputUnderrun => {}
        Cause::Undetermined { missing } => fields.push(("missing", signals_json(missing))),
    }
    Json::obj(fields)
}

impl DropoutReport {
    fn count_class(&self, class: &str) -> usize {
        self.observed
            .iter()
            .filter(|d| d.cause.class_str() == class)
            .count()
    }
}

impl SeriesReport {
    /// The figures a comparison may use. See [`crate::compare`].
    pub fn summary(&self) -> AbsoluteSummary {
        let rate = if self.dropouts.known && self.denominators.observed_ns > 0 {
            Some(
                (self.dropouts.observed.len() as u128) * NS_PER_HOUR_X1000
                    / u128::from(self.denominators.observed_ns),
            )
        } else {
            None
        };
        AbsoluteSummary {
            evidence: self.evidence,
            profile: self.profile.clone(),
            coverage_ppm: self.denominators.coverage_ppm,
            dropout_per_hour_milli: rate,
            censored_dropouts: self.dropouts.censored.len() as u64,
        }
    }

    pub fn to_json(&self) -> Json {
        let d = &self.denominators;
        let denominators = Json::obj(vec![
            ("declared_ns", Json::int(d.declared_ns)),
            ("cadence_ns", Json::int(d.cadence_ns)),
            ("expected_samples", Json::int(d.expected_samples)),
            ("samples_total", Json::usize(d.samples_total)),
            ("samples_accepted", Json::usize(d.samples_accepted)),
            (
                "samples_rejected_non_monotonic",
                Json::usize(d.samples_rejected_non_monotonic),
            ),
            ("intervals_total", Json::usize(d.intervals_total)),
            ("intervals_observed", Json::usize(d.intervals_observed)),
            ("intervals_censored", Json::usize(d.intervals_censored)),
            ("observed_ns", Json::int(d.observed_ns)),
            ("censored_ns", Json::int(d.censored_ns)),
            ("coverage_ppm", Json::int(d.coverage_ppm)),
        ]);
        let holes = Json::Arr(
            self.holes
                .iter()
                .map(|h| {
                    Json::obj(vec![
                        ("from_ns", Json::int(h.from.0)),
                        ("to_ns", Json::int(h.to.0)),
                        ("dt_ns", Json::int(h.dt.0)),
                        ("missing_samples_est", Json::int(h.missing_samples_est)),
                    ])
                })
                .collect(),
        );
        let truncated = match self.truncated_missing_ns {
            Some(m) => Json::obj(vec![("missing_ns", Json::int(m))]),
            None => Json::Null,
        };
        let wall = Json::obj(vec![
            ("carried", Json::Bool(self.wall.carried)),
            (
                "steps",
                Json::Arr(
                    self.wall
                        .steps
                        .iter()
                        .map(|s| {
                            Json::obj(vec![
                                ("at_mono_ns", Json::int(s.at.0)),
                                ("delta_ns", Json::Int(s.delta_ns)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]);
        let dv = &self.device;
        let device = Json::obj(vec![
            ("carried", Json::Bool(dv.carried)),
            ("rate_hz", Json::opt_u64(dv.rate_hz)),
            ("expected_frames", Json::int(dv.expected_frames)),
            ("observed_frames", Json::int(dv.observed_frames)),
            ("drift_ppm", Json::opt_i128(dv.drift_ppm)),
            ("resets", Json::int(dv.resets)),
            ("wraps", Json::int(dv.wraps)),
            ("stall_intervals", Json::int(dv.stall_intervals)),
        ]);
        let counters = Json::Arr(
            self.counters
                .iter()
                .map(|c| {
                    Json::obj(vec![
                        ("name", Json::str(&c.name)),
                        ("role", Json::str(c.role.as_str())),
                        ("width", Json::int(c.width)),
                        ("points", Json::usize(c.points)),
                        ("missing_values", Json::usize(c.missing_values)),
                        ("observed_events", Json::int(c.observed_events)),
                        ("observed_ns", Json::int(c.observed_ns)),
                        (
                            "per_hour_milli",
                            match c.per_hour_milli {
                                Some(v) => Json::Int(i128::try_from(v).unwrap_or(i128::MAX)),
                                None => Json::Null,
                            },
                        ),
                        ("censored_spans", Json::int(c.censored_spans)),
                        ("censored_ns", Json::int(c.censored_ns)),
                        ("unlocated_events_min", Json::int(c.unlocated_events_min)),
                        ("resets", Json::int(c.resets)),
                        ("wraps", Json::int(c.wraps)),
                    ])
                })
                .collect(),
        );
        let gauges = Json::Arr(
            self.gauges
                .iter()
                .map(|g| {
                    let mut fields: Vec<(&str, Json)> = vec![
                        ("name", Json::str(&g.name)),
                        ("role", Json::str(g.role.as_str())),
                        ("points", Json::usize(g.points)),
                        ("implausible", Json::usize(g.implausible)),
                    ];
                    if g.role == GaugeRole::Playing {
                        fields.push(("playing_samples", Json::usize(g.playing_samples)));
                        fields.push(("idle_samples", Json::usize(g.idle_samples)));
                    } else {
                        fields.push((
                            "stats",
                            match &g.stats {
                                Some(s) => Json::obj(vec![
                                    ("n", Json::usize(s.n)),
                                    ("min", Json::int(s.min)),
                                    ("max", Json::int(s.max)),
                                    ("p50", Json::int(s.p50)),
                                    ("p99", Json::int(s.p99)),
                                    ("spikes", Json::usize(s.spikes)),
                                ]),
                                None => Json::Null,
                            },
                        ));
                    }
                    Json::obj(fields)
                })
                .collect(),
        );
        let dr = &self.dropouts;
        let observed = Json::Arr(
            dr.observed
                .iter()
                .map(|o| {
                    Json::obj(vec![
                        ("from_ns", Json::int(o.from.0)),
                        ("to_ns", Json::int(o.to.0)),
                        ("underrun_events", Json::int(o.underrun_events)),
                        (
                            "stall_deficit_frames",
                            Json::opt_u64(o.stall_deficit_frames),
                        ),
                        ("cause", cause_json(&o.cause)),
                    ])
                })
                .collect(),
        );
        let censored = Json::Arr(
            dr.censored
                .iter()
                .map(|c| {
                    Json::obj(vec![
                        ("from_ns", Json::int(c.from.0)),
                        ("to_ns", Json::int(c.to.0)),
                        ("events_min", Json::int(c.events_min)),
                        (
                            "reason",
                            Json::str(match c.reason {
                                CensorReason::Hole => "hole",
                                CensorReason::Reset => "reset",
                            }),
                        ),
                    ])
                })
                .collect(),
        );
        let totals = Json::obj(vec![
            ("intervals", Json::usize(dr.observed.len())),
            (
                "underrun_events",
                Json::int(
                    dr.observed
                        .iter()
                        .fold(0u64, |a, o| a.saturating_add(o.underrun_events)),
                ),
            ),
            (
                "source_outage",
                Json::usize(dr.count_class("source_outage")),
            ),
            (
                "network_lateness",
                Json::usize(dr.count_class("network_lateness")),
            ),
            (
                "cpu_deadline_miss",
                Json::usize(dr.count_class("cpu_deadline_miss")),
            ),
            (
                "output_underrun",
                Json::usize(dr.count_class("output_underrun")),
            ),
            ("ambiguous", Json::usize(dr.count_class("ambiguous"))),
            ("undetermined", Json::usize(dr.count_class("undetermined"))),
            ("censored_spans", Json::usize(dr.censored.len())),
            (
                "censored_events_min",
                Json::int(
                    dr.censored
                        .iter()
                        .fold(0u64, |a, c| a.saturating_add(c.events_min)),
                ),
            ),
        ]);
        let dropouts = Json::obj(vec![
            ("known", Json::Bool(dr.known)),
            (
                "missing",
                Json::Arr(dr.missing.iter().map(|s| Json::str(s.as_str())).collect()),
            ),
            ("observed", observed),
            ("censored", censored),
            ("totals", totals),
        ]);
        let (verdict, reasons) = match &self.absolute.verdict {
            AbsoluteVerdict::NotAssessed => ("not_assessed", Vec::new()),
            AbsoluteVerdict::Qualified => ("qualified", Vec::new()),
            AbsoluteVerdict::NotQualified(rs) => (
                "not_qualified",
                rs.iter()
                    .map(|r| match r {
                        Reason::CoverageBelowMin { have_ppm, min_ppm } => Json::obj(vec![
                            ("kind", Json::str("coverage_below_min")),
                            ("have_ppm", Json::int(*have_ppm)),
                            ("min_ppm", Json::int(*min_ppm)),
                        ]),
                        Reason::DropoutsUnknown => {
                            Json::obj(vec![("kind", Json::str("dropouts_unknown"))])
                        }
                        Reason::DropoutsExceedMax { have, max } => Json::obj(vec![
                            ("kind", Json::str("dropouts_exceed_max")),
                            ("have", Json::int(*have)),
                            ("max", Json::int(*max)),
                        ]),
                    })
                    .collect(),
            ),
        };
        let absolute = Json::obj(vec![
            (
                "thresholds",
                Json::obj(vec![
                    (
                        "min_coverage_ppm",
                        Json::opt_u64(self.absolute.min_coverage_ppm),
                    ),
                    (
                        "max_dropout_intervals",
                        Json::opt_u64(self.absolute.max_dropout_intervals),
                    ),
                ]),
            ),
            ("verdict", Json::str(verdict)),
            ("reasons", Json::Arr(reasons)),
        ]);

        Json::obj(vec![
            ("schema", Json::str("ffw.baseline.series-report.v1")),
            ("evidence", Json::str(self.evidence.as_str())),
            ("profile", Json::str(&self.profile)),
            (
                "measured_on_device",
                Json::Bool(self.evidence == Evidence::Physical),
            ),
            ("denominators", denominators),
            ("holes", holes),
            ("truncated", truncated),
            ("wall_clock", wall),
            ("device_clock", device),
            ("counters", counters),
            ("gauges", gauges),
            ("dropouts", dropouts),
            (
                "findings",
                Json::Arr(self.findings.items().iter().map(|f| f.to_json()).collect()),
            ),
            ("findings_dropped", Json::int(self.findings.dropped())),
            ("absolute", absolute),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dt(ns: u64) -> MonoSpanNs {
        MonoSpanNs(ns)
    }

    const SEC: u64 = 1_000_000_000;

    #[test]
    fn plain_deltas_and_the_two_ways_a_counter_can_fall() {
        let one_s = dt(SEC);
        assert_eq!(
            classify_delta(10, 25, 32, 100, one_s),
            Delta {
                kind: DeltaKind::Plain,
                events: 15
            }
        );
        assert_eq!(
            classify_delta(7, 7, 64, 0, one_s),
            Delta {
                kind: DeltaKind::Plain,
                events: 0
            }
        );
        // 4294967290 -> 5 in one second, 100/s possible: wrapped delta = 5 + 2^32 - 4294967290 = 11.
        assert_eq!(
            classify_delta(4_294_967_290, 5, 32, 100, one_s),
            Delta {
                kind: DeltaKind::Wrap,
                events: 11
            }
        );
        // The boundary: 11 events need 11/s; 11/s allows exactly 11 in one second, 10/s does not.
        assert_eq!(
            classify_delta(4_294_967_290, 5, 32, 11, one_s).kind,
            DeltaKind::Wrap
        );
        assert_eq!(
            classify_delta(4_294_967_290, 5, 32, 10, one_s).kind,
            DeltaKind::Reset
        );
        // 1000 -> 3: the wrapped delta would be 4294966299, impossible at 100/s, so a reset whose
        // events-since-restart lower bound is the new value.
        assert_eq!(
            classify_delta(1000, 3, 32, 100, one_s),
            Delta {
                kind: DeltaKind::Reset,
                events: 3
            }
        );
        // No declared rate: a fall can only be a reset, however close to the top the old value was.
        assert_eq!(
            classify_delta(4_294_967_290, 5, 32, 0, one_s).kind,
            DeltaKind::Reset
        );
        // A 64-bit counter does not wrap in practice: a fall is a reset.
        assert_eq!(
            classify_delta(4_294_967_290, 5, 64, 1_000_000, one_s).kind,
            DeltaKind::Reset
        );
        // A longer interval makes the same wrap plausible at a lower rate: 11 events in 2 s needs 6/s.
        assert_eq!(
            classify_delta(4_294_967_290, 5, 32, 6, dt(2 * SEC)).kind,
            DeltaKind::Wrap
        );
        assert_eq!(
            classify_delta(4_294_967_290, 5, 32, 5, dt(2 * SEC)).kind,
            DeltaKind::Reset
        );
    }

    #[test]
    fn holes_use_a_strict_threshold_and_estimate_missing_samples() {
        // cadence 1 s, 150%: 1.5 s is not a hole, 1.5 s + 1 ns is.
        assert!(!is_hole(dt(1_500_000_000), SEC, 150));
        assert!(is_hole(dt(1_500_000_001), SEC, 150));
        assert!(!is_hole(dt(SEC), SEC, 150));
        // 4 s between samples at a 1 s cadence swallowed 3 samples.
        assert_eq!(missing_samples_est(dt(4 * SEC), SEC), 3);
        // 1.9 s rounds to 2 cadences: 1 swallowed. 1.4 s rounds to 1: none.
        assert_eq!(missing_samples_est(dt(1_900_000_000), SEC), 1);
        assert_eq!(missing_samples_est(dt(1_400_000_000), SEC), 0);
        assert_eq!(missing_samples_est(dt(0), SEC), 0);
    }

    #[test]
    fn nearest_rank_percentiles() {
        let v = [10, 20, 30, 40, 50];
        // p50: rank ceil(0.5 * 5) = 3 -> 30. p99: rank ceil(0.99 * 5) = 5 -> 50.
        assert_eq!(nearest_rank(&v, 50, 100), 30);
        assert_eq!(nearest_rank(&v, 99, 100), 50);
        assert_eq!(nearest_rank(&[7], 50, 100), 7);
        assert_eq!(nearest_rank(&[7], 99, 100), 7);
        // Four values: p50 rank 2, p99 rank ceil(3.96) = 4.
        let w = [1, 2, 3, 4];
        assert_eq!(nearest_rank(&w, 50, 100), 2);
        assert_eq!(nearest_rank(&w, 99, 100), 4);
        // 100 values 1..=100: p99 is the 99th.
        let h: Vec<u64> = (1..=100).collect();
        assert_eq!(nearest_rank(&h, 99, 100), 99);
        assert_eq!(nearest_rank(&h, 50, 100), 50);
    }

    // -- whole-capture behaviour, hand-computed ------------------------------------------------

    /// A capture with a 1 s cadence over 5 s, first sample at 10 s. `decls` are counter/gauge lines
    /// and `rows` are `sample` lines with `mono_ns` given in seconds-after-10 as `t=`.
    fn capture(meta_extra: &str, decls: &str, rows: &[&str]) -> Capture {
        let mut text = String::from("ffw.baseline.capture.v1\n");
        text.push_str(&format!(
            "meta evidence=synthetic profile=t cadence_ms=1000 declared_ms=5000 {meta_extra}\n"
        ));
        text.push_str(decls);
        for row in rows {
            // `t=3 xruns=1` -> mono_ns = (10 + 3) s
            let (head, rest) = row.split_once(' ').unwrap_or((row, ""));
            let t: u64 = head
                .strip_prefix("t=")
                .and_then(|p| p.parse().ok())
                .expect("row starts with t=<seconds>");
            text.push_str(&format!("sample mono_ns={} {rest}\n", (10 + t) * SEC));
        }
        Capture::parse(&text).expect("test capture parses")
    }

    const XRUN: &str = "counter name=xruns role=dev_underruns width=32 max_rate_per_s=1000\n";

    #[test]
    fn clean_capture_has_full_coverage_and_known_zero_dropouts() {
        let c = capture(
            "min_coverage_ppm=1000000 max_dropout_intervals=0",
            XRUN,
            &[
                "t=0 xruns=0",
                "t=1 xruns=0",
                "t=2 xruns=0",
                "t=3 xruns=0",
                "t=4 xruns=0",
                "t=5 xruns=0",
            ],
        );
        let r = analyze(&c);
        let d = &r.denominators;
        assert_eq!(
            (
                d.expected_samples,
                d.samples_accepted,
                d.samples_rejected_non_monotonic
            ),
            (6, 6, 0)
        );
        assert_eq!(
            (
                d.intervals_total,
                d.intervals_observed,
                d.intervals_censored
            ),
            (5, 5, 0)
        );
        assert_eq!(
            (d.observed_ns, d.censored_ns, d.coverage_ppm),
            (5 * SEC, 0, 1_000_000)
        );
        assert!(r.holes.is_empty());
        assert_eq!(r.truncated_missing_ns, None);
        assert!(r.dropouts.known);
        assert!(r.dropouts.observed.is_empty());
        assert_eq!(r.counters[0].observed_events, 0);
        assert_eq!(r.counters[0].per_hour_milli, Some(0));
        assert_eq!(r.absolute.verdict, AbsoluteVerdict::Qualified);
        assert!(r.findings.items().is_empty());
    }

    #[test]
    fn an_underrun_interval_is_a_dropout_with_its_exact_span() {
        let c = capture(
            "",
            XRUN,
            &[
                "t=0 xruns=0",
                "t=1 xruns=0",
                "t=2 xruns=3",
                "t=3 xruns=3",
                "t=4 xruns=3",
                "t=5 xruns=4",
            ],
        );
        let r = analyze(&c);
        let o = &r.dropouts.observed;
        assert_eq!(o.len(), 2);
        assert_eq!(
            (o[0].from, o[0].to, o[0].underrun_events),
            (MonoNs(11 * SEC), MonoNs(12 * SEC), 3)
        );
        assert_eq!(
            (o[1].from, o[1].to, o[1].underrun_events),
            (MonoNs(14 * SEC), MonoNs(15 * SEC), 1)
        );
        // 4 events over 5 observed seconds: 4 * 3600 / 5 = 2880 per hour = 2_880_000 milli.
        assert_eq!(r.counters[0].observed_events, 4);
        assert_eq!(r.counters[0].per_hour_milli, Some(2_880_000));
        assert_eq!(r.absolute.verdict, AbsoluteVerdict::NotAssessed);
    }

    #[test]
    fn a_hole_is_reported_never_interpolated_and_its_events_are_unlocated() {
        // Samples at 0,1, then 5 (a 4 s hole), 6. The counter rose 0 -> 3 across the hole.
        let c = capture(
            "min_coverage_ppm=900000",
            XRUN,
            &["t=0 xruns=0", "t=1 xruns=0", "t=5 xruns=3", "t=6 xruns=3"],
        );
        let r = analyze(&c);
        assert_eq!(r.holes.len(), 1);
        let h = r.holes[0];
        assert_eq!(
            (h.from, h.to, h.dt),
            (MonoNs(11 * SEC), MonoNs(15 * SEC), dt(4 * SEC))
        );
        assert_eq!(h.missing_samples_est, 3);
        let d = &r.denominators;
        assert_eq!(
            (
                d.intervals_total,
                d.intervals_observed,
                d.intervals_censored
            ),
            (3, 2, 1)
        );
        assert_eq!((d.observed_ns, d.censored_ns), (2 * SEC, 4 * SEC));
        // 2 s of the declared 5 s were observed: 400000 ppm.
        assert_eq!(d.coverage_ppm, 400_000);
        // No rate from the hole: observed events 0 over 2 s; the 3 events are unlocated.
        let c0 = &r.counters[0];
        assert_eq!((c0.observed_events, c0.observed_ns), (0, 2 * SEC));
        assert_eq!(
            (c0.censored_spans, c0.censored_ns, c0.unlocated_events_min),
            (1, 4 * SEC, 3)
        );
        assert!(r.dropouts.observed.is_empty());
        assert_eq!(
            r.dropouts.censored,
            vec![CensoredDropout {
                from: MonoNs(11 * SEC),
                to: MonoNs(15 * SEC),
                events_min: 3,
                reason: CensorReason::Hole
            }]
        );
        // Not truncated: the last sample is at 16 s and the declared end is 15 s.
        assert_eq!(r.truncated_missing_ns, None);
        // A coverage threshold of 90% is not met.
        assert_eq!(
            r.absolute.verdict,
            AbsoluteVerdict::NotQualified(vec![Reason::CoverageBelowMin {
                have_ppm: 400_000,
                min_ppm: 900_000
            }])
        );
    }

    #[test]
    fn a_truncated_capture_reports_what_is_missing_and_does_not_extrapolate() {
        let c = capture("", XRUN, &["t=0 xruns=0", "t=1 xruns=0", "t=2 xruns=0"]);
        let r = analyze(&c);
        // Declared 5 s, last sample at +2 s: 3 s missing.
        assert_eq!(r.truncated_missing_ns, Some(3 * SEC));
        assert_eq!(r.denominators.observed_ns, 2 * SEC);
        assert_eq!(r.denominators.coverage_ppm, 400_000);
        // Within one hole threshold of the declared end is not truncation.
        let ok = capture(
            "",
            XRUN,
            &[
                "t=0 xruns=0",
                "t=1 xruns=0",
                "t=2 xruns=0",
                "t=3 xruns=0",
                "t=4 xruns=0",
                "t=4 xruns=0",
            ],
        );
        let r2 = analyze(&ok);
        // 4 s observed of 5 declared; the last accepted sample is at +4 s, 1 s short: 1 s*100 <= 1 s*150.
        assert_eq!(r2.truncated_missing_ns, None);
        assert_eq!(r2.denominators.samples_rejected_non_monotonic, 1);
    }

    #[test]
    fn a_counter_reset_is_never_a_negative_rate_and_is_censored() {
        let c = capture(
            "",
            XRUN,
            &[
                "t=0 xruns=500",
                "t=1 xruns=502",
                "t=2 xruns=1",
                "t=3 xruns=3",
                "t=4 xruns=3",
                "t=5 xruns=3",
            ],
        );
        let r = analyze(&c);
        let c0 = &r.counters[0];
        assert_eq!((c0.resets, c0.wraps), (1, 0));
        // 500->502 (2), 1->3 (2), 3->3, 3->3 are uncensored; 502->1 is the reset span.
        assert_eq!((c0.observed_events, c0.observed_ns), (4, 4 * SEC));
        assert_eq!(
            (c0.censored_spans, c0.censored_ns, c0.unlocated_events_min),
            (1, SEC, 1)
        );
        assert_eq!(r.findings.count(FindingKind::CounterReset), 1);
        // The two uncensored intervals in which the counter rose (500->502 and 1->3) are dropouts; the
        // reset span is not one of them, it is the censored dropout below.
        assert_eq!(r.dropouts.observed.len(), 2);
        assert_eq!(
            r.dropouts.censored,
            vec![CensoredDropout {
                from: MonoNs(11 * SEC),
                to: MonoNs(12 * SEC),
                events_min: 1,
                reason: CensorReason::Reset
            }]
        );
    }

    #[test]
    fn a_plausible_wraparound_is_counted_exactly_and_stays_uncensored() {
        let c = capture(
            "",
            XRUN,
            &[
                "t=0 xruns=4294967290",
                "t=1 xruns=5",
                "t=2 xruns=5",
                "t=3 xruns=5",
                "t=4 xruns=5",
                "t=5 xruns=5",
            ],
        );
        let r = analyze(&c);
        let c0 = &r.counters[0];
        assert_eq!((c0.wraps, c0.resets), (1, 0));
        assert_eq!(
            (c0.observed_events, c0.observed_ns, c0.censored_spans),
            (11, 5 * SEC, 0)
        );
        assert_eq!(r.dropouts.observed.len(), 1);
        assert_eq!(r.dropouts.observed[0].underrun_events, 11);
    }

    #[test]
    fn a_wall_clock_step_is_reported_and_creates_no_gap_or_dropout() {
        // The wall clock jumps forward an hour between the 2nd and 3rd samples; monotonic time is regular.
        let c = capture(
            "wall_step_ms=1000",
            XRUN,
            &[
                "t=0 wall_ns=1000000000000 xruns=0",
                "t=1 wall_ns=1001000000000 xruns=0",
                "t=2 wall_ns=4602000000000 xruns=0",
                "t=3 wall_ns=4603000000000 xruns=0",
                "t=4 wall_ns=1000000000 xruns=0",
                "t=5 wall_ns=2000000000 xruns=0",
            ],
        );
        let r = analyze(&c);
        assert!(r.holes.is_empty());
        assert_eq!(r.denominators.coverage_ppm, 1_000_000);
        assert!(r.dropouts.known && r.dropouts.observed.is_empty());
        assert!(r.wall.carried);
        assert_eq!(r.wall.steps.len(), 2);
        // +3600 s forward, then (1 s elapsed, wall went from 4603 s to 1 s): 1 - 4603 - 1 = -4603 s.
        assert_eq!(
            r.wall.steps[0],
            WallStepRec {
                at: MonoNs(12 * SEC),
                delta_ns: 3_600_000_000_000
            }
        );
        assert_eq!(
            r.wall.steps[1],
            WallStepRec {
                at: MonoNs(14 * SEC),
                delta_ns: -4_603_000_000_000
            }
        );
        assert_eq!(r.findings.count(FindingKind::WallStep), 2);
    }

    #[test]
    fn no_dropout_signal_means_unknown_never_zero() {
        let c = capture(
            "max_dropout_intervals=0",
            "counter name=other_ctr role=other width=32\n",
            &[
                "t=0 other_ctr=1",
                "t=1 other_ctr=2",
                "t=2 other_ctr=3",
                "t=3 other_ctr=4",
                "t=4 other_ctr=5",
                "t=5 other_ctr=6",
            ],
        );
        let r = analyze(&c);
        assert!(!r.dropouts.known);
        assert_eq!(
            r.dropouts.missing,
            vec![Signal::DevUnderruns, Signal::DeviceClock]
        );
        assert!(r.dropouts.observed.is_empty());
        assert_eq!(
            r.absolute.verdict,
            AbsoluteVerdict::NotQualified(vec![Reason::DropoutsUnknown])
        );
        assert_eq!(r.summary().dropout_per_hour_milli, None);
    }

    // -- cause attribution -----------------------------------------------------------------------

    /// All four signals present; one underrun at t=3->t=4 unless the row says otherwise.
    const ALL: &str = "counter name=xruns role=dev_underruns width=32 max_rate_per_s=1000\n\
counter name=late role=late_packets width=32 max_rate_per_s=1000\n\
counter name=cpu role=cpu_misses width=32 max_rate_per_s=1000\n\
counter name=src role=source_bytes width=64\n\
gauge name=play role=playing\n";

    fn only_cause(r: &SeriesReport) -> &Cause {
        assert_eq!(r.dropouts.observed.len(), 1, "expected exactly one dropout");
        &r.dropouts.observed[0].cause
    }

    #[test]
    fn network_lateness_alone_is_determined() {
        let c = capture(
            "",
            ALL,
            &[
                "t=0 xruns=0 late=0 cpu=0 src=0 play=1",
                "t=1 xruns=0 late=0 cpu=0 src=100 play=1",
                "t=2 xruns=0 late=0 cpu=0 src=200 play=1",
                "t=3 xruns=0 late=4 cpu=0 src=300 play=1",
                "t=4 xruns=2 late=4 cpu=0 src=400 play=1",
                "t=5 xruns=2 late=4 cpu=0 src=500 play=1",
            ],
        );
        // playout 0: the window is the dropout interval (t=3..4) and the one before it (t=2..3) where
        // late rose by 4.
        let r = analyze(&c);
        assert_eq!(
            only_cause(&r),
            &Cause::Determined {
                cause: CauseClass::NetworkLateness,
                unexcluded: vec![]
            }
        );
    }

    #[test]
    fn a_source_outage_needs_the_source_to_stall_while_playing() {
        let c = capture(
            "",
            ALL,
            &[
                "t=0 xruns=0 late=0 cpu=0 src=0 play=1",
                "t=1 xruns=0 late=0 cpu=0 src=100 play=1",
                "t=2 xruns=0 late=0 cpu=0 src=100 play=1",
                "t=3 xruns=3 late=0 cpu=0 src=100 play=1",
                "t=4 xruns=3 late=0 cpu=0 src=200 play=1",
                "t=5 xruns=3 late=0 cpu=0 src=300 play=1",
            ],
        );
        let r = analyze(&c);
        assert_eq!(
            only_cause(&r),
            &Cause::Determined {
                cause: CauseClass::SourceOutage,
                unexcluded: vec![]
            }
        );
        // The same stall while paused is not an outage: the dropout is then an output underrun.
        let paused = capture(
            "",
            ALL,
            &[
                "t=0 xruns=0 late=0 cpu=0 src=0 play=1",
                "t=1 xruns=0 late=0 cpu=0 src=100 play=1",
                "t=2 xruns=0 late=0 cpu=0 src=100 play=0",
                "t=3 xruns=3 late=0 cpu=0 src=100 play=0",
                "t=4 xruns=3 late=0 cpu=0 src=200 play=1",
                "t=5 xruns=3 late=0 cpu=0 src=300 play=1",
            ],
        );
        assert_eq!(only_cause(&analyze(&paused)), &Cause::OutputUnderrun);
    }

    #[test]
    fn a_cpu_deadline_miss_alone_is_determined() {
        let c = capture(
            "",
            ALL,
            &[
                "t=0 xruns=0 late=0 cpu=0 src=0 play=1",
                "t=1 xruns=0 late=0 cpu=0 src=100 play=1",
                "t=2 xruns=0 late=0 cpu=0 src=200 play=1",
                "t=3 xruns=1 late=0 cpu=2 src=300 play=1",
                "t=4 xruns=1 late=0 cpu=2 src=400 play=1",
                "t=5 xruns=1 late=0 cpu=2 src=500 play=1",
            ],
        );
        assert_eq!(
            only_cause(&analyze(&c)),
            &Cause::Determined {
                cause: CauseClass::CpuDeadlineMiss,
                unexcluded: vec![]
            }
        );
    }

    #[test]
    fn two_firing_candidates_are_ambiguous_not_ranked() {
        let c = capture(
            "",
            ALL,
            &[
                "t=0 xruns=0 late=0 cpu=0 src=0 play=1",
                "t=1 xruns=0 late=0 cpu=0 src=100 play=1",
                "t=2 xruns=0 late=0 cpu=0 src=200 play=1",
                "t=3 xruns=1 late=2 cpu=2 src=300 play=1",
                "t=4 xruns=1 late=2 cpu=2 src=400 play=1",
                "t=5 xruns=1 late=2 cpu=2 src=500 play=1",
            ],
        );
        assert_eq!(
            only_cause(&analyze(&c)),
            &Cause::Ambiguous {
                present: vec![CauseClass::NetworkLateness, CauseClass::CpuDeadlineMiss]
            }
        );
    }

    #[test]
    fn an_underrun_with_every_candidate_observed_and_quiet_is_an_output_underrun() {
        let c = capture(
            "",
            ALL,
            &[
                "t=0 xruns=0 late=0 cpu=0 src=0 play=1",
                "t=1 xruns=0 late=0 cpu=0 src=100 play=1",
                "t=2 xruns=0 late=0 cpu=0 src=200 play=1",
                "t=3 xruns=5 late=0 cpu=0 src=300 play=1",
                "t=4 xruns=5 late=0 cpu=0 src=400 play=1",
                "t=5 xruns=5 late=0 cpu=0 src=500 play=1",
            ],
        );
        assert_eq!(only_cause(&analyze(&c)), &Cause::OutputUnderrun);
    }

    #[test]
    fn missing_signals_make_the_cause_undetermined_and_are_named() {
        // Only the underrun counter: none of the three candidates can be observed.
        let c = capture(
            "",
            XRUN,
            &[
                "t=0 xruns=0",
                "t=1 xruns=0",
                "t=2 xruns=0",
                "t=3 xruns=2",
                "t=4 xruns=2",
                "t=5 xruns=2",
            ],
        );
        let r = analyze(&c);
        assert_eq!(
            only_cause(&r),
            &Cause::Undetermined {
                missing: vec![
                    MissingSignal {
                        signal: Signal::SourceBytes,
                        why: Why::NotCarried
                    },
                    MissingSignal {
                        signal: Signal::PlayingState,
                        why: Why::NotCarried
                    },
                    MissingSignal {
                        signal: Signal::LatePackets,
                        why: Why::NotCarried
                    },
                    MissingSignal {
                        signal: Signal::CpuMisses,
                        why: Why::NotCarried
                    },
                ]
            }
        );
    }

    #[test]
    fn one_firing_candidate_with_an_unobservable_one_is_determined_but_not_exclusive() {
        // Late packets fired; the CPU counter is not carried at all.
        let decls = "counter name=xruns role=dev_underruns width=32 max_rate_per_s=1000\n\
counter name=late role=late_packets width=32 max_rate_per_s=1000\n\
counter name=src role=source_bytes width=64\n\
gauge name=play role=playing\n";
        let c = capture(
            "",
            decls,
            &[
                "t=0 xruns=0 late=0 src=0 play=1",
                "t=1 xruns=0 late=0 src=100 play=1",
                "t=2 xruns=0 late=0 src=200 play=1",
                "t=3 xruns=1 late=3 src=300 play=1",
                "t=4 xruns=1 late=3 src=400 play=1",
                "t=5 xruns=1 late=3 src=500 play=1",
            ],
        );
        assert_eq!(
            only_cause(&analyze(&c)),
            &Cause::Determined {
                cause: CauseClass::NetworkLateness,
                unexcluded: vec![MissingSignal {
                    signal: Signal::CpuMisses,
                    why: Why::NotCarried
                }]
            }
        );
    }

    #[test]
    fn a_gap_in_a_signal_inside_the_window_makes_it_incomplete_not_quiet() {
        // The late counter is missing at t=3, so the intervals ending at t=3 and t=4 have no delta.
        let c = capture(
            "",
            ALL,
            &[
                "t=0 xruns=0 late=0 cpu=0 src=0 play=1",
                "t=1 xruns=0 late=0 cpu=0 src=100 play=1",
                "t=2 xruns=0 late=0 cpu=0 src=200 play=1",
                "t=3 xruns=0 cpu=0 src=300 play=1",
                "t=4 xruns=2 late=0 cpu=0 src=400 play=1",
                "t=5 xruns=2 late=0 cpu=0 src=500 play=1",
            ],
        );
        let r = analyze(&c);
        assert_eq!(
            only_cause(&r),
            &Cause::Undetermined {
                missing: vec![MissingSignal {
                    signal: Signal::LatePackets,
                    why: Why::IncompleteInWindow
                }]
            }
        );
    }

    #[test]
    fn the_playout_horizon_widens_the_window_to_earlier_intervals() {
        // The only evidence, a CPU miss, is two intervals before the underrun. With playout 0 the window
        // is [t=3..4 (dropout), t=2..3]; the CPU miss at t=1..2 is outside, so the cause is an output
        // underrun. With playout 1000 ms the window reaches back to t=1..2 and finds it.
        let rows = [
            "t=0 xruns=0 late=0 cpu=0 src=0 play=1",
            "t=1 xruns=0 late=0 cpu=0 src=100 play=1",
            "t=2 xruns=0 late=0 cpu=4 src=200 play=1",
            "t=3 xruns=0 late=0 cpu=4 src=300 play=1",
            "t=4 xruns=1 late=0 cpu=4 src=400 play=1",
            "t=5 xruns=1 late=0 cpu=4 src=500 play=1",
        ];
        assert_eq!(
            only_cause(&analyze(&capture("", ALL, &rows))),
            &Cause::OutputUnderrun
        );
        assert_eq!(
            only_cause(&analyze(&capture("playout_ms=1000", ALL, &rows))),
            &Cause::Determined {
                cause: CauseClass::CpuDeadlineMiss,
                unexcluded: vec![]
            }
        );
    }

    #[test]
    fn a_hole_before_a_dropout_blocks_attribution_through_it() {
        // The interval before the dropout is a 4 s hole, so every counter is incomplete in the window.
        // The playing state is still complete there, so it is not among the missing signals.
        let c = capture(
            "",
            ALL,
            &[
                "t=0 xruns=0 late=0 cpu=0 src=0 play=1",
                "t=1 xruns=0 late=0 cpu=0 src=100 play=1",
                "t=5 xruns=0 late=0 cpu=0 src=900 play=1",
                "t=6 xruns=2 late=0 cpu=0 src=1000 play=1",
            ],
        );
        let r = analyze(&c);
        let Cause::Undetermined { missing } = only_cause(&r) else {
            panic!("expected undetermined");
        };
        let signals: Vec<Signal> = missing.iter().map(|m| m.signal).collect();
        assert_eq!(
            signals,
            vec![Signal::SourceBytes, Signal::LatePackets, Signal::CpuMisses]
        );
        assert!(missing.iter().all(|m| m.why == Why::IncompleteInWindow));
    }

    // -- gauges, devices, rejection ---------------------------------------------------------------

    #[test]
    fn implausible_readings_are_excluded_and_spikes_are_kept_and_flagged() {
        let decls = "gauge name=lat role=value max=1000000\n";
        let c = capture(
            "spike_factor=8",
            &format!("{decls}counter name=x role=other width=32\n"),
            &[
                "t=0 lat=100 x=0",
                "t=1 lat=110 x=0",
                "t=2 lat=9999999 x=0",
                "t=3 lat=105 x=0",
                "t=4 lat=2000 x=0",
                "t=5 lat=95 x=0",
            ],
        );
        let r = analyze(&c);
        let g = &r.gauges[0];
        assert_eq!((g.points, g.implausible), (5, 1));
        let s = g.stats.as_ref().expect("stats");
        // Kept values sorted: 95 100 105 110 2000. n=5, p50 rank 3 = 105, p99 rank 5 = 2000.
        assert_eq!((s.n, s.min, s.max, s.p50, s.p99), (5, 95, 2000, 105, 2000));
        // Spike threshold 8 * 105 = 840: only 2000 exceeds it. The implausible 9999999 never entered.
        assert_eq!(s.spikes, 1);
        assert_eq!(r.findings.count(FindingKind::ImplausibleValue), 1);
    }

    #[test]
    fn non_monotonic_samples_are_rejected_and_never_reordered() {
        let c = capture(
            "",
            XRUN,
            &[
                "t=0 xruns=0",
                "t=2 xruns=0",
                "t=1 xruns=9",
                "t=2 xruns=9",
                "t=3 xruns=0",
            ],
        );
        let r = analyze(&c);
        let d = &r.denominators;
        assert_eq!(
            (
                d.samples_total,
                d.samples_accepted,
                d.samples_rejected_non_monotonic
            ),
            (5, 3, 2)
        );
        assert_eq!(r.findings.count(FindingKind::NonMonotonicClock), 2);
        // The rejected xruns=9 samples never reached the counter.
        assert_eq!(r.counters[0].observed_events, 0);
        assert!(r.dropouts.observed.is_empty());
    }

    #[test]
    fn a_counter_value_wider_than_its_declared_width_is_missing_not_trusted() {
        let c = capture(
            "",
            XRUN,
            &[
                "t=0 xruns=0",
                "t=1 xruns=4294967296",
                "t=2 xruns=1",
                "t=3 xruns=1",
            ],
        );
        let r = analyze(&c);
        assert_eq!(r.findings.count(FindingKind::ValueOutOfWidth), 1);
        assert_eq!(r.counters[0].points, 3);
        assert_eq!(r.counters[0].missing_values, 1);
    }

    #[test]
    fn the_device_clock_is_compared_to_monotonic_time_and_a_32_bit_wrap_is_not_a_stall() {
        // 48 kHz. 48000 frames per second expected. Frames start just below 2^32 and wrap at t=2.
        let meta = "device_rate_hz=48000 device_width=32 device_stall_frames=4800";
        let c = capture(
            meta,
            XRUN,
            &[
                "t=0 dev_frames=4294915296 xruns=0",
                "t=1 dev_frames=4294963296 xruns=0",
                "t=2 dev_frames=48000 xruns=0",
                "t=3 dev_frames=96000 xruns=0",
                "t=4 dev_frames=120000 xruns=0",
                "t=5 dev_frames=168000 xruns=0",
            ],
        );
        let r = analyze(&c);
        let dv = &r.device;
        assert!(dv.carried);
        // t=1->2: 4294963296 -> 48000 wraps: 48000 + 2^32 - 4294963296 = 48000 + 4000 = 52000?
        // 2^32 = 4294967296; 4294967296 - 4294963296 = 4000; + 48000 = 52000 frames, plausible at 96000/s.
        assert_eq!(dv.wraps, 1);
        // Expected 5 * 48000 = 240000; observed 48000 + 52000 + 48000 + 24000 + 48000 = 220000.
        assert_eq!((dv.expected_frames, dv.observed_frames), (240_000, 220_000));
        // -20000 / 240000 = -83333.33 ppm, truncated toward zero.
        assert_eq!(dv.drift_ppm, Some(-83_333));
        // t=3->4: only 24000 of 48000 frames, a deficit of 24000 >= 4800: a stall dropout.
        // t=1->2: deficit 48000 - 52000 < 0: not a stall (the device ran fast over the wrap).
        assert_eq!(dv.stall_intervals, 1);
        assert_eq!(r.dropouts.observed.len(), 1);
        assert_eq!(r.dropouts.observed[0].stall_deficit_frames, Some(24_000));
        assert_eq!(r.dropouts.observed[0].underrun_events, 0);
    }

    #[test]
    fn device_frames_without_a_declared_rate_are_not_interpreted() {
        let c = capture(
            "",
            XRUN,
            &[
                "t=0 dev_frames=0 xruns=0",
                "t=1 dev_frames=48000 xruns=0",
                "t=2 dev_frames=96000 xruns=0",
            ],
        );
        let r = analyze(&c);
        assert!(!r.device.carried);
        assert_eq!(r.device.drift_ppm, None);
        assert_eq!(r.findings.count(FindingKind::DeviceRateMissing), 1);
    }

    #[test]
    fn json_output_is_stable_and_contains_the_named_fields() {
        let c = capture("", XRUN, &["t=0 xruns=0", "t=1 xruns=2"]);
        let a = analyze(&c).to_json().render();
        let b = analyze(&c).to_json().render();
        assert_eq!(a, b);
        assert!(a.starts_with(
            "{\"schema\":\"ffw.baseline.series-report.v1\",\"evidence\":\"synthetic\""
        ));
        assert!(a.contains("\"measured_on_device\":false"));
        assert!(a.contains("\"known\":true"));
    }
}
