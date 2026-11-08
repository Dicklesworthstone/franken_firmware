//! P05's real runtime probe: the pinned Asupersync runtime, under its own bounded `LegacyProfile`, doing real work.
//!
//! Bead ffw-ipz. The sibling `p05-target` probe runs `franken-atomic` only; no Asupersync code executed in the guest. This one links
//! the Git-pinned runtime and exercises, in order: the profile's refusals and acceptance, a runtime built from that profile and
//! AUDITED against it, spawn and join, abort of a timer-parked task, a timer wake, loopback UDP, the bounded blocking pool at its
//! queue bound, and a root drain with live tasks. Every operation prints one `FFW_P05_RUNTIME:<NAME>` marker carrying what it
//! observed; `ok` or `failed` is computed from those observations at run time, and an operation this platform or API cannot do is
//! printed `unsupported` with the reason and counted. Nothing is polyfilled and nothing is reported as passed because it was skipped.
//! One `FFW_P05_RUNTIME:END` marker closes the transcript with the real counts; a transcript without it did not finish.
//!
//! Thread and memory census. Between phases (after each `block_on` has returned) and once inside a parked task, the probe reads
//! `/proc/self/task` and `/proc/self/status` (`Threads`, `VmRSS`, `VmHWM`) and `/proc/meminfo` (`MemAvailable`). A figure that cannot
//! be read, because `/proc` is not mounted or the field is absent, is printed `unknown`. It is never replaced by a guess or a zero.
//!
//! Scope. Loopback only: every socket is bound to `127.0.0.1` through a literal `SocketAddr`, so no name is resolved, and a bound
//! address that is not loopback is refused. No `unsafe` (the crate forbids it); as PID 1 the probe parks after END instead of calling
//! `reboot`, and the supervisor that owns the QEMU process ends it. What this does not show: it is not a memory-fit result, not a
//! throughput or latency figure, and not the cancellation audit; the stack sizes below are requested sizes, not measurements.
//!
//! Topologies. By default the probe builds the threaded profile (two scheduler workers) and its transcript is unchanged. Run with the
//! argument `--profile=single-owner` it builds the single-owner profile instead: the same bounded `LegacyProfile` with exactly one
//! scheduler worker, built and audited by the same path, so one thread polls every task. Its transcript has more rows and is not the
//! one the default judge reads. The caller-driven mode (`RuntimeBuilder::current_thread()`) is not something `LegacyProfile` can
//! build at the pinned revision, so that row is printed `unsupported` and is never counted as `ok`.
#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fmt::Display;
use std::fs;
use std::future::Future;
use std::io::Write;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::task::{Poll, Waker};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use asupersync::cx::Cx;
use asupersync::net::UdpSocket;
use asupersync::runtime::legacy_profile::{CapViolation, LegacyCaps, LegacyProfile};
use asupersync::runtime::reactor::create_reactor;
use asupersync::runtime::{
    BlockingSpawnErrorKind, BlockingTaskHandle, JoinError, RootDrainOutcome, RootDrainReport,
    Runtime, yield_now,
};
use asupersync::time::sleep;

const MIB: usize = 1024 * 1024;
const CHILDREN: usize = 8;
const DRAIN_TASKS: usize = 4;
const UDP_PAYLOAD: &[u8] = b"ffw-p05-runtime-udp";
/// A timer wake may be reported a few milliseconds early by a coarse timer; anything further is a failure.
const EARLY_TOLERANCE: Duration = Duration::from_millis(5);
const LONG: Duration = Duration::from_secs(10);
/// How long any one phase waits for something that should already be happening before it records a failure instead of waiting on.
const PHASE_LIMIT: Duration = Duration::from_secs(20);

/// Wait, yielding to the runtime, until `$child` has reached its terminal join state or `$limit` passes; evaluates to whether it did.
/// A macro and not a function so that no reference to the handle is held across the await (the phase futures must be `Send`).
macro_rules! finished_within {
    ($child:expr, $limit:expr) => {{
        let started = Instant::now();
        loop {
            if started.elapsed() >= $limit {
                break false;
            }
            if $child.is_finished() {
                break true;
            }
            yield_now().await;
        }
    }};
}

/// Probe watchdog independent of Asupersync's timer driver. A pending operation requeues its poll;
/// the outer process supervisor remains the final bound if the scheduler itself stops progressing.
async fn wall_clock_timeout<F: Future>(future: F, limit: Duration) -> Option<F::Output> {
    let started = Instant::now();
    let mut future = pin!(future);
    std::future::poll_fn(|cx| {
        if started.elapsed() >= limit {
            return Poll::Ready(None);
        }
        let polled = future.as_mut().poll(cx);
        if started.elapsed() >= limit {
            return Poll::Ready(None);
        }
        match polled {
            Poll::Ready(value) => Poll::Ready(Some(value)),
            Poll::Pending => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    })
    .await
}

// ---- markers and counters ---------------------------------------------------------------------------------------------------

/// One marker line. Pure, so the format is tested natively.
fn line(name: &str, status: &str, detail: &str) -> String {
    format!("FFW_P05_RUNTIME:{name} status={status} {detail}")
}

fn emit(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{text}");
    let _ = out.flush();
}

/// What an operation observed. Only `Pass` is a pass. `Fail` is a contradiction of the contract. `Unsupported` is for what this
/// platform or API cannot do here. `Partial` is an observation that was only partly readable or not taken at one instant, and
/// `Unknown` is one with nothing readable at all. The last three are counted and printed under their own names, never as `ok`.
enum Verdict {
    Pass(String),
    Fail(String),
    Unsupported(String),
    Partial(String),
    Unknown(String),
}

impl Verdict {
    /// The status word a marker prints for this verdict.
    fn status(&self) -> &'static str {
        match self {
            Self::Pass(_) => "ok",
            Self::Fail(_) => "failed",
            Self::Unsupported(_) => "unsupported",
            Self::Partial(_) => "partial",
            Self::Unknown(_) => "unknown",
        }
    }

    fn detail(&self) -> &str {
        match self {
            Self::Pass(detail)
            | Self::Fail(detail)
            | Self::Unsupported(detail)
            | Self::Partial(detail)
            | Self::Unknown(detail) => detail.as_str(),
        }
    }
}

/// `ops == ok + failed + unsupported + partial + unknown` always; `census_samples` is how many of those operations were CENSUS lines.
#[derive(Default)]
struct Report {
    ops: u32,
    ok: u32,
    failed: u32,
    unsupported: u32,
    partial: u32,
    unknown: u32,
    census_samples: u32,
    /// The name of every recorded operation, in order, so a caller can check WHICH phases ran and not only how many.
    names: Vec<String>,
    /// The name and detail of every operation recorded `unsupported`, in order, so an exit code can tell WHICH row it was.
    unsupported_rows: Vec<(String, String)>,
}

impl Report {
    fn record(&mut self, name: &str, verdict: Verdict) {
        self.ops += 1;
        self.names.push(name.to_string());
        if name == "CENSUS" {
            self.census_samples += 1;
        }
        let (status, detail) = match verdict {
            Verdict::Pass(detail) => {
                self.ok += 1;
                ("ok", detail)
            }
            Verdict::Fail(detail) => {
                self.failed += 1;
                ("failed", detail)
            }
            Verdict::Unsupported(detail) => {
                self.unsupported += 1;
                self.unsupported_rows
                    .push((name.to_string(), detail.clone()));
                ("unsupported", detail)
            }
            Verdict::Partial(detail) => {
                self.partial += 1;
                ("partial", detail)
            }
            Verdict::Unknown(detail) => {
                self.unknown += 1;
                ("unknown", detail)
            }
        };
        emit(&line(name, status, &detail));
    }

    fn end(&self) -> String {
        let detail = format!(
            "ops={} ok={} failed={} unsupported={} partial={} unknown={} census_samples={}",
            self.ops,
            self.ok,
            self.failed,
            self.unsupported,
            self.partial,
            self.unknown,
            self.census_samples
        );
        line("END", "done", &detail)
    }

    /// 0 only when every operation passed; 1 if any failed; 2 if none failed but some were unsupported, partial or unknown.
    fn exit_code(&self) -> i32 {
        if self.failed > 0 {
            1
        } else if self.unsupported + self.partial + self.unknown > 0 {
            2
        } else {
            0
        }
    }

    /// The single-owner run's exit code. It is 0 only when every operation passed except exactly one: the declared row,
    /// `CALLER_DRIVEN_CURRENT_THREAD`, recorded `unsupported` with the pin's stated reason, in a run of the declared size (33
    /// operations, 32 ok). The transcript still carries that row; the exit code only stops calling a declared gap a crash. Any other
    /// result is nonzero: a second unsupported row, a failed, partial or unknown row, a different tally, or a run in which the
    /// declared row is missing or ok get the ordinary code, or 1 if that would have been 0.
    fn single_owner_exit_code(&self) -> i32 {
        let declared_only = self.failed == 0
            && self.partial == 0
            && self.unknown == 0
            && self.ops == SINGLE_OWNER_OPS
            && self.ok == SINGLE_OWNER_OPS - 1
            && self.unsupported == 1
            && matches!(
                self.unsupported_rows.as_slice(),
                [(name, detail)] if name == CALLER_DRIVEN_ROW && detail.starts_with(CALLER_DRIVEN_REASON)
            );
        if declared_only {
            0
        } else {
            self.exit_code().max(1)
        }
    }
}

// ---- the census -------------------------------------------------------------------------------------------------------------

/// One reading of the process. Counts before and after the status read can detect disagreement, but cannot prove thread identities
/// stayed fixed or exclude a transient thread between samples. Unreadable entries invalidate a count instead of producing a partial one.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Census {
    task_dir_before: Option<usize>,
    task_dir_after: Option<usize>,
    status_threads: Option<u64>,
    rss_kb: Option<u64>,
    hwm_kb: Option<u64>,
    mem_available_kb: Option<u64>,
}

impl Census {
    /// The thread count in `/proc/self/task` when it was readable both times and did not change between them.
    fn stable_task_dir(&self) -> Option<usize> {
        match (self.task_dir_before, self.task_dir_after) {
            (Some(before), Some(after)) if before == after => Some(before),
            _ => None,
        }
    }
}

/// The first line `<key>:` followed by a decimal number (any unit word after it is ignored). A missing key, a different key that merely
/// starts with this one, or a value that is not a number is `None`.
fn field(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|row| {
        let rest = row.strip_prefix(key)?.strip_prefix(':')?;
        rest.split_whitespace().next()?.parse().ok()
    })
}

fn show<T: Display>(value: Option<T>) -> String {
    value.map_or_else(|| "unknown".to_string(), |known| known.to_string())
}

fn task_dir_count() -> Option<usize> {
    count_readable_entries(fs::read_dir("/proc/self/task").ok()?)
}

fn count_readable_entries<T, E>(entries: impl IntoIterator<Item = Result<T, E>>) -> Option<usize> {
    entries.into_iter().try_fold(0_usize, |count, entry| {
        entry.ok().and_then(|_| count.checked_add(1))
    })
}

fn census() -> Census {
    let task_dir_before = task_dir_count();
    let status = fs::read_to_string("/proc/self/status").ok();
    let task_dir_after = task_dir_count();
    let meminfo = fs::read_to_string("/proc/meminfo").ok();
    let in_status = |key: &str| status.as_deref().and_then(|text| field(text, key));
    Census {
        task_dir_before,
        task_dir_after,
        status_threads: in_status("Threads"),
        rss_kb: in_status("VmRSS"),
        hwm_kb: in_status("VmHWM"),
        mem_available_kb: meminfo
            .as_deref()
            .and_then(|text| field(text, "MemAvailable")),
    }
}

fn census_detail(phase: &str, c: &Census) -> String {
    let dir_stable = match (c.task_dir_before, c.task_dir_after) {
        (Some(before), Some(after)) => (before == after).to_string(),
        _ => "unknown".to_string(),
    };
    let agree = match (c.stable_task_dir(), c.status_threads) {
        (Some(dir), Some(status)) => (u64::try_from(dir).ok() == Some(status)).to_string(),
        _ => "unknown".to_string(),
    };
    format!(
        "phase={phase} threads_task_dir_before={} threads_task_dir_after={} task_dir_stable={dir_stable} threads_status={} sources_agree={agree} vm_rss_kb={} vm_hwm_kb={} mem_available_kb={}",
        show(c.task_dir_before),
        show(c.task_dir_after),
        show(c.status_threads),
        show(c.rss_kb),
        show(c.hwm_kb),
        show(c.mem_available_kb)
    )
}

/// What one census reading means. Pure, so every branch is tested with made-up readings.
/// * `Fail`: two sources that were read stably DISAGREE about the thread count, a thread figure is 0 (a running process has at
///   least one), or the high-water mark is below the current resident size.
/// * `Unknown`: nothing at all could be read.
/// * `Partial`: something could not be read, or the thread set changed while it was being read, so the two thread sources were not
///   read at one instant and no agreement or disagreement is claimed.
/// * `Pass`: both thread sources were stable and equal, and all three memory figures were read.
///
/// A missing figure is never turned into a number.
fn judge_census(phase: &str, c: &Census) -> Verdict {
    let detail = census_detail(phase, c);
    let stable = c.stable_task_dir();
    if let (Some(dir), Some(status)) = (stable, c.status_threads)
        && u64::try_from(dir).ok() != Some(status)
    {
        return Verdict::Fail(format!("{detail} reason=thread_sources_disagree"));
    }
    if stable == Some(0) || c.status_threads == Some(0) {
        return Verdict::Fail(format!("{detail} reason=zero_threads_in_a_running_process"));
    }
    if let (Some(hwm), Some(rss)) = (c.hwm_kb, c.rss_kb)
        && hwm < rss
    {
        return Verdict::Fail(format!("{detail} reason=high_water_below_resident"));
    }
    let nothing = c.task_dir_before.is_none()
        && c.task_dir_after.is_none()
        && c.status_threads.is_none()
        && c.rss_kb.is_none()
        && c.hwm_kb.is_none()
        && c.mem_available_kb.is_none();
    if nothing {
        return Verdict::Unknown(format!("{detail} reason=nothing_readable"));
    }
    let complete = stable.is_some()
        && c.status_threads.is_some()
        && c.rss_kb.is_some()
        && c.hwm_kb.is_some()
        && c.mem_available_kb.is_some();
    if complete {
        Verdict::Pass(detail)
    } else if c.task_dir_before.is_some() && c.task_dir_after.is_some() && stable.is_none() {
        Verdict::Partial(format!(
            "{detail} reason=thread_set_changed_during_the_reading"
        ))
    } else {
        Verdict::Partial(format!("{detail} reason=some_figures_unreadable"))
    }
}

/// Take one sample and record its judged verdict. Returns the reading for a caller that wants a figure from it.
fn sample(report: &mut Report, phase: &str) -> Census {
    let c = census();
    report.record("CENSUS", judge_census(phase, &c));
    c
}

// ---- the profile ------------------------------------------------------------------------------------------------------------

/// Two scheduler workers, one blocking thread and one queued blocking job, every queue bounded, every stack stated.
fn caps() -> LegacyCaps {
    LegacyCaps {
        worker_threads: 2,
        thread_stack_bytes: MIB,
        blocking_max_threads: 1,
        blocking_thread_stack_bytes: MIB / 2,
        global_queue_limit: 256,
        blocking_max_queued: 1,
    }
}

fn profile() -> Option<LegacyProfile> {
    let stated = caps();
    stated
        .worst_case_stack_bytes()
        .map(|budget| LegacyProfile::new(stated, budget))
}

/// Which scheduler topology a probe run builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Topology {
    /// The default: the profile of `caps()`, two scheduler workers.
    Threaded,
    /// The profile of `single_owner_caps()`: the same bounds with exactly one scheduler worker.
    SingleOwner,
}

/// The `caps()` bounds with exactly one scheduler worker and nothing else changed, so the single-owner run is the same profile with
/// the one worker count different.
fn single_owner_caps() -> LegacyCaps {
    LegacyCaps {
        worker_threads: 1,
        ..caps()
    }
}

fn single_owner_profile() -> Option<LegacyProfile> {
    let stated = single_owner_caps();
    stated
        .worst_case_stack_bytes()
        .map(|budget| LegacyProfile::new(stated, budget))
}

/// Why a profile that claims the single-owner topology was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SingleOwnerRefusal {
    /// The caps are not an acceptable profile at all. Zero workers lands here: the runtime would raise it to one, so it is not a
    /// stated single worker.
    Invalid(Vec<CapViolation>),
    /// The profile states more than one scheduler worker.
    MoreThanOneWorker(usize),
}

impl SingleOwnerRefusal {
    fn detail(&self) -> String {
        match self {
            Self::Invalid(violations) => format!(
                "claimed=single_owner refused=invalid_profile violations={} first={:?}",
                violations.len(),
                violations.first()
            ),
            Self::MoreThanOneWorker(workers) => format!(
                "claimed=single_owner refused=more_than_one_worker stated_worker_threads={workers} required_worker_threads=1"
            ),
        }
    }
}

/// A profile may claim the single-owner topology only if it is an acceptable profile that states exactly one scheduler worker. Pure.
fn single_owner_claim(profile: &LegacyProfile) -> Result<(), SingleOwnerRefusal> {
    let violations = profile.violations();
    if !violations.is_empty() {
        return Err(SingleOwnerRefusal::Invalid(violations));
    }
    match profile.caps().worker_threads {
        1 => Ok(()),
        workers => Err(SingleOwnerRefusal::MoreThanOneWorker(workers)),
    }
}

/// The profile accepts the caps it was given and refuses, by name, the ones that leave something unbounded or over budget.
fn profile_phase(report: &mut Report, stated: Option<LegacyProfile>) {
    let Some(good) = stated else {
        report.record(
            "PROFILE_ACCEPT",
            Verdict::Fail("worst_case_stack_bytes=overflow".to_string()),
        );
        return;
    };
    let accepted = good.violations();
    let worst = good.caps().worst_case_stack_bytes();
    let detail = format!(
        "violations={} worst_case_stack_bytes={} budget={}",
        accepted.len(),
        show(worst),
        good.stack_budget_bytes()
    );
    let verdict = if accepted.is_empty() && good.validate().is_ok() {
        Verdict::Pass(detail)
    } else {
        Verdict::Fail(detail)
    };
    report.record("PROFILE_ACCEPT", verdict);

    let budget = good.stack_budget_bytes();
    let no_workers = LegacyProfile::new(
        LegacyCaps {
            worker_threads: 0,
            ..good.caps()
        },
        budget,
    );
    let unbounded = LegacyProfile::new(
        LegacyCaps {
            global_queue_limit: 0,
            ..good.caps()
        },
        budget,
    );
    let over = LegacyProfile::new(good.caps(), budget.saturating_sub(1));
    let refused = [
        (
            "PROFILE_REFUSES_ZERO_WORKERS",
            no_workers.violations().contains(&CapViolation::NoWorkers),
            no_workers.builder().is_err(),
        ),
        (
            "PROFILE_REFUSES_UNBOUNDED_QUEUE",
            unbounded
                .violations()
                .contains(&CapViolation::GlobalQueueUnbounded),
            unbounded.builder().is_err(),
        ),
        (
            "PROFILE_REFUSES_OVER_BUDGET",
            over.violations()
                .iter()
                .any(|v| matches!(v, CapViolation::StackBudgetExceeded { .. })),
            over.builder().is_err(),
        ),
    ];
    for (name, named, builder_refused) in refused {
        let detail = format!("named_violation={named} builder_refused={builder_refused}");
        let verdict = if named && builder_refused {
            Verdict::Pass(detail)
        } else {
            Verdict::Fail(detail)
        };
        report.record(name, verdict);
    }
}

/// Build the runtime from the profile and audit it against the profile. The reactor is the platform's own; when it cannot be
/// created the runtime is built without one and every phase that needs I/O says so.
fn build_phase(report: &mut Report, profile: &LegacyProfile) -> Option<(Runtime, bool)> {
    let builder = match profile.builder() {
        Ok(builder) => builder,
        Err(error) => {
            report.record(
                "RUNTIME_BUILD",
                Verdict::Fail(format!("builder_error={error:?}")),
            );
            return None;
        }
    };
    let (builder, reactor) = match create_reactor() {
        Ok(reactor) => {
            report.record("REACTOR", Verdict::Pass("kind=platform".to_string()));
            (builder.with_reactor(reactor), true)
        }
        Err(error) => {
            report.record(
                "REACTOR",
                Verdict::Unsupported(format!("create_reactor_error_kind={:?}", error.kind())),
            );
            (builder.enable_platform_reactor(false), false)
        }
    };
    let runtime = match builder.build() {
        Ok(runtime) => runtime,
        Err(error) => {
            report.record(
                "RUNTIME_BUILD",
                Verdict::Fail(format!("build_error={error:?}")),
            );
            return None;
        }
    };
    let audit = profile.audit(&runtime);
    let carried = LegacyCaps::of_runtime(&runtime);
    let stated = profile.caps();
    let detail = format!(
        "audit_ok={} workers={}/{} blocking_threads={}/{} global_queue={}/{} blocking_queue={}/{} (carried/stated)",
        audit.is_ok(),
        carried.worker_threads,
        stated.worker_threads,
        carried.blocking_max_threads,
        stated.blocking_max_threads,
        carried.global_queue_limit,
        stated.global_queue_limit,
        carried.blocking_max_queued,
        stated.blocking_max_queued
    );
    match audit {
        Ok(()) => report.record("RUNTIME_AUDIT", Verdict::Pass(detail)),
        Err(error) => report.record(
            "RUNTIME_AUDIT",
            Verdict::Fail(format!("{detail} error={error:?}")),
        ),
    }
    Some((runtime, reactor))
}

// ---- the async phases (each runs as a task under `block_on`) ----------------------------------------------------------------

fn run_async<F>(runtime: &Runtime, phase: F) -> Verdict
where
    F: Future<Output = Verdict> + Send + 'static,
{
    runtime.block_on(runtime.handle().spawn(phase))
}

/// `run_async` for a phase that returns an observation instead of a verdict, so a judge can read it.
fn run_async_value<T, F>(runtime: &Runtime, phase: F) -> T
where
    T: Send + 'static,
    F: Future<Output = T> + Send + 'static,
{
    runtime.block_on(runtime.handle().spawn(phase))
}

async fn spawn_join_phase() -> Verdict {
    let Some(cx) = Cx::current() else {
        return Verdict::Fail("no_current_cx".to_string());
    };
    let mut handles = Vec::new();
    for i in 0..CHILDREN {
        match cx.spawn(move |_child| async move {
            yield_now().await;
            i * i
        }) {
            Ok(handle) => handles.push(handle),
            Err(error) => {
                return Verdict::Fail(format!("spawn_refused={error:?} after={}", handles.len()));
            }
        }
    }
    let (mut joined, mut sum) = (0_usize, 0_usize);
    for mut handle in handles {
        if !finished_within!(handle, PHASE_LIMIT) {
            return Verdict::Fail(format!(
                "child_not_finished_within_{}s joined={joined}",
                PHASE_LIMIT.as_secs()
            ));
        }
        match handle.join(&cx).await {
            Ok(value) => {
                joined += 1;
                sum += value;
            }
            Err(error) => return Verdict::Fail(format!("join_error={error:?} joined={joined}")),
        }
    }
    let expected: usize = (0..CHILDREN).map(|i| i * i).sum();
    let detail = format!("children={CHILDREN} joined={joined} sum={sum} expected={expected}");
    if joined == CHILDREN && sum == expected {
        Verdict::Pass(detail)
    } else {
        Verdict::Fail(detail)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SleepCleanup {
    child_id: usize,
    cancel_requested: bool,
    before_deadline: bool,
}

fn cleanup_counts(samples: &[SleepCleanup]) -> (usize, usize, usize, usize) {
    (
        samples.len(),
        samples
            .iter()
            .enumerate()
            .filter(|(index, sample)| {
                samples[..*index]
                    .iter()
                    .all(|earlier| earlier.child_id != sample.child_id)
            })
            .count(),
        samples
            .iter()
            .filter(|sample| sample.cancel_requested)
            .count(),
        samples
            .iter()
            .filter(|sample| sample.before_deadline)
            .count(),
    )
}

fn cleanup_succeeded(samples: &[SleepCleanup], wanted: usize) -> bool {
    wanted > 0
        && cleanup_counts(samples) == (wanted, wanted, wanted, wanted)
        && (0..wanted).all(|id| samples.iter().any(|sample| sample.child_id == id))
}

/// Abort a child parked on a 10 s timer: it must finish well inside a second and leave no timer registered.
async fn abort_timer_phase() -> Verdict {
    let Some(cx) = Cx::current() else {
        return Verdict::Fail("no_current_cx".to_string());
    };
    let Some(timer) = cx.timer_driver() else {
        return Verdict::Unsupported("no_timer_driver_on_this_task".to_string());
    };
    let parked = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&parked);
    let cleanup = Arc::new(Mutex::new(Vec::with_capacity(1)));
    let child_cleanup = Arc::clone(&cleanup);
    let spawned = cx.spawn(move |child_cx| async move {
        let armed = Instant::now();
        let mut sleeper = pin!(sleep(child_cx.now(), LONG));
        std::future::poll_fn(|poll_cx| {
            let polled = sleeper.as_mut().poll(poll_cx);
            if polled.is_pending() {
                flag.store(true, Ordering::Release);
            }
            polled
        })
        .await;
        child_cleanup
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(SleepCleanup {
                child_id: 0,
                cancel_requested: child_cx.is_cancel_requested(),
                before_deadline: armed.elapsed() < LONG,
            });
    });
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => return Verdict::Fail(format!("spawn_refused={error:?}")),
    };
    let started = Instant::now();
    while !parked.load(Ordering::Acquire) && started.elapsed() < Duration::from_secs(2) {
        yield_now().await;
    }
    let during = census();
    let pending_before = timer.pending_count();
    let t0 = Instant::now();
    child.abort();
    if !finished_within!(child, PHASE_LIMIT) {
        return Verdict::Fail(format!(
            "aborted_child_not_finished_within_{}s pending_timers_before={pending_before}",
            PHASE_LIMIT.as_secs()
        ));
    }
    let joined = child.join(&cx).await;
    let elapsed = t0.elapsed();
    let pending_after = timer.pending_count();
    let cleanup = cleanup.lock().unwrap_or_else(PoisonError::into_inner);
    let witnessed = cleanup_counts(&cleanup);
    // The contract, as the pinned audit asserts it for this very child
    // (`abort_and_join_complete_promptly_for_a_timer_parked_native_child`, `assert_eq!(result, Ok(()))`): `Sleep` has no error
    // output, so the cancellation it acknowledged completes the wait and the child's own result is preserved. Exactly `Ok(())`,
    // not "any Ok" and not "any outcome that finished": `Err(JoinError::Cancelled(_))` is the OTHER case, a future that did not
    // acknowledge (see `ABORT_BLIND_VALUE`), and here it is a contradiction. That audit runs on a current-thread runtime; this
    // runtime has two workers, so a `Cancelled` here is a finding to read, and the oracle is not loosened to accept it.
    let preserved = matches!(joined, Ok(()));
    let detail = format!(
        "parked={} pending_timers_before={pending_before} pending_timers_after={pending_after} abort_to_join_ms={} join_result={} expected_join_result=Ok threads_during_task_dir={} threads_during_status={} cleanup_resumed={} cleanup_unique={} cleanup_cancelled={} cleanup_before_deadline={}",
        parked.load(Ordering::Acquire),
        elapsed.as_millis(),
        join_kind(&joined),
        show(during.stable_task_dir()),
        show(during.status_threads),
        witnessed.0,
        witnessed.1,
        witnessed.2,
        witnessed.3,
    );
    let ok = parked.load(Ordering::Acquire)
        && pending_before >= 1
        && pending_after.checked_add(1) == Some(pending_before)
        && preserved
        && cleanup_succeeded(&cleanup, 1)
        && elapsed < Duration::from_secs(1);
    if ok {
        Verdict::Pass(detail)
    } else {
        Verdict::Fail(detail)
    }
}

/// Which kind of result a join gave, by name, so a report says which contract case it saw.
fn join_kind<T>(joined: &Result<T, JoinError>) -> &'static str {
    match joined {
        Ok(_) => "Ok",
        Err(JoinError::Cancelled(_)) => "Cancelled",
        Err(JoinError::Panicked(_)) => "Panicked",
        #[allow(unreachable_patterns)]
        Err(_) => "OtherError",
    }
}

/// The other half of the abort contract. A child that never acknowledges cancellation and only returns a value once the abort has
/// been requested joins as `Err(JoinError::Cancelled(_))`, not as `Ok(value)` (the pinned audit's
/// `ordinary_spawn_keeps_cancellation_dominant_for_cancellation_blind_late_values`). The value is released only AFTER `abort()`, on
/// any worker, so the order is fixed by this code and not by which worker polls first.
async fn abort_blind_phase() -> Verdict {
    abort_blind_with_start_signal(true, Duration::from_secs(2)).await
}

async fn abort_blind_with_start_signal(publish_start: bool, start_limit: Duration) -> Verdict {
    let Some(cx) = Cx::current() else {
        return Verdict::Fail("no_current_cx".to_string());
    };
    let released = Arc::new(AtomicBool::new(false));
    let slot: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));
    let started_signal = Arc::new(AtomicBool::new(false));
    let child_started = Arc::clone(&started_signal);
    let (child_released, child_slot) = (Arc::clone(&released), Arc::clone(&slot));
    let spawned = cx.spawn(move |_child_cx| async move {
        std::future::poll_fn(|poll_cx| {
            if child_released.load(Ordering::Acquire) {
                return Poll::Ready(42_u32);
            }
            *child_slot.lock().unwrap_or_else(PoisonError::into_inner) =
                Some(poll_cx.waker().clone());
            if publish_start {
                child_started.store(true, Ordering::Release);
            }
            // Release can race with first registration, including the setup-failure cleanup.
            // Recheck after storing the waker so that no pending poll loses its release wake.
            if child_released.load(Ordering::Acquire) {
                Poll::Ready(42_u32)
            } else {
                Poll::Pending
            }
        })
        .await
    });
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => return Verdict::Fail(format!("spawn_refused={error:?}")),
    };
    let started = Instant::now();
    while !started_signal.load(Ordering::Acquire) && started.elapsed() < start_limit {
        yield_now().await;
    }
    let start_observed = started_signal.load(Ordering::Acquire);
    // Setup failure must use the same release/wake/bounded-join cleanup as the normal path.
    child.abort();
    released.store(true, Ordering::Release);
    let waker = slot.lock().unwrap_or_else(PoisonError::into_inner).take();
    if let Some(waker) = waker {
        waker.wake();
    }
    if !finished_within!(child, PHASE_LIMIT) {
        return Verdict::Fail(format!(
            "aborted_blind_child_not_finished_within_{}s",
            PHASE_LIMIT.as_secs()
        ));
    }
    let joined = child.join(&cx).await;
    if !start_observed {
        return Verdict::Fail(format!(
            "blind_child_start_signal_missing cleanup_completed=true join_result={}",
            join_kind(&joined)
        ));
    }
    let detail = format!(
        "join_result={} expected_join_result=Cancelled ok_value={:?}",
        join_kind(&joined),
        joined.as_ref().ok()
    );
    if matches!(joined, Err(JoinError::Cancelled(_))) {
        Verdict::Pass(detail)
    } else {
        Verdict::Fail(detail)
    }
}

async fn timer_wake_phase() -> Verdict {
    let Some(cx) = Cx::current() else {
        return Verdict::Fail("no_current_cx".to_string());
    };
    let wanted = Duration::from_millis(50);
    let spawned = cx.spawn(move |child_cx| async move {
        let t0 = Instant::now();
        sleep(child_cx.now(), wanted).await;
        t0.elapsed()
    });
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => return Verdict::Fail(format!("spawn_refused={error:?}")),
    };
    if !finished_within!(child, PHASE_LIMIT) {
        return Verdict::Fail(format!(
            "sleeping_child_not_finished_within_{}s",
            PHASE_LIMIT.as_secs()
        ));
    }
    match child.join(&cx).await {
        Ok(elapsed) => {
            let detail = format!(
                "wanted_ms={} slept_ms={}",
                wanted.as_millis(),
                elapsed.as_millis()
            );
            let not_early = elapsed + EARLY_TOLERANCE >= wanted;
            if not_early && elapsed < Duration::from_secs(5) {
                Verdict::Pass(detail)
            } else {
                Verdict::Fail(detail)
            }
        }
        Err(error) => Verdict::Fail(format!("join_error={error:?}")),
    }
}

/// One datagram from one loopback socket to another, received by a spawned task; a timeout aborts the receiver instead of hanging.
async fn udp_phase() -> Verdict {
    let Some(cx) = Cx::current() else {
        return Verdict::Fail("no_current_cx".to_string());
    };
    let any = SocketAddr::from(([127, 0, 0, 1], 0));
    let mut sender = match UdpSocket::bind(any).await {
        Ok(socket) => socket,
        Err(error) => return Verdict::Unsupported(format!("bind_error_kind={:?}", error.kind())),
    };
    let receiver = match UdpSocket::bind(any).await {
        Ok(socket) => socket,
        Err(error) => return Verdict::Unsupported(format!("bind_error_kind={:?}", error.kind())),
    };
    let (Ok(from), Ok(to)) = (sender.local_addr(), receiver.local_addr()) else {
        return Verdict::Unsupported("local_addr_unreadable".to_string());
    };
    if !from.ip().is_loopback() || !to.ip().is_loopback() {
        return Verdict::Fail(format!("not_loopback from={from} to={to}"));
    }
    let spawned = cx.spawn(move |_child| async move {
        let mut receiver = receiver;
        let mut buf = [0_u8; 64];
        receiver
            .recv_from(&mut buf)
            .await
            .map(|(n, peer)| (buf[..n].to_vec(), peer))
    });
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => return Verdict::Fail(format!("spawn_refused={error:?}")),
    };
    let send = wall_clock_timeout(sender.send_to(UDP_PAYLOAD, to), Duration::from_secs(3)).await;
    let send_failure = match send {
        Some(Ok(bytes)) if bytes == UDP_PAYLOAD.len() => None,
        Some(Ok(bytes)) => Some(format!(
            "short_send bytes={bytes} expected={}",
            UDP_PAYLOAD.len()
        )),
        Some(Err(error)) => Some(format!("send_error_kind={:?}", error.kind())),
        None => Some("send_timeout_after_3s".to_string()),
    };
    if let Some(failure) = send_failure {
        child.abort();
        let cleanup = finished_within!(child, PHASE_LIMIT);
        if cleanup {
            let _ = child.join(&cx).await;
        }
        return Verdict::Fail(format!("{failure} receiver_cleanup_completed={cleanup}"));
    }
    if !finished_within!(child, Duration::from_secs(3)) {
        child.abort();
        let cleanup = finished_within!(child, PHASE_LIMIT);
        if cleanup {
            let _ = child.join(&cx).await;
        }
        return Verdict::Fail(format!(
            "receive_timeout_after_3s receiver_aborted=true receiver_cleanup_completed={cleanup}"
        ));
    }
    match child.join(&cx).await {
        Ok(Ok((bytes, peer))) => {
            let detail = format!(
                "bytes={} payload_equal={} peer_is_sender={}",
                bytes.len(),
                bytes == UDP_PAYLOAD,
                peer == from
            );
            if bytes == UDP_PAYLOAD && peer == from {
                Verdict::Pass(detail)
            } else {
                Verdict::Fail(detail)
            }
        }
        Ok(Err(error)) => Verdict::Fail(format!("recv_error_kind={:?}", error.kind())),
        Err(error) => Verdict::Fail(format!("join_error={error:?}")),
    }
}

// ---- the bounded blocking pool (plain threads, driven from the main thread) -------------------------------------------------

#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    fn wait(&self) {
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        while !*open {
            open = self
                .changed
                .wait(open)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn release(&self) {
        *self.open.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.changed.notify_all();
    }
}

fn wait_until(limit: Duration, condition: impl Fn() -> bool) -> bool {
    let started = Instant::now();
    while !condition() {
        if started.elapsed() >= limit {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}

fn gated_job(
    gate: &Arc<Gate>,
    running: &Arc<AtomicUsize>,
) -> impl FnOnce() + Send + 'static + use<> {
    let (gate, running) = (Arc::clone(gate), Arc::clone(running));
    move || {
        running.fetch_add(1, Ordering::SeqCst);
        gate.wait();
    }
}

/// One blocking thread and one queued job: the first job runs, the second queues, the third is refused as saturated, and after the
/// gate opens both admitted jobs finish. No blocking thread exists before the first job.
fn blocking_phase(report: &mut Report, runtime: &Runtime) {
    let Some(pool) = runtime.blocking_handle() else {
        report.record(
            "BLOCKING_POOL",
            Verdict::Unsupported("runtime_has_no_blocking_pool".to_string()),
        );
        return;
    };
    let (gate, running) = (Arc::new(Gate::default()), Arc::new(AtomicUsize::new(0)));
    let idle_threads = pool.active_threads();
    let first = pool.try_spawn(gated_job(&gate, &running));
    let started = wait_until(Duration::from_secs(5), || {
        running.load(Ordering::SeqCst) == 1
    });
    let second = pool.try_spawn(gated_job(&gate, &running));
    let third = pool.try_spawn(gated_job(&gate, &running));
    let third_kind = third.err().map(|refused| refused.kind());
    let (active, pending) = (pool.active_threads(), pool.pending_count());
    let held = census();
    let deadline = Instant::now() + Duration::from_secs(5);
    gate.release();
    let done = (finished(&first, deadline), finished(&second, deadline));
    let detail = format!(
        "idle_threads={idle_threads} first_admitted={} first_started={started} second_admitted={} third_refused={third_kind:?} active_threads_while_held={active} pending_while_held={pending} threads_held_task_dir={} threads_held_status={} first_finished={} second_finished={} ran={}",
        first.is_ok(),
        second.is_ok(),
        show(held.stable_task_dir()),
        show(held.status_threads),
        done.0,
        done.1,
        running.load(Ordering::SeqCst)
    );
    let ok = idle_threads == 0
        && first.is_ok()
        && started
        && second.is_ok()
        && third_kind == Some(BlockingSpawnErrorKind::Saturated)
        && active == 1
        && pending == 1
        && done == (true, true)
        && running.load(Ordering::SeqCst) == 2;
    report.record(
        "BLOCKING_POOL",
        if ok {
            Verdict::Pass(detail)
        } else {
            Verdict::Fail(detail)
        },
    );
}

/// Whether a submission was admitted AND its task completed within five seconds of the gate opening.
fn finished<E>(submitted: &Result<BlockingTaskHandle, E>, deadline: Instant) -> bool {
    submitted.as_ref().is_ok_and(|task| {
        task.wait_timeout(deadline.saturating_duration_since(Instant::now()))
            && Instant::now() < deadline
    })
}

// ---- drain ------------------------------------------------------------------------------------------------------------------

/// Root tasks parked on 10 s timers, then a bounded root drain: it must cancel them and leave no live task, obligation or finalizer.
fn drain_phase(report: &mut Report, runtime: &Runtime) {
    let handle = runtime.handle();
    let mut spawned = 0_usize;
    let mut tasks = Vec::new();
    // Each task counts itself the first time its sleep is polled to `Pending`, i.e. when it is really parked on the timer.
    let entered = Arc::new(AtomicUsize::new(0));
    let cleanup = Arc::new(Mutex::new(Vec::with_capacity(DRAIN_TASKS)));
    // The runtime's timer driver, handed out by the tasks (a driver handle is only reachable from a task's `Cx`), so the main thread
    // can count the pending timers.
    let timer_slot = Arc::new(Mutex::new(None));
    for child_id in 0..DRAIN_TASKS {
        let counter = Arc::clone(&entered);
        let slot = Arc::clone(&timer_slot);
        let child_cleanup = Arc::clone(&cleanup);
        let parked = handle.try_spawn(async move {
            let Some(cx) = Cx::current() else {
                return;
            };
            if let Some(timer) = cx.timer_driver() {
                *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(timer);
            }
            let armed = Instant::now();
            let mut sleeper = pin!(sleep(cx.now(), LONG));
            let mut counted = false;
            std::future::poll_fn(|poll_cx| {
                let polled = sleeper.as_mut().poll(poll_cx);
                if polled.is_pending() && !counted {
                    counted = true;
                    counter.fetch_add(1, Ordering::SeqCst);
                }
                polled
            })
            .await;
            child_cleanup
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(SleepCleanup {
                    child_id,
                    cancel_requested: cx.is_cancel_requested(),
                    before_deadline: armed.elapsed() < LONG,
                });
        });
        if let Ok(task) = parked {
            spawned += 1;
            tasks.push(task);
        }
    }
    // The drain is triggered only once every admitted task has been SEEN parked, not after a guessed delay. If they do not all park
    // within the limit the drain is refused and said so, because a drain of tasks that never slept proves nothing about cancelling
    // parked ones.
    let all_parked = wait_until(PHASE_LIMIT, || entered.load(Ordering::SeqCst) == spawned);
    let parked_count = entered.load(Ordering::SeqCst);
    if !all_parked {
        let detail = format!(
            "drain_not_triggered: {parked_count}/{spawned} admitted tasks entered their sleep within {}s",
            PHASE_LIMIT.as_secs()
        );
        report.record("DRAIN", Verdict::Fail(detail));
        drop(tasks);
        return;
    }
    // `entered == spawned` says each task slept ONCE; it does not say they are all STILL parked (a 10 s sleep can end while a slow
    // task is only now starting). So, immediately before the trigger, look again: no admitted task may have finished, and the timer
    // driver must show at least one pending timer per task. Otherwise the drain is refused with the numbers seen, and no deadline is
    // loosened.
    let snapshot = ParkedSnapshot {
        admitted: tasks.len(),
        unfinished: tasks.iter().filter(|task| !task.is_finished()).count(),
        timers_pending: timer_slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|timer| timer.pending_count()),
    };
    if !snapshot.all_parked(DRAIN_TASKS) {
        let detail = format!(
            "drain_refused_not_all_still_parked: {} parked_counter={parked_count}/{spawned}",
            snapshot.detail()
        );
        report.record("DRAIN", Verdict::Fail(detail));
        drop(tasks);
        return;
    }
    let bound = Duration::from_secs(5);
    let drained = runtime.shutdown_drained(bound);
    // Draining a root that is already closed is itself pinned (`handle_drain_of_an_already_closed_root_preserves_bounded_teardown`):
    // the same success, with nothing live.
    let again = runtime.shutdown_drained(Duration::ZERO);
    let cleanup = cleanup.lock().unwrap_or_else(PoisonError::into_inner);
    let witnessed = cleanup_counts(&cleanup);
    let detail = format!(
        "tasks_spawned={spawned}/{DRAIN_TASKS} tasks_parked_before_drain={parked_count} snapshot_before_drain=({}) {} elapsed_ms={} bound_ms={} cleanup_resumed={} cleanup_unique={} cleanup_cancelled={} cleanup_before_deadline={} repeat: {}",
        snapshot.detail(),
        drain_detail(&drained),
        drained.elapsed.as_millis(),
        bound.as_millis(),
        witnessed.0,
        witnessed.1,
        witnessed.2,
        witnessed.3,
        drain_detail(&again)
    );
    let ok = spawned == DRAIN_TASKS
        && parked_count == DRAIN_TASKS
        && drain_succeeded(&drained)
        && cleanup_succeeded(&cleanup, DRAIN_TASKS)
        && drained.elapsed < bound
        && drain_succeeded(&again);
    report.record(
        "DRAIN",
        if ok {
            Verdict::Pass(detail)
        } else {
            Verdict::Fail(detail)
        },
    );
    drop(tasks);
}

/// What was seen immediately before the drain was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParkedSnapshot {
    /// Handles of the tasks the runtime admitted.
    admitted: usize,
    /// Of those, the ones that had not reached their terminal join state.
    unfinished: usize,
    /// The timer driver's pending timers; `None` when no driver handle could be read.
    timers_pending: Option<usize>,
}

impl ParkedSnapshot {
    /// True only if exactly `want` tasks were admitted, none of them has finished, and the timer driver shows at least `want` pending
    /// timers (other timers may also be pending). A driver that could not be read is not a pass.
    fn all_parked(&self, want: usize) -> bool {
        self.admitted == want
            && self.unfinished == want
            && self.timers_pending.is_some_and(|timers| timers >= want)
    }

    fn detail(&self) -> String {
        format!(
            "admitted={} unfinished={} timers_pending={}",
            self.admitted,
            self.unfinished,
            show(self.timers_pending)
        )
    }
}

/// The pinned success contract of `shutdown_drained`. `Quiescent` is only reported when the root region is gone AND every count is
/// zero, so `live_regions == 0` is the baseline after a successful drain (the pinned timeout test reports `TimedOut` with
/// `live_regions == 1` while the root is still open). The report's counts are checked as well, not only the outcome, because the
/// documentation says a count of zero alone does not certify a drain.
fn drain_succeeded(report: &RootDrainReport) -> bool {
    report.outcome == RootDrainOutcome::Quiescent
        && report.live_tasks == 0
        && report.pending_obligations == 0
        && report.live_regions == 0
        && report.queued_finalizers == 0
        && report.pending_spawns == 0
        && !report.has_pending_obligation_posts
}

fn drain_detail(report: &RootDrainReport) -> String {
    format!(
        "outcome={:?} expected_outcome=Quiescent live_tasks={} pending_obligations={} live_regions={} expected_live_regions=0 queued_finalizers={} pending_spawns={} pending_obligation_posts={}",
        report.outcome,
        report.live_tasks,
        report.pending_obligations,
        report.live_regions,
        report.queued_finalizers,
        report.pending_spawns,
        report.has_pending_obligation_posts
    )
}

// ---- the single-owner run ---------------------------------------------------------------------------------------------------

/// The argument that selects the single-owner run. Anything else, including the `--catalog` alias a supervisor passes, runs the default.
const SINGLE_OWNER_ARG: &str = "--profile=single-owner";

/// The row that is the one declared gap of the single-owner run, and the start of its `unsupported` detail (the reason, which the
/// judge pins too). A single-owner run is 20 phases plus 13 census samples, which is the size its exit code is defined for.
const CALLER_DRIVEN_ROW: &str = "CALLER_DRIVEN_CURRENT_THREAD";
const CALLER_DRIVEN_REASON: &str = "reason=profile_builder_cannot_build_caller_driven_mode";
const SINGLE_OWNER_OPS: u32 = 33;

/// Why the caller-driven mode is not run here, with where the pinned source shows it (Asupersync 460306de): the profile's builder
/// starts from `RuntimeBuilder::new()` and the mode's flag is private to the `current_thread()` constructor. This is a DECLARATION
/// from reading that source (`reason_source=static_source_reading`), not an observation: the one runtime observation next to it,
/// `observed_tasks_on_caller_thread`, can only contradict it, and nothing checks the file and line citations.
const CALLER_DRIVEN_UNSUPPORTED: &str = "reason=profile_builder_cannot_build_caller_driven_mode reason_source=static_source_reading evidence=asupersync_460306de:src/runtime/legacy_profile.rs:406,src/runtime/builder.rs:3911-3914";

/// The blocking pool's live-byte budget in the byte-budget run: small, so a declared charge over it is refused as too large.
const BYTE_BUDGET: NonZeroUsize = match NonZeroUsize::new(4096) {
    Some(bytes) => bytes,
    None => panic!("the byte budget is nonzero"),
};
/// The heap an in-budget job declares, well inside `BYTE_BUDGET`.
const BYTE_BUDGET_JOB_HEAP: usize = 64;

/// Whether the arguments select the single-owner run: only the exact argument does.
fn single_owner_requested(args: impl IntoIterator<Item = std::ffi::OsString>) -> bool {
    args.into_iter().any(|arg| arg == SINGLE_OWNER_ARG)
}

/// The marker file the guest runner packs into the initramfs for a single-owner run, the way the other guests read their `/ffw_seed`.
/// The supervisor starts this probe with a fixed argv and an empty environment and is not changed for this, so a file is the one input
/// the runner can still vary. No such file, or any other content, is the default run.
const SINGLE_OWNER_MARKER: &str = "/ffw_p05_profile";
/// The marker's whole content, with at most one trailing newline, that selects the single-owner run.
const SINGLE_OWNER_MARKER_WORD: &[u8] = b"single-owner";
/// A marker is read no further than one byte past this: a longer one is not the word.
const MARKER_READ_LIMIT: usize = 64;

/// At most `MARKER_READ_LIMIT + 1` bytes of `source`, so an endless or huge file costs a bounded read. A read error is no marker.
fn read_bounded(source: impl std::io::Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut limited = std::io::Read::take(
        source,
        u64::try_from(MARKER_READ_LIMIT + 1).unwrap_or(u64::MAX),
    );
    match std::io::Read::read_to_end(&mut limited, &mut bytes) {
        Ok(_) => bytes,
        Err(_) => Vec::new(),
    }
}

fn read_single_owner_marker() -> Option<Vec<u8>> {
    std::fs::File::open(SINGLE_OWNER_MARKER)
        .ok()
        .map(read_bounded)
}

/// Whether marker contents select the single-owner run: exactly the word, with at most one trailing newline. A missing marker and
/// anything else, including a longer or differently cased word, select the default run. Pure.
fn marker_selects_single_owner(contents: Option<&[u8]>) -> bool {
    let Some(bytes) = contents else {
        return false;
    };
    bytes.strip_suffix(b"\n").unwrap_or(bytes) == SINGLE_OWNER_MARKER_WORD
}

/// The single-owner run is selected by the exact argument or by the marker, and by nothing else.
fn single_owner_selected(
    args: impl IntoIterator<Item = std::ffi::OsString>,
    marker: Option<&[u8]>,
) -> bool {
    single_owner_requested(args) || marker_selects_single_owner(marker)
}

/// Which threads polled the tasks of one phase.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TaskThreads {
    /// Children that ran to completion and were joined.
    joined: usize,
    /// Distinct OS threads among the phase's own task and its children.
    distinct: usize,
    /// Whether the thread that called `block_on` was one of them (the caller-driven mode would make it so).
    on_caller: bool,
}

/// Spawn `CHILDREN` children and record the thread each finished on, together with the thread of this phase's own task. `caller` is the
/// thread that called `block_on`.
async fn task_threads_phase(caller: ThreadId) -> Result<TaskThreads, String> {
    let Some(cx) = Cx::current() else {
        return Err("no_current_cx".to_string());
    };
    let mut seen = HashSet::new();
    seen.insert(std::thread::current().id());
    let mut handles = Vec::new();
    for _ in 0..CHILDREN {
        match cx.spawn(move |_child| async move {
            yield_now().await;
            std::thread::current().id()
        }) {
            Ok(handle) => handles.push(handle),
            Err(error) => {
                return Err(format!("spawn_refused={error:?} after={}", handles.len()));
            }
        }
    }
    let mut joined = 0_usize;
    for mut handle in handles {
        if !finished_within!(handle, PHASE_LIMIT) {
            return Err(format!(
                "child_not_finished_within_{}s joined={joined}",
                PHASE_LIMIT.as_secs()
            ));
        }
        match handle.join(&cx).await {
            Ok(thread) => {
                joined += 1;
                seen.insert(thread);
            }
            Err(error) => return Err(format!("join_error={error:?} joined={joined}")),
        }
    }
    Ok(TaskThreads {
        joined,
        distinct: seen.len(),
        on_caller: seen.contains(&caller),
    })
}

fn task_threads_detail(observed: &Result<TaskThreads, String>) -> String {
    match observed {
        Ok(seen) => format!(
            "children_joined={} task_threads={} tasks_on_caller_thread={}",
            seen.joined, seen.distinct, seen.on_caller
        ),
        Err(why) => format!("observation_failed={why}"),
    }
}

/// The single-owner runtime row. Pure, so every branch is tested with made-up readings. It passes only if the runtime CARRIES one worker
/// (the audit against the stated caps said so) and every child joined, with the phase's tasks seen on exactly one OS thread. Only
/// that one phase's nine tasks are thread-checked: the UDP, drain and abort phases are not, so this is not "the whole run was on one
/// thread". `carried_workers` is configuration read from the runtime, not an observation.
fn judge_single_owner_runtime(
    carried_workers: usize,
    audit_ok: bool,
    observed: &Result<TaskThreads, String>,
) -> Verdict {
    let detail = format!(
        "carried_workers={carried_workers} stated_workers=1 audit_ok={audit_ok} {}",
        task_threads_detail(observed)
    );
    match observed {
        Ok(seen)
            if carried_workers == 1
                && audit_ok
                && seen.joined == CHILDREN
                && seen.distinct == 1 =>
        {
            Verdict::Pass(detail)
        }
        _ => Verdict::Fail(detail),
    }
}

/// The caller-driven mode is not something `LegacyProfile` can build at the pin, so this probe does not run its phases in it: that is
/// `unsupported`, never `ok`. If tasks were nevertheless seen on the thread that called `block_on`, the stated reason is wrong and that
/// is a failure to read, not a pass. If nothing could be observed it is `unknown`.
fn caller_driven_verdict(tasks_on_caller: Option<bool>) -> Verdict {
    match tasks_on_caller {
        Some(false) => Verdict::Unsupported(format!(
            "{CALLER_DRIVEN_UNSUPPORTED} observed_tasks_on_caller_thread=false"
        )),
        Some(true) => Verdict::Fail(format!(
            "caller_driven_mode_observed_on_a_legacy_profile_runtime observed_tasks_on_caller_thread=true contradicts {CALLER_DRIVEN_UNSUPPORTED}"
        )),
        None => Verdict::Unknown("task_thread_observation_unavailable".to_string()),
    }
}

/// A blocking job is held on the pool's only thread while async work runs to completion on the runtime's one worker: offloaded blocking
/// work does not starve a single scheduler thread. (Blocking ON that worker would starve it; this probe never does that.)
fn blocking_offload_phase(report: &mut Report, runtime: &Runtime) {
    let Some(pool) = runtime.blocking_handle() else {
        report.record(
            "SINGLE_OWNER_BLOCKING_OFFLOAD",
            Verdict::Unsupported("runtime_has_no_blocking_pool".to_string()),
        );
        return;
    };
    let (gate, running) = (Arc::new(Gate::default()), Arc::new(AtomicUsize::new(0)));
    let held = pool.try_spawn(gated_job(&gate, &running));
    let started = wait_until(Duration::from_secs(5), || {
        running.load(Ordering::SeqCst) == 1
    });
    let during = run_async(runtime, spawn_join_phase());
    let held_still = held
        .as_ref()
        .is_ok_and(|task| !task.wait_timeout(Duration::from_millis(1)));
    // Opened whatever happened above, so a failed phase never leaves the pool's thread waiting.
    gate.release();
    let done = finished(&held, Instant::now() + Duration::from_secs(5));
    let detail = format!(
        "held_admitted={} held_started={started} async_phase={} held_job_unfinished_during_async={held_still} held_job_finished_after_release={done} async_detail=({})",
        held.is_ok(),
        during.status(),
        during.detail()
    );
    let ok = held.is_ok() && started && matches!(during, Verdict::Pass(_)) && held_still && done;
    report.record(
        "SINGLE_OWNER_BLOCKING_OFFLOAD",
        if ok {
            Verdict::Pass(detail)
        } else {
            Verdict::Fail(detail)
        },
    );
}

/// Judge the first use of the blocking pool. Pure. `idle` is the pool's threads before any accepted job and `active` while the first
/// accepted job ran. The pool's counters decide pass or fail; the OS thread counts (`before`, `during`, from stable `/proc/self/task`
/// readings) must show a thread appearing when they can be read, and a count that cannot be read is `partial`, never `ok`.
fn judge_first_use(
    idle: usize,
    active: usize,
    started: bool,
    finished: bool,
    before: Option<usize>,
    during: Option<usize>,
) -> Verdict {
    let detail = format!(
        "pool_threads_before_first_job={idle} pool_threads_while_job_runs={active} job_started={started} job_finished={finished} os_threads_before={} os_threads_during={}",
        show(before),
        show(during)
    );
    if idle != 0 || active != 1 || !started || !finished {
        return Verdict::Fail(detail);
    }
    // The pool's counters decide pass or fail. A count that did not grow is an unstable observation (an unrelated thread may have
    // exited between the two readings), so it is `partial`, never `ok` and never a failure of the pool.
    match (before, during) {
        (Some(before), Some(during)) if during > before => Verdict::Pass(detail),
        (Some(_), Some(_)) => Verdict::Partial(format!(
            "{detail} reason=os_thread_count_did_not_grow_unstable_observation"
        )),
        _ => Verdict::Partial(format!("{detail} reason=os_thread_count_unreadable")),
    }
}

/// A fresh single-owner runtime, built WITHOUT a platform reactor (`reactor=none`; the refusal and first-use logic need none), whose
/// blocking pool is also bounded in bytes. A charge over the pool's whole budget is refused and starts no thread; the first accepted
/// job starts the pool's one thread; and the same runtime then still runs async work and drains.
fn byte_budget_phases(report: &mut Report, single_owner: LegacyProfile) {
    let profile = single_owner.with_blocking_live_bytes(BYTE_BUDGET);
    let builder = match profile.builder() {
        Ok(builder) => builder.enable_platform_reactor(false),
        Err(error) => {
            report.record(
                "BYTE_BUDGET_REFUSAL",
                Verdict::Fail(format!("builder_error={error:?}")),
            );
            return;
        }
    };
    let runtime = match builder.build() {
        Ok(runtime) => runtime,
        Err(error) => {
            report.record(
                "BYTE_BUDGET_REFUSAL",
                Verdict::Fail(format!("build_error={error:?}")),
            );
            return;
        }
    };
    let audit = profile.audit(&runtime);
    let Some(pool) = runtime.blocking_handle() else {
        report.record(
            "BYTE_BUDGET_REFUSAL",
            Verdict::Unsupported("runtime_has_no_blocking_pool".to_string()),
        );
        return;
    };
    let policy = pool.admission_policy();
    let idle = pool.active_threads();

    // The refusal: a declared charge over the pool's whole budget can never be admitted, so it is refused with that kind and its job
    // never runs and no pool thread is started for it.
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let declared = BYTE_BUDGET.get() + 1;
    let refused = pool.try_spawn_charged(move || flag.store(true, Ordering::SeqCst), declared);
    let refusal = refused.err().map(|error| error.kind());
    let threads_after_refusal = pool.active_threads();
    let refused_job_ran = ran.load(Ordering::SeqCst);
    let detail = format!(
        "audit_ok={} policy={policy:?} reactor=none budget_bytes={} declared_heap_bytes={declared} refusal={refusal:?} expected_refusal=Some(ChargeTooLarge) pool_threads_after_refusal={threads_after_refusal} refused_job_ran={refused_job_ran}",
        audit.is_ok(),
        BYTE_BUDGET.get()
    );
    let refusal_ok = audit.is_ok()
        && refusal == Some(BlockingSpawnErrorKind::ChargeTooLarge)
        && threads_after_refusal == 0
        && !refused_job_ran;
    report.record(
        "BYTE_BUDGET_REFUSAL",
        if refusal_ok {
            Verdict::Pass(detail)
        } else {
            Verdict::Fail(format!("{detail} audit={audit:?}"))
        },
    );

    // First use: the first accepted job (charged, in budget) starts the pool's one thread.
    let (gate, running) = (Arc::new(Gate::default()), Arc::new(AtomicUsize::new(0)));
    // Read right before the submission, so the only thing between the two thread readings is this one job.
    let before = census();
    let first = pool.try_spawn_charged(gated_job(&gate, &running), BYTE_BUDGET_JOB_HEAP);
    let started = wait_until(Duration::from_secs(5), || {
        running.load(Ordering::SeqCst) == 1
    });
    let active = pool.active_threads();
    let during = census();
    gate.release();
    let first_finished = finished(&first, Instant::now() + Duration::from_secs(5));
    let first_refusal = first.as_ref().err().map(|error| error.kind());
    let verdict = match first_refusal {
        Some(kind) => Verdict::Fail(format!("first_job_refused={kind:?}")),
        None => judge_first_use(
            idle,
            active,
            started,
            first_finished,
            before.stable_task_dir(),
            during.stable_task_dir(),
        ),
    };
    report.record("FIRST_USE_BACKGROUND", verdict);

    // Still usable: the refusal changed nothing, so the same runtime runs async work and drains to quiescence.
    let usable = run_async(&runtime, spawn_join_phase());
    let drained = runtime.shutdown_drained(Duration::from_secs(5));
    let detail = format!("spawn_join={} {}", usable.status(), drain_detail(&drained));
    let ok = matches!(usable, Verdict::Pass(_)) && drain_succeeded(&drained);
    report.record(
        "RUNTIME_USABLE_AFTER_REFUSAL",
        if ok {
            Verdict::Pass(detail)
        } else {
            Verdict::Fail(format!("{detail} spawn_join_detail=({})", usable.detail()))
        },
    );
}

// ---- main -------------------------------------------------------------------------------------------------------------------

fn finish(report: &Report, code: i32) -> ! {
    emit(&report.end());
    // As PID 1 there is nothing to return to and no `reboot` without `unsafe`: park, and the supervisor that owns the QEMU process
    // ends it once it has read END.
    if std::process::id() == 1 {
        loop {
            std::thread::park();
        }
    }
    std::process::exit(code);
}

fn main() {
    let marker = read_single_owner_marker();
    if single_owner_selected(std::env::args_os().skip(1), marker.as_deref()) {
        let report = run_single_owner_probe();
        let code = report.single_owner_exit_code();
        finish(&report, code)
    }
    let report = run_probe();
    let code = report.exit_code();
    finish(&report, code)
}

/// Every phase, in order, and the report of what happened. `main` calls it and then `finish`, unchanged (END, PID 1 parking, the exit
/// code); the native test calls it directly, so the REAL phases run under `cargo test`, not a stand-in. A failure to set up returns
/// the report so far, never an exit.
fn run_probe() -> Report {
    run_probe_for(Topology::Threaded, profile())
}

/// The same phases against the single-owner profile (one scheduler worker), plus the rows that are about that topology.
fn run_single_owner_probe() -> Report {
    run_probe_for(Topology::SingleOwner, single_owner_profile())
}

/// The one body both runs share. `stated` is the profile the run builds its runtime from. A run that claims the single-owner topology
/// refuses a profile that does not state exactly one worker before it builds anything; the default run's rows and output are unchanged.
fn run_probe_for(topology: Topology, stated: Option<LegacyProfile>) -> Report {
    let single_owner = topology == Topology::SingleOwner;
    let mut report = Report::default();
    let mut begin = format!(
        "pid={} arch={} endian={} pointer_bits={} threads_available_to_std={}",
        std::process::id(),
        std::env::consts::ARCH,
        if cfg!(target_endian = "big") {
            "big"
        } else {
            "little"
        },
        usize::BITS,
        show(
            std::thread::available_parallelism()
                .ok()
                .map(std::num::NonZeroUsize::get)
        )
    );
    if single_owner {
        begin.push_str(" topology=single_owner");
    }
    emit(&line("BEGIN", "start", &begin));
    sample(&mut report, "start");

    if single_owner {
        match stated.as_ref().map(single_owner_claim) {
            Some(Ok(())) => report.record(
                "SINGLE_OWNER_PROFILE",
                Verdict::Pass(
                    "claimed=single_owner stated_worker_threads=1 required_worker_threads=1"
                        .to_string(),
                ),
            ),
            Some(Err(refusal)) => {
                report.record("SINGLE_OWNER_PROFILE", Verdict::Fail(refusal.detail()));
                return report;
            }
            None => {
                report.record(
                    "SINGLE_OWNER_PROFILE",
                    Verdict::Fail("worst_case_stack_bytes=overflow".to_string()),
                );
                return report;
            }
        }
    }

    profile_phase(&mut report, stated);
    let Some(stated) = stated else {
        return report;
    };
    let Some((runtime, reactor)) = build_phase(&mut report, &stated) else {
        return report;
    };
    sample(&mut report, "after_build");

    if single_owner {
        let caller = std::thread::current().id();
        let observed = run_async_value(&runtime, task_threads_phase(caller));
        let carried = LegacyCaps::of_runtime(&runtime).worker_threads;
        report.record(
            "SINGLE_OWNER_RUNTIME",
            judge_single_owner_runtime(carried, stated.audit(&runtime).is_ok(), &observed),
        );
        report.record(
            CALLER_DRIVEN_ROW,
            caller_driven_verdict(observed.as_ref().ok().map(|seen| seen.on_caller)),
        );
        sample(&mut report, "after_single_owner_threads");
    }

    report.record("SPAWN_JOIN", run_async(&runtime, spawn_join_phase()));
    sample(&mut report, "after_spawn_join");
    report.record(
        "ABORT_TIMER_PARKED",
        run_async(&runtime, abort_timer_phase()),
    );
    sample(&mut report, "after_abort_timer_parked");
    report.record(
        "ABORT_BLIND_VALUE",
        run_async(&runtime, abort_blind_phase()),
    );
    sample(&mut report, "after_abort_blind_value");
    report.record("TIMER_WAKE", run_async(&runtime, timer_wake_phase()));
    sample(&mut report, "after_timer_wake");
    if reactor {
        report.record("UDP_LOOPBACK", run_async(&runtime, udp_phase()));
    } else {
        report.record(
            "UDP_LOOPBACK",
            Verdict::Unsupported("no_reactor_on_this_runtime".to_string()),
        );
    }
    sample(&mut report, "after_udp");
    blocking_phase(&mut report, &runtime);
    sample(&mut report, "after_blocking_pool");
    if single_owner {
        blocking_offload_phase(&mut report, &runtime);
        sample(&mut report, "after_blocking_offload");
    }
    drain_phase(&mut report, &runtime);
    sample(&mut report, "after_drain");
    drop(runtime);
    sample(&mut report, "after_runtime_drop");
    if single_owner {
        byte_budget_phases(&mut report, stated);
        sample(&mut report, "after_byte_budget");
    }
    report
}

// ---- native helper tests and real-runtime cases; the standalone program produces one clean transcript ---------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::{Context, Wake};

    #[derive(Default)]
    struct CountWake(AtomicUsize);

    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn runtime_for_test() -> Runtime {
        profile()
            .expect("bounded profile")
            .builder()
            .expect("valid caps")
            .enable_platform_reactor(false)
            .build()
            .expect("runtime build")
    }

    #[test]
    fn directory_iteration_errors_are_unknown_instead_of_a_partial_known_count() {
        assert_eq!(count_readable_entries([Ok::<_, ()>(()), Ok(())]), Some(2));
        assert_eq!(count_readable_entries([Ok(()), Err(()), Ok(())]), None);
        assert_eq!(count_readable_entries([Err::<(), _>(())]), None);
        assert_eq!(
            count_readable_entries(std::iter::empty::<Result<(), ()>>()),
            Some(0)
        );
    }

    #[test]
    fn wall_watchdog_requeues_pending_work_and_expires_without_a_runtime_timer() {
        let wakes = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        let mut ready = pin!(wall_clock_timeout(async { 42_u32 }, Duration::from_secs(1)));
        assert_eq!(ready.as_mut().poll(&mut cx), Poll::Ready(Some(42)));
        let mut pending = pin!(wall_clock_timeout(
            std::future::pending::<u32>(),
            Duration::from_millis(30)
        ));
        assert!(pending.as_mut().poll(&mut cx).is_pending());
        assert!(wakes.0.load(Ordering::SeqCst) >= 1);
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(pending.as_mut().poll(&mut cx), Poll::Ready(None));
    }

    #[test]
    fn wall_watchdog_rejects_a_ready_result_observed_after_the_deadline() {
        let wakes = Arc::new(CountWake::default());
        let waker = Waker::from(wakes);
        let mut cx = Context::from_waker(&waker);
        let late = std::future::poll_fn(|_| {
            std::thread::sleep(Duration::from_millis(30));
            Poll::Ready(7_u32)
        });
        let mut future = pin!(wall_clock_timeout(late, Duration::from_millis(10)));
        assert_eq!(future.as_mut().poll(&mut cx), Poll::Ready(None));
    }

    #[test]
    fn child_cleanup_must_resume_unique_children_under_cancellation_before_natural_expiry() {
        for wanted in [1, DRAIN_TASKS] {
            let valid: Vec<_> = (0..wanted)
                .map(|child_id| SleepCleanup {
                    child_id,
                    cancel_requested: true,
                    before_deadline: true,
                })
                .collect();
            assert!(cleanup_succeeded(&valid, wanted));
            assert!(
                !cleanup_succeeded(&[], wanted),
                "forced drop is not child cleanup"
            );
            let mut late = valid.clone();
            late[0].before_deadline = false;
            assert!(
                !cleanup_succeeded(&late, wanted),
                "natural expiry or a late continuation cannot pass"
            );
            let mut not_cancelled = valid.clone();
            not_cancelled[0].cancel_requested = false;
            assert!(!cleanup_succeeded(&not_cancelled, wanted));
            let mut wrong_child = valid.clone();
            wrong_child[0].child_id = wanted;
            assert!(!cleanup_succeeded(&wrong_child, wanted));
            if wanted > 1 {
                let duplicate = vec![valid[0]; wanted];
                assert!(
                    !cleanup_succeeded(&duplicate, wanted),
                    "repeated callbacks cannot replace a missing child"
                );
                assert!(!cleanup_succeeded(&valid[..wanted - 1], wanted));
            }
        }
        assert!(!cleanup_succeeded(&[], 0));
    }

    #[test]
    fn missing_blind_child_start_signal_still_releases_and_retires_the_real_child() {
        let runtime = runtime_for_test();
        // Only the start observation is withheld. The real future still registers its real task waker.
        let negative = run_async(
            &runtime,
            abort_blind_with_start_signal(false, Duration::from_millis(20)),
        );
        let positive = run_async(&runtime, abort_blind_phase());
        let drained = runtime.shutdown_drained(Duration::from_secs(5));
        assert!(matches!(positive, Verdict::Pass(_)));
        let Verdict::Fail(detail) = negative else {
            panic!("a missing observation must remain a failure");
        };
        assert!(
            detail.contains("blind_child_start_signal_missing cleanup_completed=true"),
            "{detail}"
        );
        assert!(detail.contains("join_result=Cancelled"), "{detail}");
        assert!(drain_succeeded(&drained), "{}", drain_detail(&drained));
    }

    #[test]
    fn blocking_completion_uses_the_shared_deadline_instead_of_readmitting_an_expired_wait() {
        let runtime = runtime_for_test();
        let pool = runtime.blocking_handle().expect("bounded blocking pool");
        let first = pool.try_spawn(|| {});
        let deadline = Instant::now() + Duration::from_secs(1);
        let first_done = finished(&first, deadline);
        std::thread::sleep(Duration::from_millis(1100));
        let second = pool.try_spawn(|| std::thread::sleep(Duration::from_millis(150)));
        let second_done = finished(&second, deadline);
        let second_retired = second
            .as_ref()
            .is_ok_and(|task| task.wait_timeout(Duration::from_secs(5)));
        assert!(first_done);
        assert!(
            !second_done,
            "a fresh five-second wait would incorrectly accept this job"
        );
        assert!(
            second_retired,
            "the deliberate late job must still be cleaned up"
        );
    }

    const STATUS: &str =
        "Name:\tffw\nThreads:\t7\nVmPeak:\t  9000 kB\nVmHWM:\t  4321 kB\nVmRSS:\t  4000 kB\n";

    #[test]
    fn a_field_is_read_by_its_exact_key_and_its_number() {
        assert_eq!(field(STATUS, "Threads"), Some(7));
        assert_eq!(field(STATUS, "VmHWM"), Some(4321));
        assert_eq!(field(STATUS, "VmRSS"), Some(4000));
        assert_eq!(
            field("MemAvailable:   123456 kB\n", "MemAvailable"),
            Some(123_456)
        );
    }

    #[test]
    fn a_missing_key_a_longer_key_and_a_non_number_are_unknown_not_zero() {
        assert_eq!(field(STATUS, "VmSwap"), None);
        assert_eq!(field("VmRSSx:\t5 kB\n", "VmRSS"), None);
        assert_eq!(field("Threads:\tmany\n", "Threads"), None);
        assert_eq!(field("Threads:\n", "Threads"), None);
        assert_eq!(field("", "Threads"), None);
        assert_eq!(field("Threads:\t-3\n", "Threads"), None);
        assert_eq!(show(field("", "Threads")), "unknown");
        assert_eq!(show(Some(0_u64)), "0");
    }

    #[test]
    fn the_first_matching_row_wins_and_a_later_bad_row_does_not_hide_it() {
        assert_eq!(field("Threads:\t3\nThreads:\tbad\n", "Threads"), Some(3));
        assert_eq!(field("Threads:\tbad\nThreads:\t3\n", "Threads"), Some(3));
    }

    #[test]
    fn a_marker_line_names_its_operation_and_status() {
        let text = line("SPAWN_JOIN", "ok", "children=8");
        assert_eq!(text, "FFW_P05_RUNTIME:SPAWN_JOIN status=ok children=8");
    }

    /// The REAL phases under `cargo test`; nothing here is simulated. It needs what the program needs (a platform reactor, loopback
    /// UDP, a readable /proc) and must be run with `--test-threads=1`: another test thread starting or ending during a census sample
    /// would, rightly, make that sample `partial`. It asserts the exact phase list and counts and an exit code of 0, so a skipped,
    /// unsupported, partial or failed phase fails it.
    #[test]
    fn native_runtime_exercises_all_phases_and_drains() {
        const PHASES: [&str; 13] = [
            "PROFILE_ACCEPT",
            "PROFILE_REFUSES_ZERO_WORKERS",
            "PROFILE_REFUSES_UNBOUNDED_QUEUE",
            "PROFILE_REFUSES_OVER_BUDGET",
            "REACTOR",
            "RUNTIME_AUDIT",
            "SPAWN_JOIN",
            "ABORT_TIMER_PARKED",
            "ABORT_BLIND_VALUE",
            "TIMER_WAKE",
            "UDP_LOOPBACK",
            "BLOCKING_POOL",
            "DRAIN",
        ];
        let report = run_probe();
        let summary = report.end();
        emit(&summary);
        let phases: Vec<&str> = report
            .names
            .iter()
            .map(String::as_str)
            .filter(|name| *name != "CENSUS")
            .collect();
        assert_eq!(phases, PHASES, "{summary}");
        assert_eq!(report.census_samples, 10, "{summary}");
        assert_eq!(report.ops, 23, "{summary}");
        let tally = (
            report.ok,
            report.failed,
            report.unsupported,
            report.partial,
            report.unknown,
        );
        assert_eq!(tally, (23, 0, 0, 0, 0), "{summary}");
        assert_eq!(report.exit_code(), 0, "{summary}");
    }

    fn counts(report: &Report) -> (u32, u32, u32, u32, u32, u32) {
        (
            report.ops,
            report.ok,
            report.failed,
            report.unsupported,
            report.partial,
            report.unknown,
        )
    }

    #[test]
    fn the_counters_count_what_was_recorded_and_the_exit_code_never_hides_a_failure() {
        let mut report = Report::default();
        assert_eq!(report.exit_code(), 0);
        report.record("A", Verdict::Pass("x=1".to_string()));
        assert_eq!(counts(&report), (1, 1, 0, 0, 0, 0));
        assert_eq!(report.exit_code(), 0);
        report.record("B", Verdict::Unsupported("why".to_string()));
        assert_eq!(counts(&report), (2, 1, 0, 1, 0, 0));
        assert_eq!(report.exit_code(), 2);
        report.record("C", Verdict::Partial("some".to_string()));
        report.record("D", Verdict::Unknown("none".to_string()));
        assert_eq!(counts(&report), (4, 1, 0, 1, 1, 1));
        assert_eq!(report.exit_code(), 2);
        report.record("E", Verdict::Fail("y=2".to_string()));
        assert_eq!(counts(&report), (5, 1, 1, 1, 1, 1));
        assert_eq!(report.exit_code(), 1);
        let (ops, ok, failed, unsupported, partial, unknown) = counts(&report);
        assert_eq!(ops, ok + failed + unsupported + partial + unknown);
        let end = report.end();
        assert!(end.starts_with("FFW_P05_RUNTIME:END status=done "));
        assert!(
            end.contains("ops=5 ok=1 failed=1 unsupported=1 partial=1 unknown=1 census_samples=0")
        );
    }

    #[test]
    fn a_partial_or_unknown_result_is_never_counted_as_a_pass() {
        let mut report = Report::default();
        report.record("CENSUS", Verdict::Partial("p".to_string()));
        report.record("CENSUS", Verdict::Unknown("u".to_string()));
        assert_eq!((report.ok, report.partial, report.unknown), (0, 1, 1));
        assert_eq!(report.census_samples, 2);
        assert_eq!(report.exit_code(), 2);
    }

    fn reading() -> Census {
        Census {
            task_dir_before: Some(3),
            task_dir_after: Some(3),
            status_threads: Some(3),
            rss_kb: Some(4000),
            hwm_kb: Some(4321),
            mem_available_kb: Some(90_000),
        }
    }

    fn word(verdict: &Verdict) -> &'static str {
        match verdict {
            Verdict::Pass(_) => "pass",
            Verdict::Fail(_) => "fail",
            Verdict::Unsupported(_) => "unsupported",
            Verdict::Partial(_) => "partial",
            Verdict::Unknown(_) => "unknown",
        }
    }

    #[test]
    fn a_complete_stable_reading_is_the_only_census_that_passes() {
        assert_eq!(word(&judge_census("t", &reading())), "pass");
    }

    #[test]
    fn two_stable_thread_sources_that_disagree_fail_and_do_not_pass() {
        let disagree = Census {
            status_threads: Some(4),
            ..reading()
        };
        let verdict = judge_census("t", &disagree);
        assert_eq!(word(&verdict), "fail");
        let Verdict::Fail(text) = verdict else {
            panic!("a disagreement must be a failure");
        };
        assert!(text.contains("reason=thread_sources_disagree"));
        assert!(text.contains("sources_agree=false"));
    }

    #[test]
    fn a_thread_set_that_changed_during_the_reading_is_partial_not_a_disagreement_and_not_a_pass() {
        let changed = Census {
            task_dir_before: Some(3),
            task_dir_after: Some(4),
            status_threads: Some(4),
            ..reading()
        };
        assert_eq!(word(&judge_census("t", &changed)), "partial");
        assert_eq!(changed.stable_task_dir(), None);
    }

    #[test]
    fn one_missing_figure_is_partial_and_every_missing_figure_is_unknown_never_zero() {
        let no_status = Census {
            status_threads: None,
            ..reading()
        };
        let no_hwm = Census {
            hwm_kb: None,
            ..reading()
        };
        let no_meminfo = Census {
            mem_available_kb: None,
            ..reading()
        };
        let no_dir = Census {
            task_dir_before: None,
            task_dir_after: None,
            ..reading()
        };
        for census in [&no_status, &no_hwm, &no_meminfo, &no_dir] {
            assert_eq!(word(&judge_census("t", census)), "partial");
        }
        let nothing = Census {
            task_dir_before: None,
            task_dir_after: None,
            status_threads: None,
            rss_kb: None,
            hwm_kb: None,
            mem_available_kb: None,
        };
        let verdict = judge_census("t", &nothing);
        assert_eq!(word(&verdict), "unknown");
        let Verdict::Unknown(text) = verdict else {
            panic!("not unknown");
        };
        assert!(text.contains("threads_status=unknown"));
        assert!(text.contains("vm_rss_kb=unknown"));
        assert!(!text.contains("=0 "));
        assert_eq!(nothing.stable_task_dir(), None);
    }

    #[test]
    fn a_zero_thread_count_and_a_high_water_mark_below_the_resident_size_fail() {
        let zero_dir = Census {
            task_dir_before: Some(0),
            task_dir_after: Some(0),
            status_threads: None,
            ..reading()
        };
        let zero_status = Census {
            status_threads: Some(0),
            ..reading()
        };
        let low_water = Census {
            hwm_kb: Some(3999),
            ..reading()
        };
        for census in [&zero_dir, &zero_status, &low_water] {
            assert_eq!(word(&judge_census("t", census)), "fail");
        }
        let equal_water = Census {
            hwm_kb: Some(4000),
            ..reading()
        };
        assert_eq!(word(&judge_census("t", &equal_water)), "pass");
    }

    #[test]
    fn the_census_of_a_real_process_never_passes_on_a_disagreement_and_prints_unknown_for_what_it_cannot_read()
     {
        let c = census();
        if let (Some(dir), Some(status)) = (c.stable_task_dir(), c.status_threads) {
            assert!(dir >= 1);
            assert!(status >= 1);
        }
        let text = census_detail("test", &c);
        assert!(text.starts_with("phase=test threads_task_dir_before="));
        let unreadable = Census {
            task_dir_before: None,
            task_dir_after: None,
            status_threads: None,
            rss_kb: None,
            hwm_kb: None,
            mem_available_kb: None,
        };
        let unknown = census_detail("none", &unreadable);
        assert!(
            unknown
                .contains("task_dir_stable=unknown threads_status=unknown sources_agree=unknown")
        );
        assert!(unknown.contains("mem_available_kb=unknown"));
    }

    fn drained() -> RootDrainReport {
        RootDrainReport {
            outcome: RootDrainOutcome::Quiescent,
            elapsed: Duration::from_millis(5),
            live_tasks: 0,
            pending_obligations: 0,
            live_regions: 0,
            queued_finalizers: 0,
            pending_spawns: 0,
            has_pending_obligation_posts: false,
        }
    }

    #[test]
    fn only_a_quiescent_report_with_every_count_zero_is_a_successful_drain() {
        assert!(drain_succeeded(&drained()));
        let timed_out = RootDrainReport {
            outcome: RootDrainOutcome::TimedOut,
            ..drained()
        };
        assert!(
            !drain_succeeded(&timed_out),
            "zero counts do not make a timeout a success"
        );
        let planted = [
            RootDrainReport {
                live_tasks: 1,
                ..drained()
            },
            RootDrainReport {
                pending_obligations: 1,
                ..drained()
            },
            RootDrainReport {
                live_regions: 1,
                ..drained()
            },
            RootDrainReport {
                queued_finalizers: 1,
                ..drained()
            },
            RootDrainReport {
                pending_spawns: 1,
                ..drained()
            },
            RootDrainReport {
                has_pending_obligation_posts: true,
                ..drained()
            },
        ];
        for report in &planted {
            assert!(!drain_succeeded(report), "{}", drain_detail(report));
        }
        let text = drain_detail(&timed_out);
        assert!(text.contains("outcome=TimedOut expected_outcome=Quiescent"));
        assert!(text.contains("live_regions=0 expected_live_regions=0"));
    }

    #[test]
    fn a_drain_is_triggered_only_when_every_task_is_still_parked_on_a_live_timer() {
        let parked = ParkedSnapshot {
            admitted: 4,
            unfinished: 4,
            timers_pending: Some(4),
        };
        assert!(parked.all_parked(4));
        let more_timers = ParkedSnapshot {
            timers_pending: Some(6),
            ..parked
        };
        assert!(
            more_timers.all_parked(4),
            "other pending timers are allowed"
        );
        let finished_child = ParkedSnapshot {
            unfinished: 3,
            ..parked
        };
        let missing_timer = ParkedSnapshot {
            timers_pending: Some(3),
            ..parked
        };
        let unreadable_timer = ParkedSnapshot {
            timers_pending: None,
            ..parked
        };
        let short_admission = ParkedSnapshot {
            admitted: 3,
            unfinished: 3,
            ..parked
        };
        for planted in [
            finished_child,
            missing_timer,
            unreadable_timer,
            short_admission,
        ] {
            assert!(!planted.all_parked(4), "{}", planted.detail());
        }
        assert!(unreadable_timer.detail().contains("timers_pending=unknown"));
        assert_eq!(parked.detail(), "admitted=4 unfinished=4 timers_pending=4");
    }

    #[test]
    fn a_join_is_named_by_its_kind() {
        let ok: Result<(), JoinError> = Ok(());
        assert_eq!(join_kind(&ok), "Ok");
    }

    #[test]
    fn wait_until_gives_up_at_its_limit_and_returns_at_once_when_true() {
        let started = Instant::now();
        assert!(!wait_until(Duration::from_millis(30), || false));
        assert!(started.elapsed() >= Duration::from_millis(30));
        assert!(wait_until(Duration::from_secs(5), || true));
    }

    #[test]
    fn a_gate_holds_a_waiter_until_it_is_released() {
        let gate = Arc::new(Gate::default());
        let done = Arc::new(AtomicBool::new(false));
        let (g, d) = (Arc::clone(&gate), Arc::clone(&done));
        let waiter = std::thread::spawn(move || {
            g.wait();
            d.store(true, Ordering::SeqCst);
        });
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !done.load(Ordering::SeqCst),
            "the waiter passed a closed gate"
        );
        gate.release();
        assert!(wait_until(Duration::from_secs(5), || done.load(Ordering::SeqCst)));
        assert!(waiter.join().is_ok());
    }

    #[test]
    fn the_probe_profile_is_bounded_and_the_planted_defects_are_refused_by_name() {
        let good = profile().expect("the stated caps do not overflow");
        assert!(good.violations().is_empty());
        let budget = good.stack_budget_bytes();
        let no_workers = LegacyProfile::new(
            LegacyCaps {
                worker_threads: 0,
                ..good.caps()
            },
            budget,
        );
        assert!(no_workers.violations().contains(&CapViolation::NoWorkers));
        let over = LegacyProfile::new(good.caps(), budget - 1);
        assert!(
            over.violations()
                .iter()
                .any(|v| matches!(v, CapViolation::StackBudgetExceeded { .. }))
        );
        let unbounded = LegacyProfile::new(
            LegacyCaps {
                blocking_max_queued: 0,
                ..good.caps()
            },
            budget,
        );
        assert!(
            unbounded
                .violations()
                .contains(&CapViolation::BlockingQueueUnbounded)
        );
    }

    // ---- the single-owner run -------------------------------------------------------------------------------------------------

    /// The REAL single-owner phases under `cargo test`, through the same body as `run_probe`, with the same needs as
    /// `native_runtime_exercises_all_phases_and_drains` (a platform reactor, loopback UDP, a readable /proc, `--test-threads=1`).
    /// Exactly one row is not `ok`: the caller-driven mode, which `LegacyProfile` cannot build. It must be there, typed `unsupported`
    /// (the tally leaves no other row for it to be). The generic code says so (2), and the single-owner run's own code, which treats
    /// exactly this declared row as a gap and not a crash, is 0.
    #[test]
    fn single_owner_runtime_exercises_the_supported_phases_and_types_the_unsupported_one() {
        const PHASES: [&str; 20] = [
            "SINGLE_OWNER_PROFILE",
            "PROFILE_ACCEPT",
            "PROFILE_REFUSES_ZERO_WORKERS",
            "PROFILE_REFUSES_UNBOUNDED_QUEUE",
            "PROFILE_REFUSES_OVER_BUDGET",
            "REACTOR",
            "RUNTIME_AUDIT",
            "SINGLE_OWNER_RUNTIME",
            "CALLER_DRIVEN_CURRENT_THREAD",
            "SPAWN_JOIN",
            "ABORT_TIMER_PARKED",
            "ABORT_BLIND_VALUE",
            "TIMER_WAKE",
            "UDP_LOOPBACK",
            "BLOCKING_POOL",
            "SINGLE_OWNER_BLOCKING_OFFLOAD",
            "DRAIN",
            "BYTE_BUDGET_REFUSAL",
            "FIRST_USE_BACKGROUND",
            "RUNTIME_USABLE_AFTER_REFUSAL",
        ];
        let report = run_single_owner_probe();
        let summary = report.end();
        emit(&summary);
        let phases: Vec<&str> = report
            .names
            .iter()
            .map(String::as_str)
            .filter(|name| *name != "CENSUS")
            .collect();
        assert_eq!(phases, PHASES, "{summary}");
        assert_eq!(report.census_samples, 13, "{summary}");
        assert_eq!(report.ops, 33, "{summary}");
        let tally = (
            report.ok,
            report.failed,
            report.unsupported,
            report.partial,
            report.unknown,
        );
        assert_eq!(tally, (32, 0, 1, 0, 0), "{summary}");
        assert_eq!(report.exit_code(), 2, "{summary}");
        assert_eq!(report.single_owner_exit_code(), 0, "{summary}");
    }

    /// The single-owner exit code. Control: exactly the declared row unsupported (32 ok) is 0. Every planted deviation from it, one
    /// at a time, is nonzero, and none of them is 0 by way of the generic code either.
    #[test]
    fn the_single_owner_exit_code_is_zero_only_for_exactly_the_declared_unsupported_row() {
        let declared = || caller_driven_verdict(Some(false));
        let unsupported = |why: &str| Verdict::Unsupported(format!("{why} observed=1"));
        // `rows` ok operations plus the given extra rows, recorded in order; the caller picks the total.
        let build = |ok_rows: u32, extra: Vec<(&str, Verdict)>| {
            let mut report = Report::default();
            for index in 0..ok_rows {
                report.record(&format!("ROW{index}"), Verdict::Pass("x=1".to_string()));
            }
            for (name, verdict) in extra {
                report.record(name, verdict);
            }
            report
        };
        let control = build(32, vec![(CALLER_DRIVEN_ROW, declared())]);
        assert_eq!((control.ops, control.ok, control.unsupported), (33, 32, 1));
        assert_eq!(control.single_owner_exit_code(), 0);
        assert_eq!(control.exit_code(), 2, "the generic code is unchanged");

        let planted: Vec<(&str, Report)> = vec![
            (
                "a second unsupported row",
                build(
                    31,
                    vec![
                        ("OTHER", unsupported("reason=other")),
                        (CALLER_DRIVEN_ROW, declared()),
                    ],
                ),
            ),
            (
                "a failed row",
                build(
                    31,
                    vec![
                        ("OTHER", Verdict::Fail("x=0".to_string())),
                        (CALLER_DRIVEN_ROW, declared()),
                    ],
                ),
            ),
            (
                "a partial row",
                build(
                    31,
                    vec![
                        ("OTHER", Verdict::Partial("x=0".to_string())),
                        (CALLER_DRIVEN_ROW, declared()),
                    ],
                ),
            ),
            (
                "an unknown row",
                build(
                    31,
                    vec![
                        ("OTHER", Verdict::Unknown("x=0".to_string())),
                        (CALLER_DRIVEN_ROW, declared()),
                    ],
                ),
            ),
            (
                "the declared row failed (tasks seen on the caller)",
                build(
                    32,
                    vec![(CALLER_DRIVEN_ROW, caller_driven_verdict(Some(true)))],
                ),
            ),
            (
                "the declared row ok, so nothing is declared",
                build(
                    32,
                    vec![(CALLER_DRIVEN_ROW, Verdict::Pass("x=1".to_string()))],
                ),
            ),
            (
                "the declared row unknown",
                build(32, vec![(CALLER_DRIVEN_ROW, caller_driven_verdict(None))]),
            ),
            (
                "a different row is the only unsupported one",
                build(32, vec![("UDP_LOOPBACK", unsupported("reason=no_reactor"))]),
            ),
            (
                "the declared row with another reason",
                build(
                    32,
                    vec![(CALLER_DRIVEN_ROW, unsupported("reason=something_else"))],
                ),
            ),
            (
                "a run of the wrong size",
                build(10, vec![(CALLER_DRIVEN_ROW, declared())]),
            ),
            ("a run with no rows at all", build(0, vec![])),
        ];
        for (name, report) in &planted {
            assert_ne!(report.single_owner_exit_code(), 0, "{name}");
        }
    }

    #[test]
    fn the_declared_reason_is_the_start_of_the_caller_driven_detail_the_exit_code_looks_for() {
        assert!(CALLER_DRIVEN_UNSUPPORTED.starts_with(CALLER_DRIVEN_REASON));
        let detail = caller_driven_verdict(Some(false));
        assert!(detail.detail().starts_with(CALLER_DRIVEN_REASON));
        assert!(
            detail
                .detail()
                .contains("reason_source=static_source_reading"),
            "the row is a declaration from the source, and says so"
        );
        assert_eq!(detail.status(), "unsupported");
        assert_eq!(CALLER_DRIVEN_ROW, "CALLER_DRIVEN_CURRENT_THREAD");
        assert_eq!(
            SINGLE_OWNER_OPS,
            20 + 13,
            "20 phases plus 13 census samples"
        );
    }

    /// The planted negative, in its pure form. A profile that claims the single-owner topology but states worker threads beyond the
    /// one is refused by name, zero workers is refused as an invalid profile, and the one-worker profile is accepted: the worker count
    /// is the only difference between the planted cases and the control.
    #[test]
    fn a_profile_that_claims_single_owner_but_has_worker_threads_is_refused() {
        let single = single_owner_profile().expect("the stated caps do not overflow");
        assert_eq!(single_owner_claim(&single), Ok(()));
        assert_eq!(single.caps().worker_threads, 1);
        assert_eq!(
            LegacyCaps {
                worker_threads: 2,
                ..single.caps()
            },
            caps(),
            "the two profiles differ only in the worker count"
        );
        let threaded = profile().expect("the stated caps do not overflow");
        assert_eq!(
            single_owner_claim(&threaded),
            Err(SingleOwnerRefusal::MoreThanOneWorker(2))
        );
        for workers in [2_usize, 3, 64] {
            let many = LegacyProfile::new(
                LegacyCaps {
                    worker_threads: workers,
                    ..single_owner_caps()
                },
                u64::MAX,
            );
            assert_eq!(
                single_owner_claim(&many),
                Err(SingleOwnerRefusal::MoreThanOneWorker(workers))
            );
        }
        let none = LegacyProfile::new(
            LegacyCaps {
                worker_threads: 0,
                ..single_owner_caps()
            },
            u64::MAX,
        );
        match single_owner_claim(&none) {
            Err(SingleOwnerRefusal::Invalid(violations)) => {
                assert!(violations.contains(&CapViolation::NoWorkers));
            }
            other => panic!("zero workers is not a stated single worker: {other:?}"),
        }
        let control = LegacyProfile::new(single_owner_caps(), u64::MAX);
        assert_eq!(single_owner_claim(&control), Ok(()));
    }

    /// The planted negative through the probe itself: the single-owner run handed the two-worker profile stops at the claim, with a
    /// failed row, before any phase runs or any runtime is built.
    #[test]
    fn the_single_owner_run_refuses_a_threaded_profile_before_building_a_runtime() {
        let report = run_probe_for(Topology::SingleOwner, profile());
        let phases: Vec<&str> = report.names.iter().map(String::as_str).collect();
        assert_eq!(phases, ["CENSUS", "SINGLE_OWNER_PROFILE"]);
        assert_eq!(report.failed, 1);
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn the_caller_driven_mode_is_unsupported_unknown_or_failed_and_never_ok() {
        let unsupported = caller_driven_verdict(Some(false));
        assert_eq!(word(&unsupported), "unsupported");
        assert_eq!(unsupported.status(), "unsupported");
        assert!(unsupported.detail().contains("legacy_profile.rs:406"));
        assert!(unsupported.detail().contains("builder.rs:3911"));
        assert_eq!(word(&caller_driven_verdict(Some(true))), "fail");
        assert_eq!(word(&caller_driven_verdict(None)), "unknown");
        for observed in [Some(false), Some(true), None] {
            assert_ne!(word(&caller_driven_verdict(observed)), "pass");
        }
    }

    #[test]
    fn the_single_owner_runtime_row_passes_only_for_one_carried_worker_and_one_task_thread() {
        let seen =
            |joined: usize, distinct: usize, on_caller: bool| -> Result<TaskThreads, String> {
                Ok(TaskThreads {
                    joined,
                    distinct,
                    on_caller,
                })
            };
        let good = judge_single_owner_runtime(1, true, &seen(CHILDREN, 1, false));
        assert_eq!(word(&good), "pass", "{}", good.detail());
        for (carried, audit_ok, observed) in [
            (2, true, seen(CHILDREN, 1, false)),
            (1, false, seen(CHILDREN, 1, false)),
            (1, true, seen(CHILDREN, 2, false)),
            (1, true, seen(CHILDREN - 1, 1, false)),
            (1, true, Err("no_current_cx".to_string())),
        ] {
            let verdict = judge_single_owner_runtime(carried, audit_ok, &observed);
            assert_eq!(word(&verdict), "fail", "{}", verdict.detail());
        }
    }

    #[test]
    fn first_use_of_the_blocking_pool_is_judged_from_its_counters_and_the_os_thread_count() {
        let good = judge_first_use(0, 1, true, true, Some(3), Some(4));
        assert_eq!(word(&good), "pass", "{}", good.detail());
        for planted in [
            judge_first_use(1, 1, true, true, Some(3), Some(4)),
            judge_first_use(0, 0, true, true, Some(3), Some(4)),
            judge_first_use(0, 2, true, true, Some(3), Some(4)),
            judge_first_use(0, 1, false, true, Some(3), Some(4)),
            judge_first_use(0, 1, true, false, Some(3), Some(4)),
        ] {
            assert_eq!(word(&planted), "fail", "{}", planted.detail());
        }
        // The pool's counters are right but the OS thread count did not grow (or could not be read): an unstable observation, so
        // `partial`, never `pass` and never a pool failure. (These two were `fail` before; they are still not ok.)
        for unstable in [
            judge_first_use(0, 1, true, true, Some(4), Some(4)),
            judge_first_use(0, 1, true, true, Some(5), Some(4)),
            judge_first_use(0, 1, true, true, None, Some(4)),
            judge_first_use(0, 1, true, true, Some(3), None),
        ] {
            assert_eq!(word(&unstable), "partial", "{}", unstable.detail());
            assert_ne!(word(&unstable), "pass");
        }
        // A wrong pool counter stays a failure whatever the thread counts say.
        for wrong_pool in [
            judge_first_use(1, 1, true, true, Some(4), Some(4)),
            judge_first_use(0, 0, true, true, Some(5), Some(4)),
        ] {
            assert_eq!(word(&wrong_pool), "fail", "{}", wrong_pool.detail());
        }
    }

    /// The byte-budget rows alone, on a fresh runtime: the oversized charge is refused as too large and starts no thread, the first
    /// in-budget job starts the pool's thread, and the same runtime then runs async work and drains.
    #[test]
    fn the_byte_budget_run_refuses_an_oversized_charge_and_leaves_the_runtime_usable() {
        let mut report = Report::default();
        let single = single_owner_profile().expect("the stated caps do not overflow");
        byte_budget_phases(&mut report, single);
        let summary = report.end();
        emit(&summary);
        assert_eq!(
            report.names,
            [
                "BYTE_BUDGET_REFUSAL",
                "FIRST_USE_BACKGROUND",
                "RUNTIME_USABLE_AFTER_REFUSAL"
            ],
            "{summary}"
        );
        let tally = (
            report.ok,
            report.failed,
            report.unsupported,
            report.partial,
            report.unknown,
        );
        assert_eq!(tally, (3, 0, 0, 0, 0), "{summary}");
    }

    #[test]
    fn only_the_exact_single_owner_argument_selects_the_single_owner_run() {
        let args = |list: &[&str]| -> Vec<std::ffi::OsString> {
            list.iter()
                .map(|item| std::ffi::OsString::from(*item))
                .collect()
        };
        assert!(single_owner_requested(args(&["--profile=single-owner"])));
        assert!(single_owner_requested(args(&[
            "--catalog",
            "--profile=single-owner"
        ])));
        assert!(!single_owner_requested(args(&[])));
        assert!(!single_owner_requested(args(&["--catalog"])));
        assert!(!single_owner_requested(args(&["--profile=single-owner-x"])));
        assert!(!single_owner_requested(args(&["--profile=threaded"])));
    }

    #[test]
    fn the_marker_selects_the_single_owner_run_only_when_it_is_exactly_the_word() {
        assert!(marker_selects_single_owner(Some(b"single-owner")));
        assert!(marker_selects_single_owner(Some(b"single-owner\n")));
        assert!(!marker_selects_single_owner(None));
        let refused: &[&[u8]] = &[
            b"",
            b"\n",
            b"single-owner\n\n",
            b"single-owner ",
            b" single-owner",
            b"Single-owner",
            b"single-owner-x",
            b"threaded",
            b"--profile=single-owner",
            b"single-owner\0",
        ];
        for contents in refused {
            assert!(
                !marker_selects_single_owner(Some(contents)),
                "{contents:?} must not select the single-owner run"
            );
        }
    }

    #[test]
    fn the_marker_read_is_bounded_and_an_oversized_marker_is_not_the_word() {
        let endless = read_bounded(std::io::repeat(b'x'));
        assert_eq!(endless.len(), MARKER_READ_LIMIT + 1);
        assert!(!marker_selects_single_owner(Some(&endless)));
        let short = read_bounded(&b"single-owner\n"[..]);
        assert_eq!(short, b"single-owner\n");
        assert!(marker_selects_single_owner(Some(&short)));
        let mut long = b"single-owner".to_vec();
        long.extend(std::iter::repeat_n(b' ', 1000));
        let clipped = read_bounded(&long[..]);
        assert_eq!(clipped.len(), MARKER_READ_LIMIT + 1);
        assert!(!marker_selects_single_owner(Some(&clipped)));
    }

    #[test]
    fn the_argument_or_the_marker_selects_the_single_owner_run_and_the_supervisors_argv_alone_does_not()
     {
        let args = |list: &[&str]| -> Vec<std::ffi::OsString> {
            list.iter()
                .map(|item| std::ffi::OsString::from(*item))
                .collect()
        };
        // What the unchanged supervisor really passes: `--catalog`, and no marker unless the runner packed one.
        assert!(!single_owner_selected(args(&["--catalog"]), None));
        assert!(!single_owner_selected(args(&[]), None));
        assert!(single_owner_selected(
            args(&["--catalog"]),
            Some(b"single-owner\n")
        ));
        assert!(single_owner_selected(
            args(&["--profile=single-owner"]),
            None
        ));
        assert!(!single_owner_selected(
            args(&["--catalog"]),
            Some(b"threaded\n")
        ));
    }
}
