//! P03's caller-driven control executor, consumed by `SettledRender`.
//!
//! Only crate-owned, borrowed control turns are admitted: callers cannot submit
//! arbitrary futures or heap-owning jobs. A turn processes the existing bounded
//! control batch or one HTTP mailbox entry. Rendering and HAL drain remain with
//! their original owner, outside this executor. In particular, a cooperative
//! poll quota does not preempt synchronous storage: storage latency remains an
//! independent qualification requirement, not a property of this wrapper.

use asupersync::cx::Cx;
use asupersync::record::region::RegionLimits;
use asupersync::runtime::legacy_profile::{LegacyCaps, LegacyProfile};
use asupersync::runtime::{RootDrainReport, Runtime, yield_now};
use asupersync::types::Budget;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

const ROOT_TASKS: usize = 4;
const TURN_POLLS: u32 = 8;
const MAX_CAPTURE_BYTES: usize = 64;
const STACK_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ControlRuntimeError {
    #[error("bounded control runtime could not be built or audited")]
    Unavailable,
    #[error("another control turn is already active")]
    Busy,
    #[error("control turn capture exceeds its admission budget")]
    CaptureTooLarge,
    #[error("control executor is shutting down")]
    Closed,
    #[error("control turn cancelled before dispatch")]
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlRuntimeStats {
    pub completed_turns: usize,
    pub rejected_turns: usize,
    pub peak_capture_bytes: usize,
    pub active_turns: usize,
    /// This executor admits no queued or running blocking closure bytes.
    pub blocking_job_bytes: usize,
}

struct Admission {
    active: AtomicBool,
    closed: AtomicBool,
    completed: AtomicUsize,
    rejected: AtomicUsize,
    peak_capture: AtomicUsize,
}

fn increment_saturating(counter: &AtomicUsize) {
    let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(1))
    });
}

/// Clones share one admission gate and one runtime. They do not create workers.
/// A clone is used to borrow the actual control owner during a scoped root turn;
/// no task can keep that borrow after the turn returns.
#[derive(Clone)]
pub struct ControlRuntime {
    runtime: Runtime,
    admission: Arc<Admission>,
}

struct TurnPermit<'a>(&'a AtomicBool);
impl Drop for TurnPermit<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl ControlRuntime {
    pub fn new() -> Result<Self, ControlRuntimeError> {
        let profile = LegacyProfile::new(
            LegacyCaps {
                worker_threads: 1,
                thread_stack_bytes: STACK_BYTES,
                blocking_max_threads: 0,
                blocking_thread_stack_bytes: 0,
                global_queue_limit: ROOT_TASKS,
                blocking_max_queued: 0,
            },
            STACK_BYTES as u64,
        )
        .caller_driven();
        let runtime = profile
            .builder()
            .map_err(|_| ControlRuntimeError::Unavailable)?
            .root_region_limits(RegionLimits {
                max_children: Some(1),
                max_tasks: Some(ROOT_TASKS),
                max_obligations: Some(4),
                // This accounts only region-owned allocation, not total RSS.
                max_heap_bytes: Some(64 * 1024),
                curve_budget: None,
            })
            .build()
            .map_err(|_| ControlRuntimeError::Unavailable)?;
        profile
            .audit(&runtime)
            .map_err(|_| ControlRuntimeError::Unavailable)?;
        Ok(Self {
            runtime,
            admission: Arc::new(Admission {
                active: AtomicBool::new(false),
                closed: AtomicBool::new(false),
                completed: AtomicUsize::new(0),
                rejected: AtomicUsize::new(0),
                peak_capture: AtomicUsize::new(0),
            }),
        })
    }

    /// Private admission surface: production captures only borrowed owner and
    /// mailbox references. The size check is not a deep heap-size estimator.
    pub(crate) fn turn<T>(&self, work: impl FnOnce() -> T) -> Result<T, ControlRuntimeError> {
        self.turn_with_budget(work, TURN_POLLS)
    }

    fn turn_with_budget<T>(
        &self,
        work: impl FnOnce() -> T,
        polls: u32,
    ) -> Result<T, ControlRuntimeError> {
        let capture_bytes = size_of_val(&work);
        let refusal = if capture_bytes > MAX_CAPTURE_BYTES {
            Some(ControlRuntimeError::CaptureTooLarge)
        } else if self.admission.closed.load(Ordering::Acquire) {
            Some(ControlRuntimeError::Closed)
        } else {
            None
        };
        if let Some(error) = refusal {
            increment_saturating(&self.admission.rejected);
            return Err(error);
        }
        let _permit = self.acquire_open_turn().inspect_err(|_| {
            increment_saturating(&self.admission.rejected);
        })?;
        self.admission
            .peak_capture
            .fetch_max(capture_bytes, Ordering::Relaxed);
        let result =
            self.runtime
                .block_on_with_budget(Budget::INFINITE.with_poll_quota(polls), async {
                    yield_now().await;
                    let cx = Cx::current().ok_or(ControlRuntimeError::Unavailable)?;
                    cx.checkpoint()
                        .map_err(|_| ControlRuntimeError::Cancelled)?;
                    if self.admission.closed.load(Ordering::Acquire) {
                        return Err(ControlRuntimeError::Closed);
                    }
                    Ok(work())
                });
        if result.is_ok() {
            increment_saturating(&self.admission.completed);
        } else {
            increment_saturating(&self.admission.rejected);
        }
        result
    }

    // Shutdown may complete between the preliminary open check and this CAS.
    // Recheck while owning the gate, before creating a root task at all.
    fn acquire_open_turn(&self) -> Result<TurnPermit<'_>, ControlRuntimeError> {
        self.admission
            .active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ControlRuntimeError::Busy)?;
        let permit = TurnPermit(&self.admission.active);
        if self.admission.closed.load(Ordering::Acquire) {
            return Err(ControlRuntimeError::Closed);
        }
        Ok(permit)
    }

    pub fn stats(&self) -> ControlRuntimeStats {
        ControlRuntimeStats {
            completed_turns: self.admission.completed.load(Ordering::Relaxed),
            rejected_turns: self.admission.rejected.load(Ordering::Relaxed),
            peak_capture_bytes: self.admission.peak_capture.load(Ordering::Relaxed),
            active_turns: usize::from(self.admission.active.load(Ordering::Acquire)),
            blocking_job_bytes: 0,
        }
    }

    /// Software root drain only. It never claims HAL or DMA completion. A busy
    /// turn retains custody and must finish before drain is attempted again.
    pub fn shutdown(&self, bound: Duration) -> Result<RootDrainReport, ControlRuntimeError> {
        self.admission.closed.store(true, Ordering::Release);
        if self
            .admission
            .active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ControlRuntimeError::Busy);
        }
        let _permit = TurnPermit(&self.admission.active);
        Ok(self.runtime.shutdown_drained(bound))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_saturates_instead_of_wrapping_on_32_bit_targets() {
        let runtime = ControlRuntime::new().unwrap();
        runtime
            .admission
            .completed
            .store(usize::MAX, Ordering::Relaxed);
        runtime
            .admission
            .rejected
            .store(usize::MAX, Ordering::Relaxed);
        runtime.turn(|| ()).unwrap();
        assert_eq!(
            runtime.turn_with_budget(|| (), 0),
            Err(ControlRuntimeError::Cancelled)
        );
        let stats = runtime.stats();
        assert_eq!(stats.completed_turns, usize::MAX);
        assert_eq!(stats.rejected_turns, usize::MAX);
    }

    #[test]
    fn borrowed_owner_changes_on_the_calling_thread_without_detached_work() {
        let runtime = ControlRuntime::new().unwrap();
        let mut value = 3;
        let caller = std::thread::current().id();
        runtime
            .turn(|| {
                assert_eq!(std::thread::current().id(), caller);
                assert!(Cx::current().is_some());
                value += 4;
            })
            .unwrap();
        assert_eq!(value, 7);
        assert_eq!(runtime.stats().completed_turns, 1);
        assert_eq!(runtime.stats().active_turns, 0);
    }

    #[test]
    fn saturation_rejects_reentrance_but_releases_the_next_turn() {
        let runtime = ControlRuntime::new().unwrap();
        let other = runtime.clone();
        assert_eq!(
            runtime.turn(|| other.turn(|| 9)).unwrap(),
            Err(ControlRuntimeError::Busy)
        );
        assert_eq!(runtime.turn(|| 7).unwrap(), 7);
        assert_eq!(runtime.stats().rejected_turns, 1);
    }

    #[test]
    fn exhausted_poll_budget_never_dispatches_the_control_command() {
        let runtime = ControlRuntime::new().unwrap();
        let mut called = false;
        assert_eq!(
            runtime.turn_with_budget(|| called = true, 0),
            Err(ControlRuntimeError::Cancelled)
        );
        assert!(!called);
        assert!(runtime.turn(|| ()).is_ok());
    }

    #[test]
    fn oversized_capture_is_refused_before_dispatch() {
        let runtime = ControlRuntime::new().unwrap();
        let captured = [1_u8; MAX_CAPTURE_BYTES + 1];
        assert_eq!(
            runtime.turn(move || std::hint::black_box(captured)),
            Err(ControlRuntimeError::CaptureTooLarge)
        );
        assert_eq!(runtime.stats().peak_capture_bytes, 0);
    }

    #[test]
    fn shutdown_between_open_check_and_gate_acquisition_prevents_late_root() {
        let runtime = ControlRuntime::new().unwrap();
        assert!(!runtime.admission.closed.load(Ordering::Acquire));
        // Suspend a turn after its preliminary check. Another clone completes
        // shutdown before the first turn acquires the active gate.
        let report = runtime.clone().shutdown(Duration::from_secs(1)).unwrap();
        assert_eq!(
            report.outcome,
            asupersync::runtime::RootDrainOutcome::Quiescent
        );
        assert!(matches!(
            runtime.acquire_open_turn(),
            Err(ControlRuntimeError::Closed)
        ));
        assert!(!runtime.admission.active.load(Ordering::Acquire));
        let open = ControlRuntime::new().unwrap();
        let permit = open.acquire_open_turn().unwrap();
        assert!(open.admission.active.load(Ordering::Acquire));
        drop(permit);
        assert!(!open.admission.active.load(Ordering::Acquire));
    }

    #[test]
    fn repeat_start_stop_drains_and_never_reopens_closed_runtime() {
        for _ in 0..4 {
            let runtime = ControlRuntime::new().unwrap();
            runtime.turn(|| ()).unwrap();
            assert_eq!(
                runtime.shutdown(Duration::from_secs(1)).unwrap().outcome,
                asupersync::runtime::RootDrainOutcome::Quiescent
            );
            assert_eq!(runtime.turn(|| 1), Err(ControlRuntimeError::Closed));
        }
    }

    #[test]
    fn forbidden_blocking_jobs_never_execute_inline_or_allocate_a_worker() {
        let runtime = ControlRuntime::new().unwrap();
        let pool = runtime
            .runtime
            .blocking_handle()
            .expect("forbidden pool must exist");
        let ran = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ran);
        let refusal = pool
            .try_spawn_charged(move || flag.store(true, Ordering::Release), 1024)
            .expect_err("no blocking jobs admitted");
        assert_eq!(
            refusal.kind(),
            asupersync::runtime::BlockingSpawnErrorKind::Forbidden
        );
        assert!(!ran.load(Ordering::Acquire));
        assert_eq!(pool.active_threads(), 0);
        assert_eq!(runtime.stats().blocking_job_bytes, 0);
    }

    #[test]
    fn real_timer_task_cancel_join_and_root_drain_leave_no_live_work() {
        use std::future::Future;
        use std::time::Instant;
        let runtime = ControlRuntime::new().unwrap();
        runtime.runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let timer = cx.timer_driver().expect("real timer driver");
            let parked = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&parked);
            let mut child = cx
                .spawn(move |child_cx| async move {
                    let mut sleep = std::pin::pin!(asupersync::time::sleep(
                        child_cx.now(),
                        Duration::from_secs(30),
                    ));
                    std::future::poll_fn(|poll_cx| {
                        let polled = sleep.as_mut().poll(poll_cx);
                        if polled.is_pending() {
                            flag.store(true, Ordering::Release);
                        }
                        polled
                    })
                    .await;
                    child_cx.is_cancel_requested()
                })
                .unwrap();
            let started = Instant::now();
            while !parked.load(Ordering::Acquire) && started.elapsed() < Duration::from_secs(1) {
                yield_now().await;
            }
            assert!(
                parked.load(Ordering::Acquire),
                "child must actually park on timer"
            );
            let pending_before = timer.pending_count();
            assert!(pending_before > 0);
            let aborted = Instant::now();
            child.abort();
            let joined =
                asupersync::time::timeout(cx.now(), Duration::from_secs(1), child.join(&cx)).await;
            // Sleep explicitly acknowledges cancellation and preserves the
            // child's result (same contract as P05 ABORT_TIMER). A blind late
            // value instead joins Cancelled; those are distinct contracts.
            assert!(
                matches!(joined, Ok(Ok(true))),
                "acknowledged cancellation must be observed: {joined:?}"
            );
            assert!(aborted.elapsed() < Duration::from_secs(1));
            assert_eq!(timer.pending_count() + 1, pending_before);
        });
        let report = runtime.shutdown(Duration::from_secs(1)).unwrap();
        assert_eq!(
            report.outcome,
            asupersync::runtime::RootDrainOutcome::Quiescent
        );
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.pending_obligations, 0);
        assert_eq!(report.queued_finalizers, 0);
    }

    #[test]
    fn real_loopback_socket_progresses_under_the_caller_driven_reactor() {
        let runtime = ControlRuntime::new().unwrap();
        runtime.runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let address = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
            let mut sender = asupersync::net::UdpSocket::bind(address).await.unwrap();
            let mut receiver = asupersync::net::UdpSocket::bind(address).await.unwrap();
            let to = receiver.local_addr().unwrap();
            let from = sender.local_addr().unwrap();
            let mut child = cx
                .spawn(move |_| async move {
                    let mut bytes = [0_u8; 4];
                    let received = receiver.recv_from(&mut bytes).await.unwrap();
                    (bytes, received)
                })
                .unwrap();
            assert_eq!(sender.send_to(b"P03!", to).await.unwrap(), 4);
            let result =
                asupersync::time::timeout(cx.now(), Duration::from_secs(1), child.join(&cx)).await;
            if result.is_err() {
                child.abort();
            }
            let (bytes, (length, peer)) = result.expect("bounded loopback receive").unwrap();
            assert_eq!(bytes, *b"P03!");
            assert_eq!(length, 4);
            assert_eq!(peer, from);
        });
    }
}
