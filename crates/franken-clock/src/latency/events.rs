//! Render-side numeric events; the control side pops and serializes them.
//!
//! The estimate path performs no I/O, callbacks, heap allocations, locks or
//! retries. Control-side `to_jsonl` allocates after a record has been popped.
//! Identifiers supplied by the caller must already be opaque pseudonyms.

use super::{Context, LatencyError, LatencyEstimate, LatencyTimeline};
use crate::events::{BufferedEvent, EventBuffer, EventStats};
use serde::Serialize;

pub const EVENT_CAPACITY: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DiagnosticIds {
    pub run_id: u64,
    pub case_id: u64,
    pub member_id: u64,
    pub group_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventOutcome {
    Estimated {
        estimate: LatencyEstimate,
    },
    Refused {
        code: &'static str,
        missing_mask: u16,
    },
}

impl From<Result<LatencyEstimate, LatencyError>> for EventOutcome {
    fn from(result: Result<LatencyEstimate, LatencyError>) -> Self {
        match result {
            Ok(estimate) => Self::Estimated { estimate },
            Err(error) => Self::Refused {
                code: match error {
                    LatencyError::NegativeTimestamp => "negative_timestamp",
                    LatencyError::ReversedInterval => "reversed_interval",
                    LatencyError::ContextMismatch => "context_mismatch",
                    LatencyError::TransformExpired => "transform_expired",
                    LatencyError::InvalidRate => "invalid_rate",
                    LatencyError::Overflow => "overflow",
                    LatencyError::MissingStages(_) => "missing_stages",
                    LatencyError::InvalidStageMask => "invalid_stage_mask",
                    LatencyError::StaleSnapshot => "stale_snapshot",
                    LatencyError::OutsideTimeline => "outside_timeline",
                },
                missing_mask: if let LatencyError::MissingStages(mask) = error {
                    mask
                } else {
                    0
                },
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LatencyEvent {
    pub schema_version: &'static str,
    pub timebase: &'static str,
    pub ids: DiagnosticIds,
    pub context: Context,
    pub outcome: EventOutcome,
}

/// A latency-specific adapter over the clock crate's shared fixed buffer.
#[derive(Debug)]
pub struct LatencyEventBuffer {
    ids: DiagnosticIds,
    queue: EventBuffer<LatencyEvent, EVENT_CAPACITY>,
}

impl LatencyEventBuffer {
    pub fn new(ids: DiagnosticIds, max_per_window: u32, window_ns: u64) -> Self {
        Self {
            ids,
            queue: EventBuffer::new(max_per_window, window_ns),
        }
    }

    pub fn set_available(&mut self, available: bool) {
        self.queue.set_available(available);
    }
    pub const fn stats(&self) -> EventStats {
        self.queue.stats()
    }
    pub const fn pending(&self) -> usize {
        self.queue.pending()
    }

    /// Sink state cannot change the estimate, refusal or freshness decision.
    pub fn estimate(
        &mut self,
        timeline: &LatencyTimeline,
        current: Context,
        now_ns: u64,
    ) -> Result<LatencyEstimate, LatencyError> {
        let result = timeline.estimate(current, now_ns);
        let payload = LatencyEvent {
            schema_version: "ffw.latency.event.v1",
            timebase: "local_monotonic_ns",
            ids: self.ids,
            context: current,
            outcome: result.into(),
        };
        if result.is_err() {
            self.queue.try_emit_critical(now_ns, payload);
        } else {
            self.queue.try_emit(now_ns, payload);
        }
        result
    }

    pub fn pop(&mut self) -> Option<BufferedEvent<LatencyEvent>> {
        self.queue.pop()
    }
}

/// Same field order as the shared ffw.log.v1 contract. Construct and serialize
/// only on the control side, after a typed event has left the render queue.
#[derive(Serialize)]
struct LogRecord {
    schema_version: &'static str,
    timestamp_mono_ns: u64,
    run_id: String,
    case_id: String,
    correlation_id: String,
    member_id: String,
    group_id: String,
    source_epoch: u64,
    state_revision: u64,
    event_kind: &'static str,
    message: String,
    queue_depth: usize,
    latency_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    fault: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cause: Option<&'static str>,
}

/// Encodes one popped event including newline. Persistence and any disk cap
/// belong to the caller. No such operation is called by `estimate`.
pub fn to_jsonl(event: BufferedEvent<LatencyEvent>) -> Result<String, serde_json::Error> {
    let payload = event.payload;
    let (event_kind, latency_us, cause) = match payload.outcome {
        EventOutcome::Estimated { estimate } => {
            ("latency_estimated", estimate.effective_ns / 1_000, None)
        }
        EventOutcome::Refused { code, .. } => ("latency_refused", 0, Some(code)),
    };
    let mut line = serde_json::to_string(&LogRecord {
        schema_version: "ffw.log.v1",
        timestamp_mono_ns: event.timestamp_mono_ns,
        run_id: format!("run-{}", payload.ids.run_id),
        case_id: format!("V01-{}", payload.ids.case_id),
        correlation_id: format!("snapshot-{}", payload.context.snapshot_id),
        member_id: format!("p-{}", payload.ids.member_id),
        group_id: format!("p-{}", payload.ids.group_id),
        source_epoch: payload.context.epoch,
        state_revision: payload.context.route_revision,
        event_kind,
        message: serde_json::to_string(&event)?,
        queue_depth: event.pending_before,
        latency_us,
        fault: None,
        cause,
    })?;
    line.push('\n');
    Ok(line)
}
