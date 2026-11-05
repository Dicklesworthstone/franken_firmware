//! Typed contracts for the native-service adapters (P01 / `ffw-h3g`): secret store, source session,
//! command and latency, each with a test-only ephemeral implementation.
//!
//! These are the interfaces adapters share, so that none of them has to invent its own way to hold a
//! credential, describe a stream, acknowledge a command or report a missed budget:
//!
//! * [`secret_store`]: typed handles to credentials; a value that cannot be printed, copied, compared
//!   with `==` or serialized; compare-and-swap replacement.
//! * [`source_session`]: distinct identity types, a validated stream description, four visible failure
//!   categories with bounded recovery, and lease terms that stop a stale coordinator.
//! * [`command`]: idempotency tokens where repeating is unsafe, and acknowledgements that cannot claim
//!   more than the renderer has evidenced.
//! * [`latency`]: budgets as typed durations whose breach is a typed error, wrapping the existing
//!   `LatencyLedger`.
//!
//! Nothing here opens a socket, reads a file or touches a device. The ephemeral implementations are
//! `#[cfg(test)]` only and never persist anything.

pub mod command;
pub mod latency;
pub mod secret_store;
pub mod source_session;
