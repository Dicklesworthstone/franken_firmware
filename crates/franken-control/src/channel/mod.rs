//! The reliable bounded control channel (N02 / `ffw-ugf`).
//!
//! Peers send signed control requests; one owner applies them to the group session. Between the two
//! the channel guarantees, in this order of defence:
//!
//! * **authentication first**: a request that does not authenticate changes nothing, not even a
//!   rate-limit bucket ([`peer`]);
//! * **bounded everything**: two fixed-size queues, a fixed-size outcome ledger, a per-peer rate
//!   limit, and a time limit on how long an accepted command may wait ([`limiter`], [`pipeline`]);
//! * **at most one application per command**: a retry is answered from the ledger with the command's
//!   recorded outcome, and a retry the ledger has forgotten is answered "unknown" and not applied
//!   ([`ledger`]);
//! * **stale leaders change nothing**: the epoch and the revision a sender last saw are checked
//!   before anything is applied ([`pipeline`]);
//! * **stop and mute keep their place**: a separate priority lane with slots reserved for the local
//!   user, served before everything else ([`pipeline`]).
//!
//! The request format and the bytes the authentication proof covers are in [`request`]. The reply a client can
//! check (an explicit encoding, bound to the command, its request and the epoch and revision it was made at)
//! is in [`reply`]. The peers' keys, roles, epoch bindings and revocations are kept on U01's journal, and the
//! peer directory is rebuilt from it at boot, by [`custody`].
//!
//! Nothing here opens a socket or reads a clock: transport is the caller's, and time is passed in as
//! nanoseconds. See `docs/contracts/n02.md` for the guarantees and for what is deliberately not
//! promised.

pub mod custody;
pub mod diag;
pub mod ledger;
pub mod limiter;
pub mod peer;
pub mod pipeline;
pub mod reply;
pub mod request;

#[cfg(test)]
mod replay;
#[cfg(test)]
mod testkit;
