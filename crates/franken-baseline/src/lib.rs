#![forbid(unsafe_code)]
//! Offline analyzer for the incumbent resource and dropout baseline (bead ffw-za4, E02).
//!
//! Two inputs, both plain text, both analyzed with integer arithmetic only:
//!
//! * [`memory`]: `/proc` captures (`meminfo`, `status`, `smaps_rollup`, `statm`) turned into one memory
//!   ledger that counts a shared page once, keeps kernel memory apart from process memory, and gives
//!   headroom against a reserve declared before the run.
//! * [`series`]: timestamped counter and gauge samples turned into coverage, holes, dropouts and, only
//!   where the capture carries the signal, a cause for each dropout. See the rules at the top of that
//!   module.
//!
//! [`compare`] decides when a comparative claim may be made at all.
//!
//! [`redact`] keeps site identifiers out of every report and diagnostic: a profile, series name or snapshot
//! label shaped like an address or a serial number is refused, and any other input text a diagnostic repeats is
//! redacted and bounded.
//!
//! [`summary`] turns a printed report into the one concise human line the CLI writes on stderr, reading only the
//! report's own fields.
//!
//! What this crate does not do. It measures nothing: it analyzes captures it is given, so on a
//! synthetic capture its output is a statement about the analyzer, not about any device. It does not
//! interpolate across gaps, infer a cause the capture cannot show, or turn the absence of a signal into
//! a zero. See `docs/contracts/e02.md` for the formats and for what each verdict does and does not prove.

pub mod capture;
pub mod clock;
pub mod compare;
pub mod finding;
pub mod json;
pub mod memory;
pub mod parse;
pub mod procfs;
pub mod redact;
pub mod series;
pub mod summary;
