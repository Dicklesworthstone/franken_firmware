//! Fuzz harness for the N01 parsers (`docs/contracts/n01.md` section 11): four targets, an independent oracle for each,
//! a seed corpus made of the committed golden vectors, and a planted bug for the control run.
//!
//! Host-only. It is not a member of the repository workspace and nothing in a device closure depends on it.
//!
//! Targets (each takes arbitrary bytes; the first byte of a datagram input says "use as is" or "re-sign"):
//! - `stream_decode`: `AuthenticatedStreamPacket::decode_and_verify` against `wire::expected_decode`, plus re-encode and
//!   bounds for every accepted packet.
//! - `stream_receiver`: a real `StreamReceiver` driven by an operation stream against `model::Window`, plus counters.
//! - `negotiation_respond`, `negotiation_finish`: the two Hello parsers against `hello::expected_decode`.

pub mod fixture;
pub mod hello;
pub mod model;
pub mod plant;
pub mod seed;
pub mod stream;
pub mod wire;
