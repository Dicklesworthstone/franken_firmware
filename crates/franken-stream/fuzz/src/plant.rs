//! The planted bug of the control run (`docs/contracts/n01.md` section 11).
//!
//! A fuzzer that finds nothing proves nothing unless it is shown to find something. In a build with the `control`
//! feature, the harness's call into the real decoder panics when an ACCEPTED packet carries a payload of exactly
//! `CONTROL_PAYLOAD_LEN` bytes, a length no seed has (the seeds' accepted payloads are 4, 8, 12 and 1024 bytes).
//! Reaching it takes a datagram that is structurally valid, carries a valid tag and declares that length, which is the
//! whole path a coverage-guided run has to learn. The plant is here and not in franken-stream on purpose: a device
//! closure crate carries no deliberately broken path, even a gated one. What this proves is reach and reporting; it
//! does not prove the real decoder has no bug the oracles cannot see.

/// A multiple of 4 and at most 1024, so a datagram with this payload can be valid; not equal to any seed's.
pub const CONTROL_PAYLOAD_LEN: usize = 516;

/// Whether this build carries the plant.
pub const fn control_enabled() -> bool {
    cfg!(feature = "control")
}

/// Called with the payload length of every packet the decoder accepted.
pub fn after_accept(payload_len: usize) {
    if control_enabled() && payload_len == CONTROL_PAYLOAD_LEN {
        panic!("planted decoder bug: payload length {CONTROL_PAYLOAD_LEN}");
    }
}
